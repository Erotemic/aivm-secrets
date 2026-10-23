#!/usr/bin/env python3
"""Opt-in OUT-6 check of the constrained-http profile on a real AIVM VM (HP-6).

Runs `aivm-secrets native-session` with `constrained_proxy` against a
synthetic loopback provider and a synthetic credential, with the guest
reached over the VM's own SSH config. The native bridge runs on the host;
`garrett-proxy` runs **inside the guest** as the constrained translator and
holds no credential. Then:

1. stock `curl` in the guest, using only the published `env` file, reads one
   allowed pull request's diff; the provider must see the host's own `pull`
   check and the diff, both with the substituted credential, and the guest
   gets only the disclosure;
2. an out-of-scope pull request and an unmatched path through the proxy
   never reach the provider;
3. no file in the guest session directory contains the credential;
4. closing the session removes the guest directory.

Only synthetic credentials; never changes firewall rules or forwards an
agent. Every provider effect is a named operation the host bridge
authorized; this is finite evidence for that path, not a VM isolation claim.
"""
from __future__ import annotations

import argparse
import json
import select
import shlex
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dev import offline_native_guest as offline
from dev.aivm_vm_acceptance import GuestSSH, ssh_configuration, validate_vm_name
from dev.offline_native_guest import DemoError, LocalProvider, safe_environment, write

OTHER_PR = offline.PR + 1


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def session_spec(workspace: Path, ssh: GuestSSH, bin_dir: Path, provider, guest_port: int) -> dict:
    for path in provider.files.values():
        path.chmod(0o600)
    return dict(
        version=1, bin_dir=str(bin_dir), workspace=str(workspace / 'host'),
        policy_file=str(workspace / 'policy.json'),
        disclosure_file=str(workspace / 'disclosure.json'),
        credential_file=str(workspace / 'credential'),
        provider=dict(host=provider.host, address='127.0.0.1', port=provider.port,
                      server_ca=str(provider.files['ca']), authentication='bearer'),
        binding=dict(access_identity='operator-acceptance', vm=ssh.vm),
        guest=dict(kind='ssh', ssh_config=str(ssh.config), host=ssh.vm),
        approve_session_key=True,
        constrained_proxy=dict(guest_port=guest_port),
    )


def _curl(env: str, *words: str) -> str:
    return '. ' + shlex.quote(env) + ' && exec curl -sS --max-time 30 ' + shlex.join(words)


def run_constrained_acceptance(workspace: Path, ssh: GuestSSH, bin_dir: Path) -> dict:
    report: dict = {'ok': False, 'profile': 'constrained-http', 'translator': 'guest'}
    with LocalProvider(workspace / 'provider') as provider:
        write(workspace / 'policy.json', offline.policy(workspace / 'host-credential', provider))
        write(workspace / 'disclosure.json', offline.disclosure())
        write(workspace / 'credential', offline.FAKE_TOKEN + '\n')
        spec = write(workspace / 'session.json',
                     session_spec(workspace, ssh, bin_dir, provider, free_port()))
        process = subprocess.Popen(
            [sys.executable, '-I', '-m', 'aivm_secrets', 'native-session', '--spec', str(spec)],
            cwd=REPO_ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=safe_environment())
        guest_dir = ''
        try:
            if not select.select([process.stdout], [], [], 180)[0]:
                raise DemoError('native-session did not announce')
            announcement = json.loads(process.stdout.readline())
            if announcement.get('ready') is not True:
                raise DemoError(f"native-session refused: {announcement.get('error')}")
            guest_dir, env = announcement['guest']['dir'], announcement['guest']['env']
            base = f'https://{provider.host}/repos/{offline.REPOSITORY.lower()}/pulls/'
            allowed = ssh.call(_curl(env, '--fail', base + str(offline.PR)))
            if allowed.returncode or json.loads(allowed.stdout).get('diff') != offline.DIFF:
                raise DemoError('the allowed read through the guest translator failed')
            # The host bridge runs its own `pull` check, then the diff.
            seen = provider.seen()
            if (len(seen) != 2 or {r['authorization'] for r in seen} != {'Bearer ' + offline.FAKE_TOKEN}
                    or {r['path'] for r in seen} != {offline.PULL_PATH}):
                raise DemoError('the provider did not see the check and the read, both substituted')
            report['allowed_read'] = True
            for target in (base + str(OTHER_PR), f'https://{provider.host}/user'):
                refused = ssh.call(_curl(env, '-o', '/dev/null', '-w', '%{http_code}', target))
                if refused.stdout.strip() == b'200':
                    raise DemoError('a request outside the named operations succeeded')
            if len(provider.seen()) != 2:
                raise DemoError('a refused request reached the provider')
            report['outside_named_operations_refused'] = True
            scan = ssh.call('grep -rqF ' + shlex.quote(offline.FAKE_TOKEN) + ' '
                            + shlex.quote(guest_dir))
            if scan.returncode != 1:
                raise DemoError('the credential appeared in the guest session directory')
            report['credential_absent_from_guest'] = True
        finally:
            if process.stdin:
                process.stdin.close()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
        if guest_dir:
            left = ssh.call('test -e ' + shlex.quote(guest_dir))
            report['guest_session_removed'] = left.returncode != 0
            if not report['guest_session_removed']:
                raise DemoError('the guest session directory was not removed')
        report['provider_requests'] = len(provider.seen())
    report['ok'] = True
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', default='aivm-2404', help='existing managed AIVM VM')
    parser.add_argument('--bin-dir', type=Path, default=REPO_ROOT / 'rust/target/debug',
                        help='directory containing the garrett-* binaries')
    args = parser.parse_args(argv)
    try:
        vm = validate_vm_name(args.vm)
        with tempfile.TemporaryDirectory(prefix='garrett-constrained-vm-', dir='/tmp') as temporary:
            workspace = Path(temporary)
            config = ssh_configuration(workspace, vm)
            report = run_constrained_acceptance(workspace, GuestSSH(vm, config),
                                                args.bin_dir.absolute())
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (DemoError, OSError, ValueError, UnicodeError) as error:
        print(f'AIVM constrained acceptance failed: {type(error).__name__}: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
