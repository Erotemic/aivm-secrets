#!/usr/bin/env python3
"""Opt-in OUT-6 proxy-profile check across a real AIVM VM boundary (HP-3/HP-7).

Runs `aivm-secrets proxy-session` (native `garrett-proxy` by default, or the
Python reference with --python) against a synthetic loopback provider and a
synthetic credential, with the guest reached over the VM's own SSH config:

1. stock `curl` in the guest, using only the published `env` file, reads one
   allowed path; the provider must see the substituted credential;
2. an unlisted origin through the proxy is refused with no provider traffic;
3. no file in the guest session directory contains the credential;
4. with --egress-check, report whether the guest can open a direct public
   connection (expected blocked only when AIVM `firewall.public_egress` is
   false);
5. closing the session removes the guest directory.

Only synthetic credentials; never changes firewall rules or forwards an
agent. Finite evidence for the credential-substitution profile, which makes
no authority-confinement claim.
"""
from __future__ import annotations

import argparse
import json
import select
import shlex
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
from aivm_secrets.kernel.presets import GITHUB_JSON

GUEST_PORT = 18443


def proxy_policy(provider: LocalProvider) -> dict:
    return dict(schema=1, profile='credential-substitution', lifetime_seconds=900,
                origins=[dict(host=provider.host, address='127.0.0.1', port=provider.port,
                              ca_file=str(provider.files['ca']), authentication='bearer')],
                deny=[dict(method='*', path='/admin/')])


def session_spec(workspace: Path, ssh: GuestSSH, bin_dir: Path | None) -> dict:
    return dict(version=1, bin_dir=str(bin_dir) if bin_dir else None,
                policy_file=str(workspace / 'proxy.json'),
                credential_file=str(workspace / 'credential'),
                audit_file=str(workspace / 'proxy-audit.jsonl'),
                guest=dict(kind='ssh', ssh_config=str(ssh.config), host=ssh.vm),
                guest_port=GUEST_PORT)


def _curl(env: str, *words: str) -> str:
    return '. ' + shlex.quote(env) + ' && exec curl -sS --max-time 20 ' + shlex.join(words)


def run_proxy_acceptance(workspace: Path, ssh: GuestSSH, bin_dir: Path | None,
                         *, egress_check: bool) -> dict:
    report: dict = {'ok': False, 'profile': 'credential-substitution',
                    'backend': 'native' if bin_dir else 'python'}
    with LocalProvider(workspace / 'provider') as provider:
        write(workspace / 'proxy.json', proxy_policy(provider))
        write(workspace / 'credential', offline.FAKE_TOKEN + '\n')
        spec = write(workspace / 'session.json', session_spec(workspace, ssh, bin_dir))
        process = subprocess.Popen(
            [sys.executable, '-I', '-m', 'aivm_secrets', 'proxy-session', '--spec', str(spec)],
            cwd=REPO_ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=safe_environment())
        guest_dir = ''
        try:
            if not select.select([process.stdout], [], [], 120)[0]:
                raise DemoError('proxy-session did not announce')
            announcement = json.loads(process.stdout.readline())
            if announcement.get('ready') is not True:
                raise DemoError(f"proxy-session refused: {announcement.get('error')}")
            guest_dir, env = announcement['guest']['dir'], announcement['guest']['env']
            allowed = ssh.call(_curl(env, '--fail', '-H', 'Accept: ' + GITHUB_JSON,
                                     f'https://{provider.host}{offline.PULL_PATH}'))
            if allowed.returncode or json.loads(allowed.stdout).get('number') != offline.PR:
                raise DemoError('the allowed read through the proxy failed')
            seen = provider.seen()
            if len(seen) != 1 or seen[0]['authorization'] != 'Bearer ' + offline.FAKE_TOKEN:
                raise DemoError('the provider did not see exactly one substituted credential')
            report['allowed_read'] = True
            unlisted = ssh.call(_curl(env, '-o', '/dev/null', '-w', '%{http_code}',
                                      'https://example.com/'))
            if unlisted.returncode == 0 and unlisted.stdout.strip() not in (b'000', b'403'):
                raise DemoError('an unlisted origin was reachable through the proxy')
            if len(provider.seen()) != 1:
                raise DemoError('the unlisted request reached the provider')
            report['unlisted_origin_refused'] = True
            scan = ssh.call('grep -rqF ' + shlex.quote(offline.FAKE_TOKEN) + ' '
                            + shlex.quote(guest_dir))
            if scan.returncode != 1:
                raise DemoError('the credential appeared in the guest session directory')
            report['credential_absent_from_guest'] = True
            if egress_check:
                direct = ssh.call('exec curl -sS --noproxy "*" --max-time 8 -o /dev/null '
                                  'https://1.1.1.1/', timeout=30)
                report['direct_public_egress_reachable'] = direct.returncode == 0
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
    report['authority_confinement_claimed'] = False
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', default='aivm-2404', help='existing managed AIVM VM')
    parser.add_argument('--bin-dir', type=Path, default=REPO_ROOT / 'rust/target/debug',
                        help='directory containing garrett-proxy')
    parser.add_argument('--python', action='store_true', help='use the Python reference proxy')
    parser.add_argument('--egress-check', action='store_true',
                        help='also report whether direct public egress is reachable')
    args = parser.parse_args(argv)
    try:
        vm = validate_vm_name(args.vm)
        with tempfile.TemporaryDirectory(prefix='garrett-proxy-vm-', dir='/tmp') as temporary:
            workspace = Path(temporary)
            config = ssh_configuration(workspace, vm)
            report = run_proxy_acceptance(
                workspace, GuestSSH(vm, config),
                None if args.python else args.bin_dir.absolute(),
                egress_check=args.egress_check)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (DemoError, OSError, ValueError, UnicodeError) as error:
        print(f'AIVM proxy acceptance failed: {type(error).__name__}: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
