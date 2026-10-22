#!/usr/bin/env python3
"""Opt-in OUT-2 native Garrett smoke test across a real AIVM VM boundary.

Only synthetic provider credentials.  Never mounts host custody into the VM,
changes guest firewall rules, or forwards the host's SSH agent.  The real
Garrett client creates its identity key inside the VM; the operator sends its
CSR to the native host authority.  A temporary SSH StreamLocalForward relays
only the native mTLS application socket.  This is finite evidence, not a
proof of whole-guest isolation or source-level noninterference.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# Works from a checkout without installing the development helpers as a package.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dev import offline_native_guest as offline
from dev.offline_native_guest import (
    DIFF,
    HEAD_SHA,
    PR,
    REPOSITORY,
    DemoError,
    LocalProvider,
    authority_action,
    binaries,
    bridge_config,
    disclosure,
    policy,
    safe_environment,
    start_bridge,
    stop_bridge,
    validate_disclosure_coverage,
    validate_sent,
    write,
)
from aivm_secrets.identity.certificates import inspect_csr

# Only the operator-selected VM name and the automatically generated private
# guest workspace are interpolated into the SSH command line or guest shell.
VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
GUEST_DIR = re.compile(r"/tmp/garrett-out2\.[A-Za-z0-9]{8,16}\Z")


def validate_vm_name(value: str) -> str:
    if not VM_NAME.fullmatch(value):
        raise DemoError('invalid AIVM VM name')
    return value


def inspect_vm_listing(output: str, vm: str) -> None:
    """Refuse to weaken or silently disable the configured AIVM firewall."""
    found = [line.strip() for line in output.splitlines()
             if line.lstrip().startswith(f'- {vm} |')]
    if len(found) != 1:
        raise DemoError(f'managed VM {vm} was not found uniquely by aivm vm list')
    if not re.search(r'\bstrict_firewall=yes\b', found[0]):
        raise DemoError('the selected VM is not configured with strict_firewall=yes')


def inspect_ssh_config(output: str, vm: str) -> None:
    """AIVM provides the SSH target; never infer an IP or identity ourselves."""
    lines = output.splitlines()
    if f'Host {vm}' not in [line.strip() for line in lines]:
        raise DemoError('aivm vm ssh_config does not select the requested VM')
    if re.search(r'^\s*HostName\s+VM_IP_UNKNOWN\s*$', output, re.M):
        raise DemoError('VM IP not cached; run aivm vm wait_ip first')
    for key in ('HostName', 'User', 'IdentityFile'):
        if not re.search(rf'^\s*{key}\s+\S+', output, re.M):
            raise DemoError(f'aivm vm ssh_config lacks {key}')
    # AIVM's ssh_config returns one Host block.  Don't copy agent forwarding
    # directives or arbitrary local SSH command execution into this fixture.
    if len(re.findall(r'^\s*Host\s+\S+', output, re.M)) != 1:
        raise DemoError('expected one AIVM SSH host stanza')
    if re.search(r'^\s*(ProxyCommand|LocalCommand|RemoteCommand|Match|Include)\b', output, re.I | re.M):
        raise DemoError('unexpected executable SSH directive in AIVM config')


def _local_command(args: list[str], *, label: str, timeout: int = 20) -> bytes:
    try:
        result = subprocess.run(args, capture_output=True, env=safe_environment(), timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise DemoError(f'{label} could not run ({type(ex).__name__})') from None
    if result.returncode:
        raise DemoError(f'{label} failed (exit {result.returncode})')
    return result.stdout


def ssh_configuration(workspace: Path, vm: str) -> Path:
    listing = _local_command(['aivm', 'vm', 'list'], label='AIVM VM listing')
    inspect_vm_listing(listing.decode('utf-8', 'replace'), vm)
    value = _local_command(['aivm', 'vm', 'ssh_config'], label='AIVM SSH configuration')
    try:
        config = value.decode('utf-8')
    except UnicodeDecodeError:
        raise DemoError('AIVM SSH configuration is not UTF-8') from None
    inspect_ssh_config(config, vm)
    return write(workspace / 'vm-ssh.conf', config)


@dataclass
class GuestSSH:
    vm: str
    config: Path

    def base(self) -> list[str]:
        return [
            'ssh', '-F', str(self.config), '-T',
            '-o', 'BatchMode=yes', '-o', 'ForwardAgent=no',
            '-o', 'ForwardX11=no', '-o', 'PermitLocalCommand=no',
            '-o', 'ControlMaster=no', '-o', 'ConnectTimeout=10',
            '-o', 'LogLevel=ERROR',
        ]

    def call(self, script: str, *, data: bytes | None = None,
             timeout: int = 35) -> subprocess.CompletedProcess[bytes]:
        command = [*self.base(), '-o', 'ClearAllForwardings=yes', self.vm,
                   'sh -c ' + shlex.quote(script)]
        try:
            result = subprocess.run(command, input=data, capture_output=True,
                                    env=safe_environment(), timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as ex:
            raise DemoError(f'guest SSH execution failed ({type(ex).__name__})') from None
        if offline.FAKE_TOKEN.encode() in (result.stdout + result.stderr):
            raise DemoError('synthetic provider credential appeared in guest output')
        return result

    def required(self, script: str, *, label: str,
                 data: bytes | None = None, timeout: int = 35) -> bytes:
        result = self.call(script, data=data, timeout=timeout)
        if result.returncode:
            raise DemoError(f'{label} failed in guest (exit {result.returncode})')
        return result.stdout

    def publish(self, remote: str, data: bytes, *, executable: bool = False) -> None:
        # Guest-owned private mktemp directory; POSIX noclobber prevents silent
        # replacement if a file already exists at this name.
        script = 'set -eu; umask 077; set -C; cat > ' + shlex.quote(remote)
        if executable:
            script += '; chmod 700 ' + shlex.quote(remote)
        self.required(script, label='distribute guest-only material',
                      data=data, timeout=120)

    def guest_tmpdir(self) -> str:
        value = self.required('umask 077; mktemp -d /tmp/garrett-out2.XXXXXXXX',
                              label='create guest-private workspace')
        result = value.decode('ascii', 'strict').strip()
        if not GUEST_DIR.fullmatch(result):
            raise DemoError('guest returned an invalid private workspace path')
        return result

    def remove_tmpdir(self, directory: str) -> None:
        if GUEST_DIR.fullmatch(directory):
            self.required('rm -rf -- ' + shlex.quote(directory),
                          label='remove temporary VM client identity', timeout=20)

    def forward(self, *, remote_socket: str, host_socket: Path) -> subprocess.Popen[bytes]:
        # No TCP listen sockets and no VM firewall changes.  Explicitly disable
        # agent/X11 forwarding; forward just this application Unix socket.
        command = [*self.base(), '-o', 'ExitOnForwardFailure=yes',
                   '-o', 'StreamLocalBindMask=0177', '-N',
                   '-R', f'{remote_socket}:{host_socket}', self.vm]
        try:
            return subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, env=safe_environment())
        except OSError:
            raise DemoError('could not start SSH application-socket forward') from None


def _guest_command(guest: str, *words: str) -> str:
    return 'exec ' + shlex.join([
        f'{guest}/garrett-client', '--config', f'{guest}/client.json',
        '--capability-file', f'{guest}/capability.jwt', *words,
    ])


def _read_output(result: subprocess.CompletedProcess[bytes], stage: str) -> object:
    if result.returncode:
        raise DemoError(f'{stage} failed (exit {result.returncode})')
    try:
        return json.loads(result.stdout)
    except (UnicodeError, ValueError):
        raise DemoError(f'{stage} produced invalid JSON') from None


def _expect_path_not_readable(ssh: GuestSSH, path: Path, *, label: str) -> None:
    cmd = 'if test -e ' + shlex.quote(str(path)) + ' || test -r ' + shlex.quote(str(path)) + \
        '; then exit 13; else exit 0; fi'
    if ssh.call(cmd).returncode:
        raise DemoError(f'VM can reach a host-private {label} path')


def _wait_for_forward(ssh: GuestSSH, process: subprocess.Popen[bytes], socket_path: str) -> None:
    for _ in range(40):
        if process.poll() is not None:
            raise DemoError('SSH Unix-socket forwarding failed; inspect guest sshd AllowStreamLocalForwarding')
        result = ssh.call('test -S ' + shlex.quote(socket_path))
        if result.returncode == 0:
            permissions = ssh.required('stat -c %a ' + shlex.quote(socket_path),
                                       label='inspect guest forwarded socket').decode('ascii').strip()
            try:
                mode = int(permissions, 8)
            except ValueError:
                raise DemoError('guest forwarded socket has invalid mode') from None
            if mode & 0o077:
                raise DemoError('guest application socket has group/other access')
            return
        time.sleep(0.15)
    raise DemoError('guest application socket did not appear')


def _stop_forward(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def run_vm_acceptance(workspace: Path, ssh: GuestSSH, bin_dir: Path) -> dict:
    tools = binaries(bin_dir)
    host = workspace / 'host'
    host.mkdir(mode=0o700)
    (host / 'provider').mkdir(mode=0o700)
    # A new token for each run: no credential value is embedded in the
    # repository or guest executable.  Existing synthetic fixtures share
    # this one process-local value for exact provider-header validation.
    offline.FAKE_TOKEN = 'github_pat_OFFLINE_VM_' + secrets.token_hex(32)
    write(host / 'credential', offline.FAKE_TOKEN)
    guest = ''
    bridge = None
    tunnel = None
    try:
        # The remotely executed shell is a real VM, not the operator host or
        # an AIVM-mounted directory.  Only accept the intended KVM/QEMU mode.
        virt = ssh.required('systemd-detect-virt --vm', label='verify VM boundary').decode('ascii').strip()
        if virt not in {'kvm', 'qemu'}:
            raise DemoError('SSH target is not reported as a KVM/QEMU VM')
        guest = ssh.guest_tmpdir()
        guest_arch = ssh.required('uname -m', label='guest architecture').decode('ascii').strip()
        if guest_arch != os.uname().machine:
            raise DemoError('guest and host architectures differ; cross-build garrett-client first')
        # Binary and identity private key live in the guest; the private key
        # never transits through the host SSH client or operator filesystem.
        ssh.publish(f'{guest}/garrett-client', tools['client'].read_bytes(), executable=True)
        csr_response = ssh.required('exec ' + shlex.join([
            f'{guest}/garrett-client', 'request', '--key-mode', 'software',
            '--key', f'{guest}/client.key', '--csr', f'{guest}/client.csr',
        ]), label='guest native key/CSR generation', timeout=75)
        try:
            csr_manifest = json.loads(csr_response)
        except (ValueError, UnicodeError):
            raise DemoError('guest CSR metadata is not JSON') from None
        csr = ssh.required('cat ' + shlex.quote(f'{guest}/client.csr'),
                           label='retrieve guest public CSR')
        fingerprint = inspect_csr(csr)
        if csr_manifest.get('key_fingerprint') != fingerprint:
            raise DemoError('guest CSR fingerprint changed during transport')
        csr_host_path = write(host / 'guest.csr', csr)
        authority_action(tools['authority'], host, 'init',
                         issuer='aivm.test', audience='aivm-secrets.remote')
        authority_action(tools['authority'], host, 'enroll',
                         subject='offline-guest', csr_file=str(csr_host_path),
                         approve_fingerprint=fingerprint)
        public = authority_action(tools['authority'], host, 'public-client', subject='offline-guest')
        ssh.publish(f'{guest}/ca.pem', base64.b64decode(public['ca_pem_b64']))
        ssh.publish(f'{guest}/client.pem', base64.b64decode(public['certificate_pem_b64']))
        # Host paths must be inaccessible *before* application-socket forwarding.
        _expect_path_not_readable(ssh, host / 'credential', label='credential')
        _expect_path_not_readable(ssh, host / 'authority', label='authority')
        with LocalProvider(host / 'provider') as provider:
            manifest = policy(host, provider)
            releases = disclosure()
            validate_disclosure_coverage(manifest, releases)
            write(host / 'policy.json', manifest)
            write(host / 'disclosure.json', releases)
            config = bridge_config(host, provider)
            config['binding']['vm'] = ssh.vm
            write(host / 'bridge.json', config)
            bridge, ready = start_bridge(tools['bridge'], host)
            ssh.publish(f'{guest}/capability.jwt', ready['capability'].encode('utf-8'))
            client_cfg = {
                'schema': 1, 'key_mode': 'software',
                'socket': f'{guest}/broker.sock', 'server_name': 'localhost',
                'certificate': f'{guest}/client.pem',
                'private_key': f'{guest}/client.key',
                'server_ca': f'{guest}/ca.pem',
            }
            ssh.publish(f'{guest}/client.json', json.dumps(client_cfg).encode('utf-8'))
            # The broker's privileged socket and provider never leave the host.
            _expect_path_not_readable(ssh, host / 'identity.sock', label='privileged broker socket')
            tunnel = ssh.forward(remote_socket=f'{guest}/broker.sock',
                                 host_socket=host / 'identity.sock')
            _wait_for_forward(ssh, tunnel, f'{guest}/broker.sock')
            view = _read_output(ssh.call(_guest_command(
                guest, 'gh', 'pr', 'view', str(PR), '--repo', REPOSITORY,
                '--json', 'number,title,headRefOid')), 'VM-approved PR view')
            expected = {'number': PR, 'title': 'Proof repair', 'headRefOid': HEAD_SHA}
            if view != expected:
                raise DemoError('VM guest received an unexpected PR view')
            diff = ssh.call(_guest_command(
                guest, 'gh', 'pr', 'diff', str(PR), '--repo', REPOSITORY))
            if diff.returncode or diff.stdout != DIFF.encode('utf-8'):
                raise DemoError('VM-approved PR diff did not match projection')
            requests_after_reads = len(provider.seen())
            if requests_after_reads != 3:
                raise DemoError('unexpected provider request count after VM reads')
            # Unlike an unsupported CLI operation, this reaches the native
            # broker with a named write and must fail before credentialed I/O.
            denied = ssh.call(_guest_command(
                guest, 'invoke', 'pr.comment', '--arguments',
                json.dumps({'repository': REPOSITORY, 'pr': PR,
                            'body': 'not authorized'}, separators=(',', ':'))))
            try:
                denial = json.loads(denied.stdout)
            except (ValueError, UnicodeError):
                raise DemoError('VM write refusal did not return public JSON') from None
            if (denied.returncode == 0 or denial.get('ok') is not False
                    or denial.get('error', {}).get('code') != 'denied'):
                raise DemoError('VM broker write was not denied')
            if len(provider.seen()) != requests_after_reads:
                raise DemoError('VM write refusal caused provider traffic')
            authority_action(tools['authority'], host, 'revoke', subject='offline-guest')
            revoked = ssh.call(_guest_command(
                guest, 'gh', 'pr', 'view', str(PR), '--repo', REPOSITORY,
                '--json', 'number'))
            if revoked.returncode == 0 or revoked.stdout:
                raise DemoError('revoked VM guest still obtained a PR view')
            if len(provider.seen()) != requests_after_reads:
                raise DemoError('revoked VM guest reached the provider')
            audit_bytes = (host / 'provider-audit.jsonl').read_bytes()
            if offline.FAKE_TOKEN.encode() in audit_bytes or ready['capability'].encode() in audit_bytes:
                raise DemoError('host audit contains private credential or surrogate')
            witness = validate_sent(provider, expected_count=3)
            write(host / 'provider-observations.json', {'requests': witness})
            return {
                'ok': True, 'mode': 'native-rust/aivm-kvm/synthetic-local-https',
                'vm': ssh.vm, 'virtualization': virt,
                'approved_view': view, 'approved_diff': True,
                'denied_write': True, 'revocation_fenced': True,
                'host_private_paths_unreadable_in_guest': True,
                'application_socket_forwarding': 'ssh-remote-unix/mTLS',
                'provider_requests': witness,
                'filesystem_isolation_proved': False,
                'whole_service_secrecy_proved': False,
            }
    finally:
        # Every teardown step runs even if the prior one reports an error.
        # In particular, a failed host cleanup must not strand guest keys.
        try:
            if tunnel is not None:
                _stop_forward(tunnel)
        finally:
            try:
                if bridge is not None:
                    stop_bridge(bridge)
            finally:
                if guest:
                    ssh.remove_tmpdir(guest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm', default='aivm-2404', help='existing managed AIVM VM')
    parser.add_argument('--workspace', type=Path,
                        help='new private host evidence directory under trusted ancestors')
    parser.add_argument('--bin-dir', type=Path, default=REPO_ROOT / 'rust/target/debug',
                        help='directory containing native Rust executables')
    args = parser.parse_args(argv)
    try:
        vm = validate_vm_name(args.vm)
        binaries(args.bin_dir.absolute())
        if args.workspace is None:
            with tempfile.TemporaryDirectory(prefix='garrett-vm-', dir='/tmp') as temporary:
                workspace = Path(temporary)
                config = ssh_configuration(workspace, vm)
                report = run_vm_acceptance(workspace, GuestSSH(vm, config),
                                           args.bin_dir.absolute())
        else:
            workspace = args.workspace.absolute()
            workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
            config = ssh_configuration(workspace, vm)
            report = run_vm_acceptance(workspace, GuestSSH(vm, config),
                                       args.bin_dir.absolute())
            write(workspace / 'summary.json', report)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (DemoError, OSError, ValueError, UnicodeError) as error:
        # No subprocess output: the host/guest processes may have sensitive data.
        print(f'AIVM Garrett acceptance failed: {type(error).__name__}: {error}',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
