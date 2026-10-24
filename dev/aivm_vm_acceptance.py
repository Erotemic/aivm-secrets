#!/usr/bin/env python3
"""Opt-in OUT-2 native Garrett smoke test across a real AIVM VM boundary.

Only synthetic provider credentials.  Never mounts host custody into the VM,
changes guest firewall rules, or forwards the host's SSH agent.  The real
Garrett client creates its identity key inside the VM; the operator sends its
CSR to the native host authority.  A temporary SSH StreamLocalForward relays
only the native mTLS application socket.  The optional --adversarial mode
adds controlled negative tests without changing production security policy.
This is finite evidence, not a proof of whole-guest isolation or source-level
noninterference.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
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



def _client_command(guest: str, *, config: str = 'client.json',
                    capability: str = 'capability.jwt', words: tuple[str, ...]) -> str:
    """Invoke the native client with one expressly selected guest-only identity."""
    for name in (config, capability):
        if not re.fullmatch(r'[a-z][a-z0-9._-]{0,63}', name):
            raise DemoError('invalid guest client material filename')
    return 'exec ' + shlex.join([
        f'{guest}/garrett-client', '--config', f'{guest}/{config}',
        '--capability-file', f'{guest}/{capability}', *words,
    ])


def _reject_without_provider_effect(ssh: GuestSSH, provider: LocalProvider,
                                    count: int, command: str, *, label: str) -> None:
    """Reject on the VM and verify independently that no provider I/O occurred."""
    result = ssh.call(command)
    if result.returncode == 0:
        raise DemoError(f'{label}: untrusted guest request succeeded')
    if result.stdout:
        try:
            public = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise DemoError(f'{label}: unexpected guest output on refusal') from None
        if not isinstance(public, dict) or public.get('ok') is not False:
            raise DemoError(f'{label}: guest received a potentially released result')
    if len(provider.seen()) != count:
        raise DemoError(f'{label}: rejected request caused provider traffic')


def _corrupt_capability(jwt: str) -> str:
    """Change a SIGNED segment byte, not unused base64url padding bits."""
    parts = jwt.split('.')
    if len(parts) != 3 or len(parts[2]) < 16 or not re.fullmatch(r'[A-Za-z0-9_-]+', parts[2]):
        raise DemoError('native capability has an unexpected compact-JWS shape')
    first = parts[2][0]
    parts[2] = ('A' if first != 'A' else 'B') + parts[2][1:]
    return '.'.join(parts)


def _parse_guest_default_gateway(routes: str) -> str:
    """Require one IPv4 default gateway from guest /proc/net/route."""
    gateways: set[str] = set()
    for line in routes.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[1] != '00000000':
            continue
        try:
            if not (int(fields[3], 16) & 0x2):
                continue
            address = socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])
            parsed = ipaddress.IPv4Address(address)
        except (ValueError, OSError):
            raise DemoError('guest has malformed IPv4 route evidence') from None
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            raise DemoError('guest has an invalid default gateway')
        gateways.add(address)
    if len(gateways) != 1:
        raise DemoError('guest must report exactly one default IPv4 gateway for the canary')
    return next(iter(gateways))


def _guest_tcp_reachable(ssh: GuestSSH, address: str, port: int) -> bool:
    """Use a bounded guest TCP connection probe; fail on missing guest Python."""
    address = str(ipaddress.IPv4Address(address))
    if not (1 <= port <= 65535):
        raise DemoError('invalid host canary port')
    script = (
        'import socket,sys; '
        's=socket.socket(socket.AF_INET,socket.SOCK_STREAM); '
        's.settimeout(2); '
        'rc=s.connect_ex((sys.argv[1],int(sys.argv[2]))); '
        's.close(); sys.exit(0 if rc==0 else 17)'
    )
    result = ssh.call('python3 -c ' + shlex.quote(script) + ' '
                      + shlex.quote(address) + ' ' + str(port), timeout=12)
    if result.returncode not in {0, 17} or result.stdout:
        raise DemoError('guest TCP probe did not return its bounded status')
    return result.returncode == 0


def _probe_direct_egress(ssh: GuestSSH, provider: LocalProvider) -> dict:
    """Can a guest contact a deliberately exposed *credential-free* host canary?

    Never assumes the configured strict firewall is installed: the kernel
    behavior is tested.  Does not modify firewall state or serve credentials.
    """
    routes = ssh.required('cat /proc/net/route', label='inspect guest default route')
    gateway = _parse_guest_default_gateway(routes.decode('ascii', 'strict'))
    if _guest_tcp_reachable(ssh, gateway, provider.port):
        raise DemoError('VM can directly contact the host-only synthetic provider port')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as canary:
        try:
            canary.bind((gateway, 0))  # prove this gateway address belongs to the host
        except OSError:
            raise DemoError('host could not bind the guest gateway for canary verification') from None
        canary.listen(1)
        port = canary.getsockname()[1]
        reached = _guest_tcp_reachable(ssh, gateway, port)
        canary.settimeout(0.3)
        try:
            connection, _ = canary.accept()
        except socket.timeout:
            accepted = False
        else:
            connection.close()
            accepted = True
        if reached or accepted:
            raise DemoError('VM reached a non-allowlisted host TCP canary')
    return {
        'host_gateway_canary_denied': True,
        'direct_synthetic_provider_tcp_denied': True,
        'scope': 'guest gateway TCP: one ephemeral canary and the host-loopback provider port',
    }


def _parse_share_mounts(text: str) -> list[dict]:
    """virtiofs/9p entries of a mountinfo table: device, root within the
    share, and mount point (octal escapes decoded)."""
    def unescape(field: str) -> str:
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), field)
    shares = []
    for line in text.splitlines():
        if ' - ' not in line:
            continue
        before, after = line.split(' - ', 1)
        fields, tail = before.split(), after.split()
        if len(fields) < 5 or not tail or tail[0] not in {'virtiofs', '9p'}:
            continue
        shares.append({'device': fields[2], 'root': unescape(fields[3]),
                       'mount_point': unescape(fields[4]), 'type': tail[0]})
    return shares


def _share_aliases(shares: list[dict]) -> dict:
    """Group share mounts by device. A mount is an alias when another mount
    of the same device has the same or an enclosing root, so the same host
    files are reachable at two guest paths (e.g. AIVM's persistent root plus
    its per-directory bind mounts)."""
    def within(inner: str, outer: str) -> bool:
        return outer == '/' or inner == outer or inner.startswith(outer.rstrip('/') + '/')
    aliased = 0
    for index, mount in enumerate(shares):
        if any(other['device'] == mount['device'] and within(mount['root'], other['root'])
               for position, other in enumerate(shares) if position != index):
            aliased += 1
    return {
        'attachment_devices': len({mount['device'] for mount in shares}),
        'whole_share_root_mounts': sum(mount['root'] == '/' for mount in shares),
        'aliased_mounts': aliased,
    }


def _guest_canary_search(ssh: GuestSSH, mount_points: list[str], marker: str) -> dict:
    """Bounded search of the guest's share mount points for the host canary
    file name. Depth and time are capped (a whole-tree walk of a large
    virtiofs share can exhaust the host daemon's file handles), so a
    timeout is reported as incomplete, never as absence.

    The search runs as guest root when passwordless sudo is available, as it
    is for AIVM's default guest user: an agent with that sudo reads whatever
    root reads, including AIVM's root-only staging mounts. An unprivileged
    search there would stop at a permission error and say nothing."""
    if not mount_points:
        return {'found': False, 'complete': True, 'mount_points_searched': 0}
    script = ('if sudo -n true 2>/dev/null; then run="sudo -n"; echo as_root=1; '
              'else run=""; echo as_root=0; fi; '
              'timeout 20 $run find ' + ' '.join(shlex.quote(m) for m in mount_points)
              + ' -xdev -maxdepth 4 -name ' + shlex.quote(marker) + ' -print -quit 2>/dev/null; '
              'echo "status=$?"')
    result = ssh.call(script)
    text = result.stdout.decode('utf-8', 'replace')
    if marker in text:
        raise DemoError('host custody canary is reachable through a guest share')
    status = re.search(r'status=(\d+)', text)
    return {'found': False, 'complete': bool(status) and status.group(1) == '0',
            'as_guest_root': 'as_root=1' in text,
            'mount_points_searched': len(mount_points), 'max_depth': 4}


def _guest_mount_inventory(ssh: GuestSSH, host: Path, marker: str | None = None) -> dict:
    """Record share attachments and their aliases; don't mistake enumeration
    for an isolation proof."""
    info = ssh.required('cat /proc/self/mountinfo', label='inspect guest mounts')
    text = info.decode('utf-8', 'replace')
    if str(host) in text:
        raise DemoError('guest mount table mentions the host custody workspace')
    shares = _parse_share_mounts(text)
    result = {
        'attachment_mounts_observed': len(shares),
        **_share_aliases(shares),
        'host_workspace_in_mount_table': False,
        'scope': ('mount table metadata, alias grouping and a depth-4 search for the '
                  'host canary name; not an exhaustive reachability proof'),
    }
    if marker is not None:
        result['canary_search'] = _guest_canary_search(
            ssh, sorted({mount['mount_point'] for mount in shares}), marker)
    return result


def _prepare_independent_identity(ssh: GuestSSH, guest: str, host: Path,
                                  authority: Path) -> None:
    """Enroll the *other subject* before the broker snapshots issuer state.

    Its private key is generated inside the VM and never crosses to the host.
    The broker boots with both CA-issued identities in its registry, so the
    later wrong-subject denial is not merely a missing-enrollment rejection.
    """
    ssh.required('exec ' + shlex.join([
        f'{guest}/garrett-client', 'request', '--key-mode', 'software',
        '--key', f'{guest}/other.key', '--csr', f'{guest}/other.csr',
    ]), label='create independent VM client identity')
    csr = ssh.required('cat ' + shlex.quote(f'{guest}/other.csr'),
                       label='retrieve independent public CSR')
    fingerprint = inspect_csr(csr)
    host_csr = write(host / 'other-guest.csr', csr)
    authority_action(authority, host, 'enroll', subject='other-guest',
                     csr_file=str(host_csr), approve_fingerprint=fingerprint)
    public = authority_action(authority, host, 'public-client', subject='other-guest')
    ssh.publish(f'{guest}/other.pem', base64.b64decode(public['certificate_pem_b64']))


def _probe_independent_identities(
    ssh: GuestSSH, guest: str, provider: LocalProvider,
    count: int, client_cfg: dict, jwt: str,
) -> dict:
    """Attempt wrong-subject TLS, mismatched key, and corrupted JWT reads."""
    other_cfg = {**client_cfg, 'certificate': f'{guest}/other.pem',
                 'private_key': f'{guest}/other.key'}
    ssh.publish(f'{guest}/other.json', json.dumps(other_cfg).encode('utf-8'))
    read = ('gh', 'pr', 'view', str(PR), '--repo', REPOSITORY, '--json', 'number')
    _reject_without_provider_effect(
        ssh, provider, count,
        _client_command(guest, config='other.json', words=read),
        label='independently enrolled wrong-subject identity')
    mismatch_cfg = {**client_cfg, 'private_key': f'{guest}/other.key'}
    ssh.publish(f'{guest}/mismatch.json', json.dumps(mismatch_cfg).encode('utf-8'))
    _reject_without_provider_effect(
        ssh, provider, count,
        _client_command(guest, config='mismatch.json', words=read),
        label='certificate/private-key mismatch')
    ssh.publish(f'{guest}/bad-capability.jwt', _corrupt_capability(jwt).encode('ascii'))
    _reject_without_provider_effect(
        ssh, provider, count,
        _client_command(guest, capability='bad-capability.jwt', words=read),
        label='tampered signed capability')
    return {'other_enrolled_subject_rejected': True,
            'certificate_key_mismatch_rejected': True,
            'tampered_capability_rejected': True}


def _probe_reenrolled_certificate(ssh: GuestSSH, guest: str, host: Path, authority: Path,
                                  provider: LocalProvider, count: int) -> dict:
    """Re-enroll the original subject with a NEW VM-generated key while the
    broker runs. The original certificate and capability must then be
    refused without provider traffic. Run last: it retires the guest's
    working identity (revocation follows)."""
    ssh.required('exec ' + shlex.join([
        f'{guest}/garrett-client', 'request', '--key-mode', 'software',
        '--key', f'{guest}/renewed.key', '--csr', f'{guest}/renewed.csr',
    ]), label='create replacement VM client key')
    csr = ssh.required('cat ' + shlex.quote(f'{guest}/renewed.csr'),
                       label='retrieve replacement public CSR')
    fingerprint = inspect_csr(csr)
    host_csr = write(host / 'renewed-guest.csr', csr)
    authority_action(authority, host, 'enroll', subject='offline-guest',
                     csr_file=str(host_csr), approve_fingerprint=fingerprint,
                     replace=True)
    _reject_without_provider_effect(
        ssh, provider, count,
        _guest_command(guest, 'gh', 'pr', 'view', str(PR), '--repo', REPOSITORY,
                       '--json', 'number'),
        label='certificate replaced by a live re-enrollment')
    return {'reenrolled_certificate_rejected': True}


def _invoke_json(ssh: GuestSSH, guest: str, operation: str, arguments: dict) -> dict:
    result = ssh.call(_guest_command(guest, 'invoke', operation, '--arguments',
                                     json.dumps(arguments, separators=(',', ':'))))
    try:
        reply = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise DemoError(f'{operation} did not return public JSON') from None
    if not isinstance(reply, dict):
        raise DemoError(f'{operation} returned a non-object reply')
    return reply


def _approved_write(ssh: GuestSSH, guest: str, host: Path, provider: LocalProvider,
                    count: int) -> tuple[dict, int]:
    """One exactly approved comment, end to end (OUT-4 rehearsal).

    The guest asks; the broker answers `approval_required` with a digest and
    sends nothing. The host operator approves that digest on the private
    control socket. A different comment still needs approval. The approved
    comment then runs once, and asking again needs a new approval."""
    from aivm_secrets.host.session import control_call

    comment = {'repository': REPOSITORY, 'pr': PR, 'body': 'synthetic approved comment'}
    first = _invoke_json(ssh, guest, 'pr.comment', comment)
    if first.get('error', {}).get('code') != 'approval_required' or len(provider.seen()) != count:
        raise DemoError('an unapproved write was not held for approval')
    digest = first.get('approval', {}).get('digest')
    pending = control_call(host, {'command': 'pending'}).get('pending', [])
    # The host shows the normalized request: the repository is folded to lowercase.
    if len(pending) != 1 or pending[0].get('arguments') != dict(comment, repository=REPOSITORY.lower()):
        raise DemoError('the host did not see exactly the pending comment')
    if not control_call(host, {'command': 'approve', 'digest': digest}).get('ok'):
        raise DemoError('the host could not approve the pending comment')
    other = _invoke_json(ssh, guest, 'pr.comment', dict(comment, body='a different comment'))
    if other.get('error', {}).get('code') != 'approval_required' or len(provider.seen()) != count:
        raise DemoError('an approval authorized a different comment')
    done = _invoke_json(ssh, guest, 'pr.comment', comment)
    if done.get('ok') is not True or done.get('result') != {'body': comment['body']}:
        raise DemoError('the approved comment did not run')
    sent = provider.seen()[count:]
    posts = [row for row in sent if row['method'] == 'POST']
    if len(posts) != 1 or json.loads(posts[0]['body']) != {'body': comment['body']}:
        raise DemoError('the provider did not receive exactly the approved comment once')
    count += len(sent)
    again = _invoke_json(ssh, guest, 'pr.comment', comment)
    if again.get('error', {}).get('code') != 'approval_required' or len(provider.seen()) != count:
        raise DemoError('a spent approval authorized a second comment')
    elsewhere = _invoke_json(ssh, guest, 'pr.comment', dict(comment, repository='attacker/elsewhere'))
    if elsewhere.get('ok') is not False or len(provider.seen()) != count:
        raise DemoError('a comment outside the grant was not refused')
    return {'held_for_approval': True, 'different_comment_still_held': True,
            'approved_comment_sent_once': True, 'approval_single_use': True,
            'other_repository_refused': True, 'provider_requests': len(sent)}, count


AGENT_ATTACK_LABELS = frozenset({
    'path_traversal_in_repository', 'encoded_slash_in_repository',
    'header_injection_in_repository', 'query_in_repository', 'other_repository',
    'other_pull_request', 'pr_as_path', 'pr_negative', 'pr_huge', 'pr_float',
    'extra_url_argument', 'missing_argument', 'arguments_not_an_object',
    'arguments_not_json', 'unknown_operation', 'unlisted_write', 'denied_write',
    'oversized_argument',
})


def _run_simulated_agent(ssh: GuestSSH, guest: str, provider: LocalProvider,
                         count: int) -> dict:
    """Run `dev/guest_agent.py` in the guest as an arbitrary untrusted program.

    Pass/fail comes from the agent's report *and* from the provider's own
    record: exactly its two allowed reads may reach the provider, on the one
    allowed path, whatever the agent claims."""
    ssh.publish(f'{guest}/guest_agent.py',
                (REPO_ROOT / 'dev' / 'guest_agent.py').read_bytes(), executable=True)
    result = ssh.call('exec python3 -I ' + shlex.join(
        [f'{guest}/guest_agent.py', guest, REPOSITORY, str(PR)]), timeout=600)
    if result.returncode:
        raise DemoError(f'simulated agent exited {result.returncode}')
    try:
        report = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise DemoError('simulated agent produced invalid JSON') from None
    attacks = report.get('attacks', {})
    if set(attacks) - {'plain_http_on_broker_socket', 'one_megabyte_of_garbage',
                       'tls_without_client_certificate'} != AGENT_ATTACK_LABELS:
        raise DemoError('simulated agent did not run the expected attacks')
    escaped = sorted(label for label in AGENT_ATTACK_LABELS if attacks[label] != 'refused')
    if escaped:
        raise DemoError(f'simulated agent was not refused: {", ".join(escaped)}')
    if not str(attacks['tls_without_client_certificate']).startswith('refused'):
        raise DemoError('a TLS client without a certificate got an answer')
    if report.get('useful_read') is not True or report.get('useful_read_after_attacks') is not True:
        raise DemoError('simulated agent could not do its allowed reads')
    seen = provider.seen()
    new = seen[count:]
    if len(new) != 2 or any(row['path'] != offline.PULL_PATH for row in new):
        raise DemoError('simulated agent caused provider traffic beyond its two allowed reads')
    return report


def _guest_credential_search(ssh: GuestSSH, guest: str) -> dict:
    """Search the whole guest, as root, for the credential and its encodings.

    The patterns travel on stdin, never in a guest file or argument list."""
    if ssh.call('sudo -n true').returncode:
        return {'ran': False, 'reason': 'no passwordless sudo in the guest'}
    ssh.publish(f'{guest}/guest_secret_hunt.py',
                (REPO_ROOT / 'dev' / 'guest_secret_hunt.py').read_bytes())
    token = offline.FAKE_TOKEN.encode()
    patterns = [token, base64.b64encode(token), base64.urlsafe_b64encode(token).rstrip(b'=')]
    result = ssh.call('exec sudo -n python3 -I ' + shlex.quote(f'{guest}/guest_secret_hunt.py'),
                      data=b''.join(p.hex().encode() + b'\n' for p in patterns), timeout=900)
    try:
        report = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise DemoError('guest credential search produced invalid JSON') from None
    if result.returncode or 'files_scanned' not in report:
        raise DemoError('guest credential search failed')
    if report['file_hits'] or report['process_hits']:
        raise DemoError('the provider credential was found in the guest: '
                        + ', '.join(report['file_hits'] + report['process_hits']))
    return {'ran': True, 'as_guest_root': True, 'patterns': len(patterns),
            'files_scanned': report['files_scanned'],
            'processes_scanned': report['processes_scanned'], 'found': False}


def run_vm_acceptance(workspace: Path, ssh: GuestSSH, bin_dir: Path,
                      *, adversarial: bool = False, agent: bool = False,
                      write_mode: bool = False) -> dict:
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
        if adversarial:
            _prepare_independent_identity(ssh, guest, host, tools['authority'])
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
            if write_mode:
                config['provider']['writes'] = 'approve'
                config['provider']['control_socket'] = str(host / 'control.sock')
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
            approved_write = None
            if write_mode:
                approved_write, requests_after_reads = _approved_write(
                    ssh, guest, host, provider, requests_after_reads)
            else:
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
            agent_report = None
            if agent:
                agent_report = _run_simulated_agent(ssh, guest, provider, requests_after_reads)
                requests_after_reads += 2
            attacks: dict = {}
            if adversarial:
                # A random file name in the host custody workspace: if any
                # guest share exposes the workspace, the search finds it.
                marker = 'aivm-secrets-canary-' + secrets.token_hex(12)
                write(host / marker, 'canary')
                attacks['mounts'] = _guest_mount_inventory(ssh, host, marker)
                attacks['network'] = _probe_direct_egress(ssh, provider)
                _reject_without_provider_effect(
                    ssh, provider, requests_after_reads,
                    _client_command(guest, words=(
                        'invoke', 'pr.view', '--arguments',
                        json.dumps({'repository': 'attacker/elsewhere', 'pr': PR},
                                   separators=(',', ':')))),
                    label='out-of-scope native read operation')
                attacks['out_of_scope_read_denied'] = True
                attacks['identities'] = _probe_independent_identities(
                    ssh, guest, provider, requests_after_reads,
                    client_cfg, ready['capability'])
                # Tear down the forward. The old capability is still active,
                # so the request must fail for transport reasons alone.
                _stop_forward(tunnel)
                tunnel = None
                _reject_without_provider_effect(
                    ssh, provider, requests_after_reads,
                    _guest_command(guest, 'gh', 'pr', 'view', str(PR),
                                   '--repo', REPOSITORY, '--json', 'number'),
                    label='disconnected application socket')
                # AIVM/sshd may leave the disconnected Unix path behind. Only
                # remove our own socket in the guest-owned private directory.
                ssh.required('rm -f -- ' + shlex.quote(f'{guest}/broker.sock'),
                             label='remove stale guest application socket')
                tunnel = ssh.forward(remote_socket=f'{guest}/broker.sock',
                                     host_socket=host / 'identity.sock')
                _wait_for_forward(ssh, tunnel, f'{guest}/broker.sock')
                recovered = _read_output(ssh.call(_guest_command(
                    guest, 'gh', 'pr', 'view', str(PR), '--repo', REPOSITORY,
                    '--json', 'number')), 'VM read after tunnel restoration')
                if recovered != {'number': PR}:
                    raise DemoError('restored VM tunnel failed an authorized read')
                requests_after_reads += 1
                if len(provider.seen()) != requests_after_reads:
                    raise DemoError('restored VM tunnel caused unexpected provider effects')
                attacks['lifecycle'] = {
                    'no_provider_effect_with_forward_disconnected': True,
                    'authorized_read_after_reconnect': True,
                }
                attacks['identities'].update(_probe_reenrolled_certificate(
                    ssh, guest, host, tools['authority'], provider, requests_after_reads))
            authority_action(tools['authority'], host, 'revoke', subject='offline-guest')
            revoked = ssh.call(_guest_command(
                guest, 'gh', 'pr', 'view', str(PR), '--repo', REPOSITORY,
                '--json', 'number'))
            if revoked.returncode == 0 or revoked.stdout:
                raise DemoError('revoked VM guest still obtained a PR view')
            if len(provider.seen()) != requests_after_reads:
                raise DemoError('revoked VM guest reached the provider')
            credential_search = _guest_credential_search(ssh, guest) if agent else None
            audit_bytes = (host / 'provider-audit.jsonl').read_bytes()
            if offline.FAKE_TOKEN.encode() in audit_bytes or ready['capability'].encode() in audit_bytes:
                raise DemoError('host audit contains private credential or surrogate')
            witness = validate_sent(provider, expected_count=requests_after_reads)
            write(host / 'provider-observations.json', {'requests': witness})
            return {
                'ok': True, 'mode': 'native-rust/aivm-kvm/synthetic-local-https',
                'vm': ssh.vm, 'virtualization': virt,
                'approved_view': view, 'approved_diff': True,
                'denied_write': not write_mode, 'revocation_fenced': True,
                **({'approved_write': approved_write} if write_mode else {}),
                'host_private_paths_unreadable_in_guest': True,
                'application_socket_forwarding': 'ssh-remote-unix/mTLS',
                'provider_requests': witness,
                **({'adversarial': attacks} if adversarial else {}),
                **({'simulated_agent': agent_report,
                    'guest_credential_search': credential_search} if agent else {}),
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
    parser.add_argument('--adversarial', action='store_true',
                        help='opt-in controlled VM identity/egress/socket attack checks')
    parser.add_argument('--write', action='store_true',
                        help='run the broker in approve mode and check one exactly approved comment')
    parser.add_argument('--agent', action='store_true',
                        help='also run dev/guest_agent.py in the guest and search the guest for the credential')
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
                                           args.bin_dir.absolute(),
                                           adversarial=args.adversarial, agent=args.agent,
                                       write_mode=args.write)
        else:
            workspace = args.workspace.absolute()
            workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
            config = ssh_configuration(workspace, vm)
            report = run_vm_acceptance(workspace, GuestSSH(vm, config),
                                       args.bin_dir.absolute(),
                                       adversarial=args.adversarial, agent=args.agent,
                                       write_mode=args.write)
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
