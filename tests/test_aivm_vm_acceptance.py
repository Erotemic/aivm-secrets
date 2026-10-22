"""Portable boundary tests for opt-in *real-VM* native acceptance tooling.

These do not simulate or claim a passing VM acceptance result.  Its actual
acceptance gate is `python dev/aivm_vm_acceptance.py --vm aivm-2404` on the
operator host with a running managed VM.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from dev.aivm_vm_acceptance import (
    DemoError, GuestSSH, _expect_path_not_readable, _guest_command,
    _read_output, inspect_ssh_config, inspect_vm_listing, validate_vm_name,
)


VM_LIST = '''Managed VMs
  Trust mode: kernel-identity
  - aivm-2404 | network=aivm-net | strict_firewall=yes | access=1/1 active
'''
VM_SSH = '''Host aivm-2404
  HostName 192.168.122.101
  User developer
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
'''


def test_selected_vm_requires_explicit_strict_firewall():
    inspect_vm_listing(VM_LIST, 'aivm-2404')
    with pytest.raises(DemoError, match='strict_firewall=yes'):
        inspect_vm_listing(VM_LIST.replace('strict_firewall=yes', 'strict_firewall=no'), 'aivm-2404')
    with pytest.raises(DemoError, match='not found'):
        inspect_vm_listing(VM_LIST, 'some-other-vm')
    with pytest.raises(DemoError, match='not found'):
        inspect_vm_listing(VM_LIST + VM_LIST, 'aivm-2404')


@pytest.mark.parametrize('malicious', [
    '../somewhere', 'vm name', 'foo; rm -rf /', 'foo/bar', '-R', 'foo\nBar',
])
def test_vm_name_rejects_shell_and_option_metacharacters(malicious):
    with pytest.raises(DemoError, match='VM name'):
        validate_vm_name(malicious)


def test_vm_ssh_config_must_match_exact_selected_target():
    inspect_ssh_config(VM_SSH, 'aivm-2404')
    with pytest.raises(DemoError, match='requested VM'):
        inspect_ssh_config(VM_SSH, 'aivm-other')
    with pytest.raises(DemoError, match='not cached'):
        inspect_ssh_config(VM_SSH.replace('192.168.122.101', 'VM_IP_UNKNOWN'), 'aivm-2404')
    with pytest.raises(DemoError, match='one AIVM SSH'):
        inspect_ssh_config(VM_SSH + '\nHost attacker\n  HostName 127.0.0.1\n', 'aivm-2404')
    with pytest.raises(DemoError, match='executable SSH directive'):
        inspect_ssh_config(VM_SSH + '  ProxyCommand nc badhost 1234\n', 'aivm-2404')


def test_guest_ssh_command_explicitly_disables_agent_and_existing_forwardings(tmp_path, monkeypatch):
    config = tmp_path / 'ssh.conf'
    config.write_text(VM_SSH)
    commands = []

    def fake_run(cmd, **kwargs):
        commands.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, b'kvm\n', b'')

    monkeypatch.setattr('dev.aivm_vm_acceptance.subprocess.run', fake_run)
    client = GuestSSH('aivm-2404', config)
    assert client.required('systemd-detect-virt --vm', label='vm boundary') == b'kvm\n'
    command, kwargs = commands[0]
    assert command[0] == 'ssh'
    assert '-F' in command and str(config) in command
    assert command[-2] == 'aivm-2404'
    assert 'ForwardAgent=no' in command
    assert 'ForwardX11=no' in command
    assert 'ClearAllForwardings=yes' in command
    assert 'BatchMode=yes' in command
    assert kwargs['input'] is None or 'input' not in kwargs


def test_ssh_forwards_only_unix_application_socket(tmp_path, monkeypatch):
    commands = []

    def fake_popen(cmd, **kwargs):
        commands.append((cmd, kwargs))
        return object()

    monkeypatch.setattr('dev.aivm_vm_acceptance.subprocess.Popen', fake_popen)
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    ssh.forward(remote_socket='/tmp/garrett-out2.abcd1234/broker.sock',
                host_socket=Path('/tmp/host-private/identity.sock'))
    cmd, kwargs = commands[0]
    assert '-N' in cmd and '-R' in cmd
    assert '/tmp/garrett-out2.abcd1234/broker.sock:/tmp/host-private/identity.sock' in cmd
    assert 'StreamLocalBindMask=0177' in cmd
    assert 'ForwardAgent=no' in cmd
    assert 'ExitOnForwardFailure=yes' in cmd
    assert 'ClearAllForwardings=yes' not in cmd
    assert kwargs['stdin'] == subprocess.DEVNULL
    assert kwargs['stdout'] == subprocess.DEVNULL


def test_guest_publication_is_private_and_exclusive(tmp_path, monkeypatch):
    calls = []
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')

    def fake_required(script, *, label, data=None, timeout=35):
        calls.append((script, label, data))
        return b''

    monkeypatch.setattr(ssh, 'required', fake_required)
    ssh.publish('/tmp/garrett-out2.abcd1234/garrett-client', b'ELF', executable=True)
    ssh.publish('/tmp/garrett-out2.abcd1234/ca.pem', b'CA')
    assert calls[0][0].startswith('set -eu; umask 077; set -C; cat > ')
    assert calls[0][0].endswith('; chmod 700 /tmp/garrett-out2.abcd1234/garrett-client')
    assert calls[0][2] == b'ELF'
    assert calls[1][2] == b'CA'
    assert 'chmod 700' not in calls[1][0]


def test_guest_client_config_has_no_host_paths_or_token():
    command = _guest_command('/tmp/garrett-out2.abcd1234', 'gh', 'pr', 'view', '13861')
    assert '--capability-file' in command
    assert '/tmp/garrett-out2.abcd1234/client.json' in command
    assert '/tmp/garrett-out2.abcd1234/capability.jwt' in command
    assert 'credential' not in command and 'authority' not in command
    assert 'FAKE_TOKEN' not in command


def test_unreadable_private_path_is_required(tmp_path, monkeypatch):
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    scripts = []

    def fake_call(script, **kwargs):
        scripts.append(script)
        return subprocess.CompletedProcess([], 0, b'', b'')

    monkeypatch.setattr(ssh, 'call', fake_call)
    _expect_path_not_readable(ssh, Path('/tmp/host/credential'), label='credential')
    assert 'test -e /tmp/host/credential' in scripts[0]
    assert 'test -r /tmp/host/credential' in scripts[0]
    monkeypatch.setattr(ssh, 'call', lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 13, b'', b'private detail'))
    with pytest.raises(DemoError, match='VM can reach') as ex:
        _expect_path_not_readable(ssh, Path('/tmp/host/authority'), label='authority')
    assert 'private detail' not in str(ex.value)


def test_guest_json_and_failure_output_not_leaked():
    result = subprocess.CompletedProcess([], 1, b'{"credential":"PRIVATE"}', b'PRIVATE')
    with pytest.raises(DemoError) as ex:
        _read_output(result, 'approved read')
    assert 'PRIVATE' not in str(ex.value)


# Adversarial mode extends the *same real-VM fixture*. These tests validate
# the probe invariants without representing themselves as a VM security result.
from dev.aivm_vm_acceptance import (
    _client_command,
    _corrupt_capability,
    _guest_mount_inventory,
    _guest_tcp_reachable,
    _parse_guest_default_gateway,
    _probe_direct_egress,
    _prepare_independent_identity,
    _probe_independent_identities,
    _reject_without_provider_effect,
)


ROUTES = '''Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
ens3 00000000 0102A8C0 0003 0 0 100 00000000 0 0 0
ens3 0002A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0
'''


def test_default_gateway_comes_from_guest_route_not_a_hardcoded_vm_address():
    assert _parse_guest_default_gateway(ROUTES) == '192.168.2.1'
    with pytest.raises(DemoError, match='exactly one'):
        _parse_guest_default_gateway(ROUTES.replace('00000000 0102A8C0', '00000001 0102A8C0'))
    with pytest.raises(DemoError, match='exactly one'):
        _parse_guest_default_gateway(ROUTES + 'ens4 00000000 0103A8C0 0003 0 0 100 00000000 0 0 0\n')
    with pytest.raises(DemoError, match='malformed'):
        _parse_guest_default_gateway(ROUTES.replace('0102A8C0', 'FFFFFFFFG'))
    with pytest.raises(DemoError, match='invalid default gateway'):
        _parse_guest_default_gateway(ROUTES.replace('0102A8C0', '0100007F'))


def test_capability_tampering_alters_signed_bytes_not_padding():
    value = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJmb28ifQ.abcdefghijklmnopABCDEFGHIJKLMNOP'
    changed = _corrupt_capability(value)
    assert changed != value
    assert changed.split('.')[:2] == value.split('.')[:2]
    assert changed.split('.')[2][1:] == value.split('.')[2][1:]
    with pytest.raises(DemoError, match='compact-JWS'):
        _corrupt_capability('not-a-jwt')


def test_selected_client_material_is_strict_guest_filename_only():
    command = _client_command('/tmp/garrett-out2.abcd1234', config='other.json',
                              capability='bad-capability.jwt', words=('gh', 'pr', 'view', '1'))
    assert '--config /tmp/garrett-out2.abcd1234/other.json' in command
    assert '--capability-file /tmp/garrett-out2.abcd1234/bad-capability.jwt' in command
    for unsafe in ('../host.key', '/tmp/x', 'foo;true', '-flag'):
        with pytest.raises(DemoError, match='material filename'):
            _client_command('/tmp/garrett-out2.abcd1234', config=unsafe, words=('gh',))


class _Provider:
    def __init__(self):
        self.calls = []

    def seen(self):
        return list(self.calls)


def test_rejected_guest_request_requires_failure_and_no_provider_effect(tmp_path, monkeypatch):
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    provider = _Provider()
    monkeypatch.setattr(ssh, 'call', lambda command: subprocess.CompletedProcess(
        [], 1, b'{"ok":false,"error":{"code":"denied"}}', b''))
    _reject_without_provider_effect(ssh, provider, 0, 'guest-client', label='wrong identity')
    monkeypatch.setattr(ssh, 'call', lambda command: subprocess.CompletedProcess([], 0, b'{}', b''))
    with pytest.raises(DemoError, match='succeeded'):
        _reject_without_provider_effect(ssh, provider, 0, 'guest-client', label='wrong identity')
    monkeypatch.setattr(ssh, 'call', lambda command: subprocess.CompletedProcess([], 1, b'RELEASE', b''))
    with pytest.raises(DemoError, match='unexpected guest output'):
        _reject_without_provider_effect(ssh, provider, 0, 'guest-client', label='wrong identity')
    monkeypatch.setattr(ssh, 'call', lambda command: subprocess.CompletedProcess([], 1, b'', b''))
    provider.calls.append({'method': 'GET'})
    with pytest.raises(DemoError, match='provider traffic'):
        _reject_without_provider_effect(ssh, provider, 0, 'guest-client', label='wrong identity')


def test_guest_tcp_probe_is_bounded_and_fails_closed(tmp_path, monkeypatch):
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    scripts = []

    def response(script, **kwargs):
        scripts.append((script, kwargs))
        return subprocess.CompletedProcess([], 17, b'', b'')

    monkeypatch.setattr(ssh, 'call', response)
    assert not _guest_tcp_reachable(ssh, '192.168.122.1', 40123)
    assert scripts[0][0].startswith('python3 -c ')
    assert '192.168.122.1' in scripts[0][0]
    assert scripts[0][1]['timeout'] == 12
    monkeypatch.setattr(ssh, 'call', lambda *a, **k:
                        subprocess.CompletedProcess([], 0, b'', b''))
    assert _guest_tcp_reachable(ssh, '192.168.122.1', 40123)
    monkeypatch.setattr(ssh, 'call', lambda *a, **k:
                        subprocess.CompletedProcess([], 127, b'', b''))
    with pytest.raises(DemoError, match='bounded status'):
        _guest_tcp_reachable(ssh, '192.168.122.1', 40123)
    with pytest.raises(DemoError, match='port'):
        _guest_tcp_reachable(ssh, '192.168.122.1', 70000)


def test_guest_mount_inventory_records_only_bounded_counts(tmp_path, monkeypatch):
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    mounts = b'''29 28 0:26 / /mnt/aivm-shared rw - virtiofs shared-root rw
30 28 0:27 / /mnt/home rw - 9p host-share rw
31 28 8:1 / / rw - ext4 /dev/vda1 rw
'''
    monkeypatch.setattr(ssh, 'required', lambda *a, **k: mounts)
    result = _guest_mount_inventory(ssh, Path('/tmp/garrett-vm-secret/host'))
    assert result['attachment_mounts_observed'] == 2
    assert result['host_workspace_in_mount_table'] is False
    monkeypatch.setattr(ssh, 'required', lambda *a, **k:
                        mounts + b'/tmp/garrett-vm-secret/host\n')
    with pytest.raises(DemoError, match='host custody workspace'):
        _guest_mount_inventory(ssh, Path('/tmp/garrett-vm-secret/host'))


def test_independent_identity_probe_uses_separate_guest_key_and_subject(tmp_path, monkeypatch):
    import dev.aivm_vm_acceptance as target
    host = tmp_path / 'host'
    host.mkdir()
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    ssh_scripts = []
    files = []
    actions = []

    def fake_required(script, *, label, **kwargs):
        ssh_scripts.append(script)
        if 'other.csr' in script and script.startswith('cat '):
            return b'PUBLIC-CSR'
        return b''

    def fake_action(binary, host_path, action, **kwargs):
        actions.append((action, kwargs))
        if action == 'public-client':
            return {'certificate_pem_b64': 'UEVNLUNFUlQ='}
        return {}

    monkeypatch.setattr(ssh, 'required', fake_required)
    monkeypatch.setattr(ssh, 'publish', lambda name, payload, **kwargs: files.append((name, payload)))
    monkeypatch.setattr(ssh, 'call', lambda script: subprocess.CompletedProcess([], 1, b'', b''))
    monkeypatch.setattr(target, 'inspect_csr', lambda pem: 'fingerprint')
    monkeypatch.setattr(target, 'authority_action', fake_action)
    provider = _Provider()
    config = {'schema': 1, 'certificate': '/guest/client.pem',
              'private_key': '/guest/client.key'}
    _prepare_independent_identity(ssh, '/guest', host, Path('/host/authority'))
    result = _probe_independent_identities(ssh, '/guest', provider, 0, config,
                                           'e30.e30.abcdefghijklmnop')
    assert all(result.values())
    assert any('other.key' in cmd and 'other.csr' in cmd for cmd in ssh_scripts)
    assert actions[0][0] == 'enroll'
    assert actions[0][1]['subject'] == 'other-guest'
    assert actions[1] == ('public-client', {'subject': 'other-guest'})
    assert (host / 'other-guest.csr').read_bytes() == b'PUBLIC-CSR'
    names = {Path(name).name for name, _ in files}
    assert names == {'other.pem', 'other.json', 'mismatch.json', 'bad-capability.jwt'}
    assert all(b'HOST_CREDENTIAL' not in payload for _, payload in files)
    assert provider.seen() == []


def test_network_canary_reports_denial_and_raises_on_reachability(tmp_path, monkeypatch):
    import dev.aivm_vm_acceptance as target
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    monkeypatch.setattr(ssh, 'required', lambda *a, **k: ROUTES.encode())
    # Bind the canary only to the local loopback interface in this portable
    # unit test. The live fixture uses the guest-discovered VM gateway.
    monkeypatch.setattr(target, '_parse_guest_default_gateway', lambda data: '127.0.0.1')
    monkeypatch.setattr(target, '_guest_tcp_reachable', lambda *a, **k: False)
    outcome = _probe_direct_egress(ssh, type('LocalPort', (), {'port': 8080})())
    assert outcome['host_gateway_canary_denied']
    monkeypatch.setattr(target, '_guest_tcp_reachable', lambda *a, **k: True)
    with pytest.raises(DemoError, match='host-only synthetic provider'):
        _probe_direct_egress(ssh, type('LocalPort', (), {'port': 8080})())


def test_host_canary_detects_actual_connection_even_if_guest_reports_failure(tmp_path, monkeypatch):
    import socket
    import dev.aivm_vm_acceptance as target
    ssh = GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    monkeypatch.setattr(ssh, 'required', lambda *a, **k: ROUTES.encode())
    monkeypatch.setattr(target, '_parse_guest_default_gateway', lambda data: '127.0.0.1')
    calls = 0

    def a_lying_guest(_ssh, address, port):
        nonlocal calls
        calls += 1
        if calls == 2:
            # Probe claims denial, but the host kernel has already queued a
            # successful TCP handshake. Independent host observation catches it.
            with socket.create_connection((address, port), timeout=2):
                pass
        return False

    monkeypatch.setattr(target, '_guest_tcp_reachable', a_lying_guest)
    with pytest.raises(DemoError, match='non-allowlisted host TCP canary'):
        _probe_direct_egress(ssh, type('LocalPort', (), {'port': 8080})())
    assert calls == 2
