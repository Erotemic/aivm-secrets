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
