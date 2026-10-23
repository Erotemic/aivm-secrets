"""Portable checks of the opt-in real-VM proxy acceptance script (no VM)."""

from __future__ import annotations

from pathlib import Path

from dev import aivm_proxy_acceptance as acceptance
from dev.aivm_vm_acceptance import GuestSSH
from aivm_secrets.proxy.policy import parse_policy


class FakeProvider:
    host = 'api.example.org'
    port = 4443
    files = {'ca': Path('/tmp/provider-ca.pem')}


def test_the_policy_is_a_valid_substitution_policy_for_the_provider():
    policy = parse_policy(acceptance.proxy_policy(FakeProvider()))
    assert policy.profile == 'credential-substitution'
    origin = policy.origins['api.example.org']
    assert (origin.address, origin.port, origin.authentication) == ('127.0.0.1', 4443, 'bearer')


def test_the_session_spec_matches_the_proxy_session_contract(tmp_path):
    from aivm_secrets.proxy_session import load_spec

    ssh = GuestSSH('aivm-2404', tmp_path / 'vm-ssh.conf')
    for bin_dir in (None, tmp_path):
        spec = acceptance.session_spec(tmp_path, ssh, bin_dir)
        path = tmp_path / 'spec.json'
        path.write_text(__import__('json').dumps(spec))
        loaded = load_spec(path)
        assert loaded['guest'] == {'kind': 'ssh', 'ssh_config': str(ssh.config), 'host': 'aivm-2404'}
        assert loaded['bin_dir'] == (str(bin_dir) if bin_dir else None)


def test_guest_commands_quote_their_paths():
    command = acceptance._curl('/tmp/aivm-native-x/env', '--fail', 'https://h/a b')
    assert command.startswith(". /tmp/aivm-native-x/env && exec curl")
    assert "'https://h/a b'" in command
