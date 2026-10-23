"""Portable checks of the opt-in real-VM constrained-http acceptance script (no VM)."""

from __future__ import annotations

import json
from pathlib import Path

from dev import aivm_constrained_acceptance as acceptance
from dev.aivm_vm_acceptance import GuestSSH


class FakeProvider:
    host = 'api.example.org'
    port = 4443

    def __init__(self, directory: Path):
        ca = directory / 'provider-ca.pem'
        ca.write_text('not a certificate')
        self.files = {'ca': ca}


def test_the_spec_matches_the_native_session_contract_with_the_guest_translator(tmp_path):
    from aivm_secrets.native_session import load_spec

    ssh = GuestSSH('aivm-2404', tmp_path / 'vm-ssh.conf')
    spec = acceptance.session_spec(tmp_path, ssh, tmp_path, FakeProvider(tmp_path), 18443)
    path = tmp_path / 'spec.json'
    path.write_text(json.dumps(spec))
    loaded = load_spec(path)
    assert loaded['guest'] == {'kind': 'ssh', 'ssh_config': str(ssh.config), 'host': 'aivm-2404'}
    assert loaded['constrained_proxy'] == {'guest_port': 18443}
    assert loaded['binding']['vm'] == 'aivm-2404'


def test_guest_commands_quote_their_paths():
    command = acceptance._curl('/tmp/aivm-native-x/env', '--fail', 'https://h/a b')
    assert command.startswith('. /tmp/aivm-native-x/env && exec curl')
    assert "'https://h/a b'" in command


def test_the_free_port_is_unprivileged():
    assert 1024 <= acceptance.free_port() <= 65535
