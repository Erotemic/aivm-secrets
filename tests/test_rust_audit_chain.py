"""The native session audit file's tamper-evident ``.chain`` sidecar."""
from __future__ import annotations

import hashlib
import os

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.audit import verify_native
from aivm_secrets.kernel import codec
from tests.secrets_helpers import TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
from tests.test_rust_garrett_manifest import provider_directory


def session(directory, audit):
    """A native broker session in its own directory, logging to ``audit``."""
    directory.mkdir(mode=0o700)
    provider = TLSService(provider_directory(directory), host='api.example.org')
    provider.routes[('GET', '/v1/account')] = dict(id=7, active=True)
    return provider, lambda: AuthorityProviderCase(
        directory, provider, AuthorityCase(directory), audit_file=str(audit))


def run_reads(tmp_path, count, name='first'):
    audit = tmp_path / 'provider-audit.jsonl'
    provider, case = session(tmp_path / name, audit)
    with provider:
        with case() as broker:
            for _ in range(count):
                assert broker.invoke(operation='profile.read', arguments={})['ok']
    return audit


def chain_of(audit):
    return audit.with_name(audit.name + '.chain')


def test_every_native_record_is_chained_and_verifies(tmp_path):
    audit = run_reads(tmp_path, 2)
    records = audit.read_bytes().splitlines()
    count, head = verify_native(audit)
    assert count == len(records) >= 4
    entries = chain_of(audit).read_bytes().splitlines()
    assert head == hashlib.sha256(entries[-1]).hexdigest()
    assert os.stat(chain_of(audit)).st_mode & 0o077 == 0
    first = codec.loads(entries[0])
    assert first == {'prev': '0' * 64, 'seq': 0,
                     'record': hashlib.sha256(records[0] + b'\n').hexdigest()}


@pytest.mark.parametrize('change', ['edit', 'remove', 'reorder', 'drop_chain_line'])
def test_tampering_is_detected(tmp_path, change):
    audit = run_reads(tmp_path, 2)
    lines = audit.read_bytes().splitlines(keepends=True)
    if change == 'edit':
        lines[1] = lines[1].replace(b'"vm-test"', b'"vm-evil"')
    elif change == 'remove':
        del lines[1]
    elif change == 'reorder':
        lines[1], lines[2] = lines[2], lines[1]
    if change == 'drop_chain_line':
        entries = chain_of(audit).read_bytes().splitlines(keepends=True)
        chain_of(audit).write_bytes(b''.join(entries[:-1]))
    else:
        audit.write_bytes(b''.join(lines))
    with pytest.raises(SecretsError) as caught:
        verify_native(audit)
    assert caught.value.code == 'audit_failed'


def test_a_tampered_chain_refuses_the_next_session(tmp_path):
    audit = run_reads(tmp_path, 1)
    lines = audit.read_bytes().splitlines(keepends=True)
    audit.write_bytes(b''.join([lines[0].replace(b'"schema":1', b'"schema":2')] + lines[1:]))
    provider, case = session(tmp_path / 'second', audit)
    with provider:
        with pytest.raises(AssertionError, match='unsafe_file'):
            with case():
                pass
        assert provider.seen() == []


def test_an_unchained_log_is_chained_when_the_next_session_opens(tmp_path):
    audit = run_reads(tmp_path, 1)
    before = len(audit.read_bytes().splitlines())
    chain_of(audit).unlink()
    run_reads(tmp_path, 1, name='second')
    count, _ = verify_native(audit)
    assert count == len(audit.read_bytes().splitlines()) > before


def test_audit_verify_native_command(tmp_path):
    import subprocess
    import sys
    audit = run_reads(tmp_path, 1)
    command = [sys.executable, '-I', '-m', 'aivm_secrets', 'audit-verify', '--native', str(audit)]
    ok = subprocess.run(command, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    assert verify_native(audit)[1] in ok.stdout
    chain_of(audit).write_bytes(chain_of(audit).read_bytes()[:-1])
    broken = subprocess.run(command, capture_output=True, text=True)
    assert broken.returncode != 0 and 'chain lines' in broken.stderr
