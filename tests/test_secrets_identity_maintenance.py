"""Operator maintenance verbs: status expiry, verify, prune-keys, issuer naming."""

from __future__ import annotations

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.enrollment import (
    CLIENT_DAYS, KEY_DIRECTORY, IdentityAuthority)


@pytest.fixture
def authority(tmp_path):
    return IdentityAuthority.initialize(tmp_path / 'identity', issuer='aivm.test',
                                        audience='aivm-secrets.identity')


def codes(report):
    return {finding['code']: finding['items'] for finding in report['findings']}


def test_status_reports_when_the_ca_expires(authority):
    status = authority.status()
    assert type(status['ca_not_after']) is int
    assert status['ca_not_after'] > CLIENT_DAYS * 86400


def test_a_fresh_authority_verifies_clean(authority):
    report = authority.verify()
    assert report == {'clean': True, 'findings': [],
                      'ca_not_after': authority.status()['ca_not_after']}


def test_verify_reports_and_prune_removes_only_superseded_keys(authority):
    authority.rotate_issuer()                      # local-2 active
    authority.retire_issuer('local-1')             # local-1 retired
    authority.renew_server()                       # server-1 superseded
    sha = authority.status()['ca_sha256']
    authority.rotate_ca(expected_ca_sha256=sha)    # ca-1 superseded
    authority = IdentityAuthority(authority.root)
    found = codes(authority.verify())
    assert found['retired_issuer_keys'] == [f'{KEY_DIRECTORY}/local-1.key']
    assert any(name.endswith('ca-1.key') for name in found['superseded_ca_keys'])
    assert found['superseded_server_keys']

    removed = authority.prune_keys(superseded=True)['removed']
    assert f'{KEY_DIRECTORY}/local-1.key' in removed
    assert f'{KEY_DIRECTORY}/local-1.aes256' in removed
    assert not (authority.root / KEY_DIRECTORY / 'local-1.key').exists()
    assert (authority.root / KEY_DIRECTORY / 'local-1.pub').exists()
    assert (authority.root / KEY_DIRECTORY / 'local-2.key').exists()
    assert authority.verify()['clean'] is True
    # Still a working authority, and a second prune has nothing to do.
    assert authority.status()['ca_generation'] == 2
    assert authority.prune_keys(superseded=True) == {'removed': []}


def test_prune_needs_the_explicit_flag(authority):
    with pytest.raises(SecretsError):
        authority.prune_keys(superseded=False)


def test_rotate_issuer_skips_a_name_a_restore_left_behind(authority):
    """A restored keyring can name a number whose files exist already."""
    leftover = authority.root / KEY_DIRECTORY / 'local-2.key'
    leftover.write_bytes(b'from a later rotation')
    leftover.chmod(0o600)
    assert authority.rotate_issuer()['active'] == 'local-3'
    assert leftover.read_bytes() == b'from a later rotation'
    # The skipped name is not enabled, so verify lists it with the retired keys.
    assert codes(authority.verify()) == {'retired_issuer_keys': [f'{KEY_DIRECTORY}/local-2.key']}


def test_verify_flags_key_files_the_keyring_does_not_list(authority):
    stray = authority.root / KEY_DIRECTORY / 'local-9.key'
    stray.write_bytes(b'restore leftover')
    stray.chmod(0o600)
    assert codes(authority.verify())['unlisted_issuer_keys'] == [f'{KEY_DIRECTORY}/local-9.key']


def test_python_leaf_near_ca_expiry_is_cut_short_and_refused_within_a_day(authority):
    from aivm_secrets.identity import enrollment as module

    ca_end = authority.status()['ca_not_after']
    late = ca_end - 3 * 86400
    assert module._client_not_after(late, authority._load_ca()[1]) == ca_end - 1
    with pytest.raises(SecretsError):
        module._client_not_after(ca_end - 86400, authority._load_ca()[1])
    assert module._client_not_after(0, authority._load_ca()[1]) == 7 * 86400
