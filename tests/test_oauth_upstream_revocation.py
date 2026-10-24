"""Optional RFC 7009 revocation at the provider, after local deactivation."""

from __future__ import annotations

from urllib.parse import parse_qs

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.garrett.oauth_contract import parse_grant
from aivm_secrets.identity.oauth_provider import OAuthProvider
from aivm_secrets.identity.oauth_vault import OAuthVault

BASE = {
    'schema': 1, 'name': 'synthetic', 'client_id': 'test-client',
    'authorization_url': 'https://login.example.org/authorize',
    'token_url': 'https://login.example.org/token',
    'resource_host': 'api.example.org', 'callback_port': 18765, 'scopes': ['read'],
}
GRANT = {'access_token': 'SYNTHETIC-OAUTH-ACCESS-PRIVATE',
         'refresh_token': 'SYNTHETIC-OAUTH-REFRESH-PRIVATE',
         'expires_at': 10000, 'scopes': ['read'], 'generation': 0}


def test_the_endpoint_must_share_the_token_origin():
    OAuthProvider.parse(dict(BASE, revocation_url='https://login.example.org/revoke'))
    with pytest.raises(SecretsError):
        OAuthProvider.parse(dict(BASE, revocation_url='https://elsewhere.example.org/revoke'))


def test_existing_profiles_keep_their_digest():
    plain = OAuthProvider.parse(BASE)
    assert b'revocation_url' not in plain.canonical()
    configured = OAuthProvider.parse(dict(BASE, revocation_url='https://login.example.org/revoke'))
    assert configured.digest != plain.digest


class FakeTransport:
    def __init__(self, outcome):
        self.outcome, self.sent = outcome, []

    def revoke(self, provider, fields):
        self.sent.append(dict(fields))
        return self.outcome


@pytest.mark.parametrize('outcome', ['revoked', 'refused', 'in_doubt', 'not_sent'])
def test_local_revocation_comes_first_whatever_the_provider_says(tmp_path, outcome):
    provider = OAuthProvider.parse(dict(BASE, revocation_url='https://login.example.org/revoke'))
    OAuthVault.initialize(tmp_path / 'vault')
    vault = OAuthVault(tmp_path / 'vault')
    vault.enroll(provider, 'vm-test', parse_grant(GRANT))
    transport = FakeTransport(outcome)
    reply = vault.revoke(provider, 'vm-test', transport=transport)
    assert reply['active'] is False and reply['upstream'] == outcome
    assert transport.sent == [{'token': GRANT['refresh_token'],
                               'token_type_hint': 'refresh_token',
                               'client_id': 'test-client'}]
    assert vault.status(provider, 'vm-test')['active'] is False
    # Already revoked: nothing left to send upstream.
    assert vault.revoke(provider, 'vm-test', transport=transport)['upstream'] == 'no_grant'
    assert len(transport.sent) == 1


def test_without_an_endpoint_the_reply_is_unchanged(tmp_path):
    provider = OAuthProvider.parse(BASE)
    OAuthVault.initialize(tmp_path / 'vault')
    vault = OAuthVault(tmp_path / 'vault')
    vault.enroll(provider, 'vm-test', parse_grant(GRANT))
    assert 'upstream' not in vault.revoke(provider, 'vm-test', transport=FakeTransport('revoked'))


@pytest.mark.parametrize('status, outcome', [(200, 'revoked'), (400, 'refused')])
def test_native_vault_revokes_upstream_over_the_pinned_origin(tmp_path, status, outcome):
    pytest.importorskip('cryptography')
    from tests.test_rust_garrett_oauth_vault import REFRESH, VaultCase, profile
    from tests.secrets_helpers import TLSService
    try:
        case = VaultCase(tmp_path, provider=profile(revocation_url='https://login.example.org/revoke'))
    except Exception as error:  # native binary not configured
        pytest.skip(f'native OAuth admin unavailable: {error}')
    case.enroll()
    seen = []
    with TLSService(tmp_path, host='login.example.org') as server:
        def respond(request):
            seen.append(parse_qs(request['body']))
            return status, {}, b''
        server.routes[('POST', '/revoke')] = respond
        result = case.call('revoke', now=100, transport=case.transport(server))
    assert result['active'] is False and result['upstream'] == outcome
    assert seen == [{'token': [REFRESH], 'token_type_hint': ['refresh_token'],
                     'client_id': ['test-client']}]
    assert case.reference.status(case.provider, 'vm-test')['active'] is False
    case.audit()
