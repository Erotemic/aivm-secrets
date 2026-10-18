"""Native provider observations against the independent Python HTTP executor."""
from __future__ import annotations

import json

import pytest

from aivm_secrets.host.egress import HTTPSExecutor
from aivm_secrets.kernel.machine import AuthorizedEffect
from aivm_secrets.kernel.model import Effect
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase, private
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory


@pytest.mark.parametrize('profile', ['account', 'manifest'])
@pytest.mark.parametrize('authentication', ['bearer', 'x-api-key'])
@pytest.mark.parametrize('token_kind', ['punctuation', 'maximum'])
def test_actual_native_authentication_bytes_match_python(tmp_path, profile,
                                                       authentication, token_kind):
    token = ''.join(chr(byte) for byte in range(33, 127))
    if token_kind == 'maximum':
        token = (token * 44)[:4096]
    selected = private(tmp_path / 'selected-credential', token.encode('ascii'))
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        provider.routes[('GET', '/v1/account')] = dict(id=7, active=True, private='discarded')
        policy = dict(schema=2, adapter='https', service='profile', host=provider.host,
            authentication=authentication, credential_source=dict(kind='file', path=str(selected)),
            egress=dict(address='127.0.0.1', port=provider.port, ca_file=str(provider.files['ca'])),
            operations=[dict(name='profile.read', effect='read', method='GET', path='/v1/account')])
        spec = parse_policy(policy)
        options = dict(authentication=authentication, credential_file=str(selected))
        if profile == 'account':
            session = AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path), **options)
        else:
            releases = {'profile.read': {
                'id': {'at': ['id'], 'type': 'integer'},
                'active': {'at': ['active'], 'type': 'boolean'},
            }}
            session = ManifestCase(tmp_path, provider, policy, releases, **options)
        with session:
            reply = session.invoke(operation='profile.read', arguments={})
            assert reply['ok'], reply
            assert reply['result'] == dict(id=7, active=True)
            assert token not in json.dumps(reply)
        effect = AuthorizedEffect(1, 'grant', 'digest', False, False,
                                  Effect('GET', '/v1/account'))
        HTTPSExecutor(spec.egress).execute(effect, token)
        observed = provider.seen()
        assert len(observed) == 2
        field, value = ('authorization', 'Bearer ' + token) if authentication == 'bearer' \
            else ('x-api-key', token)
        other = 'x-api-key' if field == 'authorization' else 'authorization'
        for request in observed:
            assert request['method'] == 'GET' and request['target'] == '/v1/account'
            assert request['headers'][field] == value
            assert other not in request['headers']
            assert request['headers']['host'] == f'{provider.host}:{provider.port}'
            assert request['body'] == ''
        assert token.encode('ascii') not in (tmp_path / 'provider-audit.jsonl').read_bytes()
