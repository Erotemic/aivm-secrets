"""Observe full native request framing against the independent Python executor."""
from __future__ import annotations

from collections import Counter
import json

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.egress import HTTPSExecutor
from aivm_secrets.kernel.machine import AuthorizedEffect
from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory


@pytest.mark.parametrize('invalid_nul', [False, True])
@pytest.mark.parametrize('authentication', ['bearer', 'x-api-key'])
@pytest.mark.parametrize('method', ['POST', 'PATCH'])
def test_complete_native_request_framing_matches_reference(tmp_path, authentication, method, invalid_nul):
    with TLSService(provider_directory(tmp_path), host='api.example.org', wire_headers=True) as provider:
        provider.routes[(method, '/v1/tickets/7')] = dict(id=7, private=TOKEN)
        text = 'é🦀\r\n\r\nGET /forbidden HTTP/1.1\r\nHost: attacker.test'
        if invalid_nul:
            text += '\x00'
        headers = {f'X-Policy-{i}': f'value-{i}: fixed' for i in range(8)}
        policy = dict(schema=2, adapter='https', service='tracker', host=provider.host,
            authentication=authentication, headers=headers,
            credential_source=dict(kind='file', path=str(tmp_path / 'credential')),
            egress=dict(address='127.0.0.1', port=provider.port, ca_file=str(provider.files['ca'])),
            operations=[dict(name='ticket.edit', effect='write', method=method,
                path='/v1/tickets/{ticket}', parameters={'ticket': [7]}, body_fields={'text': 256})])
        arguments = dict(ticket=7, text=text)
        releases = {'ticket.edit': {'id': {'at': ['id'], 'type': 'integer'}}}
        with ManifestCase(tmp_path, provider, policy, releases, writes='allow',
                          authentication=authentication) as session:
            reply = session.invoke(operation='ticket.edit', arguments=arguments)
            if invalid_nul:
                assert reply['ok'] is False and reply['error']['code'] == 'invalid_request'
                with pytest.raises(SecretsError) as error:
                    parse_policy(policy).parse_request(dict(operation='ticket.edit', arguments=arguments))
                assert error.value.code == 'invalid_request'
                assert provider.seen() == []
                return
            assert reply['ok'], reply
            assert reply['result'] == {'id': 7}
            assert TOKEN not in json.dumps(reply)
        spec = parse_policy(policy)
        request = spec.parse_request(dict(operation='ticket.edit', arguments=arguments))
        effect = spec.final(request, None)
        HTTPSExecutor(spec.egress).execute(AuthorizedEffect(1, 'grant', 'digest', True, True, effect), TOKEN)
        rows = provider.seen()
        assert len(rows) == 2
        expected_body = codec.dumps({'text': text})
        field, value = ('authorization', 'Bearer ' + TOKEN) if authentication == 'bearer' else ('x-api-key', TOKEN)
        other = 'x-api-key' if field == 'authorization' else 'authorization'
        for row in rows:
            counts = Counter(name.lower() for name, _ in row['header_pairs'])
            assert all(count == 1 for count in counts.values()), row['header_pairs']
            assert row['request_version'] == 'HTTP/1.1'
            assert row['method'] == method and row['target'] == '/v1/tickets/7'
            assert row['headers']['host'] == f'{provider.host}:{provider.port}'
            assert row['headers'][field] == value and other not in row['headers']
            assert row['headers']['content-type'] == 'application/json'
            assert row['headers']['content-length'] == str(len(expected_body))
            assert 'transfer-encoding' not in row['headers']
            assert row['body'].encode('utf-8') == expected_body
            assert json.loads(row['body']) == {'text': text}
            assert {key: row['headers'][key] for key in counts if key.startswith('x-policy-')} == {
                name.lower(): value for name, value in headers.items()}
        assert TOKEN.encode() not in (tmp_path / 'provider-audit.jsonl').read_bytes()
