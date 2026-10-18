"""Observe compiled native request lines against the independent Python executor."""
from __future__ import annotations

import json

import pytest

from aivm_secrets.host.egress import HTTPSExecutor
from aivm_secrets.kernel.machine import AuthorizedEffect
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory


@pytest.mark.parametrize('method', ['GET', 'POST', 'PATCH'])
@pytest.mark.parametrize('state', ['open', 'closed'])
def test_compiled_request_line_and_body_match_python(tmp_path, method, state):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        target = f'/v1/tickets/7?state={state}'
        provider.routes[(method, target)] = dict(id=7, private=TOKEN)
        write = method != 'GET'
        operation = dict(name='ticket.action', effect='write' if write else 'read',
            method=method, path='/v1/tickets/{ticket}',
            parameters={'ticket': [7], 'state': ['open', 'closed']},
            query={'state': '{state}'})
        arguments = dict(ticket=7, state=state)
        if write:
            operation['body_fields'] = {'text': 30}
            arguments['text'] = 'quote " and newline\n'
        policy = dict(schema=2, adapter='https', service='tracker', host=provider.host,
            authentication='bearer',
            credential_source=dict(kind='file', path=str(tmp_path / 'credential')),
            egress=dict(address='127.0.0.1', port=provider.port,
                        ca_file=str(provider.files['ca'])), operations=[operation])
        releases = {'ticket.action': {'id': {'at': ['id'], 'type': 'integer'}}}
        with ManifestCase(tmp_path, provider, policy, releases, writes='allow') as session:
            reply = session.invoke(operation='ticket.action', arguments=arguments)
            assert reply['ok'], reply
            assert reply['result'] == {'id': 7}
            assert TOKEN not in json.dumps(reply)
        spec = parse_policy(policy)
        request = spec.parse_request(dict(operation='ticket.action', arguments=arguments))
        effect = spec.final(request, None)
        HTTPSExecutor(spec.egress).execute(
            AuthorizedEffect(1, 'grant', 'digest', True, write, effect), TOKEN)
        seen = provider.seen()
        assert len(seen) == 2
        for row in seen:
            assert row['method'] == method and row['target'] == target
            assert row['headers']['host'] == f'{provider.host}:{provider.port}'
            assert row['headers']['authorization'] == 'Bearer ' + TOKEN
        assert seen[0]['body'] == seen[1]['body']
        if write:
            assert json.loads(seen[0]['body']) == {'text': arguments['text']}
        else:
            assert seen[0]['body'] == ''
        assert TOKEN.encode() not in (tmp_path / 'provider-audit.jsonl').read_bytes()
