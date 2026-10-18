"""Decoded key/text traversal, separate wire checks and provider selection."""
import json
import random

import pytest

from aivm_secrets.primitives import codec
from tests.test_rust_garrett import executable, run
from tests.secrets_helpers import TOKEN, TLSService
from tests.secrets_github_scenario import PULL_PATH, install_github_routes
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory
from tests.test_rust_w2_github_workflow import native_policy, native_disclosure, arguments


def decoded_safe(value, secret, fuel):
    if not fuel:
        return False
    if type(value) is str:
        return not (secret and secret in value.encode())
    if type(value) is list:
        return all(decoded_safe(child, secret, fuel - 1) for child in value)
    if type(value) is dict:
        return all(not (secret and secret in name.encode())
                   and decoded_safe(child, secret, fuel - 1)
                   for name, child in value.items())
    return True


def test_recursive_reflection_matches_independent_python_oracle():
    rng = random.Random(14419)
    secret = b'credential-0123456789'
    values = [None, False, 7, 12345678901234567, '', 'safe', secret.decode(),
              ['safe', {'nested': [None, secret.decode()]}],
              {secret.decode(): None}, {'first': True, 'last': secret.decode()},
              {'key': 'x' + secret.decode() + 'y'}, ['before', ['after', secret.decode()]],
              {'\\"' + secret.decode(): 'value'}, {'unicode': 'é🦀'},
              {'a': True, 'b': False}]
    def tree(depth):
        if not depth or rng.randrange(3) == 0:
            return rng.choice([None, True, -17, '', secret.decode(), 'prefix-' + secret.decode(), '雪\\"', 'safe'])
        if rng.randrange(2):
            return [tree(depth - 1) for _ in range(rng.randrange(5))]
        return {rng.choice(['safe', '雪', secret.decode()]) + str(i): tree(depth - 1)
                for i in range(rng.randrange(5))}
    values += [tree(6) for _ in range(250)]
    rows = []
    for value in values:
        for needle in [secret, b'', b'\\"', '雪'.encode(), b'12345678901234567', b'true,"b"']:
            for fuel in [0, 1, 2, 7, 65]:
                rows.append(dict(action='json-reflection', value=value,
                                 secret_hex=needle.hex(), fuel=fuel))
    expected = [dict(ok=True,
        decoded_safe=bool(decoded_safe(row['value'], bytes.fromhex(row['secret_hex']), row['fuel'])),
        public_safe=bool(decoded_safe(row['value'], bytes.fromhex(row['secret_hex']), 65))
            and not (row['secret_hex'] and bytes.fromhex(row['secret_hex']) in codec.dumps(row['value'])))
        for row in rows]
    actual = run(executable('AIVM_SECRETS_RUST_GARRETT_RUNNER'), rows, crypto=True)
    assert actual == expected


@pytest.mark.parametrize('credential_kind', ['plain', 'json-escape'])
@pytest.mark.parametrize('shape', ['direct', 'nested', 'escaped-provider', 'discarded'])
def test_actual_manifest_checks_selected_decoded_text_before_release(tmp_path, shape, credential_kind):
    from tests.test_rust_garrett_authority import private
    credential = TOKEN if credential_kind == 'plain' else 'credential-quote"-slash\\-end'
    source = private(tmp_path / 'actual-credential', credential.encode())
    with TLSService(provider_directory(tmp_path)) as provider:
        install_github_routes(provider)
        original = provider.routes[('GET', PULL_PATH)]
        disclosure = native_disclosure()
        if shape == 'nested':
            disclosure['pr.view']['title'] = {'at': ['extra'], 'type': 'array',
                'max_items': 3, 'items': {'at': [], 'type': 'object', 'fields': {
                    'text': {'at': ['text'], 'type': 'text'}}}}
        def response(seen):
            status, headers, raw = original(seen)
            value = json.loads(raw)
            if shape == 'discarded':
                value['discarded'] = {credential: [credential]}
            elif shape == 'nested':
                value['extra'] = [{'text': 'safe'}, {'text': credential}]
            else:
                value['title'] = credential
            raw = codec.dumps(value)
            if shape == 'escaped-provider':
                # Encoded input must be checked after decoding, even though the
                # literal credential bytes are absent from the HTTP body.
                encoded = ''.join('\\u%04x' % ord(c) for c in credential).encode()
                raw = raw.replace(codec.dumps(credential)[1:-1], encoded)
                assert credential.encode() not in raw
            return status, headers, raw
        provider.routes[('GET', PULL_PATH)] = response
        policy = native_policy(tmp_path, provider)
        policy['credential_source']['path'] = str(source)
        with ManifestCase(tmp_path, provider, policy, disclosure, credential_file=str(source)) as case:
            reply = case.invoke(operation='pr.view', arguments=arguments())
            assert reply['ok'] == (shape == 'discarded'), reply
            if shape != 'discarded':
                assert reply['error']['code'] == 'upstream_response'
            assert credential not in json.dumps(reply)
            assert credential.encode() not in codec.dumps(reply)
            assert len(provider.seen()) == 1


@pytest.mark.parametrize('kind', ['text', 'key', 'array', 'safe'])
@pytest.mark.parametrize('credential', [TOKEN, 'credential-quote"-slash\\-end'])
def test_python_broker_and_native_guard_agree_on_selected_text(tmp_path, kind, credential):
    from tests.secrets_helpers import Harness, https_policy
    value = {'text': credential} if kind == 'text' else (
        {credential: None} if kind == 'key' else (
            {'rows': [None, {'text': credential}]} if kind == 'array' else {'text': 'public'}))
    class SelectedProvider:
        def execute(self, effect, secret):
            assert secret == credential
            if not effect.final:
                from tests.secrets_helpers import metadata
                return metadata()
            return value
    harness = Harness(tmp_path, policy=https_policy(), executor=SelectedProvider(), token=credential)
    try:
        reply = harness.invoke('profile.read')
        assert reply['ok'] == (kind == 'safe')
        if kind != 'safe':
            assert reply['error']['code'] == 'upstream_response'
        assert credential not in json.dumps(reply)
    finally:
        harness.broker.close()
    row = dict(action='json-reflection', value=value, secret_hex=credential.encode().hex(), fuel=65)
    [native] = run(executable('AIVM_SECRETS_RUST_GARRETT_RUNNER'), [row], crypto=True)
    assert native['public_safe'] == reply['ok']
