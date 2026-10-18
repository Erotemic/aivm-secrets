"""Independent policy identity and real coordinated-record parity."""
from __future__ import annotations

import copy
import random
import subprocess

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.primitives import codec
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_manifest import checked, policy


def normalize_rows(rows):
    binary = executable('AIVM_SECRETS_RUST_MANIFEST_RUNNER')
    result = subprocess.run([binary], input=b''.join(
        codec.dumps(dict(version=1, policy=p)) + b'\n' for p in rows),
        capture_output=True, check=True, timeout=20)
    assert result.stderr == b''
    replies = [codec.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == len(rows)
    return replies


def reference(policy):
    try:
        spec = parse_policy(policy)
        return dict(ok=True, policy=spec.to_dict(), digest=spec.digest)
    except SecretsError as error:
        return dict(ok=False, code=error.code)


def examples(tmp_path):
    basic = policy(tmp_path)
    minimum = {k: v for k, v in basic.items() if k not in {
        'lifetime_seconds', 'max_requests', 'max_body_bytes'}}
    minimum['operations'] = [basic['operations'][0]]
    body = copy.deepcopy(basic)
    body['operations'][1]['body_fields'] = {
        'text': {'max_bytes': 20, 'optional': False},
        'description': {'max_bytes': 128, 'optional': True},
    }
    body['operations'][1]['idempotency_header'] = 'Idempotency-Key'
    graph = copy.deepcopy(minimum)
    graph['operations'] = [dict(name='ticket.graph', effect='read', method='POST',
        path='/graphql', parameters={'ticket': [8, 7]}, graphql=dict(
            document='query Ticket($number: Int!) { ticket(number: $number) { id } }',
            operation='Ticket', variables={'number': 'ticket'}))]
    text = copy.deepcopy(minimum)
    text['operations'][0].update(response='text')
    pinned = copy.deepcopy(basic)
    pinned.update(egress=dict(port=8443, address='2001:db8::1', ca_file='/host/ca.pem'),
                  authentication='x-api-key', headers={'X-Api-Version': '2026-10-18'})
    command = copy.deepcopy(basic)
    command['credential_source'] = dict(kind='command', argv=['/host/resolver', 'é🔐'],
                                       inherit_env=['Z_VAR', '_FIRST', 'A_VAR'])
    implicit_env = copy.deepcopy(command)
    implicit_env['credential_source'].pop('inherit_env')
    page = copy.deepcopy(basic)
    page['operations'][0]['page'] = {'size': 10}
    literal = checked(basic)
    literal['checks']['ticket']['require'].append({'at': ['count'], 'equals': 0})
    parameter = checked(basic)
    parameter['checks']['ticket']['require'] = [
        {'at': ['id'], 'equals_parameter': 'ticket'},
        {'at': ['label'], 'equals': 'é🔐'},
    ]
    return [minimum, basic, body, graph, text, pinned, command, implicit_env,
            page, literal, parameter]


def test_normalized_policy_and_digest_match_python(tmp_path):
    rows = examples(tmp_path)
    replies = normalize_rows(rows)
    expected = [reference(p) for p in rows]
    assert all(row['ok'] for row in expected)
    assert replies == expected
    # Normalization is idempotent in both implementations, including all
    # defaults and sorted finite sets, not just a matching digest string.
    canonical = [row['policy'] for row in replies]
    assert normalize_rows(canonical) == replies
    assert [reference(p) for p in canonical] == replies


def test_equivalent_policy_spellings_share_identity(tmp_path):
    randomizer = random.Random(19081)
    rows, expected = [], []
    for p in examples(tmp_path):
        canonical = reference(p)
        for _ in range(12):
            variant = copy.deepcopy(p)
            randomizer.shuffle(variant['operations'])
            for operation in variant['operations']:
                for values in operation.get('parameters', {}).values():
                    if isinstance(values, list):
                        randomizer.shuffle(values)
                randomizer.shuffle(operation.get('fold', []))
                if operation.get('returns') != 'check':
                    operation.setdefault('returns', 'response')
                    operation.setdefault('response', 'json')
                    operation.setdefault('accept', 'text/plain' if operation['response'] == 'text'
                                         else 'application/json')
                fields = ['defaults', 'parameters']
                if operation.get('returns') != 'check':
                    fields += ['body_fields', 'query']
                for field in fields:
                    operation.setdefault(field, {})
                operation.setdefault('fold', [])
                operation.setdefault('idempotency_header', '')
            for check in variant.get('checks', {}).values():
                check.setdefault('accept', 'application/json')
                check.setdefault('bind', {})
                for requirement in check['require']:
                    requirement.setdefault('fold', False)
            for field in ['headers', 'checks', 'cli', 'egress']:
                variant.setdefault(field, {})
            variant['egress'].setdefault('port', 443)
            for field, value in [('lifetime_seconds', 1800), ('max_requests', 200),
                                 ('max_body_bytes', 8192)]:
                variant.setdefault(field, value)
            if variant['credential_source']['kind'] == 'command':
                randomizer.shuffle(variant['credential_source'].setdefault('inherit_env', []))
            assert reference(variant) == canonical
            rows.append(variant)
            expected.append(canonical)
    assert normalize_rows(rows) == expected


@pytest.mark.parametrize('change', ['host', 'source', 'operation', 'allowlist',
                                 'write', 'header', 'limits', 'auth', 'egress'])
def test_security_meaning_changes_policy_identity(tmp_path, change):
    original = policy(tmp_path)
    changed = copy.deepcopy(original)
    if change == 'host':
        changed['host'] = 'other.example.org'
    elif change == 'source':
        changed['credential_source']['path'] = '/different/credential'
    elif change == 'operation':
        changed['operations'][0]['path'] = '/other/{ticket}'
    elif change == 'allowlist':
        changed['operations'][0]['parameters']['ticket'] = [7]
    elif change == 'write':
        changed['operations'][0]['effect'] = 'write'
    elif change == 'header':
        changed['headers'] = {'X-Api-Version': '1'}
    elif change == 'limits':
        changed['max_body_bytes'] += 1
    elif change == 'auth':
        changed['authentication'] = 'x-api-key'
    else:
        changed['egress'] = {'port': 8443}
    actual = normalize_rows([original, changed])
    assert actual == [reference(original), reference(changed)]
    assert all(row['ok'] for row in actual)
    assert actual[0]['digest'] != actual[1]['digest']


def test_normalization_does_not_accept_invalid_policy(tmp_path):
    rows = []
    for field in ['host', 'service', 'credential_source', 'operations',
                  'lifetime_seconds', 'headers', 'egress', 'checks']:
        for value in [None, True, [], 1, {}, 'unexpected']:
            p = policy(tmp_path)
            p[field] = value
            # Some empty optional mappings are valid policies.
            if not reference(p)['ok']:
                rows.append(p)
    duplicate = policy(tmp_path)
    duplicate['operations'][0]['parameters']['ticket'] = [7, 7]
    rows.append(duplicate)
    assert normalize_rows(rows) == [reference(p) for p in rows]


def test_policy_inspection_frames_remain_closed(tmp_path):
    binary = executable('AIVM_SECRETS_RUST_MANIFEST_RUNNER')
    frame = dict(version=1, policy=policy(tmp_path))
    rows = [dict(frame, facts={}), dict(frame, request=None),
            dict(frame, unknown=True), dict(frame, version=2)]
    # A refused frame must not stop or contaminate the following valid one.
    result = subprocess.run([binary], input=b''.join(codec.dumps(row) + b'\n'
        for row in [*rows, frame]), capture_output=True, check=True, timeout=20)
    assert not result.stderr
    replies = [codec.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == len(rows) + 1
    assert all(row['ok'] is False and isinstance(row['code'], str) for row in replies[:-1])
    assert replies[-1] == reference(frame['policy'])
