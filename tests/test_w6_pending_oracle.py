"""Portable adversarial mutants for the audited-but-unsent read prefix."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace

import pytest

from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN
from tests.secrets_w6_pending import (
    PendingContract, assert_pending_publicly_equivalent, checked_pending_witness,
)
from tests.secrets_w6_trace import TraceMismatch
from tests.test_w6_failure_oracle import _scenario


def _pending(tmp_path, *, code='revoked'):
    fixture = _scenario(tmp_path)
    original = fixture['left']
    reply = {'version': 1, 'ok': False, 'error': {
        'code': code, 'message': ('Capability authentication failed.' if code == 'invalid_capability'
                                 else 'Broker failed closed.'),
    }}
    # Historical failure fixture omits the irrelevant response-format field;
    # this boundary oracle requires the *complete* compiled host effect.
    full_plan = copy.deepcopy(original.plan)
    full_plan[0][1]['response'] = 'json'
    observed = replace(original, plan=full_plan, provider=[], provider_arrivals=[],
                       audit=[original.audit[0]], reply=reply,
                       frame=codec.dumps(reply) + b'\n')
    contract = PendingContract(('final',), (), code)
    expected = dict(policy=fixture['policy'], operation=fixture['operation'],
                    normalized_arguments=fixture['normalized_arguments'],
                    credential=TOKEN, host=fixture['host'], port=fixture['port'])
    return observed, contract, expected


@pytest.mark.parametrize('code', ['revoked', 'unreachable', 'expired', 'invalid_capability'])
def test_single_audited_unsent_read_is_a_distinct_valid_prefix(tmp_path, code):
    observation, contract, expected = _pending(tmp_path, code=code)
    witness = checked_pending_witness(observed=observation, contract=contract, **expected)
    assert witness.events == ('audit:final', f'guest-denied:{code}')
    assert witness.frame == observation.frame


def test_pair_with_same_public_failure_cannot_depend_on_private_setup(tmp_path):
    left, contract, expected = _pending(tmp_path)
    right = copy.deepcopy(left)
    a, b = assert_pending_publicly_equivalent(
        left=left, right=right, left_contract=contract,
        right_contract=contract, **expected,
    )
    assert a == b


def test_pair_with_different_declassified_failure_is_not_equivalent(tmp_path):
    left, contract, expected = _pending(tmp_path)
    with pytest.raises(TraceMismatch, match='public failure class'):
        assert_pending_publicly_equivalent(
            left=left, right=left, left_contract=contract,
            right_contract=PendingContract(('final',), (), 'unreachable'), **expected,
        )


@pytest.mark.parametrize('mutation', [
    'delete-audit', 'extra-audit', 'extra-provider-send', 'wrong-phase',
    'wrong-route', 'changed-digest', 'wrong-identity', 'private-audit-field',
    'completion-audit', 'write-promotion', 'wrong-public-code', 'guest-extra-result',
    'extra-guest-frame', 'wrong-selected-effect',
])
def test_pending_prefix_rejects_adversarial_mutants(tmp_path, mutation):
    value, contract, expected = _pending(tmp_path)
    altered = copy.deepcopy(value)
    row = altered.audit[0]
    if mutation == 'delete-audit':
        altered = replace(altered, audit=[])
    elif mutation == 'extra-audit':
        altered = replace(altered, audit=altered.audit * 2)
    elif mutation == 'extra-provider-send':
        altered = replace(altered, provider=[{
            'method': 'GET', 'target': '/v1/tickets/7', 'body': '', 'headers': {},
        }])
    elif mutation == 'wrong-phase':
        row['phase'] = 'preflight'
    elif mutation == 'wrong-route':
        row['route']['path'] = '/v1/tickets/8'
    elif mutation == 'changed-digest':
        row['request_digest'] = 'f' * 64
    elif mutation == 'wrong-identity':
        row['identity']['cnf'] = {'wrong': 'fingerprint'}
    elif mutation == 'private-audit-field':
        row['secret'] = TOKEN
    elif mutation == 'completion-audit':
        row['event'] = 'completed'
    elif mutation == 'write-promotion':
        altered.plan[0][1]['write'] = True
    elif mutation == 'wrong-public-code':
        altered.reply['error']['code'] = 'unreachable'
        altered = replace(altered, frame=codec.dumps(altered.reply) + b'\n')
    elif mutation == 'guest-extra-result':
        altered.reply['result'] = {'credential': TOKEN}
        altered = replace(altered, frame=codec.dumps(altered.reply) + b'\n')
    elif mutation == 'extra-guest-frame':
        altered = replace(altered, frame=altered.frame * 2)
    elif mutation == 'wrong-selected-effect':
        altered.plan[0][1]['target'] = '/v1/tickets/8'
    with pytest.raises(TraceMismatch):
        checked_pending_witness(observed=altered, contract=contract, **expected)


def test_pending_contract_rejects_two_missing_or_future_sends(tmp_path):
    value, _, expected = _pending(tmp_path)
    invalid = [
        PendingContract(('final',), ('final',), 'revoked'),
        PendingContract(('preflight', 'final'), (), 'revoked'),
        PendingContract(('final', 'preflight'), (), 'revoked'),
        PendingContract((), (), 'revoked'),
    ]
    for contract in invalid:
        with pytest.raises(TraceMismatch):
            checked_pending_witness(observed=value, contract=contract, **expected)


def _two_phase_pending(tmp_path):
    """Synthetic independent preflight send followed by an unsent final audit."""
    from aivm_secrets.kernel.service import parse_policy
    from tests.secrets_github_scenario import PULL
    from tests.secrets_helpers import TLSService
    from tests.secrets_w6_history import ReadObservation
    from tests.test_rust_garrett_provider import provider_directory
    from tests.test_rust_garrett_manifest import reference_compile
    from tests.test_rust_w2_github_workflow import native_policy, arguments

    with TLSService(provider_directory(tmp_path), host='api.example.org') as server:
        policy = native_policy(tmp_path, server)
        operation, args = 'pr.diff', arguments()
        output = reference_compile(policy, {'operation': operation, 'arguments': args}, PULL)
        assert output['ok'], output
        result = output['result']
        plan = [('preflight', result['preflight']), ('final', result['effect'])]
        original, _, _ = _pending(tmp_path)
        template = original.audit[0]
        digest = codec.digest(parse_policy(policy).parse_request({
            'operation': operation, 'arguments': args,
        }).to_dict())
        audit = []
        for phase, effect in plan:
            audit.append({**copy.deepcopy(template), 'phase': phase,
                          'operation': operation, 'request_digest': digest,
                          'route': {'host': server.host, 'port': server.port,
                                    'method': effect['method'], 'path': effect['target']}})
        effect = plan[0][1]
        headers = {'host': f'{server.host}:{server.port}', 'accept': effect['accept'],
                   'accept-encoding': 'identity', 'user-agent': 'aivm-secrets/1',
                   'connection': 'close', 'authorization': 'Bearer ' + TOKEN}
        headers.update({name.lower(): value for name, value in policy.get('headers', {}).items()})
        provider = [{'method': effect['method'], 'target': effect['target'],
                     'body': '', 'headers': headers}]
        reply = {'version': 1, 'ok': False, 'error': {
            'code': 'revoked', 'message': 'Broker failed closed.',
        }}
        observation = ReadObservation(
            provider=provider, audit=audit, reply=reply,
            frame=codec.dumps(reply) + b'\n', plan=plan,
            provider_arrivals=[[copy.deepcopy(audit[0])]],
        )
        expected = dict(policy=policy, operation=operation, normalized_arguments=args,
                        credential=TOKEN, host=server.host, port=server.port,
                        checked_facts=PULL)
        return observation, PendingContract(('preflight', 'final'), ('preflight',), 'revoked'), expected


def test_preflight_sent_final_audited_but_unsent(tmp_path):
    observation, contract, expected = _two_phase_pending(tmp_path)
    result = checked_pending_witness(observed=observation, contract=contract, **expected)
    assert result.events == (
        'audit:preflight', 'provider-send:preflight',
        'audit:final', 'guest-denied:revoked',
    )


@pytest.mark.parametrize('mutation', [
    'second-send', 'future-final-audit', 'principal-switch',
    'provider-accept-change', 'checked-fact-mutation', 'missing-preflight',
])
def test_two_phase_pending_rejects_traces_that_cannot_be_refined(tmp_path, mutation):
    observation, contract, expected = _two_phase_pending(tmp_path)
    value = copy.deepcopy(observation)
    if mutation == 'second-send':
        value.provider.append(copy.deepcopy(value.provider[0]))
    elif mutation == 'future-final-audit':
        value.provider_arrivals[0].append(copy.deepcopy(value.audit[1]))
    elif mutation == 'principal-switch':
        value.audit[1]['identity']['sub'] = 'other-client'
    elif mutation == 'provider-accept-change':
        value.provider[0]['headers']['accept'] = 'text/plain'
    elif mutation == 'checked-fact-mutation':
        expected['checked_facts'] = {'head': {'sha': '0' * 40}}
    elif mutation == 'missing-preflight':
        value.provider.clear()
    with pytest.raises(TraceMismatch):
        checked_pending_witness(observed=value, contract=contract, **expected)


def test_preflight_audited_without_any_provider_arrival(tmp_path):
    value, _, expected = _two_phase_pending(tmp_path)
    reply = {'version': 1, 'ok': False,
             'error': {'code': 'unreachable', 'message': 'Broker failed closed.'}}
    value = replace(value, plan=[value.plan[0]], audit=[value.audit[0]],
                    provider=[], provider_arrivals=[],
                    reply=reply, frame=codec.dumps(reply) + b'\n')
    witness = checked_pending_witness(
        observed=value,
        contract=PendingContract(('preflight',), (), 'unreachable'), **expected,
    )
    assert witness.events == ('audit:preflight', 'guest-denied:unreachable')


def _write_native_audit(root, rows):
    """Persist a synthetic native session/audit log for scope regression tests."""
    (root / 'provider-audit.jsonl').write_bytes(
        b''.join(codec.dumps(row) + b'\n' for row in rows)
    )


def _opening():
    return {'schema': 1, 'event': 'session_open',
            'profile': 'manifest-https-v1', 'grant': 'a' * 32,
            'policy': 'b' * 64}


def _synthetic_startup(opening, identity=None):
    """Reproduce the native two-record prefix and JWT public-claim layout.

    The fixture token is deliberately unsigned; these tests only verify the
    audit-to-public-claims comparison. Real mTLS/native tests use the signed
    Rust token returned by the bridge.
    """
    if identity is None:
        identity = {
            'iss': 'aivm.test', 'aud': 'aivm-secrets.remote',
            'sub': 'vm-test', 'jti': 'f' * 32,
            'iat': 10, 'exp': 200, 'epoch': 0,
            'cnf': {'x5t#S256': 'q' * 43},
        }
    identity = copy.deepcopy(identity)
    issued = {
        'schema': 1, 'event': 'issued',
        'grant': opening['grant'], 'policy': opening['policy'],
        'identity': identity,
    }
    body = base64.urlsafe_b64encode(
        codec.dumps({**identity, 'enc': 'synthetic-protected-capability'})
    ).rstrip(b'=').decode('ascii')
    token = 'e30.' + body + '.e30'
    return [opening, issued], token


def test_pending_native_session_prefix_is_not_a_provider_dispatch(tmp_path):
    from tests.test_rust_w6_pending import _observation, _session_prefix

    startup, token = _synthetic_startup(_opening())
    opening, issued = startup
    preflight = {'schema': 1, 'event': 'dispatch', 'phase': 'preflight',
                 'grant': opening['grant'], 'policy': opening['policy'],
                 'identity': issued['identity']}
    final = {**preflight, 'phase': 'final'}
    _write_native_audit(tmp_path, startup)
    saved = _session_prefix(tmp_path, token)
    _write_native_audit(tmp_path, [*startup, preflight, final])

    class Provider:
        def seen(self):
            return [{'method': 'GET', 'target': '/v1/preflight'}]

    reply = {'version': 1, 'ok': False, 'error': {
        'code': 'revoked', 'message': 'Broker failed closed.',
    }}
    frame = codec.dumps(reply) + b'\n'
    observation = _observation(
        tmp_path, Provider(), plan=[('preflight', {}), ('final', {})],
        reply=reply, frame=frame, arrivals=[[*startup, preflight]], startup=saved,
    )
    assert observation.audit == [preflight, final]
    assert observation.provider_arrivals == [[preflight]]
    assert observation.frame == frame


@pytest.mark.parametrize('mutation', [
    'bad-profile', 'extra-opening-field', 'invalid-grant',
    'missing-issued', 'wrong-issued-grant', 'wrong-issued-policy',
    'extra-issued-field', 'different-issued-identity', 'extra-pre-request-record',
    'malformed-token-identity',
    'altered-opening', 'missing-opening-at-arrival', 'different-arrival-opening',
    'missing-issued-at-arrival', 'different-arrival-issued',
    'different-dispatch-grant', 'different-dispatch-identity',
    'extra-post-request-record',
])
def test_pending_native_session_scope_rejects_mutations(tmp_path, mutation):
    from tests.test_rust_w6_pending import _observation, _session_prefix

    startup, token = _synthetic_startup(_opening())
    opening, issued = startup
    invalid_start = {
        'bad-profile', 'extra-opening-field', 'invalid-grant',
        'missing-issued', 'wrong-issued-grant', 'wrong-issued-policy',
        'extra-issued-field', 'different-issued-identity', 'extra-pre-request-record',
        'malformed-token-identity',
    'malformed-token-identity',
    }
    if mutation == 'bad-profile':
        opening['profile'] = 'account-status-v1'
    elif mutation == 'extra-opening-field':
        opening['secret'] = TOKEN
    elif mutation == 'invalid-grant':
        opening['grant'] = 'xyz'
    elif mutation == 'missing-issued':
        startup.pop()
    elif mutation == 'wrong-issued-grant':
        issued['grant'] = 'd' * 32
    elif mutation == 'wrong-issued-policy':
        issued['policy'] = 'd' * 64
    elif mutation == 'extra-issued-field':
        issued['secret'] = TOKEN
    elif mutation == 'different-issued-identity':
        issued['identity']['sub'] = 'different-principal'
    elif mutation == 'extra-pre-request-record':
        startup.append({'event': 'unreviewed-boot-event'})
    elif mutation == 'malformed-token-identity':
        token = 'e30.e30.e30'
    if mutation in invalid_start:
        _write_native_audit(tmp_path, startup)
        with pytest.raises(TraceMismatch):
            _session_prefix(tmp_path, token)
        return

    _write_native_audit(tmp_path, startup)
    saved = _session_prefix(tmp_path, token)
    dispatch = {'schema': 1, 'event': 'dispatch', 'phase': 'preflight',
                'grant': opening['grant'], 'policy': opening['policy'],
                'identity': issued['identity']}
    rows = [*startup, dispatch]
    arrivals = [rows.copy()]
    if mutation == 'altered-opening':
        rows[0] = {**opening, 'policy': 'c' * 64}
    elif mutation == 'missing-opening-at-arrival':
        arrivals = [[issued, dispatch]]
    elif mutation == 'different-arrival-opening':
        arrivals = [[{**opening, 'grant': 'd' * 32}, issued, dispatch]]
    elif mutation == 'missing-issued-at-arrival':
        arrivals = [[opening, dispatch]]
    elif mutation == 'different-arrival-issued':
        arrivals = [[opening, {**issued, 'grant': 'd' * 32}, dispatch]]
    elif mutation == 'different-dispatch-grant':
        rows[2] = {**dispatch, 'grant': 'd' * 32}
    elif mutation == 'different-dispatch-identity':
        rows[2] = {**dispatch, 'identity': {**issued['identity'], 'sub': 'another'}}
    elif mutation == 'extra-post-request-record':
        rows.append({'event': 'unexpected', 'grant': opening['grant'],
                     'policy': opening['policy']})
    _write_native_audit(tmp_path, rows)

    class Provider:
        def seen(self):
            return []

    reply = {'version': 1, 'ok': False, 'error': {
        'code': 'revoked', 'message': 'Broker failed closed.',
    }}
    with pytest.raises(TraceMismatch):
        _observation(
            tmp_path, Provider(), plan=[('preflight', {})],
            reply=reply, frame=codec.dumps(reply) + b'\n',
            arrivals=arrivals, startup=saved,
        )


@pytest.mark.parametrize('shape', ['final-only', 'preflight-then-final'])
def test_native_session_scoping_preserves_strict_pending_witness(tmp_path, shape):
    """The real two-record bootstrap must not alter a scoped W6 request trace."""
    from tests.test_rust_w6_pending import _observation, _session_prefix

    if shape == 'final-only':
        original, contract, expected = _pending(tmp_path)
    else:
        original, contract, expected = _two_phase_pending(tmp_path)
    opening = {'schema': 1, 'event': 'session_open',
               'profile': 'manifest-https-v1',
               'grant': original.audit[0]['grant'],
               'policy': original.audit[0]['policy']}
    startup, token = _synthetic_startup(opening, original.audit[0]['identity'])
    _write_native_audit(tmp_path, startup)
    saved = _session_prefix(tmp_path, token)
    _write_native_audit(tmp_path, [*startup, *original.audit])

    class Provider:
        def seen(self):
            return original.provider

    observation = _observation(
        tmp_path, Provider(), plan=original.plan, reply=original.reply,
        frame=original.frame, startup=saved,
        arrivals=[[*startup, *snapshot] for snapshot in original.provider_arrivals],
    )
    assert observation.audit == original.audit
    assert observation.provider_arrivals == original.provider_arrivals
    witness = checked_pending_witness(
        observed=observation, contract=contract, **expected,
    )
    assert witness.frame == original.frame
