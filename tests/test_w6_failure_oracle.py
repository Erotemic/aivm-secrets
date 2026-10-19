"""Offline W4/W5 failed-read interpreter mutations; no Rust dependency."""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN
from tests.secrets_w6_failure import (
    FailureContract, assert_failed_reads_publicly_equivalent, checked_failure_witness,
)
from tests.secrets_w6_history import ReadObservation
from tests.secrets_w6_trace import TraceMismatch
from tests.test_rust_garrett_manifest import policy as ticket_policy


def _scenario(tmp_path, cause='http-4xx'):
    policy = ticket_policy(tmp_path)
    digest = codec.digest(parse_policy(policy).parse_request({
        'operation': 'ticket.view', 'arguments': {'ticket': 7},
    }).to_dict())
    effect = {
        'method': 'GET', 'target': '/v1/tickets/7',
        'accept': 'application/json', 'body': None, 'write': False,
    }
    identity = {'iss': 'test-issuer', 'aud': 'test-guest', 'sub': 'guest',
                'jti': 'test-token', 'iat': 100, 'exp': 200, 'epoch': 1,
                'cnf': {'x5t#S256': 'a' * 64}}
    dispatch = {
        'schema': 1, 'grant': 'c' * 32, 'policy': 'd' * 64,
        'identity': identity, 'operation': 'ticket.view',
        'event': 'dispatch', 'phase': 'final', 'request_digest': digest,
        'route': {'host': 'api.example.org', 'port': 443,
                  'method': 'GET', 'path': '/v1/tickets/7'},
    }
    reply = {'version': 1, 'ok': False, 'error': {
        'code': FailureContract(cause, ('final',)).error_code,
        'message': 'Broker failed closed.',
    }}
    observation = ReadObservation(
        provider=[{
            'method': 'GET', 'target': '/v1/tickets/7', 'body': '',
            'request_version': 'HTTP/1.1',
            'headers': {
                'host': 'api.example.org:443', 'accept': 'application/json',
                'accept-encoding': 'identity', 'user-agent': 'aivm-secrets/1',
                'connection': 'close', 'authorization': 'Bearer ' + TOKEN,
            },
        }],
        audit=[dispatch],
        reply=reply,
        frame=codec.dumps(reply) + b'\n',
        plan=[('final', effect)],
        provider_arrivals=[[dispatch]],
    )
    return {
        'left': observation, 'right': copy.deepcopy(observation),
        'left_contract': FailureContract(cause, ('final',)),
        'right_contract': FailureContract(cause, ('final',)),
        'policy': policy,
        'operation': 'ticket.view', 'normalized_arguments': {'ticket': 7},
        'credential': TOKEN, 'host': 'api.example.org', 'port': 443,
        'hidden_canaries': ('HIDDEN_FROM_PROVIDER_1', 'HIDDEN_FROM_PROVIDER_2'),
    }


@pytest.mark.parametrize('cause,code', [
    ('http-4xx', 'upstream_rejected'),
    ('http-other', 'upstream_error'),
    ('bad-representation', 'upstream_response'),
    ('disclosure-veto', 'upstream_response'),
])
def test_failure_category_is_declared_by_host(tmp_path, cause, code):
    case = _scenario(tmp_path, cause)
    assert case['left_contract'].error_code == code
    a, b = assert_failed_reads_publicly_equivalent(**case)
    assert a == b
    assert a.observed_events == (
        'audit:final', 'provider-send:final', 'guest-denied:' + code,
    )


def test_reject_different_declassified_failure_class(tmp_path):
    case = _scenario(tmp_path)
    case['right_contract'] = FailureContract('http-other', ('final',))
    with pytest.raises(TraceMismatch, match='public denial classes differ'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_changed_guest_error_even_if_each_message_is_public(tmp_path):
    case = _scenario(tmp_path)
    reply = {'version': 1, 'ok': False, 'error': {
        'code': 'upstream_error', 'message': 'Broker failed closed.',
    }}
    case['right'] = replace(case['right'], reply=reply, frame=codec.dumps(reply) + b'\n')
    with pytest.raises(TraceMismatch, match='different code'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_hidden_error_text_from_provider(tmp_path):
    case = _scenario(tmp_path)
    reply = {'version': 1, 'ok': False, 'error': {
        'code': 'upstream_rejected', 'message': 'HIDDEN_FROM_PROVIDER_1',
    }}
    case['right'] = replace(case['right'], reply=reply, frame=codec.dumps(reply) + b'\n')
    with pytest.raises(TraceMismatch):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_extra_guest_error_field(tmp_path):
    case = _scenario(tmp_path)
    reply = {**case['right'].reply, 'meta': {'private': 'x'}}
    case['right'] = replace(case['right'], reply=reply, frame=codec.dumps(reply) + b'\n')
    with pytest.raises(TraceMismatch, match='unexpected public denial fields'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_postdated_audit_on_failure(tmp_path):
    case = _scenario(tmp_path)
    case['right'] = replace(case['right'], provider_arrivals=[[]])
    with pytest.raises(TraceMismatch, match='not present when provider received'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_unapproved_second_provider_send_on_failure(tmp_path):
    case = _scenario(tmp_path)
    case['right'] = replace(case['right'], provider=case['right'].provider * 2)
    with pytest.raises(TraceMismatch, match='unexpected/missing credentialed'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_completion_audit_on_failed_request(tmp_path):
    case = _scenario(tmp_path)
    extra = {key: value for key, value in case['right'].audit[0].items()
             if key in {'schema', 'grant', 'policy', 'operation', 'request_digest'}}
    extra['event'] = 'completed'
    case['right'] = replace(case['right'], audit=case['right'].audit + [extra])
    with pytest.raises(TraceMismatch, match='completion audit/guest release'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_unapproved_write_in_failure_prefix(tmp_path):
    case = _scenario(tmp_path)
    effect = {**case['right'].plan[0][1], 'write': True}
    case['right'] = replace(case['right'], plan=[('final', effect)])
    with pytest.raises(TraceMismatch, match='write effect'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_modified_request_digest_on_failure(tmp_path):
    case = _scenario(tmp_path)
    bogus = {**case['right'].audit[0], 'request_digest': 'a' * 64}
    case['right'] = replace(case['right'], audit=[bogus], provider_arrivals=[[bogus]])
    with pytest.raises(TraceMismatch, match='host-normalized guest request'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_private_audit_field_on_failure(tmp_path):
    case = _scenario(tmp_path)
    row = {**case['right'].audit[0], 'diagnostic': 'HIDDEN_FROM_PROVIDER_2'}
    case['right'] = replace(case['right'], audit=[row], provider_arrivals=[[row]])
    with pytest.raises(TraceMismatch, match='extra/missing fields'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_doubled_guest_failure_frame(tmp_path):
    case = _scenario(tmp_path)
    case['right'] = replace(case['right'], frame=case['right'].frame * 2)
    with pytest.raises(TraceMismatch, match='incomplete or additional frame'):
        assert_failed_reads_publicly_equivalent(**case)


def test_failure_contract_rejects_invalid_or_empty_phase_paths(tmp_path):
    case = _scenario(tmp_path)
    for phases in ((), ('preflight', 'preflight'), ('final', 'preflight')):
        with pytest.raises(TraceMismatch, match='unmodeled'):
            checked_failure_witness(
                observed=case['left'],
                contract=FailureContract('http-4xx', phases),
                policy=case['policy'], operation=case['operation'],
                normalized_arguments=case['normalized_arguments'],
                credential=TOKEN, host='api.example.org', port=443,
            )


def test_reject_unreviewed_audit_field_without_a_canary(tmp_path):
    case = _scenario(tmp_path)
    row = {**case['right'].audit[0], 'credentials_encoded': 'not-in-explicit-canaries'}
    case['right'] = replace(case['right'], audit=[row], provider_arrivals=[[row]])
    with pytest.raises(TraceMismatch, match='extra/missing fields'):
        assert_failed_reads_publicly_equivalent(**case)


def test_reject_changed_identity_on_second_audited_phase(tmp_path):
    case = _scenario(tmp_path)
    row = case['right'].audit[0]
    second = {**row, 'phase': 'final',
              'identity': {**row['identity'], 'sub': 'unrelated-principal'}}
    first = {**row, 'phase': 'preflight'}
    observation = replace(
        case['right'], audit=[first, second],
        provider=[case['right'].provider[0], case['right'].provider[0]],
        plan=[('preflight', case['right'].plan[0][1]),
              ('final', case['right'].plan[0][1])],
        provider_arrivals=[[first], [first, second]],
    )
    with pytest.raises(TraceMismatch, match='bound client identities'):
        checked_failure_witness(
            observed=observation,
            contract=FailureContract('http-4xx', ('preflight', 'final')),
            policy=case['policy'], operation=case['operation'],
            normalized_arguments=case['normalized_arguments'],
            credential=TOKEN, host='api.example.org', port=443,
        )


def test_strict_schema_accepts_completed_native_read_shape(tmp_path):
    case = _scenario(tmp_path)
    dispatch = case['left'].audit[0]
    completed = {key: dispatch[key] for key in
                 ('schema', 'grant', 'policy', 'operation', 'request_digest')}
    completed['event'] = 'completed'
    reply = {'version': 1, 'ok': True, 'result': {'id': 7}}
    observation = replace(
        case['left'], audit=[dispatch, completed],
        reply=reply, frame=codec.dumps(reply) + b'\n',
    )
    from tests.secrets_w6_trace import assert_native_effect_trace
    assert_native_effect_trace(
        provider=observation.provider, audit=observation.audit,
        reply=observation.reply, planned=observation.plan,
        host='api.example.org', port=443, credential=TOKEN,
        expect_success=True, expected_result={'id': 7}, expected_meta=None,
        expected_request_digest=dispatch['request_digest'],
        guest_frame=observation.frame,
        audit_at_provider=observation.provider_arrivals,
        strict_audit_schema=True, expected_operation='ticket.view',
    )


def test_strict_schema_rejects_orphan_completion_identity(tmp_path):
    case = _scenario(tmp_path)
    dispatch = case['left'].audit[0]
    completed = {key: dispatch[key] for key in
                 ('schema', 'grant', 'policy', 'operation', 'request_digest')}
    completed['event'] = 'completed'
    completed['grant'] = 'f' * 32
    reply = {'version': 1, 'ok': True, 'result': {'id': 7}}
    from tests.secrets_w6_trace import assert_native_effect_trace
    with pytest.raises(TraceMismatch, match='mixed two grant/policy'):
        assert_native_effect_trace(
            provider=case['left'].provider,
            audit=[dispatch, completed], reply=reply,
            planned=case['left'].plan, host='api.example.org', port=443,
            credential=TOKEN, expect_success=True,
            strict_audit_schema=True, expected_operation='ticket.view',
        )


def test_failed_trace_harness_cannot_omit_expected_error(tmp_path):
    # This assertion fires before any Rust process or provider is consulted.
    from tests.test_rust_w6_adapter import trace_of
    with pytest.raises(AssertionError, match='independently declared error code'):
        trace_of(None, tmp_path, None, 'ticket.view', {'ticket': 7}, [],
                 successful=False, capture_observation=True)


def test_reject_unreviewed_failure_category():
    with pytest.raises(TraceMismatch, match='unreviewed public failure'):
        _ = FailureContract('unknown-provider-failure', ('final',)).error_code
