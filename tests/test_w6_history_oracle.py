"""Portable W5 paired-observation mutations; no Rust binary or provider needed."""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from aivm_secrets.primitives import codec
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import TOKEN
from tests.secrets_w6_history import ReadObservation, assert_publicly_equivalent
from tests.secrets_w6_trace import TraceMismatch
from tests.test_rust_garrett_manifest import policy as ticket_policy, disclosure as ticket_disclosure


def _case(tmp_path):
    credential = TOKEN
    p = ticket_policy(tmp_path)
    normalized = parse_policy(p).parse_request({
        'operation': 'ticket.view', 'arguments': {'ticket': 7},
    }).to_dict()
    request_digest = codec.digest(normalized)
    dispatch = {
        'event': 'dispatch', 'phase': 'final', 'request_digest': request_digest,
        'route': {'host': 'api.example.org', 'port': 443,
                  'method': 'GET', 'path': '/v1/tickets/7'},
    }
    completion = {'event': 'completed', 'request_digest': request_digest}
    effect = {'method': 'GET', 'target': '/v1/tickets/7',
              'accept': 'application/json', 'body': None, 'write': False}
    response = {'version': 1, 'ok': True, 'result': {'id': 7}}
    observed = ReadObservation(
        provider=[{'method': 'GET', 'target': '/v1/tickets/7', 'body': '',
                   'request_version': 'HTTP/1.1',
                   'headers': {'host': 'api.example.org:443',
                               'accept': 'application/json', 'accept-encoding': 'identity',
                               'user-agent': 'aivm-secrets/1', 'connection': 'close',
                               'authorization': 'Bearer ' + credential}}],
        audit=[dispatch, completion],
        reply=response,
        frame=codec.dumps(response) + b'\n',
        plan=[('final', effect)],
        provider_arrivals=[[dispatch]],
    )
    return {
        'policy': p, 'disclosure': ticket_disclosure(),
        'operation': 'ticket.view', 'normalized_arguments': {'ticket': 7},
        'provider_left': {'id': 7, 'private': 'HIDDEN_A_8732'},
        'provider_right': {'id': 7, 'private': 'HIDDEN_B_8732'},
        'left': observed, 'right': copy.deepcopy(observed),
        'credential': credential, 'host': 'api.example.org', 'port': 443,
        'hidden_canaries': ('HIDDEN_A_8732', 'HIDDEN_B_8732'),
    }


def test_equivalent_approved_private_mutation_passes(tmp_path):
    assert_publicly_equivalent(**_case(tmp_path))


def test_reject_changed_selected_value_even_with_same_guest_reply(tmp_path):
    case = _case(tmp_path)
    case['provider_right']['id'] = 8
    with pytest.raises(TraceMismatch, match='selected host releases differ'):
        assert_publicly_equivalent(**case)


def test_reject_unauthorized_extra_guest_field(tmp_path):
    case = _case(tmp_path)
    result = {'version': 1, 'ok': True, 'result': {'id': 7, 'debug': 'HIDDEN_B_8732'}}
    case['right'] = replace(case['right'], reply=result, frame=codec.dumps(result) + b'\n')
    with pytest.raises(TraceMismatch):
        assert_publicly_equivalent(**case)


def test_reject_postdated_audit_mutant(tmp_path):
    case = _case(tmp_path)
    case['right'] = replace(case['right'], provider_arrivals=[[]])
    with pytest.raises(TraceMismatch, match='dispatch audit was not present'):
        assert_publicly_equivalent(**case)


def test_reject_guest_extra_frame_even_when_reply_matches(tmp_path):
    case = _case(tmp_path)
    right = case['right']
    case['right'] = replace(right, frame=right.frame + right.frame)
    with pytest.raises(TraceMismatch, match='incomplete or additional frame'):
        assert_publicly_equivalent(**case)


def test_reject_extra_provider_send_not_in_host_plan(tmp_path):
    case = _case(tmp_path)
    right = case['right']
    case['right'] = replace(right, provider=right.provider + right.provider)
    with pytest.raises(TraceMismatch, match='unexpected/missing credentialed provider send'):
        assert_publicly_equivalent(**case)


def test_reject_changed_release_metadata(tmp_path):
    case = _case(tmp_path)
    op = next(op for op in case['policy']['operations'] if op['name'] == 'ticket.list')
    assert op['page']['size'] == 2
    case['operation'] = 'ticket.list'
    case['normalized_arguments'] = {'page': 1, 'state': 'open'}
    # Hold the selected field fixed while changing only raw page length.
    case['disclosure']['ticket.list'] = {
        'id': {'at': ['id'], 'type': 'integer'},
    }
    case['provider_left'] = {'id': 7, 'rows': [{'id': 7}, {'id': 8}]}
    case['provider_right'] = {'id': 7, 'rows': [{'id': 7}]}
    with pytest.raises(TraceMismatch, match='public metadata differs'):
        assert_publicly_equivalent(**case)


def test_reject_hidden_provider_field_in_host_audit(tmp_path):
    case = _case(tmp_path)
    right = case['right']
    case['right'] = replace(right, audit=[{**right.audit[0], 'hidden': 'HIDDEN_B_8732'},
                                          right.audit[1]])
    with pytest.raises(TraceMismatch):
        assert_publicly_equivalent(**case)


def test_reject_write_phase_in_read_observation(tmp_path):
    case = _case(tmp_path)
    left = case['left']
    case['left'] = replace(left, plan=[('final', {**left.plan[0][1], 'write': True})])
    with pytest.raises(TraceMismatch, match='host effect plan differs'):
        assert_publicly_equivalent(**case)


def test_reject_different_normalized_audit_identity(tmp_path):
    case = _case(tmp_path)
    right = case['right']
    other = 'a' * 64
    changed = [{**right.audit[0], 'request_digest': other},
               {**right.audit[1], 'request_digest': other}]
    case['right'] = replace(right, audit=changed, provider_arrivals=[[changed[0]]])
    with pytest.raises(TraceMismatch, match='host-normalized guest request'):
        assert_publicly_equivalent(**case)


def test_reflection_decision_is_an_explicit_release_premise(tmp_path):
    case = _case(tmp_path)
    case['disclosure']['ticket.view'] = {
        'name': {'at': ['name'], 'type': 'text'},
    }
    case['provider_left'] = {'name': 'public'}
    case['provider_right'] = {'name': TOKEN}
    # A leaked credential is a public denial condition in the native profile,
    # not an input variation that W5 may silently treat as unobservable.
    with pytest.raises(TraceMismatch, match='unapproved host release'):
        assert_publicly_equivalent(**case)
