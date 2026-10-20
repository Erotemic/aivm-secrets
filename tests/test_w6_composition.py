"""Offline mutations of the compositional native-read normal form."""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from tests.secrets_w6_composition import ReadContract, read_prefix, sequential_history
from tests.secrets_w6_history import assert_publicly_equivalent
from tests.secrets_w6_failure import checked_failure_witness
from tests.secrets_w6_pending import checked_pending_witness
from tests.secrets_w6_trace import TraceMismatch
from tests.test_w6_history_oracle import _case
from tests.test_w6_failure_oracle import _scenario
from tests.test_w6_pending_oracle import _pending, _two_phase_pending, _synthetic_startup, _opening


def _good_release(tmp_path):
    case = _case(tmp_path)
    assert_publicly_equivalent(**case)
    return case['left']


def test_composed_success_failure_pending_cover_existing_concrete_oracles(tmp_path):
    success = _good_release(tmp_path)
    checked = read_prefix(success, ReadContract('released', ('final',), ('final',)))
    assert checked.events == ('audit:final', 'provider-send:final',
                              'audit:completed', 'guest-released')
    failure = _scenario(tmp_path)
    checked_failure_witness(
        observed=failure['left'], contract=failure['left_contract'],
        policy=failure['policy'], operation=failure['operation'],
        normalized_arguments=failure['normalized_arguments'],
        credential=failure['credential'], host=failure['host'], port=failure['port'],
    )
    denied = read_prefix(failure['left'], ReadContract(
        'provider-denied', ('final',), ('final',), 'upstream_rejected'))
    assert denied.events == ('audit:final', 'provider-send:final',
                             'guest-denied:upstream_rejected')
    pending, contract, expected = _pending(tmp_path)
    checked_pending_witness(observed=pending, contract=contract, **expected)
    unsent = read_prefix(pending, ReadContract(
        'pending-denied', ('final',), (), 'revoked'))
    assert unsent.events == ('audit:final', 'guest-denied:revoked')
    two_phase, contract, expected = _two_phase_pending(tmp_path)
    checked_pending_witness(observed=two_phase, contract=contract, **expected)
    partial = read_prefix(two_phase, ReadContract(
        'pending-denied', ('preflight', 'final'), ('preflight',), 'revoked'))
    assert partial.events == ('audit:preflight', 'provider-send:preflight',
                              'audit:final', 'guest-denied:revoked')


@pytest.mark.parametrize('contract', [
    ReadContract('released', ('final',), (), None),
    ReadContract('provider-denied', ('final',), (), 'revoked'),
    ReadContract('pending-denied', ('preflight', 'final'), (), 'revoked'),
    ReadContract('released', ('preflight', 'final'), ('final',), None),
    ReadContract('released', ('final', 'preflight'), ('final', 'preflight'), None),
    ReadContract('released', ('final',), ('final',), 'upstream_error'),
])
def test_reject_unmodeled_transition_contract(contract):
    with pytest.raises(TraceMismatch):
        contract.validate()


@pytest.mark.parametrize('mutation', [
    'lost-completion', 'early-completion', 'extra-provider',
    'provider-after-completion', 'wrong-phase', 'write-effect',
    'guest-leak', 'wrong-digest', 'wrong-declared-outcome',
])
def test_reject_invalid_single_request_prefix(tmp_path, mutation):
    observation = copy.deepcopy(_good_release(tmp_path))
    contract = ReadContract('released', ('final',), ('final',))
    if mutation == 'lost-completion':
        observation.audit.pop()
    elif mutation == 'early-completion':
        observation.audit.reverse()
    elif mutation == 'extra-provider':
        observation.provider.append(copy.deepcopy(observation.provider[0]))
    elif mutation == 'provider-after-completion':
        observation.provider_arrivals[0].append(observation.audit[1])
    elif mutation == 'wrong-phase':
        observation.audit[0]['phase'] = 'preflight'
    elif mutation == 'write-effect':
        observation.plan[0][1]['write'] = True
    elif mutation == 'guest-leak':
        observation = replace(observation, frame=observation.frame * 2)
    elif mutation == 'wrong-digest':
        observation.audit[1]['request_digest'] = 'a' * 64
    elif mutation == 'wrong-declared-outcome':
        contract = ReadContract('provider-denied', ('final',), ('final',), 'upstream_error')
    with pytest.raises(TraceMismatch):
        read_prefix(observation, contract)


def _session(tmp_path):
    case = _case(tmp_path)
    opening, issued_token = _synthetic_startup(_opening())
    identity = opening[1]['identity']
    grant = opening[0]['grant']
    policy = opening[0]['policy']
    observations = []
    for _ in range(2):
        obs = copy.deepcopy(case['left'])
        request_rows = []
        for row in obs.audit:
            new = {'schema': 1, 'grant': grant, 'policy': policy, **row}
            if new['event'] == 'dispatch':
                new['identity'] = copy.deepcopy(identity)
            request_rows.append(new)
        obs = replace(obs, audit=request_rows, provider_arrivals=[[request_rows[0]]])
        observations.append(obs)
    refined = [read_prefix(obs, ReadContract('released', ('final',), ('final',)))
               for obs in observations]
    complete = [*opening, *refined[0].audit, *refined[1].audit]
    arrivals = [opening + list(refined[0].provider_arrivals[0]),
                opening + list(refined[0].audit) + list(refined[1].provider_arrivals[0])]
    return refined, opening, complete, arrivals


def test_sequential_history_compiles_actual_full_audit_and_arrival_snapshots(tmp_path):
    prefixes, opening, complete, arrivals = _session(tmp_path)
    checked = sequential_history(prefixes=prefixes, session_open_and_issued=opening,
                                 complete_host_audit=complete, provider_arrivals=arrivals)
    assert len(checked.frames) == 2
    assert checked.events.count('guest-released') == 2
    assert checked.events.count('provider-send:final') == 2


@pytest.mark.parametrize('mutation', [
    'unknown-event', 'postdated-first-arrival', 'extra-provider-arrival',
    'second-principal', 'second-policy', 'startup-reorder', 'changed-issued-principal',
    'missing-session-completion', 'extra-audit-between-requests',
])
def test_sequential_history_rejects_mutations(tmp_path, mutation):
    prefixes, opening, complete, arrivals = _session(tmp_path)
    prefixes, opening, complete, arrivals = (
        copy.deepcopy(prefixes), copy.deepcopy(opening),
        copy.deepcopy(complete), copy.deepcopy(arrivals),
    )
    if mutation == 'unknown-event':
        complete.append({'event': 'leak'})
    elif mutation == 'postdated-first-arrival':
        arrivals[0].append(copy.deepcopy(complete[3]))
    elif mutation == 'extra-provider-arrival':
        arrivals.append(copy.deepcopy(arrivals[-1]))
    elif mutation == 'second-principal':
        second = prefixes[1]
        rows = list(second.audit)
        rows[0] = {**rows[0], 'identity': {**rows[0]['identity'], 'sub': 'other'}}
        prefixes[1] = replace(second, audit=tuple(rows))
        complete[4] = rows[0]
    elif mutation == 'second-policy':
        complete[4] = {**complete[4], 'policy': 'f' * 64}
    elif mutation == 'startup-reorder':
        opening.reverse()
    elif mutation == 'changed-issued-principal':
        opening[1]['identity']['sub'] = 'substituted'
    elif mutation == 'missing-session-completion':
        complete.pop()
    elif mutation == 'extra-audit-between-requests':
        complete.insert(4, {'event': 'surprise'})
    with pytest.raises(TraceMismatch):
        sequential_history(prefixes=prefixes, session_open_and_issued=opening,
                           complete_host_audit=complete, provider_arrivals=arrivals)
