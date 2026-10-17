"""W0 source/assumption reference integrity (not a security proof)."""

import copy
import json

from dev.verification.w0_contract import LEDGER, ROOT, SPEC, validate


def load_contract():
    return json.loads(SPEC.read_text(encoding='utf8'))


def load_ledger():
    return json.loads(LEDGER.read_text(encoding='utf8'))


def test_w0_boundary_contract_has_closed_references():
    assert validate(load_contract(), load_ledger(), ROOT) == []


def test_unclassified_guest_sink_is_detected():
    contract = load_contract()
    bogus = copy.deepcopy(contract['sinks'][0])
    bogus['id'] = 'S-NEW-GUEST-SINK'
    bogus['release_rules'] = []
    contract['sinks'].append(bogus)
    errors = validate(contract, load_ledger(), ROOT)
    assert any('S-NEW-GUEST-SINK' in error for error in errors)


def test_missing_environmental_premise_is_detected():
    contract = load_contract()
    contract['profiles'][0]['assumptions'].append('UNKNOWN-ENVIRONMENT')
    errors = validate(contract, load_ledger(), ROOT)
    assert any('UNKNOWN-ENVIRONMENT' in error for error in errors)


def test_downgrading_guest_observation_to_host_only_is_detected():
    contract = load_contract()
    observation = next(obs for obs in contract['observations'] if obs['id'] == 'O-GUEST-BYTES')
    observation['treatment'] = 'other_principal'
    errors = validate(contract, load_ledger(), ROOT)
    assert any('guest-readable' in error for error in errors)


def test_unlinked_release_is_detected():
    contract = load_contract()
    contract['sinks'][0]['release_rules'].remove('R-GUEST-RESULT')
    errors = validate(contract, load_ledger(), ROOT)
    assert any('asymmetric' in error for error in errors)
