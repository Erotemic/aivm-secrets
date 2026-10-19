"""Fast, binary-free W6 release tests and negative oracle mutations."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from tests.secrets_helpers import TOKEN
from tests.secrets_w6_release import ReleaseMismatch, release
from tests.test_rust_garrett_manifest import disclosure, policy


def selected_page():
    config = policy(Path('/synthetic'))
    rules = disclosure()
    args = {'page': 2, 'state': 'closed'}  # host-normalized defaults are explicit
    response = {'rows': [
        {'id': 7, 'token': TOKEN, 'owner': {'address': 'hidden@example.test'}},
        {'id': 8, 'debug': ['unselected', 'private']},
    ]}
    return config, rules, args, response


def test_w6_oracle_derives_selected_result_and_metadata_without_a_guest_reply():
    config, rules, args, provider = selected_page()
    selected, meta = release(config, rules, 'ticket.list', args, provider, credential=TOKEN)
    assert selected == {'rows': [{'id': 7}, {'id': 8}]}
    assert meta == {'pagination': {'per_page': 2, 'page': 2, 'possibly_more': True}}
    other = copy.deepcopy(provider)
    other['rows'][0]['token'] = 'a different private provider value'
    other['rows'][0]['owner'] = {'address': 'another discarded private address'}
    assert release(config, rules, 'ticket.list', args, other, credential=TOKEN) == (selected, meta)
    shorter = {'rows': [provider['rows'][0]]}
    _, new_meta = release(config, rules, 'ticket.list', args, shorter, credential=TOKEN)
    assert new_meta == {'pagination': {'per_page': 2, 'page': 2, 'possibly_more': False}}


def test_w6_oracle_has_no_raw_provider_fallback_and_checks_types():
    config, rules, args, provider = selected_page()
    mutations = []
    bad = copy.deepcopy(provider)
    bad['rows'][0]['id'] = True  # Python True == 1 must not pass integer selection
    mutations.append(bad)
    bad = copy.deepcopy(provider)
    bad['rows'][0].pop('id')
    mutations.append(bad)
    bad = copy.deepcopy(provider)
    bad['rows'].append({'id': 9})  # Host selected max_items=2
    mutations.append(bad)
    bad = copy.deepcopy(provider)
    bad['rows'] = {'id': 7}
    mutations.append(bad)
    for changed in mutations:
        with pytest.raises(ReleaseMismatch):
            release(config, rules, 'ticket.list', args, changed, credential=TOKEN)


def test_w6_oracle_refuses_credential_reflection_in_a_selected_value():
    config, rules, args, provider = selected_page()
    provider['rows'][1]['id'] = 9
    rules['ticket.list']['rows']['items']['fields']['note'] = {
        'at': ['note'], 'type': 'text',
    }
    for row in provider['rows']:
        row['note'] = 'safe selected value'
    provider['rows'][1]['note'] = 'prefix-' + TOKEN + '-suffix'
    with pytest.raises(ReleaseMismatch, match='reflected'):
        release(config, rules, 'ticket.list', args, provider, credential=TOKEN)


def test_w6_oracle_no_preflight_scalar_result_is_strict():
    config, rules, _, _ = selected_page()
    expected = release(config, rules, 'ticket.view', {'ticket': 7},
                       {'id': 7, 'hidden': TOKEN}, credential=TOKEN)
    assert expected == ({'id': 7}, None)
    with pytest.raises(ReleaseMismatch, match='integer'):
        release(config, rules, 'ticket.view', {'ticket': 7},
                {'id': True}, credential=TOKEN)
