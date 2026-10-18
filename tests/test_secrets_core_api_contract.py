"""Keep the Python core/Rust parity classification executable and complete."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTRACT = REPO / 'docs/planning/aivm-secrets-python-core-api.json'


def test_every_python_module_is_classified_and_symbols_exist():
    data = json.loads(CONTRACT.read_text())
    assert data['schema'] == 1
    core = data['classification']['core_modules']
    noncore = data['classification']['non_core_modules']
    assert core and noncore
    assert set(core).isdisjoint(noncore)
    discovered = {
        str(path.relative_to(REPO)).replace('/', '.')[:-3]
        for path in (REPO / 'aivm_secrets').rglob('*.py')
    }
    assert set(core) | set(noncore) == discovered, (
        'New Python modules must be explicitly core or non-core; '
        'unclassified modules or stale manifest entries detected')
    ids = set()
    symbols = set()
    assert len(data['core_contracts']) >= 9
    for contract in data['core_contracts']:
        assert contract['id'] not in ids
        ids.add(contract['id'])
        assert contract['rust'] in data['rust_parity_states']
        assert contract['acceptance'] and contract['python']
        for reference in contract['python']:
            module, target = reference.split(':', 1)
            assert module in core
            obj = importlib.import_module(module)
            for part in target.split('.'):
                assert hasattr(obj, part), reference
                obj = getattr(obj, part)
            symbols.add(reference)
        for source in contract['rust_source']:
            assert (REPO / source).is_file(), source
    assert len(symbols) >= 15


def test_new_core_contracts_are_explicit_rust_parity_gaps():
    data = json.loads(CONTRACT.read_text())
    by_id = {c['id']: c for c in data['core_contracts']}
    assert by_id['CORE-07']['rust'] == 'missing'
    assert by_id['CORE-08']['rust'] == 'missing'
    assert by_id['CORE-09']['rust'] == 'missing'
    assert by_id['CORE-06']['rust'] == 'partial'
    assert 'outcome' in by_id['CORE-10']['acceptance']
