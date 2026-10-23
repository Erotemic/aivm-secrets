"""Every ledgered assumption has a class, justification and removal roadmap."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLANNING = ROOT / 'docs' / 'planning'


def test_every_assumption_is_on_the_roadmap() -> None:
    ledger = json.loads((PLANNING / 'aivm-secrets-assumptions.json').read_text())
    roadmap = json.loads((PLANNING / 'aivm-secrets-assumption-roadmap.json').read_text())
    ids = [entry['id'] for entry in ledger['assumptions']]
    rows = {row['id']: row for row in roadmap['entries']}
    assert len(rows) == len(roadmap['entries']), 'duplicate roadmap rows'
    assert set(rows) == set(ids), (set(ids) - set(rows), set(rows) - set(ids))
    fields = {'id', 'class', 'justification', 'track', 'removal', 'priority'}
    for row in rows.values():
        assert set(row) == fields, row['id']
        assert row['class'] in roadmap['classes'], row['id']
        assert all(row[key].strip() for key in fields), row['id']
    # Project-owned native code must have a concrete, prioritized removal path.
    for row in rows.values():
        if row['class'] == 'native-trusted':
            assert row['priority'] in {'P0', 'P1', 'P2', 'P3'}, row['id']


def test_roadmap_document_names_every_class_and_native_entry() -> None:
    roadmap = json.loads((PLANNING / 'aivm-secrets-assumption-roadmap.json').read_text())
    text = (PLANNING / 'aivm-secrets-assumption-roadmap.md').read_text()
    for name in roadmap['classes']:
        assert f'`{name}`' in text, name
    for row in roadmap['entries']:
        if row['class'] == 'native-trusted':
            assert row['id'] in text, row['id']
