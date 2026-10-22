"""Focused opt-in source-guard regressions; not a formal reachability proof."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nr23_native_edges',
    ROOT / 'dev' / 'verification' / 'nr23_native_edges.py')
assert SPEC and SPEC.loader
import sys

module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_known_reviewed_production_edges() -> None:
    assert not module.scan(module.read_sources())


def test_mutations_in_each_reviewed_edge_are_detected() -> None:
    baseline = module.read_sources()
    for edge in module.EDGES:
        source = baseline[edge.file]
        start = source.index(edge.start)
        stop = source.index(edge.stop, start + len(edge.start))
        region = source[start:stop]
        cursor = 0
        for marker in edge.sequence:
            at = region.index(marker, cursor)
            cursor = at + len(marker)
        at = cursor - len(marker)
        altered = region[:at] + 'NR23_MUTATED' + region[cursor:]
        tampered = source[:start] + altered + source[stop:]
        sources = dict(baseline)
        sources[edge.file] = tampered
        findings = module.scan(sources)
        assert any(edge.label in item for item in findings), edge.label


def test_order_change_is_detected() -> None:
    edge = next(e for e in module.EDGES if e.label == 'fail-stop-audit-prepoison-and-sync')
    sources = module.read_sources()
    source = sources[edge.file]
    start = source.index(edge.start)
    stop = source.index(edge.stop, start + len(edge.start))
    region = source[start:stop]
    assert 'sink.sync_record()?;' in region and '*poisoned = false;' in region
    region = region.replace('sink.sync_record()?;\n    *poisoned = false;',
                            '*poisoned = false;\n    sink.sync_record()?;')
    sources[edge.file] = source[:start] + region + source[stop:]
    assert any('fail-stop-audit-prepoison-and-sync' in p for p in module.scan(sources))
