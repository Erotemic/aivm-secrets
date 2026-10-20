"""Portable assurance-scope regressions; no Lean compiler required."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

# Verification scripts are CLI modules with sibling imports, not a package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'dev/verification'))
import read_prefixes


def _snapshot(tmp_path, monkeypatch):
    src = read_prefixes.ROOT
    for name in (read_prefixes.PROOF, read_prefixes.SPEC,
                 'proofs/GarrettReadPaths.lean'):
        dst = tmp_path / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src / name, dst)
    # The already-reviewed dependent modules are checked separately by the
    # standard quick gate. Here we deliberately exercise this new guard.
    monkeypatch.setattr(read_prefixes.read_paths, 'check', lambda root: {})
    return tmp_path


def test_new_generic_lean_provenance_guard(tmp_path, monkeypatch):
    root = _snapshot(tmp_path, monkeypatch)
    assert read_prefixes.check(root)['theorems'] == 5


def test_proof_guard_rejects_dropped_open_obligations(tmp_path, monkeypatch):
    root = _snapshot(tmp_path, monkeypatch)
    p = root / read_prefixes.SPEC
    manifest = json.loads(p.read_text())
    manifest['open_obligations'].remove('TLS-RECORD-AND-SEND-BOUNDARY')
    p.write_text(json.dumps(manifest))
    with pytest.raises(read_prefixes.PrefixReviewError, match='security assumption'):
        read_prefixes.check(root)


def test_proof_guard_rejects_silent_theorem_or_axiom_changes(tmp_path, monkeypatch):
    root = _snapshot(tmp_path, monkeypatch)
    proof = root / read_prefixes.PROOF
    proof.write_text(proof.read_text().replace(
        '#print axioms aivm_secrets_garrett_core.confinement.ReadPrefixes.history_sound',
        '#print axioms omitted_history_sound',
    ))
    with pytest.raises(read_prefixes.PrefixReviewError, match='Lean source changed'):
        read_prefixes.check(root)
    # A reviewer updating the fingerprint must still preserve the axiom audit.
    p = root / read_prefixes.SPEC
    manifest = json.loads(p.read_text())
    manifest['proof_sha256'] = read_prefixes.sha(proof)
    p.write_text(json.dumps(manifest))
    with pytest.raises(read_prefixes.PrefixReviewError, match='kernel axiom report'):
        read_prefixes.check(root)
