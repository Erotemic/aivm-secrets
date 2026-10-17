"""W4 source/claim guard. These tests are *not* a substitute for Lean."""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'w4_trace_contract', ROOT / 'dev/verification/w4_trace.py'
)
w4 = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(w4)


def fixture_root(tmp_path):
    info = json.loads((ROOT / w4.MANIFEST).read_text())
    files = {*info['core_sha256'], w4.MANIFEST, w4.PROOF}
    for name in files:
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, dest)
    return tmp_path


def refresh_proof_hash(root):
    manifest = root / w4.MANIFEST
    data = json.loads(manifest.read_text())
    data['proof_sha256'] = w4.digest(root / w4.PROOF)
    manifest.write_text(json.dumps(data) + '\n')


def test_w4_contract_is_source_linked():
    info = w4.check(ROOT)
    assert info['source_inputs'] == 5
    assert info['theorems'] >= 12
    assert 'structure only' in info['status']


@pytest.mark.parametrize('before,after,expected', [
    ('gate.accepted ∧ auditOK = true', 'True', 'reviewed binding'),
    ('aivm_secrets_garrett_core.manifest.authorize',
     'True -- dropped extracted authorization', 'reviewed binding'),
    ('aivm_secrets_garrett_core.disclosure.project',
     'True -- dropped extracted projection', 'reviewed binding'),
    ('#print axioms aivm_secrets_garrett_core.confinement.Proofs.request_trace_sound',
     '-- missing kernel audit', 'Lean axiom audit'),
])
def test_w4_review_guard_rejects_bypasses_even_after_hash_refresh(
        tmp_path, before, after, expected):
    root = fixture_root(tmp_path)
    proof_path = root / w4.PROOF
    proof = proof_path.read_text()
    assert before in proof
    proof_path.write_text(proof.replace(before, after))
    refresh_proof_hash(root)
    with pytest.raises(w4.ContractError, match=expected):
        w4.check(root)


def test_w4_extracted_source_drift_is_detected(tmp_path):
    root = fixture_root(tmp_path)
    source = root / 'rust/crates/aivm-secrets-garrett-core/src/manifest.rs'
    source.write_text(source.read_text() + '\n// reviewed core changed\n')
    with pytest.raises(w4.ContractError, match='core/extraction changed'):
        w4.check(root)


def test_w4_scope_cannot_silently_drop_adapter_obligations(tmp_path):
    root = fixture_root(tmp_path)
    path = root / w4.MANIFEST
    data = json.loads(path.read_text())
    data['open_obligations'].remove('IO-REFINE')
    path.write_text(json.dumps(data) + '\n')
    with pytest.raises(w4.ContractError, match='missing unproved'):
        w4.check(root)


def test_w4_unrecorded_theorem_is_rejected(tmp_path):
    root = fixture_root(tmp_path)
    proof_path = root / w4.PROOF
    proof_path.write_text(proof_path.read_text() + '\ntheorem surprise : True := by trivial\n')
    refresh_proof_hash(root)
    with pytest.raises(w4.ContractError, match='unreviewed W4 theorem'):
        w4.check(root)


def test_w4_axiom_audit_accepts_only_builtins():
    info = json.loads((ROOT / w4.MANIFEST).read_text())
    lines = '\n'.join(
        f"'aivm_secrets_garrett_core.confinement.Proofs.{n}' does not depend on any axioms"
        for n in info['theorems']
    )
    w4.audit(lines, info['theorems'])
    injected = re.sub('does not depend on any axioms',
                      'depends on axioms: [project.SecretEscape]', lines, count=1)
    with pytest.raises(w4.ContractError, match='unreviewed axioms'):
        w4.audit(injected, info['theorems'])
    with pytest.raises(w4.ContractError, match='incomplete'):
        w4.audit('\n'.join(lines.splitlines()[1:]), info['theorems'])


def test_w4_prove_refuses_missing_kernel(monkeypatch):
    monkeypatch.setattr(w4.shutil, 'which', lambda command: None)
    with pytest.raises(w4.ContractError, match='pinned'):
        w4.prove(ROOT)


def test_w4_prove_reports_missing_aeneas_backend(monkeypatch, tmp_path):
    # A working `lake` alone is insufficient: proofs/lakefile.lean requires
    # the pinned, locally bootstrapped Aeneas backend.
    fake_lake = tmp_path / 'lake'
    fake_lake.write_text('#!/bin/sh\nexit 0\n')
    monkeypatch.setattr(w4.shutil, 'which', lambda command: str(fake_lake))
    with pytest.raises(w4.ContractError, match='garrett.py bootstrap'):
        w4.prove(fixture_root(tmp_path))
