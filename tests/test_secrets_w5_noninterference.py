"""W5 source/proof/assumption guard tests (not Lean kernel verification)."""
from __future__ import annotations

import importlib.util
import json
import shutil
from types import SimpleNamespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'w5_ni_contract', ROOT / 'dev/verification/w5_noninterference.py'
)
w5 = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(w5)


def fixture(tmp_path):
    paths = [w5.SPEC, w5.W4_SPEC, w5.W4, w5.PROOF,
             'proofs/generated/AivmSecretsGarrettCore.lean']
    for name in paths:
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, dest)
    return tmp_path


def refresh(root):
    path = root / w5.SPEC
    data = json.loads(path.read_text())
    data['proof_sha256'] = w5.digest(root / w5.PROOF)
    path.write_text(json.dumps(data, indent=2) + '\n')


def test_w5_contract_contains_scoped_two_run_and_adaptive_observations():
    info = w5.check(ROOT)
    assert info['theorems'] >= 10
    assert info['scope'] == 'adaptive-modeled-guest-observations-v1'


@pytest.mark.parametrize('old,new,pattern', [
    ('reflectionStatus : a.reflectionBlocked = b.reflectionBlocked',
     '-- reflection status is ignored', 'reviewed binding'),
    ('metadata : a.metadata = b.metadata',
     '-- hidden wire metadata', 'reviewed binding'),
    ('disclosure.Proofs.ProjectionAgreement',
     'disclosure.Proofs.UnconstrainedRelation', 'reviewed binding'),
    ('requestTrace r.pre r.final',
     '[] -- bypass W4 source-linked trace', 'reviewed binding'),
])
def test_w5_guard_rejects_unsafe_claim_changes_with_updated_hash(
        tmp_path, old, new, pattern):
    root = fixture(tmp_path)
    path = root / w5.PROOF
    source = path.read_text()
    assert old in source
    path.write_text(source.replace(old, new))
    refresh(root)
    with pytest.raises(w5.ContractError, match=pattern):
        w5.check(root)


def test_w5_rejects_new_axiom_and_unreviewed_theorem(tmp_path):
    root = fixture(tmp_path)
    path = root / w5.PROOF
    path.write_text(path.read_text() + '\naxiom bypass : False\n')
    refresh(root)
    with pytest.raises(w5.ContractError, match='unsupported escape'):
        w5.check(root)
    path.write_text(path.read_text().replace('axiom bypass : False',
                                              'theorem bypass : True := by trivial'))
    refresh(root)
    with pytest.raises(w5.ContractError, match='unreviewed W5 theorem'):
        w5.check(root)


def test_w5_rejects_silent_declassification_of_reflection(tmp_path):
    root = fixture(tmp_path)
    path = root / w5.SPEC
    data = json.loads(path.read_text())
    data['explicit_release_premises'].remove('reflectionStatus')
    path.write_text(json.dumps(data) + '\n')
    with pytest.raises(w5.ContractError, match='release classification'):
        w5.check(root)


def test_w5_rejects_missing_excluded_metadata_bytes(tmp_path):
    root = fixture(tmp_path)
    path = root / w5.SPEC
    data = json.loads(path.read_text())
    data['excluded_properties'].remove('concrete_transport_bytes_and_error_codes')
    path.write_text(json.dumps(data) + '\n')
    with pytest.raises(w5.ContractError, match='exclusions'):
        w5.check(root)


def test_w5_detects_w4_change(tmp_path):
    root = fixture(tmp_path)
    path = root / w5.W4
    path.write_text(path.read_text() + '\n-- source changed\n')
    with pytest.raises(w5.ContractError, match='W4 source changed'):
        w5.check(root)


def test_w5_prove_compiles_only_dependencies_and_w5_without_auditing(
        monkeypatch, tmp_path, capsys):
    root = fixture(tmp_path)
    backend = root / '.tools/aeneas/backends/lean/lakefile.lean'
    backend.parent.mkdir(parents=True)
    backend.write_text('package aeneas')
    monkeypatch.setattr(w5.shutil, 'which', lambda command: '/usr/bin/lake')
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0,
                               stdout='hidden dependency proof output\n',
                               stderr='')

    monkeypatch.setattr(w5.subprocess, 'run', fake_run)
    w5.prove(root)
    assert calls == [
        ['/usr/bin/lake', 'build', '+GarrettProtocol', '+GarrettManifest',
         '+GarrettDisclosure'],
        ['/usr/bin/lake', 'env', 'lean', '-DwarningAsError=true', '-o',
         str(root / 'proofs/.lake/build/lib/lean/GarrettConfinement.olean'),
         'GarrettConfinement.lean'],
        ['/usr/bin/lake', 'env', 'lean', '-DwarningAsError=true',
         'GarrettNoninterference.lean'],
    ]
    output = capsys.readouterr().out
    assert 'hidden dependency proof output' not in output
    assert 'W5 Lean compilation passed' in output


def test_w5_prove_reports_compiler_errors_without_auditing(
        monkeypatch, tmp_path, capsys):
    root = fixture(tmp_path)
    backend = root / '.tools/aeneas/backends/lean/lakefile.lean'
    backend.parent.mkdir(parents=True)
    backend.write_text('package aeneas')
    monkeypatch.setattr(w5.shutil, 'which', lambda command: '/usr/bin/lake')
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) < 3:
            return SimpleNamespace(returncode=0, stdout='dependency messages\n', stderr='')
        return SimpleNamespace(returncode=1,
                               stdout='GarrettNoninterference.lean:42:9: error: invalid proof\n',
                               stderr='')

    monkeypatch.setattr(w5.subprocess, 'run', fake_run)
    with pytest.raises(w5.ContractError, match='W5 Lean compilation failed'):
        w5.prove(root)
    output = capsys.readouterr().out
    assert 'dependency messages' not in output
    assert 'GarrettNoninterference.lean:42:9: error: invalid proof' in output


def test_w5_prove_refuses_missing_kernel(monkeypatch):
    monkeypatch.setattr(w5.shutil, 'which', lambda command: None)
    with pytest.raises(w5.ContractError, match='pinned Lean'):
        w5.prove(ROOT)


def test_w5_prove_reports_aeneas_bootstrap_requirement(monkeypatch, tmp_path):
    root = fixture(tmp_path)
    monkeypatch.setattr(w5.shutil, 'which', lambda command: '/usr/bin/lake')
    with pytest.raises(w5.ContractError, match='garrett.py bootstrap'):
        w5.prove(root)
