"""Portable mutation checks for the reviewed native public-error source leaf."""
from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'dev/verification/w6_error_boundary.py'
spec = importlib.util.spec_from_file_location('w6_error_boundary', SCRIPT)
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def _review_snapshot(tmp_path):
    for name in (checker.MANIFEST, checker.TLS, checker.ERROR,
                 checker.MANIFEST_SESSION, checker.PUBLIC_ERROR, checker.STATUS,
                 checker.CUSTODY):
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    return tmp_path


def test_reviewed_public_denial_leaf_is_stable(tmp_path):
    assert checker.check(_review_snapshot(tmp_path))['public_classes'] == 4


@pytest.mark.parametrize('name,original,mutant', [
    (checker.PUBLIC_ERROR, 'b"Broker failed closed."', 'b"Provider said: "'),
    (checker.TLS, 'aivm_secrets_garrett_core::public_error::answer_frame(public, MAX_REPLY)', 'json::capture(&json!({"detail": format!("{:?}", captured.as_ref().err())})).prepare(MAX_REPLY)'),
    (checker.TLS, 'write_all(wire)', 'write_all(&b"raw"[..])'),
    (checker.TLS, 'self.0.send(&mut GuestWriter(writer))',
     'unchecked_send(writer)'),
    (checker.ERROR, 'PublicError::UpstreamRejected => "upstream_rejected"',
     'PublicError::UpstreamRejected => "upstream_error"'),
    (checker.STATUS, 'if status >= 400 && status < 500 {', 'if status >= 400 && status < 499 {'),
])
def test_public_error_mutations_are_rejected(tmp_path, name, original, mutant):
    root = _review_snapshot(tmp_path)
    path = root / name
    source = path.read_text()
    assert source.count(original) >= 1
    path.write_text(source.replace(original, mutant, 1))
    with pytest.raises(checker.ReviewError):
        checker.check(root)


def test_failure_scope_cannot_drop_unproved_runtime_correspondence(tmp_path):
    root = _review_snapshot(tmp_path)
    path = root / checker.MANIFEST
    manifest = json.loads(path.read_text())
    manifest['excluded'].remove('full-native-to-Lean-simulation')
    path.write_text(json.dumps(manifest))
    with pytest.raises(checker.ReviewError, match='dropped an open obligation'):
        checker.check(root)


def test_failure_scope_cannot_drop_observable_channel(tmp_path):
    root = _review_snapshot(tmp_path)
    path = root / checker.MANIFEST
    manifest = json.loads(path.read_text())
    manifest['expected_observations'].remove('canonical-single-guest-jsonl-frame')
    path.write_text(json.dumps(manifest))
    with pytest.raises(checker.ReviewError, match='observation set changed'):
        checker.check(root)
