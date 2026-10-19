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
                 checker.MANIFEST_SESSION):
        dest = tmp_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    return tmp_path


def test_reviewed_public_denial_leaf_is_stable(tmp_path):
    assert checker.check(_review_snapshot(tmp_path))['public_classes'] == 4


@pytest.mark.parametrize('name,original,mutant', [
    (checker.TLS, '"Broker failed closed."', '"Provider said: "'),
    (checker.TLS, 'Self(answer.unwrap_or_else(failure))', 'Self(answer.unwrap())'),
    (checker.TLS, 'write_all(&json::canonical(&self.0))', 'write_all(&b"raw"[..])'),
    (checker.TLS, '.and_then(|_| writer.write_all(b"\\n"))',
     '.and_then(|_| writer.write_all(b"\\n\\n"))'),
    (checker.ERROR, 'Self::UpstreamRejected => "upstream_rejected"',
     'Self::UpstreamRejected => "upstream_error"'),
    (checker.MANIFEST_SESSION, 'if (400..500).contains(&status) {',
     'if (400..499).contains(&status) {'),
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
