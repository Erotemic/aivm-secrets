"""Acceptance must reject the green-but-skipped native backend failure mode."""
from pathlib import Path
import importlib.util

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('system_gate', ROOT / 'dev/verification/system.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


@pytest.mark.parametrize('body', [
    '<testsuite/>',
    '<testsuite><testcase name="bad"><failure/></testcase></testsuite>',
    '<testsuite><testcase name="bad"><error/></testcase></testsuite>',
    '<testsuite><testcase name="native"><skipped message="binary unavailable"/></testcase></testsuite>',
])
def test_no_cases_or_missing_native_backend_fails(tmp_path, body):
    report = tmp_path / 'report.xml'
    report.write_text(body)
    with pytest.raises(RuntimeError):
        gate.require_no_skips(report)


def test_nested_junit_success_counts_cases(tmp_path):
    report = tmp_path / 'report.xml'
    report.write_text('<testsuites><testsuite><testcase name="native"/>'
                      '<testcase name="reference"/></testsuite></testsuites>')
    assert gate.require_no_skips(report) == 2


def test_fingerprint_tracks_new_and_changed_source_but_not_ignored_state(monkeypatch, tmp_path):
    import subprocess
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path / '.gitignore').write_text('private-state/\n')
    monkeypatch.setattr(gate, 'ROOT', tmp_path)
    initial = gate.source_fingerprint()
    source = tmp_path / 'new.rs'
    source.write_text('first implementation')
    first = gate.source_fingerprint()
    assert first != initial and 'new.rs' in first
    source.write_text('different implementation')
    second = gate.source_fingerprint()
    assert second['new.rs'] != first['new.rs']
    private = tmp_path / 'private-state'
    private.mkdir()
    (private / 'not-source').write_text('never an input')
    assert gate.source_fingerprint() == second
