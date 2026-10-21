"""Portable regression tests for the *process* boundary of scoped Lean checks.

These exercise diagnostics and build orchestration, not Lean kernel checking.
"""
from __future__ import annotations

import signal
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'dev/verification'))
import lean_step
import read_paths
import read_prefixes


def test_silent_signal_reports_status_and_does_not_claim_proof(monkeypatch, tmp_path):
    monkeypatch.setattr(lean_step.subprocess, 'run', lambda *a, **kw:
        subprocess.CompletedProcess(a[0], -signal.SIGKILL, '', ''))
    with pytest.raises(lean_step.LeanStepError) as failure:
        lean_step.run(['lake', 'env', 'lean', 'GarrettReadPaths.lean'],
                      tmp_path, 'read-path compilation')
    detail = str(failure.value)
    assert 'SIGKILL (9)' in detail
    assert 'stdout: (empty)' in detail
    assert 'stderr: (empty)' in detail
    assert 'out-of-memory' in detail
    assert 'GarrettReadPaths.lean' in detail


def test_nonzero_exit_preserves_compiler_error_and_context(monkeypatch, tmp_path):
    monkeypatch.setattr(lean_step.subprocess, 'run', lambda *a, **kw:
        subprocess.CompletedProcess(a[0], 1, '', 'error: unknown identifier'))
    with pytest.raises(lean_step.LeanStepError) as failure:
        lean_step.run(['lake', 'env', 'lean', 'GarrettReadPrefixes.lean'],
                      tmp_path, 'prefix compilation')
    detail = str(failure.value)
    assert 'exited with code 1' in detail
    assert 'error: unknown identifier' in detail
    assert f'cwd: {tmp_path}' in detail


def test_read_paths_compilation_is_reused_for_prefix_imports(monkeypatch, tmp_path):
    """One successful compilation must also produce the import object for prefixes."""
    backend = tmp_path / '.tools/aeneas/backends/lean/lakefile.lean'
    backend.parent.mkdir(parents=True)
    backend.write_text('-- fake backend: tests only')
    (tmp_path / 'proofs').mkdir()
    monkeypatch.setattr(read_paths.shutil, 'which', lambda _: '/usr/bin/fake-lake')
    calls = []

    def fake_read_path(command, cwd, label):
        calls.append((command, label))
        if 'GarrettReadPaths.lean' in command:
            idx = command.index('-o')
            Path(command[idx + 1]).write_bytes(b'mocked olean: NOT a proof')
            return ''
        return ''

    def fake_prefix(command, cwd, label):
        calls.append((command, label))
        return ''

    monkeypatch.setattr(read_paths, '_run', fake_read_path)
    monkeypatch.setattr(read_prefixes, '_run', fake_prefix)
    read_prefixes.prove(tmp_path)
    read_path_runs = [cmd for cmd, _ in calls if 'GarrettReadPaths.lean' in cmd]
    assert len(read_path_runs) == 1
    assert '-o' in read_path_runs[0]
    prefix_runs = [cmd for cmd, _ in calls if 'GarrettReadPrefixes.lean' in cmd]
    assert len(prefix_runs) == 1


def test_missing_import_object_is_not_silently_accepted(monkeypatch, tmp_path):
    (tmp_path / 'proofs').mkdir()
    monkeypatch.setattr(read_prefixes.shutil, 'which', lambda _: '/usr/bin/fake-lake')
    monkeypatch.setattr(read_prefixes.read_paths, 'prove', lambda root: None)
    with pytest.raises(read_prefixes.PrefixReviewError, match='import object missing'):
        read_prefixes.prove(tmp_path)


def test_prefix_reports_read_path_failure_without_traceback(monkeypatch, tmp_path):
    monkeypatch.setattr(read_prefixes.shutil, 'which', lambda _: '/usr/bin/fake-lake')

    def fail(_root):
        raise read_paths.ReviewError('read-path kernel: terminated by SIGKILL (9)')

    monkeypatch.setattr(read_prefixes.read_paths, 'prove', fail)
    with pytest.raises(read_prefixes.PrefixReviewError,
                       match='read-path prerequisite: .*SIGKILL'):
        read_prefixes.prove(tmp_path)
