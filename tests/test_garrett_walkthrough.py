"""Portable tests for the demo narration and container command boundary.

These are not a surrogate for the required real Rust end-to-end acceptance.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from dev.offline_native_guest import DemoError, walkthrough_step

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / 'scripts/garrett-container-demo.sh'
DOCKERFILE = ROOT / 'examples/garrett-demo/Dockerfile'


def test_narration_disabled_is_silent(capsys):
    walkthrough_step('step', 'description', enabled=False)
    assert capsys.readouterr().err == ''


def test_narration_is_on_stderr_and_not_report_stdout(capsys):
    walkthrough_step('one', 'this is public', enabled=True)
    output = capsys.readouterr()
    assert output.out == ''
    assert '=== one ===' in output.err
    assert 'this is public' in output.err


def test_pause_consumes_just_one_line(monkeypatch, capsys):
    from io import StringIO
    monkeypatch.setattr(sys, 'stdin', StringIO('\nnext\n'))
    walkthrough_step('one', 'description', enabled=True, pause=True)
    assert sys.stdin.readline() == 'next\n'
    assert 'Press Enter' in capsys.readouterr().err


def test_pause_fails_closed_on_eof(monkeypatch):
    from io import StringIO
    monkeypatch.setattr(sys, 'stdin', StringIO(''))
    with pytest.raises(DemoError, match='input closed'):
        walkthrough_step('one', 'description', enabled=True, pause=True)


def test_pause_argument_requires_walkthrough():
    process = subprocess.run(
        [sys.executable, str(ROOT / 'dev/offline_native_guest.py'), '--pause'],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert process.returncode == 2
    assert '--pause requires --walkthrough' in process.stderr


def test_container_builds_real_rust_read_only_binary_and_runs_unprivileged():
    dockerfile = DOCKERFILE.read_text()
    script = WRAPPER.read_text()
    assert '--bin garrett-authority' in dockerfile
    assert '--bin garrett-bridge-read-only' in dockerfile
    assert '--bin garrett-client' in dockerfile
    assert 'garrett-bridge-read-only /usr/local/bin/garrett-bridge' in dockerfile
    assert 'USER 10001:10001' in dockerfile
    assert 'ENTRYPOINT ["python"' in dockerfile
    assert '--walkthrough' in dockerfile
    assert '--network none' in script
    assert '--read-only' in script
    assert '--cap-drop ALL' in script
    assert '--security-opt no-new-privileges' in script
    assert '--privileged' not in script
    assert '--mount' not in script
    assert 'run --rm -i' in script
    assert '--volume' not in script


def test_wrapper_arg_errors_do_not_require_container_engine():
    process = subprocess.run(['bash', str(WRAPPER), '--help'],
                             capture_output=True, text=True, cwd=ROOT)
    assert process.returncode == 0
    assert 'Usage:' in process.stdout
    process = subprocess.run(['bash', str(WRAPPER), '--unknown'],
                             capture_output=True, text=True, cwd=ROOT)
    assert process.returncode == 2
    assert 'Unsupported argument' in process.stderr


def test_wrapper_builds_then_runs_with_no_host_network_or_mount(tmp_path):
    # Only the *container CLI invocation* is captured. No protocol outcome is
    # simulated: native integration validation still requires Docker and Rust.
    log = tmp_path / 'args.txt'
    fake = tmp_path / 'capture-container-cli'
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$LOG"\n')
    fake.chmod(0o755)
    env = dict(os.environ, CONTAINER_ENGINE=str(fake), LOG=str(log))
    process = subprocess.run(['bash', str(WRAPPER)], cwd=ROOT, env=env,
                             capture_output=True, text=True)
    assert process.returncode == 0, process.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 2
    assert calls[0].startswith('build --file ')
    assert 'examples/garrett-demo/Dockerfile' in calls[0]
    assert calls[1].startswith('run --rm -i ')
    assert '--network none' in calls[1]
    assert '--read-only' in calls[1]
    assert '--tmpfs /tmp:' in calls[1]
    assert '--cap-drop ALL' in calls[1]
    assert '--pause' not in calls[1]
