"""The system gate must not mix the source checkout with a stale -I wheel."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from dev.verification import system


def test_check_accepts_an_isolated_import_of_the_checkout(monkeypatch):
    expected = system.ROOT / 'aivm_secrets/identity/cli.py'
    seen = []

    def run(command, **kwargs):
        seen.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, str(expected) + '\n', '')

    monkeypatch.setattr(system.subprocess, 'run', run)
    assert system.require_isolated_checkout('python-for-test', {}) == expected.resolve()
    assert seen[0][0][:3] == ['python-for-test', '-I', '-c']
    assert seen[0][1]['cwd'] == system.ROOT


@pytest.mark.parametrize('exit_code,location', [
    (0, '/tmp/stale-wheel/aivm_secrets/identity/cli.py'),
    (1, ''),
])
def test_check_rejects_stale_or_missing_isolated_install(monkeypatch, exit_code, location):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, exit_code, location + '\n', '')

    monkeypatch.setattr(system.subprocess, 'run', run)
    with pytest.raises(RuntimeError, match='-I flag ignores PYTHONPATH'):
        system.require_isolated_checkout('python-for-test', {})
