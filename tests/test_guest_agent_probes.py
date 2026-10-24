"""Portable checks of the simulated guest agent and the guest credential search (no VM)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HUNT = REPO / 'dev' / 'guest_secret_hunt.py'


def hunt(root: Path, *patterns: bytes, env: dict | None = None) -> dict:
    data = b''.join(p.hex().encode() + b'\n' for p in patterns)
    result = subprocess.run([sys.executable, '-I', str(HUNT), '--root', str(root)],
                            input=data, capture_output=True, check=True, env=env)
    return json.loads(result.stdout)


def test_the_search_finds_a_planted_credential_and_reports_only_its_path(tmp_path):
    (tmp_path / 'deep' / 'er').mkdir(parents=True)
    (tmp_path / 'deep' / 'er' / 'leak.txt').write_bytes(b'prefix SECRET-TOKEN-123 suffix')
    (tmp_path / 'clean.txt').write_text('nothing here')
    report = hunt(tmp_path, b'SECRET-TOKEN-123')
    assert report['file_hits'] == [str(tmp_path / 'deep' / 'er' / 'leak.txt')]
    assert report['files_scanned'] == 2
    assert b'SECRET-TOKEN-123' not in json.dumps(report).encode()


def test_the_search_finds_a_credential_in_a_process_environment(tmp_path):
    marker = 'ENV-ONLY-' + os.urandom(8).hex()
    holder = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                              env={**os.environ, 'LEAKED': marker})
    try:
        report = hunt(tmp_path, marker.encode())
    finally:
        holder.kill()
        holder.wait()
    assert f'{holder.pid}/environ' in report['process_hits']


def test_the_search_does_not_report_its_own_stdin(tmp_path):
    report = hunt(tmp_path, b'ONLY-ON-STDIN-' + os.urandom(8).hex().encode())
    assert report['file_hits'] == [] and report['process_hits'] == []


def test_the_agent_verdict_does_not_trust_the_agent(tmp_path, monkeypatch):
    """A report claiming every attack was refused still fails when the
    provider saw a third request."""
    import dev.aivm_vm_acceptance as target
    from dev.offline_native_guest import DemoError

    report = {'useful_read': True, 'useful_read_after_attacks': True,
              'attacks': {**{label: 'refused' for label in target.AGENT_ATTACK_LABELS},
                          'plain_http_on_broker_socket': 'answered:7',
                          'one_megabyte_of_garbage': 'closed',
                          'tls_without_client_certificate': 'refused:SSLError'}}

    class Provider:
        def __init__(self, rows):
            self.rows = rows

        def seen(self):
            return self.rows

    ssh = target.GuestSSH('aivm-2404', tmp_path / 'ssh.conf')
    monkeypatch.setattr(ssh, 'publish', lambda *a, **k: None)
    monkeypatch.setattr(ssh, 'call', lambda *a, **k: subprocess.CompletedProcess(
        [], 0, json.dumps(report).encode(), b''))
    allowed = {'path': target.offline.PULL_PATH}
    assert target._run_simulated_agent(ssh, '/tmp/g', Provider([allowed, allowed]), 0) == report
    with pytest.raises(DemoError, match='beyond its two allowed reads'):
        target._run_simulated_agent(ssh, '/tmp/g', Provider([allowed] * 3), 0)
    report['attacks']['pr_huge'] = 'NOT REFUSED'
    with pytest.raises(DemoError, match='pr_huge'):
        target._run_simulated_agent(ssh, '/tmp/g', Provider([allowed, allowed]), 0)
