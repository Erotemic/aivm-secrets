"""`garrett-bridge-read-only` refuses every configuration outside the read profile."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

BRIDGE = os.environ.get('AIVM_SECRETS_RUST_GARRETT_BRIDGE')
pytestmark = pytest.mark.skipif(not BRIDGE, reason='native bridge not configured')


def start(tmp_path: Path, config: dict) -> subprocess.CompletedProcess:
    binary = Path(BRIDGE).with_name('garrett-bridge-read-only')
    path = tmp_path / 'bridge.json'
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    return subprocess.run([str(binary), '--config', str(path)],
                          capture_output=True, timeout=30)


@pytest.mark.parametrize('provider', [
    pytest.param({'profile': 'manifest-https-v1', 'writes': 'allow'}, id='writes-allow'),
    pytest.param({'profile': 'manifest-https-v1', 'writes': 'approve'}, id='writes-approve'),
    pytest.param({'profile': 'account-status-v1', 'writes': 'deny'}, id='other-profile'),
    pytest.param({'profile': 'manifest-https-v1', 'writes': 'deny',
                  'coordination_file': '/c'}, id='coordinated'),
])
def test_a_configuration_outside_the_profile_never_starts(tmp_path, provider):
    result = start(tmp_path, {'schema': 1, 'listen': str(tmp_path / 's'), 'provider': provider})
    assert result.returncode == 1
    assert result.stderr.strip() == b'invalid_policy'
    assert not (tmp_path / 's').exists()


def test_legacy_forwarding_never_starts(tmp_path):
    result = start(tmp_path, {'schema': 1, 'listen': str(tmp_path / 's'),
                              'broker_socket': str(tmp_path / 'b')})
    assert result.returncode == 1 and result.stderr.strip() == b'invalid_policy'


def test_the_read_profile_passes_the_gate(tmp_path):
    """An otherwise incomplete read configuration fails later, for another reason."""
    result = start(tmp_path, {'schema': 1, 'listen': str(tmp_path / 's'),
                              'provider': {'profile': 'manifest-https-v1', 'writes': 'deny'}})
    assert result.returncode == 1
    assert result.stderr.strip() != b'invalid_policy'
