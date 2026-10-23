"""HP-3: the proxy-session process contract, end to end with a local guest.

The guest is a directory on this host; its tool is stock ``curl`` reading
only the published ``env`` file. Both the Python reference proxy and the
native ``garrett-proxy`` are exercised.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from tests.secrets_helpers import TOKEN, TLSService, write_private
from tests.test_proxy_substitution import HOST

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


@pytest.fixture
def service(tmp_path):
    (tmp_path / 'provider').mkdir()
    with TLSService(tmp_path / 'provider', host=HOST) as provider:
        provider.routes[('GET', '/v1/account')] = {'login': 'demo'}
        yield provider


def spec_for(tmp_path, service, bin_dir):
    host = tmp_path / 'host'
    host.mkdir(mode=0o700)
    policy = dict(schema=1, profile='credential-substitution', lifetime_seconds=600,
                  origins=[dict(host=HOST, address='127.0.0.1', port=service.port,
                                ca_file=str(service.files['ca']), authentication='bearer')])
    spec = dict(
        version=1, bin_dir=bin_dir, guest=dict(kind='local'), guest_port=free_port(),
        policy_file=str(write_private(host / 'proxy.json', json.dumps(policy).encode())),
        credential_file=str(write_private(host / 'credential', (TOKEN + '\n').encode())),
        audit_file=str(host / 'audit.jsonl'),
    )
    return write_private(host / 'session.json', json.dumps(spec).encode())


def backends():
    native = os.environ.get('AIVM_SECRETS_RUST_GARRETT_PROXY')
    return [None, pytest.param(str(Path(native).parent) if native else '/nonexistent',
                               marks=pytest.mark.skipif(not native, reason='native proxy not built'),
                               id='native')]


@pytest.mark.skipif(shutil.which('curl') is None, reason='needs curl')
@pytest.mark.parametrize('bin_dir', backends(), ids=['python', 'native'])
def test_guest_tool_uses_the_published_env_and_never_sees_the_credential(
        tmp_path, service, bin_dir):
    process = subprocess.Popen(
        [sys.executable, '-m', 'aivm_secrets', 'proxy-session', '--spec',
         str(spec_for(tmp_path, service, bin_dir))],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert select.select([process.stdout], [], [], 60)[0]
        announcement = json.loads(process.stdout.readline())
        assert announcement['ready'] is True, announcement
        guest = Path(announcement['guest']['dir'])
        env_file = announcement['guest']['env']
        done = subprocess.run(
            ['sh', '-c', f'. {env_file} && curl -sS --fail https://{HOST}/v1/account'],
            capture_output=True, timeout=30, env={'PATH': os.environ['PATH']})
        assert done.returncode == 0, done.stderr
        assert json.loads(done.stdout) == {'login': 'demo'}
        assert service.requests[0]['headers']['authorization'] == 'Bearer ' + TOKEN
        for path in guest.rglob('*'):
            assert TOKEN.encode() not in path.read_bytes(), path
        assert TOKEN.encode() not in done.stdout + done.stderr
        assert 'proxy_token' not in json.dumps(announcement)
    finally:
        process.stdin.close()
        assert process.wait(timeout=30) == 0
    assert not guest.exists()
    assert TOKEN.encode() not in process.stdout.read() + process.stderr.read()


def test_a_bad_spec_is_refused_with_a_code(tmp_path):
    spec = write_private(tmp_path / 'bad.json', b'{"version": 1}')
    done = subprocess.run([sys.executable, '-m', 'aivm_secrets', 'proxy-session', '--spec',
                           str(spec)], cwd=ROOT, capture_output=True, timeout=30)
    assert done.returncode == 1
    assert json.loads(done.stdout) == {'version': 1, 'ready': False, 'error': 'invalid_spec'}
