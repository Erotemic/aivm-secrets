"""garrett-stateless-v1 interoperability: every combination of the Python and
Rust broker and proxy, as separate processes over real TLS, against the
synthetic HTTPS provider. Each run logs in through the broker-language agent
CLI, stops the broker, uses the surrogate through a proxy, refuses it on
another certificate, and reuses it through an independently restarted proxy.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from aivm_secrets.garrett_stateless import inspect
from tests.garrett_stateless_support import Environment, Process, python_command, require_rust

IMPLEMENTATIONS = ('python', 'rust')


def _command(implementation: str) -> list[str]:
    return python_command() if implementation == 'python' else [str(require_rust())]


def _agent(env: Environment, implementation: str, name: str, *args: str) -> list[str]:
    return _command(implementation) + ['agent', *args, '--ca', 'ca.pem', '--cert', f'{name}.pem',
                                       '--key', f'{name}.key']


def _request(env, implementation, name, proxy, target='/user', *extra) -> tuple[int, int, bytes]:
    result = subprocess.run(
        _agent(env, implementation, name, 'request', '--proxy', 'https://proxy.test:8443', '--connect', proxy,
               '--token-file', 'token', *extra, target),
        cwd=env.root, capture_output=True, timeout=60)
    status = json.loads(result.stderr.decode().strip().splitlines()[-1])['status']
    return result.returncode, status, result.stdout


@pytest.mark.parametrize('broker_impl', IMPLEMENTATIONS)
@pytest.mark.parametrize('proxy_impl', IMPLEMENTATIONS)
def test_broker_proxy_matrix(tmp_path, broker_impl, proxy_impl):
    env = Environment(tmp_path)
    broker = Process(_command(broker_impl) + ['broker', '--config', 'broker.json'], env.root)
    try:
        login = subprocess.Popen(
            _agent(env, broker_impl, 'agent-c', 'login', '--broker', 'https://broker.test:9443',
                   '--connect', broker.announcement['agent'], '--provider', 'api', '--out', 'token',
                   '--timeout', '60'),
            cwd=env.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        started = json.loads(login.stdout.readline())
        done = env.human(started['authorization_url'], broker.announcement['browser'],
                         expect_confirmation=started['confirmation'])
        assert done.status == 200
        delivered = json.loads(login.stdout.readline())
        assert login.wait(30) == 0, login.stderr.read()
        assert delivered['token_file'] == 'token'
    finally:
        broker.stop()
    token = (env.root / 'token').read_text()
    header, payload = inspect(token)
    assert header['typ'] == 'garrett-stateless-v1+jwt' and payload['sub'] == 'spiffe://test/agent-c'
    real = next(e['credential_sha256'] for e in env.provider_log() if e['event'] == 'token_issued')

    for attempt in ('first', 'restarted'):
        proxy = Process(_command(proxy_impl) + ['proxy', '--config', 'proxy.json'], env.root)
        address = proxy.announcement['address']
        try:
            code, status, body = _request(env, proxy_impl, 'agent-c', address, '/user?x=1')
            assert (code, status) == (0, 200), (attempt, body)
            assert json.loads(body)['query'] == {'x': '1'}
            assert env.provider_log()[-1]['credential_sha256'] == real
            before = len(env.provider_log())
            # The other language's agent CLI on the other certificate: refused, nothing sent.
            other = 'rust' if proxy_impl == 'python' else 'python'
            code, status, _ = _request(env, other, 'agent-d', address)
            assert (code, status) == (22, 401)
            code, status, _ = _request(env, other, 'agent-c', address, '/repo', '-X', 'DELETE')
            assert status == 403
            assert len(env.provider_log()) == before
            code, status, body = _request(env, proxy_impl, 'agent-c', address, '/items', '--data', '{"n":1}')
            assert status == 201 and json.loads(body)['body_bytes'] == 7
        finally:
            diagnostics = proxy.stop()
        assert token not in diagnostics and 'syn_' not in diagnostics
