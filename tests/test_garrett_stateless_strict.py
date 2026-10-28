"""The strict stateless profile and direct provisioning (spec sections 7.1 and
9), for both implementations: a provider whose API key the operator mints, with
no OAuth client, browser listener, token endpoint or login mailbox, a broker
that only renews, and a proxy with no audit file. Every implementation refuses
the configurations that would keep more state.

Everything is synthetic: the ``syn_static_`` key is the synthetic provider's
stand-in for a provisioned API key."""
from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from aivm_secrets.garrett_stateless import inspect
from tests.garrett_stateless_support import Environment, Process, python_command, require_rust

IMPLEMENTATIONS = ('python', 'rust')
API_KEY = 'syn_static_PROVISIONED_0123456789'


def _command(implementation: str) -> list[str]:
    return python_command() if implementation == 'python' else [str(require_rust())]


def _strict(env: Environment) -> None:
    env.write('api-key.json', json.dumps({'schema': 'garrett-stateless-v1/provider', 'name': 'api',
                                          'acquisition': 'provisioned'}))
    env.write('strict-broker.json', json.dumps(_broker(['api-key.json'], stateless='strict')))
    env.proxy_config('strict-proxy.json', stateless='strict')
    env.write('api.key', API_KEY, private=True)
    # A second provisioned provider, to combine with the OAuth provider `api`.
    env.write('keyed.json', json.dumps({'schema': 'garrett-stateless-v1/provider', 'name': 'keyed',
                                        'acquisition': 'provisioned'}))


def _broker(providers: list[str], **extra) -> dict:
    config = {
        'schema': 'garrett-stateless-v1/broker', 'issuer': 'https://broker.test', 'audience': 'https://proxy.test',
        'replica': 'a', 'agent_listen': '127.0.0.1:0', 'certificate': 'server.pem', 'private_key': 'server.key',
        'agent_ca': 'ca.pem', 'keys': 'broker-keys.json', 'providers': providers,
    }
    config.update(extra)
    return config


def _agent(implementation: str, *args: str) -> list[str]:
    return _command(implementation) + ['agent', *args, '--ca', 'ca.pem', '--cert', 'agent-c.pem',
                                       '--key', 'agent-c.key']


@pytest.mark.parametrize('broker_impl', IMPLEMENTATIONS)
@pytest.mark.parametrize('proxy_impl', IMPLEMENTATIONS)
def test_strict_provisioned_matrix(tmp_path, broker_impl, proxy_impl):
    env = Environment(tmp_path)
    _strict(env)
    minted = subprocess.run(_command(broker_impl) + [
        'mint', '--config', 'strict-broker.json', '--provider', 'api', '--credential-file', 'api.key',
        '--certificate', 'agent-c.pem', '--lifetime', '600', '--out', 'token'],
        cwd=env.root, capture_output=True, timeout=60)
    assert minted.returncode == 0, minted.stderr
    token = (env.root / 'token').read_text()
    assert API_KEY not in token and inspect(token)[1]['prv'] == 'api'

    broker = Process(_command(broker_impl) + ['broker', '--config', 'strict-broker.json'], env.root)
    try:
        assert broker.announcement['browser'] is None
        assert broker.announcement['stateless'] == 'strict'
        endpoint = ['--broker', 'https://broker.test:9443', '--connect', broker.announcement['agent']]
        login = subprocess.run(_agent(broker_impl, 'login', *endpoint, '--provider', 'api', '--timeout', '5'),
                               cwd=env.root, capture_output=True, timeout=60)
        assert login.returncode != 0
        renewed = subprocess.run(_agent(broker_impl, 'renew', *endpoint, '--token-file', 'token', '--out', 'renewed'),
                                 cwd=env.root, capture_output=True, timeout=60)
        assert renewed.returncode == 0, renewed.stderr
    finally:
        broker.stop()
    renewed_token = (env.root / 'renewed').read_text()
    assert inspect(renewed_token)[1]['ren'] <= inspect(token)[1]['ren']

    proxy = Process(_command(proxy_impl) + ['proxy', '--config', 'strict-proxy.json'], env.root)
    try:
        assert proxy.announcement['stateless'] == 'strict'
        for name in ('token', 'renewed'):
            result = subprocess.run(
                _agent(proxy_impl, 'request', '--proxy', 'https://proxy.test:8443', '--connect',
                       proxy.announcement['address'], '--token-file', name, '/user'),
                cwd=env.root, capture_output=True, timeout=60)
            assert result.returncode == 0, result.stderr
            assert env.provider_log()[-1]['credential_sha256'] == hashlib.sha256(API_KEY.encode()).hexdigest()
    finally:
        diagnostics = proxy.stop()
    assert API_KEY not in diagnostics and token not in diagnostics
    assert not any(env.root.glob('*.log'))


@pytest.mark.parametrize('implementation', IMPLEMENTATIONS)
def test_state_keeping_configurations_refused(tmp_path, implementation):
    env = Environment(tmp_path)
    _strict(env)
    browser = {'browser_listen': '127.0.0.1:0', 'public_url': 'https://broker.test/'}
    refused = {
        # A strict broker has no OAuth provider: its logins need the mailbox.
        'strict-oauth.json': _broker(['keyed.json', 'provider.json'], stateless='strict', **browser),
        # The browser endpoint exists exactly when an OAuth provider does.
        'no-browser.json': _broker(['provider.json']),
        'stray-browser.json': _broker(['api-key.json'], **browser),
        'bad-mode.json': _broker(['api-key.json'], stateless='relaxed'),
    }
    for name, config in refused.items():
        env.write(name, json.dumps(config))
    env.write('oauth-member.json', json.dumps({'schema': 'garrett-stateless-v1/provider', 'name': 'api',
                                               'acquisition': 'provisioned', 'client_id': 'x'}))
    env.write('oauth-member-broker.json', json.dumps(_broker(['oauth-member.json'])))
    # A strict proxy writes no audit file.
    env.proxy_config('audited-proxy.json', stateless='strict', audit='audit.log')
    for role, name in [('broker', n) for n in [*refused, 'oauth-member-broker.json']] + \
            [('proxy', 'audited-proxy.json')]:
        result = subprocess.run(_command(implementation) + [role, '--config', name, '--until-stdin-eof'],
                                cwd=env.root, capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        assert result.returncode != 0 and not result.stdout, (name, result.stdout)
    assert not (env.root / 'audit.log').exists()
    # A standard broker may combine both kinds of provider.
    env.write('both.json', json.dumps(_broker(['keyed.json', 'provider.json'], **{
        'browser_listen': f'127.0.0.1:{env.browser_port}', 'public_url': f'https://broker.test:{env.browser_port}/'})))
    both = Process(_command(implementation) + ['broker', '--config', 'both.json'], env.root)
    try:
        assert both.announcement['browser'] and both.announcement['stateless'] == 'standard'
    finally:
        both.stop()
