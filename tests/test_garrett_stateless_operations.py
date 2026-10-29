"""Operation authorization (spec section 11.1), for both implementations: one
surrogate, issued once, used through two differently configured proxies —
Garrett's unrestricted proxy and the constrained read-only proxy — and the
same request set against two replicas of each configuration.

Requests are written as raw HTTP over the agent's mutual TLS, not through the
agent CLI, so nothing on the guest side constrains them: the proxy alone
decides. Everything is synthetic: the ``syn_static_`` keys are the synthetic
provider's stand-ins for provisioned API keys."""
from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from aivm_secrets.garrett_stateless import tls, wire
from tests.garrett_stateless_support import Environment, Process, python_command, require_rust

IMPLEMENTATIONS = ('python', 'rust')
API_KEY = 'syn_static_OPERATIONS_API_0123456789'
MIRROR_KEY = 'syn_static_OPERATIONS_MIRROR_0123456789'
RESOURCES = [{'provider': 'api', 'path': '/user'}, {'provider': 'api', 'method': 'GET', 'path': '/repos/'}]

# (label, token, raw request after the request line's target is filled in, Garrett, read-only)
# The expected codes are the guest-visible statuses of each proxy.
ALLOWED_BOTH = 'allowed by both'
GARRETT_ONLY = 'allowed by Garrett only'
REFUSED_BOTH = 'refused by both'


def _request(method: str, target: str, token_name: str = 'api-token', body: bytes = b'',
             host: str = 'proxy.test:8443', extra: tuple[str, ...] = ()) -> tuple[str, str, bytes]:
    head = [f'{method} {target} HTTP/1.1', f'Host: {host}', 'Authorization: Bearer {' + token_name + '}',
            'Connection: close', *extra]
    if body or method in ('POST', 'PUT', 'PATCH'):
        head.append(f'Content-Length: {len(body)}')
    return method, token_name, ('\r\n'.join(head) + '\r\n\r\n').encode() + body


CASES = [
    # Authorized reads, through both proxies.
    ('read /user', ALLOWED_BOTH, _request('GET', '/user')),
    ('head /user', ALLOWED_BOTH, _request('HEAD', '/user')),
    ('read a repository', ALLOWED_BOTH, _request('GET', '/repos/octo/demo?page=2')),
    # A changed method.
    ('write /user', GARRETT_ONLY, _request('POST', '/user', body=b'{"name":"x"}')),
    ('replace /user', GARRETT_ONLY, _request('PUT', '/user', body=b'{}')),
    ('head a GET-only resource', GARRETT_ONLY, _request('HEAD', '/repos/octo/demo')),
    ('read with a body', GARRETT_ONLY, _request('GET', '/user', body=b'x')),
    # A changed path.
    ('read another resource', GARRETT_ONLY, _request('GET', '/admin')),
    ('read a longer name', GARRETT_ONLY, _request('GET', '/users')),
    ('read below an exact resource', GARRETT_ONLY, _request('GET', '/user/keys')),
    # A changed destination: the mirror provider's surrogate, a route the
    # read-only policy grants nothing on.
    ('read through another provider', GARRETT_ONLY, _request('GET', '/user', token_name='mirror-token')),
    # The deny rule applies in both.
    ('delete', REFUSED_BOTH, _request('DELETE', '/user')),
    # Destinations the guest names are never used: a foreign Host, an
    # absolute-form target and a method override are refused or dropped.
    ('foreign host', REFUSED_BOTH, _request('GET', '/user', host='api.test')),
    ('absolute-form target', REFUSED_BOTH, _request('GET', 'https://api.test/user')),
]


def _command(implementation: str) -> list[str]:
    return python_command() if implementation == 'python' else [str(require_rust())]


def _setup(env: Environment) -> None:
    for name in ('api', 'mirror'):
        env.write(f'{name}-key.json', json.dumps({'schema': 'garrett-stateless-v1/provider', 'name': name,
                                                  'acquisition': 'provisioned'}))
    env.write('issue.json', json.dumps({
        'schema': 'garrett-stateless-v1/broker', 'issuer': 'https://broker.test', 'audience': 'https://proxy.test',
        'replica': 'a', 'agent_listen': '127.0.0.1:0', 'certificate': 'server.pem', 'private_key': 'server.key',
        'agent_ca': 'ca.pem', 'keys': 'broker-keys.json', 'providers': ['api-key.json', 'mirror-key.json'],
        'stateless': 'strict'}))
    env.write('api.key', API_KEY, private=True)
    env.write('mirror.key', MIRROR_KEY, private=True)
    api_host, api_port = env.api.rsplit(':', 1)
    routes = [{'provider': name, 'host': 'api.test', 'address': api_host, 'port': int(api_port),
               'ca_file': 'ca.pem', 'authentication': 'bearer', 'deny': [{'method': 'DELETE', 'path': '/'}]}
              for name in ('api', 'mirror')]
    env.proxy_config('garrett.json', routes=routes, stateless='strict')
    env.proxy_config('read-only.json', routes=routes, stateless='strict', read_only=RESOURCES)
    # Both surrogates are issued once, by one implementation, and used everywhere.
    for name in ('api', 'mirror'):
        minted = subprocess.run(python_command() + [
            'mint', '--config', 'issue.json', '--provider', name, '--credential-file', f'{name}.key',
            '--certificate', 'agent-c.pem', '--lifetime', '600', '--out', f'{name}-token'],
            cwd=env.root, capture_output=True, timeout=60)
        assert minted.returncode == 0, minted.stderr


def _send(env: Environment, address: str, method: str, token_name: str, raw: bytes) -> tuple[int, bytes]:
    token = (env.root / token_name).read_text().strip()
    request = raw.replace(b'{' + token_name.encode() + b'}', token.encode())
    context = tls.agent_client(env.root / 'ca.pem', env.root / 'agent-c.pem', env.root / 'agent-c.key')
    reply = wire.parse_response(wire.exchange(context, address, 'proxy.test', request, 1 << 20), method)
    return reply.status, reply.body


def _run(env: Environment, address: str) -> list[tuple[str, int, bytes, list[dict]]]:
    """Every case through one proxy: its status, body and provider requests."""
    results = []
    for label, _, (method, token_name, raw) in CASES:
        before = len(env.provider_log())
        status, body = _send(env, address, method, token_name, raw)
        results.append((label, status, body, env.provider_log()[before:]))
    return results


def _proxy(implementation: str, env: Environment, config: str) -> Process:
    proxy = Process(_command(implementation) + ['proxy', '--config', config], env.root)
    assert proxy.announcement['stateless'] == 'strict'
    return proxy


@pytest.mark.parametrize('implementation', IMPLEMENTATIONS)
def test_one_surrogate_two_policies(tmp_path, implementation):
    env = _setup_env(tmp_path)
    observed = {}
    for config, operations in (('garrett.json', 'unrestricted'), ('read-only.json', 'read-only')):
        proxy = _proxy(implementation, env, config)
        try:
            assert proxy.announcement['operations'] == operations
            observed[operations] = _run(env, proxy.announcement['address'])
        finally:
            diagnostics = proxy.stop()
        for key in (API_KEY, MIRROR_KEY):
            assert key not in diagnostics
    keys = {'api-token': API_KEY, 'mirror-token': MIRROR_KEY}
    for (label, kind, (method, token_name, _)), garrett, read_only in zip(
            CASES, observed['unrestricted'], observed['read-only']):
        credential = hashlib.sha256(keys[token_name].encode()).hexdigest()
        for result, permitted in ((garrett, kind != REFUSED_BOTH), (read_only, kind == ALLOWED_BOTH)):
            _, status, body, upstream = result
            if permitted:
                # One credentialed request, carrying the real key, for exactly this method.
                assert status in (200, 201), (label, status, body)
                assert len(upstream) == 1 and upstream[0]['credential_sha256'] == credential, label
                assert upstream[0]['method'] == method, label
            else:
                # Refused before any credentialed egress.
                assert status >= 400 and upstream == [], (label, status, upstream)
        if kind == GARRETT_ONLY:
            # The fixed `denied` refusal (a HEAD reply has no body).
            assert read_only[1] == 403 and (method == 'HEAD' or b'denied' in read_only[2]), (label, read_only)


@pytest.mark.parametrize('config', ['garrett.json', 'read-only.json'])
def test_replicas_decide_alike(tmp_path, config):
    """Two replicas of one configuration — the Python and the Rust proxy,
    sharing nothing but the key file and the configuration — give the same
    status and body, and send the provider the same requests, for every case."""
    env = _setup_env(tmp_path)
    runs = []
    for implementation in IMPLEMENTATIONS:
        proxy = _proxy(implementation, env, config)
        try:
            runs.append(_run(env, proxy.announcement['address']))
        finally:
            proxy.stop()
    for first, second in zip(*runs):
        label = first[0]
        assert first[1:3] == second[1:3], label
        strip = [{k: v for k, v in event.items() if k != 'time'} for event in first[3]]
        assert strip == [{k: v for k, v in event.items() if k != 'time'} for event in second[3]], label


def _setup_env(tmp_path) -> Environment:
    env = Environment(tmp_path)
    _setup(env)
    return env


def test_read_only_configuration_refused(tmp_path):
    """The proxy refuses a read-only list that names an unrouted provider or a
    write method, in both implementations."""
    env = _setup_env(tmp_path)
    bad = {
        'unrouted.json': [{'provider': 'elsewhere', 'path': '/user'}],
        'write.json': [{'provider': 'api', 'method': 'POST', 'path': '/user'}],
        'relative.json': [{'provider': 'api', 'path': 'user'}],
        'empty.json': [],
    }
    for name, resources in bad.items():
        env.proxy_config(name, read_only=resources)
    for implementation in IMPLEMENTATIONS:
        for name in bad:
            result = subprocess.run(_command(implementation) + ['proxy', '--config', name, '--until-stdin-eof'],
                                    cwd=env.root, capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
            assert result.returncode != 0 and not result.stdout, (implementation, name, result.stdout)
