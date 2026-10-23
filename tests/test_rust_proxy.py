"""HP-4: the native ``garrett-proxy`` against the same adversarial cases.

``garrett-proxy`` is a thin I/O shell around the extracted ``proxy_http``
core. These tests run it as a real process with the same process contract
as ``aivm-secrets proxy`` and the same synthetic provider and credential,
and check what reached the provider, what the guest received, and the audit.
"""

from __future__ import annotations

import base64
import json
import select
import shutil
import subprocess
import time

import pytest

from tests.secrets_helpers import TOKEN, TLSService, write_private
from tests.test_proxy_substitution import HOST, World, get, status
from tests.test_rust_garrett import executable


class NativeWorld(World):
    """``World``'s raw tunnel helper, driving the native binary."""

    def __init__(self, tmp_path, service, *, secret: str = TOKEN, **policy_changes):
        self.service = service
        policy = dict(
            schema=1, profile='credential-substitution', lifetime_seconds=600,
            origins=[dict(host=HOST, address='127.0.0.1', port=service.port,
                          ca_file=str(service.files['ca']), authentication='bearer')],
            deny=[dict(method='POST', path='/v1/tokens'), dict(method='*', path='/v1/admin/')],
        )
        policy.update(policy_changes)
        self.directory = tmp_path / 'native'
        self.directory.mkdir(mode=0o700)
        self.policy_path = write_private(self.directory / 'proxy.json', json.dumps(policy).encode())
        self.credential = write_private(self.directory / 'credential', (secret + '\n').encode())
        self.audit_path = self.directory / 'audit.jsonl'
        self.ca_path = tmp_path / 'native-ca.pem'

    def __enter__(self):
        self.process = subprocess.Popen(
            [executable('AIVM_SECRETS_RUST_GARRETT_PROXY'), '--policy', str(self.policy_path),
             '--credential-file', str(self.credential), '--audit', str(self.audit_path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert select.select([self.process.stdout], [], [], 30)[0], 'no announcement'
        self.announcement = json.loads(self.process.stdout.readline())
        assert self.announcement['ready'] is True, self.announcement
        self.ca_path.write_text(self.announcement['ca_pem'])
        self.port = int(self.announcement['listen'].rsplit(':', 1)[1])
        self.session = type('Session', (), {'token': self.announcement['proxy_token']})
        return self

    def __exit__(self, *exc):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        assert self.process.wait(timeout=30) == 0
        self.output = self.process.stdout.read() + self.process.stderr.read()
        assert TOKEN.encode() not in self.output

    def audit(self):
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]


@pytest.fixture
def service(tmp_path):
    (tmp_path / 'provider').mkdir()
    with TLSService(tmp_path / 'provider', host=HOST, wire_headers=True) as provider:
        provider.routes[('GET', '/v1/account')] = {'login': 'demo'}
        provider.routes[('POST', '/v1/issues')] = lambda seen: (201, {}, json.dumps(
            {'created': True, 'echo': json.loads(seen['body'])}).encode())
        yield provider


@pytest.fixture
def world(tmp_path, service):
    with NativeWorld(tmp_path, service) as w:
        yield w


def assert_clean(world, *outputs):
    for output in outputs:
        assert TOKEN.encode() not in output
    audit = world.audit_path.read_bytes()
    assert TOKEN.encode() not in audit and world.session.token.encode() not in audit


@pytest.mark.skipif(shutil.which('curl') is None, reason='needs curl')
def test_native_stock_curl_reads_and_the_provider_gets_the_credential(world):
    done = subprocess.run(
        ['curl', '-sS', '--fail', '--proxy', f'http://127.0.0.1:{world.port}',
         '--proxy-user', f'aivm:{world.session.token}', '--cacert', str(world.ca_path),
         '-H', 'Authorization: Bearer placeholder', f'https://{HOST}/v1/account'],
        capture_output=True, timeout=30)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {'login': 'demo'}
    [seen] = world.service.requests
    assert [v for k, v in seen['header_pairs'] if k.lower() == 'authorization'] == [
        'Bearer ' + TOKEN]
    assert_clean(world, done.stdout, done.stderr)
    assert [row['event'] for row in world.audit()] == ['session_start', 'admitted', 'completed']


def test_native_body_is_reencoded_and_guest_credentials_replaced(world):
    body = b'{"title":"fix"}'
    request = (b'POST /v1/issues HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n'
               b'authorization: token guest\r\nX-API-KEY: guest\r\nCookie: a=b\r\n'
               b'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
               + b'%x\r\n%s\r\n0\r\n\r\n' % (len(body), body))
    reply = world.raw(request)
    assert status(reply) == 201, reply
    [seen] = world.service.requests
    pairs = [(k.lower(), v) for k, v in seen['header_pairs']]
    assert [v for k, v in pairs if k == 'authorization'] == ['Bearer ' + TOKEN]
    assert 'x-api-key' not in dict(pairs) and 'cookie' not in dict(pairs)
    assert dict(pairs)['content-length'] == str(len(body)) and seen['body'] == body.decode()
    assert_clean(world, reply)


def test_native_keep_alive_serves_sequential_requests(world):
    one = b'GET /v1/account HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n\r\n'
    reply = world.raw(one + one, read_all=False)
    assert reply.count(b'HTTP/1.1 200 ') == 2
    assert len(world.service.requests) == 2


@pytest.mark.parametrize('request_bytes', [
    get(extra=b'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n'),
    get(extra=b'X-Folded: a\r\n b\r\n'),
    b'GET /v1/account HTTP/1.1\nHost: ' + HOST.encode() + b'\r\n\r\n',
    b'GET /v1/account HTTP/1.1\r\nHost: other.example.org\r\n\r\n',
    get('/v1/../admin/x'),
    get('/v1%2Faccount'),
    get(extra=b'Upgrade: h2c\r\n'),
    b'GET /v1/account HTTP/1.0\r\nHost: ' + HOST.encode() + b'\r\n\r\n',
], ids=['cl-and-te', 'obs-fold', 'bare-lf', 'host-mismatch', 'dot-segment', 'encoded-slash',
        'upgrade', 'http-1.0'])
def test_native_ambiguous_requests_never_reach_the_provider(world, request_bytes):
    reply = world.raw(request_bytes)
    assert status(reply) == 400, reply
    assert world.service.requests == []


@pytest.mark.parametrize('method, path', [('POST', '/v1/tokens'), ('GET', '/v1/admin/users')])
def test_native_deny_list_refuses_before_egress(world, method, path):
    reply = world.raw(method.encode() + b' ' + path.encode() + b' HTTP/1.1\r\nHost: '
                      + HOST.encode() + b'\r\nContent-Length: 0\r\n\r\n')
    assert status(reply) == 403 and b'"denied"' in reply
    assert world.service.requests == []


@pytest.mark.parametrize('connect, auth, code', [
    (None, b'', 407),
    (None, b'wrong-token', 407),
    (b'CONNECT evil.example.net:443 HTTP/1.1\r\n', None, 403),
    (b'CONNECT ' + HOST.encode() + b':8443 HTTP/1.1\r\n', None, 403),
    (b'GET http://' + HOST.encode() + b'/v1/account HTTP/1.1\r\n', None, 400),
], ids=['no-auth', 'bad-auth', 'unlisted-origin', 'other-port', 'plain-proxying'])
def test_native_tunnel_requires_session_and_origin(world, connect, auth, code):
    reply = world.raw(get(), connect=connect, auth=auth)
    assert status(reply) == code, reply
    assert world.service.requests == []


@pytest.mark.parametrize('encoded', [
    TOKEN.encode(),
    base64.b64encode(b'x-access-token:' + TOKEN.encode()),
    TOKEN.encode().hex().upper().encode(),
], ids=['raw', 'basic-b64', 'hex'])
def test_native_reflected_credential_is_refused(world, encoded):
    world.service.routes[('GET', '/v1/account')] = lambda seen: (
        200, {'X-Echo': encoded.decode()}, b'{}')
    reply = world.raw(get())
    assert status(reply) == 502 and b'"reflected"' in reply
    assert_clean(world, reply)


def test_native_compressed_response_and_redirects(world):
    world.service.routes[('GET', '/v1/account')] = lambda seen: (
        200, {'Content-Encoding': 'gzip'}, b'\x1f\x8b')
    assert status(world.raw(get())) == 502
    world.service.routes[('GET', '/v1/account')] = lambda seen: (
        302, {'Location': 'https://evil.example.net/x'}, b'')
    assert status(world.raw(get())) == 302
    assert len(world.service.requests) == 2


def test_native_oversize_and_expiry(tmp_path, service):
    with NativeWorld(tmp_path, service, lifetime_seconds=2,
                     limits={'request_body': 8, 'response_body': 4}) as world:
        big = (b'POST /v1/issues HTTP/1.1\r\nHost: ' + HOST.encode()
               + b'\r\nContent-Length: 9\r\n\r\n123456789')
        assert status(world.raw(big)) == 413
        assert service.requests == []
        assert status(world.raw(get())) == 413
        time.sleep(2.2)
        assert status(world.raw(get())) == 403
        assert len(service.requests) == 1


def test_native_unreachable_origin(tmp_path, service):
    with NativeWorld(tmp_path, service, origins=[dict(
            host=HOST, address='127.0.0.1', port=1, ca_file=str(service.files['ca']),
            authentication='bearer')]) as world:
        reply = world.raw(get())
        assert status(reply) == 502 and b'"unreachable"' in reply


def test_native_stdin_eof_ends_the_session(tmp_path, service):
    world = NativeWorld(tmp_path, service)
    world.__enter__()
    assert status(world.raw(get())) == 200
    world.__exit__(None, None, None)
    assert world.audit()[-1]['event'] == 'session_end'


def test_native_refuses_a_bad_policy(tmp_path, service):
    world = NativeWorld(tmp_path, service, profile='constrained-http')
    process = subprocess.run(
        [executable('AIVM_SECRETS_RUST_GARRETT_PROXY'), '--policy', str(world.policy_path),
         '--credential-file', str(world.credential), '--audit', str(world.audit_path)],
        capture_output=True, timeout=30, input=b'')
    assert process.returncode == 1
    assert json.loads(process.stdout) == {'version': 1, 'ready': False, 'error': 'invalid_policy'}


def test_native_proxy_writes_only_core_outputs():
    """Source shape of the native shell (reviewed, not proved).

    Upstream: only the ``wire`` that the extracted ``proxy_controller::serve``
    passes to ``Upstream::exchange`` (proved to be ``encode_upstream``'s
    output). Guest: fixed refusals, the fixed CONNECT answer, or the
    ``reply`` returned by ``serve`` (proved: a fixed refusal or
    ``guest_response`` output). Audit and announcement
    are JSON written by this file; neither contains the credential (checked
    at runtime above).
    """
    import re
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1]
              / 'rust/crates/aivm-secrets-garrett/src/proxy_main.rs').read_text()
    writes = re.findall(r'(\w+)\.write_all\(([^)]*\)?)\)', source)
    allowed = {('tls', 'wire'), ('tls', '&reply'), ('tls', '&refusal(code)'),
               ('tls', '&refusal("too_large")'),
               ('stream', '&core::refusal(&code)'),
               ('stream', '&core::refusal(&core::Code::InvalidRequest)'),
               ('stream', 'b"HTTP/1.1 200 Connection established\\r\\n\\r\\n"')}
    for target, argument in writes:
        assert (target, argument) in allowed or (
            target == 'stream' and argument.startswith('&refusal("')), (target, argument)
    # Every request decision is the extracted controller's (PROXY-NATIVE-01).
    assert source.count('controller::serve(') == 1
    assert 'core::encode_upstream(' not in source and 'core::guest_response(' not in source
    assert source.count('exchange(self.session, self.origin, wire)') == 1
    assert re.findall(r'fn exchange\(&mut self, wire: &\[u8\]\)', source)
    assert re.findall(r'\.write\(', source) == []
    assert source.count('writeln!') == 2
