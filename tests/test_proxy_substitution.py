"""HP-1: the ``credential-substitution`` proxy profile, Python reference.

A synthetic TLS provider plays the origin and a synthetic credential is
substituted. The "guest" is stock ``curl`` or a raw TLS client speaking
through ``CONNECT``. Assertions are on what reached the provider, what the
guest received and what the audit recorded.
"""

from __future__ import annotations

import base64
import json
import shutil
import socket
import ssl
import subprocess
from pathlib import Path

import pytest

from aivm_secrets.proxy import http1
from aivm_secrets.proxy.policy import PolicyError, parse_policy
from aivm_secrets.proxy.server import ProxyAudit, ProxyServer, ProxySession
from tests.secrets_helpers import TOKEN, TLSService

HOST = 'api.example.org'


def policy_for(service, **changes):
    value = dict(
        schema=1, profile='credential-substitution', lifetime_seconds=600,
        origins=[dict(host=HOST, address='127.0.0.1', port=service.port,
                      ca_file=str(service.files['ca']), authentication='bearer')],
        deny=[dict(method='POST', path='/v1/tokens'), dict(method='*', path='/v1/admin/')],
    )
    value.update(changes)
    return parse_policy(value)


class World:
    def __init__(self, tmp_path, service, *, secret: str = TOKEN, **policy_changes):
        self.service = service
        self.audit_path = tmp_path / 'proxy-audit.jsonl'
        self.session = ProxySession(policy_for(service, **policy_changes), secret.encode(),
                                    audit=ProxyAudit(self.audit_path))
        self.ca_path = tmp_path / 'session-ca.pem'
        self.ca_path.write_bytes(self.session.ca.pem)
        self.server = ProxyServer(self.session)

    def __enter__(self):
        self.server.__enter__()
        self.port = int(self.server.address.rsplit(':', 1)[1])
        return self

    def __exit__(self, *exc):
        self.server.__exit__(*exc)

    def raw(self, request: bytes, *, connect: bytes | None = None,
            auth: bytes | None = None, read_all: bool = True) -> bytes:
        """Send ``request`` through a CONNECT tunnel; return the guest's bytes."""
        token = self.session.token.encode() if auth is None else auth
        host = getattr(self, 'host', HOST)
        connect = connect or (b'CONNECT ' + host.encode() + b':443 HTTP/1.1\r\nHost: '
                              + host.encode() + b':443\r\n')
        head = connect
        if token:
            head += b'Proxy-Authorization: Basic ' + base64.b64encode(b'aivm:' + token) + b'\r\n'
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as raw:
            raw.sendall(head + b'\r\n')
            answer = b''
            while b'\r\n\r\n' not in answer:
                chunk = raw.recv(65536)
                if not chunk:
                    return answer
                answer += chunk
            if not answer.startswith(b'HTTP/1.1 200 '):
                return answer
            context = ssl.create_default_context(cafile=str(self.ca_path))
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(request)
                reply = b''
                while True:
                    try:
                        chunk = tls.recv(65536)
                    except (ssl.SSLError, OSError):
                        break
                    if not chunk:
                        break
                    reply += chunk
                    if not read_all and reply.count(b'HTTP/1.1 ') >= 2:
                        break
                return reply

    def audit(self) -> list[dict]:
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]


def get(path: str = '/v1/account', extra: bytes = b'') -> bytes:
    return (b'GET ' + path.encode() + b' HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n'
            + extra + b'Connection: close\r\n\r\n')


def status(reply: bytes) -> int:
    return int(reply.split(b' ', 2)[1])


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
    with World(tmp_path, service) as w:
        yield w


def assert_clean(world, *outputs: bytes) -> None:
    for output in outputs:
        assert TOKEN.encode() not in output
    audit = world.audit_path.read_bytes()
    assert TOKEN.encode() not in audit and world.session.token.encode() not in audit


@pytest.mark.skipif(shutil.which('curl') is None, reason='needs curl')
def test_stock_curl_reads_with_a_placeholder_and_the_provider_gets_the_credential(world):
    done = subprocess.run(
        ['curl', '-sS', '--fail', '--proxy', f'http://127.0.0.1:{world.port}',
         '--proxy-user', f'aivm:{world.session.token}', '--cacert', str(world.ca_path),
         '-H', 'Authorization: Bearer placeholder', f'https://{HOST}/v1/account'],
        capture_output=True, timeout=30,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {'login': 'demo'}
    [seen] = world.service.requests
    assert [v for k, v in seen['header_pairs'] if k.lower() == 'authorization'] == [
        'Bearer ' + TOKEN]
    assert_clean(world, done.stdout, done.stderr)
    events = [row['event'] for row in world.audit()]
    assert events == ['session_start', 'admitted', 'completed']


def test_a_body_is_reencoded_and_guest_credentials_are_replaced(world):
    body = b'{"title":"fix"}'
    chunked = b'%x\r\n%s\r\n0\r\n\r\n' % (len(body), body)
    request = (b'POST /v1/issues HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n'
               b'Authorization: token guest-supplied\r\nX-Api-Key: guest-key\r\n'
               b'Cookie: session=guest\r\nAccept-Encoding: gzip\r\n'
               b'Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n'
               b'Connection: close\r\n\r\n' + chunked)
    reply = world.raw(request)
    assert status(reply) == 201
    [seen] = world.service.requests
    pairs = [(k.lower(), v) for k, v in seen['header_pairs']]
    assert [v for k, v in pairs if k == 'authorization'] == ['Bearer ' + TOKEN]
    names = [k for k, _ in pairs]
    assert 'x-api-key' not in names and 'cookie' not in names
    assert 'transfer-encoding' not in names
    assert dict(pairs)['content-length'] == str(len(body))
    assert dict(pairs)['accept-encoding'] == 'identity'
    assert seen['body'] == body.decode()
    assert_clean(world, reply)


def test_keep_alive_serves_sequential_requests_on_one_tunnel(world):
    one = b'GET /v1/account HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n\r\n'
    reply = world.raw(one + one, read_all=False)
    assert reply.count(b'HTTP/1.1 200 ') == 2
    assert len(world.service.requests) == 2


@pytest.mark.parametrize('request_bytes', [
    get(extra=b'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n'),
    get(extra=b'Content-Length: 1\r\nContent-Length: 1\r\n'),
    get(extra=b'Transfer-Encoding: gzip, chunked\r\n'),
    get(extra=b'X-Folded: a\r\n b\r\n'),
    b'GET /v1/account HTTP/1.1\nHost: ' + HOST.encode() + b'\r\n\r\n',
    get(extra=b'X-Bad: a\rb\r\n'),
    b'GET /v1/account HTTP/1.1\r\nHost: other.example.org\r\n\r\n',
    b'GET /v1/account HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\nHost: ' + HOST.encode() + b'\r\n\r\n',
    get('/v1/../admin/x'),
    get('/v1/%2e%2e/admin'),
    get('/v1//account'),
    get('/v1%2Faccount'),
    get(extra=b'Upgrade: h2c\r\n'),
    get(extra=b'Expect: 100-continue\r\n'),
    b'GET https://' + HOST.encode() + b'/v1/account HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n\r\n',
    b'GET /v1/account HTTP/1.0\r\nHost: ' + HOST.encode() + b'\r\n\r\n',
    b'TRACE /v1/account HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n\r\n',
], ids=['cl-and-te', 'duplicate-cl', 'te-not-chunked', 'obs-fold', 'bare-lf',
        'bare-cr', 'host-mismatch', 'two-hosts', 'dot-segment', 'encoded-dots', 'empty-segment',
        'encoded-slash', 'upgrade', 'expect', 'absolute-form', 'http-1.0', 'trace'])
def test_ambiguous_or_unsupported_requests_never_reach_the_provider(world, request_bytes):
    reply = world.raw(request_bytes)
    assert status(reply) == 400, reply
    assert world.service.requests == []
    assert_clean(world, reply)


@pytest.mark.parametrize('method, path', [('POST', '/v1/tokens'), ('GET', '/v1/admin/users')])
def test_deny_listed_requests_are_refused_before_egress(world, method, path):
    request = (method.encode() + b' ' + path.encode() + b' HTTP/1.1\r\nHost: '
               + HOST.encode() + b'\r\nContent-Length: 0\r\n\r\n')
    reply = world.raw(request)
    assert status(reply) == 403 and b'"denied"' in reply
    assert world.service.requests == []


@pytest.mark.parametrize('connect, auth, code', [
    (None, b'', 407),
    (None, b'wrong-token', 407),
    (b'CONNECT evil.example.net:443 HTTP/1.1\r\n', None, 403),
    (b'CONNECT ' + HOST.encode() + b':8443 HTTP/1.1\r\n', None, 403),
    (b'GET http://' + HOST.encode() + b'/v1/account HTTP/1.1\r\n', None, 400),
], ids=['no-auth', 'bad-auth', 'unlisted-origin', 'other-port', 'plain-proxying'])
def test_the_tunnel_requires_the_session_and_a_configured_origin(world, connect, auth, code):
    reply = world.raw(get(), connect=connect, auth=auth)
    assert status(reply) == code, reply
    assert world.service.requests == []


def _encodings_of_token() -> list[bytes]:
    from urllib.parse import quote

    return [
        TOKEN.encode(),
        base64.b64encode(b'x-access-token:' + TOKEN.encode()),
        base64.urlsafe_b64encode(b'ab' + TOKEN.encode()),
        quote(TOKEN + '/', safe='').lower().encode(),
        TOKEN.encode().hex().upper().encode(),
    ]


@pytest.mark.parametrize('encoded', _encodings_of_token(),
                         ids=['raw', 'basic-b64', 'b64url-offset', 'percent', 'hex'])
@pytest.mark.parametrize('where', ['body', 'header'])
def test_a_response_that_reflects_the_credential_is_refused(world, encoded, where):
    if where == 'body':
        world.service.routes[('GET', '/v1/account')] = lambda seen: (
            200, {}, b'{"echo":"' + encoded + b'"}')
    else:
        world.service.routes[('GET', '/v1/account')] = lambda seen: (
            200, {'X-Echo': encoded.decode()}, b'{}')
    reply = world.raw(get())
    assert status(reply) == 502 and b'"reflected"' in reply
    assert len(world.service.requests) == 1
    assert_clean(world, reply)


def test_a_compressed_response_is_refused(world):
    world.service.routes[('GET', '/v1/account')] = lambda seen: (
        200, {'Content-Encoding': 'gzip'}, b'\x1f\x8b')
    reply = world.raw(get())
    assert status(reply) == 502


def test_redirects_are_returned_not_followed(world):
    world.service.routes[('GET', '/v1/account')] = lambda seen: (
        302, {'Location': 'https://evil.example.net/steal'}, b'')
    reply = world.raw(get())
    assert status(reply) == 302
    assert len(world.service.requests) == 1


def test_revocation_and_expiry_stop_the_next_request(tmp_path, service):
    with World(tmp_path, service) as world:
        assert status(world.raw(get())) == 200
        world.session.revoke()
        assert status(world.raw(get())) == 403
        assert len(service.requests) == 1
    now = [1000.0]
    (tmp_path / 'b').mkdir()
    with World(tmp_path / 'b', service) as world:
        world.session._clock = lambda: now[0]
        world.session.expires_at = 1010.0
        assert status(world.raw(get())) == 200
        now[0] = 1010.0
        assert status(world.raw(get())) == 403
        assert len(service.requests) == 2


def test_oversize_bodies_are_refused(tmp_path, service):
    with World(tmp_path, service, limits={'request_body': 8, 'response_body': 4}) as world:
        big = (b'POST /v1/issues HTTP/1.1\r\nHost: ' + HOST.encode()
               + b'\r\nContent-Length: 9\r\n\r\n123456789')
        assert status(world.raw(big)) == 413
        assert service.requests == []
        assert status(world.raw(get())) == 413  # '{"login":"demo"}' > 4 bytes
        assert len(service.requests) == 1


def test_a_failed_admission_audit_sends_nothing(world, monkeypatch):
    """Fail closed, as the native proxy: if the admission record cannot be
    written, the guest gets ``internal_error`` and nothing is sent."""
    real = world.session.audit.record

    def record(event, **detail):
        if event == 'admitted':
            raise OSError('disk full')
        return real(event, **detail)

    monkeypatch.setattr(world.session.audit, 'record', record)
    reply = world.raw(get())
    assert status(reply) == 502 and b'"internal_error"' in reply, reply
    assert world.service.requests == []


def test_an_unreachable_origin_reports_that_nothing_was_sent(tmp_path, service):
    with World(tmp_path, service) as world:
        origin = world.session.policy.origins[HOST]
        world.session.policy.origins[HOST] = type(origin)(
            origin.host, origin.address, 1, origin.ca_file, origin.authentication)
        reply = world.raw(get())
        assert status(reply) == 502 and b'"unreachable"' in reply


def test_the_session_ca_is_name_constrained_and_mints_only_configured_origins(world):
    from cryptography import x509

    constraints = world.session.ca.certificate.extensions.get_extension_for_class(
        x509.NameConstraints)
    assert constraints.critical
    assert [n.value for n in constraints.value.permitted_subtrees] == [HOST]
    with pytest.raises(ValueError):
        world.session.ca.server_context('evil.example.net')


@pytest.mark.parametrize('change', [
    {'profile': 'constrained-http'},
    {'origins': []},
    {'origins': [dict(host='bad host', address='127.0.0.1', port=1, ca_file='x',
                      authentication='bearer')]},
    {'origins': [dict(host=HOST, address='127.0.0.1', port=1, ca_file='x',
                      authentication='cookie')]},
    {'deny': [dict(method='GET', path='/a/../b')]},
    {'lifetime_seconds': 0},
    {'limits': {'request_body': 0}},
    {'extra': True},
])
def test_policy_schema_is_exact(service, change):
    with pytest.raises(PolicyError):
        policy_for(service, **change)


def test_strict_parser_round_trip_is_canonical():
    request, rest = http1.parse_request(
        get(extra=b'X-Trace:   abc  \r\n'), host=HOST.encode(), body_limit=10)
    assert rest == b'' and request.values(b'x-trace') == [b'abc']
    wire = http1.encode_request(request, host=HOST.encode(),
                                forwarded=((b'x-trace', b'abc'),),
                                authentication=(b'authorization', b'Bearer t'))
    again, _ = http1.parse_request(
        wire.replace(b'Connection: close\r\n', b''), host=HOST.encode(), body_limit=10)
    assert again.method == request.method and again.target == request.target
    assert again.values(b'authorization') == [b'Bearer t']


def test_revocation_applies_inside_an_open_keep_alive_tunnel(world):
    """Each request re-samples revocation; an open tunnel is not a grant."""
    def revoke_after_answering(seen):
        world.session.revoke()
        return 200, {}, b'{"login":"demo"}'

    world.service.routes[('GET', '/v1/account')] = revoke_after_answering
    one = b'GET /v1/account HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n\r\n'
    reply = world.raw(one + one, read_all=False)
    assert reply.startswith(b'HTTP/1.1 200 ') and b'HTTP/1.1 403 ' in reply
    assert len(world.service.requests) == 1


def test_process_contract_announces_serves_and_ends_on_stdin_eof(tmp_path, service):
    import select
    import sys

    from tests.secrets_helpers import write_private

    root = Path(__file__).resolve().parents[1]
    policy = dict(schema=1, profile='credential-substitution', lifetime_seconds=600,
                  origins=[dict(host=HOST, address='127.0.0.1', port=service.port,
                                ca_file=str(service.files['ca']), authentication='bearer')])
    policy_path = write_private(tmp_path / 'proxy.json', json.dumps(policy).encode())
    credential = write_private(tmp_path / 'credential', (TOKEN + '\n').encode())
    process = subprocess.Popen(
        [sys.executable, '-m', 'aivm_secrets', 'proxy', '--policy', str(policy_path),
         '--credential-file', str(credential), '--audit', str(tmp_path / 'audit.jsonl')],
        cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert select.select([process.stdout], [], [], 30)[0]
        announcement = json.loads(process.stdout.readline())
        assert announcement['ready'] is True
        assert announcement['profile'] == 'credential-substitution'
        assert announcement['origins'] == [HOST]
        ca = tmp_path / 'ca.pem'
        ca.write_text(announcement['ca_pem'])
        host, port = announcement['listen'].rsplit(':', 1)
        context = ssl.create_default_context(cafile=str(ca))
        with socket.create_connection((host, int(port)), timeout=10) as raw:
            auth = base64.b64encode(b'aivm:' + announcement['proxy_token'].encode())
            raw.sendall(b'CONNECT ' + HOST.encode() + b':443 HTTP/1.1\r\n'
                        b'Proxy-Authorization: Basic ' + auth + b'\r\n\r\n')
            assert raw.recv(4096).startswith(b'HTTP/1.1 200 ')
            with context.wrap_socket(raw, server_hostname=HOST) as tls:
                tls.sendall(get())
                reply = b''
                while chunk := tls.recv(65536):
                    reply += chunk
        assert status(reply) == 200 and json.loads(reply.split(b'\r\n\r\n', 1)[1]) == {
            'login': 'demo'}
    finally:
        process.stdin.close()
        assert process.wait(timeout=30) == 0
    out, err = process.stdout.read(), process.stderr.read()
    assert TOKEN.encode() not in out + err
    assert TOKEN.encode() not in (tmp_path / 'audit.jsonl').read_bytes()
    assert json.dumps(announcement).find(TOKEN) < 0
