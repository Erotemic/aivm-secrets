"""Security-review hardening of the credential-substitution proxy (HP-5).

Each case runs against the Python reference and the native ``garrett-proxy``:
deny-list spellings fail closed, method-override and range fields are not
forwarded, line-wrapped encodings are still recognised as reflections, the
audit is a 0600 hash chain, and the connection cap releases its slots.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import stat
import time

import pytest

from tests.secrets_helpers import TOKEN, TLSService
from tests.test_proxy_substitution import HOST, World, get, status


@pytest.fixture
def service(tmp_path):
    (tmp_path / 'provider').mkdir()
    with TLSService(tmp_path / 'provider', host=HOST, wire_headers=True) as provider:
        provider.routes[('GET', '/v1/account')] = {'login': 'demo'}
        provider.routes[('POST', '/v1/issues')] = {'created': True}
        yield provider


@pytest.fixture(params=['python', 'native'])
def world(request, tmp_path, service):
    if request.param == 'python':
        with World(tmp_path, service) as w:
            yield w
    else:
        from tests.test_rust_proxy import NativeWorld
        with NativeWorld(tmp_path, service) as w:
            yield w


def request(method: bytes, target: bytes, extra: bytes = b'') -> bytes:
    return (method + b' ' + target + b' HTTP/1.1\r\nHost: ' + HOST.encode() + b'\r\n'
            + extra + b'Content-Length: 0\r\n\r\n')


@pytest.mark.parametrize('method, target, code', [
    (b'GET', b'/v1/admin', 403),
    (b'GET', b'/v1/admin/', 403),
    (b'POST', b'/v1/tokens/', 403),
    (b'GET', b'/v1/%61dmin/users', 400),
    (b'GET', b'/v1/admin%2Fusers', 400),
    (b'GET', b'/v1/admin%5cusers', 400),
    (b'GET', b'/v1/admin;x/users', 400),
    (b'GET', b'/v1/%zz', 400),
    (b'GET', b'/v1/%4', 400),
], ids=['no-slash', 'slash', 'post-trailing', 'escaped-letter', 'escaped-slash',
        'escaped-backslash', 'semicolon', 'bad-escape', 'short-escape'])
def test_equivalent_spellings_of_a_denied_path_fail_closed(world, method, target, code):
    reply = world.raw(request(method, target))
    assert status(reply) == code, reply
    assert world.service.requests == []


def test_method_override_and_range_fields_are_not_forwarded(world):
    extra = (b'X-HTTP-Method-Override: DELETE\r\nx-method-override: DELETE\r\n'
             b'X-Http-Method: DELETE\r\nRange: bytes=0-3\r\nIf-Range: "x"\r\n')
    reply = world.raw(request(b'POST', b'/v1/issues', extra))
    assert status(reply) == 200, reply
    [seen] = world.service.requests
    names = {name.lower() for name, _ in seen['header_pairs']}
    assert not names & {'x-http-method-override', 'x-method-override', 'x-http-method',
                        'range', 'if-range'}


@pytest.mark.parametrize('separator', [b'\n', b'\r\n'])
def test_line_wrapped_base64_of_the_credential_is_refused(world, separator):
    encoded = base64.b64encode(b'x-access-token:' + TOKEN.encode())
    wrapped = separator.join(encoded[i:i + 16] for i in range(0, len(encoded), 16))
    world.service.routes[('GET', '/v1/account')] = lambda seen: (200, {}, wrapped)
    reply = world.raw(get())
    assert status(reply) == 502 and b'"reflected"' in reply
    assert TOKEN.encode() not in reply


@pytest.mark.parametrize('kind', ['python', 'native'])
def test_a_json_escaped_credential_with_slashes_is_refused(tmp_path, service, kind):
    """A credential containing ``/`` is also checked in its JSON ``\\/`` form."""
    from tests.test_rust_proxy import NativeWorld

    slashed = 'tok/en/' + TOKEN
    escaped = b'{"k":"' + slashed.replace('/', '\\/').encode() + b'"}'
    service.routes[('GET', '/v1/account')] = lambda seen: (200, {}, escaped)
    make = World if kind == 'python' else NativeWorld
    with make(tmp_path, service, secret=slashed) as live:
        reply = live.raw(get())
    assert status(reply) == 502 and b'"reflected"' in reply, reply


def test_the_audit_is_a_private_hash_chain(world):
    assert status(world.raw(get())) == 200
    raw = world.audit_path.read_bytes()
    assert stat.S_IMODE(world.audit_path.stat().st_mode) == 0o600
    lines = raw.splitlines()
    assert len(lines) >= 2
    head = '0' * 64
    for seq, line in enumerate(lines):
        row = json.loads(line)
        assert row['seq'] == seq and row['prev'] == head, row
        head = hashlib.sha256(line).hexdigest()


def test_the_connection_cap_refuses_extra_clients_and_recovers(world):
    idle = [socket.create_connection(('127.0.0.1', world.port), timeout=10) for _ in range(32)]
    try:
        time.sleep(0.5)
        with socket.create_connection(('127.0.0.1', world.port), timeout=10) as extra:
            extra.sendall(b'CONNECT ' + HOST.encode() + b':443 HTTP/1.1\r\n\r\n')
            try:
                assert extra.recv(1024) == b''
            except ConnectionResetError:
                pass
    finally:
        for connection in idle:
            connection.close()
    deadline = time.monotonic() + 10
    while True:
        reply = world.raw(get())
        if reply.startswith(b'HTTP/1.1 200 ') or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    assert status(reply) == 200, reply
