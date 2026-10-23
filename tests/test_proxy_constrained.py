"""HP-2: the ``constrained-http`` proxy profile, Python reference.

The proxy holds no credential. A guest HTTPS request is served only when
the broker's own encoder, run on the arguments read off the request, gives
back exactly that request; the in-process broker then builds and sends the
provider request itself and returns only the operation's disclosure.
Everything else is refused with no provider call, and nothing ever falls
back to credential substitution.
"""

from __future__ import annotations

import json
import os

import pytest

from aivm_secrets.host.broker import Broker
from aivm_secrets.kernel.model import Binding
from aivm_secrets.kernel.service import parse_policy as parse_service
from aivm_secrets.proxy import constrained, http1
from aivm_secrets.proxy.http1 import Refused
from aivm_secrets.proxy.policy import PolicyError, parse_policy
from aivm_secrets.proxy.server import ProxyAudit, ProxyServer, ProxySession
from tests.secrets_helpers import SERVICE_TOKEN, TLSService, write_private
from tests.test_proxy_substitution import HOST, World, status

POLICY = dict(schema=1, profile='constrained-http', lifetime_seconds=600,
              origins=[dict(host=HOST)])


class ConstrainedWorld(World):
    def __init__(self, tmp_path, service, *, writes='deny'):
        token = write_private(tmp_path / 'token', (SERVICE_TOKEN + '\n').encode())
        spec = parse_service(service.policy(token))
        self.broker = Broker(spec, Binding(os.getuid(), 'principal-test', 'vm-test', 'b' * 32),
                             SERVICE_TOKEN, tmp_path / 'broker-audit' / 'session.jsonl',
                             writes=writes)
        self.service = service
        self.audit_path = tmp_path / 'proxy-audit.jsonl'
        self.session = ProxySession(parse_policy(POLICY), None, broker=self.broker,
                                    audit=ProxyAudit(self.audit_path))
        self.ca_path = tmp_path / 'session-ca.pem'
        self.ca_path.write_bytes(self.session.ca.pem)
        self.server = ProxyServer(self.session)

    def __exit__(self, *exc):
        super().__exit__(*exc)
        self.broker.close()


@pytest.fixture
def service(tmp_path):
    (tmp_path / 'provider').mkdir()
    with TLSService(tmp_path / 'provider', host=HOST, wire_headers=True) as provider:
        provider.routes[('GET', '/v1/account')] = {'login': 'demo'}
        provider.routes[('GET', '/v1/issues/23')] = {'id': 23}
        provider.routes[('GET', '/v1/issues?page=2&state=open')] = [{'id': 1}]
        provider.routes[('POST', '/v1/issues/23/comments')] = {'created': True}
        yield provider


@pytest.fixture
def world(tmp_path, service):
    with ConstrainedWorld(tmp_path, service) as w:
        yield w


def request(method: str, target: str, body: bytes = b'', extra: bytes = b'') -> bytes:
    head = (method.encode() + b' ' + target.encode() + b' HTTP/1.1\r\nHost: '
            + HOST.encode() + b'\r\n' + extra)
    if body or method in ('POST', 'PATCH', 'PUT'):
        head += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    return head + b'Connection: close\r\n\r\n' + body


def body(reply: bytes):
    return json.loads(reply.split(b'\r\n\r\n', 1)[1])


@pytest.mark.parametrize('target, expected, provider_target', [
    ('/v1/account', {'login': 'demo'}, '/v1/account'),
    ('/v1/issues/23', {'id': 23}, '/v1/issues/23'),
    ('/v1/issues?state=open&page=2', [{'id': 1}], '/v1/issues?page=2&state=open'),
])
def test_requests_equal_to_a_named_operation_are_served_by_the_broker(
        world, target, expected, provider_target):
    reply = world.raw(request('GET', target, extra=b'Authorization: Bearer placeholder\r\n'))
    assert status(reply) == 200, reply
    assert body(reply) == expected
    [seen] = world.service.requests
    assert seen['target'] == provider_target
    # The broker attached the credential; the guest's placeholder never left.
    assert seen['headers']['authorization'] == 'Bearer ' + SERVICE_TOKEN
    assert 'placeholder' not in json.dumps(seen)
    assert SERVICE_TOKEN.encode() not in reply
    events = [row['event'] for row in world.audit()]
    assert events[-2:] == ['admitted', 'completed']


@pytest.mark.parametrize('method, target, payload', [
    ('GET', '/v1/issues/99', b''),                       # not an allowlisted value
    ('GET', '/v1/issues/023', b''),                      # non-canonical integer
    ('GET', '/v1/account?x=1', b''),                     # extra query parameter
    ('GET', '/v1/issues?state=closed&page=2', b''),      # wrong literal
    ('GET', '/v1/issues?state=open&page=2&page=3', b''),  # duplicate parameter
    ('GET', '/v1/issues?state=open&page=99', b''),       # out of range
    ('GET', '/v1/admin', b''),                           # no operation
    ('DELETE', '/v1/issues/23', b''),                    # no operation
    ('POST', '/v1/issues/23/comments', b'{"body":"hi"}'),  # write, writes=deny
    ('POST', '/v1/issues/23/comments', b'{"body":"hi","x":"y"}'),  # extra field
    ('GET', '/v1/account', b'{}'),                       # body on a GET operation
], ids=['value', 'leading-zero', 'extra-query', 'wrong-literal', 'duplicate-query',
        'range', 'unknown-path', 'unknown-method', 'write-denied', 'extra-field', 'get-body'])
def test_everything_else_is_refused_before_any_provider_call(world, method, target, payload):
    reply = world.raw(request(method, target, payload))
    assert status(reply) in (400, 403), reply
    assert world.service.requests == []


def test_writes_follow_the_broker_write_mode(tmp_path, service):
    with ConstrainedWorld(tmp_path, service, writes='allow') as world:
        reply = world.raw(request('POST', '/v1/issues/23/comments', b'{"body":"hi"}'))
        assert status(reply) == 200, reply
        [seen] = service.requests
        assert json.loads(seen['body']) == {'body': 'hi'}


def test_revocation_closes_the_constrained_session(world):
    assert status(world.raw(request('GET', '/v1/account'))) == 200
    world.session.revoke()
    assert status(world.raw(request('GET', '/v1/account'))) == 403
    assert len(world.service.requests) == 1


def test_the_profiles_cannot_be_mixed(tmp_path, service):
    token = write_private(tmp_path / 'token', (SERVICE_TOKEN + '\n').encode())
    broker = Broker(parse_service(service.policy(token)),
                    Binding(os.getuid(), 'principal-test', 'vm-test', 'b' * 32),
                    SERVICE_TOKEN, tmp_path / 'audit' / 's.jsonl')
    try:
        constrained_policy = parse_policy(POLICY)
        with pytest.raises(PolicyError):  # no credential in constrained mode
            ProxySession(constrained_policy, SERVICE_TOKEN.encode(), broker=broker)
        with pytest.raises(PolicyError):  # the CONNECT origin is the broker's host
            ProxySession(parse_policy(dict(POLICY, origins=[dict(host='other.example.org')])),
                         None, broker=broker)
        with pytest.raises(PolicyError):  # substitution never gets a broker
            ProxySession(parse_policy(dict(
                schema=1, profile='credential-substitution', lifetime_seconds=60,
                origins=[dict(host=HOST, address='127.0.0.1', port=1, ca_file='x',
                              authentication='bearer')])), b'token', broker=broker)
    finally:
        broker.close()
    for bad in (dict(POLICY, deny=[]),
                dict(POLICY, origins=[dict(host=HOST, address='127.0.0.1', port=1,
                                           ca_file='x', authentication='bearer')]),
                dict(POLICY, origins=[dict(host=HOST), dict(host='b.example.org')])):
        with pytest.raises(PolicyError):
            parse_policy(bad)


def test_translation_is_checked_by_the_host_encoder_not_trusted(tmp_path, service):
    """A matcher defect cannot widen authority: the equality check refuses."""
    token = write_private(tmp_path / 'token', (SERVICE_TOKEN + '\n').encode())
    spec = parse_service(service.policy(token))
    parsed, _ = http1.parse_request(request('GET', '/v1/issues/23'), host=HOST.encode(),
                                    body_limit=100)
    assert constrained.translate(spec, parsed).operation == 'issue.view'
    original = constrained.candidates
    try:
        # A broken matcher proposes a different issue for the same request.
        constrained.candidates = lambda op, m, t: [
            {**c, 'issue': 24} if 'issue' in c else c for c in original(op, m, t)]
        with pytest.raises(Refused):
            constrained.translate(spec, parsed)
    finally:
        constrained.candidates = original


def test_process_contract_runs_a_constrained_session(tmp_path, service):
    import base64
    import select
    import socket
    import ssl
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    token = write_private(tmp_path / 'token', (SERVICE_TOKEN + '\n').encode())
    service_policy = write_private(tmp_path / 'service.json',
                                   json.dumps(service.policy(token)).encode())
    proxy_policy = write_private(tmp_path / 'proxy.json', json.dumps(POLICY).encode())
    (tmp_path / 'audit').mkdir(mode=0o700)
    process = subprocess.Popen(
        [sys.executable, '-m', 'aivm_secrets', 'proxy', '--policy', str(proxy_policy),
         '--credential-file', str(token), '--audit', str(tmp_path / 'audit' / 'proxy.jsonl'),
         '--service-policy', str(service_policy),
         '--broker-audit', str(tmp_path / 'audit' / 'broker.jsonl')],
        cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert select.select([process.stdout], [], [], 30)[0]
        announcement = json.loads(process.stdout.readline())
        assert announcement['ready'] is True, announcement
        assert announcement['profile'] == 'constrained-http'
        ca = tmp_path / 'ca.pem'
        ca.write_text(announcement['ca_pem'])
        host, port = announcement['listen'].rsplit(':', 1)
        with socket.create_connection((host, int(port)), timeout=10) as raw:
            auth = base64.b64encode(b'aivm:' + announcement['proxy_token'].encode())
            raw.sendall(b'CONNECT ' + HOST.encode() + b':443 HTTP/1.1\r\n'
                        b'Proxy-Authorization: Basic ' + auth + b'\r\n\r\n')
            assert raw.recv(4096).startswith(b'HTTP/1.1 200 ')
            context = ssl.create_default_context(cafile=str(ca))
            with context.wrap_socket(raw, server_hostname=HOST) as tls:
                tls.sendall(request('GET', '/v1/issues/23'))
                reply = b''
                while chunk := tls.recv(65536):
                    reply += chunk
        assert status(reply) == 200 and body(reply) == {'id': 23}
    finally:
        process.stdin.close()
        assert process.wait(timeout=30) == 0
    out, err = process.stdout.read(), process.stderr.read()
    assert SERVICE_TOKEN.encode() not in out + err
    for path in (tmp_path / 'audit').iterdir():
        assert SERVICE_TOKEN.encode() not in path.read_bytes()
