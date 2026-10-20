"""Real provider bytes must pass response admission before public projection."""
from __future__ import annotations

import json
import socketserver

import pytest

from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
from tests.test_rust_garrett_manifest import ManifestCase, policy, provider_directory


class RawProvider(TLSService):
    """A recording TLS origin whose response is not repaired by http.server."""
    def __init__(self, directory, response):
        super().__init__(directory, host='api.example.org')
        service = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(5)
                request = self.rfile.readline(4096)
                headers = {}
                while True:
                    line = self.rfile.readline(32768)
                    if line == b'\r\n':
                        break
                    if not line:
                        raise AssertionError('missing request headers')
                    name, value = line.rstrip(b'\r\n').split(b':', 1)
                    headers[name.decode().lower()] = value.decode().strip()
                body = self.rfile.read(int(headers.get('content-length', '0')))
                method, target, _ = request.decode().strip().split(' ')
                with service._lock:
                    service.requests.append(dict(method=method, target=target,
                        headers=headers, body=body.decode()))
                self.wfile.write(response)
                self.wfile.flush()
                self.close_connection = True

        self._server.RequestHandlerClass = Handler


def response(status=b'200 OK', *, kind=b'application/json', extra=b'', body=None):
    body = body if body is not None else json.dumps(dict(id=7, active=True, discarded=TOKEN)).encode()
    return (b'HTTP/1.1 ' + status + b'\r\nContent-Type: ' + kind +
        b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + extra + b'\r\n' + body)


@pytest.mark.parametrize('profile', ['account', 'read', 'write'])
@pytest.mark.parametrize('raw', [
    response(b'+200 OK'),
    response(b'0200 OK'),
    response(b'200'),
    response(b'200 OK\x00private'),
    response(kind=b'\xc2\xa0application/json'),
    response(kind=b'application/json\xc2\xa0'),
], ids=['signed-status', 'wide-status', 'missing-reason-space', 'control-reason',
        'unicode-leading-ows', 'unicode-trailing-ows'])
def test_native_malformed_response_cannot_reach_disclosure(tmp_path, profile, raw):
    with RawProvider(provider_directory(tmp_path), raw) as provider:
        if profile == 'account':
            case = AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path))
            request = {}
        else:
            case = ManifestCase(tmp_path, provider, writes='allow')
            request = dict(operation='ticket.view' if profile=='read' else 'ticket.edit',
                           arguments=dict(ticket=7, **({} if profile=='read' else dict(text='hello'))))
        with case:
            reply = case.invoke(**request)
            assert not reply['ok'], reply
            if profile == 'write':
                assert reply['error']['code'] == 'outcome_unknown'
            assert TOKEN not in json.dumps(reply)
            assert len(provider.seen()) == 1
            assert provider.seen()[0]['headers']['authorization'] == 'Bearer '+TOKEN
            audit = tmp_path/'provider-audit.jsonl'
            assert not any(json.loads(line)['event']=='completed' for line in audit.read_text().splitlines())


@pytest.mark.parametrize('backend', ['python', 'rust'])
@pytest.mark.parametrize('framing', ['length', 'leading-zero-length', 'chunked'])
@pytest.mark.parametrize('write', [False, True])
def test_provider_response_success_matches_python_effect_and_public_subset(tmp_path, backend, framing, write):
    from aivm_secrets.host.egress import HTTPSExecutor
    from aivm_secrets.kernel.service import parse_policy
    from tests.secrets_helpers import Harness
    body = b'{"id":7}'
    if framing == 'chunked':
        header = b'Transfer-Encoding: chunked\r\n'
        encoded = b'8\r\n'+body+b'\r\n0\r\n\r\n'
    else:
        header = b'Content-Length: '+(b'000' if framing=='leading-zero-length' else b'')+b'8\r\n'
        encoded = body
    raw = b'HTTP/1.1 200 \r\nCoNtEnT-TyPe:\tapplication/json ; charset=utf-8\t\r\n'+header+b'\r\n'+encoded
    with RawProvider(provider_directory(tmp_path), raw) as provider:
        p = policy(tmp_path, provider)
        operation = 'ticket.edit' if write else 'ticket.view'
        arguments = dict(ticket=7, **(dict(text='hello') if write else {}))
        if backend == 'python':
            spec = parse_policy(p)
            harness = Harness(tmp_path, policy=p, writes='allow', executor=HTTPSExecutor(spec.egress))
            try:
                reply = harness.invoke(operation, **arguments)
            finally:
                harness.broker.close()
        else:
            with ManifestCase(tmp_path, provider, p, writes='allow') as case:
                reply = case.invoke(operation=operation, arguments=arguments)
        assert reply['ok'] and reply['result'] == dict(id=7)
        assert len(provider.seen()) == 1
        sent = provider.seen()[0]
        assert sent['method'] == ('PATCH' if write else 'GET')
        assert sent['target'] == '/v1/tickets/7'
        assert sent['headers']['authorization'] == 'Bearer '+TOKEN


