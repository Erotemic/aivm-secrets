"""W6: real native bridge/client, provider TLS and host audit observations.

Rust executables are required; no Python broker fallback. Test uses the
repository's synthetic GitHub policy and a local HTTPS test provider.
"""
from __future__ import annotations

import copy
import json
import socket
import ssl

import pytest

from tests.secrets_github_scenario import (
    ALLOWED_PR, CHECKS, CHECKS_PATH, DIFF, HEAD_SHA, PULL, PULL_PATH, install_github_routes,
)
from aivm_secrets.kernel import codec
from tests.secrets_helpers import TOKEN, RawHTTPResponse, TLSService
from tests.secrets_w6_trace import (
    TraceMismatch, assert_native_effect_trace, records, audit_since,
)
from tests.test_rust_garrett_manifest import (
    ManifestCase, policy as ticket_policy, disclosure as ticket_disclosure,
    provider_directory, reference_compile,
)
from tests.test_rust_w2_github_workflow import (
    arguments, native_disclosure, native_policy,
)


def native_guest_frame(case, *, operation, arguments):
    """Read the actual bridge TLS bytes, not the native CLI's parsed stdout.

    This client only submits a normal bound request using the synthetic client
    certificate. The bridge and provider remain real Rust/local TLS processes.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(case.certs['ca']))
    context.load_cert_chain(str(case.certs['client1'][0]), str(case.certs['client1'][1]))
    request = codec.dumps({
        'version': 1, 'capability': case.token,
        'request': {'operation': operation, 'arguments': arguments},
    }) + b'\n'
    with socket.socket(socket.AF_UNIX) as raw:
        raw.settimeout(15)
        raw.connect(str(case.directory / 'identity.sock'))
        with context.wrap_socket(raw, server_hostname='localhost') as channel:
            channel.sendall(request)
            received = bytearray()
            while True:
                chunk = channel.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
                assert len(received) <= 65536, 'unbounded guest output'
    wire = bytes(received)
    assert wire.endswith(b'\n') and wire.count(b'\n') == 1, 'missing/extra guest frame'
    reply = codec.loads(wire[:-1])
    assert wire == codec.dumps(reply) + b'\n', 'guest response is not canonical JSONL'
    assert TOKEN.encode() not in wire and case.token.encode() not in wire
    return reply, wire


def snapshot(tmp_path, provider):
    return len(provider.seen()), len(records(tmp_path / 'provider-audit.jsonl'))


def effects(policy, operation, args, facts):
    compiled = reference_compile(policy, dict(operation=operation, arguments=args), facts)
    assert compiled['ok'], compiled
    result = compiled['result']
    return [
        (phase, result[key])
        for phase, key in [('preflight', 'preflight'), ('final', 'effect')]
        if result[key] is not None
    ]


def trace_of(case, tmp_path, server, operation, args, planned, *, successful=True,
             expected_result=None, expected_meta=None, provider_arrivals=None,
             raw_guest=False):
    requests_before, audit_before = snapshot(tmp_path, server)
    if raw_guest:
        reply, wire = native_guest_frame(case, operation=operation, arguments=args)
    else:
        reply, wire = case.invoke(operation=operation, arguments=args), None
    expected = {}
    if wire is not None:
        expected['guest_frame'] = wire
    if expected_result is not None:
        expected['expected_result'] = expected_result
    if expected_meta is not None:
        expected['expected_meta'] = expected_meta
    if provider_arrivals is not None:
        expected['audit_at_provider'] = [
            rows[audit_before:] for rows in provider_arrivals[requests_before:]
        ]
    assert_native_effect_trace(
        provider=server.seen()[requests_before:],
        audit=audit_since(tmp_path / 'provider-audit.jsonl', audit_before),
        reply=reply, planned=planned,
        host=server.host, port=server.port, credential=TOKEN,
        expect_success=successful,
        policy_headers=json.loads(case.policy_file.read_text()).get('headers', {}),
        sensitive=(case.token,),
        **expected,
    )
    return reply


def test_w6_reference_trace_oracle_rejects_bypass_and_leaks():
    """Runs without Rust: checks the oracle can detect meaningful mutations."""
    declared = dict(method='GET', target='/v1/allowed', accept='application/json', body=None)
    provider = [dict(method='GET', target='/v1/allowed', body='', headers={
        'host': 'api.example.org:443', 'accept': 'application/json',
        'accept-encoding': 'identity', 'connection': 'close', 'user-agent': 'aivm-secrets/1',
        'authorization': 'Bearer TEST_CREDENTIAL_123456',
    })]
    audit = [dict(event='dispatch', phase='final', request_digest='d' * 64, route={
        'host': 'api.example.org', 'port': 443, 'method': 'GET', 'path': '/v1/allowed',
    }), dict(event='completed', request_digest='d' * 64)]
    kwargs = dict(provider=provider, audit=audit, reply=dict(version=1, ok=True, result={'id': 7}),
                  planned=[('final', declared)], host='api.example.org', port=443,
                  credential='TEST_CREDENTIAL_123456', expect_success=True)
    assert_native_effect_trace(**kwargs)
    for bad in [
        dict(provider=provider + provider),
        dict(audit=audit[1:]),
        dict(audit=[{**audit[0], 'route': {**audit[0]['route'], 'path': '/outside'}}, audit[1]]),
        dict(reply={'version': 1, 'ok': True, 'result': {'token': 'TEST_CREDENTIAL_123456'}}),
        dict(reply={'version': 1, 'ok': False, 'error': {'code': 'denied', 'message': 'x'}}),
    ]:
        with pytest.raises(TraceMismatch):
            assert_native_effect_trace(**(kwargs | bad))




def test_w6_reference_oracle_rejects_header_smuggling_and_unselected_release():
    """Mutate only the observed wire/audit/reply: the approved effect stays fixed."""
    planned = [('final', {'method': 'PATCH', 'target': '/v1/tickets/7',
                          'accept': 'application/json', 'body': {'count': 1}})]
    headers = {
        'host': 'api.example.org:443', 'accept': 'application/json',
        'accept-encoding': 'identity', 'user-agent': 'aivm-secrets/1',
        'connection': 'close', 'authorization': 'Bearer ' + TOKEN,
        'content-type': 'application/json', 'content-length': '11',
        'x-api-version': '2026-03-10',
    }
    # The captured header pairs are the wire source of truth. Converting to a
    # mapping may hide duplicate Authorization or Host lines from the provider.
    provider = [dict(method='PATCH', target='/v1/tickets/7',
                     body='{"count":1}', headers=headers,
                     header_pairs=list(headers.items()), request_version='HTTP/1.1')]
    audit = [dict(event='dispatch', phase='final', request_digest='d' * 64, route={
        'host': 'api.example.org', 'port': 443, 'method': 'PATCH', 'path': '/v1/tickets/7',
    }), dict(event='completed', request_digest='d' * 64)]
    reply = {'version': 1, 'ok': True, 'result': {'id': 7}}
    base = dict(provider=provider, audit=audit, reply=reply, planned=planned,
                host='api.example.org', port=443, credential=TOKEN,
                policy_headers={'X-Api-Version': '2026-03-10'},
                expect_success=True, expected_result={'id': 7},
                sensitive=('surrogate-secret',))
    assert_native_effect_trace(**base)

    mutations = []
    for name, value in [
        ('cookie', 'token=' + TOKEN), ('proxy-authorization', 'Basic leak'),
        ('x-hidden', 'unreviewed'), ('authorization', 'Bearer attacker'),
    ]:
        bad = copy.deepcopy(base)
        bad['provider'][0]['headers'][name] = value
        mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['provider'][0]['header_pairs'].append(('AUTHORIZATION', 'Bearer attacker'))
    mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['provider'][0]['header_pairs'].append(('X-Hidden', 'unreviewed'))
    mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['provider'][0]['request_version'] = 'HTTP/1.0'
    mutations.append(bad)
    # Keep framing internally consistent, so these mutants can only fail
    # the strict typed JSON equality (duplicate keys or bool vs integer).
    for wire in ['{"count":1,"count":1}', '{"count":true}']:
        bad = copy.deepcopy(base)
        bad['provider'][0]['body'] = wire
        length = str(len(wire.encode()))
        bad['provider'][0]['headers']['content-length'] = length
        bad['provider'][0]['header_pairs'] = [
            (name, length if name.lower() == 'content-length' else value)
            for name, value in bad['provider'][0]['header_pairs']
        ]
        mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['audit'][0]['request_digest'] = '0' * 64
    mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['audit'][1]['request_digest'] = '1' * 64
    mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['reply']['result']['unselected'] = 'provider-private-field'
    mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['reply']['meta'] = {'private': 'provider-data'}
    mutations.append(bad)
    bad = copy.deepcopy(base)
    bad['audit'][0]['token'] = 'surrogate-secret'
    mutations.append(bad)

    for index, mutated in enumerate(mutations):
        try:
            assert_native_effect_trace(**mutated)
        except TraceMismatch:
            continue
        raise AssertionError(f'W6 trace oracle missed mutant {index}')



def test_w6_native_checked_request_trace_matches_policy_audit_and_tls(tmp_path, monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:1')
    with TLSService(provider_directory(tmp_path), wire_headers=True) as server:
        install_github_routes(server)
        p = native_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, native_disclosure()) as case:
            view = trace_of(case, tmp_path, server, 'pr.view', arguments(),
                            effects(p, 'pr.view', arguments(), PULL),
                            expected_result={'number': ALLOWED_PR, 'title': PULL['title'], 'headRefOid': HEAD_SHA})
            assert view['result'] == {
                'number': ALLOWED_PR, 'title': PULL['title'], 'headRefOid': HEAD_SHA,
            }
            diff = trace_of(case, tmp_path, server, 'pr.diff', arguments(),
                            effects(p, 'pr.diff', arguments(), PULL),
                            expected_result={'diff': DIFF})
            assert 'diff' in diff['result']
            checks = trace_of(case, tmp_path, server, 'pr.checks', arguments(),
                              effects(p, 'pr.checks', arguments(), PULL),
                              expected_result={'checks': CHECKS['check_runs']},
                              expected_meta={'pagination': {'page': 1, 'per_page': 100, 'possibly_more': False}})
            assert checks['result']['checks'][0]['name'] == 'lean'
            # Unsupported operation and cross-PR access cause no effects.
            for op, args in [
                ('pr.view', {'repository': arguments()['repository'], 'pr': ALLOWED_PR + 1}),
                ('arbitrary.fetch', {'url': 'https://elsewhere.invalid'}),
            ]:
                denied = trace_of(case, tmp_path, server, op, args, [], successful=False)
                assert denied['error']['code'] in ('denied', 'invalid_request')
            before = server.seen()
            assert case.invoke(verb='renounce')['renounced'] is True
            denied = trace_of(case, tmp_path, server, 'pr.view', arguments(), [], successful=False)
            assert denied['error']['code'] in ('invalid_capability', 'revoked')
            assert server.seen() == before
        saved = (tmp_path / 'provider-audit.jsonl').read_text()
        assert case.token not in saved and TOKEN not in saved


def test_w6_audit_is_present_when_each_read_reaches_real_https_provider(tmp_path):
    """Native TLS process witness for audit-before-send, not fsync durability."""
    arrivals = []
    audit_file = tmp_path / 'provider-audit.jsonl'
    def capture(_request):
        arrivals.append(records(audit_file))

    with TLSService(provider_directory(tmp_path), wire_headers=True,
                    on_request=capture) as server:
        install_github_routes(server)
        p = native_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, native_disclosure(), writes='deny') as case:
            # A useful read whose checked-fact lookup and final HTTP request
            # are two independently audited credential-bearing effects.
            reply = trace_of(case, tmp_path, server, 'pr.diff', arguments(),
                             effects(p, 'pr.diff', arguments(), PULL),
                             expected_result={'diff': DIFF},
                             provider_arrivals=arrivals, raw_guest=True)
            assert reply['result'] == {'diff': DIFF}
            # Malicious resource mismatch may spend a preflight, but cannot
            # authorize the final provider request or release any result.
            wrong = dict(PULL)
            wrong['head'] = dict(PULL['head'], repo={'full_name': 'attacker/repository'})
            server.routes[('GET', PULL_PATH)] = wrong
            failed = trace_of(case, tmp_path, server, 'pr.diff', arguments(),
                              [('preflight', effects(p, 'pr.diff', arguments(), PULL)[0][1])],
                              successful=False, provider_arrivals=arrivals,
                              raw_guest=True)
            assert failed['error']['code'] == 'resource_mismatch'
            # No provider or dispatch audit is allowed for unsupported and
            # post-renunciation guest requests.
            trace_of(case, tmp_path, server, 'fetch.url', {'url': 'https://evil.invalid'},
                     [], successful=False, provider_arrivals=arrivals,
                     raw_guest=True)
            assert case.invoke(verb='renounce')['renounced'] is True
            trace_of(case, tmp_path, server, 'pr.diff', arguments(),
                     [], successful=False, provider_arrivals=arrivals,
                     raw_guest=True)


def test_w6_arrival_oracle_rejects_reordered_or_postdated_dispatch_audit():
    """Fail on temporal mutants even if the final provider/audit sets agree."""
    declared = dict(method='GET', target='/v1/allowed', accept='application/json', body=None)
    dispatch = dict(event='dispatch', phase='final', request_digest='d' * 64,
                    route={'host':'api.example.org', 'port':443,
                           'method':'GET', 'path':'/v1/allowed'})
    completion = dict(event='completed', request_digest='d' * 64)
    provider = [dict(method='GET', target='/v1/allowed', body='', headers={
        'host': 'api.example.org:443', 'accept': 'application/json',
        'accept-encoding': 'identity', 'connection': 'close',
        'user-agent': 'aivm-secrets/1',
        'authorization': 'Bearer TEST_CREDENTIAL_123456',
    })]
    kwargs = dict(provider=provider, audit=[dispatch, completion],
                  reply={'version': 1, 'ok': True, 'result': {'id': 7}},
                  planned=[('final', declared)], host='api.example.org', port=443,
                  credential='TEST_CREDENTIAL_123456', expect_success=True)
    frame = codec.dumps(kwargs['reply']) + b'\n'
    assert_native_effect_trace(**kwargs, audit_at_provider=[[dispatch]], guest_frame=frame)
    for bad_frame in [frame[:-1], frame + frame, frame + b'garbage',
                      codec.dumps({'version': 1, 'ok': True, 'result': {'id': 8}}) + b'\n']:
        with pytest.raises(TraceMismatch):
            assert_native_effect_trace(**kwargs, audit_at_provider=[[dispatch]], guest_frame=bad_frame)
    for bad in [[], [[completion, dispatch]], [[completion]], [[dispatch, completion]],
                [[dict(dispatch, phase='preflight')]], [[dict(dispatch, request_digest='0' * 64)]]]:
        with pytest.raises(TraceMismatch):
            assert_native_effect_trace(**kwargs, audit_at_provider=bad)


def test_w6_checked_fact_refusal_emits_preflight_only(tmp_path):
    with TLSService(provider_directory(tmp_path), wire_headers=True) as server:
        install_github_routes(server)
        p = native_policy(tmp_path, server)
        wrong = dict(PULL)
        wrong['head'] = dict(PULL['head'], repo={'full_name': 'attacker/repository'})
        server.routes[('GET', PULL_PATH)] = wrong
        with ManifestCase(tmp_path, server, p, native_disclosure()) as case:
            response = trace_of(case, tmp_path, server, 'pr.diff', arguments(),
                                [('preflight', effects(p, 'pr.diff', arguments(), PULL)[0][1])],
                                successful=False)
            assert response['error']['code'] == 'resource_mismatch'
            assert len(server.seen()) == 1


@pytest.mark.parametrize('attack,status,headers', [
    ('redirect', 302, {'Location': 'https://attacker.invalid/steal'}),
    ('partial', 206, {}),
    ('wrong-content-type', 200, {'Content-Type': 'text/html'}),
    ('compressed', 200, {'Content-Encoding': 'gzip'}),
    ('conflicting-length', 200, {'Transfer-Encoding': 'chunked'}),
])
def test_w6_native_rejects_adversarial_http_without_public_release(
    tmp_path, attack, status, headers,
):
    with TLSService(provider_directory(tmp_path), host='api.example.org', wire_headers=True) as server:
        server.routes[('GET', '/v1/tickets/7')] = (
            lambda seen: (status, headers, b'{"id":7,"secret":"' + TOKEN.encode() + b'"}')
        )
        p = ticket_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, ticket_disclosure()) as case:
            reply = trace_of(case, tmp_path, server, 'ticket.view', {'ticket': 7},
                             effects(p, 'ticket.view', {'ticket': 7}, None), successful=False)
            assert reply['error']['code'] in {'upstream_error', 'upstream_response', 'upstream_rejected'}
            assert len(server.seen()) == 1, attack
            assert TOKEN not in json.dumps(reply)





@pytest.mark.parametrize('framing', [
    b'Connection: close\r\n',
    b'Content-Length: 8\r\nContent-Length: 8\r\n',
    b'Content-Length: 8\r\nTransfer-Encoding: chunked\r\n',
    b'Transfer-Encoding: gzip\r\n',
], ids=['unframed', 'duplicate-length', 'length-and-chunked', 'unsupported-transfer'])
def test_w6_native_rejects_ambiguous_success_framing(tmp_path, framing):
    """Real Rust TLS + concrete HTTP parser; provider sees only one call."""
    data = (b'8\r\n{"id":7}\r\n0\r\n\r\n'
            if b'Transfer-Encoding: chunked' in framing else b'{"id":7}')
    wire = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n' + framing + b'\r\n' + data
    with TLSService(provider_directory(tmp_path), host='api.example.org',
                    wire_headers=True) as server:
        server.routes[('GET', '/v1/tickets/7')] = RawHTTPResponse(wire)
        p = ticket_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, ticket_disclosure()) as case:
            reply = trace_of(case, tmp_path, server, 'ticket.view', {'ticket': 7},
                             effects(p, 'ticket.view', {'ticket': 7}, None),
                             successful=False)
            assert reply['error']['code'] == 'upstream_response'
            assert len(server.seen()) == 1
            assert TOKEN not in json.dumps(reply)




def test_w6_native_chunked_success_still_projects_only_selected_fields(tmp_path):
    """Positive witness using the same raw-response fixture as the denials."""
    body = b'{"id":7,"private":"discard this"}'
    wire = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
            b'Transfer-Encoding: chunked\r\n\r\n'
            + format(len(body), 'x').encode() + b'\r\n' + body + b'\r\n0\r\n\r\n')
    with TLSService(provider_directory(tmp_path), host='api.example.org',
                    wire_headers=True) as server:
        server.routes[('GET', '/v1/tickets/7')] = RawHTTPResponse(wire)
        p = ticket_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, ticket_disclosure()) as case:
            reply = trace_of(case, tmp_path, server, 'ticket.view', {'ticket': 7},
                             effects(p, 'ticket.view', {'ticket': 7}, None),
                             expected_result={'id': 7})
            assert reply['result'] == {'id': 7}
            assert len(server.seen()) == 1



def test_w6_native_write_wire_and_uncertain_provider_failure(tmp_path):
    """A credentialed write is never silently retried after upstream failure."""
    with TLSService(provider_directory(tmp_path), host='api.example.org', wire_headers=True) as server:
        server.routes[('PATCH', '/v1/tickets/7')] = {'id': 7, 'unselected': TOKEN}
        p = ticket_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, ticket_disclosure(), writes='allow') as case:
            args = {'ticket': 7, 'text': 'reviewed'}
            planned = effects(p, 'ticket.edit', args, None)
            result = trace_of(case, tmp_path, server, 'ticket.edit', args, planned, expected_result={'id': 7})
            assert result['result'] == {'id': 7}
            assert server.seen()[-1]['method'] == 'PATCH'
            server.routes[('PATCH', '/v1/tickets/7')] = (
                lambda seen: (422, {'Content-Type': 'application/json'},
                              b'{"error":"' + TOKEN.encode() + b'"}')
            )
            failed = trace_of(case, tmp_path, server, 'ticket.edit', args, planned,
                              successful=False)
            assert failed['error']['code'] == 'outcome_unknown'
            assert len(server.seen('PATCH')) == 2  # no automatic retry


def test_w6_native_credential_reflection_keeps_denial_public_and_audit_private(tmp_path):
    with TLSService(provider_directory(tmp_path), wire_headers=True) as server:
        install_github_routes(server)
        p = native_policy(tmp_path, server)
        base = server.routes[('GET', PULL_PATH)]
        def reflected(seen):
            status, headers, raw = base(seen)
            if seen['headers']['accept'] == 'application/vnd.github.diff':
                return status, {'Content-Type': 'text/plain'}, TOKEN.encode()
            return status, headers, raw
        server.routes[('GET', PULL_PATH)] = reflected
        with ManifestCase(tmp_path, server, p, native_disclosure()) as case:
            reply = trace_of(case, tmp_path, server, 'pr.diff', arguments(),
                             effects(p, 'pr.diff', arguments(), PULL), successful=False)
            assert reply['error']['code'] == 'upstream_response'
            assert TOKEN not in (tmp_path / 'provider-audit.jsonl').read_text()


@pytest.mark.parametrize('marker', ['$serde_json::private::Number', '$serde_json::private::RawValue'])
def test_w6_json_marker_object_is_not_a_guest_integer(tmp_path, marker):
    with TLSService(provider_directory(tmp_path), host='api.example.org', wire_headers=True) as server:
        server.routes[('GET', '/v1/tickets/7')] = {'id': 7}
        with ManifestCase(tmp_path, server) as case:
            reply = case.invoke(operation='ticket.view', arguments={'ticket': {marker: '7'}})
            assert reply['ok'] is False, reply
            assert reply['error']['code'] in {'denied', 'invalid_request'}
            assert server.seen() == []


@pytest.mark.parametrize('marker', ['$serde_json::private::Number', '$serde_json::private::RawValue'])
def test_w6_json_marker_object_cannot_satisfy_integer_disclosure(tmp_path, marker):
    with TLSService(provider_directory(tmp_path), host='api.example.org', wire_headers=True) as server:
        server.routes[('GET', '/v1/tickets/7')] = {'id': {marker: '7'}, 'secret': TOKEN}
        p = ticket_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p) as case:
            reply = trace_of(case, tmp_path, server, 'ticket.view', {'ticket': 7},
                             effects(p, 'ticket.view', {'ticket': 7}, None), successful=False)
            assert reply['error']['code'] == 'upstream_response'
            assert 'result' not in reply
            assert len(server.seen()) == 1
            assert TOKEN not in json.dumps(reply)
