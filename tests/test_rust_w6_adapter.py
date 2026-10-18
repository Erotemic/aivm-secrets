"""W6: real native bridge/client, provider TLS and host audit observations.

Rust executables are required; no Python broker fallback. Test uses the
repository's synthetic GitHub policy and a local HTTPS test provider.
"""
from __future__ import annotations

import json

import pytest

from tests.secrets_github_scenario import (
    ALLOWED_PR, CHECKS_PATH, HEAD_SHA, PULL, PULL_PATH, install_github_routes,
)
from tests.secrets_helpers import TOKEN, TLSService
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


def trace_of(case, tmp_path, server, operation, args, planned, *, successful=True):
    requests_before, audit_before = snapshot(tmp_path, server)
    reply = case.invoke(operation=operation, arguments=args)
    assert_native_effect_trace(
        provider=server.seen()[requests_before:],
        audit=audit_since(tmp_path / 'provider-audit.jsonl', audit_before),
        reply=reply, planned=planned,
        host=server.host, port=server.port, credential=TOKEN,
        expect_success=successful,
    )
    return reply


def test_w6_reference_trace_oracle_rejects_bypass_and_leaks():
    """Runs without Rust: checks the oracle can detect meaningful mutations."""
    declared = dict(method='GET', target='/v1/allowed', accept='application/json', body=None)
    provider = [dict(method='GET', target='/v1/allowed', body='', headers={
        'host': 'api.example.org:443', 'accept': 'application/json',
        'accept-encoding': 'identity', 'connection': 'close',
        'authorization': 'Bearer TEST_CREDENTIAL_123456',
    })]
    audit = [dict(event='dispatch', phase='final', request_digest='digest', route={
        'host': 'api.example.org', 'port': 443, 'method': 'GET', 'path': '/v1/allowed',
    }), dict(event='completed', request_digest='digest')]
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


def test_w6_native_checked_request_trace_matches_policy_audit_and_tls(tmp_path, monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:1')
    with TLSService(provider_directory(tmp_path)) as server:
        install_github_routes(server)
        p = native_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, native_disclosure()) as case:
            view = trace_of(case, tmp_path, server, 'pr.view', arguments(),
                            effects(p, 'pr.view', arguments(), PULL))
            assert view['result'] == {
                'number': ALLOWED_PR, 'title': PULL['title'], 'headRefOid': HEAD_SHA,
            }
            diff = trace_of(case, tmp_path, server, 'pr.diff', arguments(),
                            effects(p, 'pr.diff', arguments(), PULL))
            assert 'diff' in diff['result']
            checks = trace_of(case, tmp_path, server, 'pr.checks', arguments(),
                              effects(p, 'pr.checks', arguments(), PULL))
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


def test_w6_checked_fact_refusal_emits_preflight_only(tmp_path):
    with TLSService(provider_directory(tmp_path)) as server:
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
    with TLSService(provider_directory(tmp_path), host='api.example.org') as server:
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



def test_w6_native_write_wire_and_uncertain_provider_failure(tmp_path):
    """A credentialed write is never silently retried after upstream failure."""
    with TLSService(provider_directory(tmp_path), host='api.example.org') as server:
        server.routes[('PATCH', '/v1/tickets/7')] = {'id': 7, 'unselected': TOKEN}
        p = ticket_policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, ticket_disclosure(), writes='allow') as case:
            args = {'ticket': 7, 'text': 'reviewed'}
            planned = effects(p, 'ticket.edit', args, None)
            result = trace_of(case, tmp_path, server, 'ticket.edit', args, planned)
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
    with TLSService(provider_directory(tmp_path)) as server:
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
