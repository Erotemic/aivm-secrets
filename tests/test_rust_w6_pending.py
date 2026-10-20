"""Scoped native W6 evidence for audit-without-provider-emission windows.

These tests launch the real Rust bridge, a local HTTPS fixture and optional
independent Python coordinator authority. Native Rust authority parity is
covered in the separate coordinator test suite. No provider account or external
credentials are used. A recorded dispatch is *not* treated as a provider send.
"""
from __future__ import annotations

import base64
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.primitives import codec
from tests.secrets_github_scenario import PULL, install_github_routes
from tests.secrets_helpers import TOKEN, TLSService, make_certificates
from tests.secrets_w6_history import ReadObservation
from tests.secrets_w6_pending import PendingContract, checked_pending_witness
from tests.secrets_w6_trace import TraceMismatch, records, require
from tests.test_rust_coordination import CoordinatorCase
from tests.test_rust_garrett_manifest import (
    ManifestCase, policy as ticket_policy, disclosure as ticket_disclosure,
    provider_directory,
)
from tests.test_rust_w2_github_workflow import arguments, native_policy, native_disclosure
from tests.test_rust_w6_adapter import effects, native_guest_frame


def _session_prefix(root, token):
    """Validate the complete native bootstrap audit, then freeze its prefix.

    The manifest bridge records ``session_open`` followed by ``issued`` before
    announcing the bound surrogate. Both records are host-side security events;
    neither is a provider dispatch. Compare issuance with the JWT's *public*
    claims; this is a correspondence check, not signature verification.
    """
    rows = records(root / 'provider-audit.jsonl')
    events = [row.get('event') if type(row) is dict else '<not-object>'
              for row in rows]
    require(len(rows) == 2,
            f'expected session_open + issued before first request; got {events!r}')
    opening, issued = rows
    require(type(opening) is dict and set(opening) ==
            {'schema', 'event', 'profile', 'grant', 'policy'} and
            opening['schema'] == 1 and opening['event'] == 'session_open' and
            opening['profile'] == 'manifest-https-v1',
            'native session opening audit has an unreviewed shape')
    for name, width in (('grant', 32), ('policy', 64)):
        value = opening[name]
        require(type(value) is str and len(value) == width and
                all(char in '0123456789abcdef' for char in value),
                'native session opening has an invalid grant/policy identity')
    require(type(issued) is dict and set(issued) ==
            {'schema', 'event', 'grant', 'policy', 'identity'} and
            issued['schema'] == 1 and issued['event'] == 'issued' and
            issued['grant'] == opening['grant'] and
            issued['policy'] == opening['policy'],
            'native issuance audit is missing, reordered, or bound to another grant')
    # The live token is signed by Rust; this test only compares the observable
    # public claims with the audit, never opens/decrypts its protected `enc`.
    require(type(token) is str and token.count('.') == 2,
            'native surrogate token has an unexpected shape')
    try:
        payload = base64.urlsafe_b64decode(token.split('.')[1] + '===')
        claims = codec.loads(payload)
    except (ValueError, UnicodeError, SecretsError) as error:
        raise TraceMismatch('invalid public surrogate claims') from error
    public_fields = {'iss', 'aud', 'sub', 'jti', 'iat', 'exp', 'epoch', 'cnf'}
    require(type(claims) is dict and set(claims) == public_fields | {'enc'} and
            type(claims['enc']) is str and bool(claims['enc']),
            'native surrogate does not have the reviewed public claims')
    require(all(type(claims[name]) is str and bool(claims[name])
                for name in ('iss', 'aud', 'sub', 'jti')) and
            all(type(claims[name]) is int for name in ('iat', 'exp', 'epoch')) and
            type(claims['cnf']) is dict and set(claims['cnf']) == {'x5t#S256'} and
            type(claims['cnf']['x5t#S256']) is str and
            bool(claims['cnf']['x5t#S256']),
            'native surrogate public identity has unreviewed field types')
    identity = {name: claims[name] for name in public_fields}
    require(type(issued['identity']) is dict and set(issued['identity']) == public_fields and
            issued['identity'] == identity,
            'native issuance audit disagrees with the bound surrogate identity')
    # Freeze the entire validated prefix; the request oracle must not skip
    # arbitrary startup rows, or treat issuance as a provider dispatch.
    return (opening, issued)


def _observation(root, provider, *, plan, frame, reply, arrivals, startup):
    prefix = list(startup)
    require(len(prefix) == 2, 'invalid saved native session audit prefix')
    full_audit = records(root / 'provider-audit.jsonl')
    require(full_audit[:2] == prefix,
            'native session startup records were changed, removed, or reordered')
    audit = full_audit[2:]
    require(all(type(row) is dict and row.get('event') in {'dispatch', 'completed'}
                for row in audit),
            'unreviewed native audit event in request-scoped prefix')
    require(all(row.get('grant') == prefix[0]['grant'] and
                row.get('policy') == prefix[0]['policy'] for row in audit),
            'request audit does not belong to the opened grant/policy')
    require(all(row.get('identity') == prefix[1]['identity']
                for row in audit if row['event'] == 'dispatch'),
            'request dispatch identity differs from issued surrogate')
    arrivals_for_request = []
    for snapshot in arrivals:
        require(snapshot[:2] == prefix,
                'provider arrival lacks the validated session/issuance audit prefix')
        arrivals_for_request.append(snapshot[2:])
    return ReadObservation(
        provider=provider.seen(),
        audit=audit,
        reply=reply, frame=frame, plan=plan,
        provider_arrivals=arrivals_for_request,
    )


@pytest.mark.parametrize('shape', ['final-only', 'preflight-only'])
def test_native_untrusted_provider_ca_leaves_audited_but_unsent_read(tmp_path, shape):
    """A real TLS verification failure must not turn an audit into a send."""
    with TLSService(provider_directory(tmp_path), host='api.example.org',
                    wire_headers=True) as provider:
        other = tmp_path / 'untrusted-ca'
        other.mkdir(mode=0o700)
        provider.files['ca'] = make_certificates(other, 'api.example.org')['ca']
        if shape == 'final-only':
            operation, args = 'ticket.view', {'ticket': 7}
            p = ticket_policy(tmp_path, provider)
            disclosures = ticket_disclosure()
            plan = effects(p, operation, args, None)
        else:
            operation, args = 'pr.diff', arguments()
            p = native_policy(tmp_path, provider)
            disclosures = native_disclosure()
            plan = effects(p, operation, args, PULL)[:1]
        with ManifestCase(tmp_path, provider, p, disclosures) as case:
            startup = _session_prefix(tmp_path, case.token)
            reply, frame = native_guest_frame(case, operation=operation, arguments=args)
            assert reply['error']['code'] == 'unreachable', reply
            observation = _observation(tmp_path, provider, plan=plan, reply=reply,
                                       frame=frame, arrivals=[], startup=startup)
            witness = checked_pending_witness(
                observed=observation,
                contract=PendingContract(tuple(phase for phase, _ in plan), (), 'unreachable'),
                policy=p, operation=operation, normalized_arguments=args,
                credential=TOKEN, host=provider.host, port=provider.port,
                sensitive=(case.token,),
            )
            assert witness.events == (f'audit:{plan[0][0]}', 'guest-denied:unreachable')
            assert not provider.seen()


@pytest.mark.parametrize('shape', ['final-only', 'preflight-then-final'])
def test_native_late_remote_revocation_never_emits_pending_read(
    tmp_path, shape,
):
    """Revoke only after the audited phase reached provider TLS setup.

    The server's accept hook pauses *before* TLS handshake completion. The
    coordinator is independently committed to revoked while the Rust worker
    is blocked. No credential-bearing HTTP for the pending phase may arrive.
    """
    arrivals = []
    root = tmp_path / 'coord'
    with CoordinatorCase(root) as coord, TLSService(
        provider_directory(tmp_path), host='api.example.org', wire_headers=True,
        on_request=lambda _: arrivals.append(records(tmp_path / 'provider-audit.jsonl')),
    ) as provider:
        coord.operator.activate([coord.members[0][2]])
        if shape == 'final-only':
            operation, args = 'ticket.view', {'ticket': 7}
            p = ticket_policy(tmp_path, provider)
            disclosure = ticket_disclosure()
            checked_facts = None
            paused_accept = 1
        else:
            install_github_routes(provider)
            operation, args = 'pr.diff', arguments()
            p = native_policy(tmp_path, provider)
            disclosure = native_disclosure()
            checked_facts = PULL  # host's synthetic preflight facts
            paused_accept = 2
        plan = effects(p, operation, args, checked_facts)
        assert [phase for phase, _ in plan] == (
            ['final'] if shape == 'final-only' else ['preflight', 'final']
        )
        entered, resume = threading.Event(), threading.Event()
        original_accept = provider._server.get_request
        accepts = 0

        def gate_after_audit():
            nonlocal accepts
            accepts += 1
            if accepts == paused_accept:
                entered.set()
                if not resume.wait(timeout=8):
                    raise TimeoutError('test did not release provider TLS gate')
            return original_accept()

        provider._server.get_request = gate_after_audit
        options = dict(coordination_file=str(coord.member_file()))
        with ManifestCase(tmp_path, provider, p, disclosure, **options) as case:
            startup = _session_prefix(tmp_path, case.token)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(native_guest_frame, case, operation=operation,
                                      arguments=args)
                try:
                    assert entered.wait(timeout=5), 'native broker never reached TLS setup'
                    # The host has recorded its intent; the provider has not
                    # received HTTP for this pending phase.
                    prior = records(tmp_path / 'provider-audit.jsonl')
                    assert prior[:2] == list(startup)
                    assert [row['phase'] for row in prior[2:]] == [
                        phase for phase, _ in plan
                    ]
                    assert len(provider.seen()) == paused_accept - 1
                    coord.operator.revoke()
                finally:
                    resume.set()
                reply, frame = pending.result(timeout=12)
            assert reply['error']['code'] == 'revoked', reply
            observation = _observation(
                tmp_path, provider, plan=plan, frame=frame, reply=reply,
                arrivals=arrivals, startup=startup,
            )
            audited = tuple(phase for phase, _ in plan)
            sent = audited[:-1]
            witness = checked_pending_witness(
                observed=observation,
                contract=PendingContract(audited, sent, 'revoked'),
                policy=p, operation=operation, normalized_arguments=args,
                credential=TOKEN, host=provider.host, port=provider.port,
                sensitive=(case.token,), checked_facts=checked_facts,
            )
            assert witness.events[-1] == 'guest-denied:revoked'
            assert not any(r.get('event') == 'completed' for r in observation.audit)
            # Remote revocation also fences every subsequent request even
            # though the same live Rust broker/guest identity remain present.
            assert case.invoke(operation=operation, arguments=args)['error']['code'] == 'revoked'
            assert len(provider.seen()) == paused_accept - 1
            assert records(tmp_path / 'provider-audit.jsonl') == [*startup, *observation.audit], (
                'a rejected subsequent request unexpectedly altered the host audit'
            )
