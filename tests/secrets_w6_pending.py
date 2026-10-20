"""Independent finite witness for audited but *unsent* native manifest reads.

An audit records intent; it is not evidence that credentialed provider HTTP was
emitted. W6's normal observed-effect oracle demands one send for each dispatch,
so this module handles the important intermediate prefix explicitly. Every
sent phase is checked by that strict oracle. Exactly one final audit record is
permitted without a corresponding provider request, and that record is checked
against the host-compiled read effect and the canonical request identity.

This is not a formal proof of the temporal gap between the last fresh check
and a network syscall, nor a trusted Rust-to-Lean refinement certificate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.primitives import codec
from tests.secrets_w6_history import ReadObservation
from tests.secrets_w6_trace import TraceMismatch, assert_native_effect_trace, require
from tests.test_rust_garrett_manifest import reference_compile, reference_effect

Phase = Literal['preflight', 'final']


@dataclass(frozen=True)
class PendingContract:
    """Host-declared audited prefix, provider-received prefix, public denial.

    Only a single last un-emitted phase is allowed. This corresponds to the
    currently scoped sequential manifest request, *not* general concurrency or
    interrupted in-flight provider sends.
    """

    audited: tuple[Phase, ...]
    sent: tuple[Phase, ...]
    public_code: Literal['revoked', 'unreachable', 'expired', 'invalid_capability']

    def validate(self) -> None:
        require(self.audited in (('final',), ('preflight',), ('preflight', 'final')),
                'unreviewed audited-read phase sequence')
        require(self.sent == self.audited[:-1],
                'a pending read requires exactly one audited-but-unsent tail')
        require(self.public_code in {'revoked', 'unreachable', 'expired', 'invalid_capability'},
                'unreviewed pre-send denial class')


@dataclass(frozen=True)
class PendingWitness:
    """Concrete finite-prefix observation, after all independent checks."""

    events: tuple[str, ...]
    frame: bytes
    request_digest: str


def _audit_tail(row: dict[str, Any], *, phase: str, effect: dict[str, Any],
                operation: str, request_digest: str, host: str, port: int,
                previous: list[dict[str, Any]]) -> None:
    keys = {'schema', 'event', 'phase', 'grant', 'policy', 'identity',
            'operation', 'request_digest', 'route'}
    require(type(row) is dict and set(row) == keys and row['schema'] == 1,
            'pending dispatch audit has unreviewed schema/fields')
    require(row['event'] == 'dispatch' and row['phase'] == phase,
            'missing or wrong pending dispatch audit phase')
    require(row['operation'] == operation and row['request_digest'] == request_digest,
            'pending dispatch does not identify normalized host request')
    require(row['route'] == {
        'host': host, 'port': port, 'method': effect['method'],
        'path': effect['target'],
    }, 'pending dispatch is not the host-compiled route')
    for name, length in (('grant', 32), ('policy', 64)):
        value = row[name]
        require(type(value) is str and len(value) == length and
                all(c in '0123456789abcdef' for c in value),
                'invalid grant/policy identity in pending audit')
    identity = row['identity']
    require(type(identity) is dict and set(identity) ==
            {'iss', 'aud', 'sub', 'jti', 'iat', 'exp', 'epoch', 'cnf'} and
            type(identity['cnf']) is dict and
            set(identity['cnf']) == {'x5t#S256'},
            'invalid bound-client identity on pending audit')
    require(all(type(identity[name]) is str for name in
                ('iss', 'aud', 'sub', 'jti',)) and
            all(type(identity[name]) is int for name in ('iat', 'exp', 'epoch')) and
            type(identity['cnf']['x5t#S256']) is str,
            'invalid pending identity field types')
    if previous:
        first = previous[0]
        require(row['grant'] == first['grant'] and row['policy'] == first['policy'] and
                codec.dumps(row['identity']) == codec.dumps(first['identity']),
                'pending dispatch changed grant, policy or bound client')


def checked_pending_witness(*, observed: ReadObservation, contract: PendingContract,
                            policy: dict[str, Any], operation: str,
                            normalized_arguments: dict[str, Any], credential: str,
                            host: str, port: int, sensitive: tuple[str, ...] = (),
                            checked_facts: Any = None) -> PendingWitness:
    """Validate a real provider/audit/frame prefix against *declared* facts.

    The caller supplies the independently compiled audited plan. No phase or
    public error is inferred from the observed log or guest denial. We also
    verify the emitted prefix using the same strict W6 byte-level oracle as
    successful and provider-failed reads.
    """
    contract.validate()
    require(tuple(phase for phase, _ in observed.plan) == contract.audited,
            'audited plan differs from host pending-read contract')
    require(all(effect.get('write') is False for _, effect in observed.plan),
            'pending-read plan permits a write')
    require(len(observed.audit) == len(contract.audited),
            'unexpected number of pending read audit records')
    require(len(observed.provider) == len(contract.sent),
            'unauthorized or missing provider send in pending-read prefix')
    normalized = parse_policy(policy).parse_request({
        'operation': operation, 'arguments': normalized_arguments,
    }).to_dict()
    digest = codec.digest(normalized)
    # Independently derive exact effects from host policy, not from the
    # untrusted guest's frame, native audit rows, or network recorder. A final
    # effect after preflight depends on host-selected synthetic checked facts.
    if contract.audited == ('preflight',):
        parsed = parse_policy(policy)
        typed = parsed.parse_request({
            'operation': operation, 'arguments': normalized_arguments,
        })
        preflight = parsed.preflight(typed)
        require(preflight is not None, 'host policy has no claimed preflight effect')
        compiled_plan = [('preflight', reference_effect(preflight, False))]
    else:
        if contract.audited == ('preflight', 'final'):
            require(checked_facts is not None,
                    'two-phase pending proof needs declared synthetic checked facts')
        compiled = reference_compile(policy, {
            'operation': operation, 'arguments': normalized_arguments,
        }, checked_facts)
        require(compiled.get('ok') is True,
                'host policy did not compile pending effect plan')
        outcome = compiled['result']
        compiled_plan = [(phase, outcome[key]) for phase, key in (
            ('preflight', 'preflight'), ('final', 'effect'),
        ) if outcome[key] is not None]
    require(codec.dumps(compiled_plan) == codec.dumps(observed.plan),
            'pending audit plan differs from independently compiled host policy')
    sent_length = len(contract.sent)
    # This verifier compares exact provider request headers, route, body,
    # causal arrival snapshots, public error, and the single canonical frame.
    assert_native_effect_trace(
        provider=observed.provider,
        audit=observed.audit[:sent_length],
        reply=observed.reply,
        planned=observed.plan[:sent_length],
        host=host, port=port, credential=credential,
        expect_success=False, expected_error_code=contract.public_code,
        expected_request_digest=digest,
        policy_headers=policy.get('headers', {}),
        sensitive=sensitive, audit_at_provider=observed.provider_arrivals,
        guest_frame=observed.frame,
        strict_audit_schema=True, expected_operation=operation,
    )
    _audit_tail(
        observed.audit[-1], phase=contract.audited[-1],
        effect=observed.plan[-1][1], operation=operation,
        request_digest=digest, host=host, port=port,
        previous=observed.audit[:-1],
    )
    # The last audit MUST be absent from all earlier provider-arrival snapshots.
    # A preflight provider cannot observe a future final-effect audit.
    for prior in observed.provider_arrivals:
        require(len(prior) <= sent_length and observed.audit[-1] not in prior,
                'future pending audit was present at an earlier provider arrival')
    for protected in (credential, *sensitive):
        require(protected.encode() not in observed.frame and
                protected not in codec.dumps(observed.audit).decode('utf-8'),
                'private bytes appear in pending audit or guest denial')
    events: list[str] = []
    for index, phase in enumerate(contract.audited):
        events.append(f'audit:{phase}')
        if index < sent_length:
            events.append(f'provider-send:{phase}')
    events.append(f'guest-denied:{contract.public_code}')
    from tests.secrets_w6_composition import ReadContract, read_prefix
    normal = read_prefix(observed, ReadContract(
        'pending-denied', contract.audited, contract.sent, contract.public_code))
    if normal.events != tuple(events) or normal.request_digest != digest:
        raise TraceMismatch('pending-read interpreter does not refine normal form')
    return PendingWitness(normal.events, observed.frame, digest)


def assert_pending_publicly_equivalent(*, left: ReadObservation, right: ReadObservation,
                                       left_contract: PendingContract,
                                       right_contract: PendingContract,
                                       policy: dict[str, Any], operation: str,
                                       normalized_arguments: dict[str, Any],
                                       credential: str, host: str, port: int,
                                       sensitive: tuple[str, ...] = (),
                                       checked_facts: Any = None) -> tuple[PendingWitness, PendingWitness]:
    """Paired pending reads: equal declassified class and equal raw guest frame.

    Timing, TLS handshakes and packet lengths are explicitly outside this
    observational relation. Different public denial codes are NOT asserted to
    be noninterference violations: they are separate declassified outcomes.
    """
    if (left_contract.audited != right_contract.audited or
            left_contract.sent != right_contract.sent or
            left_contract.public_code != right_contract.public_code):
        raise TraceMismatch('pending executions do not share public failure class and phases')
    require([(p, codec.dumps(e)) for p, e in left.plan] ==
            [(p, codec.dumps(e)) for p, e in right.plan],
            'pending executions use different host-authorized read effects')
    expected = dict(policy=policy, operation=operation,
                    normalized_arguments=normalized_arguments,
                    credential=credential, host=host, port=port,
                    sensitive=sensitive, checked_facts=checked_facts)
    l = checked_pending_witness(observed=left, contract=left_contract, **expected)
    r = checked_pending_witness(observed=right, contract=right_contract, **expected)
    require(l.events == r.events and l.request_digest == r.request_digest,
            'public pending-read trace histories disagree')
    require(l.frame == r.frame and codec.dumps(left.reply) == codec.dumps(right.reply),
            'private setup diagnostics changed public pending-read denial')
    return l, r
