"""Sequential native-read trace normal form, AFTER independent W6 checks.

A verified policy/egress oracle is a *premise*, not a result of this module:
this grammar consumes the per-request audit, provider-arrival and guest
observations after `assert_native_effect_trace`, `checked_failure_witness`, or
`checked_pending_witness` has validated their host-authorized content.

The normal form and whole-session concatenation checks are independent of a
particular success/failure/pending test case. They do not prove that every
reachable Rust execution is observed, or that TCP/TLS writes are atomic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence

from aivm_secrets.primitives import codec
from tests.secrets_w6_history import ReadObservation
from tests.secrets_w6_trace import TraceMismatch, require

Phase = Literal['preflight', 'final']
Kind = Literal['released', 'provider-denied', 'pending-denied']
VALID_PHASES = (('final',), ('preflight',), ('preflight', 'final'))


@dataclass(frozen=True)
class ReadContract:
    """Host-declared public outcome and effect prefix, not observed guesses."""
    kind: Kind
    audited: tuple[Phase, ...]
    sent: tuple[Phase, ...]
    public_code: str | None = None

    def validate(self) -> None:
        require(self.audited in VALID_PHASES, 'unsupported manifest read phase order')
        require(self.sent == self.audited[:len(self.sent)],
                'provider sends are not a prefix of audited phases')
        if self.kind == 'released':
            require(self.sent == self.audited and self.public_code is None,
                    'released read must send every audited phase')
        elif self.kind == 'provider-denied':
            require(self.sent == self.audited and bool(self.public_code),
                    'provider denial must follow its audited provider prefix')
        elif self.kind == 'pending-denied':
            require(self.sent == self.audited[:-1] and bool(self.public_code),
                    'pending denial requires one final audited-but-unsent phase')
        else:
            raise TraceMismatch('unreviewed native read outcome')


@dataclass(frozen=True)
class ReadPrefix:
    """Normalized evidence, conditional on the preceding concrete oracle."""
    events: tuple[str, ...]
    audit: tuple[dict, ...]
    provider_arrivals: tuple[tuple[dict, ...], ...]
    frame: bytes
    request_digest: str
    kind: Kind


def read_prefix(observed: ReadObservation, contract: ReadContract) -> ReadPrefix:
    """Check one complete request's audit/send/release grammar and observation.

    This step deliberately does not authorize an effect or check provider wire
    bytes. The caller MUST first check the appropriate independent W6 oracle.
    """
    contract.validate()
    require(tuple(phase for phase, _ in observed.plan) == contract.audited,
            'audit phases differ from host-selected plan')
    require(all(effect.get('write') is False for _, effect in observed.plan),
            'write effect in the read-only trace language')
    expected_audit = ['dispatch'] * len(contract.audited)
    if contract.kind == 'released':
        expected_audit.append('completed')
    require([row.get('event') for row in observed.audit] == expected_audit,
            'read audit records are missing, reordered or extended')
    require(len(observed.provider) == len(contract.sent) and
            len(observed.provider_arrivals) == len(contract.sent),
            'provider arrivals do not match the public read prefix')
    digest = None
    for index, phase in enumerate(contract.audited):
        row = observed.audit[index]
        require(row.get('phase') == phase, 'wrong audited read phase')
        current = row.get('request_digest')
        require(type(current) is str and len(current) == 64 and
                all(ch in '0123456789abcdef' for ch in current),
                'missing/malformed normalized request digest')
        if digest is None:
            digest = current
        require(current == digest, 'request digest changed between phases')
    if contract.kind == 'released':
        require(observed.audit[-1].get('request_digest') == digest,
                'completion audit refers to a different normalized request')
    for index, snapshot in enumerate(observed.provider_arrivals):
        require(snapshot == observed.audit[:index + 1],
                'provider arrival lacks exact causal request audit prefix')
    require(type(observed.reply) is dict and
            observed.frame == codec.dumps(observed.reply) + b'\n',
            'guest frame differs from canonical single public reply')
    require(observed.reply.get('version') == 1, 'wrong public frame version')
    if contract.kind == 'released':
        require(observed.reply.get('ok') is True and
                set(observed.reply) in ({'version', 'ok', 'result'},
                                        {'version', 'ok', 'result', 'meta'}),
                'unreviewed successful release envelope')
    else:
        require(observed.reply.get('ok') is False and
                set(observed.reply) == {'version', 'ok', 'error'} and
                type(observed.reply['error']) is dict and
                set(observed.reply['error']) == {'code', 'message'} and
                observed.reply['error']['code'] == contract.public_code,
                'public denial differs from the declared host failure class')
    events: list[str] = []
    for i, phase in enumerate(contract.audited):
        events.append(f'audit:{phase}')
        if i < len(contract.sent):
            events.append(f'provider-send:{phase}')
    if contract.kind == 'released':
        events += ['audit:completed', 'guest-released']
    else:
        events.append(f'guest-denied:{contract.public_code}')
    return ReadPrefix(tuple(events), tuple(observed.audit),
                      tuple(tuple(row for row in snapshot)
                            for snapshot in observed.provider_arrivals),
                      observed.frame, digest or '', contract.kind)


@dataclass(frozen=True)
class ReadHistory:
    """A sequential native session, excluding *validated* issuance startup."""
    prefixes: tuple[ReadPrefix, ...]
    events: tuple[str, ...]
    frames: tuple[bytes, ...]


def sequential_history(*, prefixes: Sequence[ReadPrefix],
                       session_open_and_issued: Sequence[dict],
                       complete_host_audit: Sequence[dict],
                       provider_arrivals: Sequence[Sequence[dict]]) -> ReadHistory:
    """Bind request-local witnesses to ONE continuous native host audit log.

    Do not skip unknown startup, inter-request, or post-request records. The
    session/issuance pair is validated against public JWT claims by the caller
    (e.g. `_session_prefix`); here only its exact placement and session
    identity continuity are inspected. Each real provider-arrival snapshot
    must contain precisely the already completed request prefix and current
    dispatch, with no future audit record.
    """
    start = tuple(session_open_and_issued)
    require(len(start) == 2 and
            [row.get('event') for row in start] == ['session_open', 'issued'],
            'unreviewed native session startup events')
    grant, policy = start[0].get('grant'), start[0].get('policy')
    require(start[1].get('grant') == grant and start[1].get('policy') == policy,
            'issued grant/policy do not match opened session')
    identity = start[1].get('identity')
    require(type(identity) is dict, 'missing issued public identity')
    accumulated = list(start)
    seen_arrivals: list[list[dict]] = []
    events: list[str] = []
    frames: list[bytes] = []
    for prefix in prefixes:
        for row in prefix.audit:
            require(row.get('grant') == grant and row.get('policy') == policy,
                    'request audit switched grant or policy')
            if row.get('event') == 'dispatch':
                require(row.get('identity') == identity,
                        'read dispatch used a different issued identity')
        seen_arrivals.extend([accumulated + list(snapshot)
                              for snapshot in prefix.provider_arrivals])
        accumulated.extend(prefix.audit)
        events.extend(prefix.events)
        frames.append(prefix.frame)
    require(list(complete_host_audit) == accumulated,
            'native host audit has gaps, extra events, or changed records')
    require([list(arrival) for arrival in provider_arrivals] == seen_arrivals,
            'provider arrival differs from the global causal audit history')
    return ReadHistory(tuple(prefixes), tuple(events), tuple(frames))
