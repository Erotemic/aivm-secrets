"""Finite, independently expected W4/W5 failure-path observations.

The expected public error class and sent-effect prefix are declared from the
host-controlled synthetic scenario *before* observing the Rust bridge. Neither
is derived from a guest error or from the network recorder. A successful oracle
check is one concrete I/O-to-abstract-event witness, not a universal native
refinement proof and not a claim about timing or transport packet boundaries.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.primitives import codec
from tests.secrets_w6_history import ReadObservation
from tests.secrets_w6_trace import TraceMismatch, assert_native_effect_trace

FailureClass = Literal[
    'http-4xx', 'http-other', 'bad-representation', 'disclosure-veto',
]
Phase = Literal['preflight', 'final']


@dataclass(frozen=True)
class FailureContract:
    """A host-specified failure and the prefix that actually reached provider I/O.

    This first slice intentionally excludes failures before an audited provider
    send. It also excludes authority changes, transport EOF/timeout behavior,
    writes, and any change to the abstract disclosure/reflection decisions.
    """

    cause: FailureClass
    phases: tuple[Phase, ...]

    @property
    def error_code(self) -> str:
        table = {
            'http-4xx': 'upstream_rejected',
            'http-other': 'upstream_error',
            'bad-representation': 'upstream_response',
            'disclosure-veto': 'upstream_response',
        }
        if self.cause not in table:
            raise TraceMismatch('unreviewed public failure cause')
        return table[self.cause]

    def validate(self) -> None:
        if self.phases not in (
            ('final',), ('preflight',), ('preflight', 'final'),
        ):
            raise TraceMismatch('unmodeled failed native read path')


@dataclass(frozen=True)
class FailureWitness:
    """A model-level description justified by one checked finite execution."""

    observed_events: tuple[str, ...]
    guest_frame: bytes
    public_code: str


def checked_failure_witness(
    *,
    observed: ReadObservation,
    contract: FailureContract,
    policy: dict[str, Any],
    operation: str,
    normalized_arguments: dict[str, Any],
    credential: str,
    host: str,
    port: int,
    sensitive: tuple[str, ...] = (),
    hidden_canaries: tuple[str, ...] = (),
) -> FailureWitness:
    """Refine a recorded native read failure to an explicit abstract prefix.

    Every provider send must correspond to an independently selected read
    effect, with an audit row present *at provider arrival*. There must be no
    completion audit, public result or metadata; the fixed public denial is
    a separate observable, and its code is declared by ``contract``.
    """
    contract.validate()
    actual_phases = tuple(phase for phase, _ in observed.plan)
    if actual_phases != contract.phases:
        raise TraceMismatch('observed read prefix differs from host failure contract')
    if any(effect.get('write') is not False for _, effect in observed.plan):
        raise TraceMismatch('write effect is outside failed native read profile')
    normalized = parse_policy(policy).parse_request({
        'operation': operation, 'arguments': normalized_arguments,
    }).to_dict()
    digest = codec.digest(normalized)
    assert_native_effect_trace(
        provider=observed.provider,
        audit=observed.audit,
        reply=observed.reply,
        planned=observed.plan,
        host=host,
        port=port,
        credential=credential,
        expect_success=False,
        expected_error_code=contract.error_code,
        expected_request_digest=digest,
        policy_headers=policy.get('headers', {}),
        sensitive=sensitive + hidden_canaries,
        audit_at_provider=observed.provider_arrivals,
        guest_frame=observed.frame,
        strict_audit_schema=True,
        expected_operation=operation,
    )
    for protected in (credential, *sensitive, *hidden_canaries):
        if protected.encode() in observed.frame:
            raise TraceMismatch('protected/private bytes in failed guest frame')
        if protected in codec.dumps(observed.audit).decode('utf-8'):
            raise TraceMismatch('protected/private field in failed host audit')

    # This is an *observational interpretation*, not a reconstruction of Rust
    # execution order within TLS. The W6 oracle checked causal audit snapshots
    # separately; no guest result/completion event may appear in this prefix.
    events = []
    for phase in contract.phases:
        events.extend((f'audit:{phase}', f'provider-send:{phase}'))
    events.append(f'guest-denied:{contract.error_code}')
    from tests.secrets_w6_composition import ReadContract, read_prefix
    normal = read_prefix(observed, ReadContract(
        'provider-denied', contract.phases, contract.phases, contract.error_code))
    if normal.events != tuple(events):
        raise TraceMismatch('failed-read interpreter does not refine normal form')
    return FailureWitness(normal.events, observed.frame, contract.error_code)


def assert_failed_reads_publicly_equivalent(
    *,
    left: ReadObservation,
    right: ReadObservation,
    left_contract: FailureContract,
    right_contract: FailureContract,
    policy: dict[str, Any],
    operation: str,
    normalized_arguments: dict[str, Any],
    credential: str,
    host: str,
    port: int,
    sensitive: tuple[str, ...] = (),
    hidden_canaries: tuple[str, ...] = (),
) -> tuple[FailureWitness, FailureWitness]:
    """Two private provider failures must have equal *approved* observations.

    The host has explicitly chosen the same public failure code and provider
    effect prefix. Without those premises a differing error class is a
    declassified result, not necessarily a noninterference violation. These
    observations intentionally do not include timing, packet sizes or closure.
    """
    if left_contract.phases != right_contract.phases:
        raise TraceMismatch('failure paths differ: not low-equivalent')
    if left_contract.error_code != right_contract.error_code:
        raise TraceMismatch('public denial classes differ: not low-equivalent')
    left_witness = checked_failure_witness(
        observed=left, contract=left_contract, policy=policy,
        operation=operation, normalized_arguments=normalized_arguments,
        credential=credential, host=host, port=port,
        sensitive=sensitive, hidden_canaries=hidden_canaries,
    )
    right_witness = checked_failure_witness(
        observed=right, contract=right_contract, policy=policy,
        operation=operation, normalized_arguments=normalized_arguments,
        credential=credential, host=host, port=port,
        sensitive=sensitive, hidden_canaries=hidden_canaries,
    )
    if left_witness.observed_events != right_witness.observed_events:
        raise TraceMismatch('abstract failure events differ')
    if left_witness.guest_frame != right_witness.guest_frame:
        raise TraceMismatch('failure guest frames differ despite equal public decisions')
    if codec.dumps(left.reply) != codec.dumps(right.reply):
        raise TraceMismatch('failure guest replies differ')
    return left_witness, right_witness
