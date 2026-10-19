"""Independent paired-run observer for the scoped native manifest read profile.

Use host policy, host disclosure, and *synthetic provider fixture bodies* as
inputs. Never derive the expected projection from the guest's returned data.
This is bounded two-run evidence for W5, not a universal Rust-to-Lean theorem.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aivm_secrets.primitives import codec
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_w6_release import ReleaseMismatch, release
from tests.secrets_w6_trace import TraceMismatch, assert_native_effect_trace


@dataclass(frozen=True)
class ReadObservation:
    """One post-request slice of actual, separately recorded native effects."""

    provider: list[dict[str, Any]]
    audit: list[dict[str, Any]]
    reply: dict[str, Any]
    frame: bytes
    plan: list[tuple[str, dict[str, Any]]]
    provider_arrivals: list[list[dict[str, Any]]]


def assert_publicly_equivalent(
    *,
    policy: dict[str, Any],
    disclosure: dict[str, Any],
    operation: str,
    normalized_arguments: dict[str, Any],
    provider_left: Any,
    provider_right: Any,
    left: ReadObservation,
    right: ReadObservation,
    credential: str,
    host: str,
    port: int,
    sensitive: tuple[str, ...] = (),
    hidden_canaries: tuple[str, ...] = (),
) -> None:
    """Check two native executions with equal explicitly declassified facts.

    This does not assume that equal public requests imply equal observations.
    First calculate permitted release and metadata from each independent host
    fixture. Then require their equality, matching effect phases/identities,
    fixed public success envelopes and byte-identical guest TLS frames.

    A changed selected field, error decision, pagination count, or reflection
    decision is OUTSIDE the claim, rather than automatically labeled a leak.
    Timing, packet segmentation and the external filesystem are not modeled.
    """
    try:
        first_result, first_meta = release(
            policy, disclosure, operation, normalized_arguments,
            provider_left, credential=credential,
        )
        second_result, second_meta = release(
            policy, disclosure, operation, normalized_arguments,
            provider_right, credential=credential,
        )
    except ReleaseMismatch as exc:
        raise TraceMismatch(f'unapproved host release: {exc}') from exc

    def canonical(obj: Any) -> bytes:
        return codec.dumps(obj)

    if canonical(first_result) != canonical(second_result):
        raise TraceMismatch('selected host releases differ: pair not low-equivalent')
    if canonical(first_meta) != canonical(second_meta):
        raise TraceMismatch('public metadata differs: pair not low-equivalent')

    if [(phase, canonical(effect)) for phase, effect in left.plan] != [
        (phase, canonical(effect)) for phase, effect in right.plan
    ]:
        raise TraceMismatch('host effect plan differs between paired executions')
    phases = [phase for phase, _ in left.plan]
    if phases not in (['final'], ['preflight'], ['preflight', 'final']):
        raise TraceMismatch('unmodeled native manifest read phase sequence')
    if any(effect.get('write') is not False for _, effect in left.plan):
        raise TraceMismatch('paired native read experiment contains a write')

    normalized = parse_policy(policy).parse_request({
        'operation': operation, 'arguments': normalized_arguments,
    }).to_dict()
    expected_digest = codec.digest(normalized)

    for run in (left, right):
        assert_native_effect_trace(
            provider=run.provider,
            audit=run.audit,
            reply=run.reply,
            planned=run.plan,
            host=host,
            port=port,
            credential=credential,
            expect_success=True,
            policy_headers=policy.get('headers', {}),
            sensitive=sensitive + hidden_canaries,
            expected_result=first_result,
            expected_meta=first_meta,
            expected_request_digest=expected_digest,
            audit_at_provider=run.provider_arrivals,
            guest_frame=run.frame,
        )

    if left.frame != right.frame:
        raise TraceMismatch('guest-visible TLS frames differ despite agreed releases')
    if left.reply != right.reply:
        raise TraceMismatch('guest replies differ despite agreed releases')

    # The normalized audit request identity must agree; the native provider
    # response and its unselected private fields must never select the digest.
    def identities(run: ReadObservation) -> list[str]:
        return [row['request_digest'] for row in run.audit
                if row.get('event') == 'dispatch']

    if identities(left) != identities(right):
        raise TraceMismatch('host-normalized request identities differ')

    # The guest must not see the raw, differently valued provider canaries or
    # synthetic credentials. Provider request headers ARE allowed to contain
    # the credential; host audit records and guest replies are not.
    for value in (credential, *sensitive, *hidden_canaries):
        if value.encode() in left.frame or value.encode() in right.frame:
            raise TraceMismatch('protected or ignored data in guest TLS frame')
        if value in str(left.audit) or value in str(right.audit):
            raise TraceMismatch('protected or ignored data in host audit')
