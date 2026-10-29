"""Provider claims a surrogate may carry (spec section 4.4) and unverified
inspection, around the core codec (:mod:`.core.stateless_token`)."""
from __future__ import annotations

from typing import Any, Sequence

from .core import encoding as enc
from .core.stateless import Rejection
from .core.stateless_token import MAX_TOKEN, Informational, segments

MAX_UPSTREAM = 4096
DEFAULT_COPIED = ('aud', 'azp', 'client_id', 'exp', 'iat', 'iss', 'jti', 'nbf', 'scope', 'scp')


def _payload(token: bytes) -> dict:
    _, p, _ = segments(token)
    data = enc.from_b64url(p)
    if data is None:
        raise Rejection('malformed')
    try:
        value = enc.parse(data, MAX_TOKEN, 16)
    except enc.JsonError:
        raise Rejection('malformed') from None
    if not isinstance(value, dict):
        raise Rejection('malformed')
    return value


def informational(token: bytes) -> Informational:
    """Informational claims to carry across a renewal (after ``open``)."""
    payload = _payload(token)
    scope = payload.get('scope')
    upstream = payload.get('upstream')
    return Informational(scope if isinstance(scope, str) else None, upstream if isinstance(upstream, dict) else None)


def inspect(token: str) -> tuple[dict, dict]:
    """Header and payload **without verification**, for an agent to look at."""
    raw = token.encode('ascii', 'replace')
    h, _, _ = segments(raw)
    data = enc.from_b64url(h)
    if data is None:
        raise Rejection('malformed')
    try:
        head = enc.parse(data, 1024, 2)
    except enc.JsonError:
        raise Rejection('malformed') from None
    return head, _payload(raw)


class ClaimCopy:
    """Which provider claims a surrogate copies (spec section 4.4):
    ``'access'`` (default), ``'all'``, or an explicit tuple of names."""

    def __init__(self, policy: str | Sequence[str] = 'access'):
        if isinstance(policy, str) and policy not in ('access', 'all'):
            raise ValueError(policy)
        self.policy = policy if isinstance(policy, str) else tuple(policy)

    def allows(self, name: str) -> bool:
        if self.policy == 'access':
            return name in DEFAULT_COPIED
        if self.policy == 'all':
            return True
        return name in self.policy


def _copyable_scalar(value: Any) -> bool:
    if value is None or type(value) in (bool, int):
        return True
    return (isinstance(value, str) and not isinstance(value, enc.Number) and len(value) <= 1024
            and all(0x20 <= ord(c) <= 0x7E for c in value))


def _copyable(value: Any) -> bool:
    if isinstance(value, list):
        return len(value) <= 32 and all(_copyable_scalar(v) for v in value)
    return _copyable_scalar(value)


def _copyable_name(name: str) -> bool:
    return 1 <= len(name) <= 128 and all(0x21 <= ord(c) <= 0x7E and c not in '"\\' for c in name)


def copy_upstream(access_token: str, policy: ClaimCopy) -> dict | None:
    parts = access_token.split('.')
    if len(parts) != 3 or enc.from_b64url(parts[0]) is None or enc.from_b64url(parts[2]) is None:
        return None
    data = enc.from_b64url(parts[1])
    if data is None:
        return None
    try:
        payload = enc.parse(data, MAX_TOKEN, 16)
    except enc.JsonError:
        return None
    if not isinstance(payload, dict):
        return None
    copied = {k: v for k, v in payload.items() if _copyable_name(k) and _copyable(v) and policy.allows(k)}
    if len(enc.canonical(copied)) > MAX_UPSTREAM:
        return None
    return copied
