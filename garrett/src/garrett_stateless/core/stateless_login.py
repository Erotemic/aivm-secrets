"""The OAuth login: sealed login state, callback acceptance, exchange and
delivery (Rust ``stateless_login``, over ``oauth_login``).

Part of the Python reference: tested against the same vectors as the Rust
crate, not proved. No I/O, clock or randomness."""
from __future__ import annotations

import enum
from dataclasses import dataclass, replace

from .stateless import (
    MAX_TIME,
    Issued,
    IssuePolicy,
    Rejection,
    SurrogateGrant,
    SurrogateSealer,
    issue,
)

MAX_LOGIN = 600
DELIVERY_GRACE = 300

class Stage(enum.Enum):
    PENDING = 'pending'
    ACCEPTED = 'accepted'
    DENIED = 'denied'
    EXCHANGING = 'exchanging'
    COMPLETE = 'complete'
    UNCERTAIN = 'failed'


class LoginDenial(Exception):
    """``invalid``, ``expired`` or ``consumed``."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class LoginState:
    login: str
    provider: str
    certificate: str
    subject: str
    certificate_expires: int
    replica: str
    scope: str
    verifier: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class LoginPolicy:
    replica: str
    providers: tuple[str, ...]
    ttl: int = 600


@dataclass(frozen=True)
class Entry:
    login: str
    provider: str
    certificate: str
    subject: str
    certificate_expires: int
    issued_at: int
    expires_at: int
    stage: Stage = Stage.PENDING


def begin_login(policy: LoginPolicy, provider: str, peer: str, subject: str, certificate_expires: int,
                login: str, verifier: str, scope: str, now: int) -> LoginState:
    if not 1 <= policy.ttl <= MAX_LOGIN or not 0 <= now <= MAX_TIME - MAX_LOGIN:
        raise Rejection('bad_policy')
    if provider not in policy.providers:
        raise Rejection('unknown_provider')
    if certificate_expires <= now:
        raise Rejection('expired')
    return LoginState(login, provider, peer, subject, min(certificate_expires, MAX_TIME), policy.replica, scope,
                      verifier, now, now + policy.ttl)


def entry_of(state: LoginState) -> Entry:
    return Entry(state.login, state.provider, state.certificate, state.subject, state.certificate_expires,
                 state.issued_at, state.expires_at)


def _current(issued_at: int, expires_at: int, now: int) -> None:
    if not 0 <= issued_at <= 9223372036854775207:
        raise LoginDenial('invalid')
    if expires_at <= issued_at or expires_at > issued_at + 600:
        raise LoginDenial('invalid')
    if now < issued_at or now >= expires_at:
        raise LoginDenial('expired')


def same_login(policy: LoginPolicy, entry: Entry, state: LoginState) -> bool:
    return (state.replica == policy.replica and entry.login == state.login
            and entry.provider == state.provider and entry.certificate == state.certificate
            and entry.subject == state.subject and entry.certificate_expires == state.certificate_expires
            and entry.issued_at == state.issued_at and entry.expires_at == state.expires_at)


def accept_callback(policy: LoginPolicy, entry: Entry, state: LoginState, issuer_rule: str | None,
                    issuer: str | None, denied: bool, now: int) -> Stage:
    """``issuer_rule`` is the provider's RFC 9207 issuer (``None``: absent)."""
    if not same_login(policy, entry, state):
        raise LoginDenial('invalid')
    if entry.stage is not Stage.PENDING:
        raise LoginDenial('consumed')
    _current(entry.issued_at, entry.expires_at, now)
    if state.login != entry.login:
        raise LoginDenial('invalid')
    if issuer_rule is None:
        if issuer is not None:
            raise LoginDenial('invalid')
    elif issuer is None or issuer != issuer_rule:
        raise LoginDenial('invalid')
    return Stage.DENIED if denied else Stage.ACCEPTED


def begin_exchange(entry: Entry, now: int) -> Stage:
    if entry.stage is not Stage.ACCEPTED:
        raise LoginDenial('consumed')
    _current(entry.issued_at, entry.expires_at, now)
    return Stage.EXCHANGING


def finish(stage: Stage, installed: bool) -> Stage:
    if stage is not Stage.EXCHANGING:
        raise LoginDenial('consumed')
    return Stage.COMPLETE if installed else Stage.UNCERTAIN


def grant_of(entry: Entry, credential_expires: int) -> SurrogateGrant:
    return SurrogateGrant(entry.provider, entry.subject, entry.certificate, entry.certificate_expires,
                          credential_expires)


def complete(sealer: SurrogateSealer, policy: IssuePolicy, entry: Entry, credential: bytes,
             credential_expires: int, token_id: str, now: int, lifetime: int) -> Issued:
    if entry.stage is not Stage.EXCHANGING:
        raise Rejection('malformed')
    return issue(sealer, policy, grant_of(entry, credential_expires), credential, token_id, now, lifetime)


def deliver(entry: Entry, peer: str, now: int) -> str:
    """``pending``, ``deliver``, ``wrong_certificate``, ``denied``, ``failed`` or ``expired``."""
    if entry.certificate != peer:
        return 'wrong_certificate'
    if entry.expires_at > MAX_TIME - DELIVERY_GRACE or now >= entry.expires_at + DELIVERY_GRACE:
        return 'expired'
    if entry.stage is Stage.COMPLETE:
        return 'deliver'
    if entry.stage is Stage.DENIED:
        return 'denied'
    if entry.stage is Stage.UNCERTAIN:
        return 'failed'
    return 'expired' if now >= entry.expires_at else 'pending'


def with_stage(entry: Entry, stage: Stage) -> Entry:
    return replace(entry, stage=stage)


