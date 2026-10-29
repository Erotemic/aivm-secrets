"""Surrogate claims, opening (verify, admit, decrypt), issuance and renewal
(Rust ``stateless``).

Part of the Python reference: tested against the same vectors as the Rust
crate, not proved. No I/O, clock or randomness."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

MAX_TIME = 2**53 - 1
MAX_LIFETIME = 86400
MAX_RENEW = 2592000
MAX_SKEW = 300


class Rejection(Exception):
    """A surrogate refused or not issued; ``code`` is the stable reason."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SurrogateClaims:
    """The authoritative claims (``iss``, ``aud``, ``sub``, ``jti``, ``prv``,
    ``cnf``, ``iat``, ``exp``, ``ren``); informational ones are not here."""

    issuer: str
    audience: str
    subject: str
    token_id: str
    provider: str
    certificate: str
    issued_at: int
    expires_at: int
    renew_until: int


@dataclass(frozen=True)
class Verified:
    key: int
    key_issuer: str
    claims: SurrogateClaims
    aad: bytes
    sealed: bytes


@dataclass(frozen=True)
class Acceptance:
    audiences: tuple[str, ...]
    providers: tuple[str, ...]
    max_lifetime: int = 3600
    skew: int = 60


class SurrogateOpener(Protocol):
    def verify(self, token: bytes) -> Verified: ...
    def unseal(self, verified: Verified) -> bytes: ...


class SurrogateSealer(Protocol):
    def seal(self, claims: SurrogateClaims, credential: bytes) -> bytes: ...


@dataclass(frozen=True)
class Opened:
    claims: SurrogateClaims
    credential: bytes


def valid_credential(credential: bytes) -> bool:
    return 1 <= len(credential) <= 4096 and all(0x21 <= b <= 0x7E for b in credential)


def acceptance_valid(acceptance: Acceptance) -> bool:
    return 1 <= acceptance.max_lifetime <= MAX_LIFETIME and 0 <= acceptance.skew <= MAX_SKEW


def lifetime_valid(claims: SurrogateClaims, max_lifetime: int) -> bool:
    return (0 <= claims.issued_at <= MAX_TIME
            and claims.expires_at > claims.issued_at
            and claims.expires_at - claims.issued_at <= max_lifetime
            and claims.renew_until >= claims.expires_at
            and claims.renew_until - claims.issued_at <= MAX_RENEW)


def admit(claims: SurrogateClaims, key_issuer: str, acceptance: Acceptance, peer: str, now: int) -> None:
    if not acceptance_valid(acceptance) or not 0 <= now <= MAX_TIME:
        raise Rejection('bad_policy')
    if claims.issuer != key_issuer:
        raise Rejection('wrong_issuer')
    if claims.audience not in acceptance.audiences:
        raise Rejection('wrong_audience')
    if claims.provider not in acceptance.providers:
        raise Rejection('unknown_provider')
    if not lifetime_valid(claims, acceptance.max_lifetime):
        raise Rejection('bad_lifetime')
    if now + acceptance.skew < claims.issued_at:
        raise Rejection('not_yet_valid')
    if now >= claims.expires_at:
        raise Rejection('expired')
    if claims.certificate != peer:
        raise Rejection('wrong_certificate')


def authenticate(opener: SurrogateOpener, token: bytes, acceptance: Acceptance, peer: str, now: int) -> Verified:
    """The first half of ``open``: verify, then admit, without decrypting."""
    verified = opener.verify(token)
    admit(verified.claims, verified.key_issuer, acceptance, peer, now)
    return verified


def decrypt(opener: SurrogateOpener, verified: Verified) -> Opened:
    """The second half of ``open``: unseal and check the credential."""
    credential = opener.unseal(verified)
    if not valid_credential(credential):
        raise Rejection('invalid_credential')
    return Opened(verified.claims, credential)


def open_surrogate(opener: SurrogateOpener, token: bytes, acceptance: Acceptance, peer: str, now: int) -> Opened:
    """Verify, then admit, then (only then) decrypt."""
    verified = opener.verify(token)
    admit(verified.claims, verified.key_issuer, acceptance, peer, now)
    credential = opener.unseal(verified)
    if not valid_credential(credential):
        raise Rejection('invalid_credential')
    return Opened(verified.claims, credential)


@dataclass(frozen=True)
class IssuePolicy:
    issuer: str
    audience: str
    providers: tuple[str, ...]
    max_lifetime: int = 3600
    max_renew: int = 604800


@dataclass(frozen=True)
class SurrogateGrant:
    provider: str
    subject: str
    certificate: str
    certificate_expires: int
    credential_expires: int = MAX_TIME


@dataclass(frozen=True)
class Window:
    issued_at: int
    expires_at: int
    renew_until: int


def issue_window(policy: IssuePolicy, grant: SurrogateGrant, now: int, lifetime: int) -> Window:
    if not 1 <= policy.max_lifetime <= MAX_LIFETIME or not 0 <= policy.max_renew <= MAX_RENEW:
        raise Rejection('bad_policy')
    if not 0 <= now <= MAX_TIME - MAX_RENEW:
        raise Rejection('bad_policy')
    if not 1 <= lifetime <= policy.max_lifetime:
        raise Rejection('bad_lifetime')
    cap = min(grant.certificate_expires, grant.credential_expires)
    renew_until = min(now + policy.max_renew, cap)
    expires_at = min(now + lifetime, renew_until)
    if expires_at <= now:
        raise Rejection('expired')
    return Window(now, expires_at, renew_until)


def credential_expiry(now: int, expires_in: int | None) -> int:
    if not 0 <= now <= MAX_TIME:
        raise Rejection('bad_policy')
    if expires_in is None:
        return MAX_TIME
    if not 1 <= expires_in <= MAX_TIME - now:
        raise Rejection('malformed')
    return now + expires_in


def claims_for(policy: IssuePolicy, grant: SurrogateGrant, token_id: str, now: int, lifetime: int) -> SurrogateClaims:
    if grant.provider not in policy.providers:
        raise Rejection('unknown_provider')
    window = issue_window(policy, grant, now, lifetime)
    return SurrogateClaims(policy.issuer, policy.audience, grant.subject, token_id, grant.provider,
                           grant.certificate, window.issued_at, window.expires_at, window.renew_until)


@dataclass(frozen=True)
class Issued:
    claims: SurrogateClaims
    token: bytes


def issue(sealer: SurrogateSealer, policy: IssuePolicy, grant: SurrogateGrant, credential: bytes,
          token_id: str, now: int, lifetime: int) -> Issued:
    if not valid_credential(credential):
        raise Rejection('invalid_credential')
    claims = claims_for(policy, grant, token_id, now, lifetime)
    return Issued(claims, sealer.seal(claims, credential))


def renewal_grant(claims: SurrogateClaims, certificate_expires: int) -> SurrogateGrant:
    return SurrogateGrant(claims.provider, claims.subject, claims.certificate, certificate_expires, claims.renew_until)


def renew(opener: SurrogateOpener, sealer: SurrogateSealer, acceptance: Acceptance, policy: IssuePolicy,
          token: bytes, peer: str, certificate_expires: int, token_id: str, now: int, lifetime: int) -> Issued:
    opened = open_surrogate(opener, token, acceptance, peer, now)
    grant = renewal_grant(opened.claims, certificate_expires)
    return issue(sealer, policy, grant, opened.credential, token_id, now, lifetime)


