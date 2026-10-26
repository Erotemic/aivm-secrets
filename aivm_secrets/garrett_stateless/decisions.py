"""The decisions of ``garrett-stateless-v1``, mirroring the extracted Rust
controllers ``stateless``, ``stateless_login`` and ``stateless_proxy`` one
function for one function.

This module is the Python reference; it is tested against the same
conformance vectors as the Rust controllers but is **not** the proved
code. It performs no I/O and reads no clock: every decision is a function
of its arguments, which is what makes proxies stateless.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from typing import Protocol

from ..proxy import http1, policy as proxy_policy

MAX_TIME = 2**53 - 1
MAX_LIFETIME = 86400
MAX_RENEW = 2592000
MAX_SKEW = 300
MAX_LOGIN = 600
DELIVERY_GRACE = 300


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


# --- login (stateless_login, over oauth_login) -------------------------------

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
    return LoginState(login, provider, peer, subject, certificate_expires, policy.replica, scope, verifier,
                      now, now + policy.ttl)


def entry_of(state: LoginState) -> Entry:
    return Entry(state.login, state.provider, state.certificate, state.issued_at, state.expires_at)


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


def grant_of(entry: Entry, state: LoginState, credential_expires: int) -> SurrogateGrant:
    return SurrogateGrant(entry.provider, state.subject, entry.certificate, state.certificate_expires, credential_expires)


def complete(sealer: SurrogateSealer, login_policy: LoginPolicy, policy: IssuePolicy, entry: Entry,
             state: LoginState, credential: bytes, credential_expires: int, token_id: str, now: int,
             lifetime: int) -> Issued:
    if entry.stage is not Stage.EXCHANGING or not same_login(login_policy, entry, state):
        raise Rejection('malformed')
    return issue(sealer, policy, grant_of(entry, state, credential_expires), credential, token_id, now, lifetime)


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


# --- proxy (stateless_proxy) -------------------------------------------------

@dataclass(frozen=True)
class Route:
    provider: str
    host: str
    authentication: str  # 'bearer' or 'api-key'
    deny: tuple[tuple[str, str], ...] = ()  # (method or '', path)


@dataclass(frozen=True)
class Served:
    reply: bytes
    keep: bool
    stage: str  # 'refused', 'failed' or 'completed'
    code: str
    status: int = 0


class Origin(Protocol):
    def rejected(self, code: str) -> None: ...
    def admitted(self, claims: SurrogateClaims, route: int) -> bool: ...
    def exchange(self, route: int, wire: bytes) -> bytes: ...  # raises http1.Refused(code)
    def completed(self, status: int) -> bool: ...


UNAUTHORIZED = (b'HTTP/1.1 401 Unauthorized\r\n'
                b'WWW-Authenticate: Bearer realm="garrett-stateless", error="invalid_token"\r\n'
                b'Content-Type: application/json\r\nContent-Length: 26\r\n'
                b'Connection: close\r\n\r\n{"error":"invalid_token"}\n')


def _scheme_is(value: bytes, prefix: bytes) -> bool:
    return len(value) > len(prefix) and value[:len(prefix)].lower() == prefix


_STD = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def _decode_base64(text: bytes) -> bytes | None:
    """Strict standard base64 with canonical padding (``proxy_connect``)."""
    import base64
    import binascii
    if len(text) % 4 or any(b not in _STD and b != ord('=') for b in text):
        return None
    try:
        data = base64.b64decode(text, validate=True)
    except binascii.Error:
        return None
    return data if base64.b64encode(data) == text else None


def surrogate_value(value: bytes) -> bytes | None:
    """``Bearer T``, ``token T`` or ``Basic base64(USER:T)``."""
    if _scheme_is(value, b'token '):
        return value[6:]
    if _scheme_is(value, b'basic '):
        decoded = _decode_base64(value[6:])
        if decoded is None or b':' not in decoded:
            return None
        return decoded.split(b':', 1)[1]
    if _scheme_is(value, b'bearer '):
        return value[7:]
    return None


def surrogate_of(fields: tuple[tuple[bytes, bytes], ...]) -> bytes | None:
    values = [v for k, v in fields if k.lower() == b'authorization']
    if len(values) != 1:
        return None
    return surrogate_value(values[0])


def route_of(routes: tuple[Route, ...], provider: str) -> int:
    for index, route in enumerate(routes):
        if route.provider == provider:
            return index
    return len(routes)


def stopped(code: str, stage: str) -> Served:
    return Served(http1.refusal(code), False, stage, code)


def unauthorized() -> Served:
    return Served(UNAUTHORIZED, False, 'refused', 'unauthenticated')


def encode_upstream(request: http1.Request, route: Route, credential: bytes) -> bytes:
    """``proxy_http::encode_upstream`` through the parity-tested Python policy."""
    scheme = 'bearer' if route.authentication == 'bearer' else 'x-api-key'
    origin = proxy_policy.Origin(host=route.host, address=route.host, port=443, ca_file='',
                                 authentication=scheme)
    rules = tuple(proxy_policy.Deny(method=(m.encode('ascii') or b'*'), prefix=p.encode('ascii'))
                  for m, p in route.deny)
    policy = proxy_policy.ProxyPolicy(profile='credential-substitution', origins={route.host: origin},
                                      deny=rules, request_body=1, response_body=1, lifetime_seconds=1)
    return proxy_policy.upstream_request(policy, origin, request, credential)


def release(raw: bytes, request: http1.Request, forms: list, limit: int) -> Served:
    head = request.method == b'HEAD'
    try:
        response = http1.parse_response(raw, method=request.method, body_limit=limit, complete=True)
    except http1.Refused as refused:
        return stopped('too_large' if refused.code == 'too_large' else 'outcome_unknown', 'failed')
    if response is None:
        return stopped('outcome_unknown', 'failed')
    try:
        out = proxy_policy.guest_response(response, forms, keep_alive=request.keep_alive, head=head)
    except http1.Refused:
        return stopped('reflected', 'failed')
    return Served(out, request.keep_alive, 'completed', 'outcome_unknown', response.status)


def serve(opener: SurrogateOpener, origin: Origin, request: http1.Request, routes: tuple[Route, ...],
          acceptance: Acceptance, peer: str, now: int, limit: int) -> Served:
    token = surrogate_of(request.fields)
    if token is None:
        origin.rejected('malformed')
        return unauthorized()
    try:
        opened = open_surrogate(opener, token, acceptance, peer, now)
    except Rejection as rejection:
        origin.rejected(rejection.code)
        return unauthorized()
    index = route_of(routes, opened.claims.provider)
    if index >= len(routes):
        return stopped('unknown_origin', 'refused')
    try:
        wire = encode_upstream(request, routes[index], opened.credential)
    except http1.Refused as refused:
        return stopped(refused.code, 'refused')
    if not origin.admitted(opened.claims, index):
        return stopped('internal_error', 'refused')
    forms = proxy_policy.reflection_forms(opened.credential)
    try:
        raw = origin.exchange(index, wire)
    except http1.Refused as refused:
        return stopped(refused.code, 'failed')
    served = release(raw, request, forms, limit)
    if served.stage == 'completed':
        return served if origin.completed(served.status) else stopped('outcome_unknown', 'failed')
    return served
