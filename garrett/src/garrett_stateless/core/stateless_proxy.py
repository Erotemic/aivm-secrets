"""The proxy's pure request decision and its action on it (Rust
``stateless_proxy``; spec section 11).

Part of the Python reference: tested against the same vectors as the Rust
crate, not proved. No I/O, clock or randomness."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Protocol

from . import proxy_http
from .proxy_http import Refused, Request
from .stateless import (
    Acceptance,
    Opened,
    Rejection,
    SurrogateClaims,
    SurrogateOpener,
    authenticate,
    decrypt,
)
from .stateless_policy import OperationPolicy, operation_of


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
    def exchange(self, route: int, wire: bytes) -> bytes: ...  # raises Refused(code)
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
    return Served(proxy_http.refusal(code), False, stage, code)


def unauthorized() -> Served:
    return Served(UNAUTHORIZED, False, 'refused', 'unauthenticated')


def encode_upstream(request: Request, route: Route, credential: bytes) -> bytes:
    """``proxy_http.encode_upstream`` for this route."""
    rules = tuple(proxy_http.DenyRule(m.encode('ascii'), p.encode('ascii')) for m, p in route.deny)
    scheme = 'bearer' if route.authentication == 'bearer' else 'x-api-key'
    return proxy_http.encode_upstream(request, route.host.encode('ascii'), rules, credential, scheme)


def release(raw: bytes, request: Request, forms: list, limit: int) -> Served:
    head = request.method == b'HEAD'
    try:
        response = proxy_http.parse_response(raw, method=request.method, body_limit=limit, complete=True)
    except Refused as refused:
        return stopped('too_large' if refused.code == 'too_large' else 'outcome_unknown', 'failed')
    if response is None:
        return stopped('outcome_unknown', 'failed')
    try:
        out = proxy_http.guest_response(response, forms, keep_alive=request.keep_alive, head=head)
    except Refused:
        return stopped('reflected', 'failed')
    return Served(out, request.keep_alive, 'completed', 'outcome_unknown', response.status)


@dataclass(frozen=True)
class Decision:
    """``stateless_proxy::Decision``: ``unauthorized`` (``rejection`` is
    ``None`` when no surrogate was presented), ``refused`` (``code``) or
    ``dispatch`` (``route``, the exact ``wire`` bytes and the ``opened``
    surrogate)."""
    kind: str
    rejection: str | None = None
    code: str | None = None
    route: int = 0
    wire: bytes = b''
    opened: Opened | None = None

    def __repr__(self) -> str:
        return f'Decision({self.kind!r}, route={self.route})'


def decide(opener: SurrogateOpener, policy: OperationPolicy, request: Request, routes: tuple[Route, ...],
           acceptance: Acceptance, peer: str, now: int) -> Decision:
    """The pure authorization decision for one request (``stateless_proxy::decide``):
    keys (through ``opener``), operation policy, routes, acceptance policy,
    peer and clock only. The policy is consulted before decryption."""
    token = surrogate_of(request.fields)
    if token is None:
        return Decision('unauthorized')
    try:
        verified = authenticate(opener, token, acceptance, peer, now)
    except Rejection as rejection:
        return Decision('unauthorized', rejection=rejection.code)
    index = route_of(routes, verified.claims.provider)
    if index >= len(routes):
        return Decision('refused', code='unknown_origin')
    if not policy.permits(verified.claims, operation_of(request)):
        return Decision('refused', code='denied')
    try:
        opened = decrypt(opener, verified)
    except Rejection as rejection:
        return Decision('unauthorized', rejection=rejection.code)
    try:
        wire = encode_upstream(request, routes[index], opened.credential)
    except Refused as refused:
        return Decision('refused', code=refused.code)
    return Decision('dispatch', route=index, wire=wire, opened=opened)


def serve(opener: SurrogateOpener, policy: OperationPolicy, origin: Origin, request: Request,
          routes: tuple[Route, ...], acceptance: Acceptance, peer: str, now: int, limit: int) -> Served:
    decision = decide(opener, policy, request, routes, acceptance, peer, now)
    if decision.kind == 'unauthorized':
        origin.rejected(decision.rejection or 'malformed')
        return unauthorized()
    if decision.kind == 'refused':
        return stopped(decision.code, 'refused')
    opened, index = decision.opened, decision.route
    if not origin.admitted(opened.claims, index):
        return stopped('internal_error', 'refused')
    forms = proxy_http.reflection_forms(opened.credential)
    try:
        raw = origin.exchange(index, decision.wire)
    except Refused as refused:
        return stopped(refused.code, 'failed')
    served = release(raw, request, forms, limit)
    if served.stage == 'completed':
        return served if origin.completed(served.status) else stopped('outcome_unknown', 'failed')
    return served
