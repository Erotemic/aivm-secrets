"""The surrogate token codec (spec sections 3-5) and the sealed login state
(section 8.2), mirroring Rust ``stateless_token``.

Ed25519 and AES-256-GCM are the only adapters (:class:`KeyMaterial`,
:class:`StateKey`); the application implements them. This module fixes every
byte they are given and every check made on what they return: which key a
token selects, which bytes are signed, which bytes are authenticated with the
credential, and which claims authorize. The caller supplies each fresh
nonce, so nothing here reads randomness.

Part of the Python reference: tested against the same vectors as the Rust
crate, not proved.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from . import encoding as enc
from .stateless import Rejection, SurrogateClaims, Verified
from .stateless_login import LoginState

TYP = 'garrett-stateless-v1+jwt'
MAX_TOKEN = 16384
NONCE = 12
TAG = 16
SIGNATURE = 64
CREDENTIAL_LABEL = b'garrett-stateless-v1/credential\0'
REQUIRED = frozenset({'aud', 'cnf', 'enc', 'exp', 'iat', 'iss', 'jti', 'prv', 'ren', 'sub'})
OPTIONAL = frozenset({'scope', 'upstream'})
STATE_PREFIX = 'gs1.'
MAX_STATE = 4096
LOGIN_LABEL = b'garrett-stateless-v1/login\0'


class KeyMaterial(Protocol):
    """One configured ``kid``: the issuer it signs for and its primitives."""

    kid: str
    issuer: str

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Ed25519: whether ``signature`` is valid for ``message``."""

    def open(self, nonce: bytes, aad: bytes, sealed: bytes) -> bytes | None:
        """AES-256-GCM: the plaintext, or ``None`` if authentication fails."""

    def sign(self, message: bytes) -> bytes | None:
        """Ed25519 signature, or ``None`` without a signing key."""

    def seal(self, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes | None:
        """AES-256-GCM: the ciphertext with its tag appended."""


class StateKey(Protocol):
    """The broker's AES-256-GCM login-state key."""

    def seal(self, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes | None: ...

    def open(self, nonce: bytes, aad: bytes, sealed: bytes) -> bytes | None: ...


@dataclass(frozen=True)
class Informational:
    """Claims that inform the agent but never authorize anything."""

    scope: str | None = None
    upstream: dict | None = None


def header(kid: str) -> dict:
    return {'alg': 'EdDSA', 'kid': kid, 'typ': TYP}


def public_payload(claims: SurrogateClaims, info: Informational) -> dict:
    if not (enc.is_text(claims.issuer) and enc.is_text(claims.audience) and enc.is_text(claims.subject)
            and enc.is_id(claims.token_id) and enc.is_provider(claims.provider)
            and enc.is_thumbprint(claims.certificate)):
        raise Rejection('malformed')
    payload: dict[str, Any] = {
        'iss': claims.issuer, 'aud': claims.audience, 'sub': claims.subject, 'jti': claims.token_id,
        'prv': claims.provider, 'cnf': {'x5t#S256': claims.certificate},
    }
    for name, value in (('iat', claims.issued_at), ('exp', claims.expires_at), ('ren', claims.renew_until)):
        if type(value) is not int or not 0 <= value <= enc.MAX_INTEGER:
            raise Rejection('malformed')
        payload[name] = value
    if info.scope is not None:
        if not enc.is_scope(info.scope):
            raise Rejection('malformed')
        payload['scope'] = info.scope
    if info.upstream is not None:
        payload['upstream'] = dict(info.upstream)
    return payload


def associated(header_bytes: bytes, public: bytes) -> bytes:
    return CREDENTIAL_LABEL + header_bytes + b'\0' + public


def seal_token(entry: KeyMaterial, info: Informational, claims: SurrogateClaims, credential: bytes,
               nonce: bytes) -> bytes:
    """Sign and seal a surrogate with one key entry and a fresh ``nonce``.
    The credential never occurs in the public part."""
    if not enc.is_credential(credential) or not enc.is_kid(entry.kid) or len(nonce) != NONCE:
        raise Rejection('invalid_credential')
    header_bytes = enc.canonical(header(entry.kid))
    payload = public_payload(claims, info)
    public = enc.canonical(payload)
    if credential in header_bytes or credential in public:
        raise Rejection('malformed')
    sealed = entry.seal(nonce, associated(header_bytes, public), credential)
    if sealed is None:
        raise Rejection('malformed')
    payload['enc'] = enc.b64url(nonce + sealed)
    body = enc.b64url(header_bytes) + '.' + enc.b64url(enc.canonical(payload))
    signature = entry.sign(body.encode('ascii'))
    if signature is None:
        raise Rejection('unknown_key')
    token = body + '.' + enc.b64url(signature)
    if len(token) > MAX_TOKEN:
        raise Rejection('malformed')
    return token.encode('ascii')


@dataclass
class TokenSealer:
    """``stateless.SurrogateSealer`` for one key entry, the informational
    claims, and a fresh nonce from the application's random source."""

    entry: KeyMaterial
    nonce: bytes
    info: Informational = field(default_factory=Informational)

    def seal(self, claims: SurrogateClaims, credential: bytes) -> bytes:
        return seal_token(self.entry, self.info, claims, credential, self.nonce)


def segments(token: bytes) -> tuple[str, str, str]:
    if len(token) > MAX_TOKEN or not token.isascii():
        raise Rejection('malformed')
    parts = token.decode('ascii').split('.')
    if len(parts) != 3:
        raise Rejection('malformed')
    return parts[0], parts[1], parts[2]


def header_kid(encoded: str) -> tuple[str, bytes]:
    data = enc.from_b64url(encoded)
    if data is None:
        raise Rejection('malformed')
    try:
        value = enc.parse(data, 1024, 2)
    except enc.JsonError:
        raise Rejection('malformed') from None
    kid = value.get('kid') if isinstance(value, dict) else None
    if not enc.is_kid(kid) or value != header(kid) or enc.canonical(value) != data:
        raise Rejection('malformed')
    return kid, data


def _string(mapping: dict, name: str, valid) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not valid(value):
        raise Rejection('malformed')
    return value


def _time(mapping: dict, name: str) -> int:
    value = mapping.get(name)
    if type(value) is not int or value < 0:
        raise Rejection('malformed')
    return value


@dataclass
class KeySet:
    """``stateless.SurrogateOpener`` over the configured key entries (any
    listed ``kid``)."""

    keys: Sequence[KeyMaterial]

    def verify(self, token: bytes) -> Verified:
        h, p, s = segments(token)
        kid, header_bytes = header_kid(h)
        index = next((i for i, e in enumerate(self.keys) if e.kid == kid), None)
        if index is None:
            raise Rejection('unknown_key')
        entry = self.keys[index]
        signature = enc.from_b64url(s)
        if signature is None or len(signature) != SIGNATURE:
            raise Rejection('malformed')
        if not entry.verify(token[:len(h) + 1 + len(p)], signature):
            raise Rejection('bad_signature')
        payload_bytes = enc.from_b64url(p)
        if payload_bytes is None:
            raise Rejection('malformed')
        try:
            payload = enc.parse(payload_bytes, MAX_TOKEN, 16)
            if not isinstance(payload, dict) or enc.canonical(payload) != payload_bytes:
                raise Rejection('malformed')
        except enc.JsonError:
            raise Rejection('malformed') from None
        if not REQUIRED <= set(payload) <= REQUIRED | OPTIONAL:
            raise Rejection('malformed')
        if 'scope' in payload and not enc.is_scope(payload['scope']):
            raise Rejection('malformed')
        if 'upstream' in payload and not isinstance(payload['upstream'], dict):
            raise Rejection('malformed')
        cnf = payload['cnf']
        if not isinstance(cnf, dict) or len(cnf) != 1:
            raise Rejection('malformed')
        claims = SurrogateClaims(
            issuer=_string(payload, 'iss', enc.is_text), audience=_string(payload, 'aud', enc.is_text),
            subject=_string(payload, 'sub', enc.is_text), token_id=_string(payload, 'jti', enc.is_id),
            provider=_string(payload, 'prv', enc.is_provider),
            certificate=_string(cnf, 'x5t#S256', enc.is_thumbprint),
            issued_at=_time(payload, 'iat'), expires_at=_time(payload, 'exp'), renew_until=_time(payload, 'ren'),
        )
        sealed_text = payload.pop('enc')
        sealed = enc.from_b64url(sealed_text) if isinstance(sealed_text, str) else None
        if sealed is None or len(sealed) < NONCE + TAG + 1:
            raise Rejection('malformed')
        return Verified(index, entry.issuer, claims, associated(header_bytes, enc.canonical(payload)), sealed)

    def unseal(self, verified: Verified) -> bytes:
        if not 0 <= verified.key < len(self.keys):
            raise Rejection('unknown_key')
        plain = self.keys[verified.key].open(verified.sealed[:NONCE], verified.aad, verified.sealed[NONCE:])
        if plain is None:
            raise Rejection('undecryptable')
        return plain


# --- the sealed login state (spec section 8.2) ------------------------------

def state_plaintext(state: LoginState) -> bytes:
    return enc.canonical({
        'cert_exp': min(state.certificate_expires, enc.MAX_INTEGER), 'cnf': state.certificate,
        'exp': state.expires_at, 'iat': state.issued_at, 'login': state.login, 'prv': state.provider,
        'rep': state.replica, 'scope': state.scope, 'sub': state.subject, 'verifier': state.verifier,
    })


def is_verifier(value) -> bool:
    return (isinstance(value, str) and 43 <= len(value) <= 128
            and all(c.isascii() and (c.isalnum() or c in '-._~') for c in value))


def state_valid(state: LoginState) -> bool:
    return (enc.is_thumbprint(state.certificate) and enc.is_id(state.login) and enc.is_provider(state.provider)
            and enc.is_kid(state.replica) and enc.is_scope(state.scope) and enc.is_text(state.subject)
            and is_verifier(state.verifier)
            and all(type(v) is int and 0 <= v <= enc.MAX_INTEGER
                    for v in (state.certificate_expires, state.issued_at, state.expires_at)))


def seal_plaintext(key: StateKey, plaintext: bytes, nonce: bytes) -> str:
    sealed = key.seal(nonce, LOGIN_LABEL, plaintext)
    if sealed is None or len(nonce) != NONCE:
        raise Rejection('malformed')
    out = STATE_PREFIX + enc.b64url(nonce + sealed)
    if len(out) > MAX_STATE:
        raise Rejection('malformed')
    return out


def seal_state(key: StateKey, state: LoginState, nonce: bytes) -> str:
    """Seal a login state under the broker's state key with a fresh ``nonce``."""
    if not state_valid(state):
        raise Rejection('malformed')
    return seal_plaintext(key, state_plaintext(state), nonce)


def open_state(key: StateKey, text: str) -> LoginState:
    if not isinstance(text, str) or len(text) > MAX_STATE or not text.startswith(STATE_PREFIX):
        raise Rejection('malformed')
    sealed = enc.from_b64url(text[len(STATE_PREFIX):])
    if sealed is None or len(sealed) < NONCE + TAG + 1:
        raise Rejection('malformed')
    plain = key.open(sealed[:NONCE], LOGIN_LABEL, sealed[NONCE:])
    if plain is None:
        raise Rejection('undecryptable')
    try:
        value = enc.parse(plain, MAX_STATE, 2)
        # Only the one canonical plaintext of a state is accepted.
        if enc.canonical(value) != plain:
            raise Rejection('malformed')
    except enc.JsonError:
        raise Rejection('malformed') from None
    if not isinstance(value, dict) or len(value) != 10:
        raise Rejection('malformed')

    def text_of(name, valid):
        item = value.get(name)
        if not isinstance(item, str) or not valid(item):
            raise Rejection('malformed')
        return item

    def number(name):
        item = value.get(name)
        if type(item) is not int or item < 0:
            raise Rejection('malformed')
        return item

    return LoginState(
        login=text_of('login', enc.is_id), provider=text_of('prv', enc.is_provider),
        certificate=text_of('cnf', enc.is_thumbprint), subject=text_of('sub', enc.is_text),
        certificate_expires=number('cert_exp'), replica=text_of('rep', enc.is_kid),
        scope=text_of('scope', enc.is_scope), verifier=text_of('verifier', is_verifier),
        issued_at=number('iat'), expires_at=number('exp'),
    )
