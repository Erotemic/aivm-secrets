"""The surrogate token codec (spec section 4): signing and sealing behind
``decisions.SurrogateSealer``, verifying and unsealing behind
``decisions.SurrogateOpener``."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import encoding as enc
from .decisions import Rejection, SurrogateClaims, Verified
from .keys import KeyEntry

TYP = 'garrett-stateless-v1+jwt'
MAX_TOKEN = 16384
MAX_UPSTREAM = 4096
CREDENTIAL_LABEL = b'garrett-stateless-v1/credential\0'
REQUIRED = frozenset({'aud', 'cnf', 'enc', 'exp', 'iat', 'iss', 'jti', 'prv', 'ren', 'sub'})
OPTIONAL = frozenset({'scope', 'upstream'})
DEFAULT_COPIED = ('aud', 'azp', 'client_id', 'exp', 'iat', 'iss', 'jti', 'nbf', 'scope', 'scp')


@dataclass(frozen=True)
class Informational:
    """Claims that inform the agent but never authorize anything."""

    scope: str | None = None
    upstream: dict | None = None


def header(kid: str) -> dict:
    return {'alg': 'EdDSA', 'kid': kid, 'typ': TYP}


def _public_payload(claims: SurrogateClaims, info: Informational) -> dict:
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


def _associated(header_bytes: bytes, public: bytes) -> bytes:
    return CREDENTIAL_LABEL + header_bytes + b'\0' + public


@dataclass
class Sealer:
    """Signs with one broker key entry; the controller chose every other claim."""

    entry: KeyEntry
    info: Informational = field(default_factory=Informational)

    def seal_with_nonce(self, claims: SurrogateClaims, credential: bytes, nonce: bytes) -> bytes:
        if not enc.is_credential(credential) or not enc.is_kid(self.entry.kid):
            raise Rejection('invalid_credential')
        header_bytes = enc.canonical(header(self.entry.kid))
        payload = _public_payload(claims, self.info)
        public = enc.canonical(payload)
        if credential in header_bytes or credential in public:
            # The credential never appears outside its sealed form.
            raise Rejection('malformed')
        sealed = AESGCM(self.entry.seal).encrypt(nonce, credential, _associated(header_bytes, public))
        payload['enc'] = enc.b64url(nonce + sealed)
        body = enc.b64url(header_bytes) + '.' + enc.b64url(enc.canonical(payload))
        if self.entry.signer is None:
            raise Rejection('unknown_key')
        token = body + '.' + enc.b64url(self.entry.signer.sign(body.encode('ascii')))
        if len(token) > MAX_TOKEN:
            raise Rejection('malformed')
        return token.encode('ascii')

    def seal(self, claims: SurrogateClaims, credential: bytes) -> bytes:
        return self.seal_with_nonce(claims, credential, os.urandom(12))


def _segments(token: bytes) -> tuple[str, str, str]:
    if len(token) > MAX_TOKEN or not token.isascii():
        raise Rejection('malformed')
    parts = token.decode('ascii').split('.')
    if len(parts) != 3:
        raise Rejection('malformed')
    return parts[0], parts[1], parts[2]


def _header_kid(encoded: str) -> tuple[str, bytes]:
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
class Opener:
    """Verifies against configured key entries (any listed ``kid``)."""

    keys: Sequence[KeyEntry]

    def verify(self, token: bytes) -> Verified:
        h, p, s = _segments(token)
        kid, header_bytes = _header_kid(h)
        index = next((i for i, e in enumerate(self.keys) if e.kid == kid), None)
        if index is None:
            raise Rejection('unknown_key')
        entry = self.keys[index]
        signature = enc.from_b64url(s)
        if signature is None or len(signature) != 64:
            raise Rejection('malformed')
        try:
            Ed25519PublicKey.from_public_bytes(entry.verify).verify(signature, token[:len(h) + 1 + len(p)])
        except InvalidSignature:
            raise Rejection('bad_signature') from None
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
        if sealed is None or len(sealed) < 12 + 16 + 1:
            raise Rejection('malformed')
        return Verified(index, entry.issuer, claims, _associated(header_bytes, enc.canonical(payload)), sealed)

    def unseal(self, verified: Verified) -> bytes:
        if not 0 <= verified.key < len(self.keys):
            raise Rejection('unknown_key')
        try:
            return AESGCM(self.keys[verified.key].seal).decrypt(verified.sealed[:12], verified.sealed[12:], verified.aad)
        except InvalidTag:
            raise Rejection('undecryptable') from None


def _payload(token: bytes) -> dict:
    _, p, _ = _segments(token)
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
    h, _, _ = _segments(raw)
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
