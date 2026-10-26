"""The sealed login state (spec section 8.2), PKCE, and the transient login
mailbox (section 9)."""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import encoding as enc
from .decisions import DELIVERY_GRACE, Entry, LoginState, Rejection

STATE_PREFIX = 'gs1.'
MAX_STATE = 4096
MAX_PENDING = 1024
LOGIN_LABEL = b'garrett-stateless-v1/login\0'


def seal_plaintext(state_key: bytes, plaintext: bytes, nonce: bytes) -> str:
    sealed = nonce + AESGCM(state_key).encrypt(nonce, plaintext, LOGIN_LABEL)
    out = STATE_PREFIX + enc.b64url(sealed)
    if len(out) > MAX_STATE:
        raise Rejection('malformed')
    return out


def state_plaintext(state: LoginState) -> bytes:
    return enc.canonical({
        'cert_exp': min(state.certificate_expires, enc.MAX_INTEGER), 'cnf': state.certificate,
        'exp': state.expires_at, 'iat': state.issued_at, 'login': state.login, 'prv': state.provider,
        'rep': state.replica, 'scope': state.scope, 'sub': state.subject, 'verifier': state.verifier,
    })


def seal_state(state_key: bytes, state: LoginState) -> str:
    return seal_plaintext(state_key, state_plaintext(state), os.urandom(12))


def _is_verifier(value) -> bool:
    return (isinstance(value, str) and 43 <= len(value) <= 128
            and all(c.isascii() and (c.isalnum() or c in '-._~') for c in value))


def open_state(state_key: bytes, text: str) -> LoginState:
    if not isinstance(text, str) or len(text) > MAX_STATE or not text.startswith(STATE_PREFIX):
        raise Rejection('malformed')
    sealed = enc.from_b64url(text[len(STATE_PREFIX):])
    if sealed is None or len(sealed) < 12 + 16 + 1:
        raise Rejection('malformed')
    try:
        plain = AESGCM(state_key).decrypt(sealed[:12], sealed[12:], LOGIN_LABEL)
    except InvalidTag:
        raise Rejection('undecryptable') from None
    try:
        value = enc.parse(plain, MAX_STATE, 2)
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
        scope=text_of('scope', enc.is_scope), verifier=text_of('verifier', _is_verifier),
        issued_at=number('iat'), expires_at=number('exp'),
    )


def pkce_verifier() -> str:
    return enc.b64url(os.urandom(32))


def pkce_challenge(verifier: str) -> str:
    return enc.b64url(hashlib.sha256(verifier.encode('ascii')).digest())


def confirmation(login: str) -> str:
    upper = login.upper()
    return f'{upper[:4]}-{upper[4:8]}'


@dataclass
class Slot:
    entry: Entry
    token: tuple[str, int, int] | None = None  # (surrogate, exp, ren)


class Mailbox:
    """The broker's only mutable state: logins in progress, in memory."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.slots: dict[str, Slot] = {}

    def prune(self, now: int) -> None:
        self.slots = {k: s for k, s in self.slots.items() if now < s.entry.expires_at + DELIVERY_GRACE}

    def insert(self, login: str, entry: Entry, now: int) -> None:
        self.prune(now)
        if len(self.slots) >= MAX_PENDING:
            raise Rejection('too_many_logins')
        if login in self.slots:
            raise Rejection('malformed')
        self.slots[login] = Slot(entry)
