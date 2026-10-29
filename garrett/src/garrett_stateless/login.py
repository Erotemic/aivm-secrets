"""PKCE, the confirmation code, and the sealed login state (spec section 8.2)
under the broker's state key with a fresh nonce. The codec is
:mod:`.core.stateless_token`; the transient login mailbox (section 9) is
:mod:`.core.stateless_mailbox`."""
from __future__ import annotations

import hashlib
import os

from .core import encoding as enc
from .core import stateless_token
from .core.stateless_login import LoginState
from .keys import AesStateKey


def seal_state(state_key: bytes, state: LoginState) -> str:
    return stateless_token.seal_state(AesStateKey(state_key), state, os.urandom(stateless_token.NONCE))


def open_state(state_key: bytes, text: str) -> LoginState:
    return stateless_token.open_state(AesStateKey(state_key), text)


def pkce_verifier() -> str:
    return enc.b64url(os.urandom(32))


def pkce_challenge(verifier: str) -> str:
    return enc.b64url(hashlib.sha256(verifier.encode('ascii')).digest())


def confirmation(login: str) -> str:
    upper = login.upper()
    return f'{upper[:4]}-{upper[4:8]}'
