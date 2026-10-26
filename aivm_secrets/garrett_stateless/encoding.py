"""b64url, strict JSON and the grammars of spec section 2.

The canonical JSON encoding is ``json.dumps(sort_keys=True,
separators=(',', ':'), ensure_ascii=True)``, byte-identical to the Rust
crate's for every value this profile emits.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

MAX_INTEGER = 2**53 - 1
_B64URL = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')


class JsonError(ValueError):
    """Input outside the strict JSON subset."""


class Number(str):
    """A non-integer (or out-of-range) number, kept as its text; never emitted."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def from_b64url(text: str) -> bytes | None:
    """Strict: no padding, alphabet only, canonical trailing bits."""
    if not isinstance(text, str) or len(text) % 4 == 1 or any(c not in _B64URL for c in text):
        return None
    data = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    return data if b64url(data) == text else None


def _reject_constant(name: str) -> Any:
    raise JsonError(name)


def _integer(text: str) -> Any:
    value = int(text)
    return value if -MAX_INTEGER <= value <= MAX_INTEGER else Number(text)


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise JsonError('duplicate key')
        out[key] = value
    return out


def _check(value: Any, level: int, depth: int) -> None:
    if isinstance(value, (dict, list)):
        if level >= depth:
            raise JsonError('too deep')
        items = value.items() if isinstance(value, dict) else enumerate(value)
        for key, item in items:
            if isinstance(key, str):
                key.encode('utf-8')
            _check(item, level + 1, depth)
    elif isinstance(value, str) and not isinstance(value, Number):
        value.encode('utf-8')  # a lone surrogate escape raises here


def parse(data: bytes, limit: int, depth: int) -> Any:
    """Parse at most ``limit`` bytes nested at most ``depth`` containers."""
    if len(data) > limit:
        raise JsonError('too large')
    try:
        text = data.decode('utf-8')
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=Number,
                           parse_int=_integer, parse_constant=_reject_constant)
        _check(value, 0, depth)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise JsonError(str(error)) from None
    return value


def _no_numbers(value: Any) -> None:
    if isinstance(value, Number):
        raise JsonError('non-integer number')
    if isinstance(value, dict):
        for item in value.values():
            _no_numbers(item)
    elif isinstance(value, list):
        for item in value:
            _no_numbers(item)


def canonical(value: Any) -> bytes:
    _no_numbers(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _printable_except_quote(value: str, low: int = 0x21) -> bool:
    return all(low <= ord(c) <= 0x7E and c not in '"\\' for c in value)


def is_text(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and _printable_except_quote(value)


def is_provider(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return False
    allowed = set('abcdefghijklmnopqrstuvwxyz0123456789')
    return value[0] in allowed and all(c in allowed or c in '._-' for c in value)


def is_kid(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 32 or not value.isascii():
        return False
    return value[0].isalnum() and all(c.isalnum() or c in '_-' for c in value)


def is_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 32 and all(c in '0123456789abcdef' for c in value)


def is_thumbprint(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 43:
        return False
    data = from_b64url(value)
    return data is not None and len(data) == 32


def is_credential(value: bytes) -> bool:
    return 1 <= len(value) <= 4096 and all(0x21 <= b <= 0x7E for b in value)


def is_scope(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 1024:
        return False
    return value == '' or all(token and _printable_except_quote(token) for token in value.split(' '))


def random_id() -> str:
    return secrets.token_bytes(16).hex()


def thumbprint(der: bytes) -> str:
    """The ``x5t#S256`` of a certificate DER."""
    return b64url(hashlib.sha256(der).digest())
