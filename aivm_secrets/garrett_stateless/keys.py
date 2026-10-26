"""Key sets (spec section 3) and rotation (section 10)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import encoding as enc
from .files import read_private

BROKER_SCHEMA = 'garrett-stateless-v1/broker-keys'
PROXY_SCHEMA = 'garrett-stateless-v1/proxy-keys'
MAX_KEYS = 8


class KeyFileError(ValueError):
    """An invalid key file; the message names the field, never key bytes."""


@dataclass(frozen=True, repr=False)
class KeyEntry:
    kid: str
    issuer: str
    verify: bytes
    seal: bytes
    sign: bytes | None = None

    def __repr__(self) -> str:
        return f'KeyEntry(kid={self.kid!r}, issuer={self.issuer!r})'

    @property
    def signer(self) -> Ed25519PrivateKey | None:
        return None if self.sign is None else Ed25519PrivateKey.from_private_bytes(self.sign)

    def public(self) -> dict:
        return {'issuer': self.issuer, 'kid': self.kid, 'seal': enc.b64url(self.seal), 'verify': enc.b64url(self.verify)}


def _key32(value, name: str) -> bytes:
    data = enc.from_b64url(value) if isinstance(value, str) else None
    if data is None or len(data) != 32:
        raise KeyFileError(f'{name} must be 32 bytes of b64url')
    return data


def _public_of(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _entry(value, broker: bool) -> KeyEntry:
    names = {'issuer', 'kid', 'seal', 'sign' if broker else 'verify'}
    if not isinstance(value, dict) or set(value) != names:
        raise KeyFileError(f'key entry must have exactly {sorted(names)}')
    if not enc.is_kid(value['kid']) or not enc.is_text(value['issuer']):
        raise KeyFileError('invalid kid or issuer')
    seal = _key32(value['seal'], 'seal')
    if broker:
        seed = _key32(value['sign'], 'sign')
        return KeyEntry(value['kid'], value['issuer'], _public_of(seed), seal, seed)
    return KeyEntry(value['kid'], value['issuer'], _key32(value['verify'], 'verify'), seal)


def _entries(value, broker: bool) -> list[KeyEntry]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_KEYS:
        raise KeyFileError('between 1 and 8 keys')
    entries = [_entry(v, broker) for v in value]
    if len({e.kid for e in entries}) != len(entries):
        raise KeyFileError('duplicate kid')
    return entries


def _load(data: bytes, required: set[str], schema: str) -> dict:
    try:
        value = enc.parse(data, 65536, 8)
    except enc.JsonError:
        raise KeyFileError('key file is not strict JSON') from None
    if not isinstance(value, dict) or set(value) != required or value.get('schema') != schema:
        raise KeyFileError(f'unsupported key file (expected {schema})')
    return value


@dataclass
class ProxyKeys:
    """Verification and sealing keys; no signing seed."""

    entries: list[KeyEntry]

    @classmethod
    def parse(cls, data: bytes) -> 'ProxyKeys':
        value = _load(data, {'keys', 'schema'}, PROXY_SCHEMA)
        return cls(_entries(value['keys'], False))

    @classmethod
    def load(cls, path: Path) -> 'ProxyKeys':
        return cls.parse(read_private(Path(path), 65536))

    def to_json(self) -> bytes:
        return enc.canonical({'keys': [e.public() for e in self.entries], 'schema': PROXY_SCHEMA}) + b'\n'


@dataclass
class BrokerKeys:
    """Signing seeds, sealing keys, the active ``kid`` and the login-state key."""

    active: str
    entries: list[KeyEntry]
    state: bytes

    @classmethod
    def generate(cls, issuer: str, kid: str = 'k1') -> 'BrokerKeys':
        keys = cls('', [], os.urandom(32))
        keys.rotate(issuer, kid)
        return keys

    @classmethod
    def parse(cls, data: bytes) -> 'BrokerKeys':
        value = _load(data, {'active', 'keys', 'schema', 'state'}, BROKER_SCHEMA)
        entries = _entries(value['keys'], True)
        if not any(e.kid == value['active'] for e in entries):
            raise KeyFileError('active kid is not in the key set')
        return cls(value['active'], entries, _key32(value['state'], 'state'))

    @classmethod
    def load(cls, path: Path) -> 'BrokerKeys':
        return cls.parse(read_private(Path(path), 65536))

    def to_json(self) -> bytes:
        keys = [{'issuer': e.issuer, 'kid': e.kid, 'seal': enc.b64url(e.seal), 'sign': enc.b64url(e.sign)}
                for e in self.entries]
        return enc.canonical({'active': self.active, 'keys': keys, 'schema': BROKER_SCHEMA,
                              'state': enc.b64url(self.state)}) + b'\n'

    def rotate(self, issuer: str, kid: str) -> None:
        if not enc.is_kid(kid) or not enc.is_text(issuer):
            raise KeyFileError('invalid kid or issuer')
        if any(e.kid == kid for e in self.entries):
            raise KeyFileError('kid already exists')
        if len(self.entries) >= MAX_KEYS:
            raise KeyFileError('key set is full; retire a key first')
        seed = os.urandom(32)
        self.entries.append(KeyEntry(kid, issuer, _public_of(seed), os.urandom(32), seed))
        self.active = kid

    def retire(self, kid: str) -> None:
        if kid == self.active:
            raise KeyFileError('cannot retire the active kid')
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.kid != kid]
        if len(self.entries) == before:
            raise KeyFileError('unknown kid')

    def export_proxy(self) -> ProxyKeys:
        return ProxyKeys([KeyEntry(e.kid, e.issuer, e.verify, e.seal) for e in self.entries])

    def active_entry(self) -> KeyEntry:
        return next(e for e in self.entries if e.kid == self.active)
