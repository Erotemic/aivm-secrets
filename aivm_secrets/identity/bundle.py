"""One private, atomically installed certificate/JWT snapshot for a guest.

Parsing checks consistency, not authenticity. The broker must still verify the
JWT signature, enrollment and lifetime against the actual mTLS peer on each call.
The key stays separately configured; this format does not rotate private keys.
"""
from __future__ import annotations

import base64
import ctypes
import fcntl
import hashlib
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import SecretsError
from ..host.files import _check_directory, _check_file, read_owned
from ..primitives import codec, grammar
from .garrett.claims import IdentityClaims
from .token import MAX_JWT_BYTES, _decode, _trusted_kid, certificate_thumbprint

MAX_BUNDLE = 262144
LOCK = '.bundle.lock'


@dataclass(frozen=True)
class GuestBundle:
    certificate: bytes
    capability: str = field(repr=False)
    certificate_sha256: str

    def encode(self) -> bytes:
        return codec.dumps(dict(schema=1, certificate=self.certificate.decode('ascii'),
                                capability=self.capability))


def pair(certificate: bytes, capability: str) -> GuestBundle:
    """Validate one leaf PEM and its unverified, canonical token binding."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise SecretsError('missing_crypto') from None
    try:
        if (type(certificate) is not bytes or not 1 <= len(certificate) <= 65536
                or not certificate.isascii()):
            raise ValueError('certificate')
        text = certificate.strip()
        begin, end = b'-----BEGIN CERTIFICATE-----', b'-----END CERTIFICATE-----'
        if not text.startswith(begin) or not text.endswith(end):
            raise ValueError('PEM')
        # Match the native PEM decoder's ASCII whitespace set. Vertical tab
        # is not part of that profile, even though bytes.split accepts it.
        body = bytes(c for c in text[len(begin):-len(end)] if c not in b' \t\r\n\f')
        der = base64.b64decode(body, validate=True)
        if base64.b64encode(der) != body:
            raise ValueError('base64')
        cert = x509.load_der_x509_certificate(der)
        if cert.public_bytes(serialization.Encoding.DER) != der:
            raise ValueError('DER')
        thumb = certificate_thumbprint(der)
        _trusted_kid(capability)
        header, payload, signature = capability.split('.')
        if len(_decode(signature, MAX_JWT_BYTES)) != 64:
            raise ValueError('signature shape')
        raw = _decode(payload, MAX_JWT_BYTES)
        claims = grammar.exact_keys(codec.loads(raw), frozenset({
            'iss', 'aud', 'sub', 'jti', 'iat', 'exp', 'epoch', 'cnf', 'enc',
        }), code='invalid_capability')
        if codec.dumps(claims) != raw:
            raise ValueError('canonical payload')
        if len(_decode(claims.pop('enc'), MAX_JWT_BYTES)) < 29:
            raise ValueError('encrypted claim')
        parsed = IdentityClaims.parse(claims)
        if parsed.to_dict()['cnf']['x5t#S256'] != thumb:
            raise ValueError('binding')
        return GuestBundle(cert.public_bytes(serialization.Encoding.PEM), capability, thumb)
    except (ValueError, TypeError, UnicodeError, SecretsError):
        raise SecretsError('invalid_capability') from None


def parse(data: bytes) -> GuestBundle:
    value = grammar.exact_keys(codec.loads(data, limit=MAX_BUNDLE,
                                           code='invalid_capability'),
                               frozenset({'schema', 'certificate', 'capability'}),
                               code='invalid_capability')
    if (type(value['schema']) is not int or value['schema'] != 1
            or type(value['certificate']) is not str):
        raise SecretsError('invalid_capability')
    try:
        return pair(value['certificate'].encode('ascii'), value['capability'])
    except UnicodeError:
        raise SecretsError('invalid_capability') from None


class _Directory:
    """No-symlink walk; keep all leaf operations on the held private parent."""
    def __init__(self, path: Path):
        self.path = Path(path)
        self.fd = -1
        self.lock_fd = -1
        if (not self.path.is_absolute() or '..' in self.path.parts
                or self.path.name in ('', '.', '..', LOCK)
                or self.path.name.startswith('.bundle-')
                or '\\' in self.path.name or '\x00' in str(self.path)):
            raise SecretsError('unsafe_file')

    def __enter__(self):
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            self.fd = os.open('/', flags)
            for part in self.path.parent.parts[1:]:
                _check_directory(os.fstat(self.fd), str(self.path.parent))
                next_fd = os.open(part, flags, dir_fd=self.fd)
                os.close(self.fd)
                self.fd = next_fd
            info = os.fstat(self.fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise SecretsError('unsafe_file')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.lock_fd >= 0:
            os.close(self.lock_fd)
            self.lock_fd = -1
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def read(self) -> bytes | None:
        try:
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as stream:
            _check_file(os.fstat(stream.fileno()), self.path, role='private')
            data = stream.read(MAX_BUNDLE + 1)
            if len(data) > MAX_BUNDLE:
                raise SecretsError('unsafe_file')
            return data

    def lock(self, *, exclusive: bool = True):
        flags = (os.O_RDWR if exclusive else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        try:
            self.lock_fd = os.open(LOCK, flags | (os.O_CREAT | os.O_EXCL if exclusive else 0), 0o600,
                                   dir_fd=self.fd)
            if exclusive:
                os.fsync(self.lock_fd)
                os.fsync(self.fd)
        except FileExistsError:
            self.lock_fd = os.open(LOCK, flags, dir_fd=self.fd)
        _check_file(os.fstat(self.lock_fd), self.path.parent / LOCK, role='private')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        a = os.fstat(self.lock_fd)
        b = os.stat(LOCK, dir_fd=self.fd, follow_symlinks=False)
        if (a.st_dev, a.st_ino, a.st_nlink) != (b.st_dev, b.st_ino, 1):
            raise SecretsError('unsafe_file')

    def stage(self, data: bytes) -> str:
        name = '.bundle-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return name

    def publish(self, staged: str, replace: bool):
        # Linux renameat2 gives the initial install the same no-replace rule
        # as Rust. An uncertain rename acknowledgement must never restore old.
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(self.fd, os.fsencode(staged), self.fd,
                  os.fsencode(self.path.name), 0 if replace else 1) != 0:
            raise SecretsError('outcome_unknown')
        os.fsync(self.fd)
        # The public pathname must still reach our held parent on success.
        with _Directory(self.path) as current:
            a, b = os.fstat(self.fd), os.fstat(current.fd)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise SecretsError('outcome_unknown')


def load(path: Path) -> GuestBundle:
    try:
        with _Directory(path) as directory:
            directory.lock(exclusive=False)
            data = directory.read()
            if data is None:
                raise SecretsError('unsafe_file')
            return parse(data)
    except OSError:
        raise SecretsError('unsafe_file') from None


def install(*, certificate: Path, jwt_file: Path, output: Path,
            expected_current: str | None = None) -> dict:
    """Explicit local CAS, independent of host renewal and guest key custody.

    Before publication fails: old pair remains. After publication starts: failure
    is uncertain; inspect the current digest rather than automatically retrying.
    All writers must use the lock; same-owner/root rollback is outside the model.
    """
    if expected_current is not None and (type(expected_current) is not str
            or len(expected_current) != 64
            or any(c not in '0123456789abcdef' for c in expected_current)):
        raise SecretsError('invalid_request')
    try:
        token = read_owned(jwt_file, private=True, limit=MAX_JWT_BYTES,
                           what='bound client token').decode('ascii').rstrip('\r\n')
        bundle = pair(read_owned(certificate, private=True, limit=65536,
                                 what='client certificate'), token)
    except UnicodeError:
        raise SecretsError('invalid_capability') from None
    publishing = False
    try:
        with _Directory(output) as directory:
            directory.lock()
            old = directory.read()
            if old is not None:
                parse(old)  # Never replace an arbitrary private file.
            observed = None if old is None else hashlib.sha256(old).hexdigest()
            if observed != expected_current:
                raise SecretsError('unsafe_file' if expected_current is None else 'denied')
            data = bundle.encode()
            staged = directory.stage(data)
            publishing = True
            directory.publish(staged, expected_current is not None)
    except (OSError, SecretsError) as error:
        if publishing:
            raise SecretsError('outcome_unknown') from None
        if isinstance(error, SecretsError):
            raise
        raise SecretsError('unsafe_file') from None
    return dict(path=str(output), digest=hashlib.sha256(data).hexdigest(),
                certificate_sha256=bundle.certificate_sha256)
