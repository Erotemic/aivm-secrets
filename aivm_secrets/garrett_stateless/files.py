"""Bounded file reads; private files must not be readable by other users."""
from __future__ import annotations

import os
import stat
from pathlib import Path


def _read(path: Path, limit: int) -> bytes:
    with open(path, 'rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise OSError(f'{path}: too large')
    return data


def read_public(path: Path, limit: int = 1 << 20) -> bytes:
    return _read(Path(path), limit)


def read_private(path: Path, limit: int = 1 << 20) -> bytes:
    """A secret input (keys, credentials): refused if group or other can read it."""
    mode = os.stat(path).st_mode
    if os.name == 'posix' and stat.S_IMODE(mode) & 0o077:
        raise PermissionError(f'{path}: must not be accessible to group or others')
    return _read(Path(path), limit)


def write_private(path: Path, data: bytes) -> None:
    """Create a new owner-only file; never overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def replace_private(path: Path, data: bytes) -> None:
    temporary = Path(f'{path}.tmp-{os.urandom(8).hex()}')
    write_private(temporary, data)
    os.replace(temporary, path)
