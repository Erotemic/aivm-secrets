"""Targets the Python proxy accepts have the properties proved for Rust.

``proofs/GarrettProxyHttp.lean`` proves, for the extracted Rust
``check_target``: every position of an accepted target is visible ASCII other
than ``#``, ``\\`` and ``;`` with no refused escape starting there
(``check_target_plain``), and in the part before the first ``?`` every
``/``-closed segment is non-empty and not ``.`` or ``..`` while the last is not
``.`` or ``..`` (``check_target_segments``: ``InteriorOk``, ``FinalOk``). This
test transcribes those positional predicates and checks every target of up to
five bytes from a small alphabet that the Python reference accepts.
"""

from __future__ import annotations

from itertools import product

from aivm_secrets.proxy.http1 import Refused, check_target

HEX = b'0123456789abcdefABCDEF'
UNRESERVED = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'


def refused_escape(target: bytes, k: int) -> bool:
    """Rust ``bad_escape_at``: a ``%`` that is malformed or encodes an
    unreserved byte, ``/``, ``\\``, NUL or ``;``."""
    if target[k] != ord('%'):
        return False
    if len(target) - k < 3 or target[k + 1] not in HEX or target[k + 2] not in HEX:
        return True
    byte = int(target[k + 1:k + 3], 16)
    return byte in UNRESERVED or byte in b'/\;' or byte == 0


def plain_at(target: bytes, k: int) -> bool:
    byte = target[k]
    return 0x21 <= byte <= 0x7E and byte not in b'#\;' and not refused_escape(target, k)


def seg_ok(segment: bytes, last: bool) -> bool:
    return (segment != b'' or last) and segment not in (b'.', b'..')


def interior_and_final_ok(path: bytes) -> bool:
    """``InteriorOk`` and ``FinalOk``, stated by slash positions."""
    slashes = [i for i, byte in enumerate(path) if byte == ord('/')]
    for here, after in zip(slashes, slashes[1:]):
        if not seg_ok(path[here + 1:after], False):
            return False
    return not slashes or seg_ok(path[slashes[-1] + 1:], True)


def accepted(target: bytes) -> bool:
    try:
        check_target(target)
    except Refused:
        return False
    return True


def test_every_accepted_target_has_the_proved_properties():
    seen = 0
    for size in range(1, 6):
        for chars in product(b'a/.%2F?;', repeat=size):
            target = bytes(chars)
            if not accepted(target):
                continue
            seen += 1
            assert all(plain_at(target, k) for k in range(len(target))), target
            assert interior_and_final_ok(target.split(b'?', 1)[0]), target
    assert seen > 100


def test_dot_and_empty_segments_are_refused():
    for target in (b'/a//b', b'/a/./b', b'/a/../b', b'/.', b'/a/..', b'//'):
        assert not accepted(target), target
    for target in (b'/a/', b'/a/b', b'/a.b/..c', b'/a?x=/./'):
        assert accepted(target), target
