"""Borrowed-byte reflection decisions compared with Python's byte operations."""

import random

from tests.test_rust_garrett import executable, run


def test_literal_reflection_matches_python_for_binary_and_boundary_inputs():
    rng = random.Random(7009)
    cases = [
        (b"", b"", 0),
        (b"", b"", 1),
        (b"a", b"", 0),
        (b"a", b"", 1),
        (b"a", b"a", 0),
        (b"aaa", b"aa", 1),
        (b"aaa", b"aa", 2),
        (b"end-token", b"token", 4),
        (b"\x00\xff\x00", b"\xff\x00", 1),
        (b"\x00\xff\x00", b"\x00\xff\x00x", 0),
    ]
    for index in range(5000):
        value = rng.randbytes(rng.randrange(128))
        secret = rng.randbytes(rng.randrange(40))
        start = rng.randrange(len(value) + 3)
        if index % 3 == 0:
            a = rng.randrange(len(value) + 1)
            b = rng.randrange(a, len(value) + 1)
            secret = value[a:b]
            start = a
        cases.append((value, secret, start))
    rows = [
        dict(action="reflection", value_hex=v.hex(), secret_hex=s.hex(), start=i)
        for v, s, i in cases
    ]
    expected = [
        dict(
            ok=True,
            contains=bool(secret) and secret in value,
            matches_at=(
                start <= len(value)
                and start + len(secret) <= len(value)
                and value[start : start + len(secret)] == secret
            ),
        )
        for value, secret, start in cases
    ]
    assert (
        run(executable("AIVM_SECRETS_RUST_GARRETT_RUNNER"), rows, crypto=True)
        == expected
    )
