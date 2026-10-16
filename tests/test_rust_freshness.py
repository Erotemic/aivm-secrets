"""Scoped conformance for the Rust functions extracted into the Lean proofs.

This gate covers epochs, time validity and their composition. It deliberately
leaves the existing complete primitives-runner gate unchanged.
"""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import random
import sys

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.primitives import codec, epochs, validity
from tests.secrets_helpers import reply_while_open, typed, typed_replies

ROOT = Path(__file__).resolve().parents[1]
PYTHON = [sys.executable, '-m', 'aivm_secrets.primitives_runner']


@pytest.fixture(scope='session')
def freshness_runner() -> list[str]:
    selected = os.environ.get('AIVM_SECRETS_FRESHNESS_RUNNER')
    if selected:
        assert Path(selected).is_file(), 'configured freshness runner is missing'
        return [selected]
    pytest.skip('set AIVM_SECRETS_FRESHNESS_RUNNER to the built scoped Rust runner')


def line(primitive: str, **args: object) -> bytes:
    return codec.dumps({'version': 1, 'primitive': primitive, 'args': args}) + b'\n'


def compare(runner: list[str], payload: bytes) -> None:
    assert typed_replies(runner, payload) == typed_replies(PYTHON, payload)


@pytest.mark.parametrize('name', ['epochs', 'validity', 'runner'])
def test_frozen_freshness_vectors(freshness_runner: list[str], name: str) -> None:
    rows = [json.loads(row) for row in
            (ROOT / f'tests/secrets_vectors/primitives/{name}-v1.jsonl').read_text().splitlines()]
    payload = b''.join(codec.dumps(row['input']) + b'\n' for row in rows)
    expected = [typed(row['expected_result']) for row in rows]
    assert typed_replies(freshness_runner, payload) == expected
    assert typed_replies(PYTHON, payload) == expected


def test_epoch_boundaries_and_invalid_types(freshness_runner: list[str]) -> None:
    values = [-2**63, -1, 0, 1, 2, 2**31-2, 2**31-1, 2**31,
              2**63-2, 2**63-1, 2**63, 2**64, 10**400,
              True, False, None, 0.0, 1.0, '1', [], {}]
    payload = b''.join(
        line(primitive, **dict(zip(keys, pair)))
        for primitive, keys in [
            ('epochs.advance', ('current', 'maximum')),
            ('epochs.require_current', ('actual', 'expected')),
        ]
        for pair in itertools.product(values, repeat=2)
    )
    compare(freshness_runner, payload)


def test_validity_boundaries_and_invalid_types(freshness_runner: list[str]) -> None:
    values = [-2**63, -1, 0, 1, 2, 2**63-2, 2**63-1, 2**63,
              True, None, 0.0, '0']
    compare(freshness_runner, b''.join(
        line('validity.require_active', now=now, not_before=start, expires_at=end)
        for now, start, end in itertools.product(values, repeat=3)
    ))


def test_freshness_composes_python_epoch_and_time_checks(freshness_runner: list[str]) -> None:
    # Exhaust the small domain, then sample reproducibly around machine limits.
    cases = list(itertools.product(range(-1, 3), repeat=5))
    rng = random.Random(0xA17F)
    boundaries = [-2**63, -1, 0, 1, 2, 2**63-2, 2**63-1, 2**63,
                  True, False, None, 0.0, '0', [], {}]
    cases += [tuple(rng.choice(boundaries) for _ in range(5)) for _ in range(1000)]
    payload = bytearray()
    expected = []
    for actual, current, now, start, end in cases:
        payload.extend(line('freshness.require_fresh', actual=actual, expected=current,
                            now=now, not_before=start, expires_at=end))
        try:
            epochs.require_current(actual, current)
            validity.require_active(now, start, end)
        except SecretsError as error:
            expected.append(typed({'ok': False, 'code': error.code}))
        else:
            expected.append(typed({'ok': True, 'value': None}))
    assert typed({'ok': True, 'value': None}) in expected, 'positive witness missing'
    assert typed_replies(freshness_runner, bytes(payload)) == expected


def test_raw_json_and_bounded_stream_recovery(freshness_runner: list[str]) -> None:
    good = line('epochs.advance', current=1)
    exact = good[:-1] + b' ' * (65536-len(good)) + b'\n'
    raw = [
        good,
        b'{"version":1,"primitive":"epochs.advance","args":{"current":-0}}\n',
        b'{"version":1,"primitive":"epochs.advance","args":{"current":1e0}}\n',
        b'{"version":1,"primitive":"epochs.advance","args":{"current":1e999}}\n',
        good[:-2] + b',"version":1}\n',
        good.replace(b'"current":1', b'"current":0,"curr\\u0065nt":1'),
        good.replace(b'"current":1', b'"current":"\\ud800"'),
        good.replace(b'"current":1', b'"current":"\xff"'),
        good.replace(b'"current":1', b'"current":' + b'['*65 + b'0' + b']'*65),
        good.replace(b'"current":1', b'"current":' + b'['*62 + b'0' + b']'*62),
        good.replace(b'"current":1', b'"current":' + b'['*63 + b'0' + b']'*63),
        good.replace(b'"current":1', b'"current":' + b'1'*4300),
        good.replace(b'"current":1', b'"current":' + b'1'*4301),
        good.replace(b'"current":1', b'"current":{"unused":"\\ud800"}'),
        good.replace(b'"current":1', b'"current":{"unused":"\\ud83d\\ude00"}'),
        exact, b' ' + exact, b'[' + b'0,'*100000 + b'0]\n', good,
        b'\n', b'{\n', good[:-1] + b' {}\n', good[:-1],
    ]
    compare(freshness_runner, b''.join(raw))
    assert typed(codec.loads(reply_while_open(freshness_runner, good))) == typed(
        {'ok': True, 'value': 2})
