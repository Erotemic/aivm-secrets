"""Independent W6 observations of the native manifest HTTPS adapter.

This is a *test oracle*, not a formal Rust/Lean refinement proof. It compares
real client answers, actual provider requests, and durable host audit records
with a separately compiled host policy effect. A failure is evidence of an
adapter/model mismatch; a pass covers only the exercised finite scenarios.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class TraceMismatch(AssertionError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TraceMismatch(message)


def records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(row) for row in path.read_text().splitlines() if row]


def audit_since(path: Path, prior: int) -> list[dict[str, Any]]:
    result = records(path)
    require(len(result) >= prior, 'audit truncated')
    return result[prior:]


def assert_native_effect_trace(
    *,
    provider: list[dict[str, Any]],
    audit: list[dict[str, Any]],
    reply: dict[str, Any],
    planned: list[tuple[str, dict[str, Any]]],
    host: str,
    port: int,
    credential: str,
    expect_success: bool,
) -> None:
    """Check an independently declared one-request concrete trace.

    The chosen `planned` prefix explicitly describes the provider calls that
    were supposed to occur in *this scenario*. For failures it can be shorter
    than the total policy plan. A preceding durable dispatch record is checked
    for every observed provider send; no remote timing/linearization theorem is
    inferred from the collected records.
    """
    dispatches = [row for row in audit if row.get('event') == 'dispatch']
    completions = [row for row in audit if row.get('event') == 'completed']
    require(len(provider) == len(planned), 'unexpected/missing credentialed provider send')
    require(len(dispatches) == len(planned), 'provider dispatch/audit mismatch')
    require(len(completions) == int(expect_success), 'completion audit/guest release mismatch')
    require(reply.get('version') == 1, 'invalid guest version')
    require(reply.get('ok') is expect_success, 'guest reply success/denial mismatch')
    if expect_success:
        require('result' in reply and 'error' not in reply, 'unexpected success fields')
    else:
        require('error' in reply and 'result' not in reply, 'unexpected denial fields')
        require(set(reply['error']) == {'code', 'message'}, 'unreviewed error fields')
    for (phase, declared), record, actual in zip(planned, dispatches, provider):
        require(record.get('phase') == phase, 'wrong dispatch phase')
        require(record.get('event') == 'dispatch', 'missing dispatch audit')
        require(record.get('route') == {
            'host': host, 'port': port,
            'method': declared['method'], 'path': declared['target'],
        }, 'audit route differs from authorized effect')
        require(actual['method'] == declared['method'], 'method differs from policy')
        require(actual['target'] == declared['target'], 'target differs from policy')
        require(actual['headers'].get('host') == f'{host}:{port}', 'provider Host altered')
        require(actual['headers'].get('accept') == declared['accept'], 'Accept differs from policy')
        require(actual['headers'].get('accept-encoding') == 'identity', 'compressed upstream enabled')
        require(actual['headers'].get('connection') == 'close', 'unexpected persistent connection')
        require(actual['headers'].get('authorization') == 'Bearer ' + credential,
                'provider auth header differs from protected credential')
        body = declared.get('body')
        if body is None:
            require(actual['body'] == '', 'unexpected provider request body')
            require('content-length' not in actual['headers'], 'unexpected body length')
        else:
            require(json.loads(actual['body']) == body, 'provider body differs from policy')
            require(int(actual['headers']['content-length']) == len(actual['body'].encode()),
                    'incorrect wire body framing')
    dispatch_hashes = {row.get('request_digest') for row in dispatches}
    require(len(dispatch_hashes) <= 1, 'one request produced multiple audit identities')
    for event in completions:
        require(event.get('request_digest') in dispatch_hashes if dispatch_hashes else True,
                'completion refers to a different request')
    # The provider is the ONLY sink in this test allowed to carry the token.
    require(credential not in json.dumps(reply), 'credential exposed in guest reply')
    require(credential not in json.dumps(audit), 'credential exposed in host audit')
    require('authorization' not in json.dumps(audit).lower(), 'auth header exposed in audit')
