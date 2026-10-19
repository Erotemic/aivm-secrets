"""Independent W6 observations of the native manifest HTTPS adapter.

This is a *finite, process-observed test oracle*, not a transitive call-graph,
Rust/Lean refinement proof, or assurance about guest isolation. It compares
native client replies and actual provider wire data against independently
compiled host-policy effects and host audit records. In particular, it treats
all unapproved HTTP headers and duplicate wire headers as a failed check, not
as irrelevant network metadata.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aivm_secrets.kernel import codec


class TraceMismatch(AssertionError):
    pass


_UNSPECIFIED = object()


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


def _typed_json_body(raw: str) -> bytes:
    """Reject duplicate fields and compare typed JSON values, not Python ==.

    In Python, ``True == 1``; a JSON wire oracle must distinguish them. A
    native request with duplicate JSON object keys must also be rejected even
    if its last value happens to agree with the planned request.
    """
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON request key')
            result[key] = value
        return result

    try:
        return codec.dumps(json.loads(raw, object_pairs_hook=object_pairs,
                                      parse_constant=lambda value: require(False, 'nonfinite JSON')))
    except (ValueError, TypeError, RecursionError) as exc:
        raise TraceMismatch('invalid JSON request body') from exc


def _checked_policy_headers(headers: dict[str, str]) -> dict[str, str]:
    result = {}
    for name, value in headers.items():
        require(type(name) is str and type(value) is str, 'non-text policy header')
        lower = name.lower()
        require(lower not in result, 'casefold-duplicate approved policy header')
        require(lower not in {
            'host', 'authorization', 'x-api-key', 'accept', 'accept-encoding',
            'connection', 'user-agent', 'content-type', 'content-length',
            'transfer-encoding', 'proxy-authorization', 'cookie',
        }, 'policy attempts to override a protocol header')
        result[lower] = value
    return result


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
    policy_headers: dict[str, str] | None = None,
    authentication: str = 'bearer',
    sensitive: tuple[str, ...] = (),
    expected_result: Any = _UNSPECIFIED,
    expected_meta: Any = None,
) -> None:
    """Check a complete observed prefix for one guest request.

    ``planned`` is the independently selected authorized provider-call prefix
    for this scenario. Denied operations have an empty plan, while a failed
    checked-fact operation may have preflight only. ``policy_headers`` come
    from the host policy, **not** from the observed provider request.

    This checks the recorded request bytes against the declared effect and
    audit event; it does not infer temporal durability or transitive mediation
    merely because the observations agree.
    """
    approved_headers = _checked_policy_headers(policy_headers or {})
    require(authentication in {'bearer', 'x-api-key'}, 'unknown authentication mode')
    dispatches = [row for row in audit if row.get('event') == 'dispatch']
    completions = [row for row in audit if row.get('event') == 'completed']
    require(len(provider) == len(planned), 'unexpected/missing credentialed provider send')
    require(len(dispatches) == len(planned), 'provider dispatch/audit mismatch')
    require(len(completions) == int(expect_success), 'completion audit/guest release mismatch')
    require(reply.get('version') == 1, 'invalid guest version')
    require(reply.get('ok') is expect_success, 'guest reply success/denial mismatch')
    if expect_success:
        require(set(reply) in ({'version', 'ok', 'result'},
                               {'version', 'ok', 'result', 'meta'}),
                'unexpected public success fields')
        if expected_result is not _UNSPECIFIED:
            require(codec.dumps(reply['result']) == codec.dumps(expected_result),
                    'released fields differ from approved selected result')
        if expected_meta is not _UNSPECIFIED:
            require(codec.dumps(reply.get('meta')) == codec.dumps(expected_meta),
                    'released metadata differs from approved public metadata')
    else:
        require(set(reply) == {'version', 'ok', 'error'}, 'unexpected public denial fields')
        require(type(reply['error']) is dict and set(reply['error']) == {'code', 'message'},
                'unreviewed error fields')
    for (phase, declared), record, actual in zip(planned, dispatches, provider):
        require(record.get('phase') == phase, 'wrong dispatch phase')
        require(record.get('event') == 'dispatch', 'missing dispatch audit')
        require(record.get('route') == {
            'host': host, 'port': port,
            'method': declared['method'], 'path': declared['target'],
        }, 'audit route differs from authorized effect')
        require(actual['method'] == declared['method'], 'method differs from policy')
        require(actual['target'] == declared['target'], 'target differs from policy')
        require(actual.get('request_version', 'HTTP/1.1') == 'HTTP/1.1',
                'provider request was not HTTP/1.1')
        body = declared.get('body')
        expected_headers = {
            'host': f'{host}:{port}',
            'accept': declared['accept'],
            'accept-encoding': 'identity',
            'user-agent': 'aivm-secrets/1',
            'connection': 'close',
            **approved_headers,
        }
        auth_name = 'authorization' if authentication == 'bearer' else 'x-api-key'
        expected_headers[auth_name] = ('Bearer ' + credential
                                       if authentication == 'bearer' else credential)
        if body is not None:
            expected_headers['content-type'] = 'application/json'
            # Canonical encoding is the policy-compiled, typed payload length.
            # Bytes remain checked below, so this cannot authorize an extra body.
            expected_headers['content-length'] = str(len(actual['body'].encode()))
        require(actual['headers'] == expected_headers,
                'provider headers differ from host-authorized complete set')
        if 'header_pairs' in actual:
            pairs = actual['header_pairs']
            require(len(pairs) == len(expected_headers), 'duplicate/extra wire header')
            require(len({name.lower() for name, _ in pairs}) == len(pairs),
                    'duplicate case-insensitive wire header')
            require({name.lower(): value for name, value in pairs} == expected_headers,
                    'wire headers differ from host-authorized complete set')
        if body is None:
            require(actual['body'] == '', 'unexpected provider request body')
        else:
            require(_typed_json_body(actual['body']) == codec.dumps(body),
                    'provider JSON body differs from typed policy effect')
    # An empty-plan successful returns-check may still record completion, but
    # every observed dispatch in a nonempty plan has one same-request digest.
    hashes = [row.get('request_digest') for row in dispatches]
    if hashes:
        require(all(type(value) is str and len(value) == 64 and
                    all(ch in '0123456789abcdef' for ch in value)
                    for value in hashes), 'missing/malformed request identity')
        require(len(set(hashes)) == 1, 'one request produced multiple audit identities')
    for event in completions:
        if hashes:
            require(event.get('request_digest') == hashes[0],
                    'completion refers to a different request')
    # The provider authentication field is the ONLY tested release channel
    # allowed to carry a protected credential. Other sensitive values, such
    # as the surrogate JWT, must not be reflected through audit or replies.
    for protected in (credential, *sensitive):
        require(protected not in json.dumps(reply), 'protected value in guest reply')
        require(protected not in json.dumps(audit), 'protected value in host audit')
    require('authorization' not in json.dumps(audit).lower(),
            'authentication header exposed in audit')
