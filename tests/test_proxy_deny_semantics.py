"""The Python proxy's deny list matches exactly what the Rust one is proved
to match.

``proofs/GarrettProxyHttp.lean`` proves that the extracted Rust ``denied``
returns true exactly when some rule satisfies ``RuleMatches``. This test
transcribes that predicate (``PathMatches``) and checks the Python reference
backend against it, exhaustively over every path and rule path of up to four
bytes from ``{a, /}``, so both backends refuse the same requests.
"""

from __future__ import annotations

from itertools import product

from aivm_secrets.proxy.policy import Deny, ProxyPolicy, denied

SLASH = b'/'


def words(limit: int = 4) -> list[bytes]:
    out = [b'']
    for size in range(1, limit + 1):
        out.extend(bytes(chars) for chars in product(b'a/', repeat=size))
    return out


def path_matches(rule: bytes, path: bytes) -> bool:
    """``PathMatches rule path`` from GarrettProxyHttp.lean."""
    return (path == rule
            or path == rule + SLASH
            or (rule.endswith(SLASH) and (rule == path + SLASH or path.startswith(rule))))


def method_matches(rule: bytes, method: bytes) -> bool:
    """``MethodMatches``; the Python policy spells "any method" as ``*`` where
    the Rust policy uses the empty method."""
    return rule == b'*' or rule == method


def test_python_deny_list_decides_the_proved_predicate():
    paths = words()
    for rule_path, rule_method in product(paths, (b'*', b'GET', b'POST')):
        policy = ProxyPolicy('credential-substitution', {}, (Deny(rule_method, rule_path),),
                             1024, 1024, 60)
        for path, method in product(paths, (b'GET', b'POST')):
            expected = method_matches(rule_method, method) and path_matches(rule_path, path)
            assert denied(policy, method, path) == expected, (rule_method, rule_path, method, path)


def test_two_rules_deny_when_either_matches():
    rules = (Deny(b'*', b'/admin/'), Deny(b'POST', b'/v1/tokens'))
    policy = ProxyPolicy('credential-substitution', {}, rules, 1024, 1024, 60)
    assert denied(policy, b'GET', b'/admin')
    assert denied(policy, b'GET', b'/admin/users')
    assert denied(policy, b'POST', b'/v1/tokens/')
    assert not denied(policy, b'GET', b'/v1/tokens')
    assert not denied(policy, b'GET', b'/administrator')
