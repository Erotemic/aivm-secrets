"""Shared W1 GitHub-like scenario for the standalone Python/Rust workflow gates.

This is test data, not a credential broker, an API emulator with real GitHub
semantics, or an implementation of authorization. The broker under test must
execute its normal HTTPS and request paths against the recording TLSService.

W2 can use the same responses, paths, credential and policy intent when
constructing its native Rust manifest, without assuming CLI or wire parity.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from aivm_secrets.kernel.presets import GITHUB_DIFF, GITHUB_JSON, github_pr
from tests.secrets_helpers import REPO, SERVICE_TOKEN, TLSService, github_policy

ALLOWED_PR = 13861
OTHER_PR = 13862
HEAD_SHA = 'a' * 40
PULL_PATH = f'/repos/{REPO.lower()}/pulls/{ALLOWED_PR}'
CHECKS_PATH = (
    f'/repos/{REPO.lower()}/commits/{HEAD_SHA}/check-runs'
    '?page=1&per_page=100'
)
DIFF = 'diff --git a/proof.lean b/proof.lean\n+theorem checked : True := trivial\n'
PULL = {
    'number': ALLOWED_PR,
    'title': 'Proof repair',
    'body': 'Review source changes',
    'base': {'repo': {'full_name': REPO}},
    'head': {'repo': {'full_name': 'Erotemic/TauCeti'}, 'sha': HEAD_SHA},
    'user': {'login': 'Erotemic'},
}
CHECKS = {
    'total_count': 1,
    'check_runs': [
        {'name': 'lean', 'status': 'completed', 'conclusion': 'success'},
    ],
}
# Deliberately include a listed write: the operator's --writes=deny is an
# independent gate. This test MUST NOT perform an actual write.
OPERATIONS = ['pr.view', 'pr.diff', 'pr.checks', 'pr.comment']


def synthetic_github_policy(
    service: TLSService, token_file: Path, *,
    lifetime_seconds: int = 1800,
    pr_numbers: tuple[int, ...] = (ALLOWED_PR,),
) -> dict[str, Any]:
    """Expand the *actual* GitHub preset and replace only host-side inputs.

    The policy still has normal GitHub PR checks, a commit-sha binding, CLI
    aliases, and operation schemas.  Only destination and credential source
    point to the synthetic provider; no production code gets mock shortcuts.
    """
    policy = github_pr(github_policy(
        operations=OPERATIONS,
        pr_numbers=list(pr_numbers),
        gh_compat=2,
        lifetime_seconds=lifetime_seconds,
        max_requests=32,
    ))
    policy['host'] = service.host
    policy['egress'] = service.egress()
    policy['credential_source'] = {'kind': 'file', 'path': str(token_file)}
    return policy


def install_github_routes(service: TLSService) -> None:
    """The metadata preflight and diff GET share a URL but vary by Accept."""

    def pull(seen: dict[str, Any]) -> tuple[int, dict[str, str], bytes]:
        accept = seen['headers'].get('accept')
        if accept == GITHUB_JSON:
            return 200, {'Content-Type': 'application/json'}, json.dumps(PULL).encode()
        if accept == GITHUB_DIFF:
            return 200, {'Content-Type': 'text/plain'}, DIFF.encode()
        return 406, {}, b'{"message":"unsupported accept"}'

    service.routes[('GET', PULL_PATH)] = pull
    service.routes[('GET', CHECKS_PATH)] = copy.deepcopy(CHECKS)


def assert_credentialed_read_requests(service: TLSService) -> None:
    """The provider must see each HTTPS request with the broker-held token."""
    for seen in service.seen():
        assert seen['method'] == 'GET'
        assert seen['headers']['authorization'] == 'Bearer ' + SERVICE_TOKEN
        assert seen['headers']['x-github-api-version'] == '2026-03-10'
        assert seen['headers']['host'].startswith(service.host + ':')
        assert seen['body'] == ''
