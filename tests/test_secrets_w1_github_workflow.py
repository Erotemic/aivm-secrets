"""W1: an independent, process-level, no-VM GitHub credential workflow.

The broker and guest CLI are separate installed Python processes. The broker
uses its production resolver, authorization, local IPC, and HTTPS executor;
TLSService is a real local TLS endpoint, not a fake in-process executor.
Tests assert actual provider traffic and session audit/teardown, not just
broker return values. All credentials, certificates, and PR data are synthetic.
"""

from __future__ import annotations

import copy
import json
import tempfile
import time
from pathlib import Path

import pytest

from tests.secrets_github_scenario import (
    ALLOWED_PR,
    CHECKS,
    CHECKS_PATH,
    DIFF,
    HEAD_SHA,
    OTHER_PR,
    PULL,
    PULL_PATH,
    assert_credentialed_read_requests,
    install_github_routes,
    synthetic_github_policy,
)
from tests.secrets_helpers import (
    REPO,
    SERVICE_TOKEN,
    ServeProcess,
    TLSService,
    cli_env,
    run_cli_process,
    write_policy_file,
    write_private,
)


@pytest.fixture
def github_world():
    # Short private /tmp root is required by the Unix socket path budget.
    with tempfile.TemporaryDirectory(prefix='as-w1-', dir='/tmp') as directory:
        root = Path(directory)
        with TLSService(root) as provider:
            install_github_routes(provider)
            secret = write_private(root / 'provider-token', (SERVICE_TOKEN + '\n').encode())
            policy = write_policy_file(
                root / 'github-policy.json', synthetic_github_policy(provider, secret)
            )
            yield root, provider, secret, policy, cli_env(root)


def start_broker(world, *, policy=None) -> ServeProcess:
    _, _, _, default_policy, env = world
    broker = ServeProcess(
        ['--policy', str(policy or default_policy), '--writes', 'deny'], env=env
    )
    assert broker.ready, broker.announce
    return broker


def guest_cli(broker: ServeProcess, *words: str):
    # An actual *untrusted client process*, not guest.main() in pytest.
    env = dict(
        broker.env,
        AIVM_SECRETS_SOCKET=broker.announce['socket'],
        AIVM_SECRETS_CAPABILITY_FILE=broker.announce['capability_file'],
    )
    return run_cli_process(list(words), env=env)


def assert_denied(result, error='denied') -> None:
    assert result.returncode == 3, (result.returncode, result.stdout, result.stderr)
    assert result.stdout == ''
    assert result.stderr.strip() == 'aivm-secrets: ' + error
    assert SERVICE_TOKEN not in result.stderr


def assert_clean_audit(
    broker: ServeProcess, events: set[str], *, capability: str = '',
) -> list[dict]:
    path = Path(broker.announce['audit'])
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]['event'] == 'session_open'
    assert rows[-1]['event'] == 'session_close'
    assert events <= {row['event'] for row in rows}
    assert [row['seq'] for row in rows] == list(range(len(rows)))
    assert broker.cli('audit-verify', str(path)).returncode == 0
    contents = path.read_text()
    assert SERVICE_TOKEN not in contents
    if capability:
        assert capability not in contents
    assert broker.stderr == ''
    assert not Path(broker.announce['socket']).parent.exists()
    return rows


def test_w1_real_process_github_reads_denials_and_cleanup(github_world):
    _, provider, _, _, _ = github_world
    with start_broker(github_world) as broker:
        assert broker.announce['service'] == 'github-pr'
        assert broker.announce['writes'] == 'deny'
        capability = broker.capability
        # One actual guest CLI operation returns exactly the checked JSON
        # preflight object, not a hand-constructed broker approximation.
        view = guest_cli(broker, 'invoke', 'pr.view', '--arguments', json.dumps({
            'repository': REPO, 'pr': ALLOWED_PR,
        }))
        assert view.returncode == 0, view.stderr
        assert json.loads(view.stdout) == {
            'version': 1, 'ok': True, 'result': PULL,
        }
        # Demonstrate useful gh-style commands and JSON field projection.
        fields = guest_cli(
            broker, 'as', 'gh', 'pr', 'view', str(ALLOWED_PR),
            '--repo', REPO, '--json', 'number,title,headRefOid',
        )
        assert fields.returncode == 0, fields.stderr
        assert json.loads(fields.stdout) == {
            'number': ALLOWED_PR, 'title': PULL['title'], 'headRefOid': HEAD_SHA,
        }
        diff = guest_cli(
            broker, 'as', 'gh', 'pr', 'diff', str(ALLOWED_PR), '--repo', REPO
        )
        assert diff.returncode == 0, diff.stderr
        assert diff.stdout == DIFF
        checks = guest_cli(
            broker, 'invoke', 'pr.checks', '--arguments', json.dumps({
                'repository': REPO, 'pr': ALLOWED_PR,
            }),
        )
        assert checks.returncode == 0, checks.stderr
        assert json.loads(checks.stdout) == {
            'version': 1, 'ok': True, 'result': CHECKS,
            'pagination': {'page': 1, 'per_page': 100, 'possibly_more': False},
        }
        # This also exercises JSON projection through the CLI, not just the
        # broker protocol's typed result.
        cli_checks = guest_cli(
            broker, 'as', 'gh', 'pr', 'checks', str(ALLOWED_PR), '--repo', REPO,
            '--json', 'name,status',
        )
        assert cli_checks.returncode == 0, cli_checks.stderr
        assert json.loads(cli_checks.stdout) == [
            {'name': 'lean', 'status': 'completed'},
        ]
        baseline = provider.seen()
        assert [call['target'] for call in baseline] == [
            PULL_PATH, PULL_PATH, PULL_PATH, PULL_PATH, PULL_PATH,
            CHECKS_PATH, PULL_PATH, CHECKS_PATH,
        ]
        assert_credentialed_read_requests(provider)
        assert [seen['headers']['accept'] for seen in baseline] == [
            'application/vnd.github+json',
            'application/vnd.github+json',
            'application/vnd.github+json',
            'application/vnd.github.diff',
            'application/vnd.github+json',
            'application/vnd.github+json',
            'application/vnd.github+json',
            'application/vnd.github+json',
        ]

        # Scope denial before provider I/O, with no fallback to stock gh.
        assert_denied(guest_cli(
            broker, 'as', 'gh', 'pr', 'view', str(OTHER_PR), '--repo', REPO
        ))
        assert_denied(guest_cli(
            broker, 'as', 'gh', 'pr', 'comment', str(ALLOWED_PR),
            '--repo', REPO, '--body', 'do not send',
        ))
        unauthorized = guest_cli(
            broker, 'invoke', 'provider.raw', '--arguments', '{"url":"/user"}'
        )
        assert_denied(unauthorized)
        extra = guest_cli(
            broker, 'invoke', 'pr.diff', '--arguments', json.dumps({
                'repository': REPO, 'pr': ALLOWED_PR, 'url': '/user',
            }),
        )
        assert_denied(extra, 'invalid_request')
        no_fallback = guest_cli(broker, 'as', 'gh', 'api', '/user')
        assert no_fallback.returncode == 2
        assert 'not the real gh' in no_fallback.stderr
        assert no_fallback.stdout == ''
        assert provider.seen() == baseline
        assert provider.seen('POST') == []

        # Literal credential reflection: even a policy-authorized diff read
        # is rejected if the provider echoes the credential in its output.
        def reflected(_seen):
            return 200, {'Content-Type': 'text/plain'}, (
                DIFF + 'reflected=' + SERVICE_TOKEN
            ).encode()

        original = provider.routes[('GET', PULL_PATH)]

        def pull_with_reflection(seen):
            if seen['headers'].get('accept') == 'application/vnd.github.diff':
                return reflected(seen)
            return original(seen)

        provider.routes[('GET', PULL_PATH)] = pull_with_reflection
        bad = guest_cli(
            broker, 'as', 'gh', 'pr', 'diff', str(ALLOWED_PR), '--repo', REPO
        )
        assert_denied(bad, 'upstream_response')
        assert SERVICE_TOKEN not in bad.stdout + bad.stderr
        assert [call['target'] for call in provider.seen()[len(baseline):]] == [
            PULL_PATH, PULL_PATH,
        ]
        assert_credentialed_read_requests(provider)
        assert provider.seen('POST') == []
        audit_path = Path(broker.announce['audit'])
        assert broker.stop() == 0
    # After broker shutdown, both socket/capability state are removed.
    rows = assert_clean_audit(
        broker, {'authorized', 'dispatch', 'completed', 'rejected_or_failed'},
        capability=capability,
    )
    assert sum(row['event'] == 'completed' for row in rows) == 5
    assert sum(row['event'] == 'dispatch' for row in rows) == 4
    assert 'upstream_response' in {row.get('code') for row in rows}
    assert 'denied' in {row.get('code') for row in rows}


def test_w1_bad_metadata_blocks_final_dispatch(github_world):
    root, provider, secret, _, _ = github_world
    policy = write_policy_file(
        root / 'two-prs.json', synthetic_github_policy(
            provider, secret, pr_numbers=(ALLOWED_PR, OTHER_PR)
        )
    )

    def wrong_head(_seen):
        malformed = copy.deepcopy(PULL)
        malformed['head']['repo']['full_name'] = 'attacker/other'
        return 200, {}, json.dumps(malformed).encode()

    provider.routes[('GET', PULL_PATH)] = wrong_head
    with start_broker(github_world, policy=policy) as broker:
        assert_denied(guest_cli(
            broker, 'as', 'gh', 'pr', 'diff', str(ALLOWED_PR), '--repo', REPO
        ), 'resource_mismatch')
        assert [seen['target'] for seen in provider.seen()] == [PULL_PATH]
        assert_credentialed_read_requests(provider)
        assert broker.stop() == 0
    rows = assert_clean_audit(broker, {'authorized', 'rejected_or_failed'})
    assert not any(row['event'] == 'dispatch' for row in rows)


def test_w1_operator_revocation_and_lease_expiry(github_world):
    root, provider, secret, _, _ = github_world
    with start_broker(github_world) as broker:
        assert guest_cli(
            broker, 'invoke', 'pr.view', '--arguments', json.dumps({
                'repository': REPO, 'pr': ALLOWED_PR,
            }),
        ).returncode == 0
        before_revoke = provider.seen()
        assert broker.cli('revoke', broker.announce['channel']).returncode == 0
        assert_denied(guest_cli(
            broker, 'invoke', 'pr.view', '--arguments', json.dumps({
                'repository': REPO, 'pr': ALLOWED_PR,
            }),
        ), 'revoked')
        assert provider.seen() == before_revoke
        assert broker.stop() == 0
    assert_clean_audit(broker, {'revoked', 'session_close'})

    short = write_policy_file(
        root / 'short-lived.json', synthetic_github_policy(
            provider, secret, lifetime_seconds=1
        )
    )
    with start_broker(github_world, policy=short) as broker:
        time.sleep(1.5)
        assert_denied(guest_cli(
            broker, 'invoke', 'pr.view', '--arguments', json.dumps({
                'repository': REPO, 'pr': ALLOWED_PR,
            }),
        ), 'expired')
        assert provider.seen() == before_revoke
        assert broker.stop() == 0
    assert_clean_audit(broker, {'session_close'})
