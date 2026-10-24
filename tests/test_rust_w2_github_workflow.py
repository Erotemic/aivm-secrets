"""W2: run W1 intent through native Rust custody/mTLS/HTTPS and narrow gh reads.

No Python credential broker is run. Python owns only the local test TLS
provider, native policy fixture construction, and process observations. Rust
executables are required for these integration tests; missing executables
cause an explicit pytest skip rather than silent Python substitution.
"""
from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest

from aivm_secrets.kernel.presets import github_pr
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_github_scenario import (
    ALLOWED_PR, CHECKS, CHECKS_PATH, DIFF, HEAD_SHA, OTHER_PR,
    PULL, PULL_PATH, OPERATIONS, install_github_routes,
)
from tests.secrets_helpers import REPO, TOKEN, TLSService, github_policy
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory, reference_compile
from tests.test_rust_garrett_authority import private


def native_policy(directory: Path, server: TLSService) -> dict:
    """W1 GitHub operation rules without Python's unsupported gh alias table.

    The host's Rust policy compiler still validates parameters, checked facts,
    destination and effects. Guest-side gh translation has no policy power.
    """
    result = github_pr(github_policy(
        operations=OPERATIONS,
        pr_numbers=[ALLOWED_PR],
        gh_compat=2,
        lifetime_seconds=1800,
        max_requests=32,
    ))
    # Native Rust does not parse or interpret the Python CLI alias table.
    result.pop('cli', None)
    result['host'] = server.host
    result['egress'] = server.egress()
    result['credential_source'] = {'kind': 'file', 'path': str(directory / 'credential')}
    return result


def native_disclosure() -> dict:
    """A reviewed subset, not W1 Python's entire checked metadata reply."""
    return {
        'pr.view': {
            'number': {'at': ['number'], 'type': 'integer'},
            'title': {'at': ['title'], 'type': 'text'},
            'headRefOid': {'at': ['head', 'sha'], 'type': 'text'},
        },
        'pr.diff': {'diff': {'at': [], 'type': 'text'}},
        'pr.checks': {
            'checks': {
                'at': ['check_runs'], 'type': 'array', 'max_items': 100,
                'items': {
                    'at': [], 'type': 'object', 'fields': {
                        'name': {'at': ['name'], 'type': 'text'},
                        'status': {'at': ['status'], 'type': 'text'},
                        'conclusion': {'at': ['conclusion'], 'type': 'text'},
                    },
                },
            },
        },
        'pr.comment': {'id': {'at': ['id'], 'type': 'integer'}},
    }


def arguments(**extra):
    return {'repository': REPO, 'pr': ALLOWED_PR, **extra}


def native_cli(case: ManifestCase, *words: str):
    config = private(case.directory / 'w2-client.json', {
        'schema': 1,
        'key_mode': 'software',
        'socket': str(case.directory / 'identity.sock'),
        'server_name': 'localhost',
        'certificate': str(case.certs['client1'][0]),
        'private_key': str(case.certs['client1'][1]),
        'server_ca': str(case.certs['ca']),
    })
    capability = private(case.directory / 'w2-capability', case.token.encode())
    command = [
        case.client, '--config', str(config), '--capability-file', str(capability),
        'gh', *words,
    ]
    result = subprocess.run(command, capture_output=True, timeout=20)
    assert TOKEN.encode() not in result.stdout + result.stderr
    assert case.token.encode() not in result.stdout + result.stderr
    return result


def assert_provider_reads(server, count: int):
    seen = server.seen()
    assert len(seen) == count, seen
    for row in seen:
        assert row['method'] == 'GET'
        assert row['headers']['authorization'] == 'Bearer ' + TOKEN
        assert row['headers']['x-github-api-version'] == '2026-03-10'
        assert row['body'] == ''


def test_w2_policy_uses_exact_w1_scope_and_explicit_native_release(tmp_path):
    """Fixture quality gate that still runs when the Rust binary is absent."""
    with TLSService(provider_directory(tmp_path)) as server:
        p = native_policy(tmp_path, server)
        spec = parse_policy(p)
        assert sorted(op.name for op in spec.operations) == sorted(OPERATIONS)
        assert sorted(native_disclosure()) == sorted(OPERATIONS)
        assert 'cli' not in p
        assert p['egress']['address'] == '127.0.0.1'
        assert p['host'] == server.host
        assert p['credential_source']['path'] == str(tmp_path / 'credential')
        assert p['checks']['pull']['bind']['head_sha']['format'] == 'hex'
        assert p['operations'][0]['parameters']['pr'] == [ALLOWED_PR]
        # This is an independent Python reference compilation of the expected
        # native manifest effects; it does not substitute for executing Rust.
        for op in ('pr.view', 'pr.diff', 'pr.checks'):
            compiled = reference_compile(p, {
                'operation': op, 'arguments': arguments(),
            }, PULL)
            assert compiled['ok'], compiled
            assert compiled['result']['preflight']['target'] == PULL_PATH
            effect = compiled['result']['effect']
            if op == 'pr.view':
                assert effect is None
            elif op == 'pr.diff':
                assert effect['target'] == PULL_PATH
                assert effect['accept'] == 'application/vnd.github.diff'
            else:
                assert effect['target'] == CHECKS_PATH
                assert effect['method'] == 'GET'


def test_w2_native_read_diff_checks_denials_and_renounce(tmp_path):
    with TLSService(provider_directory(tmp_path)) as server:
        install_github_routes(server)
        with ManifestCase(tmp_path, server, native_policy(tmp_path, server), native_disclosure()) as case:
            view = case.invoke(operation='pr.view', arguments=arguments())
            assert view == {
                'version': 1, 'ok': True,
                'result': {
                    'number': ALLOWED_PR, 'title': PULL['title'],
                    'headRefOid': HEAD_SHA,
                },
            }
            diff = case.invoke(operation='pr.diff', arguments=arguments())
            assert diff == {'version': 1, 'ok': True, 'result': {'diff': DIFF}}
            checks = case.invoke(operation='pr.checks', arguments=arguments())
            assert checks == {
                'version': 1, 'ok': True,
                'result': {'checks': CHECKS['check_runs']},
                'meta': {'pagination': {
                    'page': 1, 'per_page': 100, 'possibly_more': False,
                }},
            }
            assert [x['target'] for x in server.seen()] == [
                PULL_PATH, PULL_PATH, PULL_PATH, PULL_PATH, CHECKS_PATH,
            ]
            assert [x['headers']['accept'] for x in server.seen()] == [
                'application/vnd.github+json',
                'application/vnd.github+json',
                'application/vnd.github.diff',
                'application/vnd.github+json',
                'application/vnd.github+json',
            ]
            assert_provider_reads(server, 5)
            before = server.seen()
            for op, args, codes in [
                ('pr.view', {'repository': REPO, 'pr': OTHER_PR}, {'denied'}),
                ('pr.comment', arguments(body='do not send'), {'denied'}),
                ('provider.raw', {'url': '/user'}, {'denied'}),
                ('pr.diff', arguments(url='/user'), {'invalid_request'}),
            ]:
                response = case.invoke(operation=op, arguments=args)
                assert response['ok'] is False, response
                assert response['error']['code'] in codes, response
            assert server.seen() == before
            assert server.seen('POST') == []
            assert case.invoke(verb='renounce') == {
                'version': 1, 'ok': True, 'renounced': True,
            }
            denied = case.invoke(operation='pr.view', arguments=arguments())
            assert not denied['ok']
            assert server.seen() == before
        audit = (tmp_path / 'provider-audit.jsonl').read_text()
        assert TOKEN not in audit
        assert case.token not in audit


def test_w2_narrow_gh_client_uses_native_broker_only(tmp_path):
    with TLSService(provider_directory(tmp_path)) as server:
        install_github_routes(server)
        with ManifestCase(tmp_path, server, native_policy(tmp_path, server), native_disclosure()) as case:
            view = native_cli(case, 'pr', 'view', str(ALLOWED_PR), '--repo', REPO,
                              '--json', 'number,title,headRefOid')
            assert view.returncode == 0, view.stderr
            assert json.loads(view.stdout) == {
                'number': ALLOWED_PR, 'title': PULL['title'], 'headRefOid': HEAD_SHA,
            }
            diff = native_cli(case, 'pr', 'diff', str(ALLOWED_PR), '--repo', REPO)
            assert diff.returncode == 0, diff.stderr
            assert diff.stdout.decode() == DIFF
            checks = native_cli(case, 'pr', 'checks', str(ALLOWED_PR), '--repo', REPO,
                                '--json', 'name,status')
            assert checks.returncode == 0, checks.stderr
            assert json.loads(checks.stdout) == [{'name': 'lean', 'status': 'completed'}]
            assert_provider_reads(server, 5)
            before = server.seen()
            for words in [
                ('pr', 'view', str(OTHER_PR), '--repo', REPO),
                ('pr', 'comment', str(ALLOWED_PR), '--repo', REPO, '--body', 'deny'),
                ('api', '/user'),
                ('pr', 'view', str(ALLOWED_PR), '--repo', REPO, '--json', 'token'),
                ('pr', 'view', str(ALLOWED_PR), '--repo', REPO, '--repo', 'other/repo'),
            ]:
                refused = native_cli(case, *words)
                assert refused.returncode != 0
                assert refused.stdout == b''
                assert refused.stderr.strip() in (b'denied', b'invalid_request')
            assert server.seen() == before
            assert not (tmp_path / 'broker.sock').exists()


def test_w2_checked_facts_and_reflected_token_fail_closed(tmp_path):
    with TLSService(provider_directory(tmp_path)) as server:
        install_github_routes(server)
        original = server.routes[('GET', PULL_PATH)]
        def bad_head(seen):
            status, headers, data = original(seen)
            if seen['headers'].get('accept') == 'application/vnd.github+json':
                wrong = copy.deepcopy(PULL)
                wrong['head']['repo']['full_name'] = 'attacker/other'
                return 200, headers, json.dumps(wrong).encode()
            return status, headers, data
        server.routes[('GET', PULL_PATH)] = bad_head
        with ManifestCase(tmp_path, server, native_policy(tmp_path, server), native_disclosure()) as case:
            mismatch = case.invoke(operation='pr.diff', arguments=arguments())
            assert mismatch['error']['code'] == 'resource_mismatch'
            assert [x['target'] for x in server.seen()] == [PULL_PATH]


def test_w2_reflected_credential_rejected_before_guest_disclosure(tmp_path):
    with TLSService(provider_directory(tmp_path)) as server:
        install_github_routes(server)
        original = server.routes[('GET', PULL_PATH)]
        def reflect(seen):
            if seen['headers'].get('accept') == 'application/vnd.github.diff':
                return 200, {'Content-Type': 'text/plain'}, (DIFF + TOKEN).encode()
            return original(seen)
        server.routes[('GET', PULL_PATH)] = reflect
        with ManifestCase(tmp_path, server, native_policy(tmp_path, server), native_disclosure()) as case:
            refused = case.invoke(operation='pr.diff', arguments=arguments())
            assert refused['error']['code'] == 'upstream_response'
            assert TOKEN not in json.dumps(refused)
            assert [r['target'] for r in server.seen()] == [PULL_PATH, PULL_PATH]
        assert TOKEN not in (tmp_path / 'provider-audit.jsonl').read_text()


STATUSES_PATH = f'/repos/{REPO.lower()}/commits/{HEAD_SHA}/statuses?page=1&per_page=100'
STATUSES = [
    {'context': 'ci/required', 'state': 'failure', 'description': 'tests failed',
     'target_url': 'https://ci.example/1', 'creator': {'login': 'bot'}},
    {'context': 'ci/optional', 'state': 'success', 'description': 'ok',
     'target_url': 'https://ci.example/2', 'creator': {'login': 'bot'}},
]


def test_commit_statuses_are_a_separate_read_and_a_gh_alias(tmp_path):
    """Check runs can all pass while a commit status fails: `pr.statuses`
    reads the statuses, and `gh pr statuses` renders the selected fields."""
    with TLSService(provider_directory(tmp_path)) as server:
        install_github_routes(server)
        server.routes[('GET', STATUSES_PATH)] = STATUSES
        policy = github_pr(github_policy(
            operations=OPERATIONS + ['pr.statuses'], pr_numbers=[ALLOWED_PR],
            gh_compat=2, lifetime_seconds=1800, max_requests=32))
        policy.pop('cli', None)
        policy['host'] = server.host
        policy['egress'] = server.egress()
        policy['credential_source'] = {'kind': 'file', 'path': str(tmp_path / 'credential')}
        disclosure = dict(native_disclosure(), **{'pr.statuses': {'statuses': {
            'at': [], 'type': 'array', 'max_items': 100,
            'items': {'at': [], 'type': 'object', 'fields': {
                'context': {'at': ['context'], 'type': 'text'},
                'state': {'at': ['state'], 'type': 'text'},
                'description': {'at': ['description'], 'type': 'text'},
            }},
        }}})
        with ManifestCase(tmp_path, server, policy, disclosure) as case:
            reply = case.invoke(operation='pr.statuses', arguments=arguments())
            assert reply['ok'] is True, reply
            assert reply['result'] == {'statuses': [
                {'context': 'ci/required', 'state': 'failure', 'description': 'tests failed'},
                {'context': 'ci/optional', 'state': 'success', 'description': 'ok'},
            ]}
            rendered = native_cli(case, 'pr', 'statuses', str(ALLOWED_PR), '--repo', REPO,
                                  '--json', 'context,state')
            assert rendered.returncode == 0, rendered.stderr
            assert json.loads(rendered.stdout) == [
                {'context': 'ci/required', 'state': 'failure'},
                {'context': 'ci/optional', 'state': 'success'},
            ]
            unlisted = native_cli(case, 'pr', 'statuses', str(ALLOWED_PR), '--repo', REPO,
                                  '--json', 'target_url')
            assert unlisted.returncode != 0 and unlisted.stdout == b''
