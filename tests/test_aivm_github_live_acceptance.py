"""Portable invariants for the opt-in live-GitHub real-VM harness.

These tests never contact GitHub, start a native broker, or connect to AIVM.
A real OUT-3 result requires the operator's explicit --live-github VM run.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from dev import aivm_github_live_acceptance as live
from dev.offline_native_guest import DemoError


def test_manifest_is_fixed_host_only_selected_repo_and_explicit_denied_write():
    manifest = live.live_policy(Path('/tmp/host/credential'),
                                Path('/tmp/host/github-ca.pem'), '140.82.112.6')
    assert manifest['host'] == 'api.github.com'
    assert manifest['egress'] == {
        'address': '140.82.112.6', 'port': 443, 'ca_file': '/tmp/host/github-ca.pem'
    }
    assert manifest['credential_source'] == {
        'kind': 'file', 'path': '/tmp/host/credential'
    }
    assert manifest['headers'] == {'X-GitHub-Api-Version': '2026-03-10'}
    operations = {row['name']: row for row in manifest['operations']}
    assert set(operations) == {'account.probe', 'repo.view', 'repo.readme', 'repo.issue'}
    assert all(row.get('method') == 'GET' for name, row in operations.items() if name != 'repo.issue')
    assert operations['repo.issue']['effect'] == 'write'
    assert operations['repo.issue']['method'] == 'POST'
    assert operations['repo.issue']['path'] == '/repos/{owner}/{repo}/issues'
    assert all(op['parameters'] == {
        'owner': ['Erotemic'], 'repo': ['aivm-secrets']
    } for op in (operations['repo.view'], operations['repo.readme'], operations['repo.issue']))
    assert operations['account.probe']['path'] == '/user'
    assert not any('proxy' in str(op) or 'shell' in str(op) for op in operations.values())


def test_disclosure_drops_provider_response_fields():
    rules = live.live_disclosure()
    assert set(rules) == {'account.probe', 'repo.view', 'repo.readme', 'repo.issue'}
    assert set(rules['account.probe']) == {'authenticatedUserId'}
    assert all(row['at'] != ['content'] for row in rules['repo.readme'].values())
    assert set(rules['repo.view']) == {'fullName', 'defaultBranch', 'private'}


def _secret_file(tmp_path: Path, content: bytes = b'github_pat_01234567890123456789') -> Path:
    path = tmp_path / 'read-token'
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def test_operator_provides_separate_private_file(tmp_path):
    path = _secret_file(tmp_path)
    selected, value = live.check_token_file(path)
    assert selected == path
    assert value == path.read_bytes()
    assert not (path.stat().st_mode & 0o077)


@pytest.mark.parametrize('unsafe', [
    b'not_valid\n',
    b'bad credential with spaces even if sufficiently long',
    b'bad\x00credential-123456789',
    b'short',
    b'x' * 4097,
])
def test_token_must_satisfy_native_http_auth_header_grammar(tmp_path, unsafe):
    path = _secret_file(tmp_path, unsafe)
    with pytest.raises(DemoError, match='nonwhitespace ASCII'):
        live.check_token_file(path)


def test_classic_or_service_token_is_not_accepted_as_fine_grained(tmp_path):
    path = _secret_file(tmp_path, b'ghp_123456789abcdefghijklmnopq')
    with pytest.raises(DemoError, match='fine-grained'):
        live.check_token_file(path)


def test_token_refuses_group_or_world_access(tmp_path):
    path = _secret_file(tmp_path)
    path.chmod(0o640)
    with pytest.raises(DemoError, match='inaccessible to group/other'):
        live.check_token_file(path)
    path.chmod(0o604)
    with pytest.raises(DemoError, match='inaccessible to group/other'):
        live.check_token_file(path)


def test_token_refuses_symlink_and_hardlink(tmp_path):
    path = _secret_file(tmp_path)
    alias = tmp_path / 'alias'
    alias.symlink_to(path)
    with pytest.raises(DemoError, match='non-linked'):
        live.check_token_file(alias)
    hard = tmp_path / 'hard'
    os.link(path, hard)
    with pytest.raises(DemoError, match='non-linked'):
        live.check_token_file(path)


def test_token_absence_explains_required_provisioning(tmp_path):
    with pytest.raises(DemoError, match='missing or inaccessible'):
        live.check_token_file(tmp_path / 'not-there')


def test_projections_reject_unselected_or_invalid_results():
    def result(payload, code=0):
        return subprocess.CompletedProcess([], code, json.dumps(payload).encode(), b'private error')
    good = result({'version': 1, 'ok': True, 'result': {'id': 6}})
    assert live.successful_projection(good, label='probe', expected_keys={'id'}) == {'id': 6}
    bad = result({'version': 1, 'ok': True, 'result': {'id': 6, 'credential': 'PRIVATE'}})
    with pytest.raises(DemoError, match='projection') as exc:
        live.successful_projection(bad, label='probe', expected_keys={'id'})
    assert 'PRIVATE' not in str(exc.value)
    with pytest.raises(DemoError, match='provider, TLS, token or policy'):
        live.successful_projection(result({'version': 1, 'ok': False, 'error': {'code': 'upstream_error'}}),
                                   label='probe', expected_keys={'id'})


def test_broker_config_never_embeds_secret_or_allows_write(tmp_path):
    host = tmp_path / 'host'
    cfg = live.live_bridge_config(host, tmp_path / 'TOKEN_FILE', tmp_path / 'ca.pem',
                                  '140.82.112.6', 'aivm-2404')
    provider = cfg['provider']
    assert provider['writes'] == 'deny'
    assert provider['profile'] == 'manifest-https-v1'
    assert provider['credential_file'] == str(tmp_path / 'TOKEN_FILE')
    assert provider['host'] == 'api.github.com'
    assert provider['port'] == 443
    assert provider['address'] == '140.82.112.6'
    assert 'Authorization' not in json.dumps(cfg)


def test_audit_reports_only_count_and_refuses_secret_or_capability(tmp_path):
    host = tmp_path / 'host'
    host.mkdir()
    path = host / 'provider-audit.jsonl'
    path.write_text('\n'.join(json.dumps(v) for v in [
        {'schema': 1, 'event': 'session_open'},
        {'schema': 1, 'event': 'dispatch', 'operation': 'account.probe'},
        {'schema': 1, 'event': 'dispatch', 'operation': 'repo.view'},
        {'schema': 1, 'event': 'completed', 'operation': 'repo.view'},
    ]) + '\n')
    assert live.audit_dispatch_count(host, token=b'private-token-1234', capability='private-capability') == 2
    path.write_text('{"schema":1,"event":"dispatch","token":"private-token-1234"}\n')
    with pytest.raises(DemoError, match='provider credential'):
        live.audit_dispatch_count(host, token=b'private-token-1234', capability='private-capability')
    path.write_text('{"schema":1,"event":"dispatch","surrogate":"private-capability"}\n')
    with pytest.raises(DemoError, match='surrogate'):
        live.audit_dispatch_count(host, token=b'private-token-1234', capability='private-capability')


def test_read_denial_requires_no_additional_dispatch(tmp_path, monkeypatch):
    host = tmp_path / 'host'
    host.mkdir()
    (host / 'provider-audit.jsonl').write_text('{"schema":1,"event":"dispatch"}\n')
    monkeypatch.setattr(live, 'live_guest_invoke', lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [], 1, b'{"ok":false,"error":{"code":"denied"}}', b''))
    live.rejected_without_dispatch(object(), 'guest', host, b'private-token-1234',
                                   'private-capability', 'repo.issue', {}, 1, label='write')
    with pytest.raises(DemoError, match='additional|native dispatch'):
        live.rejected_without_dispatch(object(), 'guest', host, b'private-token-1234',
                                       'private-capability', 'repo.issue', {}, 0, label='write')
    monkeypatch.setattr(live, 'live_guest_invoke', lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [], 0, b'{"ok":true}', b''))
    with pytest.raises(DemoError, match='unexpectedly succeeded'):
        live.rejected_without_dispatch(object(), 'guest', host, b'private-token-1234',
                                       'private-capability', 'repo.issue', {}, 1, label='write')


def test_trust_bundle_must_be_bounded_valid_pem(tmp_path):
    source = tmp_path / 'ca.pem'
    source.write_bytes(b'not a CA')
    host = tmp_path / 'host'
    host.mkdir()
    with pytest.raises(DemoError, match='missing valid PEM'):
        live.copy_trust_bundle(host, source)
    source.write_bytes(b'-----BEGIN CERTIFICATE-----\n' + b'A' * 1048576)
    with pytest.raises(DemoError, match='exceeds Rust limit'):
        live.copy_trust_bundle(host, source)


def test_run_requires_explicit_live_opt_in(tmp_path, monkeypatch, capsys):
    # No subprocess invocation or network call is permitted in portable tests.
    monkeypatch.setattr(live, 'ssh_configuration', lambda *args: pytest.fail('no SSH'))
    monkeypatch.setattr(live, 'resolved_github_address', lambda: pytest.fail('no live GitHub'))
    with pytest.raises(SystemExit, match='2'):
        live.main(['--vm', 'aivm-2404'])


def _native_reply(exit_code: int, reply: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        [], exit_code, json.dumps(reply).encode('utf-8') + b'\n', b'',
    )


def _identity_denial(code: str = 'invalid_capability') -> dict:
    return {
        'version': 1, 'ok': False,
        'error': {'code': code, 'message': 'Capability authentication failed.'},
    }


@pytest.mark.parametrize('code', ['invalid_capability', 'revoked'])
def test_revoked_invoke_structured_stdout_denial_is_not_a_success(code):
    # The native `invoke` path prints a public denial JSON on stdout with
    # exit=1. The original live fixture incorrectly treated stdout as success.
    assert live.require_revoked_identity_denial(_native_reply(1, _identity_denial(code))) == code


@pytest.mark.parametrize('returncode,reply', [
    (0, _identity_denial()),
    (255, _identity_denial()),  # SSH transport error is not broker denial
    (0, {'version': 1, 'ok': True, 'result': {'authenticatedUserId': 12}}),
    (1, {'version': 1, 'ok': True, 'result': {'authenticatedUserId': 12}}),
    (1, {'version': 1, 'ok': False, 'error': {'code': 'denied', 'message': 'Policy denied'}}),
    (1, {'version': 1, 'ok': False, 'error': {'code': 'upstream_error', 'message': 'failure'}}),
    (1, {'version': 1, 'ok': False, 'error': {'code': 'invalid_capability', 'message': 'x'},
         'result': {'authenticatedUserId': 12}}),
    (1, {'version': 1, 'ok': False, 'error': {'code': 'invalid_capability'}}),
    (1, 'private-data'),
])
def test_revoked_invoke_rejects_success_unexpected_code_or_extra_fields(returncode, reply):
    with pytest.raises(DemoError, match='revoked VM guest'):
        live.require_revoked_identity_denial(_native_reply(returncode, reply))


def test_revoked_invoke_rejects_missing_or_invalid_json():
    for stdout in [b'', b'not JSON', b'\xff']:
        result = subprocess.CompletedProcess([], 1, stdout, b'not safe to print')
        with pytest.raises(DemoError, match='structured native denial'):
            live.require_revoked_identity_denial(result)


def _enrollment(*, active: bool, epoch: int) -> dict:
    return {'active': active, 'epoch': epoch,
            'certificate_sha256': 'public-thumbprint'}


def test_revocation_requires_durable_status_and_advancing_epoch():
    before = {'subjects': {'live-guest': _enrollment(active=True, epoch=2)}}
    after = {'subjects': {'live-guest': _enrollment(active=False, epoch=3)}}
    issued = {'state': after}
    live.verify_revocation_state(before, issued, after)

    for wrong_before, wrong_issued, wrong_after in [
        (before, issued, before),  # state was never durably changed
        (before, {'state': before}, after),  # response does not match disk
        (before, issued, {'subjects': {'live-guest': _enrollment(active=False, epoch=2)}}),
        (after, issued, after),  # already revoked is not a successful transition
        (before, {'state': {'subjects': {}}}, after),
    ]:
        with pytest.raises(DemoError, match='native authority'):
            live.verify_revocation_state(wrong_before, wrong_issued, wrong_after)


def test_revoked_denial_also_requires_no_new_native_provider_dispatch(tmp_path):
    host = tmp_path / 'host'
    host.mkdir()
    audit = host / 'provider-audit.jsonl'
    audit.write_text('{"schema":1,"event":"dispatch"}\n')
    rejected = _native_reply(1, _identity_denial())
    assert live.revoked_without_dispatch(
        rejected, host, token=b'not-a-real-token', capability='a-public-test-claim', before=1
    ) == 'invalid_capability'
    audit.write_text('{"schema":1,"event":"dispatch"}\n'
                     '{"schema":1,"event":"dispatch"}\n')
    with pytest.raises(DemoError, match='additional provider dispatch'):
        live.revoked_without_dispatch(
            rejected, host, token=b'not-a-real-token', capability='a-public-test-claim', before=1
        )
