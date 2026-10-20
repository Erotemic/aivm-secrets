"""Non-core native process evidence for acknowledged completion then denial.

Linux-only test instrumentation pauses after the real audit fsync; it does not
replace the broker, authorization, audit implementation or provider transport.
The preload library is scoped to synthetic fixture child processes only.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_manifest import ManifestCase, checked, policy, provider_directory
from tests.test_rust_w6_adapter import native_guest_frame
from tests.secrets_w6_trace import records
from tests.test_rust_coordination import coordinator_case


@pytest.fixture(scope='session')
def completion_fsync_barrier(tmp_path_factory):
    executable('AIVM_SECRETS_RUST_GARRETT_BRIDGE')
    if sys.platform != 'linux':
        pytest.skip('native fsync boundary instrumentation requires Linux')
    compiler = shutil.which('cc')
    assert compiler, 'native completion witness requires a C compiler'
    source = Path(__file__).parent / 'native/completion_fsync_barrier.c'
    output = tmp_path_factory.mktemp('completion-fsync') / 'barrier.so'
    subprocess.run([compiler, '-std=c11', '-shared', '-fPIC', '-O2',
                    '-Wall', '-Wextra', '-Werror', str(source), '-ldl', '-o', str(output)],
                   check=True, capture_output=True, timeout=30)
    return output


def await_condition(predicate, description):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline, description
        time.sleep(0.01)


@pytest.mark.parametrize('shape', ['final-only', 'checked-only', 'two-phase'])
def test_completion_fsync_ack_then_revocation_denies_actual_guest(
        tmp_path, monkeypatch, completion_fsync_barrier, shape, coordinator_case):
    """Retain the completed audit but release no value after late withdrawal."""
    ready, release = tmp_path / 'audit-ready', tmp_path / 'audit-release'
    audit = tmp_path / 'provider-audit.jsonl'
    monkeypatch.setenv('LD_PRELOAD', str(completion_fsync_barrier))
    monkeypatch.setenv('AIVM_TEST_COMPLETION_AUDIT', str(audit))
    monkeypatch.setenv('AIVM_TEST_COMPLETION_READY', str(ready))
    monkeypatch.setenv('AIVM_TEST_COMPLETION_RELEASE', str(release))
    monkeypatch.setenv('AIVM_TEST_COMPLETION_NUMBER', '2')
    with coordinator_case(tmp_path / 'coord') as coord, TLSService(
            provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([coord.members[0][2]])
        provider.routes[('GET', '/v1/tickets/7')] = dict(
            id=7, owner='alice', revision='a' * 40, private=TOKEN)
        provider.routes[('GET', '/v1/revisions/' + 'a' * 40)] = dict(id=7, private=TOKEN)
        p = policy(tmp_path, provider)
        operation, phases = 'ticket.view', ['final']
        if shape != 'final-only':
            p = checked(p)
            operation = 'ticket.check' if shape == 'checked-only' else 'revision.view'
            phases = ['preflight'] if shape == 'checked-only' else ['preflight', 'final']
        disclosures = {op['name']: {'id': {'at': ['id'], 'type': 'integer'}} for op in p['operations']}
        with ManifestCase(tmp_path, provider, p, disclosures,
                          coordination_file=str(coord.member_file())) as case:
            # A real allowed value is released before the fault is enabled.
            # The next request uses that public ID as its argument.
            first, _ = native_guest_frame(case, operation=operation, arguments={'ticket': 7})
            assert first == {'version': 1, 'ok': True, 'result': {'id': 7}}
            assert not ready.exists()
            args = {'ticket': first['result']['id']}
            startup = records(audit)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(native_guest_frame, case, operation=operation,
                                      arguments=args)
                try:
                    await_condition(ready.exists, 'native completion did not reach fsync barrier')
                    committed = records(audit)[len(startup):]
                    assert [r['event'] for r in committed] == ['dispatch'] * len(phases) + ['completed']
                    assert [r['phase'] for r in committed if r['event'] == 'dispatch'] == phases
                    assert not pending.done(), 'guest returned before completion fsync returned'
                    # The independent coordinator commits terminal revocation
                    # while the broker still holds its own audit mutex.
                    coord.operator.revoke()
                    assert not pending.done()
                finally:
                    release.touch(mode=0o600)
                reply, frame = pending.result(timeout=10)
            assert reply == {'version': 1, 'ok': False, 'error': {
                'code': 'revoked', 'message': 'Broker failed closed.'}}
            assert frame == codec.dumps(reply) + b'\n'
            assert len(provider.seen()) == 2 * len(phases)
            final = records(audit)[len(startup):]
            assert [r['event'] for r in final] == ['dispatch'] * len(phases) + ['completed']
            assert len({r['request_digest'] for r in final if r['event'] in ('dispatch', 'completed')}) == 1
            assert all(TOKEN not in str(row) for row in final)
            before = list(provider.seen()), records(audit)
            denied, _ = native_guest_frame(case, operation=operation, arguments={'ticket': 7})
            assert denied['error']['code'] == 'revoked'
            assert (provider.seen(), records(audit)) == before
