"""Exact host approval through a separate real Unix control listener."""
import json
from pathlib import Path
import time
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace

import pytest

from aivm_secrets.host.session import control_call
from aivm_secrets.kernel import machine
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_manifest import ManifestCase, policy, provider_directory


def test_native_approval_gate_matches_frozen_python_kernel_admission():
    from tests.test_rust_garrett import executable, run
    rows = [json.loads(line) for line in (Path(__file__).parent/'secrets_vectors/approval/kernel-v1.jsonl').read_text().splitlines()]
    # Re-evaluate the normative transition, so frozen vectors cannot conceal
    # a later change to Python's contract.
    from aivm_secrets.errors import SecretsError
    from aivm_secrets.kernel.model import Clock
    from tests.test_secrets_machine import session, BINDING, VIEW, COMMENT
    for row in rows:
        _, state, claims = session(write_mode=row['mode'])
        req = COMMENT if row['write'] else VIEW
        assert machine.approval_digest(state.policy_digest, claims.grant_id, req) == row['wanted']
        prior = row['approval']
        state = replace(state, approvals=() if prior is None else (machine.Approval(**prior),))
        try:
            admitted = machine.admit(state, claims, BINDING, req, Clock(row['now'], row['now']-900))
            expected = dict(ok=True, decision='allowed', remaining=asdict(admitted.approvals[0]) if admitted.approvals else None)
        except SecretsError as ex:
            assert ex.code in ('denied', 'approval_required')
            expected = dict(ok=True, decision='denied' if ex.code=='denied' else 'required', remaining=prior)
        assert row['expected'] == expected
    actual = run(executable('AIVM_SECRETS_RUST_GARRETT_RUNNER'),
                 [{k:v for k,v in row.items() if k!='expected'} for row in rows],crypto=True)
    assert actual == [row['expected'] for row in rows]


def operator(directory, command, **values):
    return control_call(directory, dict(command=command, **values))


def test_native_exact_write_approval_is_bound_and_one_shot(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        provider.routes[('PATCH', '/v1/tickets/7')] = {'id': 7, 'discarded': TOKEN}
        provider.routes[('PATCH', '/v1/tickets/8')] = {'id': 8}
        p = policy(tmp_path, provider)
        with ManifestCase(tmp_path, provider, p, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            request = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            reply = case.invoke(**request)
            assert reply['error']['code'] == 'approval_required'
            wanted = reply['approval']['digest']
            assert provider.seen() == []
            pending = operator(tmp_path, 'pending')['pending']
            assert len(pending) == 1 and pending[0]['arguments'] == request['arguments']
            canonical = parse_policy(p).parse_request(request)
            assert wanted == machine.approval_digest(parse_policy(p).digest, pending[0]['grant'], canonical)
            assert operator(tmp_path, 'approve', digest=wanted[:16])['ok']
            changed = case.invoke(operation='ticket.edit', arguments=dict(ticket=8, text='hello'))
            assert changed['error']['code'] == 'approval_required'
            assert provider.seen() == []
            assert case.invoke(**request) == dict(version=1, ok=True, result=dict(id=7))
            assert len(provider.seen()) == 1
            assert case.invoke(**request)['error']['code'] == 'approval_required'
            assert len(provider.seen()) == 1
            assert TOKEN.encode() not in json.dumps(operator(tmp_path, 'pending')).encode()


def test_native_expired_approval_denied_and_new_explicit_approval_works(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        provider.routes[('PATCH', '/v1/tickets/7')] = {'id': 7}
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            request = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**request)['approval']['digest']
            assert operator(tmp_path, 'approve', digest=wanted, ttl=1)['ok']
            time.sleep(1.1)
            assert case.invoke(**request)['error']['code'] == 'approval_required'
            assert provider.seen() == []
            assert operator(tmp_path, 'approve', digest=wanted, ttl=900)['ok']
            assert case.invoke(**request)['ok']


def test_native_host_revocation_fences_approved_writes_and_guest_control(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        provider.routes[('PATCH', '/v1/tickets/7')] = {'id': 7}
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            request = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**request)['approval']['digest']
            assert operator(tmp_path, 'approve', digest=wanted)['ok']
            assert operator(tmp_path, 'revoke')['ok']
            assert not operator(tmp_path, 'status')['session']['active']
            assert case.invoke(**request)['error']['code'] == 'revoked'
            assert case.invoke(verb='describe')['error']['code'] == 'revoked'
            assert provider.seen() == []


@pytest.mark.parametrize('fault', ['status', 'json', 'projection'])
def test_native_failed_approved_write_never_refunds_authority(tmp_path, fault):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        provider.routes[('PATCH', '/v1/tickets/7')] = {
            'status': lambda _: (503, {}, b'{"message":"private"}'),
            'json': lambda _: (200, {}, b'{broken'),
            'projection': dict(id=TOKEN),
        }[fault]
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            req = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**req)['approval']['digest']
            assert operator(tmp_path, 'approve', digest=wanted)['ok']
            assert case.invoke(**req)['error']['code'] == 'outcome_unknown'
            assert case.invoke(**req)['error']['code'] == 'approval_required'
            assert len(provider.seen()) == 1


def test_native_concurrent_writes_spend_one_approval_once(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        provider.routes[('PATCH', '/v1/tickets/7')] = dict(id=7)
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            req = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**req)['approval']['digest']
            assert operator(tmp_path, 'approve', digest=wanted)['ok']
            # The first invoke already wrote client.json. Reuse that immutable
            # file; concurrent fixture invocations would race while rewriting it.
            def invoke(_):
                result = subprocess.run([case.client, '--config', str(tmp_path/'client.json')],
                    input=json.dumps(dict(version=1, capability=case.token, request=req)).encode(),
                    capture_output=True, check=True, timeout=15)
                assert TOKEN.encode() not in result.stdout + result.stderr
                return json.loads(result.stdout)
            with ThreadPoolExecutor(max_workers=2) as pool:
                replies = list(pool.map(invoke, range(2)))
            assert sum(reply['ok'] for reply in replies) == 1
            assert [r['error']['code'] for r in replies if not r['ok']] == ['approval_required']
            assert len(provider.seen()) == 1


def test_native_host_revoke_is_responsive_during_provider_io_and_fences_release(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        entered, release = threading.Event(), threading.Event()
        def blocked(_):
            entered.set()
            assert release.wait(8)
            return 200, {}, b'{"id":7}'
        provider.routes[('PATCH', '/v1/tickets/7')] = blocked
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            req = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**req)['approval']['digest']
            assert operator(tmp_path, 'approve', digest=wanted)['ok']
            with ThreadPoolExecutor(max_workers=2) as pool:
                use = pool.submit(case.invoke, **req)
                try:
                    assert entered.wait(5)
                    assert pool.submit(operator, tmp_path, 'revoke').result(timeout=2)['ok']
                    assert not operator(tmp_path, 'status')['session']['active']
                    assert not use.done()
                finally:
                    release.set()
                assert use.result(timeout=8)['error']['code'] == 'outcome_unknown'
            assert len(provider.seen()) == 1
            assert case.invoke(**req)['error']['code'] == 'revoked'


def test_native_semantic_write_get_needs_approval_and_reads_preserve_it(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        provider.routes[('GET', '/v1/tickets/7/close')] = dict(id=7)
        provider.routes[('GET', '/v1/tickets/7')] = dict(id=7)
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            req = dict(operation='ticket.close', arguments=dict(ticket=7))
            wanted = case.invoke(**req)['approval']['digest']
            assert provider.seen() == []
            assert operator(tmp_path, 'approve', digest=wanted)['ok']
            assert case.invoke(operation='ticket.view', arguments=dict(ticket=7))['ok']
            assert case.invoke(**req)['ok']
            assert case.invoke(**req)['error']['code'] == 'approval_required'
            assert len(provider.seen()) == 2


@pytest.mark.parametrize('ttl', [True, 0, 901, 1.5, '300', None])
def test_native_invalid_host_approval_cannot_authorize(tmp_path, ttl):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            req = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**req)['approval']['digest']
            assert operator(tmp_path, 'approve', digest=wanted, ttl=ttl)['error']['code'] == 'invalid_request'
            assert case.invoke(**req)['error']['code'] == 'approval_required'
            assert provider.seen() == []


def test_native_guest_cannot_reach_operator_commands_or_create_approval(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        with ManifestCase(tmp_path, provider, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            req = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**req)['approval']['digest']
            for verb in ('approve', 'pending', 'revoke', 'status'):
                assert not case.invoke(verb=verb)['ok']
            assert operator(tmp_path, 'status')['session']['active']
            assert operator(tmp_path, 'deny', digest=wanted[:16])['ok']
            assert operator(tmp_path, 'pending')['pending'] == []
            assert operator(tmp_path, 'approve', digest=wanted)['error']['code'] == 'invalid_request'
            assert case.invoke(**req)['error']['code'] == 'approval_required'
            assert provider.seen() == []


def test_native_approval_precedes_preflight_and_is_spent_on_failed_preflight(tmp_path):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        p = policy(tmp_path, provider)
        p['checks'] = dict(ticket=dict(path='/v1/tickets/{ticket}',
            require=[dict(at=['owner'], equals='alice')]))
        p['operations'][1]['requires'] = 'ticket'
        provider.routes[('GET', '/v1/tickets/7')] = dict(owner='mallory')
        with ManifestCase(tmp_path, provider, p, writes='approve', control_socket=str(tmp_path/'control.sock')) as case:
            req = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
            wanted = case.invoke(**req)['approval']['digest']
            assert provider.seen() == []
            assert operator(tmp_path, 'approve', digest=wanted)['ok']
            assert not case.invoke(**req)['ok']
            assert len(provider.seen()) == 1
            assert provider.seen()[0]['method'] == 'GET'
            assert case.invoke(**req)['error']['code'] == 'approval_required'
            assert len(provider.seen()) == 1


@pytest.mark.parametrize('configuration', ['missing', 'allow', 'deny', 'basename', 'occupied', 'public-parent'])
def test_native_approval_requires_separate_private_host_endpoint(tmp_path, configuration):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        changes = dict(writes='approve', control_socket=str(tmp_path/'control.sock'))
        if configuration == 'missing':
            changes.pop('control_socket')
        elif configuration in ('allow', 'deny'):
            changes['writes'] = configuration
        elif configuration == 'basename':
            changes['control_socket'] = str(tmp_path/'guest.sock')
        elif configuration == 'occupied':
            (tmp_path/'control.sock').write_text('retain this file')
        else:
            public = tmp_path/'public'
            public.mkdir(mode=0o755)
            public.chmod(0o755)
            changes['control_socket'] = str(public/'control.sock')
        with pytest.raises(AssertionError):
            with ManifestCase(tmp_path, provider, **changes):
                pytest.fail('Unsafe operator endpoint was accepted')
        if configuration == 'occupied':
            assert (tmp_path/'control.sock').read_text() == 'retain this file'
        assert provider.seen() == []


def test_existing_python_operator_cli_controls_native_approval(monkeypatch):
    # Keep the actual Unix path below sockaddr_un's platform bound.
    with tempfile.TemporaryDirectory(prefix='approval-cli-') as name:
        root = Path(name)
        monkeypatch.setenv('XDG_RUNTIME_DIR', str(root))
        directory = root/'aivm-secrets'/('b'*32)
        directory.mkdir(parents=True, mode=0o700)
        directory.parent.chmod(0o700)
        def cli(*args):
            result = subprocess.run([sys.executable, '-m', 'aivm_secrets', *args],
                capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, result.stderr
            assert TOKEN not in result.stdout + result.stderr
            return result.stdout
        with TLSService(provider_directory(directory), host='api.example.org') as provider:
            provider.routes[('PATCH', '/v1/tickets/7')] = dict(id=7)
            with ManifestCase(directory, provider, writes='approve', control_socket=str(directory/'control.sock')) as case:
                req = dict(operation='ticket.edit', arguments=dict(ticket=7, text='hello'))
                wanted = case.invoke(**req)['approval']['digest']
                assert json.loads(cli('sessions', '--json'))[0]['implementation'] == 'rust'
                assert json.loads(cli('pending', '--json'))[0]['digest'] == wanted
                assert 'Approved' in cli('approve', wanted[:16], '--session', 'b'*12, '--yes')
                assert case.invoke(**req)['ok']
                assert case.invoke(**req)['error']['code'] == 'approval_required'
                assert 'Discarded' in cli('deny', wanted[:16], '--session', 'b'*12)
                assert json.loads(cli('pending', '--json')) == []
                cli('revoke', 'b'*12)
                assert case.invoke(**req)['error']['code'] == 'revoked'
