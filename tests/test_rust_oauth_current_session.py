"""Current-token rollover must preserve the running native grant and binding."""
import json
from pathlib import Path
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
from tests.test_rust_garrett_manifest import ManifestCase, policy, disclosure, provider_directory, checked
from tests.test_rust_garrett_oauth_vault import VaultCase, SUCCESSOR, response
from aivm_secrets.errors import SecretsError


def test_manifest_last_response_cannot_outlive_current_oauth_token(tmp_path):
    from tests.secrets_w6_trace import records

    vault = VaultCase(tmp_path)
    vault.enroll(access_token=TOKEN, expires_at=int(time.time()) + 3600)
    source = dict(vault_root=str(vault.root), provider_file=str(vault.provider_file),
                  subject='vm-test')
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        def expires_during_response(_):
            time.sleep(max(0, expiry - time.time() + 0.05))
            return 200, {}, b'{"id":7}'

        provider.routes[('GET', '/v1/tickets/7')] = expires_during_response
        with ManifestCase(tmp_path, provider, oauth=source, credential_file=None,
                          source_override='oauth', writes='deny') as session:
            # Avoid the independent startup-refresh margin. The trusted
            # operator installs a short-lived generation in this live session.
            expiry = int(time.time()) + 2
            row = vault.row()
            row['grant'].update(expires_at=expiry, generation=1)
            vault.reference._write(vault.provider, 'vm-test', row)
            assert session.expires_at > expiry
            reply = session.invoke(operation='ticket.view', arguments={'ticket': 7})
            assert reply.get('error', {}).get('code') == 'credential_source', reply
            assert len(provider.seen()) == 1
            assert not any(row['event'] == 'completed'
                           for row in records(tmp_path / 'provider-audit.jsonl'))


@pytest.mark.parametrize('profile', ['account', 'manifest'])
def test_explicit_refresh_updates_the_existing_native_session(profile):
    with tempfile.TemporaryDirectory(prefix='as-roll-', dir='/tmp') as directory:
        root = Path(directory)
        case = VaultCase(root)
        stamp = int(time.time())
        case.enroll(access_token=TOKEN, expires_at=stamp + 3600)
        epoch = case.row()['epoch']
        token_dir = root / 'tokens'
        token_dir.mkdir(mode=0o700)
        with TLSService(provider_directory(root), host='api.example.org') as resource, \
                TLSService(token_dir, host='login.example.org') as endpoint:
            target = '/v1/account' if profile == 'account' else '/v1/tickets/7'
            resource.routes[('GET', target)] = {'id': 42, 'active': True}
            endpoint.routes[('POST', '/token')] = response()
            source = {'vault_root': str(case.root), 'provider_file': str(case.provider_file),
                      'subject': 'vm-test'}
            if profile == 'account':
                authority = AuthorityCase(root)
                context = AuthorityProviderCase(root, resource, authority,
                                                oauth=source, credential_file=None)
                operation, arguments = 'profile.read', {}
            else:
                context = ManifestCase(root, resource, policy(root, resource), disclosure(),
                                       oauth=source, credential_file=None, source_override='oauth')
                operation, arguments = 'ticket.view', {'ticket': 7}
            with context as session:
                capability, pid = session.token, session.process.pid
                first = session.invoke(operation=operation, arguments=arguments)
                assert first['ok'], first
                assert resource.seen()[0]['headers']['authorization'] == 'Bearer ' + TOKEN
                assert endpoint.seen() == []  # guest use never implicitly refreshes
                case.call('refresh', now=stamp, transport=case.transport(endpoint))
                # Independent Python reference accepts the new credential for
                # the SAME epoch, and would fence a revoked/re-enrolled epoch.
                with case.reference.current_lease(case.provider, 'vm-test',
                        resource_host='api.example.org', expected_epoch=epoch) as current:
                    assert current == SUCCESSOR
                second = session.invoke(operation=operation, arguments=arguments)
                assert second['ok'], second
                assert session.token == capability and session.process.pid == pid
                assert [r['headers']['authorization'] for r in resource.seen()] == [
                    'Bearer ' + TOKEN, 'Bearer ' + SUCCESSOR]
                assert len(endpoint.seen()) == 1
                assert TOKEN not in json.dumps([first, second])
                assert SUCCESSOR not in json.dumps([first, second])
                case.call('revoke', now=int(time.time()))
                denied = session.invoke(operation=operation, arguments=arguments)
                assert not denied['ok']
                assert len(resource.seen()) == 2


@pytest.mark.parametrize('profile', ['account', 'manifest'])
def test_refresh_does_not_leave_session_capped_at_the_initial_token_expiry(profile):
    with tempfile.TemporaryDirectory(prefix='as-roll-exp-', dir='/tmp') as directory:
        root = Path(directory)
        case = VaultCase(root)
        stamp = int(time.time())
        case.enroll(access_token=TOKEN, expires_at=stamp + 1)
        token_dir = root / 'tokens'
        token_dir.mkdir(mode=0o700)
        with TLSService(provider_directory(root), host='api.example.org') as resource, \
                TLSService(token_dir, host='login.example.org') as endpoint:
            endpoint.routes[('POST', '/token')] = response(access_token=TOKEN, expires_in=6)
            source = {'vault_root': str(case.root), 'provider_file': str(case.provider_file),
                      'subject': 'vm-test', 'transport': case.transport(endpoint)}
            if profile == 'account':
                resource.routes[('GET', '/v1/account')] = {'id': 42, 'active': True}
                context = AuthorityProviderCase(root, resource, AuthorityCase(root),
                                                oauth=source, credential_file=None)
                operation, arguments = 'profile.read', {}
            else:
                resource.routes[('GET', '/v1/tickets/7')] = {'id': 42}
                context = ManifestCase(root, resource, policy(root, resource), disclosure(),
                                       oauth=source, credential_file=None, source_override='oauth')
                operation, arguments = 'ticket.view', {'ticket': 7}
            with context as session:
                initial_expiry = case.row()['grant']['expires_at']
                assert initial_expiry < session.expires_at
                endpoint.routes[('POST', '/token')] = response(access_token=SUCCESSOR, refresh_token='SYNTHETIC-THIRD-REFRESH')
                case.call('refresh', now=int(time.time()), transport=case.transport(endpoint))
                time.sleep(max(0, initial_expiry + 1 - time.time()))
                reply = session.invoke(operation=operation, arguments=arguments)
                assert reply['ok'], reply
                assert resource.seen()[-1]['headers']['authorization'] == 'Bearer ' + SUCCESSOR


@pytest.mark.parametrize('profile', ['account', 'manifest'])
@pytest.mark.parametrize('boundary', ['reenroll', 'token-expiry', 'session-expiry'])
def test_current_token_does_not_bypass_session_boundaries(tmp_path, profile, boundary):
    vault = VaultCase(tmp_path)
    vault.enroll(access_token=TOKEN, expires_at=int(time.time()) + 3600)
    source = dict(vault_root=str(vault.root), provider_file=str(vault.provider_file),
                  subject='vm-test')
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        options = dict(oauth=source, credential_file=None,
                       lifetime=3 if boundary == 'session-expiry' else 300)
        if profile == 'account':
            session = AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path), **options)
            request = {}
            provider.routes[('GET', '/v1/account')] = dict(id=7, active=True)
        else:
            session = ManifestCase(tmp_path, provider, source_override='oauth', **options)
            request = dict(operation='ticket.view', arguments={'ticket': 7})
            provider.routes[('GET', '/v1/tickets/7')] = dict(id=7)
        with session:
            epoch = vault.row()['epoch']
            if boundary == 'reenroll':
                vault.call('revoke', now=int(time.time()))
                vault.enroll(access_token=TOKEN, expires_at=int(time.time()) + 3600)
                assert vault.row()['epoch'] != epoch
            elif boundary == 'token-expiry':
                # Trusted operator installs a shorter-lived current generation.
                # Delay TLS after acquisition; zero credentialed HTTP may escape.
                row = vault.row()
                row['grant'].update(access_token=SUCCESSOR,
                                    expires_at=int(time.time()) + 2, generation=1)
                vault.reference._write(vault.provider, 'vm-test', row)
                deadline = row['grant']['expires_at']
                accept = provider._server.get_request

                def delayed_accept():
                    time.sleep(max(0, deadline - time.time() + 0.05))
                    return accept()

                provider._server.get_request = delayed_accept
            else:
                # A fresh current generation cannot extend the original grant.
                row = vault.row()
                row['grant'].update(access_token=SUCCESSOR, generation=1)
                vault.reference._write(vault.provider, 'vm-test', row)
                time.sleep(max(0, session.expires_at - time.time() + 0.05))
            reply = session.invoke(**request)
            assert not reply['ok'], reply
            assert provider.seen() == []
            assert TOKEN not in json.dumps(reply) and SUCCESSOR not in json.dumps(reply)
            if boundary != 'session-expiry':
                with pytest.raises(SecretsError):
                    with vault.reference.current_lease(vault.provider, 'vm-test',
                            resource_host='api.example.org', expected_epoch=epoch):
                        pytest.fail('Python admitted the fenced/expired current lease')


def test_refresh_waits_for_both_provider_phases_and_next_request_uses_successor(tmp_path):
    vault = VaultCase(tmp_path)
    vault.enroll(access_token=TOKEN, expires_at=int(time.time()) + 3600)
    token_dir = tmp_path / 'tokens'
    token_dir.mkdir(mode=0o700)
    entered, release = threading.Event(), threading.Event()
    final_entered, final_release = threading.Event(), threading.Event()
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider, \
            TLSService(token_dir, host='login.example.org') as endpoint:
        def preflight(_):
            entered.set()
            assert release.wait(10)
            return 200, {}, json.dumps(dict(id=7, owner='alice', revision='a' * 40)).encode()

        provider.routes[('GET', '/v1/tickets/7')] = preflight
        def final(_):
            final_entered.set()
            assert final_release.wait(10)
            return 200, {}, b'{"id":7}'

        provider.routes[('GET', '/v1/revisions/' + 'a' * 40)] = final
        endpoint.routes[('POST', '/token')] = response()
        source = dict(vault_root=str(vault.root), provider_file=str(vault.provider_file),
                      subject='vm-test')
        p = checked(policy(tmp_path, provider))
        releases = {'revision.view': {'id': {'at': ['id'], 'type': 'integer'}},
                    'ticket.check': {'passed': {'at': ['passed'], 'type': 'boolean'}}}
        with ManifestCase(tmp_path, provider, p, releases, oauth=source,
                          credential_file=None, source_override='oauth') as session:
            request = dict(operation='revision.view', arguments={'ticket': 7})
            with ThreadPoolExecutor(max_workers=2) as pool:
                pending = pool.submit(session.invoke, **request)
                try:
                    assert entered.wait(10)
                    refresh = pool.submit(vault.call, 'refresh', now=int(time.time()),
                                          transport=vault.transport(endpoint))
                    time.sleep(0.1)
                    assert not refresh.done() and endpoint.seen() == []
                    release.set()
                    assert final_entered.wait(10)
                    assert not refresh.done() and endpoint.seen() == []
                finally:
                    release.set()
                    final_release.set()
                assert pending.result(timeout=10)['ok']
                refresh.result(timeout=10)
            assert [r['headers']['authorization'] for r in provider.seen()] == [
                'Bearer ' + TOKEN, 'Bearer ' + TOKEN]
            assert session.invoke(**request)['ok']
            assert [r['headers']['authorization'] for r in provider.seen()][2:] == [
                'Bearer ' + SUCCESSOR, 'Bearer ' + SUCCESSOR]
