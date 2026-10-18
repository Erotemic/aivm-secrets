"""Python Garrett core boundaries: live OAuth rollover and keyed dispatch."""
from __future__ import annotations

import copy
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from aivm_secrets import guest
from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.coordination import CoordinationLedger
from aivm_secrets.identity.oauth_vault import OAuthVault
from tests.secrets_helpers import FakeExecutor, Harness, https_policy
from tests.test_secrets_garrett_oauth import FakeOAuth, grant, provider, reply
from aivm_secrets.kernel import codec


class LocalCoordination:
    """Use the same atomic disk decisions as remote hosts, without TLS I/O."""

    def __init__(self, ledger, principal='principal-a', peer='a'*64):
        self.config = SimpleNamespace(principal=principal)
        self.ledger, self.peer = ledger, peer

    def check(self):
        self.ledger.check(self.config.principal, self.peer)

    def reserve(self, key, digest):
        self.ledger.reserve(self.config.principal, self.peer, key, digest)

    def finish(self, key, digest):
        self.ledger.finish(self.config.principal, self.peer, key, digest)


class HeaderExecutor(FakeExecutor):
    def __init__(self):
        super().__init__()
        self.idempotency_keys = []

    def execute(self, authorized, credential, *, idempotency_key=None):
        self.idempotency_keys.append(idempotency_key)
        return super().execute(authorized, credential)


def _keyed_policy():
    policy = https_policy(max_requests=12)
    policy['operations'] = copy.deepcopy(policy['operations'])
    for item in policy['operations']:
        if item['name'] == 'issue.comment':
            item['idempotency_header'] = 'Idempotency-Key'
    return policy


def _request(body, key=None):
    request = {'operation': 'issue.comment',
               'arguments': {'issue': 23, 'body': body}}
    if key is not None:
        request['idempotency_key'] = key
    return request


def _send(harness, request):
    return harness.broker.handle(harness.frame('request', request))


def test_keyed_dispatch_across_sessions_and_payload_conflicts(tmp_path):
    ledger = CoordinationLedger.initialize(tmp_path / 'ledger')
    ledger.activate('principal-a', ['a'*64, 'b'*64])
    first_exec = HeaderExecutor()
    first = Harness(tmp_path / 'first', writes='allow',
                    policy=_keyed_policy(), executor=first_exec)
    first.broker._coordination = LocalCoordination(ledger)
    try:
        issued = _send(first, _request('comment', 'stable-retry-key-01'))
        assert issued['ok'], issued
        assert len(first_exec.calls) == 1
        assert first_exec.idempotency_keys[0] is not None
        assert len(first_exec.idempotency_keys[0]) == 64
        replay = _send(first, _request('comment', 'stable-retry-key-01'))
        assert replay['error']['code'] == 'outcome_unknown'
        assert len(first_exec.calls) == 1
    finally:
        first.broker.close()

    second_exec = HeaderExecutor()
    second = Harness(tmp_path / 'second', writes='allow',
                     policy=_keyed_policy(), executor=second_exec)
    second.broker._coordination = LocalCoordination(
        CoordinationLedger(tmp_path / 'ledger'), peer='b'*64)
    try:
        assert _send(second, _request('comment', 'stable-retry-key-01'))['error']['code'] == 'outcome_unknown'
        assert _send(second, _request('different', 'stable-retry-key-01'))['error']['code'] == 'outcome_unknown'
        assert not second_exec.calls
        other = _send(second, _request('comment', 'new-retry-key-0002'))
        assert other['ok'], other
        assert len(second_exec.calls) == 1
        ledger.revoke('principal-a')
        denied = _send(second, _request('comment', 'another-retry-key'))
        assert denied['error']['code'] == 'revoked'
        assert len(second_exec.calls) == 1
    finally:
        second.broker.close()


def test_missing_key_read_key_and_missing_coordinator_fail_closed(tmp_path):
    h = Harness(tmp_path / 'h', writes='allow', policy=_keyed_policy(),
                executor=HeaderExecutor())
    try:
        assert _send(h, _request('comment'))['error']['code'] == 'invalid_request'
        assert _send(h, _request('comment', 'stable-key-1234'))['error']['code'] == 'invalid_request'
        assert not h.executor.calls
    finally:
        h.broker.close()
    ledger = CoordinationLedger.initialize(tmp_path / 'ledger')
    ledger.activate('principal-a', ['a'*64])
    plain = Harness(tmp_path / 'plain', writes='allow', policy=https_policy())
    plain.broker._coordination = LocalCoordination(ledger)
    try:
        read = {'operation':'issue.view', 'arguments':{'issue':23},
                'idempotency_key':'key-for-a-read'}
        assert _send(plain, read)['error']['code'] == 'invalid_request'
        assert not plain.executor.calls
        # A coordinated session requires keys even for a provider that has
        # no native Idempotency-Key semantics, preventing unkeyed retries.
        no_key = _send(plain, _request('comment'))
        assert no_key['error']['code'] == 'invalid_request'
        assert not plain.executor.calls
        with_key = _send(plain, _request('comment', 'legacy-provider-key-01'))
        assert with_key['ok'], with_key
        assert len(plain.executor.calls) == 1
    finally:
        plain.broker.close()


def test_malformed_or_shadowed_provider_idempotency_headers(tmp_path):
    from aivm_secrets.kernel.service import parse_policy
    for bad in ('any-header', 'X-Idempotency-Key', None, 1):
        policy = _keyed_policy()
        policy['operations'][-1]['idempotency_header'] = bad
        # Modifying last operation may be a read; still rejected.
        with pytest.raises(SecretsError):
            parse_policy(policy)
    bad = https_policy(headers={'Idempotency-Key':'operator-injected'})
    with pytest.raises(SecretsError):
        parse_policy(bad)


def test_guest_cli_can_send_explicit_key_without_rewriting_arguments():
    args = guest.parser().parse_args([
        'invoke', 'issue.comment', '--arguments', '{"issue":23,"body":"hello"}',
        '--idempotency-key', 'stable-key-1234'])
    kind, payload = guest.frame_from_args(args)
    assert kind == 'request' and payload == {
        'operation':'issue.comment', 'arguments': {'issue':23,'body':'hello'},
        'idempotency_key':'stable-key-1234',
    }


def test_running_oauth_broker_uses_new_token_and_revoke_fences_epoch(tmp_path):
    profile = provider()
    stamp = int(time.time())
    vault = OAuthVault.initialize(tmp_path / 'vault')
    vault.enroll(profile, 'agent', grant('ACCESS-ONE', 'REFRESH-ONE', now=stamp))
    snapshot = vault.session_snapshot(profile, 'agent', resource_host=profile.resource_host)
    assert snapshot.credential == 'ACCESS-ONE'
    h = Harness(tmp_path / 'h', policy=https_policy(),
                token='oauth-host-managed-session')
    h.broker._credential_context = lambda: vault.current_lease(
        profile, 'agent', resource_host=profile.resource_host,
        expected_epoch=snapshot.epoch)
    try:
        assert h.invoke('issue.view', issue=23)['ok']
        assert h.executor.calls[-1][1] == 'ACCESS-ONE'
        original_capability = h.capability
        new_grant = vault.refresh(profile, 'agent', transport=FakeOAuth(
            [reply('ACCESS-TWO', 'REFRESH-TWO')]))
        assert new_grant['generation'] == 1
        assert h.invoke('issue.view', issue=23)['ok']
        assert h.executor.calls[-1][1] == 'ACCESS-TWO'
        assert h.capability == original_capability
        assert 'ACCESS-ONE' not in str(h.broker.status())
        vault.revoke(profile, 'agent')
        before = len(h.executor.calls)
        assert h.invoke('issue.view', issue=23)['error']['code'] == 'revoked'
        assert len(h.executor.calls) == before
        vault.enroll(profile, 'agent', grant('ACCESS-THREE', 'REFRESH-THREE', now=stamp),
                     replace=True)
        assert h.invoke('issue.view', issue=23)['error']['code'] == 'revoked'
        assert len(h.executor.calls) == before
    finally:
        h.broker.close()


def test_https_egress_sends_only_host_derived_idempotency_header(tmp_path):
    """The real provider wire sees the derived key, not the guest's raw key."""
    from aivm_secrets.host.egress import HTTPSExecutor
    from aivm_secrets.kernel.machine import AuthorizedEffect
    from aivm_secrets.kernel.model import Egress, Effect
    from tests.secrets_helpers import TLSService, SERVICE_TOKEN

    (tmp_path / 'tls').mkdir(mode=0o700)
    with TLSService(tmp_path / 'tls') as service:
        service.routes[('POST', '/v1/issues/23/comments')] = {'ok': True}
        egress = Egress(service.host, service.port, '127.0.0.1',
                        str(service.files['ca']), 'bearer')
        executor = HTTPSExecutor(egress)
        effect = Effect('POST', '/v1/issues/23/comments',
                        body=(('body', 'hello'),))
        authorized = AuthorizedEffect(0, 'a'*32, 'd'*64, True, True, effect)
        key = 'b'*64
        assert executor.execute(authorized, SERVICE_TOKEN,
                                idempotency_key=key) == {'ok': True}
        assert service.requests[0]['headers']['idempotency-key'] == key
        assert service.requests[0]['headers']['authorization'] == 'Bearer ' + SERVICE_TOKEN
        before = len(service.requests)
        read_effect = Effect('GET', '/v1/issues/23')
        with pytest.raises(SecretsError):
            executor.execute(AuthorizedEffect(0, 'a'*32, 'd'*64, True, False,
                                              read_effect), SERVICE_TOKEN,
                             idempotency_key=key)
        with pytest.raises(SecretsError):
            executor.execute(authorized, SERVICE_TOKEN,
                             idempotency_key='guest-controlled')
        assert len(service.requests) == before


def test_ambiguous_write_reservation_survives_broker_restart(tmp_path):
    """Provider failure is ambiguous, and a new session cannot replay it."""
    class FailedWrite(HeaderExecutor):
        def execute(self, authorized, credential, *, idempotency_key=None):
            self.idempotency_keys.append(idempotency_key)
            self.calls.append((authorized, credential))
            raise SecretsError('upstream_error')

    ledger = CoordinationLedger.initialize(tmp_path / 'ledger')
    ledger.activate('principal-a', ['a'*64, 'b'*64])
    first_executor = FailedWrite()
    h = Harness(tmp_path / 'one', writes='allow', policy=_keyed_policy(),
                executor=first_executor)
    h.broker._coordination = LocalCoordination(ledger)
    try:
        first = _send(h, _request('hello', 'stable-key-ambiguous'))
        assert first['error']['code'] == 'outcome_unknown'
        assert len(first_executor.calls) == 1
    finally:
        h.broker.close()
    next_executor = HeaderExecutor()
    next_h = Harness(tmp_path / 'two', writes='allow', policy=_keyed_policy(),
                     executor=next_executor)
    next_h.broker._coordination = LocalCoordination(
        CoordinationLedger(tmp_path / 'ledger'), peer='b'*64)
    try:
        retry = _send(next_h, _request('hello', 'stable-key-ambiguous'))
        assert retry['error']['code'] == 'outcome_unknown'
        assert next_executor.calls == []
    finally:
        next_h.broker.close()


def test_global_revocation_fences_delegate_and_describe(tmp_path):
    ledger = CoordinationLedger.initialize(tmp_path / 'ledger')
    ledger.activate('principal-a', ['a'*64])
    h = Harness(tmp_path / 'h', policy=https_policy())
    h.broker._coordination = LocalCoordination(ledger)
    try:
        assert h.broker.handle(h.frame('describe', True))['ok']
        ledger.revoke('principal-a')
        for verb in ('describe', 'delegate', 'renounce'):
            payload = (True if verb != 'delegate' else {'ttl_seconds': 30})
            response = h.broker.handle(h.frame(verb, payload))
            assert response['error']['code'] == 'revoked', (verb, response)
    finally:
        h.broker.close()


def test_bound_certificate_and_token_renew_without_restarting_services(tmp_path):
    """The same broker and bridge accept a newly pinned CSR/JWT."""
    import threading
    from aivm_secrets.host.server import LocalServer
    from aivm_secrets.identity.service import UnixIdentityService
    from aivm_secrets.identity.certificates import inspect_csr
    from tests.test_secrets_identity_service import start, call, view_request

    authority, key, old, jwt, harness = start(tmp_path)
    listen = tmp_path / 'bridge' / 'session.sock'
    try:
        with LocalServer(harness.broker, tmp_path / 'broker') as broker:
            with UnixIdentityService(
                authority=authority, broker_socket=broker.socket_path,
                listen=listen, max_connections=3, idle_seconds=12,
            ) as bridge:
                thread = threading.Thread(target=bridge.serve)
                thread.start()
                assert call(listen, authority, old, key, jwt, view_request())['ok']
                csr = tmp_path / 'vm.csr'
                # Exercise the new operator workflow, not just the library.
                import json
                import subprocess
                import sys
                capfile = tmp_path / 'broker.cap'
                capfile.write_text(harness.capability)
                capfile.chmod(0o600)
                new_jwt = tmp_path / 'bound-renewed.jwt'
                completed = subprocess.run([
                    sys.executable, '-I', '-c',
                    ('import sys; sys.path.insert(0, '
                     + repr(str(Path(__file__).resolve().parents[1])) + '); '
                     'from aivm_secrets.cli import main; '
                     'raise SystemExit(main(sys.argv[1:]))'),
                    'identity', 'renew-bound', '--root', str(tmp_path / 'host'),
                    '--subject', 'vm-alpha', '--csr', str(csr),
                    '--approve-key-fingerprint', inspect_csr(csr.read_bytes()),
                    '--expected-epoch', str(old['epoch']),
                    '--expected-certificate-sha256', old['certificate_sha256'],
                    '--capability-file', str(capfile),
                    '--jwt-output', str(new_jwt),
                ], capture_output=True, text=True, timeout=20)
                assert completed.returncode == 0, completed.stderr
                renewed = json.loads(completed.stdout)
                assert new_jwt.exists()
                assert harness.capability not in completed.stdout
                old_result = call(listen, authority, old, key, jwt,
                                  view_request())
                assert old_result['error']['code'] == 'invalid_capability'
                new_result = call(listen, authority, renewed, key,
                                  new_jwt, view_request())
                assert new_result['ok']
                assert len(harness.executor.calls) == 2
                thread.join(timeout=10)
                assert not thread.is_alive()
    finally:
        harness.broker.close()


def test_credential_context_cannot_seal_the_callers_initial_bearer(tmp_path):
    from contextlib import nullcontext
    from aivm_secrets.host.broker import Broker
    h = Harness(tmp_path / 'fixture', policy=https_policy())
    try:
        executor = FakeExecutor()
        broker = Broker(
            h.spec, h.binding, 'INITIAL-BEARER-SECRET-THAT-SHOULD-NOT-BE-SEALED',
            tmp_path / 'leased' / 'audit.jsonl', executor=executor,
            credential_context=lambda: nullcontext('CURRENT-BEARER-SECRET'),
        )
        try:
            opened = broker._codec.open(broker.capability)
            assert opened.credential == 'oauth-host-managed-session'
            assert opened.credential != 'INITIAL-BEARER-SECRET-THAT-SHOULD-NOT-BE-SEALED'
            reply = broker.handle(h.frame('request',
                {'operation': 'issue.view', 'arguments': {'issue': 23}},
                broker.capability))
            assert reply['ok'], reply
            assert executor.calls[-1][1] == 'CURRENT-BEARER-SECRET'
        finally:
            broker.close()
    finally:
        h.broker.close()
