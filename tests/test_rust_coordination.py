"""Native broker admission against independent Python/Rust durable mTLS authorities."""
from __future__ import annotations

from contextlib import ExitStack
import copy
from pathlib import Path
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aivm_secrets.identity.coordination import (
    CoordinationClient, CoordinationConfig, CoordinationLedger, CoordinationServer,
)
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.errors import SecretsError
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TLSService
from tests.test_secrets_coordination import _cert
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase, private
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory, policy


class CoordinatorCase:
    def __init__(self, root: Path):
        root.mkdir(mode=0o700)
        self.root = root
        authority = IdentityAuthority.initialize(root / 'ca',
            issuer='aivm.local', audience='aivm-secrets.identity')
        self.operator_material = _cert(authority, root, 'operator')
        self.members = [_cert(authority, root, name) for name in ('member-a', 'member-b', 'stranger')]
        self.certificate, self.key, self.ca = authority.tls_paths()
        self.ledger = CoordinationLedger.initialize(root / 'ledger')
        self.running = False

    def __enter__(self):
        self.stack = ExitStack()
        try:
            self.server = self.stack.enter_context(CoordinationServer(
                ('127.0.0.1', 0), ledger=self.ledger, server_cert=self.certificate,
                server_key=self.key, client_ca=self.ca,
                operator_fingerprints=[self.operator_material[2]]))
            self.worker = threading.Thread(target=self.server.serve_forever,
                                          kwargs={'poll_interval': 0.01})
            self.worker.start()
            self.running = True
            self.operator = self.client(self.operator_material)
            return self
        except BaseException:
            self.stop()
            self.stack.close()
            raise

    def __exit__(self, typ, error, tb):
        self.stop()
        return self.stack.__exit__(typ, error, tb)

    def stop(self):
        if self.running:
            self.server.shutdown()
            self.worker.join(timeout=5)
            assert not self.worker.is_alive()
            self.server.server_close()
            self.running = False

    def config(self, material):
        return dict(schema=1, host='localhost', port=self.server.server_address[1],
                    ca_file=str(self.ca), certificate_file=str(material[0]),
                    key_file=str(material[1]), principal='shared-principal')

    def client(self, material):
        return CoordinationClient(CoordinationConfig.parse(self.config(material)))

    def member_file(self, index=0):
        return private(self.root / f'member-{index}.json', self.config(self.members[index]))


@pytest.fixture(params=['python', 'rust'])
def coordinator_case(request):
    if request.param == 'python':
        return CoordinatorCase
    from tests.test_rust_coordinator_authority import NativeCoordinatorCase
    return NativeCoordinatorCase


@pytest.mark.parametrize('profile', ['account', 'manifest'])
def test_native_coordinator_revocation_denies_provider_and_control(tmp_path, profile, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([m[2] for m in coord.members[:2]])
        options = dict(coordination_file=str(coord.member_file()))
        if profile == 'account':
            session = AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path), **options)
            request = {}
            provider.routes[('GET', '/v1/account')] = dict(id=7, active=True)
        else:
            session = ManifestCase(tmp_path, provider, **options)
            request = dict(operation='ticket.view', arguments={'ticket': 7})
            provider.routes[('GET', '/v1/tickets/7')] = dict(id=7)
        with session:
            assert session.invoke(**request)['ok']
            assert len(provider.seen()) == 1
            coord.operator.revoke()
            for fields in (request, dict(verb='describe'), dict(verb='renounce')):
                reply = session.invoke(**fields)
                assert not reply['ok'] and reply['error']['code'] == 'revoked', reply
            assert len(provider.seen()) == 1


def write_request(key, text='hello'):
    return dict(operation='ticket.edit', arguments={'ticket': 7, 'text': text},
                request_fields={'idempotency_key': key})


@pytest.mark.parametrize('upstream_header', [False, True])
def test_two_native_hosts_share_reservations_across_restart(tmp_path, upstream_header, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([m[2] for m in coord.members[:2]])
        provider.routes[('PATCH', '/v1/tickets/7')] = dict(id=7)
        directories = [tmp_path / name for name in ('host-a', 'host-b', 'restart')]
        for directory in directories:
            directory.mkdir(mode=0o700)

        def session(index, directory):
            p = policy(directory, provider)
            if upstream_header:
                next(o for o in p['operations'] if o['name'] == 'ticket.edit')[
                    'idempotency_header'] = 'Idempotency-Key'
            return ManifestCase(directory, provider, p, writes='allow',
                                coordination_file=str(coord.member_file(index)))

        key = 'shared-retry-name-01'
        derived = codec.digest(dict(schema=1, principal='shared-principal', client_key=key))
        with session(0, directories[0]) as a, session(1, directories[1]) as b:
            assert not a.invoke(operation='ticket.edit',
                                arguments={'ticket': 7, 'text': 'unkeyed'})['ok']
            assert not a.invoke(operation='ticket.view', arguments={'ticket': 7},
                                request_fields={'idempotency_key': key})['ok']
            assert provider.seen() == []
            assert a.invoke(**write_request(key))['ok']
            sent = provider.seen()[0]
            assert sent['headers'].get('idempotency-key') == (derived if upstream_header else None)
            duplicate = b.invoke(**write_request(key, 'different body'))
            assert duplicate['error']['code'] == 'outcome_unknown', duplicate
            assert len(provider.seen()) == 1
            with pytest.raises(SecretsError, match='may have completed'):
                coord.client(coord.members[1]).reserve(derived, 'f' * 64)
            assert b.invoke(**write_request('another-retry-name-02'))['ok']
            assert len(provider.seen()) == 2
        with session(1, directories[2]) as restarted:
            reply = restarted.invoke(**write_request(key))
            assert reply['error']['code'] == 'outcome_unknown', reply
            assert len(provider.seen()) == 2


def test_concurrent_native_hosts_dispatch_one_write(tmp_path, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([m[2] for m in coord.members[:2]])
        provider.routes[('PATCH', '/v1/tickets/7')] = dict(id=7)
        sessions = []
        with ExitStack() as stack:
            for index in range(2):
                directory = tmp_path / f'host-{index}'
                directory.mkdir(mode=0o700)
                sessions.append(stack.enter_context(ManifestCase(directory, provider,
                    writes='allow', coordination_file=str(coord.member_file(index)))))
            with ThreadPoolExecutor(max_workers=2) as pool:
                replies = list(pool.map(lambda s: s.invoke(**write_request('one-racing-write-key')), sessions))
            assert sum(r['ok'] for r in replies) == 1, replies
            assert [r['error']['code'] for r in replies if not r['ok']] == ['outcome_unknown']
            assert len(provider.seen()) == 1


@pytest.mark.parametrize('failure', ['provider-error', 'completion-revocation'])
def test_uncertain_native_write_is_never_replayed(tmp_path, failure, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([coord.members[0][2]])

        def respond(_):
            if failure == 'completion-revocation':
                coord.operator.revoke()
            return (500 if failure == 'provider-error' else 200), {}, b'{"id":7}'

        provider.routes[('PATCH', '/v1/tickets/7')] = respond
        with ManifestCase(tmp_path, provider, writes='allow',
                          coordination_file=str(coord.member_file())) as session:
            reply = session.invoke(**write_request('uncertain-retry-name'))
            assert reply['error']['code'] == 'outcome_unknown', reply
            assert len(provider.seen()) == 1
            again = session.invoke(**write_request('uncertain-retry-name'))
            expected = 'revoked' if failure == 'completion-revocation' else 'outcome_unknown'
            assert again['error']['code'] == expected, again
            assert len(provider.seen()) == 1


@pytest.mark.parametrize('profile', ['account', 'manifest'])
def test_remote_revocation_during_provider_setup_prevents_http(tmp_path, profile, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([coord.members[0][2]])
        options = dict(coordination_file=str(coord.member_file()))
        if profile == 'account':
            session = AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path), **options)
            request = {}
        else:
            session = ManifestCase(tmp_path, provider, **options)
            request = dict(operation='ticket.view', arguments={'ticket': 7})
        accept = provider._server.get_request

        def revoke_before_tls():
            coord.operator.revoke()
            return accept()

        provider._server.get_request = revoke_before_tls
        with session:
            reply = session.invoke(**request)
            assert reply['error']['code'] == 'revoked', reply
            assert provider.seen() == []


@pytest.mark.parametrize('profile', ['account', 'manifest'])
def test_coordinator_outage_never_uses_cached_admission(tmp_path, profile, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([coord.members[0][2]])
        options = dict(coordination_file=str(coord.member_file()))
        if profile == 'account':
            session = AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path), **options)
            request = {}
            provider.routes[('GET', '/v1/account')] = dict(id=7, active=True)
        else:
            session = ManifestCase(tmp_path, provider, **options)
            request = dict(operation='ticket.view', arguments={'ticket': 7})
            provider.routes[('GET', '/v1/tickets/7')] = dict(id=7)
        with session:
            assert session.invoke(**request)['ok']
            coord.stop()
            reply = session.invoke(**request)
            assert reply['error']['code'] == 'revoked', reply
            assert len(provider.seen()) == 1


@pytest.mark.parametrize('member', [0, 2])
def test_unregistered_or_wrong_member_has_no_provider_authority(tmp_path, member, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        if member == 2:
            coord.operator.activate([coord.members[0][2]])
        with ManifestCase(tmp_path, provider,
                coordination_file=str(coord.member_file(member))) as session:
            reply = session.invoke(operation='ticket.view', arguments={'ticket': 7})
            assert reply['error']['code'] == 'revoked', reply
            assert not provider.seen()
            if member == 0:
                assert session.invoke(verb='renounce')['error']['code'] == 'revoked'
                coord.operator.activate([coord.members[0][2]])
                provider.routes[('GET', '/v1/tickets/7')] = dict(id=7)
                assert session.invoke(operation='ticket.view', arguments={'ticket': 7})['ok']


@pytest.mark.parametrize('key', [None, True, 17, 'short', 'x'*129, 'with space', 'line\nbreak', 'unicode-é-key'])
def test_native_retry_names_are_strict_transport_metadata(tmp_path, key, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([coord.members[0][2]])
        with ManifestCase(tmp_path, provider, writes='allow',
                          coordination_file=str(coord.member_file())) as session:
            reply = session.invoke(**write_request(key))
            assert reply['error']['code'] == 'invalid_request', reply
            assert provider.seen() == []


def test_file_loaded_coordinator_config_supports_only_explicit_localhost_exception(tmp_path, coordinator_case):
    # This file-load path previously contradicted the working direct client.
    with coordinator_case(tmp_path / 'coord') as coord:
        value = coord.config(coord.members[0])
        assert CoordinationConfig.parse(value).host == 'localhost'
        for host in (None, True, 1, 'LOCALHOST', '127.0.0.1', 'localhost.', 'bad.local', 'x\r\nHost:y'):
            with pytest.raises(SecretsError):
                CoordinationConfig.parse(dict(value, host=host))


@pytest.mark.parametrize('first_backend', ['python', 'rust'])
@pytest.mark.parametrize('native_spelling', ['input', 'normalized', 'reordered'])
def test_python_and_native_brokers_share_global_retry_names(tmp_path, first_backend,
                                                           native_spelling, coordinator_case):
    """Both live backends act, and neither replays the other's reserved key."""
    from aivm_secrets.host.egress import HTTPSExecutor
    from aivm_secrets.kernel.service import parse_policy
    from tests.secrets_helpers import Harness, TOKEN

    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([m[2] for m in coord.members[:2]])
        provider.routes[('PATCH', '/v1/tickets/7')] = dict(id=7)
        native_dir, reference_dir = tmp_path / 'native', tmp_path / 'reference'
        native_dir.mkdir(mode=0o700)
        reference_dir.mkdir(mode=0o700)
        p = policy(native_dir, provider)
        next(o for o in p['operations'] if o['name'] == 'ticket.edit')[
            'idempotency_header'] = 'Idempotency-Key'
        spec = parse_policy(p)
        reference = Harness(reference_dir, policy=p, writes='allow',
                            executor=HTTPSExecutor(spec.egress))
        reference.broker._coordination = coord.client(coord.members[1])
        native_policy = copy.deepcopy(p)
        if native_spelling == 'normalized':
            native_policy = spec.to_dict()
        elif native_spelling == 'reordered':
            native_policy['operations'].reverse()
            for operation in native_policy['operations']:
                for values in operation.get('parameters', {}).values():
                    if isinstance(values, list):
                        values.reverse()
        try:
            with ManifestCase(native_dir, provider, native_policy, writes='allow',
                              coordination_file=str(coord.member_file())) as native:
                def call(backend, key):
                    if backend == 'rust':
                        return native.invoke(**write_request(key))
                    payload = dict(operation='ticket.edit',
                                   arguments={'ticket': 7, 'text': 'hello'},
                                   idempotency_key=key)
                    return reference.broker.handle(reference.frame('request', payload))

                other = 'rust' if first_backend == 'python' else 'python'
                key = 'cross-language-retry-01'
                allowed = call(first_backend, key)
                assert allowed['ok'], allowed
                denied = call(other, key)
                assert denied['error']['code'] == 'outcome_unknown', denied
                assert len(provider.seen()) == 1
                assert call(other, 'cross-language-retry-02')['ok']
                assert call(first_backend, 'cross-language-retry-02')['error'][
                    'code'] == 'outcome_unknown'
                assert len(provider.seen()) == 2
                assert provider.seen()[0]['headers']['idempotency-key'] == codec.digest(
                    dict(schema=1, principal='shared-principal', client_key=key))
                assert all(r['headers']['authorization'] == 'Bearer ' + TOKEN
                           for r in provider.seen())
                assert TOKEN not in codec.dumps([allowed, denied]).decode()
                # Inspect the real durable records, not just duplicate denial:
                # that denial deliberately hides fingerprint differences.
                expected = codec.digest(dict(policy=spec.digest, request=dict(
                    operation='ticket.edit', arguments={'ticket': 7, 'text': 'hello'})))
                with sqlite3.connect(coord.ledger.path) as db:
                    records = db.execute('SELECT digest,state FROM writes').fetchall()
                assert len(records) == 2
                assert records == [(expected, 'completed')] * 2
        finally:
            reference.broker.close()


def test_native_idempotency_policy_field_matches_python(tmp_path):
    from tests.test_rust_garrett_manifest import compile_rows, reference_compile
    import copy
    rows = []
    for operation in ('ticket.view', 'ticket.edit'):
        for field in ('', 'Idempotency-Key', 'X-Retry-Key', None, True, 1, [], {}):
            p = copy.deepcopy(policy(tmp_path))
            next(o for o in p['operations'] if o['name'] == operation)[
                'idempotency_header'] = field
            arguments = {'ticket': 7}
            if operation == 'ticket.edit':
                arguments['text'] = 'hello'
            rows.append(dict(policy=p, request=dict(operation=operation, arguments=arguments)))
    assert compile_rows(rows) == [reference_compile(r['policy'], r['request']) for r in rows]


@pytest.mark.parametrize('profile', ['account', 'manifest'])
def test_native_coordinator_never_falls_back_from_selected_trust_anchor(tmp_path, profile, coordinator_case):
    with coordinator_case(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([coord.members[0][2]])
        config = coord.config(coord.members[0])
        config['ca_file'] = str(provider.files['ca'])
        path = private(coord.root / 'wrong-ca.json', config)
        if profile == 'account':
            session = AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path),
                                            coordination_file=str(path))
            request = {}
        else:
            session = ManifestCase(tmp_path, provider, coordination_file=str(path))
            request = dict(operation='ticket.view', arguments={'ticket': 7})
        with session:
            reply = session.invoke(**request)
            assert reply['error']['code'] == 'revoked', reply
            assert provider.seen() == []


@pytest.mark.parametrize('profile', ['account', 'manifest'])
@pytest.mark.parametrize('verb', ['describe', 'renounce'])
@pytest.mark.parametrize('boundary', ['outer', 'current-token'])
def test_coordinator_wait_cannot_extend_control_authority(tmp_path, profile, verb, boundary):
    import time
    from tests.test_rust_garrett_dispatch import shorter_surrogate

    with CoordinatorCase(tmp_path / 'coord') as coord, \
            TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        coord.operator.activate([coord.members[0][2]])
        options = dict(coordination_file=str(coord.member_file()))
        if boundary == 'current-token':
            from tests.test_rust_garrett_oauth_vault import VaultCase
            from tests.secrets_helpers import TOKEN
            vault = VaultCase(tmp_path)
            vault.enroll(access_token=TOKEN, expires_at=int(time.time()) + 3600)
            options.update(oauth=dict(vault_root=str(vault.root),
                provider_file=str(vault.provider_file), subject='vm-test'), credential_file=None)
            if profile == 'manifest':
                options['source_override'] = 'oauth'
        session = (AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path), **options)
                   if profile == 'account' else ManifestCase(tmp_path, provider, **options))
        with session:
            original_token = session.token
            if boundary == 'outer':
                session.token, expires = shorter_surrogate(session)
            else:
                row = vault.row()
                expires = int(time.time()) + 3
                row['grant']['expires_at'] = expires
                vault.reference._write(vault.provider, 'vm-test', row)
            check = coord.ledger.check
            waited = []

            def delayed_positive_check(name, peer):
                result = check(name, peer)
                if not waited:
                    waited.append(True)
                    time.sleep(max(0, expires - time.time() + 0.05))
                return result

            coord.ledger.check = delayed_positive_check
            reply = session.invoke(verb=verb)
            assert not reply['ok'], reply
            session.token = original_token
            if boundary == 'current-token':
                row['grant']['expires_at'] = int(time.time()) + 3600
                vault.reference._write(vault.provider, 'vm-test', row)
            assert session.invoke(verb='describe')['ok']
            assert provider.seen() == []
