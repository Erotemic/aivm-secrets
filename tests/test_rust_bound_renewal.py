"""Rebind a running native grant to a renewed same-key client certificate."""
from __future__ import annotations

import time
import base64
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from aivm_secrets.identity.certificates import inspect_csr
from aivm_secrets.identity.enrollment import IdentityAuthority
from tests.test_rust_garrett_certificates import request as client_request

from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase, private
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory


def same_key_csr(session):
    key = serialization.load_pem_private_key(session.certs['client1'][1].read_bytes(), None)
    _, csr = client_request(key)
    return private(session.directory / 'renewal.csr', csr.encode())


@pytest.mark.parametrize('profile', ['account', 'manifest'])
def test_native_rebinding_uses_same_running_grant_with_new_certificate(tmp_path, profile):
    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        if profile == 'account':
            authority = AuthorityCase(tmp_path)
            session = AuthorityProviderCase(tmp_path, provider, authority)
            request = {}
            provider.routes[('GET', '/v1/account')] = dict(id=7, active=True)
        else:
            session = ManifestCase(tmp_path, provider)
            authority = session.authority
            request = dict(operation='ticket.view', arguments={'ticket': 7})
            provider.routes[('GET', '/v1/tickets/7')] = dict(id=7)
        with session:
            pid = session.process.pid
            assert session.invoke(**request)['ok']
            before = authority.call('public-client', subject='vm-test')
            reference = IdentityAuthority(authority.root)
            old_der = x509.load_pem_x509_certificate(
                session.certs['client1'][0].read_bytes()).public_bytes(serialization.Encoding.DER)
            old_expected = reference.expectation_for_peer(old_der, int(time.time()))
            old_inner = reference.token_verifier(old_expected).open(session.token,
                authenticated_peer_der=old_der, now=int(time.time())).broker_capability
            source = private(tmp_path / 'original.jwt', session.token.encode())
            renewed = authority.call('renew', subject='vm-test', csr_file=str(same_key_csr(session)),
                approve_fingerprint=inspect_csr((tmp_path / 'renewal.csr').read_bytes()), expected_epoch=before['epoch'],
                expected_thumbprint=before['certificate_sha256'], now=int(time.time()))
            output = tmp_path / 'rebound.jwt'
            result = authority.call('rebind', subject='vm-test', surrogate_file=str(source),
                expected_epoch=renewed['epoch'], expected_thumbprint=renewed['certificate_sha256'],
                output=str(output), client_assurance='any-enrolled', now=int(time.time()))
            assert output.exists() and output.stat().st_mode & 0o777 == 0o600
            assert TOKEN not in str(result) and session.token not in str(result)
            assert not session.invoke(**request)['ok']  # old pair is fenced
            old_cert, key, extra = session.certs['client1']
            fresh_cert = private(tmp_path / 'renewed-client.pem',
                                 base64.b64decode(authority.call(
                                     'public-client', subject='vm-test')['certificate_pem_b64']))
            session.certs['client1'] = (fresh_cert, key, extra)
            assert not session.invoke(**request)['ok']  # old JWT + new cert
            session.token = output.read_text()
            assert old_inner not in json.dumps(result)
            fresh_der = x509.load_pem_x509_certificate(
                fresh_cert.read_bytes()).public_bytes(serialization.Encoding.DER)
            expected = reference.expectation_for_peer(fresh_der, int(time.time()))
            assert reference.token_verifier(expected).open(session.token,
                authenticated_peer_der=fresh_der, now=int(time.time())).broker_capability == old_inner
            session.certs['client1'] = (old_cert, key, extra)
            assert not session.invoke(**request)['ok']  # new JWT + old cert
            session.certs['client1'] = (fresh_cert, key, extra)
            reply = session.invoke(**request)
            assert reply['ok'], reply
            assert session.process.pid == pid
            assert len(provider.seen()) == 2
            assert all(r['headers']['authorization'] == 'Bearer ' + TOKEN for r in provider.seen())


class RebindingCase:
    def __init__(self, directory, *, lifetime=300, **provider_options):
        self.directory, self.lifetime = directory, lifetime
        self.provider_options = provider_options

    def __enter__(self):
        from contextlib import ExitStack
        self.stack = ExitStack()
        try:
            self.provider = self.stack.enter_context(TLSService(provider_directory(self.directory), host='api.example.org'))
            self.provider.routes[('GET', '/v1/account')] = dict(id=7, active=True)
            self.authority = AuthorityCase(self.directory)
            self.session = self.stack.enter_context(AuthorityProviderCase(
                self.directory, self.provider, self.authority, lifetime=self.lifetime,
                **self.provider_options))
            self.target = self.authority.call('public-client', subject='vm-test')
            self.source = private(self.directory / 'source.jwt', self.session.token.encode())
            self.output = self.directory / 'new.jwt'
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, typ, error, tb):
        return self.stack.__exit__(typ, error, tb)

    def renew(self, *, new_key=False):
        if new_key:
            _, csr = client_request()
            path = private(self.directory / 'new-key.csr', csr.encode())
        else:
            path = same_key_csr(self.session)
        self.target = self.authority.call('renew', subject='vm-test', csr_file=str(path),
            approve_fingerprint=inspect_csr(path.read_bytes()), expected_epoch=self.target['epoch'],
            expected_thumbprint=self.target['certificate_sha256'], require_new_key=new_key,
            now=int(time.time()))
        return self.target

    def rebind(self, *, error=None, **changes):
        request = dict(subject='vm-test', surrogate_file=str(self.source),
            expected_epoch=self.target['epoch'], expected_thumbprint=self.target['certificate_sha256'],
            output=str(self.output), client_assurance='any-enrolled', now=int(time.time()))
        request.update(changes)
        return self.authority.call('rebind', error=error, **request)


@pytest.mark.parametrize('attack', ['stale-epoch', 'wrong-certificate', 'different-key',
                                     'other-subject', 'revoked', 'retired-issuer', 'tampered'])
def test_rebinding_refuses_stale_or_retargeted_authority(tmp_path, attack):
    with RebindingCase(tmp_path) as case:
        case.renew(new_key=attack == 'different-key')
        fields = {}
        code = 'revoked'
        if attack == 'stale-epoch':
            fields['expected_epoch'] = case.target['epoch'] - 1
        elif attack == 'wrong-certificate':
            fields['expected_thumbprint'] = 'A' * 43
        elif attack == 'other-subject':
            _, _, other = case.authority.enroll(subject='other-principal')
            fields.update(subject='other-principal', expected_epoch=other['epoch'],
                          expected_thumbprint=other['certificate_sha256'])
        elif attack == 'revoked':
            case.authority.call('revoke', subject='vm-test')
        elif attack == 'retired-issuer':
            case.authority.call('rotate-issuer')
            case.authority.call('retire-issuer', kid='local-1')
        elif attack == 'tampered':
            value = case.source.read_text()
            # Alter a signed payload byte, retaining its framing.
            pieces = value.split('.')
            pieces[1] = ('A' if pieces[1][0] != 'A' else 'B') + pieces[1][1:]
            private(case.source, '.'.join(pieces).encode())
            code = 'invalid_capability'
        case.rebind(error=code, **fields)
        assert not case.output.exists()
        assert case.provider.seen() == []


@pytest.mark.parametrize('unsafe', ['source-mode', 'source-symlink', 'output-exists', 'output-parent-symlink'])
def test_rebinding_respects_private_inputs_and_no_replace_publication(tmp_path, unsafe):
    with RebindingCase(tmp_path) as case:
        case.renew()
        if unsafe == 'source-mode':
            case.source.chmod(0o644)
        elif unsafe == 'source-symlink':
            real = case.source.with_suffix('.real')
            case.source.rename(real)
            case.source.symlink_to(real)
        elif unsafe == 'output-exists':
            private(case.output, b'KEEP-EXISTING-OUTPUT')
        else:
            parent = tmp_path / 'actual'
            parent.mkdir(mode=0o700)
            link = tmp_path / 'linked'
            link.symlink_to(parent, target_is_directory=True)
            case.output = link / 'new.jwt'
        case.rebind(error='unsafe_file')
        if unsafe == 'output-exists':
            assert case.output.read_bytes() == b'KEEP-EXISTING-OUTPUT'
        else:
            assert not case.output.exists()
        assert case.provider.seen() == []


def test_software_rebinding_cannot_satisfy_a_tpm_required_output(tmp_path):
    with RebindingCase(tmp_path) as case:
        case.renew()
        case.rebind(error='denied', client_assurance='attested-tpm')
        assert not case.output.exists()
        assert case.provider.seen() == []


def test_rebinding_can_refresh_an_expired_outer_but_preserves_original_grant(tmp_path):
    from tests.test_rust_garrett_dispatch import shorter_surrogate
    with RebindingCase(tmp_path) as case:
        case.session.token, expires = shorter_surrogate(case.session)
        private(case.source, case.session.token.encode())
        time.sleep(max(0, expires - time.time() + 0.05))
        assert not case.session.invoke()['ok']
        case.rebind()
        case.session.token = case.output.read_text()
        assert case.session.invoke()['ok']
        assert len(case.provider.seen()) == 1


def test_rebinding_does_not_extend_an_expired_inner_grant(tmp_path):
    with RebindingCase(tmp_path, lifetime=3) as case:
        assert case.session.invoke()['ok']
        deadline = case.session.expires_at
        time.sleep(max(0, deadline - time.time() + 0.05))
        case.renew()
        case.rebind()
        cert = private(tmp_path / 'fresh.pem', base64.b64decode(case.authority.call(
            'public-client', subject='vm-test')['certificate_pem_b64']))
        _, key, extra = case.session.certs['client1']
        case.session.certs['client1'] = (cert, key, extra)
        case.session.token = case.output.read_text()
        assert not case.session.invoke()['ok']
        assert len(case.provider.seen()) == 1


def test_rebinding_reads_target_after_waiting_for_authority_lease(tmp_path):
    import fcntl
    from concurrent.futures import ThreadPoolExecutor
    from aivm_secrets.primitives import codec

    with RebindingCase(tmp_path) as case:
        case.renew()
        with (case.authority.root / '.enrollment.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(case.rebind, error='revoked')
                try:
                    time.sleep(0.1)
                    assert not pending.done()
                    path = case.authority.root / 'enrollments.json'
                    state = codec.loads(path.read_bytes())
                    state['subjects']['vm-test']['active'] = False
                    state['subjects']['vm-test']['epoch'] += 1
                    private(path, codec.dumps(state))
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                pending.result(timeout=10)
        assert not case.output.exists()
        assert case.provider.seen() == []


def test_identity_rebinding_cannot_reverse_terminal_global_revocation(tmp_path):
    from tests.test_rust_coordination import CoordinatorCase
    with CoordinatorCase(tmp_path / 'coord') as coord:
        coord.operator.activate([coord.members[0][2]])
        with RebindingCase(tmp_path, coordination_file=str(coord.member_file())) as case:
            assert case.session.invoke()['ok']
            coord.operator.revoke()
            case.renew()
            case.rebind()
            certificate = private(tmp_path / 'current.pem', base64.b64decode(case.authority.call(
                'public-client', subject='vm-test')['certificate_pem_b64']))
            _, key, extra = case.session.certs['client1']
            case.session.certs['client1'] = (certificate, key, extra)
            case.session.token = case.output.read_text()
            reply = case.session.invoke()
            assert reply['error']['code'] == 'revoked', reply
            assert len(case.provider.seen()) == 1
            assert coord.ledger.status('shared-principal')['active'] is False


def test_pruned_source_certificate_never_selects_another_key(tmp_path):
    with RebindingCase(tmp_path) as case:
        old_thumb = case.target['certificate_sha256']
        case.renew()
        digest = base64.urlsafe_b64decode(old_thumb + '=' * (-len(old_thumb) % 4)).hex()
        (case.authority.root / 'clients' / (digest + '.pem')).unlink()
        case.rebind(error='unsafe_file')
        assert not case.output.exists()


def test_normal_rebinding_samples_issuance_time_after_authority_wait(tmp_path):
    import fcntl
    from concurrent.futures import ThreadPoolExecutor
    from aivm_secrets.primitives import codec

    with RebindingCase(tmp_path) as case:
        with (case.authority.root / '.enrollment.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with ThreadPoolExecutor(max_workers=1) as pool:
                initial = int(time.time())
                pending = pool.submit(case.authority.call, 'rebind', subject='vm-test',
                    surrogate_file=str(case.source), expected_epoch=case.target['epoch'],
                    expected_thumbprint=case.target['certificate_sha256'],
                    output=str(case.output), client_assurance='any-enrolled')
                try:
                    time.sleep(0.1)
                    assert not pending.done()
                    time.sleep(max(0, initial + 2.05 - time.time()))
                    released = int(time.time())
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
                pending.result(timeout=10)
        encoded = case.output.read_text().split('.')[1]
        claims = codec.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        assert claims['iat'] >= released
