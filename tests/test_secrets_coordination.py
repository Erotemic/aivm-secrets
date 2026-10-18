"""Local coordinator concurrency, persistence, and real two-host mTLS tests.

All certificates are synthetic. The service uses localhost transport in tests,
with different authenticated members modeling different physical hosts.
"""
from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.certificates import create_csr, inspect_csr
from aivm_secrets.identity.coordination import (
    CoordinationClient, CoordinationConfig, CoordinationLedger,
    CoordinationServer,
)
from aivm_secrets.identity.enrollment import IdentityAuthority


PEER_A = 'a' * 64
PEER_B = 'b' * 64
KEY = 'c' * 64
DIGEST = 'd' * 64


def test_durable_revocation_is_terminal_and_fail_closed(tmp_path):
    root = tmp_path / 'coord'
    a = CoordinationLedger.initialize(root)
    b = CoordinationLedger(root)
    with pytest.raises(SecretsError, match='revoked'):
        b.check('global-agent', PEER_A)
    assert a.activate('global-agent', [PEER_A, PEER_B])['active']
    assert b.check('global-agent', PEER_B)['active']
    with pytest.raises(SecretsError):
        b.check('global-agent', 'e' * 64)
    assert a.revoke('global-agent')['active'] is False
    for ledger in (a, b, CoordinationLedger(root)):
        with pytest.raises(SecretsError, match='revoked'):
            ledger.check('global-agent', PEER_A)
        with pytest.raises(SecretsError):
            ledger.activate('global-agent', [PEER_A])
    # Preemptive revocation is a durable tombstone, not an empty list.
    a.revoke('never-registered')
    with pytest.raises(SecretsError):
        b.activate('never-registered', [PEER_A])


def test_write_reservation_is_shared_across_hosts_and_restarts(tmp_path):
    root = tmp_path / 'coord'
    a = CoordinationLedger.initialize(root)
    b = CoordinationLedger(root)
    a.activate('global-agent', [PEER_A, PEER_B])
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit((a if i % 2 else b).reserve,
                               'global-agent', PEER_A if i % 2 else PEER_B,
                               KEY, DIGEST) for i in range(20)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except SecretsError as error:
                outcomes.append(error.code)
    assert outcomes.count({'reserved': True}) == 1
    assert outcomes.count('outcome_unknown') == 19
    assert b.finish('global-agent', PEER_B, KEY, DIGEST)['recorded']
    with pytest.raises(SecretsError) as exc_info:
        CoordinationLedger(root).reserve('global-agent', PEER_A, KEY, DIGEST)
    assert exc_info.value.code == 'outcome_unknown'
    # The same key for a different payload is not an independent write.
    with pytest.raises(SecretsError) as exc_info:
        a.reserve('global-agent', PEER_A, KEY, 'f' * 64)
    assert exc_info.value.code == 'outcome_unknown'


def _cert(authority, tmp_path, name):
    key = tmp_path / (name + '.key')
    csr = tmp_path / (name + '.csr')
    fp = create_csr(private_key=key, request_file=csr)
    enrollment = authority.enroll(subject=name, csr=csr.read_bytes(),
                                   approve_fingerprint=fp)
    cert = Path(enrollment['certificate'])
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    der_sha = x509.load_pem_x509_certificate(cert.read_bytes()).fingerprint(
        hashes.SHA256()).hex()
    return cert, key, der_sha


def test_authenticated_cross_host_coordinator_revoke_and_outage(tmp_path):
    authority = IdentityAuthority.initialize(tmp_path / 'ca',
                issuer='aivm.local', audience='aivm-secrets.identity')
    operator = _cert(authority, tmp_path, 'coordinator-operator')
    host_a = _cert(authority, tmp_path, 'broker-host-a')
    host_b = _cert(authority, tmp_path, 'broker-host-b')
    stranger = _cert(authority, tmp_path, 'broker-stranger')
    server_cert, server_key, ca = authority.tls_paths()
    root = tmp_path / 'coord'
    ledger = CoordinationLedger.initialize(root)
    with CoordinationServer(('127.0.0.1', 0), ledger=ledger,
          server_cert=server_cert, server_key=server_key, client_ca=ca,
          operator_fingerprints=[operator[2]]) as server:
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.01})
        thread.start()
        def client(item):
            return CoordinationClient(CoordinationConfig(
                'localhost', server.server_address[1], ca,
                item[0], item[1], 'common-principal'))
        op, a, b, untrusted = map(client, (operator, host_a, host_b, stranger))
        try:
            with pytest.raises(SecretsError):
                a.check()  # no implicit registration
            op.activate([host_a[2], host_b[2]])
            a.check()
            b.check()
            with pytest.raises(SecretsError):
                untrusted.check()
            with pytest.raises(SecretsError):
                a.revoke()  # cannot exercise an operator verb
            a.reserve(KEY, DIGEST)
            with pytest.raises(SecretsError) as exc_info:
                b.reserve(KEY, DIGEST)
            assert exc_info.value.code == 'outcome_unknown'
            op.revoke()
            for client_instance in (a, b):
                with pytest.raises(SecretsError):
                    client_instance.check()
        finally:
            server.shutdown()
            thread.join(timeout=3)
    with pytest.raises(SecretsError):
        a.check()  # no cached positive admission when authority is offline
    assert CoordinationLedger(root).status('common-principal')['active'] is False


def test_real_bridge_checks_global_revocation_before_local_broker(tmp_path):
    """Remote tombstone denies fresh bound calls in a running bridge."""
    from aivm_secrets.host.server import LocalServer
    from aivm_secrets.identity.service import UnixIdentityService
    from tests.test_secrets_identity_service import start, call, view_request
    authority, key, entry, jwt, harness = start(tmp_path)
    op_cert = _cert(authority, tmp_path, 'coordinator-operator')
    host_cert = _cert(authority, tmp_path, 'coordinator-bridge-host')
    server_cert, server_key, ca = authority.tls_paths()
    ledger = CoordinationLedger.initialize(tmp_path / 'ledger')
    listen = tmp_path / 'bridge' / 'session.sock'
    try:
        with CoordinationServer(('127.0.0.1', 0), ledger=ledger,
                server_cert=server_cert, server_key=server_key, client_ca=ca,
                operator_fingerprints=[op_cert[2]]) as server:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={'poll_interval': 0.01})
            thread.start()
            try:
                def client(pair):
                    return CoordinationClient(CoordinationConfig(
                        'localhost', server.server_address[1], ca, pair[0],
                        pair[1], 'bound-client-principal'))
                operator, member = client(op_cert), client(host_cert)
                operator.activate([host_cert[2]])
                harness.broker._coordination = member
                with LocalServer(harness.broker, tmp_path / 'broker') as broker:
                    with UnixIdentityService(
                        authority=authority, broker_socket=broker.socket_path,
                        listen=listen, max_connections=2, idle_seconds=12,
                        coordination=member,
                    ) as bridge:
                        worker = threading.Thread(target=bridge.serve)
                        worker.start()
                        assert call(listen, authority, entry, key, jwt, view_request())['ok']
                        assert len(harness.executor.calls) == 1
                        operator.revoke()
                        revoked = call(listen, authority, entry, key,
                                       jwt, view_request())
                        assert revoked['error']['code'] == 'revoked'
                        assert len(harness.executor.calls) == 1
                        worker.join(timeout=10)
                        assert not worker.is_alive()
            finally:
                server.shutdown()
                thread.join(timeout=3)
    finally:
        harness.broker.close()


def test_two_brokers_use_remote_tls_atomic_write_journal(tmp_path):
    """End-to-end across two real authenticated coordinator clients."""
    from tests.secrets_helpers import Harness
    from tests.test_secrets_core_extensions import (
        HeaderExecutor, _keyed_policy, _request, _send,
    )

    authority = IdentityAuthority.initialize(tmp_path / 'ca',
        issuer='aivm.local', audience='aivm-secrets.identity')
    operator = _cert(authority, tmp_path, 'operator')
    host_a = _cert(authority, tmp_path, 'broker-a')
    host_b = _cert(authority, tmp_path, 'broker-b')
    server_cert, server_key, ca = authority.tls_paths()
    ledger = CoordinationLedger.initialize(tmp_path / 'ledger')
    ex_a, ex_b = HeaderExecutor(), HeaderExecutor()
    h_a = Harness(tmp_path / 'a', writes='allow',
                  policy=_keyed_policy(), executor=ex_a)
    h_b = Harness(tmp_path / 'b', writes='allow',
                  policy=_keyed_policy(), executor=ex_b)
    try:
        with CoordinationServer(('127.0.0.1', 0), ledger=ledger,
                server_cert=server_cert, server_key=server_key, client_ca=ca,
                operator_fingerprints=[operator[2]]) as server:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={'poll_interval': 0.01})
            thread.start()
            try:
                def client(material):
                    return CoordinationClient(CoordinationConfig(
                        'localhost', server.server_address[1], ca,
                        material[0], material[1], 'repo-write-principal'))
                op, a, b = map(client, (operator, host_a, host_b))
                op.activate([host_a[2], host_b[2]])
                h_a.broker._coordination = a
                h_b.broker._coordination = b
                assert _send(h_a, _request('hello', 'shared-key-from-host-a'))['ok']
                denied = _send(h_b, _request('hello', 'shared-key-from-host-a'))
                assert denied['error']['code'] == 'outcome_unknown'
                assert len(ex_a.calls) == 1 and not ex_b.calls
                another = _send(h_b, _request('other', 'new-key-from-host-b'))
                assert another['ok'], another
                assert len(ex_b.calls) == 1
                op.revoke()
                failed = _send(h_a, _request('after-revoke', 'third-distinct-key'))
                assert failed['error']['code'] == 'revoked'
                assert len(ex_a.calls) == 1
            finally:
                server.shutdown()
                thread.join(timeout=3)
    finally:
        h_a.broker.close()
        h_b.broker.close()


def test_stalled_unauthenticated_tls_peer_does_not_block_other_members(tmp_path, monkeypatch):
    """An accepted raw socket must not monopolize the authority's accept loop."""
    import socket
    from tests.test_rust_coordination import CoordinatorCase

    with CoordinatorCase(tmp_path / 'coord') as coord:
        accepted = threading.Event()
        original = coord.server._context.wrap_socket
        def observe_handshake(*args, **kwargs):
            accepted.set()
            return original(*args, **kwargs)
        monkeypatch.setattr(coord.server._context, 'wrap_socket', observe_handshake)
        with socket.create_connection(('127.0.0.1', coord.server.server_address[1])):
            assert accepted.wait(timeout=2)
            # This valid authenticated request has its ordinary four-second
            # deadline; it must succeed while the first socket sends no TLS.
            assert coord.operator.status() == {'ok': True, 'active': False, 'revision': None}
