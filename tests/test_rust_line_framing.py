"""Real peer framing: Python/native agreement and no dispatch on a second frame."""
from __future__ import annotations

from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.client import bound_call
from aivm_secrets.identity.mtls import server_context
from aivm_secrets.primitives import codec, wire
from tests.test_rust_garrett import BoundBridge, executable
from tests.test_secrets_identity_mtls import certificates

REPLY = dict(version=1, ok=True, result={'id': 7})
LINE = codec.dumps(REPLY) + b'\n'
MAXIMUM_LINE = LINE[:-1] + b' ' * (wire.MAX_REPLY - len(LINE)) + b'\n'
TOKEN = 'synthetic.bound.capability'
REQUEST = dict(operation='profile.read', arguments={})


def private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


class ReplyPeer:
    """One authenticated TLS exchange with explicit record-sized reply pieces."""
    def __init__(self, root, certs, pieces):
        self.path = root / 'peer.sock'
        self.certs, self.pieces = certs, pieces
        self.seen, self.errors = [], []

    def __enter__(self):
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
        return self

    def serve(self):
        try:
            context = server_context(certificate=self.certs['server'][0],
                                     private_key=self.certs['server'][1],
                                     client_ca=self.certs['ca'])
            with self.listener.accept()[0] as raw:
                raw.settimeout(5)
                with context.wrap_socket(raw, server_side=True) as channel:
                    data = bytearray()
                    while b'\n' not in data:
                        part = channel.recv(65536)
                        if not part:
                            raise AssertionError('client closed before its request')
                        data.extend(part)
                    self.seen.append(codec.loads(bytes(data).rstrip(b'\n')))
                    for part in self.pieces:
                        channel.sendall(part)
                        if len(self.pieces) > 1:
                            time.sleep(0.01)
                    # A TLS close_notify makes EOF explicit, rather than relying
                    # on an abrupt TLS transport failure to reject a missing LF.
                    channel.unwrap().close()
        except (OSError, ssl.SSLError) as error:
            if not self.seen:
                self.errors.append(repr(error))
        except BaseException as error:
            self.errors.append(repr(error))

    def __exit__(self, typ, error, tb):
        self.thread.join(timeout=7)
        self.listener.close()
        assert not self.thread.is_alive(), 'reply peer did not terminate'
        assert not self.errors, self.errors
        assert self.seen == [dict(version=1, capability=TOKEN, request=REQUEST)]


def client_call(backend, root, certs, listen):
    token = private(root / 'token', TOKEN.encode())
    if backend == 'python':
        try:
            return bound_call(socket_path=listen, ca=certs['ca'],
                certificate=certs['client1'][0], private_key=certs['client1'][1],
                jwt_file=token, request=REQUEST)
        except SecretsError as error:
            return {'transport_error': error.code}
    program = executable('AIVM_SECRETS_RUST_GARRETT_CLIENT')
    config = private(root / 'client.json', codec.dumps(dict(schema=1,
        socket=str(listen), server_name='localhost', certificate=str(certs['client1'][0]),
        server_ca=str(certs['ca']), key_mode='software', private_key=str(certs['client1'][1]))))
    done = subprocess.run([program, '--config', str(config)],
        input=codec.dumps(dict(version=1, capability=TOKEN, request=REQUEST)) + b'\n',
        capture_output=True, timeout=10)
    if done.returncode:
        assert done.stdout == b''
        return {'transport_error': done.stderr.decode().strip()}
    assert done.stderr == b''
    return codec.loads(done.stdout)


@pytest.mark.parametrize('backend', ['python', 'rust'])
@pytest.mark.parametrize('pieces,accepted', [
    ((LINE,), True),
    ((LINE[:8], LINE[8:-1], b'\n'), True),
    ((LINE[:-1],), False),
    ((LINE + b'trailing',), False),
    ((LINE + LINE,), False),
    ((b'',), False),
    ((b'\n',), False),
    ((b'[]\n',), False),
    ((b'{"ok":\ntrue}\n',), False),
    ((b'\xff\n',), False),
    ((MAXIMUM_LINE,), True),
    ((MAXIMUM_LINE[:-1] + b' \n',), False),
], ids=['complete', 'split', 'unterminated', 'trailing', 'two-replies',
        'empty', 'empty-line', 'not-object', 'multiline', 'not-utf8', 'maximum', 'over-limit'])
def test_client_reply_framing_matches_reference(backend, pieces, accepted):
    if backend == 'rust':
        executable('AIVM_SECRETS_RUST_GARRETT_CLIENT')
    with tempfile.TemporaryDirectory(prefix='as-line-') as temporary:
        root = Path(temporary)
        certs = certificates(root)
        for path in root.iterdir():
            path.chmod(0o600)
        with ReplyPeer(root, certs, pieces) as peer:
            answer = client_call(backend, root, certs, peer.path)
        assert answer == (REPLY if accepted else {'transport_error': 'outcome_unknown'})


@pytest.mark.parametrize('suffix', [b'', b' ', b'\n', b'{"version":1}'])
def test_bridge_rejects_coalesced_trailing_request_before_provider(suffix):
    bridge = executable('AIVM_SECRETS_RUST_GARRETT_BRIDGE')
    with tempfile.TemporaryDirectory(prefix='as-line-in-') as temporary:
        with BoundBridge(temporary, None, bridge, python_issuer=True) as case:
            context = ssl.create_default_context(cafile=str(case.certs['ca']))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(str(case.certs['client1'][0]), str(case.certs['client1'][1]))
            frame = dict(version=1, capability=case.token,
                request=dict(operation='pr.view', arguments=dict(repository='TauCetiProject/TauCeti', pr=13861)))
            with socket.socket(socket.AF_UNIX) as raw:
                raw.settimeout(5)
                raw.connect(str(case.listen))
                with context.wrap_socket(raw, server_hostname='localhost') as channel:
                    channel.sendall(codec.dumps(frame) + b'\n' + suffix)
                    data = bytearray()
                    while b'\n' not in data:
                        part = channel.recv(65536)
                        assert part
                        data.extend(part)
            reply = codec.loads(bytes(data))
            if suffix:
                assert reply['error']['code'] == 'invalid_request'
                assert case.harness.executor.calls == []
            else:
                assert reply['ok']
                assert len(case.harness.executor.calls) == 1


class BrokerReply:
    def __init__(self, directory, pieces):
        directory.mkdir(mode=0o700)
        self.socket_path = directory / 'broker.sock'
        self.pieces, self.seen, self.errors = pieces, [], []

    def __enter__(self):
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
        return self

    def serve(self):
        try:
            with self.listener.accept()[0] as channel:
                channel.settimeout(5)
                data = bytearray()
                while b'\n' not in data:
                    part = channel.recv(65536)
                    if not part:
                        raise AssertionError('bridge closed before forwarding')
                    data.extend(part)
                self.seen.append(codec.loads(bytes(data).rstrip(b'\n')))
                for part in self.pieces:
                    channel.sendall(part)
        except BaseException as error:
            self.errors.append(repr(error))

    def __exit__(self, typ, error, tb):
        self.thread.join(timeout=7)
        self.listener.close()
        assert not self.thread.is_alive()
        assert not self.errors, self.errors


@pytest.mark.parametrize('pieces,accepted', [((LINE,), True), ((LINE[:-1],), False),
    ((LINE + b'trailing',), False), ((LINE + LINE,), False)])
def test_forwarded_broker_reply_requires_one_complete_frame(pieces, accepted):
    bridge = executable('AIVM_SECRETS_RUST_GARRETT_BRIDGE')
    with tempfile.TemporaryDirectory(prefix='as-line-out-') as temporary:
        def factory(broker, directory):
            return BrokerReply(directory, pieces)
        with BoundBridge(temporary, None, bridge, server_factory=factory, python_issuer=True) as case:
            reply = case.exchange()
            if accepted:
                assert reply == REPLY
            else:
                assert reply['error']['code'] == 'outcome_unknown'
            assert len(case.server.seen) == 1
            assert case.server.seen[0]['capability'] == case.harness.capability
            assert case.harness.executor.calls == []
