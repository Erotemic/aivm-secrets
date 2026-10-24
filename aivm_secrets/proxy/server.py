"""The proxy session: CONNECT, TLS interception, substitution, upstream, audit.

One :class:`ProxySession` holds the credential for one guest session. The
guest reaches :class:`ProxyServer` as an ordinary ``HTTPS_PROXY``; nothing
it sends is forwarded verbatim. Each request is parsed by the strict
:mod:`.http1` subset, decided by :mod:`.policy`, re-encoded, and sent on a
new TLS connection to the origin's pinned address and trust anchor. The
response is reflection-checked and re-framed before the guest sees a byte.

Upstream failures are reported with the same knowledge rule as the broker's
egress: ``unreachable`` means nothing was sent; ``outcome_unknown`` means a
request may have reached the provider. Nothing is retried.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..errors import SecretsError
from ..host.files import read_owned
from ..primitives import codec
from . import http1
from .ca import SessionCA
from .http1 import Refused
from ..kernel.https import HTTPSpec
from .constrained import translate
from .policy import (Origin, PolicyError, ProxyPolicy, guest_response, reflection_forms,
                     upstream_request)

IO_TIMEOUT = 15.0
# Concurrent guest connections; extra connections are closed at once.
MAX_CONNECTIONS = 32
# Whole-head and whole-request deadlines, so a slow guest cannot hold a
# thread indefinitely.
HEAD_DEADLINE = 30.0
REQUEST_DEADLINE = 120.0
TOTAL_DEADLINE = 45.0
MAX_CA_BYTES = 1 << 20


class ProxyAudit:
    """Hash-chained JSONL; records decisions, never header values or bodies."""

    def __init__(self, path: Path):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_APPEND | os.O_CLOEXEC
        self._stream = os.fdopen(os.open(path, flags, 0o600), 'wb', buffering=0)
        self.head = '0' * 64
        self._seq = 0
        self._lock = threading.Lock()

    def record(self, event: str, **detail: object) -> None:
        with self._lock:
            row = {'schema': 'proxy-audit-1', 'seq': self._seq, 'prev': self.head,
                   'event': event, 'timestamp': int(time.time()), **detail}
            line = codec.dumps(row)
            self._stream.write(line + b'\n')
            os.fsync(self._stream.fileno())
            self.head = hashlib.sha256(line).hexdigest()
            self._seq += 1

    def close(self) -> None:
        with self._lock:
            self._stream.close()


class ProxySession:
    """The credential, the session CA and the guest's surrogate for one session."""

    def __init__(self, policy: ProxyPolicy, credential: bytes | None, *,
                 broker: Any = None, audit: ProxyAudit | None = None,
                 clock: Callable[[], float] = time.time):
        # Exactly one authority source per profile, and never a fallback:
        # substitution holds the credential; constrained-http holds only an
        # in-process broker, which holds the credential.
        if policy.profile == 'credential-substitution':
            if not credential or broker is not None:
                raise PolicyError('invalid_policy')
        elif (credential is not None or not isinstance(getattr(broker, 'spec', None), HTTPSpec)
              or set(policy.origins) != {broker.spec.egress.host}):
            raise PolicyError('invalid_policy')
        self.policy = policy
        self.broker = broker
        self._credential = credential or b''
        self.forms = reflection_forms(credential) if credential else []
        self.token = secrets.token_urlsafe(32)
        self.ca = SessionCA(sorted(policy.origins), policy.lifetime_seconds)
        self._clock = clock
        self.expires_at = clock() + policy.lifetime_seconds
        self._revoked = threading.Event()
        self.audit = audit

    def revoke(self) -> None:
        self._revoked.set()

    def denial(self) -> str | None:
        """Re-sampled before every upstream use."""
        if self._revoked.is_set():
            return 'revoked'
        if self._clock() >= self.expires_at:
            return 'expired'
        return None

    def authenticated(self, fields: tuple[tuple[bytes, bytes], ...]) -> bool:
        values = [v for k, v in fields if k == b'proxy-authorization']
        if len(values) != 1:
            return False
        scheme, _, credential = values[0].partition(b' ')
        if scheme.lower() == b'basic':
            try:
                decoded = base64.b64decode(credential, validate=True)
            except ValueError:
                return False
            # Canonical encodings only (padding, zero trailing bits), as the
            # extracted native decoder requires.
            if base64.b64encode(decoded) != credential:
                return False
            presented = decoded.partition(b':')[2]
        elif scheme.lower() == b'bearer':
            presented = credential
        else:
            return False
        return hmac.compare_digest(presented, self.token.encode('ascii'))

    def record(self, event: str, **detail: object) -> None:
        if self.audit is not None:
            self.audit.record(event, **detail)

    def upstream_bytes(self, origin: Origin, request: http1.Request) -> bytes:
        return upstream_request(self.policy, origin, request, self._credential)


def _upstream_context(origin: Origin) -> ssl.SSLContext:
    # Constructed explicitly: ``create_default_context`` would honour
    # SSLKEYLOGFILE. Trust is the origin's pinned anchor only.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    data = read_owned(Path(origin.ca_file), private=False, limit=MAX_CA_BYTES,
                      what='trust anchor')
    context.load_verify_locations(cadata=data.decode('ascii'))
    return context


def exchange(session: ProxySession, origin: Origin, request: http1.Request,
             wire: bytes) -> http1.Response:
    """Send ``wire`` to the origin's pinned destination and read one response."""
    deadline = time.monotonic() + TOTAL_DEADLINE
    try:
        context = _upstream_context(origin)
        raw = socket.create_connection((origin.address, origin.port), timeout=IO_TIMEOUT)
    except (OSError, ValueError, SecretsError):
        raise Refused('unreachable') from None
    try:
        channel = context.wrap_socket(raw, server_hostname=origin.host)
    except (OSError, ValueError):
        raw.close()
        raise Refused('unreachable') from None
    with channel:
        try:
            channel.sendall(wire)
        except OSError:
            raise Refused('outcome_unknown') from None
        data = b''
        limit = session.policy.response_body + http1.MAX_HEAD
        try:
            while True:
                if time.monotonic() > deadline:
                    raise Refused('outcome_unknown')
                chunk = channel.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > limit + 64:
                    raise Refused('too_large')
        except (OSError, ssl.SSLError):
            raise Refused('outcome_unknown') from None
    try:
        response = http1.parse_response(data, method=request.method,
                                        body_limit=session.policy.response_body, complete=True)
    except Refused as refused:
        # The request was sent: an unusable answer leaves its effect unknown.
        raise Refused('too_large' if refused.code == 'too_large' else 'outcome_unknown') from None
    assert response is not None
    return response


class _Handler(socketserver.BaseRequestHandler):
    server: '_Server'

    def _read_head(self, stream) -> tuple[list[bytes], bytes] | None:
        data = b''
        started = time.monotonic()
        while True:
            if time.monotonic() - started > HEAD_DEADLINE:
                return None
            split = http1.split_head(data)
            if split is not None:
                return split
            chunk = stream.recv(65536)
            if not chunk:
                return None
            data += chunk

    def handle(self) -> None:
        session = self.server.session
        connection: socket.socket = self.request
        if not self.server.slots.acquire(blocking=False):
            return
        try:
            self._handle(session, connection)
        finally:
            self.server.slots.release()

    def _handle(self, session: ProxySession, connection: socket.socket) -> None:
        connection.settimeout(IO_TIMEOUT)
        try:
            self._tunnel(session, connection)
        except Refused as refused:
            try:
                connection.sendall(http1.refusal(refused.code))
            except OSError:
                pass
        except (OSError, ssl.SSLError):
            pass

    def _tunnel(self, session: ProxySession, connection: socket.socket) -> None:
        split = self._read_head(connection)
        if split is None:
            return
        lines, rest = split
        parts = lines[0].split(b' ')
        if len(parts) != 3 or parts[0] != b'CONNECT' or parts[2] != b'HTTP/1.1' or rest:
            raise Refused('invalid_request')
        fields = http1.parse_fields(lines[1:])
        if not session.authenticated(fields):
            session.record('refused', code='unauthenticated')
            raise Refused('unauthenticated')
        host, colon, port = parts[1].decode('ascii', 'replace').rpartition(':')
        origin = session.policy.origins.get(host)
        if origin is None or not colon or port != '443':
            session.record('refused', code='unknown_origin')
            raise Refused('unknown_origin')
        denial = session.denial()
        if denial is not None:
            session.record('refused', code=denial, origin=host)
            raise Refused('revoked')
        connection.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        context = session.ca.server_context(host)
        with context.wrap_socket(connection, server_side=True) as tls:
            self._serve_requests(session, origin, tls)

    def _serve_requests(self, session: ProxySession, origin: Origin, tls: ssl.SSLSocket) -> None:
        buffer = bytearray()
        host = origin.host.encode('ascii')
        # Raw bytes allowed for one request: the body limit with room for
        # chunk framing, plus the head. This also bounds re-parsing.
        raw_limit = 2 * session.policy.request_body + http1.MAX_HEAD + 65536
        started = time.monotonic()
        while True:
            if len(buffer) > raw_limit:
                session.record('refused', code='too_large', origin=origin.host)
                tls.sendall(http1.refusal('too_large'))
                return
            if buffer and time.monotonic() - started > REQUEST_DEADLINE:
                return
            try:
                parsed = http1.parse_request(bytes(buffer), host=host,
                                             body_limit=session.policy.request_body)
            except Refused as refused:
                session.record('refused', code=refused.code, origin=origin.host)
                tls.sendall(http1.refusal(refused.code))
                return
            if parsed is None:
                chunk = tls.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                continue
            request, rest = parsed
            buffer = bytearray(rest)
            started = time.monotonic()
            reply, keep = self._one(session, origin, request)
            tls.sendall(reply)
            if not keep:
                return

    def _one(self, session: ProxySession, origin: Origin,
             request: http1.Request) -> tuple[bytes, bool]:
        path = request.path.decode('ascii')
        method = request.method.decode('ascii')
        denial = session.denial()
        if denial is not None:
            session.record('refused', code=denial, origin=origin.host, method=method, path=path)
            return http1.refusal('revoked'), False
        if session.broker is not None:
            return self._constrained(session, origin, request, method, path)
        try:
            wire = session.upstream_bytes(origin, request)
        except Refused as refused:
            session.record('refused', code=refused.code, origin=origin.host,
                           method=method, path=path)
            return http1.refusal(refused.code), False
        # Fail closed: no durable admission record, no egress (as native).
        try:
            session.record('admitted', origin=origin.host, method=method, path=path)
        except OSError:
            return http1.refusal('internal_error'), False
        try:
            response = exchange(session, origin, request, wire)
            reply = guest_response(response, session.forms, keep_alive=request.keep_alive,
                                   head=request.method == b'HEAD')
        except Refused as refused:
            session.record('failed', code=refused.code, origin=origin.host,
                           method=method, path=path)
            return http1.refusal(refused.code), False
        # Release only after the completion record is durable (as native).
        try:
            session.record('completed', origin=origin.host, method=method, path=path,
                           status=response.status)
        except OSError:
            return http1.refusal('outcome_unknown'), False
        return reply, request.keep_alive


    def _constrained(self, session: ProxySession, origin: Origin, request: http1.Request,
                     method: str, path: str) -> tuple[bytes, bool]:
        """Translate to the one named operation it equals, then ask the broker."""
        try:
            named = translate(session.broker.spec, request)
        except Refused as refused:
            session.record('refused', code=refused.code, origin=origin.host,
                           method=method, path=path)
            return http1.refusal(refused.code), False
        try:
            session.record('admitted', origin=origin.host, method=method, path=path,
                           operation=named.operation)
        except OSError:
            return http1.refusal('internal_error'), False
        frame = codec.dumps({'version': 1, 'capability': session.broker.capability,
                             'request': {'operation': named.operation,
                                         'arguments': dict(named.arguments)}})
        reply = session.broker.handle(frame)
        if reply.get('ok') is True:
            body = codec.dumps(reply.get('result'))
            response = http1.Response(200, b'OK', ((b'content-type', b'application/json'),), body)
            try:
                session.record('completed', origin=origin.host, method=method, path=path,
                               operation=named.operation, status=200)
            except OSError:
                return http1.refusal('outcome_unknown'), False
            return http1.encode_response(response, fields=response.fields,
                                         keep_alive=request.keep_alive,
                                         head=request.method == b'HEAD'), request.keep_alive
        error = reply.get('error') or {}
        code = error.get('code') if isinstance(error.get('code'), str) else 'internal_error'
        session.record('failed', code=code, origin=origin.host, method=method, path=path,
                       operation=named.operation)
        return http1.refusal(code, status=error.get('status')), False


class _Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    session: ProxySession
    slots: threading.BoundedSemaphore


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    session: ProxySession
    slots: threading.BoundedSemaphore


class ProxyServer:
    """Serve one session on loopback TCP or a private Unix socket."""

    def __init__(self, session: ProxySession, *, unix_path: Path | None = None,
                 port: int = 0):
        if unix_path is not None:
            self._server: socketserver.BaseServer = _UnixServer(str(unix_path), _Handler)
            os.chmod(unix_path, 0o600)
            self.address = str(unix_path)
        else:
            self._server = _Server(('127.0.0.1', port), _Handler)
            self.address = '127.0.0.1:%d' % self._server.server_address[1]
        self._server.session = session  # type: ignore[attr-defined]
        self._server.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)  # type: ignore[attr-defined]
        self.session = session
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> 'ProxyServer':
        self._thread.start()
        self.session.record('session_start', profile=self.session.policy.profile,
                            origins=sorted(self.session.policy.origins))
        return self

    def __exit__(self, *exc: object) -> None:
        self.session.revoke()
        self._server.shutdown()
        self._server.server_close()
        self.session.record('session_end')
