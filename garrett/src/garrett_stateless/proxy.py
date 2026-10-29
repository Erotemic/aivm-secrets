"""The stateless mTLS reverse proxy (spec section 11).

Per connection: a TLS 1.3 handshake requiring an agent certificate, then
for each request :func:`.core.stateless_proxy.serve`, which opens the surrogate for
this connection's peer, picks the route of its authenticated provider and
encodes the upstream request. Nothing about any token is kept.
"""
from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from . import tls
from .broker import _listen
from .config import ProxyConfig
from .core import encoding as enc
from .core import proxy_http, stateless, stateless_policy, stateless_proxy
from .core.stateless_token import KeySet
from .keys import ProxyKeys

IO_TIMEOUT = 15.0
UPSTREAM_DEADLINE = 45.0
REQUEST_DEADLINE = 120.0
MAX_CONNECTIONS = 64


class Proxy:
    def __init__(self, config: ProxyConfig, keys: ProxyKeys, clock: Callable[[], int] | None = None):
        self.config = config
        self.keys = keys
        self.clock = clock or (lambda: int(time.time()))
        self.routes = tuple(stateless_proxy.Route(r.provider, r.host, r.authentication, r.deny) for r in config.routes)
        self.upstream = tuple((r.address, r.port, r.host, tls.upstream_client(r.ca_file)) for r in config.routes)
        self.policy: stateless_policy.OperationPolicy = stateless_policy.Unrestricted() if config.read_only is None else stateless_policy.ReadOnly(
            tuple(stateless_policy.Resource(r.provider, r.method, r.path) for r in config.read_only))
        self.acceptance = stateless.Acceptance(config.audiences, tuple(r.provider for r in config.routes),
                                       config.max_lifetime, config.skew)
        self._audit = open(config.audit, 'ab') if config.audit else None
        self._audit_lock = threading.Lock()

    @classmethod
    def from_file(cls, path: Path, **kwargs) -> 'Proxy':
        config = ProxyConfig.load(path)
        return cls(config, ProxyKeys.load(config.keys), **kwargs)

    def record(self, event: dict) -> bool:
        """One diagnostics/audit line; never token or credential bytes."""
        line = enc.canonical(event) + b'\n'
        if self._audit is None:
            sys.stderr.buffer.write(line)
            sys.stderr.flush()
            return True
        try:
            with self._audit_lock:
                self._audit.write(line)
                self._audit.flush()
            return True
        except OSError:
            return False

    def serve_request(self, request: proxy_http.Request, peer: tls.PeerIdentity) -> stateless_proxy.Served:
        return stateless_proxy.serve(KeySet(self.keys.entries), self.policy, _Native(self, peer, request.method), request,
                       self.routes, self.acceptance, peer.thumbprint, self.clock(), self.config.request_limit)

    def exchange(self, route: int, wire: bytes) -> bytes:
        address, port, host, context = self.upstream[route]
        started = time.monotonic()
        try:
            raw = socket.create_connection((address, port), timeout=IO_TIMEOUT)
        except OSError:
            raise proxy_http.Refused('unreachable') from None
        try:
            with raw, context.wrap_socket(raw, server_hostname=host) as upstream:
                try:
                    upstream.sendall(wire)
                except OSError:
                    raise proxy_http.Refused('outcome_unknown') from None
                data = b''
                while True:
                    if time.monotonic() - started > UPSTREAM_DEADLINE:
                        raise proxy_http.Refused('outcome_unknown')
                    try:
                        chunk = upstream.recv(65536)
                    except ssl.SSLEOFError:
                        break
                    except OSError:
                        raise proxy_http.Refused('outcome_unknown') from None
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > self.config.request_limit + proxy_http.MAX_HEAD + 64:
                        raise proxy_http.Refused('too_large')
                return data
        except ssl.SSLError:
            raise proxy_http.Refused('unreachable') from None

    def serve(self) -> 'RunningProxy':
        context = tls.mtls_server(self.config.certificate, self.config.private_key, self.config.client_ca)
        listener = _listen(self.config.listen)
        running = RunningProxy(listener)
        thread = threading.Thread(target=self._accept_loop, args=(listener, context, running.stopping), daemon=True)
        thread.start()
        running.thread = thread
        return running

    def _accept_loop(self, listener, context, stopping) -> None:
        active = threading.BoundedSemaphore(MAX_CONNECTIONS)
        while not stopping.is_set():
            try:
                raw, _ = listener.accept()
            except OSError:
                return
            if not active.acquire(blocking=False):
                raw.close()
                continue
            threading.Thread(target=self._connection, args=(raw, context, active), daemon=True).start()

    def _connection(self, raw: socket.socket, context: ssl.SSLContext, active) -> None:
        try:
            raw.settimeout(IO_TIMEOUT)
            with context.wrap_socket(raw, server_side=True) as sock:
                peer = tls.PeerIdentity.from_socket(sock)
                self._tunnel(sock, peer)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            active.release()

    def _tunnel(self, sock: ssl.SSLSocket, peer: tls.PeerIdentity) -> None:
        """``proxy_controller::tunnel``: frame, refuse, read more or serve."""
        buffer = b''
        started = time.monotonic()
        limit = self.config.request_limit
        authority = self.config.authority.encode('ascii')
        while True:
            if buffer and time.monotonic() - started > REQUEST_DEADLINE:
                return
            if len(buffer) > 2 * limit + proxy_http.MAX_HEAD + 65536:
                self._refuse(sock, 'too_large')
                return
            try:
                parsed = proxy_http.parse_request(buffer, host=authority, body_limit=limit)
            except proxy_http.Refused as refused:
                self._refuse(sock, refused.code)
                return
            if parsed is None:
                chunk = sock.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                continue
            request, buffer = parsed
            served = self.serve_request(request, peer)
            started = time.monotonic()
            if served.stage != 'completed':
                self.record({'code': served.code, 'event': 'stopped'})
            sock.sendall(served.reply)
            if not served.keep:
                return

    def _refuse(self, sock, code: str) -> None:
        self.record({'code': code, 'event': 'refused'})
        sock.sendall(proxy_http.refusal(code))


class _Native:
    def __init__(self, proxy: Proxy, peer: tls.PeerIdentity, method: bytes):
        self.proxy, self.peer, self.method = proxy, peer, method.decode('ascii', 'replace')
        self.claims: stateless.SurrogateClaims | None = None

    def rejected(self, code: str) -> None:
        self.proxy.record({'event': 'rejected', 'peer': self.peer.thumbprint, 'reason': code})

    def admitted(self, claims: stateless.SurrogateClaims, route: int) -> bool:
        self.claims = claims
        return self.proxy.record({'event': 'admitted', 'jti': claims.token_id, 'method': self.method,
                                  'provider': claims.provider, 'route': route, 'sub': claims.subject})

    def exchange(self, route: int, wire: bytes) -> bytes:
        return self.proxy.exchange(route, wire)

    def completed(self, status: int) -> bool:
        claims = self.claims
        return self.proxy.record({'event': 'completed', 'jti': claims.token_id if claims else '',
                                  'provider': claims.provider if claims else '', 'status': status})


class RunningProxy:
    def __init__(self, listener: socket.socket):
        self.listener = listener
        self.stopping = threading.Event()
        self.thread: threading.Thread | None = None

    @property
    def address(self) -> str:
        host, port = self.listener.getsockname()[:2]
        return f'{host}:{port}'

    def stop(self) -> None:
        self.stopping.set()
        try:
            self.listener.close()
        except OSError:
            pass
