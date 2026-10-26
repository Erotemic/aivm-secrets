"""The agent side: mTLS calls to a broker and requests through a proxy.
An agent holds surrogates only; nothing here can return a provider credential."""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from . import encoding as enc
from . import tls, wire
from .broker import IssuedToken, LoginStarted
from .config import HttpsUrl

KNOWN_ERRORS = frozenset({'wrong_certificate', 'login_denied', 'login_failed', 'login_expired', 'login_unknown',
                          'unknown_provider', 'invalid_scope', 'invalid_token', 'too_many_logins'})


@dataclass(frozen=True)
class Endpoint:
    """A broker agent API or proxy: its URL (Host and TLS name) and where to connect."""

    url: HttpsUrl
    connect: str

    @classmethod
    def parse(cls, url: str, connect: str | None = None) -> 'Endpoint':
        parsed = HttpsUrl.parse(url)
        return cls(parsed, connect or f'{parsed.host}:{parsed.port}')


def _refusal(response: wire.Response) -> wire.ProtocolError:
    try:
        code = enc.parse(response.body, 1 << 20, 8).get('error')
    except (enc.JsonError, AttributeError):
        code = None
    return wire.ProtocolError(code if code in KNOWN_ERRORS else 'broker_error')


def _issued(value: dict) -> IssuedToken:
    if not isinstance(value, dict) or not isinstance(value.get('token'), str):
        raise wire.ProtocolError('invalid_response')
    return IssuedToken(value['token'], value.get('expires_at', 0), value.get('renew_until', 0))


class Agent:
    """``server_ca`` authenticates broker and proxy; ``certificate``/``key``
    are the agent's software identity (TPM mode is the Rust client)."""

    def __init__(self, server_ca: Path, certificate: Path, key: Path):
        self.context = tls.agent_client(server_ca, certificate, key)

    def _call(self, endpoint: Endpoint, method: str, target: str, headers: list[tuple[str, str]],
              body: bytes = b'') -> wire.Response:
        request = wire.request_bytes(method, target, endpoint.url.authority(), headers, body)
        raw = wire.exchange(self.context, endpoint.connect, endpoint.url.host, request, 32 << 20)
        return wire.parse_response(raw, method, 32 << 20)

    def _json(self, endpoint: Endpoint, method: str, path: str, body: dict | None = None) -> wire.Response:
        data = enc.canonical(body) if body is not None else b''
        target = endpoint.url.path.rstrip('/') + path
        return self._call(endpoint, method, target, [('Content-Type', 'application/json')], data)

    def begin_login(self, broker: Endpoint, provider: str, scope: str | None = None) -> LoginStarted:
        body = {'provider': provider}
        if scope is not None:
            body['scope'] = scope
        response = self._json(broker, 'POST', '/v1/logins', body)
        if response.status != 201:
            raise _refusal(response)
        value = enc.parse(response.body, 1 << 20, 8)
        return LoginStarted(value['login'], value['authorization_url'], value['confirmation'], value['expires_at'])

    def poll(self, broker: Endpoint, login: str, wait: int = 0) -> IssuedToken | None:
        response = self._json(broker, 'GET', f'/v1/logins/{login}?wait={wait}')
        if response.status == 200:
            return _issued(enc.parse(response.body, 1 << 20, 8))
        if response.status == 202:
            return None
        raise _refusal(response)

    def wait_for_token(self, broker: Endpoint, login: str, timeout: float = 600) -> IssuedToken:
        deadline = time.monotonic() + timeout
        while True:
            left = int(max(0, min(30, deadline - time.monotonic())))
            issued = self.poll(broker, login, left)
            if issued is not None:
                return issued
            if time.monotonic() >= deadline:
                raise wire.ProtocolError('login_pending')

    def renew(self, broker: Endpoint, token: str) -> IssuedToken:
        response = self._json(broker, 'POST', '/v1/renewals', {'token': token})
        if response.status != 200:
            raise _refusal(response)
        return _issued(enc.parse(response.body, 1 << 20, 8))

    def request(self, proxy: Endpoint, token: str, method: str, target: str,
                headers: list[tuple[str, str]] | None = None, body: bytes = b'') -> wire.Response:
        """An ordinary API request with the surrogate as the bearer token."""
        return self._call(proxy, method, target, [('Authorization', f'Bearer {token}')] + list(headers or []), body)
