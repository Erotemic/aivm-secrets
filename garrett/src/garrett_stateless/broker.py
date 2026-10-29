"""The OAuth broker (spec sections 7 and 8).

Decisions are the :mod:`.core` functions (mirrors of the extracted Rust
controllers); this module supplies randomness, the clock, sealing, the
token request and the transient mailbox, and serves the two listeners.
"""
from __future__ import annotations

import html
import os
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from . import login, tls, wire
from . import token as tok
from .config import BrokerConfig, ConfigError, OAuthClient, ProviderConfig
from .core import encoding as enc
from .core import stateless, stateless_login, stateless_mailbox
from .core.stateless_token import NONCE, Informational, KeySet, TokenSealer
from .files import read_private
from .keys import BrokerKeys

MAX_WAIT = 30
MAX_CONNECTIONS = 64


def _random_id() -> str:
    return secrets.token_bytes(16).hex()


def _sealer(entry, info: Informational) -> TokenSealer:
    """A sealer for one issuance, with a fresh nonce."""
    return TokenSealer(entry, os.urandom(NONCE), info)


@dataclass(frozen=True, repr=False)
class TokenResponse:
    access_token: str
    expires_in: int | None = None
    scope: str | None = None

    def __repr__(self) -> str:
        return f'TokenResponse(<access token>, expires_in={self.expires_in!r}, scope={self.scope!r})'


class TokenEndpoint(Protocol):
    def exchange(self, provider: OAuthClient, form: str) -> TokenResponse: ...


def token_response(status: int, body: bytes) -> TokenResponse:
    """Validate a token endpoint's JSON body (spec section 8.1 step 7)."""
    if status != 200:
        raise wire.ProtocolError('token_rejected')
    try:
        value = enc.parse(body, 65536, 8)
    except enc.JsonError:
        raise wire.ProtocolError('token_invalid') from None
    access = value.get('access_token') if isinstance(value, dict) else None
    if not isinstance(access, str) or not enc.is_credential(access.encode('utf-8')):
        raise wire.ProtocolError('token_invalid')
    kind = value.get('token_type')
    if not isinstance(kind, str) or kind.lower() != 'bearer':
        raise wire.ProtocolError('token_invalid')
    expires_in = value.get('expires_in')
    if expires_in is not None and (type(expires_in) is not int or expires_in < 1):
        raise wire.ProtocolError('token_invalid')
    scope = value.get('scope')
    scope = scope if isinstance(scope, str) and enc.is_scope(scope) else None
    # A refresh_token, if any, is dropped here: never stored, never sealed.
    return TokenResponse(access, expires_in, scope)


class HttpsTokenEndpoint:
    """POST the form to the provider's pinned token endpoint."""

    def exchange(self, provider: OAuthClient, form: str) -> TokenResponse:
        context = tls.upstream_client(provider.token_ca_file)
        url = provider.token_url
        address = provider.token_address or f'{url.host}:{url.port}'
        request = wire.request_bytes('POST', url.path, url.authority(),
                                     [('Accept', 'application/json'),
                                      ('Content-Type', 'application/x-www-form-urlencoded')], form.encode('ascii'))
        raw = wire.exchange(context, address, url.host, request, 1 << 20)
        parsed = wire.parse_response(raw, 'POST', 1 << 20)
        return token_response(parsed.status, parsed.body)


@dataclass(frozen=True)
class LoginStarted:
    login: str
    authorization_url: str
    confirmation: str
    expires_at: int


@dataclass(frozen=True, repr=False)
class IssuedToken:
    token: str
    expires_at: int
    renew_until: int

    def __repr__(self) -> str:
        return f'IssuedToken(<surrogate>, expires_at={self.expires_at}, renew_until={self.renew_until})'


class Broker:
    """The broker; construct from a config file with :meth:`from_file`."""

    def __init__(self, config: BrokerConfig, keys: BrokerKeys, endpoint: TokenEndpoint | None = None,
                 clock: Callable[[], int] | None = None):
        if keys.active_entry().issuer != config.issuer:
            raise ConfigError("the active key is not for the broker's issuer")
        self.config = config
        self.keys = keys
        self.endpoint = endpoint or HttpsTokenEndpoint()
        self.clock = clock or (lambda: int(time.time()))
        self.mailbox = stateless_mailbox.Mailbox()
        self.mailbox_lock = threading.Lock()
        self._secrets = {p.name: (read_private(p.oauth.client_secret_file, 4096).decode('utf-8').strip()
                                  if p.oauth and p.oauth.client_secret_file else None) for p in config.providers}

    @classmethod
    def from_file(cls, path: Path, **kwargs) -> 'Broker':
        config = BrokerConfig.load(path)
        return cls(config, BrokerKeys.load(config.keys), **kwargs)

    def _provider(self, name: str) -> ProviderConfig:
        for provider in self.config.providers:
            if provider.name == name:
                return provider
        raise wire.ProtocolError('unknown_provider')

    def _oauth_provider(self, name: str) -> tuple[ProviderConfig, OAuthClient]:
        """A provider whose credentials come from agent-initiated OAuth logins."""
        provider = self._provider(name)
        if provider.oauth is None:
            raise wire.ProtocolError('unknown_provider')
        return provider, provider.oauth

    def _names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self.config.providers)

    def issue_policy(self) -> stateless.IssuePolicy:
        return issue_policy(self.config)

    def acceptance(self) -> stateless.Acceptance:
        return stateless.Acceptance((self.config.audience,), self._names(), self.config.max_lifetime, 60)

    def _login_policy(self) -> stateless_login.LoginPolicy:
        """The mailbox's policy names the OAuth providers only, so a broker
        without one (every strict broker) never holds a login."""
        return stateless_login.LoginPolicy(self.config.replica, tuple(p.name for p in self.config.providers if p.oauth),
                             self.config.login_ttl)

    def _public_url(self) -> str:
        if self.config.browser is None:
            raise wire.ProtocolError('unknown_provider')
        return self.config.browser.public_url.url()

    def redirect_uri(self) -> str:
        return self._public_url() + 'callback'

    def begin_login(self, peer: tls.PeerIdentity, provider: str, scope: str | None = None) -> LoginStarted:
        _, client = self._oauth_provider(provider)
        public_url = self._public_url()
        try:
            scope = client.requested_scope(scope)
        except ConfigError:
            raise wire.ProtocolError('invalid_scope') from None
        login_id = _random_id()
        now = self.clock()
        with self.mailbox_lock:
            try:
                state = stateless_mailbox.mailbox_start(self.mailbox, self._login_policy(), provider, peer.thumbprint, peer.subject,
                                        peer.not_after, login_id, login.pkce_verifier(), scope, now)
            except stateless_mailbox.MailboxError as error:
                raise wire.ProtocolError(error.code) from None
        sealed = login.seal_state(self.keys.state, state)
        url = public_url + 'authorize?' + wire.form([('state', sealed)])
        return LoginStarted(login_id, url, login.confirmation(login_id), state.expires_at)

    def _provider_url(self, provider: OAuthClient, state_text: str, scope: str, verifier: str) -> str:
        return provider.authorization_url.url() + '?' + wire.form([
            ('response_type', 'code'), ('client_id', provider.client_id), ('redirect_uri', self.redirect_uri()),
            ('scope', scope), ('state', state_text), ('code_challenge', login.pkce_challenge(verifier)),
            ('code_challenge_method', 'S256'),
        ])

    def authorize(self, state_text: str) -> tuple[str, str]:
        """The interstitial for a pending login: (provider URL, HTML page)."""
        try:
            state = login.open_state(self.keys.state, state_text)
        except stateless.Rejection:
            raise wire.ProtocolError('invalid_state') from None
        with self.mailbox_lock:
            try:
                stateless_mailbox.mailbox_pending(self.mailbox, self._login_policy(), state, self.clock())
            except stateless_mailbox.MailboxError as error:
                raise wire.ProtocolError(error.code) from None
        _, client = self._oauth_provider(state.provider)
        url = self._provider_url(client, state_text, state.scope, state.verifier)
        e = html.escape
        page = ('<!doctype html><meta charset=utf-8><title>Authorize agent</title>'
                '<h1>An agent requests access</h1>'
                f'<p>Agent: <code>{e(state.subject)}</code></p><p>Provider: <code>{e(state.provider)}</code></p>'
                f'<p>Scope: <code>{e(state.scope)}</code></p>'
                f'<p>Confirmation code: <strong id=confirmation>{login.confirmation(state.login)}</strong>. '
                'Continue only if your agent shows the same code.</p>'
                f'<p><a id=continue href="{e(url)}">Continue to {e(state.provider)}</a></p>')
        return url, page

    def callback(self, request: wire.Request) -> None:
        """One provider redirect (spec section 8.1 steps 5-8)."""
        try:
            state_text, code = request.param('state'), request.param('code')
            issuer, error = request.param('iss'), request.param('error')
        except ValueError:
            raise wire.ProtocolError('invalid_callback') from None
        denied = error is not None
        if state_text is None or (not denied and (not code or len(code) > 4096)):
            raise wire.ProtocolError('invalid_callback')
        try:
            state = login.open_state(self.keys.state, state_text)
        except stateless.Rejection:
            raise wire.ProtocolError('invalid_state') from None
        provider, client = self._oauth_provider(state.provider)
        policy = self._login_policy()
        with self.mailbox_lock:
            try:
                permit = stateless_mailbox.mailbox_accept(self.mailbox, policy, state, client.issuer, issuer, denied, self.clock())
            except stateless_mailbox.MailboxError as error:
                raise wire.ProtocolError(error.code) from None
        # The mailbox is unlocked during the network exchange; the answer can
        # only reach the login the permit was made for.
        failure: Exception | None = None
        scope: str | None = None

        def token(provider_name: str, code_: str, verifier: str) -> stateless_mailbox.Token | None:
            nonlocal failure, scope
            try:
                config, oauth = self._oauth_provider(provider_name)
                fields = [('grant_type', 'authorization_code'), ('code', code_), ('redirect_uri', self.redirect_uri()),
                          ('client_id', oauth.client_id), ('code_verifier', verifier)]
                if self._secrets.get(config.name):
                    fields.append(('client_secret', self._secrets[config.name]))
                response = self.endpoint.exchange(oauth, wire.form(fields))
            except (wire.ProtocolError, OSError, ssl.SSLError) as error:
                failure = error
                return None
            scope = response.scope
            return stateless_mailbox.Token(response.access_token.encode('ascii'), response.expires_in)

        exchanged = stateless_mailbox.mailbox_exchange(token, permit, code)
        sealer = None
        if exchanged.token is not None:
            info = Informational(scope=(scope if scope is not None else state.scope) or None,
                                     upstream=tok.copy_upstream(exchanged.token.credential.decode('ascii'),
                                                                provider.copy_claims))
            sealer = _sealer(self.keys.active_entry(), info)
        with self.mailbox_lock:
            try:
                stateless_mailbox.mailbox_finish(self.mailbox, exchanged, sealer, self.issue_policy(), _random_id(), self.clock(),
                                 self.config.max_lifetime)
            except stateless_mailbox.MailboxError as error:
                if failure is None:
                    failure = error
        if failure is not None:
            code_ = getattr(failure, 'code', 'login_failed')
            raise wire.ProtocolError(code_ if isinstance(code_, str) else 'login_failed')

    def poll(self, peer: tls.PeerIdentity, login_id: str) -> IssuedToken | tuple[int, str] | None:
        """``None`` while pending, an :class:`IssuedToken`, or ``(status, code)``."""
        with self.mailbox_lock:
            outcome, slot = stateless_mailbox.mailbox_poll(self.mailbox, peer.thumbprint, login_id, self.clock())
        if outcome == 'pending':
            return None
        if outcome == 'unknown':
            return 404, 'login_unknown'
        if outcome == 'wrong_certificate':
            return 403, 'wrong_certificate'
        if outcome in ('denied', 'failed', 'expired'):
            return 410, f'login_{outcome}'
        return IssuedToken(slot.token.decode('ascii'), slot.expires_at, slot.renew_until)

    def renew(self, peer: tls.PeerIdentity, token: str) -> IssuedToken:
        raw = token.encode('ascii', 'replace')
        info = tok.informational(raw)
        issued = stateless.renew(KeySet(self.keys.entries), _sealer(self.keys.active_entry(), info), self.acceptance(),
                         self.issue_policy(), raw, peer.thumbprint, peer.not_after, _random_id(), self.clock(),
                         self.config.max_lifetime)
        return IssuedToken(issued.token.decode('ascii'), issued.claims.expires_at, issued.claims.renew_until)

    def mint(self, provider: str, credential: bytes, certificate_der: bytes, lifetime: int | None = None) -> IssuedToken:
        """Trusted operator issuance for an operator-supplied credential."""
        config = self._provider(provider)
        return mint_with(self.keys, self.issue_policy(), provider, credential, certificate_der, config.copy_claims,
                         lifetime or self.config.max_lifetime, self.clock())

    # --- HTTP ---------------------------------------------------------------

    def handle_agent(self, request: wire.Request, peer: tls.PeerIdentity) -> bytes:
        if request.method == 'POST' and request.path == '/v1/logins':
            try:
                body = enc.parse(request.body, 4096, 2)
            except enc.JsonError:
                return _error(400, 'invalid_request')
            provider = body.get('provider') if isinstance(body, dict) else None
            scope = body.get('scope') if isinstance(body, dict) else None
            if not isinstance(provider, str) or (scope is not None and not isinstance(scope, str)):
                return _error(400, 'invalid_request')
            try:
                started = self.begin_login(peer, provider, scope)
            except wire.ProtocolError as error:
                return _error(400, error.code)
            except stateless.Rejection as rejection:
                return _error(429 if rejection.code == 'too_many_logins' else 400, rejection.code)
            return _reply(201, {'authorization_url': started.authorization_url, 'confirmation': started.confirmation,
                                'expires_at': started.expires_at, 'login': started.login})
        if request.method == 'POST' and request.path == '/v1/renewals':
            try:
                body = enc.parse(request.body, 32768, 2)
            except enc.JsonError:
                return _error(400, 'invalid_request')
            token = body.get('token') if isinstance(body, dict) else None
            if not isinstance(token, str):
                return _error(400, 'invalid_request')
            try:
                return _token_reply(200, self.renew(peer, token))
            except stateless.Rejection:
                return _error(401, 'invalid_token')
        if request.method == 'GET' and request.path.startswith('/v1/logins/'):
            login_id = request.path[len('/v1/logins/'):]
            if not enc.is_id(login_id):
                return _error(404, 'login_unknown')
            try:
                wait_text = request.param('wait') or '0'
            except ValueError:
                return _error(400, 'invalid_request')
            wait = min(int(wait_text), MAX_WAIT) if wait_text.isdigit() else 0
            deadline = time.monotonic() + wait
            while True:
                outcome = self.poll(peer, login_id)
                if outcome is None:
                    if time.monotonic() < deadline:
                        time.sleep(0.1)
                        continue
                    return _reply(202, {'status': 'pending'})
                if isinstance(outcome, IssuedToken):
                    return _token_reply(200, outcome)
                return _error(*outcome)
        return _error(404, 'not_found')

    def handle_browser(self, request: wire.Request) -> bytes:
        if request.method == 'GET' and request.path == '/authorize':
            try:
                state = request.param('state')
                if state is None:
                    raise wire.ProtocolError('invalid_state')
                _, page = self.authorize(state)
            except (ValueError, wire.ProtocolError) as error:
                return _page(400, getattr(error, 'code', 'invalid_state'))
            return wire.response(200, 'text/html; charset=utf-8', page.encode('utf-8'))
        if request.method == 'GET' and request.path == '/callback':
            try:
                self.callback(request)
            except (wire.ProtocolError, stateless.Rejection) as error:
                return _page(400, error.code)
            return wire.response(200, 'text/html; charset=utf-8',
                                 b'<!doctype html><meta charset=utf-8><title>Done</title><h1 id=done>Authorized</h1>'
                                 b'<p>You can close this page; the agent now has its surrogate.</p>')
        return _page(404, 'not_found')

    def serve(self) -> 'RunningBroker':
        """The agent listener, and the browser listener when an OAuth provider is configured."""
        agent_context = tls.mtls_server(self.config.certificate, self.config.private_key, self.config.agent_ca)
        agent = _listen(self.config.agent_listen)
        listeners = [(agent, agent_context, True)]
        browser = None
        if self.config.browser is not None:
            browser = _listen(self.config.browser.listen)
            listeners.append((browser, tls.server(self.config.certificate, self.config.private_key), False))
        running = RunningBroker(agent, browser)
        for listener, context, mutual in listeners:
            thread = threading.Thread(target=_accept_loop, daemon=True,
                                      args=(listener, context, running.stopping, self._handler(mutual)))
            thread.start()
            running.threads.append(thread)
        return running

    def _handler(self, mutual: bool):
        def handle(sock: ssl.SSLSocket) -> bytes:
            peer = tls.PeerIdentity.from_socket(sock) if mutual else None
            request = wire.read_request(sock)
            return self.handle_agent(request, peer) if mutual else self.handle_browser(request)
        return handle


def issue_policy(config: BrokerConfig) -> stateless.IssuePolicy:
    """What a broker issues for: every configured provider, however its credentials are acquired."""
    return stateless.IssuePolicy(config.issuer, config.audience, tuple(p.name for p in config.providers),
                         config.max_lifetime, config.max_renew)


def mint_with(keys: BrokerKeys, policy: stateless.IssuePolicy, provider: str, credential: bytes, certificate_der: bytes,
              copy: tok.ClaimCopy, lifetime: int, now: int) -> IssuedToken:
    """Operator issuance from the keys and the issuance policy alone: no
    listener, OAuth client or client secret."""
    if keys.active_entry().issuer != policy.issuer:
        raise ConfigError("the active key is not for the broker's issuer")
    peer = tls.PeerIdentity.from_der(certificate_der)
    info = Informational(upstream=tok.copy_upstream(credential.decode('ascii', 'replace'), copy))
    grant = stateless.SurrogateGrant(provider, peer.subject, peer.thumbprint, peer.not_after)
    issued = stateless.issue(_sealer(keys.active_entry(), info), policy, grant, credential, _random_id(), now, lifetime)
    return IssuedToken(issued.token.decode('ascii'), issued.claims.expires_at, issued.claims.renew_until)


def _reply(status: int, value: dict) -> bytes:
    return wire.response(status, 'application/json', enc.canonical(value) + b'\n')


def _error(status: int, code: str) -> bytes:
    return _reply(status, {'error': code})


def _page(status: int, code: str) -> bytes:
    body = ('<!doctype html><meta charset=utf-8><title>Error</title><h1>Authorization failed</h1>'
            f'<p id=error>{html.escape(code)}</p>')
    return wire.response(status, 'text/html; charset=utf-8', body.encode('utf-8'))


def _token_reply(status: int, issued: IssuedToken) -> bytes:
    return _reply(status, {'expires_at': issued.expires_at, 'renew_until': issued.renew_until, 'token': issued.token})


def _listen(address: str) -> socket.socket:
    host, _, port = address.rpartition(':')
    sock = socket.socket(socket.AF_INET6 if ':' in host.strip('[]') else socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host.strip('[]'), int(port)))
    sock.listen(64)
    return sock


class RunningBroker:
    def __init__(self, agent: socket.socket, browser: socket.socket | None):
        self.agent, self.browser = agent, browser
        self.stopping = threading.Event()
        self.threads: list[threading.Thread] = []

    @property
    def agent_address(self) -> str:
        host, port = self.agent.getsockname()[:2]
        return f'{host}:{port}'

    @property
    def browser_address(self) -> str | None:
        """``None`` for a broker without an OAuth provider."""
        if self.browser is None:
            return None
        host, port = self.browser.getsockname()[:2]
        return f'{host}:{port}'

    def stop(self) -> None:
        self.stopping.set()
        for sock in (self.agent, self.browser) if self.browser is not None else (self.agent,):
            try:
                sock.close()
            except OSError:
                pass


def _accept_loop(listener: socket.socket, context: ssl.SSLContext, stopping: threading.Event, handle) -> None:
    active = threading.BoundedSemaphore(MAX_CONNECTIONS)
    while not stopping.is_set():
        try:
            raw, _ = listener.accept()
        except OSError:
            return
        if not active.acquire(blocking=False):
            raw.close()
            continue
        threading.Thread(target=_serve_one, args=(raw, context, handle, active), daemon=True).start()


def _serve_one(raw: socket.socket, context: ssl.SSLContext, handle, active) -> None:
    try:
        raw.settimeout(MAX_WAIT + 15)
        with context.wrap_socket(raw, server_side=True) as sock:
            try:
                answer = handle(sock)
            except (wire.ProtocolError, ssl.SSLError, ValueError):
                answer = _error(400, 'invalid_request')
            sock.sendall(answer)
    except (OSError, ssl.SSLError):
        pass
    finally:
        active.release()
