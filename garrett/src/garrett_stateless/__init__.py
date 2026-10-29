"""``garrett-stateless-v1``: Matthew Garrett's agentic identity architecture
(*Securing agentic identity*, July 2, 2026), as a standalone library.

* :class:`Broker` runs a browser authorization-code login (PKCE) for an
  mTLS-authenticated agent and mints a signed surrogate JWT carrying the
  provider credential AES-256-GCM-encrypted and bound to the agent's
  certificate.
* :class:`Proxy` accepts ordinary API requests carrying that surrogate as a
  bearer token over mTLS, checks the binding against the connection's
  certificate, decrypts and substitutes the credential, and forwards to the
  provider route the token names. It keeps no state.
* :class:`Agent` is the client for both.

The protocol itself is :mod:`.core`, a module-for-module mirror of the Rust
crate ``garrett-stateless-core`` that the Lean proofs cover; this Python
reference is tested against the same vectors, not proved. Everything else
in this package is the application around it. Specification: ``docs/garrett-stateless-v1.md``.
Requires only ``cryptography``.
"""
from .agent import Agent, Endpoint
from .broker import (
    Broker,
    HttpsTokenEndpoint,
    IssuedToken,
    LoginStarted,
    TokenEndpoint,
    TokenResponse,
)
from .config import BrokerConfig, ConfigError, ProviderConfig, ProxyConfig
from .core.stateless import Acceptance, IssuePolicy, Rejection, SurrogateClaims
from .core.stateless_token import Informational, KeySet, TokenSealer
from .keys import BrokerKeys, KeyFileError, ProxyKeys
from .proxy import Proxy
from .tls import PeerIdentity
from .token import ClaimCopy, copy_upstream, inspect
from .wire import ProtocolError

PROFILE = 'garrett-stateless-v1'

__all__ = [
    'Acceptance', 'Agent', 'Broker', 'BrokerConfig', 'BrokerKeys', 'ClaimCopy', 'ConfigError', 'Endpoint',
    'HttpsTokenEndpoint', 'Informational', 'IssuePolicy', 'IssuedToken', 'KeyFileError', 'KeySet', 'LoginStarted',
    'PROFILE', 'PeerIdentity', 'ProtocolError', 'Proxy', 'ProxyConfig', 'ProxyKeys', 'ProviderConfig', 'Rejection',
    'SurrogateClaims', 'TokenEndpoint', 'TokenResponse', 'TokenSealer', 'copy_upstream', 'inspect',
]
