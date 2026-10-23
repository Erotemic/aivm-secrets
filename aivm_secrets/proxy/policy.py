"""Host policy and per-request decisions for the HTTPS proxy profiles.

Profile ``credential-substitution`` (see
``docs/planning/aivm-secrets-http-proxy-profiles.md``): the guest may send
any request in the strict HTTP subset to a configured origin; the proxy
removes every guest-supplied credential field, injects the host credential
for that origin, and refuses responses that reflect it. It makes **no**
authority-confinement claim: the guest can do what the credential can do at
the origin, except what the deny list names.

The decision functions are pure so the Rust port can be compared to them.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import http1
from .http1 import Refused

SCHEMA = 1
PROFILES = ('credential-substitution',)
# Authentication field for each scheme, as the provider expects it.
SCHEMES = {
    'bearer': (b'authorization', b'Bearer '),
    'token': (b'authorization', b'token '),
    'x-api-key': (b'x-api-key', b''),
}
# Guest fields never forwarded upstream: credentials (any scheme), proxy
# and hop-by-hop fields, framing, and content negotiation the proxy owns.
DROPPED = frozenset({
    b'authorization', b'x-api-key', b'proxy-authorization', b'proxy-connection',
    b'connection', b'keep-alive', b'transfer-encoding', b'content-length', b'te',
    b'trailer', b'upgrade', b'host', b'accept-encoding', b'cookie',
})
# Upstream fields never returned to the guest.
DROPPED_RESPONSE = frozenset({
    b'connection', b'keep-alive', b'transfer-encoding', b'content-length',
    b'proxy-authenticate', b'proxy-connection', b'trailer', b'upgrade', b'set-cookie',
})
_HOST = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
DEFAULT_LIMITS = {'request_body': 1 << 20, 'response_body': 8 << 20}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Origin:
    host: str
    address: str
    port: int
    ca_file: str
    authentication: str


@dataclass(frozen=True)
class Deny:
    method: bytes  # b'*' for any
    prefix: bytes  # a path prefix ending in '/' or an exact path


@dataclass(frozen=True)
class ProxyPolicy:
    profile: str
    origins: dict[str, Origin]
    deny: tuple[Deny, ...]
    request_body: int
    response_body: int
    lifetime_seconds: int


def _exact_keys(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= set(value) <= required | optional:
        raise PolicyError('invalid_policy')
    return value


def parse_policy(value: Any) -> ProxyPolicy:
    top = _exact_keys(value, {'schema', 'profile', 'origins', 'lifetime_seconds'},
                      {'deny', 'limits'})
    if top['schema'] != SCHEMA or top['profile'] not in PROFILES:
        raise PolicyError('invalid_policy')
    lifetime = top['lifetime_seconds']
    if not isinstance(lifetime, int) or isinstance(lifetime, bool) or not 1 <= lifetime <= 86400:
        raise PolicyError('invalid_policy')
    origins: dict[str, Origin] = {}
    if not isinstance(top['origins'], list) or not 1 <= len(top['origins']) <= 16:
        raise PolicyError('invalid_policy')
    for row in top['origins']:
        row = _exact_keys(row, {'host', 'address', 'port', 'ca_file', 'authentication'})
        host = row['host']
        if (not isinstance(host, str) or not _HOST.match(host) or host in origins
                or row['authentication'] not in SCHEMES
                or not isinstance(row['address'], str) or not row['address']
                or not isinstance(row['port'], int) or not 1 <= row['port'] <= 65535
                or not isinstance(row['ca_file'], str) or not row['ca_file']):
            raise PolicyError('invalid_policy')
        origins[host] = Origin(host, row['address'], row['port'], row['ca_file'],
                               row['authentication'])
    deny = []
    for row in top.get('deny', []):
        row = _exact_keys(row, {'method', 'path'})
        method, path = row['method'], row['path']
        if (not isinstance(method, str) or method.encode() not in http1.METHODS | {b'*'}
                or not isinstance(path, str) or not path.startswith('/')):
            raise PolicyError('invalid_policy')
        try:
            http1.check_target(path.encode('ascii'))
        except (Refused, UnicodeEncodeError):
            raise PolicyError('invalid_policy') from None
        deny.append(Deny(method.encode(), path.encode()))
    limits = {**DEFAULT_LIMITS, **_exact_keys(top.get('limits', {}), set(),
                                               set(DEFAULT_LIMITS))}
    if any(not isinstance(v, int) or isinstance(v, bool) or not 0 < v <= 64 << 20
           for v in limits.values()):
        raise PolicyError('invalid_policy')
    return ProxyPolicy(top['profile'], origins, tuple(deny), limits['request_body'],
                       limits['response_body'], lifetime)


def load_policy(path: Path) -> ProxyPolicy:
    try:
        return parse_policy(json.loads(Path(path).read_text(encoding='utf-8')))
    except (OSError, ValueError, UnicodeDecodeError):
        raise PolicyError('invalid_policy') from None


def denied(policy: ProxyPolicy, method: bytes, path: bytes) -> bool:
    """A deny row matches an exact path, or any path under a ``/``-ending prefix.

    Matching is on the strict parser's path, which has no dot segments or
    encoded separators, and is case-sensitive like provider routing; a
    case-variant path that a provider would also route is a known limit.
    """
    for rule in policy.deny:
        if rule.method not in (b'*', method):
            continue
        if path == rule.prefix or (rule.prefix.endswith(b'/') and path.startswith(rule.prefix)):
            return True
    return False


def upstream_request(
    policy: ProxyPolicy, origin: Origin, request: http1.Request, credential: bytes
) -> bytes:
    """The exact bytes sent upstream for an accepted request, or a refusal."""
    if denied(policy, request.method, request.path):
        raise Refused('denied')
    forwarded = tuple((k, v) for k, v in request.fields if k not in DROPPED)
    name, prefix = SCHEMES[origin.authentication]
    if not credential or any(not http1._visible(b) for b in credential):
        raise Refused('credential_source')
    return http1.encode_request(
        request, host=origin.host.encode('ascii'), forwarded=forwarded,
        authentication=(name, prefix + credential),
    )


def _aligned_base64(secret: bytes, alphabet: str) -> list[bytes]:
    """Base64 text that occurs whenever ``secret`` is encoded at any offset."""
    encode = base64.b64encode if alphabet == 'std' else base64.urlsafe_b64encode
    forms = []
    for shift in range(3):
        text = encode(b'\0' * shift + secret)
        start = -(-8 * shift // 6)
        end = (8 * (shift + len(secret))) // 6
        if end - start >= 8:
            forms.append(text[start:end])
    return forms


def reflection_forms(secret: bytes) -> list[tuple[bytes, bool]]:
    """Encodings of the credential the guest must never receive.

    Each form is ``(bytes, case_insensitive)``. Percent and hex encodings are
    matched without regard to case because either digit case decodes alike.
    """
    from urllib.parse import quote

    forms = {(secret, False), (quote(secret, safe='').encode('ascii').lower(), True),
             (secret.hex().encode(), True)}
    for alphabet in ('std', 'url'):
        forms.update((form, False) for form in _aligned_base64(secret, alphabet))
    return sorted(forms)


def reflects(data: bytes, forms: list[tuple[bytes, bool]]) -> bool:
    lowered = data.lower()
    return any((form in lowered) if folded else (form in data) for form, folded in forms)


def guest_response(
    response: http1.Response, forms: list[bytes], *, keep_alive: bool, head: bool
) -> bytes:
    """The guest's bytes for an upstream response, or a refusal on reflection."""
    fields = tuple((k, v) for k, v in response.fields if k not in DROPPED_RESPONSE)
    encoded = http1.encode_response(response, fields=fields, keep_alive=keep_alive, head=False)
    if reflects(encoded, forms):
        raise Refused('reflected')
    return http1.encode_response(response, fields=fields, keep_alive=keep_alive, head=head)
