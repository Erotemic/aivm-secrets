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
PROFILES = ('credential-substitution', 'constrained-http')
# Authentication field for each scheme, spelled exactly as the extracted
# Rust `http_auth::append_header` writes it (byte parity, HP-4).
SCHEMES = {
    'bearer': (b'Authorization', b'Bearer '),
    'x-api-key': (b'X-API-Key', b''),
}
MAX_CREDENTIAL = 4096
# Guest fields never forwarded upstream: credentials (any scheme), proxy
# and hop-by-hop fields, framing, and content negotiation the proxy owns.
DROPPED = frozenset({
    b'authorization', b'x-api-key', b'proxy-authorization', b'proxy-connection',
    b'connection', b'keep-alive', b'transfer-encoding', b'content-length', b'te',
    b'trailer', b'upgrade', b'host', b'accept-encoding', b'cookie',
    # Method overrides could route around method-specific deny rules, and
    # ranges could fetch an echoed credential in pieces.
    b'x-http-method-override', b'x-method-override', b'x-http-method', b'range', b'if-range',
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
    constrained = top['profile'] == 'constrained-http'
    if constrained and ('deny' in top or len(top['origins']) != 1):
        # The broker's operations are the allowlist; its policy names one host.
        raise PolicyError('invalid_policy')
    for row in top['origins']:
        if constrained:
            # No destination, trust anchor or credential scheme: the broker's
            # own service policy owns all three.
            row = _exact_keys(row, {'host'})
            host = row['host']
            if not isinstance(host, str) or not _HOST.match(host):
                raise PolicyError('invalid_policy')
            origins[host] = Origin(host, '', 0, '', '')
            continue
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
    """A deny row matches its exact path, the same path with a trailing slash,
    or, for a ``/``-ending prefix, the prefix without its slash and everything
    under it.

    Matching is on the strict parser's path, which has one canonical spelling
    (no dot segments, ``;`` or alternate escapes). It is case-sensitive like
    provider routing; a case-variant path a provider would also route is a
    known limit, as are provider-specific overrides such as a ``_method``
    query parameter.
    """
    for rule in policy.deny:
        if rule.method not in (b'*', method):
            continue
        prefix = rule.prefix
        if path == prefix or path == prefix + b'/':
            return True
        if prefix.endswith(b'/') and (path == prefix[:-1] or path.startswith(prefix)):
            return True
    return False


def upstream_request(
    policy: ProxyPolicy, origin: Origin, request: http1.Request, credential: bytes
) -> bytes:
    """The exact bytes sent upstream for an accepted request, or a refusal."""
    # Re-validate what the parser ensures, as the extracted encoder does, so
    # upstream framing never depends on the parser.
    if request.method not in http1.METHODS:
        raise Refused('invalid_request')
    http1.check_target(request.target)
    forwarded = tuple((k, v) for k, v in request.fields if k.lower() not in DROPPED)
    if any(not k or any(b not in http1._TOKEN for b in k)
           or any(not (http1._visible(b) or b in b' \t') for b in v) for k, v in forwarded):
        raise Refused('invalid_request')
    if denied(policy, request.method, request.path):
        raise Refused('denied')
    name, prefix = SCHEMES[origin.authentication]
    if (not credential or len(credential) > MAX_CREDENTIAL
            or any(not http1._visible(b) for b in credential)):
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
    if b'/' in secret:
        # As a JSON string body may escape it.
        forms.add((secret.replace(b'/', b'\\/'), False))
    for alphabet in ('std', 'url'):
        forms.update((form, False) for form in _aligned_base64(secret, alphabet))
    return sorted(forms)


def reflects(data: bytes, forms: list[tuple[bytes, bool]]) -> bool:
    """Folded forms are searched in the lowercased data; the others in the
    data and in the data without line breaks (MIME-wrapped base64)."""
    lowered = data.lower()
    unwrapped = data.replace(b'\r', b'').replace(b'\n', b'')
    return any((form in lowered) if folded else (form in data or form in unwrapped)
               for form, folded in forms)


def guest_response(
    response: http1.Response, forms: list[bytes], *, keep_alive: bool, head: bool
) -> bytes:
    """The guest's bytes for an upstream response, or a refusal on reflection."""
    fields = tuple((k, v) for k, v in response.fields if k not in DROPPED_RESPONSE)
    encoded = http1.encode_response(response, fields=fields, keep_alive=keep_alive, head=False)
    if reflects(encoded, forms):
        raise Refused('reflected')
    return http1.encode_response(response, fields=fields, keep_alive=keep_alive, head=head)
