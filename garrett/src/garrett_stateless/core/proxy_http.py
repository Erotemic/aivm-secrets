"""The proxy's strict HTTP/1.1 subset (Rust ``proxy_http``, with the small
``proxy_connect``/``http_wire``/``http_auth``/``reflection`` leaves folded in):
request and response parsing, the field filter, the exact upstream encoder,
response re-framing with reflected-credential refusal, and the fixed refusal
responses. Everything is a pure function over bytes; refusals are
:class:`Refused` with a fixed code.

Accepted request subset:

* request line ``METHOD SP origin-form SP HTTP/1.1``; methods in ``METHODS``;
* origin-form target of visible ASCII without ``#``, backslash, ``;``,
  empty or dot segments, or a malformed escape or one that encodes an
  unreserved character, ``/``, ``\\``, NUL or ``;``;
* header fields ``token ":" OWS value OWS`` with visible ASCII/SP/HTAB
  values; no obs-fold, bare CR or LF, NUL, or duplicate framing fields;
* framing by one decimal ``Content-Length`` or ``Transfer-Encoding: chunked``
  (never both), chunks without extensions or trailers;
* no ``Upgrade``, ``Expect`` or ``TE``; exactly one ``Host``.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import quote

METHODS = frozenset({b'GET', b'HEAD', b'POST', b'PUT', b'PATCH', b'DELETE', b'OPTIONS'})
MAX_HEAD = 32 * 1024
MAX_FIELDS = 100
_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_HEX = frozenset(b'0123456789abcdefABCDEF')
_UNRESERVED = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~')


# Authentication field for each scheme, spelled exactly as the extracted
# Rust `http_auth::append_header` writes it.
SCHEMES = {
    'bearer': (b'Authorization', b'Bearer '),
    'x-api-key': (b'X-API-Key', b''),
}
MAX_CREDENTIAL = 4096
# Agent fields never forwarded upstream: credentials (any scheme), proxy
# and hop-by-hop fields, framing, and content negotiation the proxy owns.
DROPPED = frozenset({
    b'authorization', b'x-api-key', b'proxy-authorization', b'proxy-connection',
    b'connection', b'keep-alive', b'transfer-encoding', b'content-length', b'te',
    b'trailer', b'upgrade', b'host', b'accept-encoding', b'cookie',
    # Method overrides could route around method-specific deny rules, and
    # ranges could fetch an echoed credential in pieces.
    b'x-http-method-override', b'x-method-override', b'x-http-method', b'range', b'if-range',
})
# Upstream fields never returned to the agent.
DROPPED_RESPONSE = frozenset({
    b'connection', b'keep-alive', b'transfer-encoding', b'content-length',
    b'proxy-authenticate', b'proxy-connection', b'trailer', b'upgrade', b'set-cookie',
})


def bad_escape(target: bytes, index: int) -> bool:
    """A refused percent-escape: malformed, or encoding an unreserved
    character (an alternate spelling of a plain path), ``/``, ``\\``, NUL
    or ``;``. Every accepted target then has one canonical spelling."""
    if target[index] != 0x25:
        return False
    if len(target) - index < 3 or target[index + 1] not in _HEX or target[index + 2] not in _HEX:
        return True
    byte = int(target[index + 1:index + 3], 16)
    return byte in _UNRESERVED or byte in b'/\\;' or byte == 0
# Fields a request may never carry into the tunnel: they change framing or
# protocol in ways this proxy does not model.
_REFUSED_REQUEST_FIELDS = frozenset({b'upgrade', b'expect', b'te', b'trailer'})


class Refused(Exception):
    """A message outside the accepted subset. ``code`` is public and fixed."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Request:
    method: bytes
    target: bytes
    # In order, names lowercased, values exactly as received minus OWS.
    fields: tuple[tuple[bytes, bytes], ...]
    body: bytes
    keep_alive: bool

    @property
    def path(self) -> bytes:
        return self.target.split(b'?', 1)[0]

    def values(self, name: bytes) -> list[bytes]:
        return [v for k, v in self.fields if k == name]


@dataclass(frozen=True)
class Response:
    status: int
    reason: bytes
    fields: tuple[tuple[bytes, bytes], ...]
    body: bytes

    def values(self, name: bytes) -> list[bytes]:
        return [v for k, v in self.fields if k == name]


def _visible(byte: int) -> bool:
    return 0x21 <= byte <= 0x7E


def check_target(target: bytes) -> None:
    if not target.startswith(b'/') or len(target) > 8192:
        raise Refused('invalid_request')
    if any(not _visible(b) or b in b'#\\;' for b in target):
        raise Refused('invalid_request')
    if any(bad_escape(target, index) for index in range(len(target))):
        raise Refused('invalid_request')
    path = target.split(b'?', 1)[0]
    segments = path.split(b'/')[1:]
    # A trailing slash gives one empty final segment; any other is ambiguous.
    for index, segment in enumerate(segments):
        if segment in (b'.', b'..') or (segment == b'' and index != len(segments) - 1):
            raise Refused('invalid_request')


def parse_fields(lines: list[bytes]) -> tuple[tuple[bytes, bytes], ...]:
    if len(lines) > MAX_FIELDS:
        raise Refused('invalid_request')
    fields = []
    for line in lines:
        if not line or line[0] in b' \t':
            raise Refused('invalid_request')  # obs-fold or empty name
        name, colon, value = line.partition(b':')
        if not colon or not name or any(b not in _TOKEN for b in name):
            raise Refused('invalid_request')
        value = value.strip(b' \t')
        if any(not (_visible(b) or b in b' \t') for b in value):
            raise Refused('invalid_request')
        fields.append((name.lower(), value))
    return tuple(fields)


def split_head(data: bytes) -> tuple[list[bytes], bytes] | None:
    """Split a complete head into CRLF lines; ``None`` if more bytes needed."""
    end = data.find(b'\r\n\r\n')
    if end < 0:
        if len(data) > MAX_HEAD:
            raise Refused('invalid_request')
        return None
    if end > MAX_HEAD:
        raise Refused('invalid_request')
    head = data[:end]
    lines = head.split(b'\r\n')
    if any(b'\r' in line or b'\n' in line or b'\0' in line for line in lines):
        raise Refused('invalid_request')
    return lines, data[end + 4:]


def content_length(values: list[bytes], limit: int) -> int:
    if len(values) != 1 or not values[0].isdigit() or len(values[0]) > 12:
        raise Refused('invalid_request')
    length = int(values[0])
    if length > limit:
        raise Refused('too_large')
    return length


def decode_chunked(data: bytes, limit: int) -> tuple[bytes, bytes] | None:
    """Decode a chunked body without extensions or trailers.

    Returns ``(body, rest)`` or ``None`` when more bytes are needed.
    """
    body = bytearray()
    position = 0
    while True:
        end = data.find(b'\r\n', position)
        if end < 0:
            if len(data) - position > 16:
                raise Refused('invalid_request')
            return None
        size_text = data[position:end]
        if not size_text or len(size_text) > 8 or any(
            b not in b'0123456789abcdefABCDEF' for b in size_text
        ):
            raise Refused('invalid_request')
        size = int(size_text, 16)
        position = end + 2
        if size == 0:
            if data[position:position + 2] == b'\r\n':
                return bytes(body), data[position + 2:]
            if len(data) - position < 2:
                return None
            raise Refused('invalid_request')  # trailers are not accepted
        if len(body) + size > limit:
            raise Refused('too_large')
        if len(data) < position + size + 2:
            return None
        if data[position + size:position + size + 2] != b'\r\n':
            raise Refused('invalid_request')
        body += data[position:position + size]
        position += size + 2


def _keep_alive(fields: tuple[tuple[bytes, bytes], ...]) -> bool:
    tokens = [
        token.strip().lower()
        for value in (v for k, v in fields if k == b'connection')
        for token in value.split(b',')
    ]
    if any(token not in (b'close', b'keep-alive') for token in tokens):
        raise Refused('invalid_request')
    return b'close' not in tokens


def parse_request(data: bytes, *, host: bytes, body_limit: int) -> tuple[Request, bytes] | None:
    """Parse one request from ``data``; ``None`` if more bytes are needed.

    ``host`` is the proxy's own authority; the request's ``Host`` must name it.
    """
    split = split_head(data)
    if split is None:
        return None
    lines, rest = split
    parts = lines[0].split(b' ')
    if len(parts) != 3 or parts[2] != b'HTTP/1.1' or parts[0] not in METHODS:
        raise Refused('invalid_request')
    method, target = parts[0], parts[1]
    check_target(target)
    fields = parse_fields(lines[1:])
    names = [name for name, _ in fields]
    if any(name in _REFUSED_REQUEST_FIELDS for name in names):
        raise Refused('invalid_request')
    hosts = [v for k, v in fields if k == b'host']
    if len(hosts) != 1 or hosts[0].lower() not in (host, host + b':443'):
        raise Refused('invalid_request')
    keep_alive = _keep_alive(fields)
    encodings = [v for k, v in fields if k == b'transfer-encoding']
    lengths = [v for k, v in fields if k == b'content-length']
    if encodings:
        if lengths or encodings != [b'chunked']:
            raise Refused('invalid_request')
        decoded = decode_chunked(rest, body_limit)
        if decoded is None:
            return None
        body, rest = decoded
    elif lengths:
        length = content_length(lengths, body_limit)
        if len(rest) < length:
            return None
        body, rest = rest[:length], rest[length:]
    else:
        body = b''
    return Request(method, target, fields, body, keep_alive), rest


def encode_request(
    request: Request,
    *,
    host: bytes,
    forwarded: tuple[tuple[bytes, bytes], ...],
    authentication: tuple[bytes, bytes] | None,
) -> bytes:
    """The canonical upstream request: one connection, identity encoding.

    ``forwarded`` are the guest fields that survived the policy filter;
    ``authentication`` is the single injected credential field, if any.
    """
    out = bytearray(request.method + b' ' + request.target + b' HTTP/1.1\r\n')
    out += b'Host: ' + host + b'\r\n'
    for name, value in forwarded:
        out += name + b': ' + value + b'\r\n'
    if authentication is not None:
        out += authentication[0] + b': ' + authentication[1] + b'\r\n'
    out += b'Accept-Encoding: identity\r\nConnection: close\r\n'
    if request.body or request.method in (b'POST', b'PUT', b'PATCH'):
        out += b'Content-Length: ' + str(len(request.body)).encode() + b'\r\n'
    out += b'\r\n' + request.body
    return bytes(out)


def parse_response(data: bytes, *, method: bytes, body_limit: int, complete: bool) -> Response | None:
    """Parse one upstream response; ``complete`` means the peer closed.

    Refuses compressed bodies so later checks see the plain bytes.
    """
    split = split_head(data)
    if split is None:
        if complete:
            raise Refused('upstream_response')
        return None
    lines, rest = split
    parts = lines[0].split(b' ', 2)
    if (len(parts) < 2 or parts[0] != b'HTTP/1.1' or len(parts[1]) != 3
            or not parts[1].isdigit()):
        raise Refused('upstream_response')
    status = int(parts[1])
    reason = parts[2] if len(parts) == 3 else b''
    if status < 200 or any(not (_visible(b) or b in b' \t') for b in reason):
        raise Refused('upstream_response')
    try:
        fields = parse_fields(lines[1:])
    except Refused:
        raise Refused('upstream_response') from None
    codings = [v.lower() for k, v in fields if k == b'content-encoding']
    if any(coding != b'identity' for coding in codings):
        raise Refused('upstream_response')
    encodings = [v for k, v in fields if k == b'transfer-encoding']
    lengths = [v for k, v in fields if k == b'content-length']
    try:
        if method == b'HEAD' or status in (204, 304):
            body = b''
        elif encodings:
            if lengths or encodings != [b'chunked']:
                raise Refused('upstream_response')
            decoded = decode_chunked(rest, body_limit)
            if decoded is None:
                if complete:
                    raise Refused('upstream_response')
                return None
            body = decoded[0]
        elif lengths:
            length = content_length(lengths, body_limit)
            if len(rest) < length:
                if complete:
                    raise Refused('upstream_response')
                return None
            body = rest[:length]
        else:
            if not complete:
                if len(rest) > body_limit:
                    raise Refused('too_large')
                return None
            body = rest
    except Refused as refused:
        raise Refused('too_large' if refused.code == 'too_large' else 'upstream_response') from None
    if len(body) > body_limit:
        raise Refused('too_large')
    return Response(status, reason, fields, body)


def encode_response(
    response: Response, *, fields: tuple[tuple[bytes, bytes], ...], keep_alive: bool, head: bool
) -> bytes:
    """Re-frame a response for the guest with an exact ``Content-Length``."""
    out = bytearray(b'HTTP/1.1 ' + str(response.status).encode() + b' ' + response.reason + b'\r\n')
    for name, value in fields:
        out += name + b': ' + value + b'\r\n'
    out += b'Content-Length: ' + str(len(response.body)).encode() + b'\r\n'
    out += b'Connection: ' + (b'keep-alive' if keep_alive else b'close') + b'\r\n\r\n'
    if not head:
        out += response.body
    return bytes(out)


# The status of each refusal code (Rust ``proxy_http::refusal::Code``).
REFUSAL_STATUS = {
    'invalid_request': b'400 Bad Request', 'too_large': b'413 Content Too Large',
    'denied': b'403 Forbidden', 'unknown_origin': b'403 Forbidden',
    'unauthenticated': b'407 Proxy Authentication Required',
    'reflected': b'502 Bad Gateway', 'unreachable': b'502 Bad Gateway',
    'outcome_unknown': b'502 Bad Gateway', 'credential_source': b'502 Bad Gateway',
    'internal_error': b'502 Bad Gateway',
}


def refusal(code: str) -> bytes:
    """The fixed response for a refused request: no detail, no echo. A code
    outside ``REFUSAL_STATUS`` is answered as ``internal_error``."""
    if code not in REFUSAL_STATUS:
        code = 'internal_error'
    status = REFUSAL_STATUS[code]
    body = b'{"error":{"code":"' + code.encode('ascii') + b'"},"ok":false,"proxy":"garrett-stateless"}\n'
    extra = b'Proxy-Authenticate: Basic realm="garrett-stateless"\r\n' if code == 'unauthenticated' else b''
    return (b'HTTP/1.1 ' + status + b'\r\n' + extra + b'Content-Type: application/json\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)


@dataclass(frozen=True)
class DenyRule:
    method: bytes  # b'' for any method
    path: bytes


def method_ok(rule_method: bytes, method: bytes) -> bool:
    return rule_method == b'' or rule_method == method


def path_matches(rule: bytes, path: bytes) -> bool:
    """Exact, one added ``/``, and for a ``/``-ending rule the rule without
    its ``/`` or anything under it.

    Matching is on the strict parser's path, which has one canonical spelling
    (no dot segments, ``;`` or alternate escapes). It is case-sensitive like
    provider routing; a case-variant path a provider would also route is a
    known limit, as are provider-specific overrides such as a ``_method``
    query parameter.
    """
    if path == rule or path == rule + b'/':
        return True
    return rule.endswith(b'/') and (rule == path + b'/' or path.startswith(rule))


def denied(rules: tuple[DenyRule, ...], method: bytes, path: bytes) -> bool:
    return any(method_ok(rule.method, method) and path_matches(rule.path, path) for rule in rules)


def encode_upstream(request: Request, host: bytes, rules: tuple[DenyRule, ...], credential: bytes,
                    authentication: str) -> bytes:
    """The exact bytes sent upstream for an accepted request, or a refusal.
    ``authentication`` is ``'bearer'`` or ``'x-api-key'``."""
    # Re-validate what the parser ensures, so upstream framing never depends
    # on the parser.
    if request.method not in METHODS:
        raise Refused('invalid_request')
    check_target(request.target)
    forwarded = tuple((k, v) for k, v in request.fields if k.lower() not in DROPPED)
    if any(not k or any(b not in _TOKEN for b in k)
           or any(not (_visible(b) or b in b' \t') for b in v) for k, v in forwarded):
        raise Refused('invalid_request')
    if denied(rules, request.method, request.path):
        raise Refused('denied')
    name, prefix = SCHEMES[authentication]
    if (not credential or len(credential) > MAX_CREDENTIAL
            or any(not _visible(b) for b in credential)):
        raise Refused('credential_source')
    return encode_request(request, host=host, forwarded=forwarded, authentication=(name, prefix + credential))


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
    response: Response, forms: list[bytes], *, keep_alive: bool, head: bool
) -> bytes:
    """The agent's bytes for an upstream response, or a refusal on reflection."""
    fields = tuple((k, v) for k, v in response.fields if k not in DROPPED_RESPONSE)
    encoded = encode_response(response, fields=fields, keep_alive=keep_alive, head=False)
    if reflects(encoded, forms):
        raise Refused('reflected')
    return encode_response(response, fields=fields, keep_alive=keep_alive, head=head)
