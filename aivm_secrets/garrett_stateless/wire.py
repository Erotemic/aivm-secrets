"""A small, strict HTTP/1.1 subset for the broker endpoints and HTTPS
clients (one request per connection), matching the Rust crate's ``http``."""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field

from ..proxy import http1

MAX_HEAD = 16384
MAX_BODY = 65536
IO_TIMEOUT = 15.0
_UNRESERVED = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~')


class ProtocolError(Exception):
    """A closed error code (spec section 13)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def percent_encode(text: str) -> str:
    return ''.join(chr(b) if b in _UNRESERVED else f'%{b:02X}' for b in text.encode('utf-8'))


def percent_decode(text: str, plus_is_space: bool = True) -> str | None:
    data = text.encode('utf-8')
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == ord('%'):
            hex_ = data[i + 1:i + 3]
            if len(hex_) != 2 or any(c not in b'0123456789abcdefABCDEF' for c in hex_):
                return None
            out.append(int(hex_, 16))
            i += 3
        elif b == ord('+') and plus_is_space:
            out.append(0x20)
            i += 1
        else:
            out.append(b)
            i += 1
    try:
        return out.decode('utf-8')
    except UnicodeDecodeError:
        return None


def form(pairs: list[tuple[str, str]]) -> str:
    return '&'.join(f'{percent_encode(k)}={percent_encode(v)}' for k, v in pairs)


def parse_query(text: str) -> list[tuple[str, str]] | None:
    if not text:
        return []
    out = []
    for pair in text.split('&'):
        key, _, value = pair.partition('=')
        k, v = percent_decode(key), percent_decode(value)
        if k is None or v is None:
            return None
        out.append((k, v))
    return out


@dataclass
class Request:
    method: str
    path: str
    query: list[tuple[str, str]] = field(default_factory=list)
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b''

    def header(self, name: str) -> str | None:
        return next((v for n, v in self.headers if n.lower() == name.lower()), None)

    def param(self, name: str) -> str | None:
        """A parameter occurring at most once; ``ValueError`` if repeated."""
        values = [v for n, v in self.query if n == name]
        if len(values) > 1:
            raise ValueError(name)
        return values[0] if values else None


def read_request(sock) -> Request:
    data = b''
    while b'\r\n\r\n' not in data:
        if len(data) > MAX_HEAD:
            raise ProtocolError('invalid_request')
        chunk = sock.recv(4096)
        if not chunk:
            raise ProtocolError('invalid_request')
        data += chunk
    end = data.index(b'\r\n\r\n')
    try:
        lines = data[:end].decode('utf-8').split('\r\n')
    except UnicodeDecodeError:
        raise ProtocolError('invalid_request') from None
    parts = lines[0].split(' ')
    if len(parts) != 3 or parts[2] != 'HTTP/1.1':
        raise ProtocolError('invalid_request')
    path, _, query = parts[1].partition('?')
    params = parse_query(query)
    if params is None:
        raise ProtocolError('invalid_request')
    request = Request(parts[0], path, params)
    for line in lines[1:]:
        name, colon, value = line.partition(':')
        if not colon or not name or ' ' in name:
            raise ProtocolError('invalid_request')
        request.headers.append((name, value.strip()))
    if request.header('transfer-encoding') is not None:
        raise ProtocolError('invalid_request')
    length_text = request.header('content-length') or '0'
    if not length_text.isdigit() or int(length_text) > MAX_BODY:
        raise ProtocolError('invalid_request')
    length = int(length_text)
    body = data[end + 4:]
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProtocolError('invalid_request')
        body += chunk
    if len(body) != length:
        raise ProtocolError('invalid_request')
    request.body = body
    return request


_REASONS = {200: 'OK', 201: 'Created', 202: 'Accepted', 302: 'Found', 400: 'Bad Request', 401: 'Unauthorized',
            403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 410: 'Gone', 429: 'Too Many Requests',
            502: 'Bad Gateway'}


def response(status: int, content_type: str, body: bytes, extra: tuple[tuple[str, str], ...] = ()) -> bytes:
    head = f'HTTP/1.1 {status} {_REASONS.get(status, "Error")}\r\nContent-Type: {content_type}\r\n'
    head += f'Content-Length: {len(body)}\r\n'
    for name, value in extra:
        head += f'{name}: {value}\r\n'
    head += 'Cache-Control: no-store\r\nConnection: close\r\n\r\n'
    return head.encode('ascii') + body


def request_bytes(method: str, target: str, host: str, headers: list[tuple[str, str]], body: bytes) -> bytes:
    head = f'{method} {target} HTTP/1.1\r\nHost: {host}\r\n'
    for name, value in headers:
        head += f'{name}: {value}\r\n'
    if body or method in ('POST', 'PUT', 'PATCH'):
        head += f'Content-Length: {len(body)}\r\n'
    head += 'Connection: close\r\n\r\n'
    return head.encode('ascii') + body


def _address(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(':')
    return host.strip('[]'), int(port)


def exchange(context: ssl.SSLContext, address: str, server_name: str, request: bytes, limit: int) -> bytes:
    """Connect, authenticate the server as ``server_name``, send, read to close."""
    try:
        raw = socket.create_connection(_address(address), timeout=IO_TIMEOUT)
    except OSError:
        raise ProtocolError('unreachable') from None
    with raw, context.wrap_socket(raw, server_hostname=server_name) as tls:
        tls.sendall(request)
        out = b''
        while True:
            try:
                chunk = tls.recv(65536)
            except ssl.SSLEOFError:
                break
            if not chunk:
                break
            out += chunk
            if len(out) > limit:
                raise ProtocolError('response_too_large')
    return out


@dataclass
class Response:
    status: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes

    def header(self, name: str) -> str | None:
        value = next((v for k, v in self.headers if k == name.lower().encode()), None)
        return None if value is None else value.decode('latin-1')


def parse_response(raw: bytes, method: str = 'GET', limit: int = 32 << 20) -> Response:
    try:
        parsed = http1.parse_response(raw, method=method.encode('ascii'), body_limit=limit, complete=True)
    except http1.Refused:
        raise ProtocolError('invalid_response') from None
    if parsed is None:
        raise ProtocolError('invalid_response')
    return Response(parsed.status, parsed.fields, parsed.body)
