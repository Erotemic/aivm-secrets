"""Byte parity between the Python ``core.proxy_http`` and the extracted Rust.

``tests/vectors/proxy-http-v1.tsv`` records, for a corpus of guest
requests, what the Python reference does: needs more bytes, refuses with a
code, or accepts and sends exact upstream bytes. This test checks the file
is exactly the Python reference's output; the Rust unit test
``proxy_http::tests::python_reference_vectors`` checks the extracted core
against every line. Together they are a two-sided byte-equality oracle.

Regenerate after an intended change with::

    python -c "import tests.test_proxy_http_vectors as t; t.write()"
"""

from __future__ import annotations

from pathlib import Path

from garrett_stateless.core import proxy_http as http1
from garrett_stateless.core.proxy_http import DenyRule, Refused, encode_upstream, guest_response, reflection_forms

VECTORS = Path(__file__).resolve().parent / 'vectors' / 'proxy-http-v1.tsv'
RESPONSES = Path(__file__).resolve().parent / 'vectors' / 'proxy-http-response-v1.tsv'
REFUSALS = Path(__file__).resolve().parent / 'vectors' / 'proxy-http-refusal-v1.tsv'
REFUSAL_CODES = ('invalid_request', 'too_large', 'denied', 'unknown_origin', 'unauthenticated',
                 'reflected', 'unreachable', 'outcome_unknown', 'credential_source')
HOST = b'api.example.org'
LIMIT = 64
DENY = (DenyRule(b'POST', b'/v1/tokens'), DenyRule(b'', b'/v1/admin/'))
CODES = {'invalid_request': 'invalid', 'too_large': 'large', 'denied': 'denied',
         'credential_source': 'credential', 'upstream_response': 'upstream',
         'reflected': 'reflected'}


def head(line: bytes, *fields: bytes) -> bytes:
    return line + b'\r\n' + b''.join(f + b'\r\n' for f in fields) + b'\r\n'


def corpus() -> list[tuple[bytes, bytes, str]]:
    """(raw guest bytes, credential, scheme) cases; adversarial and positive."""
    h = b'Host: api.example.org'
    cases = [
        head(b'GET /v1/account HTTP/1.1', h),
        head(b'GET /v1/account HTTP/1.1', h, b'Authorization: Bearer placeholder',
             b'X-Api-Key: guest', b'Cookie: a=b', b'Accept-Encoding: gzip', b'X-Trace:  t  '),
        head(b'GET /v1/issues?state=open&page=2 HTTP/1.1', b'HOST: API.EXAMPLE.ORG:443'),
        head(b'HEAD / HTTP/1.1', h, b'Connection: keep-alive, close'),
        head(b'DELETE /v1/issues/7 HTTP/1.1', h),
        head(b'OPTIONS /v1/ HTTP/1.1', h),
        head(b'POST /v1/issues HTTP/1.1', h, b'Content-Length: 5') + b'hello',
        head(b'POST /v1/issues HTTP/1.1', h, b'Content-Length: 0'),
        head(b'PUT /v1/issues/7 HTTP/1.1', h, b'Transfer-Encoding: chunked')
        + b'3\r\nabc\r\nA\r\n0123456789\r\n0\r\n\r\n',
        head(b'PATCH /v1/issues/7 HTTP/1.1', h, b'Content-Length: 3') + b'abcEXTRA',
        # Incomplete input.
        b'GET /v1/account HTTP/1.1\r\nHost: api.example.org\r\n',
        head(b'POST /v1/issues HTTP/1.1', h, b'Content-Length: 9') + b'abc',
        head(b'POST /v1/issues HTTP/1.1', h, b'Transfer-Encoding: chunked') + b'3\r\nab',
        # Framing ambiguity and refused fields.
        head(b'GET / HTTP/1.1', h, b'Content-Length: 0', b'Transfer-Encoding: chunked'),
        head(b'GET / HTTP/1.1', h, b'Content-Length: 1', b'Content-Length: 1'),
        head(b'GET / HTTP/1.1', h, b'Content-Length: +1'),
        head(b'GET / HTTP/1.1', h, b'Content-Length: 1234567890123'),
        head(b'GET / HTTP/1.1', h, b'Transfer-Encoding: gzip, chunked'),
        head(b'GET / HTTP/1.1', h, b'Transfer-Encoding: Chunked'),
        head(b'GET / HTTP/1.1', h, b'X-Folded: a', b' b'),
        b'GET / HTTP/1.1\nHost: api.example.org\r\n\r\n',
        head(b'GET / HTTP/1.1', h, b'X-Bad: a\rb'),
        head(b'GET / HTTP/1.1', h, b'X-Nul: a\x00b'),
        head(b'GET / HTTP/1.1', h, b'Bad Name: x'),
        head(b'GET / HTTP/1.1', h, b': empty'),
        head(b'GET / HTTP/1.1', h, b'X-High: caf\xc3\xa9'),
        head(b'GET / HTTP/1.1', h, b'Upgrade: h2c'),
        head(b'GET / HTTP/1.1', h, b'Expect: 100-continue'),
        head(b'GET / HTTP/1.1', h, b'TE: trailers'),
        head(b'GET / HTTP/1.1', h, b'Connection: upgrade'),
        head(b'GET / HTTP/1.1', h, b'Connection: '),
        head(b'GET / HTTP/1.1', b'Host: other.example.org'),
        head(b'GET / HTTP/1.1', h, h),
        head(b'GET / HTTP/1.1'),
        head(b'GET / HTTP/1.0', h),
        head(b'GET  / HTTP/1.1', h),
        head(b'TRACE / HTTP/1.1', h),
        head(b'get / HTTP/1.1', h),
        head(b'GET https://api.example.org/ HTTP/1.1', h),
        head(b'GET /a/../b HTTP/1.1', h),
        head(b'GET /a/./b HTTP/1.1', h),
        head(b'GET /a//b HTTP/1.1', h),
        head(b'GET /a%2Fb HTTP/1.1', h),
        head(b'GET /a%2e%2E/b HTTP/1.1', h),
        head(b'GET /a%5cb HTTP/1.1', h),
        head(b'GET /a%00 HTTP/1.1', h),
        head(b'GET /a\\b HTTP/1.1', h),
        head(b'GET /a#frag HTTP/1.1', h),
        head(b'GET /a/ HTTP/1.1', h),
        # Chunk grammar.
        head(b'POST / HTTP/1.1', h, b'Transfer-Encoding: chunked') + b'3;x=y\r\nabc\r\n0\r\n\r\n',
        head(b'POST / HTTP/1.1', h, b'Transfer-Encoding: chunked') + b'3\r\nabcX\r\n0\r\n\r\n',
        head(b'POST / HTTP/1.1', h, b'Transfer-Encoding: chunked') + b'0\r\nTrailer: x\r\n\r\n',
        head(b'POST / HTTP/1.1', h, b'Transfer-Encoding: chunked') + b'123456789\r\n',
        # Size limits (LIMIT bytes of body).
        head(b'POST / HTTP/1.1', h, b'Content-Length: 65') + b'x' * 65,
        head(b'POST / HTTP/1.1', h, b'Transfer-Encoding: chunked') + b'41\r\n' + b'x' * 65 + b'\r\n0\r\n\r\n',
        head(b'GET / HTTP/1.1', h, *[b'X-%d: v' % i for i in range(101)]),
        # Review findings: equivalent spellings and overrides.
        head(b'POST /v1/tokens/ HTTP/1.1', h, b'Content-Length: 0'),
        head(b'POST /v1/%74okens HTTP/1.1', h, b'Content-Length: 0'),
        head(b'GET /v1/%61dmin/x HTTP/1.1', h),
        head(b'GET /v1/admin HTTP/1.1', h),
        head(b'GET /v1/admin;x/y HTTP/1.1', h),
        head(b'POST /v1/tokens; HTTP/1.1', h, b'Content-Length: 0'),
        head(b'GET /a%2 HTTP/1.1', h),
        head(b'GET /a%zz HTTP/1.1', h),
        head(b'GET /a%20b%25 HTTP/1.1', h),
        head(b'GET /v1/issues HTTP/1.1', h, b'X-HTTP-Method-Override: DELETE',
             b'x-method-override: DELETE', b'X-Http-Method: DELETE', b'Range: bytes=0-9',
             b'If-Range: x'),
        # Deny list.
        head(b'POST /v1/tokens HTTP/1.1', h, b'Content-Length: 0'),
        head(b'GET /v1/tokens HTTP/1.1', h),
        head(b'GET /v1/admin/users?x=1 HTTP/1.1', h),
        head(b'GET /v1/admin HTTP/1.1', h),
    ]
    rows = [(raw, b'SECRET-token_1', 'bearer') for raw in cases]
    rows += [(cases[1], b'k3y', 'x-api-key'), (cases[0], b'', 'bearer'),
             (cases[0], b'bad secret', 'bearer'), (cases[0], b'x' * 4097, 'x-api-key'),
             (cases[0], b'x' * 4096, 'bearer')]
    return rows


def outcome(raw: bytes, credential: bytes, scheme: str) -> str:
    try:
        parsed = http1.parse_request(raw, host=HOST, body_limit=LIMIT)
        if parsed is None:
            return 'more'
        request, rest = parsed
        wire = encode_upstream(request, HOST, DENY, credential, scheme)
    except Refused as refused:
        return 'refused:' + CODES[refused.code]
    return f'ok:{len(raw) - len(rest)}:{wire.hex()}'


def render() -> str:
    lines = ['# raw-hex\tcredential-hex\tscheme\toutcome  (deny: POST /v1/tokens, * /v1/admin/; limit 64)']
    for raw, credential, scheme in corpus():
        lines.append('\t'.join([raw.hex(), credential.hex(), scheme,
                                outcome(raw, credential, scheme)]))
    return '\n'.join(lines) + '\n'


def response_corpus() -> list[tuple[bytes, bool, bool, bytes]]:
    """(raw upstream bytes, HEAD request, keep-alive, credential)."""
    import base64
    from urllib.parse import quote

    secret = b'SECRET-token_1'

    def r(status: bytes, *fields: bytes, body: bytes = b'') -> bytes:
        return status + b'\r\n' + b''.join(f + b'\r\n' for f in fields) + b'\r\n' + body

    cl = lambda body: b'Content-Length: %d' % len(body)
    ok = b'{"login":"demo"}'
    cases = [
        r(b'HTTP/1.1 200 OK', b'Content-Type: application/json', cl(ok), body=ok),
        r(b'HTTP/1.1 201 Created', b'Transfer-Encoding: chunked', body=b'3\r\nabc\r\n0\r\n\r\n'),
        r(b'HTTP/1.1 200 OK', b'X-Note: close-delimited', body=b'abcdef'),
        r(b'HTTP/1.1 204 No Content', body=b'ignored'),
        r(b'HTTP/1.1 304 Not Modified', cl(b'12345')),
        r(b'HTTP/1.1 200', cl(b'')),
        r(b'HTTP/1.1 200 ', cl(b'')),
        r(b'HTTP/1.1 404 Not\tFound', cl(b'{}'), body=b'{}'),
        r(b'HTTP/1.1 302 Found', b'Location: https://evil.example.net/x', cl(b'')),
        r(b'HTTP/1.1 200 OK', b'Set-Cookie: s=1', b'Connection: keep-alive', b'Keep-Alive: 5',
          b'Proxy-Authenticate: Basic', b'X-Keep: yes', cl(b'ab'), body=b'ab'),
        r(b'HTTP/1.1 200 OK', b'Content-Encoding: gzip', cl(b'xx'), body=b'xx'),
        r(b'HTTP/1.1 200 OK', b'Content-Encoding: IDENTITY', cl(b'xx'), body=b'xx'),
        r(b'HTTP/1.1 199 Early', cl(b'')),
        r(b'HTTP/1.1 999 Odd', cl(b'')),
        r(b'HTTP/1.0 200 OK', cl(b'')),
        r(b'HTTP/1.1 2000 OK', cl(b'')),
        r(b'HTTP/1.1  200 OK', cl(b'')),
        r(b'HTTP/1.1 200 OK', b'Bad Header: x', cl(b'')),
        r(b'HTTP/1.1 200 OK', cl(b'12345'), body=b'12'),
        r(b'HTTP/1.1 200 OK', cl(b'1'), cl(b'1'), body=b'1'),
        r(b'HTTP/1.1 200 OK', cl(b'1'), b'Transfer-Encoding: chunked', body=b'1'),
        r(b'HTTP/1.1 200 OK', b'Transfer-Encoding: chunked', body=b'3\r\nab'),
        r(b'HTTP/1.1 200 OK', cl(b'x' * 65), body=b'x' * 65),
        r(b'HTTP/1.1 200 OK', body=b'x' * 65),
        b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n',
        r(b'HTTP/1.1 200 OK', cl(secret), body=secret),
        r(b'HTTP/1.1 200 OK', b'X-Echo: ' + secret, cl(b'')),
        r(b'HTTP/1.1 200 ' + secret, cl(b'')),
        r(b'HTTP/1.1 200 OK', cl(b'')) + b'',
    ]
    plain64 = base64.b64encode(b'pad' + secret)
    wrapped = b'\r\n'.join(plain64[i:i + 16] for i in range(0, len(plain64), 16))
    encodings = [wrapped,
                 base64.b64encode(b'x-access-token:' + secret),
                 base64.urlsafe_b64encode(b'ab' + secret),
                 base64.b64encode(b'a' + secret),
                 quote(secret + b'/', safe='').upper().encode(),
                 secret.hex().upper().encode(),
                 secret.lower()]
    for form in encodings:
        body = b'{"e":"' + form + b'"}'
        cases.append(r(b'HTTP/1.1 200 OK', cl(body), body=body))
    rows = [(raw, False, False, secret) for raw in cases]
    slashed = b'AKIA/EXAMPLE/KEY_1'
    for body in (b'{"k":"AKIA\\/EXAMPLE\\/KEY_1"}', b'{"k":"AKIA/EXAMPLE/KEY_1"}'):
        rows.append((r(b'HTTP/1.1 200 OK', cl(body), body=body), False, False, slashed))
    rows += [(cases[0], True, False, secret), (cases[0], False, True, secret),
             (cases[1], True, True, secret), (cases[0], False, False, b'abc')]
    return rows


def response_outcome(raw: bytes, head: bool, keep_alive: bool, secret: bytes) -> str:
    try:
        response = http1.parse_response(raw, method=b'HEAD' if head else b'GET',
                                        body_limit=LIMIT, complete=True)
        wire = guest_response(response, reflection_forms(secret), keep_alive=keep_alive,
                              head=head)
    except Refused as refused:
        return 'refused:' + CODES[refused.code]
    return 'ok:' + wire.hex()


def render_responses() -> str:
    lines = ['# raw-hex\thead\tkeep-alive\tcredential-hex\toutcome  (limit 64)']
    for raw, head, keep, secret in response_corpus():
        lines.append('\t'.join([raw.hex(), str(int(head)), str(int(keep)), secret.hex(),
                                response_outcome(raw, head, keep, secret)]))
    return '\n'.join(lines) + '\n'


def render_refusals() -> str:
    lines = ['# code\trefusal-hex']
    lines += [f'{code}\t{http1.refusal(code).hex()}' for code in REFUSAL_CODES]
    return '\n'.join(lines) + '\n'


def write() -> None:
    VECTORS.write_text(render())
    RESPONSES.write_text(render_responses())
    REFUSALS.write_text(render_refusals())


def test_refusal_vector_file_is_the_python_reference():
    assert REFUSALS.read_text() == render_refusals()


def test_response_vector_file_is_the_python_reference():
    assert RESPONSES.read_text() == render_responses()


def test_vector_file_is_the_python_reference():
    assert VECTORS.read_text() == render()


def test_corpus_covers_every_outcome_kind():
    kinds = {line.split('\t')[3].split(':')[0] + (':' + line.split('\t')[3].split(':')[1]
             if line.split('\t')[3].startswith('refused') else '')
             for line in render().splitlines()[1:]}
    assert kinds >= {'ok', 'more', 'refused:invalid', 'refused:large', 'refused:denied',
                     'refused:credential'}
