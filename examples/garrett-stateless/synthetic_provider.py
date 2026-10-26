"""A synthetic OAuth identity provider and protected API, for tests and the
demonstration. It is a fixture, not part of the library: it issues
synthetic access tokens only and never sees a real account.

* ``https://<idp>/authorize``: an approval page for the human (or the
  simulated human), with ``#approve`` and ``#deny`` links;
* ``https://<idp>/approve``/``/deny``: redirect to the client's
  ``redirect_uri`` with a code (or ``error=access_denied``) and the state;
* ``https://<idp>/token``: the authorization-code exchange, checking client,
  redirect URI and the PKCE S256 verifier, each code usable once;
* ``https://<api>/...``: the protected API. It accepts only an issued
  access token as ``Authorization: Bearer`` and records, per request, the
  method, path and the SHA-256 of the credential it received (never the
  credential itself). ``/echo`` reflects the Authorization value.

Usage::

    python synthetic_provider.py --cert server.pem --key server.key \\
        --idp-listen 127.0.0.1:0 --api-listen 127.0.0.1:0 --log requests.jsonl [--jwt]

It prints one JSON line with the bound addresses and serves until stdin EOF.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import socket
import ssl
import sys
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


class Provider:
    def __init__(self, log_path: str | None, jwt: bool, issuer: str | None, client_id: str):
        self.lock = threading.Lock()
        self.transactions: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.tokens: set[str] = set()
        self.log_path = log_path
        self.jwt = jwt
        self.issuer = issuer
        self.client_id = client_id

    def record(self, event: dict) -> None:
        if self.log_path:
            with self.lock, open(self.log_path, 'a') as handle:
                handle.write(json.dumps(event, sort_keys=True) + '\n')

    def access_token(self, scope: str) -> str:
        if not self.jwt:
            return 'syn_' + secrets.token_urlsafe(24)
        header = b64url(json.dumps({'alg': 'RS256', 'typ': 'at+jwt'}).encode())
        claims = {'iss': self.issuer or 'https://idp.test', 'aud': 'https://api.test', 'sub': 'user-1234',
                  'email': 'octocat@example.test', 'scope': scope, 'client_id': self.client_id,
                  'iat': int(time.time()), 'exp': int(time.time()) + 3600, 'jti': secrets.token_hex(8)}
        payload = b64url(json.dumps(claims, separators=(',', ':')).encode())
        return f'{header}.{payload}.{b64url(secrets.token_bytes(32))}'

    def idp(self, method: str, path: str, query: dict, body: dict) -> tuple[int, dict, bytes]:
        if method == 'GET' and path == '/authorize':
            if (query.get('response_type') != 'code' or query.get('client_id') != self.client_id
                    or query.get('code_challenge_method') != 'S256' or not query.get('code_challenge')):
                return 400, {}, b'invalid authorization request'
            txn = secrets.token_hex(16)
            with self.lock:
                self.transactions[txn] = query
            page = (f'<!doctype html><title>Synthetic IdP</title><h1>Sign in to the synthetic provider</h1>'
                    f'<p>Client <code>{query["client_id"]}</code> asks for <code>{query.get("scope", "")}</code>.</p>'
                    f'<a id=approve href="/approve?txn={txn}">Approve</a> <a id=deny href="/deny?txn={txn}">Deny</a>')
            return 200, {'Content-Type': 'text/html'}, page.encode()
        if method == 'GET' and path in ('/approve', '/deny'):
            with self.lock:
                txn = self.transactions.pop(query.get('txn', ''), None)
            if txn is None:
                return 400, {}, b'unknown transaction'
            params = {'state': txn['state']}
            if path == '/approve':
                code = secrets.token_urlsafe(16)
                with self.lock:
                    self.codes[code] = txn
                params['code'] = code
            else:
                params['error'] = 'access_denied'
            if self.issuer:
                params['iss'] = self.issuer
            return 302, {'Location': txn['redirect_uri'] + '?' + urlencode(params)}, b''
        if method == 'POST' and path == '/token':
            with self.lock:
                txn = self.codes.pop(body.get('code', ''), None)
            verifier = body.get('code_verifier', '')
            if (txn is None or body.get('grant_type') != 'authorization_code'
                    or body.get('client_id') != self.client_id or body.get('redirect_uri') != txn['redirect_uri']
                    or b64url(hashlib.sha256(verifier.encode()).digest()) != txn['code_challenge']):
                return 400, {'Content-Type': 'application/json'}, b'{"error":"invalid_grant"}'
            token = self.access_token(txn.get('scope', ''))
            with self.lock:
                self.tokens.add(token)
            self.record({'event': 'token_issued', 'credential_sha256': hashlib.sha256(token.encode()).hexdigest()})
            reply = {'access_token': token, 'token_type': 'bearer', 'expires_in': 3600,
                     'scope': txn.get('scope', ''), 'refresh_token': 'rt_' + secrets.token_urlsafe(24)}
            return 200, {'Content-Type': 'application/json'}, json.dumps(reply).encode()
        return 404, {}, b'not found'

    def api(self, method: str, path: str, query: dict, headers: dict, body: bytes) -> tuple[int, dict, bytes]:
        auth = headers.get('authorization', '')
        presented = auth[len('Bearer '):] if auth.startswith('Bearer ') else ''
        with self.lock:
            known = presented in self.tokens or presented.startswith('syn_static_')
        self.record({'event': 'api_request', 'method': method, 'path': path, 'body_bytes': len(body),
                     'credential_sha256': hashlib.sha256(presented.encode()).hexdigest() if presented else None,
                     'authorized': known})
        if not known:
            return 401, {'Content-Type': 'application/json'}, b'{"message":"Bad credentials"}'
        if path == '/echo':
            return 200, {'Content-Type': 'text/plain'}, auth.encode()
        reply = {'login': 'octocat', 'method': method, 'path': path, 'query': query, 'body_bytes': len(body)}
        status = 201 if method == 'POST' else 200
        return status, {'Content-Type': 'application/json'}, json.dumps(reply, sort_keys=True).encode()


def read_request(sock) -> tuple[str, str, dict, dict, bytes]:
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError
        data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    lines = head.decode('latin-1').split('\r\n')
    method, target, _ = lines[0].split(' ')
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(':')
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get('content-length', '0'))
    while len(body) < length:
        body += sock.recv(4096)
    parts = urlsplit(target)
    return method, parts.path, dict(parse_qsl(parts.query)), headers, body


def serve(listener: socket.socket, context: ssl.SSLContext, handle) -> None:
    while True:
        try:
            raw, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=one, args=(raw, context, handle), daemon=True).start()


def one(raw, context, handle) -> None:
    try:
        raw.settimeout(15)
        with context.wrap_socket(raw, server_side=True) as sock:
            method, path, query, headers, body = read_request(sock)
            status, extra, payload = handle(method, path, query, headers, body)
            reason = {200: 'OK', 201: 'Created', 302: 'Found', 400: 'Bad Request', 401: 'Unauthorized',
                      404: 'Not Found'}.get(status, 'Status')
            head = f'HTTP/1.1 {status} {reason}\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n'
            head += ''.join(f'{k}: {v}\r\n' for k, v in extra.items())
            sock.sendall(head.encode() + b'\r\n' + payload)
    except (OSError, ssl.SSLError, ValueError, ConnectionError):
        pass


def bind(address: str) -> socket.socket:
    host, _, port = address.rpartition(':')
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, int(port)))
    sock.listen(16)
    return sock


def start(cert: str, key: str, idp_listen: str, api_listen: str, log: str | None, jwt: bool = False,
          issuer: str | None = None, client_id: str = 'synthetic-client') -> tuple[Provider, str, str]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    provider = Provider(log, jwt, issuer, client_id)
    idp, api = bind(idp_listen), bind(api_listen)
    threading.Thread(target=serve, daemon=True,
                     args=(idp, context, lambda m, p, q, h, b: provider.idp(m, p, q, dict(parse_qsl(b.decode()))))).start()
    threading.Thread(target=serve, daemon=True, args=(api, context, provider.api)).start()
    name = lambda s: '%s:%d' % s.getsockname()[:2]  # noqa: E731
    return provider, name(idp), name(api)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--idp-listen', default='127.0.0.1:0')
    parser.add_argument('--api-listen', default='127.0.0.1:0')
    parser.add_argument('--log')
    parser.add_argument('--jwt', action='store_true')
    parser.add_argument('--issuer')
    parser.add_argument('--client-id', default='synthetic-client')
    parser.add_argument('--until-stdin-eof', action='store_true', help='the default; accepted for symmetry')
    args = parser.parse_args()
    _, idp, api = start(args.cert, args.key, args.idp_listen, args.api_listen, args.log, args.jwt, args.issuer,
                        args.client_id)
    print(json.dumps({'api': api, 'idp': idp, 'role': 'synthetic-provider'}), flush=True)
    sys.stdin.read()


if __name__ == '__main__':
    main()
