"""Use garrett-stateless-v1 as a library, in one process, with no repository
checkout: a development PKI, key sets, a tiny local HTTPS API standing in for
the provider, the stateless proxy, an operator-minted surrogate, an ordinary
request through the proxy, and a copied surrogate refused.

    pip install aivm-secrets        # or the wheel
    python library_example.py

(The OAuth login flow is shown by ``walkthrough.py``.)
"""
from __future__ import annotations

import http.server
import json
import ssl
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from aivm_secrets.garrett_stateless import Agent, Endpoint, Proxy, ProxyConfig, inspect
from aivm_secrets.garrett_stateless import decisions, pki
from aivm_secrets.garrett_stateless.broker import mint_with
from aivm_secrets.garrett_stateless.files import write_private
from aivm_secrets.garrett_stateless.keys import BrokerKeys
from aivm_secrets.garrett_stateless.token import ClaimCopy

CREDENTIAL = b'example_REAL_provider_token_0123456789'


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix='garrett-library-'))
    ca = pki.create_ca('example CA')
    server = pki.issue(ca, server_names=['proxy.example', 'api.example'])
    agent = pki.issue(ca, client_name='agent', uri='spiffe://example/agent')
    other = pki.issue(ca, client_name='other')
    for name, issued in (('server', server), ('agent', agent), ('other', other)):
        (root / f'{name}.pem').write_bytes(issued.certificate)
        write_private(root / f'{name}.key', issued.key)
    (root / 'ca.pem').write_bytes(ca.certificate)

    # The protected API: answers only to the real credential.
    seen = []

    class API(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'  # the proxy accepts HTTP/1.1 responses only

        def do_GET(self):
            seen.append(self.headers.get('Authorization'))
            ok = self.headers.get('Authorization') == 'Bearer ' + CREDENTIAL.decode()
            body = json.dumps({'login': 'example-user'} if ok else {'message': 'Bad credentials'}).encode()
            self.send_response(200 if ok else 401)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    api = http.server.ThreadingHTTPServer(('127.0.0.1', 0), API)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    api.socket = context.wrap_socket(api.socket, server_side=True)
    threading.Thread(target=api.serve_forever, daemon=True).start()

    # Keys: the broker's set signs; the proxy's set only verifies and opens.
    keys = BrokerKeys.generate('https://broker.example')
    write_private(root / 'proxy-keys.json', keys.export_proxy().to_json())
    (root / 'proxy.json').write_text(json.dumps({
        'schema': 'garrett-stateless-v1/proxy', 'listen': '127.0.0.1:0', 'authority': 'proxy.example:8443',
        'certificate': 'server.pem', 'private_key': 'server.key', 'client_ca': 'ca.pem', 'keys': 'proxy-keys.json',
        'audiences': ['https://proxy.example'],
        'routes': [{'provider': 'api', 'host': 'api.example', 'address': '127.0.0.1', 'port': api.server_address[1],
                    'ca_file': 'ca.pem', 'authentication': 'bearer'}]}))
    proxy = Proxy.from_file(root / 'proxy.json').serve()

    # Operator issuance: wrap the credential for the agent's certificate.
    policy = decisions.IssuePolicy('https://broker.example', 'https://proxy.example', ('api',), 900, 3600)
    der = x509.load_pem_x509_certificate(agent.certificate).public_bytes(serialization.Encoding.DER)
    surrogate = mint_with(keys, policy, 'api', CREDENTIAL, der, ClaimCopy(), 900, int(time.time()))
    header, payload = inspect(surrogate.token)
    print('surrogate for', payload['sub'], 'provider', payload['prv'], 'expires', payload['exp'])
    assert CREDENTIAL.decode() not in surrogate.token

    endpoint = Endpoint.parse('https://proxy.example:8443', proxy.address)
    mine = Agent(root / 'ca.pem', root / 'agent.pem', root / 'agent.key')
    response = mine.request(endpoint, surrogate.token, 'GET', '/user')
    print('agent  ->', response.status, response.body.decode())
    thief = Agent(root / 'ca.pem', root / 'other.pem', root / 'other.key')
    stolen = thief.request(endpoint, surrogate.token, 'GET', '/user')
    print('other  ->', stolen.status, stolen.body.decode().strip())
    assert response.status == 200 and stolen.status == 401
    assert seen == ['Bearer ' + CREDENTIAL.decode()], 'the API saw exactly one request, with the real credential'
    proxy.stop()
    api.shutdown()
    print('ok')


if __name__ == '__main__':
    main()
