"""A narrated, synthetic walkthrough of garrett-stateless-v1.

It drives the real `garrett-stateless` command-line programs: the Rust
broker and proxy (and a Python proxy replica), the Rust agent client, the
development PKI and key tools. Only the identity provider and the protected
API are fixtures (``synthetic_provider.py``). Everything runs on loopback
with synthetic credentials; nothing here touches a real account.

    python walkthrough.py [--pause] [--rust BIN] [--python-cmd CMD] [--workdir DIR]

The final line on stdout is a JSON evidence report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import ssl
import socket
import subprocess
import sys
import tempfile
import textwrap
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent


class Demo:
    def __init__(self, args):
        self.pause = args.pause
        self.rust = [args.rust]
        self.python = shlex.split(args.python_cmd)
        self.root = Path(args.workdir or tempfile.mkdtemp(prefix='garrett-stateless-demo-'))
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.processes: list[subprocess.Popen] = []
        self.evidence: dict = {'profile': 'garrett-stateless-v1', 'synthetic': True}
        self.step_number = 0

    # --- narration ---------------------------------------------------------

    def step(self, title: str, text: str) -> None:
        self.step_number += 1
        print(f'\n\033[1m== {self.step_number}. {title}\033[0m', file=sys.stderr)
        print(textwrap.fill(textwrap.dedent(text).strip(), 88), file=sys.stderr)
        if self.pause:
            input('\n[Enter to continue] ')

    def say(self, text: str) -> None:
        print('   ' + text, file=sys.stderr)

    def show(self, command: list[str]) -> None:
        shown = ' '.join(shlex.quote(str(c)) for c in command)
        print(f'   $ {shown}', file=sys.stderr)

    # --- processes ---------------------------------------------------------

    def run(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess:
        self.show(command)
        result = subprocess.run(command, cwd=self.root, capture_output=True, timeout=120)
        if check and result.returncode not in (0, 22):
            raise SystemExit(f'failed: {command}\n{result.stderr.decode()}')
        return result

    def serve(self, command: list[str]) -> tuple[subprocess.Popen, dict]:
        self.show(command)
        process = subprocess.Popen(command + ['--until-stdin-eof'], cwd=self.root, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        line = process.stdout.readline()
        if not line:
            raise SystemExit(process.stderr.read().decode())
        return process, json.loads(line)

    def stop(self, process: subprocess.Popen) -> str:
        process.stdin.close()
        process.wait(10)
        self.processes.remove(process)
        return process.stderr.read().decode()

    def close(self) -> None:
        for process in list(self.processes):
            try:
                self.stop(process)
            except Exception:  # noqa: BLE001 - cleanup only
                process.kill()

    # --- the simulated human's browser -------------------------------------

    def browse(self, url: str, connect: str) -> tuple[int, dict, bytes]:
        parts = urlsplit(url)
        target = parts.path + ('?' + parts.query if parts.query else '')
        context = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        host, port = connect.rsplit(':', 1)
        with socket.create_connection((host, int(port)), timeout=15) as raw, \
                context.wrap_socket(raw, server_hostname=parts.hostname) as tls:
            tls.sendall(f'GET {target} HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n\r\n'.encode())
            data = b''
            while chunk := tls.recv(65536):
                data += chunk
        head, _, body = data.partition(b'\r\n\r\n')
        lines = head.decode().split('\r\n')
        headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(':') for line in lines[1:])}
        return int(lines[0].split(' ')[1]), headers, body

    # --- helpers -------------------------------------------------------------

    def write(self, name: str, value) -> None:
        (self.root / name).write_text(value if isinstance(value, str) else json.dumps(value, indent=1))

    def provider_log(self) -> list[dict]:
        path = self.root / 'provider-log.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def agent(self, name: str, *args: str, binary=None) -> list[str]:
        return (binary or self.rust) + ['agent', *args, '--ca', 'ca.pem', '--cert', f'{name}.pem',
                                        '--key', f'{name}.key']

    def request(self, name: str, proxy: str, target: str, *extra: str, binary=None) -> tuple[int, bytes]:
        result = self.run(self.agent(name, 'request', '--proxy', 'https://proxy.test:8443', '--connect', proxy,
                                     '--token-file', 'surrogate', *extra, target, binary=binary), check=False)
        status = json.loads(result.stderr.decode().strip().splitlines()[-1])['status']
        self.say(f'-> HTTP {status}: {result.stdout.decode()[:160]}')
        return status, result.stdout

    # --- the walkthrough ----------------------------------------------------

    def main(self) -> None:
        self.step('What this shows', '''
            An untrusted agent uses a provider API through a proxy without ever holding the
            provider credential. The broker runs the browser login and wraps the real token in a
            signed surrogate that is encrypted and bound to the agent's client certificate. The
            proxy checks that binding on every request, swaps in the real token, and keeps no
            state at all. This is a synthetic, single-container run: container isolation is not
            VM isolation, and the agent key here is a software key, not a TPM key.''')

        self.step('Development PKI and broker keys', '''
            A CA issues one server certificate (broker, proxy, synthetic provider) and two agent
            client certificates. The broker key set holds signing and sealing keys; the proxy key
            set is exported without the signing keys or the login-state key.''')
        self.run(self.rust + ['pki', 'ca', '--name', 'demo CA', '--cert', 'ca.pem', '--key', 'ca.key'])
        self.run(self.rust + ['pki', 'server', '--ca-cert', 'ca.pem', '--ca-key', 'ca.key', '--name', 'broker.test',
                              '--name', 'proxy.test', '--name', 'idp.test', '--name', 'api.test',
                              '--cert', 'server.pem', '--key', 'server.key'])
        self.run(self.rust + ['pki', 'client', '--ca-cert', 'ca.pem', '--ca-key', 'ca.key', '--name', 'agent-c',
                              '--uri', 'spiffe://demo.test/agent-c', '--cert', 'agent-c.pem', '--key', 'agent-c.key'])
        self.run(self.rust + ['pki', 'client', '--ca-cert', 'ca.pem', '--ca-key', 'ca.key', '--name', 'agent-d',
                              '--cert', 'agent-d.pem', '--key', 'agent-d.key'])
        self.run(self.rust + ['keys', 'init', '--issuer', 'https://broker.test', '--kid', 'k1', '--out',
                              'broker-keys.json'])
        self.run(self.rust + ['keys', 'export', '--keys', 'broker-keys.json', '--out', 'proxy-keys.json'])

        self.step('Start the synthetic provider, the broker and the proxy', '''
            The synthetic identity provider and API are fixtures. The broker (Rust) has two
            listeners: the agent API, which requires client certificates, and the browser
            endpoint that receives the OAuth redirect. The proxy (Rust) requires client
            certificates and routes each request to the provider the token names.''')
        provider, announced = self.serve([sys.executable, str(HERE / 'synthetic_provider.py'), '--cert', 'server.pem',
                                          '--key', 'server.key', '--log', 'provider-log.jsonl'])
        idp, api = announced['idp'], announced['api']
        idp_port = idp.rsplit(':', 1)[1]
        self.write('provider.json', {
            'schema': 'garrett-stateless-v1/provider', 'name': 'api', 'client_id': 'synthetic-client',
            'authorization_url': f'https://idp.test:{idp_port}/authorize',
            'token_url': f'https://idp.test:{idp_port}/token', 'token_address': idp, 'token_ca_file': 'ca.pem',
            'scopes': ['read', 'write'], 'default_scope': 'read'})
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            browser_port = probe.getsockname()[1]
        self.write('broker.json', {
            'schema': 'garrett-stateless-v1/broker', 'issuer': 'https://broker.test', 'audience': 'https://proxy.test',
            'replica': 'a', 'agent_listen': '127.0.0.1:0', 'browser_listen': f'127.0.0.1:{browser_port}',
            'public_url': f'https://broker.test:{browser_port}/', 'certificate': 'server.pem',
            'private_key': 'server.key', 'agent_ca': 'ca.pem', 'keys': 'broker-keys.json',
            'providers': ['provider.json'], 'max_lifetime': 900})
        api_host, api_port = api.rsplit(':', 1)
        self.write('proxy.json', {
            'schema': 'garrett-stateless-v1/proxy', 'listen': '127.0.0.1:0', 'authority': 'proxy.test:8443',
            'certificate': 'server.pem', 'private_key': 'server.key', 'client_ca': 'ca.pem',
            'keys': 'proxy-keys.json', 'audiences': ['https://proxy.test'],
            'routes': [{'provider': 'api', 'host': 'api.test', 'address': api_host, 'port': int(api_port),
                        'ca_file': 'ca.pem', 'authentication': 'bearer', 'deny': [{'method': 'DELETE', 'path': '/'}]}]})
        broker, broker_addr = self.serve(self.rust + ['broker', '--config', 'broker.json'])
        proxy, proxy_addr = self.serve(self.rust + ['proxy', '--config', 'proxy.json'])
        self.say(f'broker agent API {broker_addr["agent"]}, browser {broker_addr["browser"]}; '
                 f'proxy {proxy_addr["address"]}')

        self.step('The agent asks for access', '''
            The agent (Rust client, certificate agent-c) asks the broker for a login. It gets a
            URL for a human and a confirmation code, and then waits. It never runs a callback
            listener and never sees the authorization code.''')
        login = subprocess.Popen(self.agent('agent-c', 'login', '--broker', 'https://broker.test:9443', '--connect',
                                            broker_addr['agent'], '--provider', 'api', '--out', 'surrogate',
                                            '--timeout', '120'),
                                 cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        started = json.loads(login.stdout.readline())
        self.say(f'open: {started["authorization_url"][:96]}...')
        self.say(f'confirmation code shown by the agent: {started["confirmation"]}')

        self.step('A human approves in the browser', '''
            The broker's page shows which agent is asking, for which provider and scope, and the
            same confirmation code. The (simulated) human checks the code, continues to the
            identity provider, signs in and approves. The provider redirects to the broker, which
            exchanges the code with the PKCE verifier sealed inside the state parameter.''')
        status, _, page = self.browse(started['authorization_url'], broker_addr['browser'])
        links = _links(page)
        code_ok = started['confirmation'].encode() in page
        self.say(f'broker page HTTP {status}; confirmation code matches: {code_ok}')
        status, _, idp_page = self.browse(links['continue'], idp)
        status, headers, _ = self.browse('https://idp.test' + _links(idp_page)['approve'], idp)
        status, _, done = self.browse(headers['location'], broker_addr['browser'])
        self.say(f'provider redirect handled by the broker: HTTP {status}')
        delivered = json.loads(login.stdout.readline())
        login.wait(30)
        self.say(f'agent received its surrogate: {delivered}')
        self.evidence['confirmation_matched'] = code_ok

        self.step('Inspect the surrogate', '''
            The surrogate is a signed token the agent can read: issuer, audience, provider,
            lifetime, the certificate binding cnf, and the provider's own access claims (none
            here: this synthetic provider issues opaque tokens). The real token is inside enc,
            AES-256-GCM-encrypted under a key the agent does not have.''')
        inspected = json.loads(self.run(self.rust + ['inspect', '--token-file', 'surrogate']).stdout)
        payload = inspected['payload']
        for key in ('iss', 'aud', 'sub', 'prv', 'iat', 'exp', 'ren', 'cnf', 'scope'):
            self.say(f'{key:>5}: {payload.get(key)}')
        self.say(f'  enc: {payload["enc"][:40]}... ({len(payload["enc"])} characters, opaque)')
        surrogate = (self.root / 'surrogate').read_text()
        real = next(e['credential_sha256'] for e in self.provider_log() if e['event'] == 'token_issued')

        self.step('An ordinary API request through the proxy', '''
            The agent sends GET /user with the surrogate as its bearer token. The proxy checks
            the signature, the claims and that cnf equals the certificate of this TLS
            connection, decrypts the real token, puts it in the Authorization header, and
            forwards to the route of the token's provider.''')
        status, body = self.request('agent-c', proxy_addr['address'], '/user?per_page=2')
        seen = self.provider_log()[-1]
        self.say(f'provider received credential sha256 {seen["credential_sha256"][:16]}...: '
                 f'{"the real token" if seen["credential_sha256"] == real else "NOT the real token"}')
        self.say(f'sha256 of the surrogate is {hashlib.sha256(surrogate.encode()).hexdigest()[:16]}...: different')
        self.evidence['authorized_request'] = status == 200 and seen['credential_sha256'] == real
        status, _ = self.request('agent-c', proxy_addr['address'], '/items', '--data', '{"name":"demo"}')
        self.evidence['post_with_body'] = status == 201

        self.step('Copy the surrogate to another agent', '''
            A second agent with its own valid certificate (agent-d) presents the stolen
            surrogate. The proxy refuses it with 401 before anything is sent upstream: the
            binding names agent-c's certificate. A copied software key and certificate would
            defeat this, which is why the stronger profile keeps the key in a TPM.''')
        before = len(self.provider_log())
        status, _ = self.request('agent-d', proxy_addr['address'], '/user')
        self.evidence['stolen_surrogate_refused'] = status == 401 and len(self.provider_log()) == before
        status, _ = self.request('agent-c', proxy_addr['address'], '/repos/x', '-X', 'DELETE')
        self.evidence['deny_rule_refused'] = status == 403 and len(self.provider_log()) == before
        status, _ = self.request('agent-c', proxy_addr['address'], '/echo')
        self.evidence['reflected_credential_withheld'] = status == 502

        self.step('Statelessness: stop the broker, restart the proxy', '''
            The broker stops. The proxy restarts as a new process with only its configuration
            and keys, and the surrogate still works. A Python proxy replica, an independent
            implementation of the same specification, accepts it too. No replica asked anyone
            whether the token exists.''')
        self.stop(broker)
        diagnostics = self.stop(proxy)
        proxy, proxy_addr = self.serve(self.rust + ['proxy', '--config', 'proxy.json'])
        status_rust, _ = self.request('agent-c', proxy_addr['address'], '/user')
        python_proxy, python_addr = self.serve(self.python + ['proxy', '--config', 'proxy.json'])
        status_python, _ = self.request('agent-c', python_addr['address'], '/user', binary=self.python)
        self.evidence['restarted_rust_proxy'] = status_rust == 200
        self.evidence['python_replica'] = status_python == 200
        diagnostics += self.stop(python_proxy)

        self.step('Revocation without state: retire the key', '''
            A single surrogate cannot be revoked; it expires (15 minutes here). Retiring the key
            it was signed with revokes every surrogate under that key once the proxies have the
            new key set.''')
        self.run(self.rust + ['keys', 'rotate', '--keys', 'broker-keys.json', '--kid', 'k2'])
        self.run(self.rust + ['keys', 'retire', '--keys', 'broker-keys.json', '--kid', 'k1'])
        os.unlink(self.root / 'proxy-keys.json')
        self.run(self.rust + ['keys', 'export', '--keys', 'broker-keys.json', '--out', 'proxy-keys.json'])
        diagnostics += self.stop(proxy)
        proxy, proxy_addr = self.serve(self.rust + ['proxy', '--config', 'proxy.json'])
        status, _ = self.request('agent-c', proxy_addr['address'], '/user')
        self.evidence['retired_key_revokes'] = status == 401
        diagnostics += self.stop(proxy)
        self.stop(provider)

        self.step('Evidence and limits', '''
            The agent's token file and every proxy diagnostic line are searched for the synthetic
            provider credential; it appears in neither. What this run does not show: VM isolation, TPM key custody, a real identity provider, or the
            behaviour of a real provider API. The Lean theorems about the extracted Rust
            controllers are listed in docs/verified-garrett-stateless.md.''')
        agent_files = b''.join((self.root / n).read_bytes() for n in ('surrogate',))
        self.evidence['no_credential_in_diagnostics'] = 'syn_' not in diagnostics
        self.evidence['no_credential_in_agent_files'] = b'syn_' not in agent_files
        self.evidence['ok'] = all(v for k, v in self.evidence.items() if k not in ('profile', 'synthetic'))
        print(json.dumps(self.evidence, sort_keys=True))
        if not self.evidence['ok']:
            raise SystemExit(1)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'id' in attrs:
            self.found[attrs['id']] = attrs['href']


def _links(page: bytes) -> dict[str, str]:
    parser = _Links()
    parser.feed(page.decode())
    return parser.found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--pause', action='store_true')
    parser.add_argument('--rust', default=shutil.which('garrett-stateless') or 'garrett-stateless')
    parser.add_argument('--python-cmd', default=f'{sys.executable} -m aivm_secrets.garrett_stateless')
    parser.add_argument('--workdir')
    args = parser.parse_args()
    demo = Demo(args)
    try:
        demo.main()
    finally:
        demo.close()
        if not args.workdir:
            shutil.rmtree(demo.root, ignore_errors=True)


if __name__ == '__main__':
    main()
