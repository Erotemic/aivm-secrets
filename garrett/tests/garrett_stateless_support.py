"""Shared fixtures for the garrett-stateless-v1 tests: a development PKI, key
sets, configuration files, the synthetic provider and a simulated human.

Everything is synthetic: no real account, no network beyond loopback."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import textwrap
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from garrett_stateless import pki, tls, wire
from garrett_stateless.keys import BrokerKeys

REPO = Path(__file__).resolve().parent.parent
SYNTHETIC = REPO / 'examples' / 'synthetic_provider.py'


def load_synthetic():
    spec = importlib.util.spec_from_file_location('garrett_synthetic_provider', SYNTHETIC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def rust_binary() -> Path | None:
    """The native CLI: ``GARRETT_STATELESS_RUST`` or the cargo debug build."""
    configured = os.environ.get('GARRETT_STATELESS_RUST')
    if configured:
        return Path(configured)
    built = REPO / 'target' / 'debug' / 'garrett-stateless'
    return built if built.exists() else None


def python_command() -> list[str]:
    return [sys.executable, '-m', 'garrett_stateless']


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and 'id' in attrs:
            self.links[attrs['id']] = attrs['href']


def links(page: bytes) -> dict[str, str]:
    parser = _Links()
    parser.feed(page.decode('utf-8'))
    return parser.links


class Environment:
    """A complete synthetic deployment in ``root`` (servers not started)."""

    def __init__(self, root: Path, *, jwt: bool = False, issuer: str | None = None, copy_claims=None):
        self.root = root
        self.ca = pki.create_ca('garrett-stateless test CA', 2)
        names = ['broker.test', 'proxy.test', 'idp.test', 'api.test', 'localhost', '127.0.0.1']
        self.server = pki.issue(self.ca, server_names=names, days=2)
        self.agent_c = pki.issue(self.ca, client_name='agent-c', uri='spiffe://test/agent-c', days=2)
        self.agent_d = pki.issue(self.ca, client_name='agent-d', days=2)
        self.write('ca.pem', self.ca.certificate)
        self.write('server.pem', self.server.certificate)
        self.write('server.key', self.server.key, private=True)
        for name, issued in (('agent-c', self.agent_c), ('agent-d', self.agent_d)):
            self.write(f'{name}.pem', issued.certificate)
            self.write(f'{name}.key', issued.key, private=True)
        keys = BrokerKeys.generate('https://broker.test', 'k1')
        self.write('broker-keys.json', keys.to_json(), private=True)
        self.write('proxy-keys.json', keys.export_proxy().to_json(), private=True)
        synthetic = load_synthetic()
        self.provider, self.idp, self.api = synthetic.start(
            str(root / 'server.pem'), str(root / 'server.key'), '127.0.0.1:0', '127.0.0.1:0',
            str(root / 'provider-log.jsonl'), jwt=jwt, issuer=issuer)
        idp_port = self.idp.rsplit(':', 1)[1]
        provider = {
            'schema': 'garrett-stateless-v1/provider', 'name': 'api', 'client_id': 'synthetic-client',
            'authorization_url': f'https://idp.test:{idp_port}/authorize',
            'token_url': f'https://idp.test:{idp_port}/token', 'token_address': self.idp,
            'token_ca_file': 'ca.pem', 'scopes': ['read', 'write'], 'default_scope': 'read',
        }
        if issuer:
            provider['issuer'] = issuer
        if copy_claims is not None:
            provider['copy_claims'] = copy_claims
        self.write('provider.json', json.dumps(provider))
        self.browser_port = free_port()
        self.write('broker.json', json.dumps({
            'schema': 'garrett-stateless-v1/broker', 'issuer': 'https://broker.test',
            'audience': 'https://proxy.test', 'replica': 'a', 'agent_listen': '127.0.0.1:0',
            'browser_listen': f'127.0.0.1:{self.browser_port}',
            'public_url': f'https://broker.test:{self.browser_port}/', 'certificate': 'server.pem',
            'private_key': 'server.key', 'agent_ca': 'ca.pem', 'keys': 'broker-keys.json',
            'providers': ['provider.json'],
        }))
        self.proxy_config('proxy.json')

    def write(self, name: str, data, private: bool = False) -> Path:
        path = self.root / name
        data = data.encode() if isinstance(data, str) else data
        if private:
            from garrett_stateless.files import write_private
            write_private(path, data)
        else:
            path.write_bytes(data)
        return path

    def proxy_config(self, name: str, **overrides) -> Path:
        api_host, api_port = self.api.rsplit(':', 1)
        config = {
            'schema': 'garrett-stateless-v1/proxy', 'listen': '127.0.0.1:0', 'authority': 'proxy.test:8443',
            'certificate': 'server.pem', 'private_key': 'server.key', 'client_ca': 'ca.pem',
            'keys': 'proxy-keys.json', 'audiences': ['https://proxy.test'], 'skew': 0,
            'routes': [{'provider': 'api', 'host': 'api.test', 'address': api_host, 'port': int(api_port),
                        'ca_file': 'ca.pem', 'authentication': 'bearer',
                        'deny': [{'method': 'DELETE', 'path': '/'}]}],
        }
        config.update(overrides)
        return self.write(name, json.dumps(config))

    def provider_log(self) -> list[dict]:
        path = self.root / 'provider-log.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def browse(self, url: str, connect: str) -> wire.Response:
        """One GET by the human's browser (server authentication only)."""
        parts = urlsplit(url)
        target = parts.path + ('?' + parts.query if parts.query else '')
        request = wire.request_bytes('GET', target, parts.netloc, [], b'')
        raw = wire.exchange(tls.upstream_client(self.root / 'ca.pem'), connect, parts.hostname, request, 1 << 20)
        return wire.parse_response(raw)

    def human(self, authorization_url: str, browser: str, *, approve: bool = True,
              expect_confirmation: str | None = None) -> wire.Response:
        """Open the broker's page, check the code, approve at the IdP, follow the redirect."""
        page = self.browse(authorization_url, browser)
        assert page.status == 200, page.body
        if expect_confirmation is not None:
            assert expect_confirmation.encode() in page.body
        idp_page = self.browse(links(page.body)['continue'], self.idp)
        choice = links(idp_page.body)['approve' if approve else 'deny']
        redirect = self.browse(f'https://idp.test{choice}', self.idp)
        assert redirect.status == 302
        return self.browse(redirect.header('location'), browser)


class Process:
    """A CLI server process announcing its addresses on one stdout line."""

    def __init__(self, command: list[str], cwd: Path):
        self.process = subprocess.Popen(command + ['--until-stdin-eof'], cwd=cwd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(self.process.stderr.read().decode())
        self.announcement = json.loads(line)

    def stop(self) -> str:
        self.process.stdin.close()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        return self.process.stderr.read().decode()


def require_rust() -> Path:
    import pytest
    binary = rust_binary()
    if binary is None:
        pytest.skip(textwrap.dedent('''\
            native garrett-stateless not built: cargo build -p garrett-stateless
            (a skipped native test is not interoperability evidence)'''))
    return binary


__all__ = ['Environment', 'Process', 'free_port', 'links', 'python_command', 'require_rust', 'rust_binary', 'shutil']
