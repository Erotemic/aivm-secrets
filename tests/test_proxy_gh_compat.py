"""HP-3: stock `gh` (REST and GraphQL) through the credential-substitution proxy.

The guest's `gh` holds only a placeholder token. It talks to a synthetic
GitHub Enterprise-shaped provider (`GH_HOST`) through `HTTPS_PROXY`, trusting
only the session CA. The proxy substitutes the real credential; the provider
must see it, and nothing `gh` prints may contain it.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess

import pytest

from aivm_secrets.proxy.policy import parse_policy
from aivm_secrets.proxy.server import ProxyAudit, ProxyServer, ProxySession
from tests.secrets_helpers import TOKEN, TLSService, write_private
from tests.test_rust_garrett import executable

HOST = 'example.org'
PLACEHOLDER = 'gho_placeholder_not_a_credential'

pytestmark = pytest.mark.skipif(shutil.which('gh') is None, reason='needs the GitHub CLI')


def proxy_policy(service) -> dict:
    return dict(schema=1, profile='credential-substitution', lifetime_seconds=600,
                origins=[dict(host=HOST, address='127.0.0.1', port=service.port,
                              ca_file=str(service.files['ca']), authentication='bearer')],
                deny=[dict(method='*', path='/api/v3/admin/')])


@pytest.fixture
def service(tmp_path):
    (tmp_path / 'provider').mkdir()
    with TLSService(tmp_path / 'provider', host=HOST, wire_headers=True) as provider:
        provider.routes[('GET', '/api/v3/user')] = {'login': 'demo', 'id': 7}
        provider.routes[('GET', '/api/v3/repos/octo/demo/pulls/7')] = {
            'number': 7, 'title': 'Fix the proof', 'state': 'open'}
        provider.routes[('POST', '/api/graphql')] = lambda seen: (200, {}, json.dumps(
            {'data': {'repository': {'pullRequest': {'title': 'Fix the proof', 'number': 7}}}}).encode())
        yield provider


class PythonProxy:
    def __init__(self, tmp_path, service):
        self.session = ProxySession(parse_policy(proxy_policy(service)), TOKEN.encode(),
                                    audit=ProxyAudit(tmp_path / 'audit.jsonl'))
        self.server = ProxyServer(self.session)
        self.ca = self.session.ca.pem.decode('ascii')

    def __enter__(self):
        self.server.__enter__()
        self.port = int(self.server.address.rsplit(':', 1)[1])
        self.token = self.session.token
        return self

    def __exit__(self, *exc):
        self.server.__exit__(*exc)


class NativeProxy:
    def __init__(self, tmp_path, service):
        directory = tmp_path / 'native'
        directory.mkdir(mode=0o700)
        self.policy = write_private(directory / 'proxy.json', json.dumps(proxy_policy(service)).encode())
        self.credential = write_private(directory / 'credential', (TOKEN + '\n').encode())
        self.audit = directory / 'audit.jsonl'

    def __enter__(self):
        self.process = subprocess.Popen(
            [executable('AIVM_SECRETS_RUST_GARRETT_PROXY'), '--policy', str(self.policy),
             '--credential-file', str(self.credential), '--audit', str(self.audit)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert select.select([self.process.stdout], [], [], 30)[0]
        announcement = json.loads(self.process.stdout.readline())
        assert announcement['ready'] is True, announcement
        self.ca = announcement['ca_pem']
        self.port = int(announcement['listen'].rsplit(':', 1)[1])
        self.token = announcement['proxy_token']
        return self

    def __exit__(self, *exc):
        self.process.stdin.close()
        assert self.process.wait(timeout=30) == 0
        assert TOKEN.encode() not in self.process.stdout.read() + self.process.stderr.read()


def gh(tmp_path, proxy, *words):
    ca = tmp_path / 'session-ca.pem'
    ca.write_text(proxy.ca)
    home = tmp_path / 'gh-home'
    home.mkdir(exist_ok=True)
    env = {
        'PATH': os.environ['PATH'], 'HOME': str(home),
        'GH_HOST': HOST, 'GH_ENTERPRISE_TOKEN': PLACEHOLDER,
        'GH_NO_UPDATE_NOTIFIER': '1', 'GH_PROMPT_DISABLED': '1', 'NO_COLOR': '1',
        'HTTPS_PROXY': f'http://aivm:{proxy.token}@127.0.0.1:{proxy.port}',
        'SSL_CERT_FILE': str(ca),
    }
    return subprocess.run(['gh', *words], env=env, capture_output=True, timeout=60)


@pytest.mark.parametrize('make', [PythonProxy, NativeProxy], ids=['python', 'native'])
def test_stock_gh_reads_through_the_proxy_with_only_a_placeholder(tmp_path, service, make):
    with make(tmp_path, service) as proxy:
        user = gh(tmp_path, proxy, 'api', '/user')
        pull = gh(tmp_path, proxy, 'api', '/repos/octo/demo/pulls/7', '--jq', '.title')
        admin = gh(tmp_path, proxy, 'api', '/admin/users')
        # GraphQL, as most `gh pr` commands use.
        view = gh(tmp_path, proxy, 'pr', 'view', '7', '--repo', 'octo/demo', '--json', 'title,number')
    assert user.returncode == 0, user
    assert view.returncode == 0 and json.loads(view.stdout) == {'number': 7, 'title': 'Fix the proof'}, view
    assert json.loads(user.stdout) == {'login': 'demo', 'id': 7}
    assert pull.returncode == 0 and pull.stdout.strip() == b'Fix the proof', pull
    assert admin.returncode != 0, admin
    sent = service.requests
    assert [r['target'] for r in sent] == [
        '/api/v3/user', '/api/v3/repos/octo/demo/pulls/7', '/api/graphql']
    assert json.loads(sent[2]['body'])['variables'] == {'owner': 'octo', 'pr_number': 7, 'repo': 'demo'}
    for request in sent:
        pairs = [(k.lower(), v) for k, v in request['header_pairs']]
        assert [v for k, v in pairs if k == 'authorization'] == ['Bearer ' + TOKEN]
        assert PLACEHOLDER not in json.dumps(pairs)
    for output in (user, pull, admin, view):
        assert TOKEN.encode() not in output.stdout + output.stderr
