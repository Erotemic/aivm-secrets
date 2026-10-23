"""HP-6: guest-side ``constrained-http`` through the native bridge.

The translator holds no credential. It turns an ordinary HTTPS request into
the one named operation it equals and sends that through the guest's native
``invoke``; the host bridge authorizes, builds the provider request itself
and releases only the operation's disclosure. A tampered route copy can
change which operation is asked for, never what the bridge allows.
"""

from __future__ import annotations

import copy
import json
import select
import subprocess
import sys

import pytest

from aivm_secrets.kernel.service import parse_policy as parse_service
from aivm_secrets.proxy.bridge import BridgeDispatcher
from aivm_secrets.proxy.policy import PolicyError, parse_policy
from aivm_secrets.proxy.server import ProxyAudit, ProxyServer, ProxySession
from tests.secrets_helpers import TOKEN, TLSService, write_private
from tests.test_proxy_substitution import World, status
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory
from tests.test_rust_invoke import client_config
from tests.test_rust_second_provider import HOST, registry_disclosure, registry_policy

POLICY = dict(schema=1, profile='constrained-http', lifetime_seconds=600,
              origins=[dict(host=HOST)])


def routes(policy: dict) -> dict:
    """The guest's public copy: no credential source path."""
    public = copy.deepcopy(policy)
    public['credential_source'] = dict(kind='file', path='/nonexistent')
    public.pop('egress', None)
    return public


class GuestWorld(World):
    host = HOST

    def __init__(self, tmp_path, case, route_policy):
        self.dispatcher = BridgeDispatcher(parse_service(route_policy), client_config(case))
        self.audit_path = tmp_path / 'guest-proxy-audit.jsonl'
        self.session = ProxySession(parse_policy(POLICY), None, broker=self.dispatcher,
                                    audit=ProxyAudit(self.audit_path))
        self.ca_path = tmp_path / 'guest-ca.pem'
        self.ca_path.write_bytes(self.session.ca.pem)
        self.server = ProxyServer(self.session)


@pytest.fixture
def registry(tmp_path):
    with TLSService(provider_directory(tmp_path), host=HOST) as provider:
        provider.routes[('GET', '/api/packages/alpha')] = {
            'name': 'alpha', 'latest': {'version': '2.1.0'},
            'stats': {'downloads': 1234, 'private_score': 0.93}, 'owner_token_echo': TOKEN,
        }
        policy = registry_policy(tmp_path, provider)
        with ManifestCase(tmp_path, provider, policy, releases=registry_disclosure(),
                          authentication='x-api-key') as case:
            yield provider, case, policy


def get(target: str) -> bytes:
    return (b'GET ' + target.encode() + b' HTTP/1.1\r\nHost: ' + HOST.encode()
            + b'\r\nAuthorization: token guest-placeholder\r\nConnection: close\r\n\r\n')


def test_a_plain_request_becomes_the_named_operation_on_the_bridge(tmp_path, registry):
    provider, case, policy = registry
    with GuestWorld(tmp_path, case, routes(policy)) as world:
        reply = world.raw(get('/api/packages/alpha'))
    assert status(reply) == 200, reply
    assert json.loads(reply.split(b'\r\n\r\n', 1)[1]) == {
        'downloads': 1234, 'latest': '2.1.0', 'name': 'alpha'}
    [sent] = provider.seen()
    assert (sent['method'], sent['target']) == ('GET', '/api/packages/alpha')
    assert sent['headers']['x-api-key'] == TOKEN
    assert 'authorization' not in sent['headers']
    assert TOKEN.encode() not in reply + world.audit_path.read_bytes()
    events = [json.loads(line) for line in world.audit_path.read_text().splitlines()]
    assert [e['event'] for e in events] == ['session_start', 'admitted', 'completed', 'session_end']
    assert events[1]['operation'] == 'package.view'


@pytest.mark.parametrize('target', [
    '/api/packages/alpha/../beta',    # refused by the strict parser
    '/api/packages/alpha?extra=1',    # no operation has this query
    '/api/users/alpha',               # no operation has this path
])
def test_unmatched_requests_are_refused_without_any_bridge_call(tmp_path, registry, target):
    provider, case, policy = registry
    with GuestWorld(tmp_path, case, routes(policy)) as world:
        reply = world.raw(get(target))
    assert status(reply) in (400, 403), reply
    assert provider.seen() == []


def test_a_tampered_route_copy_cannot_widen_what_the_bridge_allows(tmp_path, registry):
    """The guest's copy allows `gamma`; the host bridge's policy does not."""
    provider, case, policy = registry
    widened = routes(policy)
    widened['operations'][0]['parameters']['name'] = ['alpha', 'beta', 'gamma']
    with GuestWorld(tmp_path, case, widened) as world:
        reply = world.raw(get('/api/packages/gamma'))
    assert status(reply) >= 400, reply
    assert provider.seen() == []
    assert TOKEN.encode() not in reply


def test_the_process_contract_holds_no_credential(tmp_path, registry):
    provider, case, policy = registry
    proxy_policy = write_private(tmp_path / 'proxy.json', json.dumps(POLICY).encode())
    route_file = write_private(tmp_path / 'routes.json', json.dumps(routes(policy)).encode())
    command = [sys.executable, '-I', '-m', 'aivm_secrets', 'proxy', '--policy', str(proxy_policy),
               '--service-policy', str(route_file), '--audit', str(tmp_path / 'audit.jsonl'),
               '--bridge-client', json.dumps(client_config(case))]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        assert select.select([process.stdout], [], [], 30)[0]
        announcement = json.loads(process.stdout.readline())
        assert announcement['ready'] is True and announcement['profile'] == 'constrained-http'
    finally:
        process.stdin.close()
        assert process.wait(timeout=30) == 0
    assert TOKEN.encode() not in process.stdout.read() + process.stderr.read()

    # A credential next to the bridge client is refused: one authority source.
    credential = write_private(tmp_path / 'guest-credential', (TOKEN + '\n').encode())
    done = subprocess.run([*command, '--credential-file', str(credential)],
                          capture_output=True, timeout=30, input=b'')
    assert done.returncode == 1
    assert json.loads(done.stdout)['error'] == 'invalid_policy'


def test_the_dispatcher_refuses_an_empty_client():
    with pytest.raises(PolicyError):
        BridgeDispatcher(None, [])
