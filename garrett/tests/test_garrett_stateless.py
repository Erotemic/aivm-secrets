"""garrett-stateless-v1, Python implementation: the full workflow over real
TLS against the synthetic provider, and the refusals that matter."""
from __future__ import annotations

import hashlib
import json

import pytest

from garrett_stateless import (
    Agent, Broker, Endpoint, PeerIdentity, ProtocolError, Proxy, Rejection, inspect,
)
from garrett_stateless.core import stateless
from garrett_stateless.core import encoding as enc
from garrett_stateless.keys import BrokerKeys
from garrett_stateless.core.stateless_token import KeySet, TokenSealer
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tests.garrett_stateless_support import Environment, links


def _agent(env: Environment, name: str) -> Agent:
    return Agent(env.root / 'ca.pem', env.root / f'{name}.pem', env.root / f'{name}.key')


def _der(pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


@pytest.fixture
def env(tmp_path):
    return Environment(tmp_path)


def _login(env, broker_endpoint, browser, agent: Agent, **human) -> tuple:
    started = agent.begin_login(broker_endpoint, 'api')
    done = env.human(started.authorization_url, browser, expect_confirmation=started.confirmation, **human)
    return started, done


def test_full_workflow_and_statelessness(env):
    broker = Broker.from_file(env.root / 'broker.json')
    running = broker.serve()
    broker_endpoint = Endpoint.parse('https://broker.test:9443', running.agent_address)
    c, dd = _agent(env, 'agent-c'), _agent(env, 'agent-d')

    started, done = _login(env, broker_endpoint, running.browser_address, c)
    assert done.status == 200
    # Only the beginning certificate collects, once.
    with pytest.raises(ProtocolError, match='wrong_certificate'):
        dd.poll(broker_endpoint, started.login)
    issued = c.wait_for_token(broker_endpoint, started.login, 5)
    with pytest.raises(ProtocolError):
        c.poll(broker_endpoint, started.login)
    log = env.provider_log()
    real = next(e['credential_sha256'] for e in log if e['event'] == 'token_issued')
    header, payload = inspect(issued.token)
    assert header == {'alg': 'EdDSA', 'kid': 'k1', 'typ': 'garrett-stateless-v1+jwt'}
    assert payload['sub'] == 'spiffe://test/agent-c' and payload['prv'] == 'api'
    assert payload['scope'] == 'read' and 'upstream' not in payload  # opaque token
    # The broker goes away; independent proxies need only keys and config.
    running.stop()
    del broker
    for name in ('proxy-b.json', 'proxy-c.json'):
        proxy = Proxy.from_file(env.proxy_config(name)).serve()
        endpoint = Endpoint.parse('https://proxy.test:8443', proxy.address)
        response = c.request(endpoint, issued.token, 'GET', '/user?per_page=2')
        assert response.status == 200
        assert json.loads(response.body)['query'] == {'per_page': '2'}
        last = env.provider_log()[-1]
        assert last['credential_sha256'] == real and last['authorized']
        posted = c.request(endpoint, issued.token, 'POST', '/repos', [('Content-Type', 'application/json')], b'{"a":1}')
        assert posted.status == 201 and json.loads(posted.body)['body_bytes'] == 7
        before = len(env.provider_log())
        # Stolen surrogate, forged token, deny rule: refused before egress.
        assert dd.request(endpoint, issued.token, 'GET', '/user').status == 401
        forged = issued.token[:-3] + ('AAA' if not issued.token.endswith('AAA') else 'BBB')
        assert c.request(endpoint, forged, 'GET', '/user').status == 401
        assert c.request(endpoint, issued.token, 'DELETE', '/repo').status == 403
        assert len(env.provider_log()) == before
        # A provider reflecting the credential is withheld.
        echo = c.request(endpoint, issued.token, 'GET', '/echo')
        assert echo.status == 502 and b'syn_' not in echo.body
        proxy.stop()

    # Renewal on a fresh broker: same binding and credential, ren never grows.
    broker2 = Broker.from_file(env.root / 'broker.json')
    peer_c = PeerIdentity.from_der(_der(env.agent_c.certificate))
    peer_d = PeerIdentity.from_der(_der(env.agent_d.certificate))
    renewed = broker2.renew(peer_c, issued.token)
    assert renewed.renew_until <= issued.renew_until and renewed.token != issued.token
    with pytest.raises(Rejection, match='wrong_certificate'):
        broker2.renew(peer_d, issued.token)


def test_callback_replay_denial_and_forged_state(env):
    broker = Broker.from_file(env.root / 'broker.json')
    running = broker.serve()
    endpoint = Endpoint.parse('https://broker.test:9443', running.agent_address)
    c = _agent(env, 'agent-c')
    started = c.begin_login(endpoint, 'api')
    page = env.browse(started.authorization_url, running.browser_address)

    idp_page = env.browse(links(page.body)['continue'], env.idp)
    redirect = env.browse('https://idp.test' + links(idp_page.body)['approve'], env.idp)
    callback = redirect.header('location')
    assert env.browse(callback, running.browser_address).status == 200
    replay = env.browse(callback, running.browser_address)
    assert replay.status == 400 and b'login_consumed' in replay.body
    # A forged or foreign state never reaches the token endpoint.
    forged = callback.replace('state=gs1.', 'state=gs1.A')
    assert env.browse(forged, running.browser_address).status == 400
    # Denial is final.
    started2 = c.begin_login(endpoint, 'api')
    assert env.human(started2.authorization_url, running.browser_address, approve=False).status == 400
    with pytest.raises(ProtocolError, match='login_denied'):
        c.poll(endpoint, started2.login)
    with pytest.raises(ProtocolError, match='invalid_scope'):
        c.begin_login(endpoint, 'api', 'admin')
    running.stop()


def test_jwt_claims_copied_with_policy(tmp_path):
    env = Environment(tmp_path, jwt=True, issuer='https://idp.test')
    broker = Broker.from_file(env.root / 'broker.json')
    running = broker.serve()
    endpoint = Endpoint.parse('https://broker.test:9443', running.agent_address)
    c = _agent(env, 'agent-c')
    started, done = _login(env, endpoint, running.browser_address, c)
    assert done.status == 200
    _, payload = inspect(c.wait_for_token(endpoint, started.login, 5).token)
    upstream = payload['upstream']
    # Access-describing claims only by default; no personal data.
    assert set(upstream) == {'aud', 'client_id', 'exp', 'iat', 'iss', 'jti', 'scope'}
    assert 'email' not in upstream and 'sub' not in upstream
    assert payload['iss'] == 'https://broker.test' and upstream['iss'] == 'https://idp.test'
    running.stop()


def test_expiry_and_key_retirement(env):
    keys = BrokerKeys.load(env.root / 'broker-keys.json')
    policy = stateless.IssuePolicy('https://broker.test', 'https://proxy.test', ('api',), 60, 120)
    peer = PeerIdentity.from_der(_der(env.agent_c.certificate))
    from garrett_stateless.broker import mint_with
    from garrett_stateless.token import ClaimCopy
    issued = mint_with(keys, policy, 'api', b'syn_static_1', _der(env.agent_c.certificate), ClaimCopy(), 60, 1000)
    acceptance = stateless.Acceptance(('https://proxy.test',), ('api',), 3600, 0)
    opener = KeySet(keys.export_proxy().entries)
    token = issued.token.encode()
    assert stateless.open_surrogate(opener, token, acceptance, peer.thumbprint, 1059).credential == b'syn_static_1'
    with pytest.raises(Rejection, match='expired'):
        stateless.open_surrogate(opener, token, acceptance, peer.thumbprint, 1060)
    with pytest.raises(Rejection, match='not_yet_valid'):
        stateless.open_surrogate(opener, token, acceptance, peer.thumbprint, 999)
    keys.rotate('https://broker.test', 'k2')
    keys.retire('k1')
    with pytest.raises(Rejection, match='unknown_key'):
        stateless.open_surrogate(KeySet(keys.export_proxy().entries), token, acceptance, peer.thumbprint, 1030)


def test_wrong_peer_is_never_decrypted():
    keys = BrokerKeys.generate('https://broker.test')
    sealer = TokenSealer(keys.active_entry(), bytes(12))
    peer = enc.b64url(hashlib.sha256(b'c').digest())
    other = enc.b64url(hashlib.sha256(b'd').digest())
    claims = stateless.SurrogateClaims('https://broker.test', 'https://proxy.test', 'agent', '0' * 32, 'api', peer,
                               100, 200, 300)
    token = sealer.seal(claims, b'real-credential')
    unsealed = []

    class Recording(KeySet):
        def unseal(self, verified):
            unsealed.append(verified)
            return super().unseal(verified)

    acceptance = stateless.Acceptance(('https://proxy.test',), ('api',), 3600, 0)
    with pytest.raises(Rejection, match='wrong_certificate'):
        stateless.open_surrogate(Recording(keys.export_proxy().entries), token, acceptance, other, 150)
    assert unsealed == []
    assert b'real-credential' not in token
