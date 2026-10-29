"""The Python implementation against the frozen garrett-stateless-v1 vectors
(``tests/vectors/garrett-stateless-v1.jsonl``); the Rust crate checks
the same file in ``crates/garrett-stateless/tests/vectors.rs``."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from garrett_stateless.core import stateless, stateless_login, stateless_token
from garrett_stateless.core import encoding as enc
from garrett_stateless import login, tls
from garrett_stateless.keys import BrokerKeys
from garrett_stateless.core.stateless_token import Informational, KeySet, TokenSealer
from garrett_stateless.keys import AesStateKey
from garrett_stateless.token import ClaimCopy, copy_upstream

VECTORS = Path(__file__).parent / 'vectors' / 'garrett-stateless-v1.jsonl'
ROWS = [json.loads(line) for line in VECTORS.read_text().splitlines()]
KEYS = BrokerKeys.parse(enc.canonical(ROWS[0]['broker_keys']))


def _claims(c: dict) -> stateless.SurrogateClaims:
    return stateless.SurrogateClaims(**c)


def _state(s: dict) -> stateless_login.LoginState:
    return stateless_login.LoginState(**s)


def _ids(kind):
    return [r for r in ROWS if r['kind'] == kind]


def test_vector_inventory():
    kinds = {r['kind'] for r in ROWS}
    assert kinds == {'keys', 'certificate', 'seal', 'open', 'upstream', 'login_state', 'login_state_open', 'pkce',
                     'issue_window', 'accept_callback', 'deliver'}
    assert json.loads(KEYS.export_proxy().to_json()) == ROWS[0]['proxy_keys']


@pytest.mark.parametrize('row', _ids('certificate'), ids=lambda r: r['name'])
def test_certificate(row):
    peer = tls.PeerIdentity.from_der(base64.b64decode(row['der']))
    assert (peer.thumbprint, peer.subject, peer.not_after) == (row['thumbprint'], row['subject'], row['not_after'])


@pytest.mark.parametrize('row', _ids('seal'), ids=lambda r: r['label'])
def test_seal(row):
    entry = next(e for e in KEYS.entries if e.kid == row['kid'])
    info = Informational(row['info']['scope'], row['info']['upstream'])
    token = TokenSealer(entry, bytes.fromhex(row['nonce']), info).seal(_claims(row['claims']), row['credential'].encode())
    assert token.decode() == row['token']


@pytest.mark.parametrize('row', _ids('open'), ids=lambda r: r['label'])
def test_open(row):
    a = row['acceptance']
    acceptance = stateless.Acceptance(tuple(a['audiences']), tuple(a['providers']), a['max_lifetime'], a['skew'])
    opener = KeySet(KEYS.export_proxy().entries)
    if 'rejection' in row['expect']:
        with pytest.raises(stateless.Rejection) as caught:
            stateless.open_surrogate(opener, row['token'].encode(), acceptance, row['peer'], row['now'])
        assert caught.value.code == row['expect']['rejection']
    else:
        opened = stateless.open_surrogate(opener, row['token'].encode(), acceptance, row['peer'], row['now'])
        assert opened.credential.decode() == row['expect']['credential']
        if 'claims' in row['expect']:
            assert opened.claims == _claims(row['expect']['claims'])


@pytest.mark.parametrize('row', _ids('upstream'), ids=lambda r: r['label'])
def test_upstream(row):
    assert copy_upstream(row['access_token'], ClaimCopy(row['policy'])) == row['expect']


def test_login_state_and_pkce():
    (row,) = _ids('login_state')
    state = _state(row['state'])
    sealed = stateless_token.seal_plaintext(AesStateKey(KEYS.state), stateless_token.state_plaintext(state), bytes.fromhex(row['nonce']))
    assert sealed == row['sealed']
    assert login.open_state(KEYS.state, sealed) == state
    for case in _ids('login_state_open'):
        with pytest.raises(stateless.Rejection) as caught:
            login.open_state(KEYS.state, case['sealed'])
        assert caught.value.code == case['expect'], case['label']
    (pkce,) = _ids('pkce')
    assert login.pkce_challenge(pkce['verifier']) == pkce['challenge']


@pytest.mark.parametrize('row', _ids('issue_window'), ids=lambda r: r['label'])
def test_issue_window(row):
    p = row['policy']
    policy = stateless.IssuePolicy(p['issuer'], p['audience'], tuple(p['providers']), p['max_lifetime'], p['max_renew'])
    grant = stateless.SurrogateGrant('api', 'agent', 'c', row['certificate_expires'], row['credential_expires'])
    if 'rejection' in row['expect']:
        with pytest.raises(stateless.Rejection) as caught:
            stateless.issue_window(policy, grant, row['now'], row['lifetime'])
        assert caught.value.code == row['expect']['rejection']
    else:
        w = stateless.issue_window(policy, grant, row['now'], row['lifetime'])
        assert [w.issued_at, w.expires_at, w.renew_until] == row['expect']['window']


@pytest.mark.parametrize('row', _ids('accept_callback'), ids=lambda r: r['label'])
def test_accept_callback(row):
    entry = stateless_login.with_stage(stateless_login.entry_of(_state(row['entry'])), stateless_login.Stage(row['entry_stage']))
    policy = stateless_login.LoginPolicy('a', ('api',), 600)
    args = (policy, entry, _state(row['state']), row['issuer_rule'], row['issuer'], row['denied'], row['now'])
    if 'denial' in row['expect']:
        with pytest.raises(stateless_login.LoginDenial) as caught:
            stateless_login.accept_callback(*args)
        assert caught.value.code == row['expect']['denial']
    else:
        assert stateless_login.accept_callback(*args).value == row['expect']['stage']


@pytest.mark.parametrize('row', _ids('deliver'), ids=lambda r: r['label'])
def test_deliver(row):
    entry = stateless_login.with_stage(stateless_login.entry_of(_state(row['entry'])), stateless_login.Stage(row['stage']))
    assert stateless_login.deliver(entry, row['peer'], row['now']) == row['expect']
