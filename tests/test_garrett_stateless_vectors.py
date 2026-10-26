"""The Python implementation against the frozen garrett-stateless-v1 vectors
(``tests/secrets_vectors/garrett-stateless-v1.jsonl``); the Rust crate checks
the same file in ``rust/crates/garrett-stateless/tests/vectors.rs``."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aivm_secrets.garrett_stateless import decisions as d
from aivm_secrets.garrett_stateless import encoding as enc
from aivm_secrets.garrett_stateless import login, tls
from aivm_secrets.garrett_stateless.keys import BrokerKeys
from aivm_secrets.garrett_stateless.token import ClaimCopy, Informational, Opener, Sealer, copy_upstream

VECTORS = Path(__file__).parent / 'secrets_vectors' / 'garrett-stateless-v1.jsonl'
ROWS = [json.loads(line) for line in VECTORS.read_text().splitlines()]
KEYS = BrokerKeys.parse(enc.canonical(ROWS[0]['broker_keys']))


def _claims(c: dict) -> d.SurrogateClaims:
    return d.SurrogateClaims(**c)


def _state(s: dict) -> d.LoginState:
    return d.LoginState(**s)


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
    token = Sealer(entry, info).seal_with_nonce(_claims(row['claims']), row['credential'].encode(),
                                                bytes.fromhex(row['nonce']))
    assert token.decode() == row['token']


@pytest.mark.parametrize('row', _ids('open'), ids=lambda r: r['label'])
def test_open(row):
    a = row['acceptance']
    acceptance = d.Acceptance(tuple(a['audiences']), tuple(a['providers']), a['max_lifetime'], a['skew'])
    opener = Opener(KEYS.export_proxy().entries)
    if 'rejection' in row['expect']:
        with pytest.raises(d.Rejection) as caught:
            d.open_surrogate(opener, row['token'].encode(), acceptance, row['peer'], row['now'])
        assert caught.value.code == row['expect']['rejection']
    else:
        opened = d.open_surrogate(opener, row['token'].encode(), acceptance, row['peer'], row['now'])
        assert opened.credential.decode() == row['expect']['credential']
        if 'claims' in row['expect']:
            assert opened.claims == _claims(row['expect']['claims'])


@pytest.mark.parametrize('row', _ids('upstream'), ids=lambda r: r['label'])
def test_upstream(row):
    assert copy_upstream(row['access_token'], ClaimCopy(row['policy'])) == row['expect']


def test_login_state_and_pkce():
    (row,) = _ids('login_state')
    state = _state(row['state'])
    sealed = login.seal_plaintext(KEYS.state, login.state_plaintext(state), bytes.fromhex(row['nonce']))
    assert sealed == row['sealed']
    assert login.open_state(KEYS.state, sealed) == state
    for case in _ids('login_state_open'):
        with pytest.raises(d.Rejection) as caught:
            login.open_state(KEYS.state, case['sealed'])
        assert caught.value.code == case['expect'], case['label']
    (pkce,) = _ids('pkce')
    assert login.pkce_challenge(pkce['verifier']) == pkce['challenge']


@pytest.mark.parametrize('row', _ids('issue_window'), ids=lambda r: r['label'])
def test_issue_window(row):
    p = row['policy']
    policy = d.IssuePolicy(p['issuer'], p['audience'], tuple(p['providers']), p['max_lifetime'], p['max_renew'])
    grant = d.Grant('api', 'agent', 'c', row['certificate_expires'], row['credential_expires'])
    if 'rejection' in row['expect']:
        with pytest.raises(d.Rejection) as caught:
            d.issue_window(policy, grant, row['now'], row['lifetime'])
        assert caught.value.code == row['expect']['rejection']
    else:
        w = d.issue_window(policy, grant, row['now'], row['lifetime'])
        assert [w.issued_at, w.expires_at, w.renew_until] == row['expect']['window']


@pytest.mark.parametrize('row', _ids('accept_callback'), ids=lambda r: r['label'])
def test_accept_callback(row):
    entry = d.with_stage(d.entry_of(_state(row['entry'])), d.Stage(row['entry_stage']))
    policy = d.LoginPolicy('a', ('api',), 600)
    args = (policy, entry, _state(row['state']), row['issuer_rule'], row['issuer'], row['denied'], row['now'])
    if 'denial' in row['expect']:
        with pytest.raises(d.LoginDenial) as caught:
            d.accept_callback(*args)
        assert caught.value.code == row['expect']['denial']
    else:
        assert d.accept_callback(*args).value == row['expect']['stage']


@pytest.mark.parametrize('row', _ids('deliver'), ids=lambda r: r['label'])
def test_deliver(row):
    entry = d.with_stage(d.entry_of(_state(row['entry'])), d.Stage(row['stage']))
    assert d.deliver(entry, row['peer'], row['now']) == row['expect']
