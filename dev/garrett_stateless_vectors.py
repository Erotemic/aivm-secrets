"""Generate the frozen garrett-stateless-v1 conformance vectors.

    python dev/garrett_stateless_vectors.py tests/secrets_vectors/garrett-stateless-v1.jsonl

Run once; the output is committed and both implementations are checked
against it (``tests/test_garrett_stateless_vectors.py`` and
``rust/crates/garrett-stateless/tests/vectors.rs``). Keys, certificates and
nonces are synthetic and fixed so that every sealed token is reproducible.
Rejected tokens are built by re-signing deliberately broken headers and
payloads, so that each refusal is reached past the signature check.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aivm_secrets.garrett_stateless import decisions as d
from aivm_secrets.garrett_stateless import encoding as enc
from aivm_secrets.garrett_stateless import login, pki, tls
from aivm_secrets.garrett_stateless.keys import BrokerKeys
from aivm_secrets.garrett_stateless.token import ClaimCopy, Informational, Opener, Sealer, copy_upstream


def fixed(label: str) -> bytes:
    return hashlib.sha256(b'garrett-stateless-v1 vectors/' + label.encode()).digest()


def b64(data: bytes) -> str:
    return enc.b64url(data)


def broker_keys() -> BrokerKeys:
    entries = []
    for kid in ('k1', 'k2'):
        entries.append({'issuer': 'https://broker.test', 'kid': kid, 'seal': b64(fixed(f'seal-{kid}')),
                        'sign': b64(fixed(f'sign-{kid}'))})
    data = enc.canonical({'active': 'k1', 'keys': entries, 'schema': 'garrett-stateless-v1/broker-keys',
                          'state': b64(fixed('state'))})
    return BrokerKeys.parse(data)


def resign(seed: bytes, header: bytes, payload: bytes) -> str:
    body = b64(header) + '.' + b64(payload)
    return body + '.' + b64(Ed25519PrivateKey.from_private_bytes(seed).sign(body.encode()))


def main(out: Path) -> None:
    rows: list[dict] = []
    keys = broker_keys()
    proxy = keys.export_proxy()
    rows.append({'kind': 'keys', 'broker_keys': json.loads(keys.to_json()), 'proxy_keys': json.loads(proxy.to_json())})

    ca = pki.create_ca('vector CA', 3650)
    agent_c = pki.issue(ca, client_name='agent-c', uri='spiffe://test/agent-c', days=3650)
    agent_d = pki.issue(ca, client_name='agent-d', days=3650)
    peers = {}
    for name, issued in (('c', agent_c), ('d', agent_d)):
        der = x509.load_pem_x509_certificate(issued.certificate).public_bytes(serialization.Encoding.DER)
        peer = tls.PeerIdentity.from_der(der)
        peers[name] = peer
        rows.append({'kind': 'certificate', 'name': name, 'der': base64.b64encode(der).decode(),
                     'thumbprint': peer.thumbprint, 'subject': peer.subject, 'not_after': peer.not_after})
    c, other = peers['c'].thumbprint, peers['d'].thumbprint

    claims = d.SurrogateClaims('https://broker.test', 'https://proxy.test', 'spiffe://test/agent-c', 'ab' * 16,
                               'api', c, 1000000, 1003600, 1604800)
    credential = b'gho_SYNTHETIC0123456789abcdefREAL'
    jwt_payload = (b'{"aud":"https://api.test","email":"octocat@example.test","exp":1003600,'
                   b'"iss":"https://idp.test","nested":{"x":1},"ratio":1.5,"roles":["a","b"],'
                   b'"scope":"read","sub":"user-1"}')
    jwt_credential = '.'.join([b64(b'{"alg":"RS256"}'), b64(jwt_payload), b64(b'signature')])
    seals = [
        ('opaque', claims, credential, Informational(scope='read')),
        ('jwt', claims, jwt_credential.encode(), Informational(scope='read', upstream=copy_upstream(jwt_credential, ClaimCopy()))),
        ('k2', claims, credential, Informational()),
    ]
    tokens = {}
    for label, cl, cred, info in seals:
        entry = next(e for e in keys.entries if e.kid == ('k2' if label == 'k2' else 'k1'))
        nonce = fixed('nonce-' + label)[:12]
        token = Sealer(entry, info).seal_with_nonce(cl, cred, nonce)
        tokens[label] = token
        rows.append({'kind': 'seal', 'label': label, 'kid': entry.kid, 'claims': _claims(cl),
                     'info': {'scope': info.scope, 'upstream': info.upstream}, 'credential': cred.decode(),
                     'nonce': nonce.hex(), 'token': token.decode()})

    acceptance = {'audiences': ['https://proxy.test'], 'providers': ['api'], 'max_lifetime': 3600, 'skew': 60}
    good = tokens['opaque'].decode()
    h, p, s = good.split('.')
    header = enc.from_b64url(h)
    payload = json.loads(enc.from_b64url(p))
    seed1 = fixed('sign-k1')

    def variant(mutate, header_bytes=header, sign=seed1) -> str:
        changed = dict(payload)
        mutate(changed)
        return resign(sign, header_bytes, enc.canonical(changed))

    other_enc = json.loads(enc.from_b64url(tokens['k2'].decode().split('.')[1]))['enc']
    sealed = enc.from_b64url(payload['enc'])
    flipped = b64(sealed[:20] + bytes([sealed[20] ^ 1]) + sealed[21:])
    cases = [
        ('valid', good, c, 1000000, {'credential': credential.decode(), 'claims': _claims(claims)}),
        ('valid_skew', good, c, 999940, {'credential': credential.decode()}),
        ('valid_last_second', good, c, 1003599, {'credential': credential.decode()}),
        ('valid_jwt', tokens['jwt'].decode(), c, 1000500, {'credential': jwt_credential}),
        ('valid_k2', tokens['k2'].decode(), c, 1000500, {'credential': credential.decode()}),
        ('expired_boundary', good, c, 1003600, 'expired'),
        ('not_yet_valid', good, c, 999939, 'not_yet_valid'),
        ('wrong_certificate', good, other, 1000500, 'wrong_certificate'),
        ('tampered_payload', h + '.' + b64(enc.from_b64url(p).replace(b'"api"', b'"apj"')) + '.' + s, c, 1000500,
         'bad_signature'),
        ('tampered_signature', good[:-2] + ('AA' if not good.endswith('AA') else 'BA'), c, 1000500, 'bad_signature'),
        ('unknown_kid', resign(seed1, enc.canonical({'alg': 'EdDSA', 'kid': 'k9', 'typ': 'garrett-stateless-v1+jwt'}),
                               enc.from_b64url(p)), c, 1000500, 'unknown_key'),
        ('alg_none', b64(b'{"alg":"none","kid":"k1","typ":"garrett-stateless-v1+jwt"}') + '.' + p + '.', c, 1000500,
         'malformed'),
        ('other_typ', resign(seed1, b'{"alg":"EdDSA","kid":"k1","typ":"aivm-bound+jwt"}', enc.from_b64url(p)), c,
         1000500, 'malformed'),
        ('noncanonical_header', resign(seed1, b'{"kid":"k1","alg":"EdDSA","typ":"garrett-stateless-v1+jwt"}',
                                       enc.from_b64url(p)), c, 1000500, 'malformed'),
        ('padded_segment', h + '=.' + p + '.' + s, c, 1000500, 'malformed'),
        ('two_segments', h + '.' + p, c, 1000500, 'malformed'),
        ('wrong_issuer', variant(lambda m: m.update(iss='https://other.test')), c, 1000500, 'wrong_issuer'),
        ('wrong_audience', variant(lambda m: m.update(aud='https://elsewhere.test')), c, 1000500, 'wrong_audience'),
        ('unknown_provider', variant(lambda m: m.update(prv='mail')), c, 1000500, 'unknown_provider'),
        ('lifetime_too_long', variant(lambda m: m.update(exp=1003601)), c, 1000500, 'bad_lifetime'),
        ('renew_before_expiry', variant(lambda m: m.update(ren=1003599)), c, 1000500, 'bad_lifetime'),
        ('unknown_claim', variant(lambda m: m.update(admin=True)), c, 1000500, 'malformed'),
        ('missing_cnf', variant(lambda m: m.pop('cnf')), c, 1000500, 'malformed'),
        ('string_time', variant(lambda m: m.update(iat='1000000')), c, 1000500, 'malformed'),
        ('duplicate_claim', resign(seed1, header, enc.canonical(payload).replace(b'{"aud"', b'{"aud":"x","aud"', 1)),
         c, 1000500, 'malformed'),
        ('noncanonical_payload', resign(seed1, header, json.dumps(payload, sort_keys=True).encode()), c, 1000500,
         'malformed'),
        ('flipped_ciphertext', variant(lambda m: m.update(enc=flipped)), c, 1000500, 'undecryptable'),
        ('moved_ciphertext', variant(lambda m: m.update(enc=other_enc)), c, 1000500, 'undecryptable'),
        ('short_ciphertext', variant(lambda m: m.update(enc=b64(b'x' * 28))), c, 1000500, 'malformed'),
        ('garbage', 'not a token', c, 1000500, 'malformed'),
    ]
    opener = Opener(proxy.entries)
    accept = d.Acceptance(tuple(acceptance['audiences']), tuple(acceptance['providers']), 3600, 60)
    for label, token, peer, now, expect in cases:
        try:
            opened = d.open_surrogate(opener, token.encode('ascii'), accept, peer, now)
            outcome = {'credential': opened.credential.decode()}
        except d.Rejection as rejection:
            outcome = rejection.code
        want = expect if isinstance(expect, str) else {'credential': expect['credential']}
        assert outcome == want, (label, outcome, want)
        row = {'kind': 'open', 'label': label, 'token': token, 'peer': peer, 'now': now, 'acceptance': acceptance}
        row['expect'] = {'rejection': expect} if isinstance(expect, str) else expect
        rows.append(row)

    for label, token_text, policy in [
        ('access', jwt_credential, 'access'), ('all', jwt_credential, 'all'), ('only', jwt_credential, ['roles', 'sub']),
        ('opaque', 'opaque-token', 'all'), ('two_parts', 'a.b', 'all'), ('not_json', 'YQ.YQ.YQ', 'all'),
    ]:
        rows.append({'kind': 'upstream', 'label': label, 'access_token': token_text, 'policy': policy,
                     'expect': copy_upstream(token_text, ClaimCopy(policy))})

    state = d.LoginState('cd' * 16, 'api', c, 'spiffe://test/agent-c', 1999999999, 'a', 'read',
                         'v' * 43, 1000000, 1000600)
    nonce = fixed('state-nonce')[:12]
    sealed_state = login.seal_plaintext(keys.state, login.state_plaintext(state), nonce)
    rows.append({'kind': 'login_state', 'state': _state(state), 'nonce': nonce.hex(), 'sealed': sealed_state})
    rows.append({'kind': 'login_state_open', 'label': 'forged', 'sealed': sealed_state[:-2] + 'AA', 'expect': 'undecryptable'})
    rows.append({'kind': 'login_state_open', 'label': 'other_key',
                 'sealed': login.seal_plaintext(fixed('other'), login.state_plaintext(state), nonce),
                 'expect': 'undecryptable'})
    rows.append({'kind': 'login_state_open', 'label': 'no_prefix', 'sealed': sealed_state[4:], 'expect': 'malformed'})
    rows.append({'kind': 'pkce', 'verifier': 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                 'challenge': login.pkce_challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')})

    policy = {'issuer': 'https://broker.test', 'audience': 'https://proxy.test', 'providers': ['api'],
              'max_lifetime': 3600, 'max_renew': 86400}
    for label, grant, now, lifetime in [
        ('plain', (1999999999, d.MAX_TIME), 1000, 3600), ('certificate_cap', (2000, d.MAX_TIME), 1000, 3600),
        ('credential_cap', (1999999999, 1500), 1000, 3600), ('lifetime_too_long', (1999999999, d.MAX_TIME), 1000, 3601),
        ('empty_window', (1000, d.MAX_TIME), 1000, 3600), ('negative_now', (1999999999, d.MAX_TIME), -1, 60),
    ]:
        p_ = d.IssuePolicy(policy['issuer'], policy['audience'], ('api',), 3600, 86400)
        g = d.Grant('api', 'agent', c, grant[0], grant[1])
        try:
            w = d.issue_window(p_, g, now, lifetime)
            expect = {'window': [w.issued_at, w.expires_at, w.renew_until]}
        except d.Rejection as rejection:
            expect = {'rejection': rejection.code}
        rows.append({'kind': 'issue_window', 'label': label, 'policy': policy, 'certificate_expires': grant[0],
                     'credential_expires': grant[1], 'now': now, 'lifetime': lifetime, 'expect': expect})

    lp = d.LoginPolicy('a', ('api',), 600)
    entry = d.entry_of(state)
    for label, stage, st, issuer_rule, issuer, denied, now in [
        ('accept', 'pending', state, None, None, False, 1000100),
        ('deny', 'pending', state, None, None, True, 1000100),
        ('replay', 'accepted', state, None, None, False, 1000100),
        ('expired', 'pending', state, None, None, False, 1000600),
        ('other_login', 'pending', _with(state, login='ef' * 16), None, None, False, 1000100),
        ('other_peer', 'pending', _with(state, certificate=other), None, None, False, 1000100),
        ('other_replica', 'pending', _with(state, replica='b'), None, None, False, 1000100),
        ('issuer_required', 'pending', state, 'https://idp.test', None, False, 1000100),
        ('issuer_match', 'pending', state, 'https://idp.test', 'https://idp.test', False, 1000100),
        ('issuer_mismatch', 'pending', state, 'https://idp.test', 'https://evil.test', False, 1000100),
        ('issuer_unexpected', 'pending', state, None, 'https://idp.test', False, 1000100),
    ]:
        e = d.with_stage(entry, d.Stage(stage))
        try:
            expect = {'stage': d.accept_callback(lp, e, st, issuer_rule, issuer, denied, now).value}
        except d.LoginDenial as denial:
            expect = {'denial': denial.code}
        rows.append({'kind': 'accept_callback', 'label': label, 'entry_stage': stage, 'entry': _state(state),
                     'state': _state(st), 'issuer_rule': issuer_rule, 'issuer': issuer, 'denied': denied,
                     'now': now, 'expect': expect})
    for label, stage, peer, now in [
        ('pending', 'exchanging', c, 1000100), ('complete', 'complete', c, 1000100),
        ('complete_grace', 'complete', c, 1000899), ('complete_late', 'complete', c, 1000900),
        ('wrong_peer', 'complete', other, 1000100), ('denied', 'denied', c, 1000100),
        ('failed', 'failed', c, 1000100), ('pending_expired', 'pending', c, 1000600),
    ]:
        rows.append({'kind': 'deliver', 'label': label, 'stage': stage, 'entry': _state(state), 'peer': peer,
                     'now': now, 'expect': d.deliver(d.with_stage(entry, d.Stage(stage)), peer, now)})

    out.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows))
    print(f'{len(rows)} vectors -> {out}')


def _with(state: d.LoginState, **changes) -> d.LoginState:
    from dataclasses import replace
    return replace(state, **changes)


def _claims(c: d.SurrogateClaims) -> dict:
    return {'issuer': c.issuer, 'audience': c.audience, 'subject': c.subject, 'token_id': c.token_id,
            'provider': c.provider, 'certificate': c.certificate, 'issued_at': c.issued_at,
            'expires_at': c.expires_at, 'renew_until': c.renew_until}


def _state(s: d.LoginState) -> dict:
    return {'login': s.login, 'provider': s.provider, 'certificate': s.certificate, 'subject': s.subject,
            'certificate_expires': s.certificate_expires, 'replica': s.replica, 'scope': s.scope,
            'verifier': s.verifier, 'issued_at': s.issued_at, 'expires_at': s.expires_at}


if __name__ == '__main__':
    main(Path(sys.argv[1]))
