"""Local publication CAS, atomic snapshots and finite Python/native parity."""
import hashlib
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity import bundle
from aivm_secrets.identity.garrett.claims import IdentityClaims
from aivm_secrets.identity.token import IdentityTokenIssuer, certificate_thumbprint
from aivm_secrets.primitives import codec
from tests.test_secrets_identity_mtls import certificates
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import private


@pytest.fixture
def material(tmp_path):
    certs = certificates(tmp_path)
    for role in ('client1', 'client2'):
        certs[role][0].chmod(0o600)
    claims = dict(iss='aivm.test', aud='guest.test', sub='vm-test', jti='a'*32,
                  iat=1000, exp=1300, epoch=1,
                  cnf={'x5t#S256': certificate_thumbprint(certs['client1'][2])})
    issuer = IdentityTokenIssuer(Ed25519PrivateKey.generate(), b'x'*32, key_id='key1')
    first = issuer.issue(IdentityClaims.parse(claims), 'aivs1.synthetic')
    claims['jti'] = 'b'*32
    second = issuer.issue(IdentityClaims.parse(claims), 'aivs1.synthetic')
    return certs, private(tmp_path / 'first.jwt', first.encode()), private(tmp_path / 'second.jwt', second.encode())


def invoke(backend, certificate, token, output, expected=None):
    if backend == 'python':
        return bundle.install(certificate=certificate, jwt_file=token, output=output,
                              expected_current=expected)
    args = [executable('AIVM_SECRETS_RUST_GARRETT_CLIENT'), 'install-bundle',
            '--certificate', str(certificate), '--jwt-file', str(token), '--output', str(output)]
    if expected is not None:
        args += ['--expected-current', expected]
    done = subprocess.run(args, capture_output=True, timeout=15)
    assert token.read_bytes().strip() not in done.stdout + done.stderr
    if done.returncode:
        assert done.returncode == 1 and not done.stdout, done
        raise SecretsError(done.stderr.decode().strip())
    assert not done.stderr
    return codec.loads(done.stdout)


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_bundle_install_replace_cas_and_private_encoding(material, tmp_path, backend):
    certs, first, second = material
    target = tmp_path / 'identity.json'
    initial = invoke(backend, certs['client1'][0], first, target)
    before = target.read_bytes()
    assert target.stat().st_mode & 0o777 == 0o600
    assert initial == dict(path=str(target), digest=hashlib.sha256(before).hexdigest(),
                          certificate_sha256=certificate_thumbprint(certs['client1'][2]))
    assert b'PRIVATE KEY' not in before
    assert bundle.load(target).capability == first.read_text()
    assert first.read_text() not in repr(bundle.load(target))
    for expected, error in [(None, 'unsafe_file'), ('0'*64, 'denied')]:
        with pytest.raises(SecretsError) as caught:
            invoke(backend, certs['client1'][0], second, target, expected)
        assert caught.value.code == error
        assert target.read_bytes() == before
    replaced = invoke(backend, certs['client1'][0], second, target, initial['digest'])
    assert replaced['digest'] != initial['digest']
    assert bundle.load(target).capability == second.read_text()
    with pytest.raises(SecretsError) as caught:
        invoke(backend, certs['client1'][0], first, target, initial['digest'])
    assert caught.value.code == 'denied'


def test_python_native_bundle_bytes_and_cross_writer_updates(material, tmp_path):
    certs, first, second = material
    a, b = tmp_path / 'python.json', tmp_path / 'rust.json'
    p = invoke('python', certs['client1'][0], first, a)
    r = invoke('rust', certs['client1'][0], first, b)
    assert a.read_bytes() == b.read_bytes() and p['digest'] == r['digest']
    invoke('rust', certs['client1'][0], second, a, p['digest'])
    invoke('python', certs['client1'][0], second, b, r['digest'])
    assert a.read_bytes() == b.read_bytes()


@pytest.mark.parametrize('backend', ['python', 'rust'])
@pytest.mark.parametrize('kind', ['mismatch', 'chain', 'trailing-der', 'bad-signature-shape', 'bad-json', 'bad-version', 'extra-field', 'duplicate', 'noncanonical-token', 'pem-vertical-tab'])
def test_invalid_pair_or_bundle_never_replaces_current(material, tmp_path, backend, kind):
    certs, first, second = material
    target = tmp_path / 'identity.json'
    initial = invoke(backend, certs['client1'][0], first, target)
    before = target.read_bytes()
    cert, token = certs['client1'][0], second
    if kind == 'mismatch':
        cert = certs['client2'][0]
    elif kind == 'chain':
        cert = private(tmp_path / 'chain.pem', cert.read_bytes() * 2)
    elif kind == 'pem-vertical-tab':
        cert = private(tmp_path / 'vertical-tab.pem', cert.read_bytes().replace(b'\n', b'\x0b'))
    elif kind == 'trailing-der':
        import base64
        cert = private(tmp_path / 'trailing.pem', b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(certs['client1'][2] + b'x') + b'\n-----END CERTIFICATE-----\n')
    elif kind == 'bad-signature-shape':
        token = private(tmp_path / 'bad.jwt', (second.read_text().rsplit('.', 1)[0] + '.eA').encode())
    elif kind == 'noncanonical-token':
        import base64
        chunks = second.read_text().split('.')
        chunks[0] = base64.urlsafe_b64encode(json.dumps(json.loads(base64.urlsafe_b64decode(chunks[0] + '=='))).encode()).rstrip(b'=').decode()
        token = private(tmp_path / 'bad.jwt', '.'.join(chunks).encode())
    else:
        value = json.loads(before)
        if kind == 'bad-json': data = b'{'
        elif kind == 'bad-version':
            value['schema'] = True
            data = codec.dumps(value)
        elif kind == 'extra-field':
            value['private_key'] = 'no adoption'
            data = codec.dumps(value)
        else: data = before[:-1] + b',"schema":1}'
        target.write_bytes(data)
        before = data
        initial['digest'] = hashlib.sha256(data).hexdigest()
    with pytest.raises(SecretsError) as caught:
        invoke(backend, cert, token, target, initial['digest'])
    assert caught.value.code == 'invalid_capability'
    assert target.read_bytes() == before


@pytest.mark.parametrize('backend', ['python', 'rust'])
@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo', 'public', 'lock-symlink', 'parent-symlink', 'reserved-staging'])
def test_unsafe_destination_is_not_followed(material, tmp_path, backend, kind):
    certs, first, _ = material
    target = tmp_path / 'identity.json'
    saved = private(tmp_path / 'unrelated', b'private unrelated material')
    if kind == 'symlink': target.symlink_to(saved)
    elif kind == 'hardlink': os.link(saved, target)
    elif kind == 'fifo': os.mkfifo(target, 0o600)
    elif kind == 'public':
        target.write_bytes(b'{}')
        target.chmod(0o644)
    elif kind == 'lock-symlink': (tmp_path / bundle.LOCK).symlink_to(saved)
    elif kind == 'reserved-staging': target = tmp_path / '.bundle-active'
    else:
        link = tmp_path / 'parent-link'
        link.symlink_to(tmp_path, target_is_directory=True)
        target = link / 'identity.json'
    with pytest.raises(SecretsError) as caught:
        invoke(backend, certs['client1'][0], first, target)
    assert caught.value.code == 'unsafe_file'
    assert saved.read_bytes() == b'private unrelated material'


@pytest.mark.parametrize('writers', [('python', 'python'), ('rust', 'rust'), ('python', 'rust')])
def test_two_writers_have_one_cas_winner(material, tmp_path, writers):
    certs, first, second = material
    target = tmp_path / 'identity.json'
    old = invoke('python', certs['client1'][0], first, target)
    def publish(backend):
        try: return invoke(backend, certs['client1'][0], second, target, old['digest'])
        except SecretsError as error: return error.code
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(publish, writers))
    assert sum(type(result) is dict for result in results) == 1
    assert 'denied' in results
    assert bundle.load(target).capability == second.read_text()


@pytest.mark.parametrize('phase', ['stage', 'rename', 'after-rename'])
def test_python_failure_reports_the_publication_boundary(material, tmp_path, monkeypatch, phase):
    certs, first, second = material
    target = tmp_path / 'identity.json'
    old = invoke('python', certs['client1'][0], first, target)
    before = target.read_bytes()
    if phase == 'stage':
        def fail(*_): raise OSError('synthetic stage failure')
        monkeypatch.setattr(bundle._Directory, 'stage', fail)
    else:
        original = bundle._Directory.publish
        def fail(self, staged, replace):
            if phase == 'after-rename': original(self, staged, replace)
            raise OSError('synthetic acknowledgement failure')
        monkeypatch.setattr(bundle._Directory, 'publish', fail)
    with pytest.raises(SecretsError) as caught:
        invoke('python', certs['client1'][0], second, target, old['digest'])
    assert caught.value.code == ('unsafe_file' if phase == 'stage' else 'outcome_unknown')
    assert (target.read_bytes() == before) == (phase != 'after-rename')


@pytest.mark.parametrize('profile', ['account', 'manifest'])
@pytest.mark.parametrize('installer', ['python', 'rust'])
@pytest.mark.parametrize('client_backend', ['python', 'rust'])
def test_live_renewal_installs_bundle_without_restarting_broker(tmp_path, profile, installer, client_backend):
    import base64
    import time
    from aivm_secrets.identity.certificates import inspect_csr
    from aivm_secrets.identity.client import bound_call
    from tests.secrets_helpers import TLSService, TOKEN
    from tests.test_rust_bound_renewal import same_key_csr
    from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
    from tests.test_rust_garrett_manifest import ManifestCase, provider_directory

    with TLSService(provider_directory(tmp_path), host='api.example.org') as provider:
        if profile == 'account':
            authority = AuthorityCase(tmp_path)
            session = AuthorityProviderCase(tmp_path, provider, authority)
            request = dict(operation='profile.read', arguments={})
            provider.routes[('GET', '/v1/account')] = dict(id=7, active=True)
        else:
            session = ManifestCase(tmp_path, provider)
            authority = session.authority
            request = dict(operation='ticket.view', arguments={'ticket': 7})
            provider.routes[('GET', '/v1/tickets/7')] = dict(id=7)
        with session:
            pid = session.process.pid
            cert, key, _ = session.certs['client1']
            source = private(tmp_path / 'old.jwt', session.token.encode())
            target = tmp_path / 'identity.json'
            initial = invoke(installer, cert, source, target)
            config = private(tmp_path / 'bundle-client.json', dict(schema=1,
                key_mode='software', socket=str(tmp_path / 'identity.sock'),
                server_name='localhost', server_ca=str(session.certs['ca']),
                private_key=str(key), identity_bundle=str(target)))
            def call():
                if client_backend == 'python':
                    return bound_call(socket_path=tmp_path / 'identity.sock',
                        ca=session.certs['ca'], private_key=key, identity_bundle=target,
                        request=request)
                done = subprocess.run([session.client, '--config', str(config)],
                    input=codec.dumps(dict(version=1, request=request)), capture_output=True,
                    timeout=15)
                assert done.returncode == 0 and not done.stderr, done
                return codec.loads(done.stdout)
            assert call()['ok']
            current = authority.call('public-client', subject='vm-test')
            csr = same_key_csr(session)
            renewed = authority.call('renew', subject='vm-test', csr_file=str(csr),
                approve_fingerprint=inspect_csr(csr.read_bytes()), expected_epoch=current['epoch'],
                expected_thumbprint=current['certificate_sha256'], now=int(time.time()))
            fresh_jwt = tmp_path / 'renewed.jwt'
            authority.call('rebind', subject='vm-test', surrogate_file=str(source),
                expected_epoch=renewed['epoch'], expected_thumbprint=renewed['certificate_sha256'],
                output=str(fresh_jwt), client_assurance='any-enrolled', now=int(time.time()))
            fresh_cert = private(tmp_path / 'renewed.pem', base64.b64decode(
                authority.call('public-client', subject='vm-test')['certificate_pem_b64']))
            assert not call()['ok']  # host changed; local old snapshot fails closed
            invoke(installer, fresh_cert, fresh_jwt, target, initial['digest'])
            assert call()['ok']
            assert session.process.pid == pid
            assert len(provider.seen()) == 2
            assert all(row['headers']['authorization'] == 'Bearer ' + TOKEN for row in provider.seen())
            assert TOKEN.encode() not in target.read_bytes()


def test_python_cli_installs_and_calls_bundle_without_host_authority(tmp_path, capsys):
    from tests.test_secrets_identity_operator import cli
    from tests.test_rust_garrett import BoundBridge
    from tests.secrets_helpers import REPO
    with BoundBridge(tmp_path, None, executable('AIVM_SECRETS_RUST_GARRETT_BRIDGE'), python_issuer=True) as case:
        source = private(tmp_path / 'outer.jwt', case.token.encode())
        target = tmp_path / 'identity.json'
        status, result, err = cli(capsys, 'install-bundle', '--certificate', case.certs['client1'][0],
            '--jwt-file', source, '--output', target)
        assert status == 0 and result['digest'] and not err
        status, reply, err = cli(capsys, 'call', '--socket', tmp_path / 'identity.sock',
            '--ca', case.certs['ca'], '--key', case.certs['client1'][1],
            '--identity-bundle', target, '--request', json.dumps(dict(operation='pr.view', arguments={'repository': REPO, 'pr': 13861})))
        assert status == 0 and reply['ok'] and not err, (status, reply, err)


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_real_stage_write_failure_keeps_old_file(material, tmp_path, backend):
    import sys
    from pathlib import Path
    certs, first, second = material
    target = tmp_path / 'identity.json'
    old = invoke('python', certs['client1'][0], first, target)
    before = target.read_bytes()
    command = ([executable('AIVM_SECRETS_RUST_GARRETT_CLIENT'), 'install-bundle'] if backend == 'rust'
               else [sys.executable, '-I', '-m', 'aivm_secrets', 'identity', 'install-bundle'])
    command += ['--certificate', str(certs['client1'][0]), '--jwt-file', str(second),
                '--output', str(target), '--expected-current', old['digest']]
    done = subprocess.run([sys.executable, str(Path(__file__).with_name('limited_exec.py')),
                           '0', *command], capture_output=True, timeout=15)
    assert done.returncode == 1 and not done.stdout
    expected_error = b'unsafe_file\n' if backend == 'rust' else b'aivm-secrets: Host file ownership, permissions, or type is unsafe.\n'
    assert done.stderr == expected_error
    assert target.read_bytes() == before


@pytest.mark.parametrize('writer', ['python', 'rust'])
def test_readers_observe_whole_snapshots_during_replacement(material, tmp_path, writer):
    from threading import Event
    certs, first, second = material
    target = tmp_path / 'identity.json'
    current = invoke('python', certs['client1'][0], first, target)
    expected_pairs = {(certs['client1'][0].read_bytes(), token.read_text()) for token in (first, second)}
    stopped = Event()
    seen = []
    def read():
        while not stopped.is_set():
            value = bundle.load(target)
            seen.append((value.certificate, value.capability))
    with ThreadPoolExecutor(1) as pool:
        reader = pool.submit(read)
        try:
            for i in range(12):
                current = invoke(writer, certs['client1'][0], second if i % 2 == 0 else first,
                                 target, current['digest'])
        finally:
            stopped.set()
        reader.result(timeout=5)
    assert seen and set(seen) <= expected_pairs


def test_native_gh_uses_bundle_and_rejects_ambiguous_inputs(tmp_path):
    from tests.secrets_helpers import TLSService
    from tests.test_rust_garrett_manifest import ManifestCase, provider_directory
    from tests.test_rust_w2_github_workflow import native_policy, native_disclosure
    from tests.secrets_github_scenario import install_github_routes, REPO, ALLOWED_PR, PULL
    with TLSService(provider_directory(tmp_path)) as provider:
        install_github_routes(provider)
        with ManifestCase(tmp_path, provider, native_policy(tmp_path, provider), native_disclosure()) as case:
            target = tmp_path / 'identity.json'
            token = private(tmp_path / 'outer.jwt', case.token.encode())
            invoke('rust', case.certs['client1'][0], token, target)
            value = dict(schema=1, key_mode='software', socket=str(tmp_path / 'identity.sock'),
                server_name='localhost', server_ca=str(case.certs['ca']),
                private_key=str(case.certs['client1'][1]), identity_bundle=str(target))
            config = private(tmp_path / 'bundle-client.json', value)
            args = ['gh', 'pr', 'view', str(ALLOWED_PR), '--repo', REPO, '--json', 'number,title']
            done = subprocess.run([case.client, '--config', str(config), *args], capture_output=True, timeout=15)
            assert done.returncode == 0 and not done.stderr, done
            assert codec.loads(done.stdout) == dict(number=ALLOWED_PR, title=PULL['title'])
            for extra in (['--capability-file', str(token), *args],):
                done = subprocess.run([case.client, '--config', str(config), *extra], capture_output=True, timeout=15)
                assert done.returncode == 1 and done.stderr == b'invalid_request\n'
            done = subprocess.run([case.client, '--config', str(config)],
                input=codec.dumps(dict(version=1, capability=case.token, describe=True)), capture_output=True, timeout=15)
            assert done.returncode == 1 and done.stderr == b'invalid_request\n'
            value['certificate'] = str(case.certs['client1'][0])
            private(config, value)
            done = subprocess.run([case.client, '--config', str(config), *args], capture_output=True, timeout=15)
            assert done.returncode == 1 and done.stderr == b'invalid_capability\n'
            assert len(provider.seen()) == 1


def test_python_call_keeps_loaded_pair_when_bundle_changes_before_tls(material, tmp_path, monkeypatch):
    from aivm_secrets.identity.client import bound_call
    from tests.test_rust_line_framing import ReplyPeer, LINE, REPLY, REQUEST
    certs, first, second = material
    target = tmp_path / 'identity.json'
    initial = invoke('python', certs['client1'][0], first, target)
    original = bundle.load
    reads = []
    def snapshot(path):
        value = original(path)
        reads.append(path)
        invoke('python', certs['client1'][0], second, target, initial['digest'])
        return value
    monkeypatch.setattr(bundle, 'load', snapshot)
    with ReplyPeer(tmp_path, certs, [LINE], token=first.read_text()) as peer:
        assert bound_call(socket_path=peer.path, ca=certs['ca'],
            private_key=certs['client1'][1], identity_bundle=target, request=REQUEST) == REPLY
    assert reads == [target]
    assert peer.seen[0]['capability'] == first.read_text()
    assert original(target).capability == second.read_text()


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_bundle_does_not_rotate_or_fall_back_from_wrong_private_key(material, tmp_path, backend):
    from aivm_secrets.identity.client import bound_call
    certs, first, _ = material
    target = tmp_path / 'identity.json'
    invoke('python', certs['client1'][0], first, target)
    if backend == 'python':
        with pytest.raises(SecretsError) as caught:
            bound_call(socket_path=tmp_path / 'absent.sock', ca=certs['ca'],
                private_key=certs['client2'][1], identity_bundle=target, request={})
        assert caught.value.code == 'invalid_capability'
    else:
        certs['ca'].chmod(0o600)
        config = private(tmp_path / 'wrong-key.json', dict(schema=1, key_mode='software',
            socket=str(tmp_path / 'absent.sock'), server_name='localhost',
            private_key=str(certs['client2'][1]), server_ca=str(certs['ca']),
            identity_bundle=str(target)))
        done = subprocess.run([executable('AIVM_SECRETS_RUST_GARRETT_CLIENT'), '--config', str(config)],
            input=b'{"version":1,"describe":true}', capture_output=True, timeout=15)
        assert done.returncode == 1 and done.stderr == b'invalid_capability\n'


def test_selected_bundle_crypto_dependency_fails_with_explicit_code(monkeypatch):
    import builtins
    original = builtins.__import__
    def without_crypto(name, *args, **kwargs):
        if name == 'cryptography' or name.startswith('cryptography.'):
            raise ImportError('synthetic missing optional crypto')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', without_crypto)
    with pytest.raises(SecretsError) as caught:
        bundle.pair(b'unused certificate', 'unused token')
    assert caught.value.code == 'missing_crypto'
