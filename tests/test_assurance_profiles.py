"""Profile boundaries exercised through Python and native Rust TLS/provider I/O.

Copying the software client identity is deliberately allowed in this threat
scenario. It grants the same enrolled identity, not arbitrary operations or
provider-token disclosure. TPM hardware and VM isolation are not simulated.
"""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import threading

import pytest

from aivm_secrets.host.egress import HTTPSExecutor
from aivm_secrets.host.server import LocalServer
from aivm_secrets.identity.certificates import create_csr
from aivm_secrets.identity.client import bound_call
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.service import UnixIdentityService
from aivm_secrets.kernel.service import parse_policy
from tests.secrets_github_scenario import ALLOWED_PR, OTHER_PR, PULL_PATH, install_github_routes
from tests.secrets_helpers import Harness, REPO, TOKEN, TLSService, write_private
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory
from tests.test_rust_w2_github_workflow import native_policy, native_disclosure


class PythonSoftwareCase:
    def __init__(self, directory, provider):
        self.directory = directory
        self.provider = provider
        self.stack = ExitStack()
        self.stop = threading.Event()

    def __enter__(self):
        try:
            p = self.directory
            policy = native_policy(p, self.provider)
            spec = parse_policy(policy)
            self.harness = Harness(p / 'harness', policy=policy, token=TOKEN,
                                   executor=HTTPSExecutor(spec.egress))
            self.stack.callback(self.harness.broker.close)
            self.authority = IdentityAuthority.initialize(
                p / 'authority', issuer='aivm.test', audience='aivm-secrets.identity')
            self.key, csr = p / 'client.key', p / 'client.csr'
            fingerprint = create_csr(private_key=self.key, request_file=csr)
            entry = self.authority.enroll(subject='vm-test', csr=csr.read_bytes(),
                                          approve_fingerprint=fingerprint)
            self.cert = Path(entry['certificate'])
            self.jwt = p / 'bound.jwt'
            self.authority.issue(subject='vm-test', broker_capability=self.harness.capability,
                                 output=self.jwt)
            broker = self.stack.enter_context(LocalServer(self.harness.broker, p / 'broker'))
            self.bridge = self.stack.enter_context(UnixIdentityService(
                authority=self.authority, broker_socket=broker.socket_path,
                listen=p / 'bridge' / 'identity.sock', idle_seconds=30))
            self.thread = threading.Thread(target=self.bridge.serve,
                                           args=(self.stop.is_set,))
            self.thread.start()
            return self
        except BaseException:
            self.stack.close()
            raise

    def invoke_clone(self, key, cert, number):
        return bound_call(socket_path=self.bridge.listen,
                          ca=self.authority.tls_paths()[2], certificate=cert,
                          private_key=key, jwt_file=self.jwt,
                          request={'operation': 'pr.view', 'arguments': {
                              'repository': REPO, 'pr': number}})

    def revoke(self):
        self.authority.revoke(subject='vm-test')

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=5)
        self.stack.close()
        assert not self.thread.is_alive()


@pytest.mark.parametrize('backend', ['python', 'rust'])
def test_software_identity_copy_preserves_scope_confinement_and_revocation(backend):
    with tempfile.TemporaryDirectory(prefix='as-profile-', dir='/tmp') as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            install_github_routes(provider)
            context = (PythonSoftwareCase(p, provider) if backend == 'python' else
                       ManifestCase(p, provider, native_policy(p, provider), native_disclosure()))
            with context as case:
                if backend == 'python':
                    key, cert = case.key, case.cert
                else:
                    cert, key, _ = case.certs['client1']
                attacker = p / 'copied-guest-files'
                attacker.mkdir(mode=0o700)
                copied_key = write_private(attacker / 'client.key', key.read_bytes())
                copied_cert = write_private(attacker / 'client.pem', cert.read_bytes())

                def invoke(number):
                    if backend == 'python':
                        return case.invoke_clone(copied_key, copied_cert, number)
                    case.certs['clone'] = (copied_cert, copied_key, None)
                    return case.invoke(role='clone', operation='pr.view',
                                       arguments={'repository': REPO, 'pr': number})

                # TLS accepts the copied software identity. This is the exact
                # assurance lost without separately verified key custody.
                reply = invoke(ALLOWED_PR)
                assert reply['ok'], reply
                assert reply['result']['number'] == ALLOWED_PR
                assert TOKEN not in json.dumps(reply)
                assert len(provider.seen()) == 1
                seen = provider.seen()[0]
                assert seen['target'] == PULL_PATH
                assert seen['headers']['authorization'] == 'Bearer ' + TOKEN

                denied = invoke(OTHER_PR)
                assert not denied['ok']
                assert len(provider.seen()) == 1
                if backend == 'python':
                    case.revoke()
                else:
                    case.authority.call('revoke', subject='vm-test')
                revoked = invoke(ALLOWED_PR)
                assert not revoked['ok']
                assert len(provider.seen()) == 1
                assert TOKEN not in json.dumps([reply, denied, revoked])


def test_profile_report_never_promotes_device_presence_or_host_execution():
    import re
    root = Path(__file__).resolve().parents[1]
    definitions = json.loads((root / 'docs/planning/aivm-secrets-assurance-profiles.json').read_text())
    profiles = {row['id']: row for row in definitions['profiles']}
    assert profiles['bound-software']['claims'] == profiles['device-only']['claims']
    assert profiles['bound-software']['claims']['provider_confinement']
    assert not profiles['bound-software']['claims']['guest_file_key_theft_resistance']
    assert profiles['verified-tpm-key']['claims']['guest_file_key_theft_resistance']
    assert not profiles['arbitrary-host-exec']['claims']['provider_confinement']
    proof = (root / definitions['lean_module']).read_text()
    assert not re.search(r'\b(sorry|admit)\b|(?m:^\s*axiom\b)', proof)
    assert set(re.findall(r'^theorem (\w+)', proof, re.MULTILINE)) == set(definitions['theorems'])
    assert len(definitions['shared_assumptions']) >= 4
    assert len(definitions['never_inferred']) >= 5
