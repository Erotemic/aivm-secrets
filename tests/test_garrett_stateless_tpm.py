"""garrett-stateless-v1 with a TPM-resident agent key (optional; disposable swtpm).

The agent's TLS CertificateVerify is signed inside the (software) TPM by the
Rust client's tpm2-tools signer; the private key is never in a file. This is
an adapter witness, not hardware provenance: an swtpm host can copy its
state or act as a signing oracle. ``AIVM_SECRETS_REQUIRE_TPM_TESTS=1`` makes
missing tools a failure instead of a skip.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from aivm_secrets.garrett_stateless import pki
from aivm_secrets.garrett_stateless.files import write_private
from tests.garrett_stateless_support import REPO, Environment, Process, python_command
from tests.test_rust_garrett_tpm import SoftwareTPM, require_software_tpm_tools


def _tpm_binary() -> Path:
    configured = os.environ.get('GARRETT_STATELESS_RUST_TPM')
    binary = Path(configured) if configured else REPO / 'rust' / 'target' / 'tpm' / 'debug' / 'garrett-stateless'
    if not binary.exists():
        pytest.skip('garrett-stateless with the tpm feature not built: '
                    'cargo build -p garrett-stateless --features tpm --target-dir target/tpm')
    return binary


def test_tpm_bound_login_and_use(tmp_path):
    require_software_tpm_tools()
    binary = _tpm_binary()
    env = Environment(tmp_path)
    with tempfile.TemporaryDirectory(prefix='gst-') as short:
        state = Path(short) / 'tpm'
        state.mkdir(mode=0o700)
        work = Path(short) / 'work'
        work.mkdir(mode=0o700)
        with SoftwareTPM(state) as tpm:
            public = serialization.load_der_public_key((state / 'public.der').read_bytes())
            issued = pki.issue(env.ca, client_name='agent-tpm', uri='spiffe://test/agent-tpm', public_key=public)
            assert issued.key == b''
            env.write('agent-tpm.pem', issued.certificate)
            write_private(env.root / 'tpm.json', json.dumps({
                'tcti': tpm.tcti, 'persistent_handle': 0x81010011,
                'authorization_file': str(state / 'auth'), 'public_area_file': str(state / 'public.tpmt'),
                'work_directory': str(work)}).encode())
            agent = [str(binary), 'agent']
            identity = ['--ca', 'ca.pem', '--cert', 'agent-tpm.pem', '--tpm', 'tpm.json']
            broker = Process([str(binary), 'broker', '--config', 'broker.json'], env.root)
            try:
                login = subprocess.Popen(
                    agent + ['login', '--broker', 'https://broker.test:9443', '--connect', broker.announcement['agent'],
                             '--provider', 'api', '--out', 'token', '--timeout', '60'] + identity,
                    cwd=env.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                started = json.loads(login.stdout.readline())
                assert env.human(started['authorization_url'], broker.announcement['browser']).status == 200
                login.stdout.readline()
                assert login.wait(30) == 0, login.stderr.read()
            finally:
                broker.stop()
            proxy = Process([str(binary), 'proxy', '--config', 'proxy.json'], env.root)
            try:
                def request(extra):
                    result = subprocess.run(
                        agent + ['request', '--proxy', 'https://proxy.test:8443', '--connect',
                                 proxy.announcement['address'], '--token-file', 'token', '/user'] + extra,
                        cwd=env.root, capture_output=True, timeout=60)
                    return result.returncode, result.stderr.decode()

                code, err = request(identity)
                assert code == 0, err
                # The same surrogate on a software-key certificate is refused.
                code, err = request(['--ca', 'ca.pem', '--cert', 'agent-c.pem', '--key', 'agent-c.key'])
                assert code == 22 and '"status":401' in err
                # The Python agent has no TPM mode and says so instead of falling back.
                refused = subprocess.run(python_command() + ['agent', 'request', '--proxy', 'https://proxy.test:8443',
                                                             '--token-file', 'token', '/user'] + identity,
                                         cwd=env.root, capture_output=True, timeout=60)
                assert refused.returncode != 0 and b'TPM' in refused.stderr
                # Wrong TPM authorization: no signature, no connection, no fallback.
                good = (state / 'auth').read_bytes()
                (state / 'auth').write_bytes(b'wrong-authorization-0123456789012')
                code, _ = request(identity)
                assert code != 0
                (state / 'auth').write_bytes(good)
                assert list(work.iterdir()) == []
            finally:
                proxy.stop()
