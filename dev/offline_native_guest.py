#!/usr/bin/env python3
"""Run a real native Garrett operator/guest flow against LOCAL synthetic HTTPS.

This is an operator demonstration, not a test implementation of the broker.
All admission, mTLS, surrogate, custody, HTTPS, audit and revocation decisions
are performed by the production Rust authority, bridge and client binaries.
Python supplies local fake provider data and operator configuration only.

The demo uses host/guest directories under ONE Unix user. They are separate
*distributions*, not a filesystem/VM isolation proof. Do not use real secrets.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import http.server
import json
import os
import re
import select
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Permit running from the checkout without requiring an editable installation.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.certificates import inspect_csr
from aivm_secrets.kernel.presets import GITHUB_DIFF, GITHUB_JSON, github_pr
from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.primitives import codec

REPOSITORY = 'TauCetiProject/TauCeti'
PR = 13861
HEAD_SHA = 'a' * 40
FAKE_TOKEN = 'github_pat_OFFLINE_DEMO_NOT_VALID_0123456789'
HOSTNAME = 'api.example.org'
PULL_PATH = f'/repos/{REPOSITORY.lower()}/pulls/{PR}'
CHECKS_PATH = f'/repos/{REPOSITORY.lower()}/commits/{HEAD_SHA}/check-runs?page=1&per_page=100'
COMMENTS_PATH = f'/repos/{REPOSITORY.lower()}/issues/{PR}/comments'
DIFF = 'diff --git a/proof.lean b/proof.lean\n+theorem checked : True := trivial\n'
PULL = {
    'number': PR, 'title': 'Proof repair', 'body': 'Host-controlled synthetic data',
    'base': {'repo': {'full_name': REPOSITORY}},
    'head': {'repo': {'full_name': 'Erotemic/TauCeti'}, 'sha': HEAD_SHA},
    'user': {'login': 'Erotemic'},
    'private_diagnostic': 'UNSELECTED_PROVIDER_FIELD',
}


class DemoError(Exception):
    """Fixed/public failure to run the offline workflow."""


def write(path: Path, data: bytes | dict | str, *, mode: int = 0o600) -> Path:
    if isinstance(data, dict):
        data = codec.dumps(data)
    elif isinstance(data, str):
        data = data.encode('utf-8')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Exclusive create: a repeated run must not overwrite key/authority state.
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(mode)
    return path


def mkdir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def public_name(value: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def provider_certificates(directory: Path, hostname: str = HOSTNAME) -> dict[str, Path]:
    """Disposable operator-owned TLS CA and pinned provider leaf."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = public_name('Offline Garrett synthetic CA')
    ca = (x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False,
        ), True)
        .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
        .subject_name(public_name(hostname)).issuer_name(ca.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    return {
        # The native broker treats its pinned CA file as private host input.
        'ca': write(directory / 'ca.pem', ca.public_bytes(pem)),
        'cert': write(directory / 'server.pem', leaf.public_bytes(pem), mode=0o644),
        'key': write(directory / 'server.key', key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
    }


class LocalProvider:
    """HTTPS transport and deterministic data; NEVER decides guest authorization."""

    def __init__(self, directory: Path):
        self.host = HOSTNAME
        self.files = provider_certificates(directory)
        self.requests: list[dict] = []
        self.lock = threading.Lock()
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                seen = {
                    'method': self.command,
                    'path': self.path,
                    'accept': self.headers.get('Accept'),
                    'authorization': self.headers.get('Authorization'),
                    'api_version': self.headers.get('X-GitHub-Api-Version'),
                }
                with parent.lock:
                    parent.requests.append(seen)
                if self.path == PULL_PATH and seen['accept'] == GITHUB_JSON:
                    status, kind, body = 200, 'application/json', json.dumps(PULL).encode()
                elif self.path == PULL_PATH and seen['accept'] == GITHUB_DIFF:
                    status, kind, body = 200, 'text/plain', DIFF.encode()
                elif self.path == CHECKS_PATH and seen['accept'] == GITHUB_JSON:
                    status, kind, body = 200, 'application/json', json.dumps({
                        'check_runs': [{'name': 'lean', 'status': 'completed', 'conclusion': 'success'}]
                    }).encode()
                else:
                    status, kind, body = 404, 'application/json', b'{}'
                self.send_response(status)
                self.send_header('Content-Type', kind)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass
                self.close_connection = True

            def do_POST(self):
                # Only the write a write-enabled policy may send: one comment.
                length = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(min(length, 65536))
                seen = {
                    'method': self.command,
                    'path': self.path,
                    'accept': self.headers.get('Accept'),
                    'authorization': self.headers.get('Authorization'),
                    'api_version': self.headers.get('X-GitHub-Api-Version'),
                    'body': body.decode('utf-8', 'replace'),
                }
                with parent.lock:
                    parent.requests.append(seen)
                if self.path == COMMENTS_PATH:
                    try:
                        text = json.loads(body)['body']
                    except (ValueError, KeyError, TypeError):
                        text = ''
                    status, payload = 201, json.dumps({'id': 1, 'body': text}).encode()
                else:
                    status, payload = 404, b'{}'
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Connection', 'close')
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except OSError:
                    pass
                self.close_connection = True

            def log_message(self, format, *args):
                # HTTP request metadata can include credentials. Never log it.
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(self.files['cert']), str(self.files['key']))
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.05}, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def seen(self) -> list[dict]:
        with self.lock:
            return list(self.requests)


def disclosure() -> dict:
    return {
        'pr.view': {
            'number': {'at': ['number'], 'type': 'integer'},
            'title': {'at': ['title'], 'type': 'text'},
            'headRefOid': {'at': ['head', 'sha'], 'type': 'text'},
        },
        'pr.diff': {'diff': {'at': [], 'type': 'text'}},
        # The native Disclosure::parse requires an exact key for *every*
        # manifest operation, even a write that writes=deny will refuse.
        # If writes were enabled, select only the public comment body.
        'pr.comment': {'body': {'at': ['body'], 'type': 'text'}},
        'pr.checks': {'checks': {
            'at': ['check_runs'], 'type': 'array', 'max_items': 100,
            'items': {'at': [], 'type': 'object', 'fields': {
                'name': {'at': ['name'], 'type': 'text'},
                'status': {'at': ['status'], 'type': 'text'},
                'conclusion': {'at': ['conclusion'], 'type': 'text'},
            }},
        }},
    }


def validate_disclosure_coverage(manifest: dict, rules: dict) -> None:
    """Preflight native Disclosure::parse's exact operation-set requirement.

    This is only an operator configuration check. The native broker still
    parses and enforces every projection and its credential-reflection checks.
    """
    operations = {operation['name'] for operation in manifest['operations']}
    if set(rules) != operations:
        raise DemoError('offline disclosure does not cover the manifest operation set')


def policy(host: Path, provider: LocalProvider) -> dict:
    result = github_pr({
        'schema': 1, 'repository': REPOSITORY, 'pr_numbers': [PR],
        'operations': ['pr.view', 'pr.diff', 'pr.checks', 'pr.comment'],
        'author': 'Erotemic', 'head_repository': 'Erotemic/TauCeti',
        'gh_compat': 2, 'lifetime_seconds': 300, 'max_requests': 32,
        'max_body_bytes': 8192,
    })
    result.pop('cli', None)  # Native garrett-client owns its closed gh aliases.
    result['host'] = provider.host
    result['egress'] = {
        'address': '127.0.0.1', 'port': provider.port,
        'ca_file': str(provider.files['ca']),
    }
    result['credential_source'] = {'kind': 'file', 'path': str(host / 'credential')}
    # Native Rust remains the authoritative interpreter; Python validation
    # is only an early operator input sanity check.
    parse_policy(result)
    return result


def binaries(directory: Path) -> dict[str, Path]:
    names = {'authority': 'garrett-authority', 'bridge': 'garrett-bridge',
             'client': 'garrett-client'}
    paths = {role: directory / name for role, name in names.items()}
    for role, path in paths.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise DemoError(f'missing native {role} binary at {path}; build rust/Cargo.toml --bins')
    return paths


def safe_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in ('SSLKEYLOGFILE', 'RUST_LOG', 'RUST_BACKTRACE', 'PYTHONPATH',
                 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                 'http_proxy', 'https_proxy', 'all_proxy'):
        env.pop(name, None)
    return env


def run(command: list[str | Path], *, input_data: bytes | None = None,
        cwd: Path | None = None, timeout: float = 20) -> subprocess.CompletedProcess:
    result = subprocess.run([str(item) for item in command], input=input_data,
                            cwd=cwd, env=safe_environment(), capture_output=True,
                            timeout=timeout)
    # Protect against accidentally showing a credential in a subprocess error.
    if FAKE_TOKEN.encode() in result.stdout + result.stderr:
        raise DemoError('synthetic provider credential appeared on a process output')
    return result


# Native garrett-authority emits this fixed public error vocabulary. Never
# forward arbitrary stdout/stderr from an operator action (even on failure).
PUBLIC_AUTHORITY_CODES = frozenset({
    'invalid_capability', 'invalid_policy', 'resource_mismatch',
    'invalid_request', 'denied', 'unreachable', 'upstream_response',
    'upstream_rejected', 'upstream_error', 'internal_error', 'unsafe_file',
    'outcome_unknown', 'exhausted', 'revoked', 'credential_source',
    'expired',
})


def authority_error_code(stdout: bytes) -> str | None:
    """Decode only a known public code from the native JSON failure envelope."""
    try:
        response = codec.loads(stdout, limit=4096)
    except SecretsError:
        return None
    if (not isinstance(response, dict) or response.get('version') != 1
            or response.get('ok') is not False):
        return None
    error = response.get('error')
    if not isinstance(error, dict):
        return None
    code = error.get('code')
    return code if isinstance(code, str) and code in PUBLIC_AUTHORITY_CODES else None


def authority_action(binary: Path, host: Path, action: str, **kwargs) -> dict:
    path = write(host / f'operator-{action}.json', kwargs)
    try:
        result = run([binary, action, '--root', host / 'authority', '--request', path])
    finally:
        path.unlink()
    if result.returncode or not result.stdout:
        code = authority_error_code(result.stdout)
        detail = f'; native error={code}' if code else ''
        raise DemoError(f'native authority action {action} failed (exit {result.returncode}{detail})')
    try:
        data = codec.loads(result.stdout)
    except (ValueError, TypeError):
        raise DemoError(f'native authority action {action} returned invalid JSON') from None
    if data.get('version') != 1 or data.get('ok') is not True:
        raise DemoError(f'native authority action {action} rejected the operator request')
    return data['result']


def make_client(host: Path, guest: Path, authority: Path, client: Path) -> None:
    key = guest / 'client.key'
    csr = guest / 'client.csr'
    # Guest-side native key creation: the operator never constructs/loads the
    # private key. Native Garrett enforces no-replace and fd-bound publication.
    request = run([client, 'request', '--key-mode', 'software',
                   '--key', key, '--csr', csr], cwd=guest)
    if request.returncode != 0:
        raise DemoError('native guest CSR/key creation failed')
    try:
        issued = codec.loads(request.stdout)
    except (ValueError, TypeError):
        raise DemoError('native guest CSR command returned invalid public JSON') from None
    fingerprint = inspect_csr(csr.read_bytes())
    if issued.get('key_fingerprint') != fingerprint:
        raise DemoError('CSR fingerprint changed between native guest and operator')
    authority_action(authority, host, 'enroll', subject='offline-guest',
                     csr_file=str(csr), approve_fingerprint=fingerprint)
    public = authority_action(authority, host, 'public-client', subject='offline-guest')
    distribute_guest_certificates(guest, public)


def distribute_guest_certificates(guest: Path, public: dict) -> None:
    """Native clients read both PEM files through their private-file API."""
    write(guest / 'ca.pem', base64.b64decode(public['ca_pem_b64']))
    write(guest / 'client.pem', base64.b64decode(public['certificate_pem_b64']))


def bridge_config(host: Path, provider: LocalProvider) -> dict:
    return {
        'schema': 1, 'authority_root': str(host / 'authority'),
        'client_assurance': 'any-enrolled', 'subject': 'offline-guest',
        'listen': str(host / 'identity.sock'), 'lifetime': 300,
        'binding': {'owner_uid': os.getuid(), 'access_identity': 'offline-operator',
                    'vm': 'offline-guest', 'channel': 'b' * 32},
        'provider': {
            'profile': 'manifest-https-v1', 'host': provider.host,
            'address': '127.0.0.1', 'port': provider.port,
            'authentication': 'bearer', 'server_ca': str(provider.files['ca']),
            'credential_file': str(host / 'credential'),
            'audit_file': str(host / 'provider-audit.jsonl'),
            'policy_file': str(host / 'policy.json'),
            'disclosure_file': str(host / 'disclosure.json'),
            'writes': 'deny', 'request_limit': 'unbounded',
        },
    }


def guest_config(host: Path, guest: Path) -> dict:
    return {
        'schema': 1, 'key_mode': 'software',
        'socket': str(host / 'identity.sock'), 'server_name': 'localhost',
        'certificate': str(guest / 'client.pem'),
        'private_key': str(guest / 'client.key'),
        'server_ca': str(guest / 'ca.pem'),
    }


def native_error_code(stderr: bytes) -> str | None:
    """Show only a fixed-shape native error code, never raw process diagnostics."""
    try:
        value = stderr.decode('ascii').strip()
    except UnicodeError:
        return None
    return value if re.fullmatch(r'[a-z][a-z_]{0,63}', value) else None


def start_bridge(binary: Path, host: Path) -> tuple[subprocess.Popen, dict]:
    process = subprocess.Popen([str(binary), '--config', str(host / 'bridge.json')],
                               cwd=host, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=safe_environment())
    try:
        assert process.stdout is not None
        ready, _, _ = select.select([process.stdout], [], [], 15)
        if not ready:
            raise DemoError('native broker did not announce readiness')
        line = process.stdout.readline()
        if FAKE_TOKEN.encode() in line:
            raise DemoError('native broker leaked provider credential at startup')
        if not line:
            raise DemoError('native broker exited before readiness')
        try:
            response = codec.loads(line)
        except SecretsError:
            raise DemoError('native broker emitted invalid readiness JSON') from None
        if (not isinstance(response, dict) or response.get('ready') is not True
                or response.get('profile') != 'manifest-https-v1'):
            raise DemoError('native broker failed to start in manifest-https-v1 profile')
        if not isinstance(response.get('capability'), str):
            raise DemoError('native broker did not issue guest capability')
        return process, response
    except BaseException as error:
        _, stderr = stop_bridge(process)
        if isinstance(error, DemoError) and str(error) == 'native broker exited before readiness':
            code = native_error_code(stderr)
            detail = f'; native error={code}' if code else ''
            raise DemoError(f'native broker exited before readiness (status={process.returncode}{detail})') from None
        raise


def stop_bridge(process: subprocess.Popen) -> tuple[bytes, bytes]:
    if process.poll() is None:
        process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
    if FAKE_TOKEN.encode() in stdout + stderr:
        raise DemoError('synthetic provider credential leaked from broker process')
    return stdout, stderr


def guest_call(client: Path, guest: Path, *words: str) -> subprocess.CompletedProcess:
    return run([client, '--config', guest / 'client.json', '--capability-file',
                guest / 'capability.jwt', *words], cwd=guest)


def check_workspace(host: Path, guest: Path, jwt: str) -> None:
    for item in guest.iterdir():
        if item.is_file():
            data = item.read_bytes()
            if FAKE_TOKEN.encode() in data or b'UNSELECTED_PROVIDER_FIELD' in data:
                raise DemoError(f'host-only/provider-private data was copied into {item.name}')
    audit = host / 'provider-audit.jsonl'
    if not audit.is_file():
        raise DemoError('native broker failed to write host audit')
    audit_bytes = audit.read_bytes()
    if FAKE_TOKEN.encode() in audit_bytes or jwt.encode() in audit_bytes:
        raise DemoError('host audit leaked credential or surrogate')


def validate_sent(provider: LocalProvider, *, expected_count: int) -> list[dict]:
    received = provider.seen()
    if len(received) != expected_count:
        raise DemoError(f'expected {expected_count} provider requests, got {len(received)}')
    for event in received:
        allowed_method = (event['method'] == 'GET'
                          or (event['method'] == 'POST' and event['path'] == COMMENTS_PATH))
        if (not allowed_method
                or event['authorization'] != 'Bearer ' + FAKE_TOKEN
                or event['api_version'] != '2026-03-10'):
            raise DemoError('provider observed an unauthorized method, credential or API version')
    # Only approved metadata is persisted, never a bearer token.
    return [{'method': row['method'], 'path': row['path'], 'accept': row['accept'],
             'credential_substituted': True} for row in received]


def _successful_json(result: subprocess.CompletedProcess, stage: str):
    if result.returncode:
        raise DemoError(f'{stage} exited nonzero ({result.returncode})')
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise DemoError(f'{stage} did not return valid JSON') from None


def demonstrate(workspace: Path, bin_dir: Path, *, interactive: bool = False) -> dict:
    """Execute four real client operations, deny a write, then revoke live."""
    tools = binaries(bin_dir)
    host, guest = mkdir(workspace / 'host'), mkdir(workspace / 'guest')
    mkdir(host / 'provider')
    write(host / 'credential', FAKE_TOKEN)
    with LocalProvider(host / 'provider') as provider:
        manifest = policy(host, provider)
        releases = disclosure()
        validate_disclosure_coverage(manifest, releases)
        write(host / 'policy.json', manifest)
        write(host / 'disclosure.json', releases)
        authority_action(tools['authority'], host, 'init',
                         issuer='aivm.test', audience='aivm-secrets.remote')
        make_client(host, guest, tools['authority'], tools['client'])
        write(host / 'bridge.json', bridge_config(host, provider))
        process, startup = start_bridge(tools['bridge'], host)
        try:
            jwt = startup['capability']
            write(guest / 'capability.jwt', jwt)
            write(guest / 'client.json', guest_config(host, guest))
            view = _successful_json(guest_call(
                tools['client'], guest, 'gh', 'pr', 'view', str(PR),
                '--repo', REPOSITORY, '--json', 'number,title,headRefOid'), 'approved pr view')
            if view != {'number': PR, 'title': 'Proof repair', 'headRefOid': HEAD_SHA}:
                raise DemoError('native selected PR view differs from approved output')
            diff = guest_call(tools['client'], guest, 'gh', 'pr', 'diff', str(PR),
                              '--repo', REPOSITORY)
            if diff.returncode != 0 or diff.stdout.decode() != DIFF:
                raise DemoError('approved PR diff did not match selected text')
            requests_after_reads = len(provider.seen())
            if requests_after_reads != 3:  # view preflight + diff preflight/final
                raise DemoError('unexpected provider request count for two approved guest reads')
            # Send the WRITE to the broker, not just an unsupported gh alias.
            # A denial by the guest parser alone would not exercise writes=deny.
            denied = guest_call(tools['client'], guest, 'invoke', 'pr.comment',
                                '--arguments', json.dumps({
                                    'repository': REPOSITORY, 'pr': PR,
                                    'body': 'not authorized',
                                }, separators=(',', ':')))
            try:
                denied_result = json.loads(denied.stdout)
            except (ValueError, UnicodeError):
                raise DemoError('broker denial did not return public JSON') from None
            if (denied.returncode == 0 or denied_result.get('ok') is not False
                    or denied_result.get('error', {}).get('code') != 'denied'):
                raise DemoError('unapproved broker write did not fail closed')
            if len(provider.seen()) != requests_after_reads:
                raise DemoError('unapproved guest write reached the provider')
            if interactive:
                print('Native Garrett broker is running. Try this guest command:',
                      file=sys.stderr)
                cmd = [tools['client'], '--config', guest / 'client.json',
                       '--capability-file', guest / 'capability.jwt',
                       'gh', 'pr', 'checks', str(PR), '--repo', REPOSITORY,
                       '--json', 'name,status']
                print('  ' + ' '.join(str(word) for word in cmd), file=sys.stderr)
                print('Press Enter to revoke the guest and stop the session.',
                      file=sys.stderr)
                input()
            authority_action(tools['authority'], host, 'revoke', subject='offline-guest')
            revoked = guest_call(tools['client'], guest, 'gh', 'pr', 'view', str(PR),
                                 '--repo', REPOSITORY, '--json', 'number')
            if revoked.returncode == 0 or revoked.stdout:
                raise DemoError('revoked guest could still read')
            if len(provider.seen()) != requests_after_reads:
                raise DemoError('revoked guest reached provider')
            check_workspace(host, guest, jwt)
            witness = validate_sent(provider, expected_count=3)
            write(host / 'provider-observations.json', {'requests': witness})
            return {
                'ok': True, 'mode': 'real-native-rust/synthetic-local-https',
                'approved': {'view': view, 'diff': DIFF},
                'denied_write': True, 'revocation_fenced': True,
                'provider_requests': witness,
                'guest_distribution_contains_provider_credential': False,
                'filesystem_isolation_proved': False,
                'host_audit': str(host / 'provider-audit.jsonl'),
            }
        finally:
            stop_bridge(process)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, default=REPO_ROOT / 'rust/target/debug',
                        help='directory containing real garrett-{authority,bridge,client} binaries')
    parser.add_argument('--workspace', type=Path,
                        help='new output directory; must not already exist; otherwise ephemeral')
    parser.add_argument('--interactive', action='store_true',
                        help='pause for manual guest CLI calls before revocation')
    args = parser.parse_args(argv)
    try:
        # Fail before creating a persistent workspace if the native tools are
        # missing. There is deliberately no fallback to a Python fake broker.
        binaries(args.bin_dir.absolute())
        if args.workspace is None:
            with tempfile.TemporaryDirectory(prefix='garrett-offline-') as temporary:
                report = demonstrate(Path(temporary), args.bin_dir.absolute(),
                                     interactive=args.interactive)
                report.pop('host_audit')  # removed with temporary directory
        else:
            workspace = args.workspace.absolute()
            # No overwrite and no following existing symlinks to host secrets.
            workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
            report = demonstrate(workspace, args.bin_dir.absolute(),
                                 interactive=args.interactive)
            write(workspace / 'summary.json', report)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (DemoError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        # No subprocess stderr or arbitrary provider diagnostics in public output.
        print(f'offline Garrett demonstration failed: {type(error).__name__}: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
