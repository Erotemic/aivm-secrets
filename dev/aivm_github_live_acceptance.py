#!/usr/bin/env python3
"""Opt-in OUT-3 real GitHub read-only acceptance from a managed AIVM guest.

The *production Rust* authority and broker execute on the operator host.
The native garrett-client executes inside a real KVM guest and authenticates
through the existing SSH-forwarded Unix application socket using mTLS.

No synthetic provider, anonymous fallback, live mutation or generic GitHub
proxy. An operator-created fine-grained PAT stays on the host; the harness validates
its bytes for safe input/output handling and native custody reads the file.
The allowlist names Erotemic/aivm-secrets and three exact GitHub REST reads.
A synthetic-hosted negative-effect witness remains a separate OUT-2 gate.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import stat
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aivm_secrets.identity.certificates import inspect_csr
from aivm_secrets.kernel.presets import GITHUB_API_VERSION, GITHUB_JSON
from aivm_secrets.kernel.service import parse_policy
from dev import offline_native_guest as offline
from dev.aivm_vm_acceptance import (
    GuestSSH,
    _client_command,
    _expect_path_not_readable,
    _read_output,
    _stop_forward,
    _wait_for_forward,
    ssh_configuration,
    validate_vm_name,
)
from dev.offline_native_guest import (
    DemoError,
    authority_action,
    binaries,
    start_bridge,
    stop_bridge,
    validate_disclosure_coverage,
    write,
)

GITHUB_HOST = 'api.github.com'
TARGET_OWNER = 'Erotemic'
TARGET_REPO = 'aivm-secrets'
TARGET_FULL_NAME = f'{TARGET_OWNER}/{TARGET_REPO}'
DEFAULT_TOKEN_FILE = Path.home() / '.config/aivm-secrets/github-readonly.token'
TRUST_BUNDLE = Path('/etc/ssl/certs/ca-certificates.crt')
SHA40 = re.compile(r'[0-9a-f]{40}\Z')


def check_token_file(path: Path) -> tuple[Path, bytes]:
    """Reject files whose metadata would make the credential guest-readable.

    Rust's read_private guard enforces stronger trusted ancestry checks when
    it opens the file. This operator preflight only improves error locality.
    """
    path = path.expanduser().absolute()
    try:
        metadata = path.lstat()
    except OSError:
        raise DemoError('dedicated GitHub token file is missing or inaccessible') from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise DemoError('GitHub token must be a regular, non-linked file')
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise DemoError('GitHub token file must be owned by the operator and inaccessible to group/other')
    resolved = path.resolve(strict=True)
    if resolved == REPO_ROOT or REPO_ROOT in resolved.parents:
        raise DemoError('never put a live credential in the source repository')
    # Do not log, print, copy or persist the token bytes into the test workspace.
    try:
        with resolved.open('rb') as stream:
            raw = stream.read(4097)
    except OSError:
        raise DemoError('cannot read the dedicated GitHub token file') from None
    if not (16 <= len(raw) <= 4096) or any(b < 33 or b > 126 for b in raw):
        raise DemoError('token must contain 16-4096 printable nonwhitespace ASCII bytes, without a newline')
    if not raw.startswith(b'github_pat_'):
        raise DemoError('this fixture requires a dedicated fine-grained github_pat_ token')
    return resolved, raw


def resolved_github_address() -> str:
    """Resolve once on the trusted host, pin one PUBLIC IPv4 TLS destination."""
    try:
        answers = socket.getaddrinfo(GITHUB_HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        raise DemoError('host could not resolve api.github.com') from None
    addresses = sorted({answer[4][0] for answer in answers})
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            continue
        # This connection carries no credential. The native Rust transport
        # independently performs the credentialed, hostname-verified TLS read.
        try:
            connection = socket.create_connection((address, 443), timeout=3)
        except OSError:
            continue
        connection.close()
        return address
    raise DemoError('no reachable public IPv4 address resolved for api.github.com')


def copy_trust_bundle(host: Path, source: Path = TRUST_BUNDLE) -> Path:
    """Private, bounded copy of the *host's* standard CA trust anchors."""
    try:
        if not source.is_file():
            raise OSError('no system CA bundle')
        data = source.read_bytes()
    except OSError:
        raise DemoError('host system CA bundle could not be read') from None
    if b'-----BEGIN CERTIFICATE-----' not in data or not (100 <= len(data) <= 1048576):
        raise DemoError('host CA bundle is missing valid PEM certificates or exceeds Rust limit')
    return write(host / 'github-ca.pem', data)


def live_policy(token_path: Path, ca_path: Path, address: str) -> dict:
    """Exact operator-selected GETs plus an explicitly denied named write."""
    scope = {'owner': [TARGET_OWNER], 'repo': [TARGET_REPO]}
    result = {
        'schema': 2,
        'adapter': 'https',
        'service': 'github-aivm-secrets-readonly',
        'host': GITHUB_HOST,
        'authentication': 'bearer',
        'credential_source': {'kind': 'file', 'path': str(token_path)},
        'egress': {'address': address, 'port': 443, 'ca_file': str(ca_path)},
        'headers': {'X-GitHub-Api-Version': GITHUB_API_VERSION},
        'operations': [
            {
                'name': 'account.probe', 'effect': 'read', 'method': 'GET',
                'path': '/user', 'accept': GITHUB_JSON,
            },
            {
                'name': 'repo.view', 'effect': 'read', 'method': 'GET',
                'path': '/repos/{owner}/{repo}', 'accept': GITHUB_JSON,
                'parameters': scope,
            },
            {
                'name': 'repo.readme', 'effect': 'read', 'method': 'GET',
                'path': '/repos/{owner}/{repo}/readme', 'accept': GITHUB_JSON,
                'parameters': scope,
            },
            {
                'name': 'repo.issue', 'effect': 'write', 'method': 'POST',
                'path': '/repos/{owner}/{repo}/issues', 'accept': GITHUB_JSON,
                'parameters': scope, 'body_fields': {'title': 120},
            },
        ],
        'lifetime_seconds': 300,
        'max_requests': 10,
        'max_body_bytes': 4096,
    }
    # Operator-side input check only. The native bridge re-parses and owns
    # the authoritative policy; this call cannot authorize or send a request.
    parse_policy(result)
    return result


def live_disclosure() -> dict:
    return {
        # /user actually requires the token; release only a public numeric id.
        'account.probe': {'authenticatedUserId': {'at': ['id'], 'type': 'integer'}},
        'repo.view': {
            'fullName': {'at': ['full_name'], 'type': 'text'},
            'defaultBranch': {'at': ['default_branch'], 'type': 'text'},
            'private': {'at': ['private'], 'type': 'boolean'},
        },
        'repo.readme': {
            'path': {'at': ['path'], 'type': 'text'},
            'sha': {'at': ['sha'], 'type': 'text'},
            'size': {'at': ['size'], 'type': 'integer'},
        },
        # Mandatory coverage, but writes=deny prevents this from being sent.
        'repo.issue': {'number': {'at': ['number'], 'type': 'integer'}},
    }


def live_bridge_config(host: Path, token_path: Path, ca_path: Path,
                       address: str, vm: str) -> dict:
    return {
        'schema': 1,
        'authority_root': str(host / 'authority'),
        'client_assurance': 'any-enrolled',
        'subject': 'live-guest',
        'listen': str(host / 'identity.sock'),
        'lifetime': 300,
        'binding': {
            'owner_uid': os.getuid(), 'access_identity': 'github-readonly-operator',
            'vm': vm, 'channel': secrets.token_hex(16),
        },
        'provider': {
            'profile': 'manifest-https-v1', 'host': GITHUB_HOST,
            'address': address, 'port': 443,
            'authentication': 'bearer', 'server_ca': str(ca_path),
            'credential_file': str(token_path),
            'audit_file': str(host / 'provider-audit.jsonl'),
            'policy_file': str(host / 'policy.json'),
            'disclosure_file': str(host / 'disclosure.json'),
            'writes': 'deny', 'request_limit': 'unbounded',
        },
    }


def live_guest_invoke(ssh: GuestSSH, guest: str, operation: str,
                      arguments: dict | None = None):
    words = ['invoke', operation]
    if arguments:
        words += ['--arguments', json.dumps(arguments, sort_keys=True, separators=(',', ':'))]
    return ssh.call(_client_command(guest, words=tuple(words)), timeout=45)


def successful_projection(result, *, label: str, expected_keys: set[str]) -> dict:
    reply = _read_output(result, label)
    if not isinstance(reply, dict) or reply.get('version') != 1 or reply.get('ok') is not True:
        raise DemoError(f'{label}: no authorized native reply (provider, TLS, token or policy)')
    selected = reply.get('result')
    if not isinstance(selected, dict) or set(selected) != expected_keys:
        raise DemoError(f'{label}: projection contained missing/unapproved fields')
    return selected


def audit_dispatch_count(host: Path, *, token: bytes, capability: str) -> int:
    """Inspect public audit events; never expose raw records in test output."""
    path = host / 'provider-audit.jsonl'
    try:
        content = path.read_bytes()
    except OSError:
        raise DemoError('native host audit file is absent') from None
    if token in content or capability.encode('utf-8') in content:
        raise DemoError('host audit contains provider credential or surrogate')
    try:
        entries = [json.loads(line) for line in content.splitlines()]
    except (ValueError, UnicodeError):
        raise DemoError('native host audit contains malformed JSON') from None
    if not entries or not all(isinstance(item, dict) and item.get('schema') == 1 for item in entries):
        raise DemoError('native host audit contains invalid event records')
    return sum(entry.get('event') == 'dispatch' for entry in entries)


def rejected_without_dispatch(ssh: GuestSSH, guest: str, host: Path,
                              token: bytes, capability: str,
                              operation: str, arguments: dict, count: int,
                              *, label: str) -> None:
    result = live_guest_invoke(ssh, guest, operation, arguments)
    if result.returncode == 0:
        raise DemoError(f'{label}: unexpectedly succeeded')
    if result.stdout:
        try:
            reply = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise DemoError(f'{label}: unexpected released output on denial') from None
        if not isinstance(reply, dict) or reply.get('ok') is not False or reply.get('error', {}).get('code') != 'denied':
            raise DemoError(f'{label}: did not return the expected native denial')
    if audit_dispatch_count(host, token=token, capability=capability) != count:
        raise DemoError(f'{label}: unauthorized request produced a native dispatch event')


def verify_revocation_state(before: dict, result: dict, after: dict) -> None:
    """Require a persisted, epoch-advancing native authority revocation.

    A successful revoke command alone does not establish that the broker's
    authoritative enrollment is inactive. Compare the returned transition to
    an independently reopened native authority status after the commit.
    """
    try:
        prior = before['subjects']['live-guest']
        claimed = result['state']['subjects']['live-guest']
        current = after['subjects']['live-guest']
        was_active = prior['active'] is True
        is_inactive = claimed['active'] is False and current['active'] is False
        old_epoch = prior['epoch']
        new_epoch = current['epoch']
    except (KeyError, TypeError, AttributeError):
        raise DemoError('native authority did not return a complete revocation state') from None
    if (not was_active or not is_inactive or type(old_epoch) is not int
            or type(new_epoch) is not int or new_epoch != old_epoch + 1
            or current != claimed):
        raise DemoError('native authority revocation was not durably reflected in status')


def require_revoked_identity_denial(result) -> str:
    """Accept only a *structured* native identity denial, never released data.

    Unlike the `gh` alias, native `invoke` prints its public broker error JSON
    on stdout and exits 1. Stdout presence is therefore not success evidence.
    The native authority's inactive enrollment fails registry expectation
    with invalid_capability; revoked is also an explicit identity error code.
    """
    if result.returncode != 1:
        raise DemoError('revoked VM guest did not exit with native denial status')
    try:
        reply = json.loads(result.stdout)
    except (ValueError, UnicodeError, TypeError):
        raise DemoError('revoked VM guest did not return a structured native denial') from None
    if not isinstance(reply, dict) or set(reply) != {'version', 'ok', 'error'}:
        raise DemoError('revoked VM guest returned unexpected public fields')
    error = reply.get('error')
    if (reply.get('version') != 1 or reply.get('ok') is not False
            or not isinstance(error, dict)
            or set(error) != {'code', 'message'}
            or error.get('code') not in {'invalid_capability', 'revoked'}
            or not isinstance(error.get('message'), str)):
        raise DemoError('revoked VM guest did not return a native identity denial')
    return error['code']


def revoked_without_dispatch(result, host: Path, *, token: bytes,
                             capability: str, before: int) -> str:
    """Require an identity denial *and* no new native provider dispatch."""
    code = require_revoked_identity_denial(result)
    if audit_dispatch_count(host, token=token, capability=capability) != before:
        raise DemoError('revoked VM guest produced an additional provider dispatch')
    return code


def run_live(workspace: Path, ssh: GuestSSH, bin_dir: Path, token_path: Path,
             token: bytes) -> dict:
    tools = binaries(bin_dir)
    host = workspace / 'host'
    host.mkdir(mode=0o700)
    guest = ''
    bridge = None
    tunnel = None
    # Native host custody reads the token for authenticated requests. The
    # operator harness also retains preflight bytes for leak checks only.
    offline.FAKE_TOKEN = token.decode('ascii')
    try:
        virt = ssh.required('systemd-detect-virt --vm', label='verify real VM').decode('ascii').strip()
        if virt not in {'kvm', 'qemu'}:
            raise DemoError('remote target did not report a KVM/QEMU VM')
        guest = ssh.guest_tmpdir()
        arch = ssh.required('uname -m', label='verify VM architecture').decode('ascii').strip()
        if arch != os.uname().machine:
            raise DemoError('host/guest architecture mismatch; cross-build native client first')
        ssh.publish(f'{guest}/garrett-client', tools['client'].read_bytes(), executable=True)
        csr_response = ssh.required('exec ' + shlex.join([
            f'{guest}/garrett-client', 'request', '--key-mode', 'software',
            '--key', f'{guest}/client.key', '--csr', f'{guest}/client.csr',
        ]), label='generate private client key and public CSR inside VM', timeout=75)
        try:
            csr_result = json.loads(csr_response)
        except (ValueError, UnicodeError):
            raise DemoError('guest CSR metadata is not JSON') from None
        csr = ssh.required('cat ' + shlex.quote(f'{guest}/client.csr'),
                           label='retrieve public CSR')
        fingerprint = inspect_csr(csr)
        if csr_result.get('key_fingerprint') != fingerprint:
            raise DemoError('guest CSR fingerprint changed')
        authority_action(tools['authority'], host, 'init',
                         issuer='aivm.test', audience='aivm-secrets.remote')
        authority_action(tools['authority'], host, 'enroll', subject='live-guest',
                         csr_file=str(write(host / 'guest.csr', csr)),
                         approve_fingerprint=fingerprint)
        public = authority_action(tools['authority'], host, 'public-client', subject='live-guest')
        ssh.publish(f'{guest}/ca.pem', base64.b64decode(public['ca_pem_b64']))
        ssh.publish(f'{guest}/client.pem', base64.b64decode(public['certificate_pem_b64']))
        _expect_path_not_readable(ssh, token_path, label='live GitHub token')
        _expect_path_not_readable(ssh, host / 'authority', label='host authority')

        ca_path = copy_trust_bundle(host)
        address = resolved_github_address()
        manifest = live_policy(token_path, ca_path, address)
        releases = live_disclosure()
        validate_disclosure_coverage(manifest, releases)
        write(host / 'policy.json', manifest)
        write(host / 'disclosure.json', releases)
        write(host / 'bridge.json', live_bridge_config(host, token_path, ca_path, address, ssh.vm))
        bridge, ready = start_bridge(tools['bridge'], host)
        capability = ready['capability']
        ssh.publish(f'{guest}/capability.jwt', capability.encode('utf-8'))
        ssh.publish(f'{guest}/client.json', json.dumps({
            'schema': 1, 'key_mode': 'software', 'socket': f'{guest}/broker.sock',
            'server_name': 'localhost', 'certificate': f'{guest}/client.pem',
            'private_key': f'{guest}/client.key', 'server_ca': f'{guest}/ca.pem',
        }).encode('utf-8'))
        _expect_path_not_readable(ssh, host / 'identity.sock', label='privileged broker socket')
        tunnel = ssh.forward(remote_socket=f'{guest}/broker.sock', host_socket=host / 'identity.sock')
        _wait_for_forward(ssh, tunnel, f'{guest}/broker.sock')

        # Auth-required /user call demonstrates *actual* bearer authentication,
        # which a public /repos GET cannot independently establish.
        identity = successful_projection(live_guest_invoke(ssh, guest, 'account.probe'),
            label='GitHub authenticated /user', expected_keys={'authenticatedUserId'})
        if not isinstance(identity['authenticatedUserId'], int) or identity['authenticatedUserId'] <= 0:
            raise DemoError('GitHub authenticated user id is not a positive integer')
        repo_args = {'owner': TARGET_OWNER, 'repo': TARGET_REPO}
        selected = successful_projection(live_guest_invoke(ssh, guest, 'repo.view', repo_args),
            label='GitHub repository metadata', expected_keys={'fullName', 'defaultBranch', 'private'})
        if (selected['fullName'].casefold() != TARGET_FULL_NAME.casefold()
                or selected['private'] is not False
                or not isinstance(selected['defaultBranch'], str) or not selected['defaultBranch']):
            raise DemoError('GitHub selected repository metadata did not match the exact target')
        readme = successful_projection(live_guest_invoke(ssh, guest, 'repo.readme', repo_args),
            label='GitHub README read', expected_keys={'path', 'sha', 'size'})
        if (readme['path'] != 'README.md' or not isinstance(readme['size'], int)
                or readme['size'] <= 0 or not isinstance(readme['sha'], str)
                or SHA40.fullmatch(readme['sha']) is None):
            raise DemoError('GitHub README metadata was malformed or unexpected')
        sent = audit_dispatch_count(host, token=token, capability=capability)
        if sent < 3:
            raise DemoError('host audit did not observe all three approved live reads')
        rejected_without_dispatch(ssh, guest, host, token, capability, 'repo.view',
            {'owner': TARGET_OWNER, 'repo': 'aivm'}, sent,
            label='out-of-scope repository')
        rejected_without_dispatch(ssh, guest, host, token, capability, 'repo.issue',
            {**repo_args, 'title': 'UNAUTHORIZED NEVER CREATE'}, sent,
            label='explicitly denied GitHub issue creation')
        before_revoke = authority_action(tools['authority'], host, 'status')
        revoked_state = authority_action(tools['authority'], host, 'revoke', subject='live-guest')
        after_revoke = authority_action(tools['authority'], host, 'status')
        verify_revocation_state(before_revoke, revoked_state, after_revoke)
        revoked = live_guest_invoke(ssh, guest, 'account.probe')
        # `invoke` writes a public JSON error frame to stdout on denial.
        # A nonzero exit and a *native identity denial* are required; merely
        # checking stdout emptiness produced a false positive in the first
        # real-GitHub run. Still require no new provider dispatch below.
        revocation_denial_code = revoked_without_dispatch(
            revoked, host, token=token, capability=capability, before=sent)
        return {
            'ok': True,
            'mode': 'native-rust/aivm-kvm/live-github-readonly',
            'vm': ssh.vm, 'virtualization': virt,
            'provider': GITHUB_HOST, 'repository': TARGET_FULL_NAME,
            'api_version': GITHUB_API_VERSION, 'endpoint_pin': address,
            'authenticated_user_probe': True,
            'approved_repository': selected,
            'approved_readme': readme,
            'unauthorized_repository_denied': True,
            'write_denied': True, 'revocation_fenced': True,
            'revocation_denial_code': revocation_denial_code,
            'host_private_paths_unreadable_in_guest': True,
            'approved_read_count': 3,
            'provider_requests_directly_observed': False,
            'whole_service_secrecy_proved': False,
        }
    finally:
        try:
            if tunnel is not None:
                _stop_forward(tunnel)
        finally:
            try:
                if bridge is not None:
                    stop_bridge(bridge)
            finally:
                if guest:
                    ssh.remove_tmpdir(guest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-github', action='store_true',
                        help='required explicit opt-in for real GitHub traffic')
    parser.add_argument('--vm', default='aivm-2404')
    parser.add_argument('--token-file', type=Path, default=DEFAULT_TOKEN_FILE)
    parser.add_argument('--workspace', type=Path,
                        help='fresh host-private evidence directory; omit to auto-clean')
    parser.add_argument('--bin-dir', type=Path, default=REPO_ROOT / 'rust/target/debug')
    args = parser.parse_args(argv)
    if not args.live_github:
        parser.error('live GitHub network access requires --live-github')
    try:
        vm = validate_vm_name(args.vm)
        token_path, token = check_token_file(args.token_file)
        binaries(args.bin_dir.absolute())
        if args.workspace is None:
            with tempfile.TemporaryDirectory(prefix='garrett-github-live-', dir='/tmp') as temporary:
                workspace = Path(temporary)
                config = ssh_configuration(workspace, vm)
                report = run_live(workspace, GuestSSH(vm, config), args.bin_dir.absolute(),
                                  token_path, token)
        else:
            workspace = args.workspace.absolute()
            workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
            config = ssh_configuration(workspace, vm)
            report = run_live(workspace, GuestSSH(vm, config), args.bin_dir.absolute(),
                              token_path, token)
            write(workspace / 'summary.json', report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (DemoError, OSError, ValueError, UnicodeError) as ex:
        # Never print native stderr, raw provider responses, or token contents.
        print(f'live GitHub acceptance failed: {type(ex).__name__}: {ex}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
