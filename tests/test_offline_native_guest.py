"""Portable checks for the runnable offline Garrett operator/guest workflow.

The required Rust acceptance is the CLI itself; these tests never substitute
fake broker outcomes for a real native integration run.
"""
from __future__ import annotations

import base64
import json
import socket
import ssl

import pytest

from dev.offline_native_guest import (
    FAKE_TOKEN, HOSTNAME, PULL_PATH, DemoError, LocalProvider, binaries,
    bridge_config, disclosure, distribute_guest_certificates, guest_config,
    mkdir, native_error_code, policy, start_bridge, validate_disclosure_coverage,
    validate_sent, write,
)
from aivm_secrets.kernel.presets import GITHUB_JSON
from aivm_secrets.kernel.service import parse_policy


def test_policy_is_a_real_github_preset_pinned_to_local_provider(tmp_path):
    host = mkdir(tmp_path / 'host')
    mkdir(host / 'provider')
    with LocalProvider(host / 'provider') as server:
        p = policy(host, server)
        parsed = parse_policy(p)
        assert {o.name for o in parsed.operations} == {
            'pr.view', 'pr.diff', 'pr.checks', 'pr.comment',
        }
        assert next(o for o in parsed.operations if o.name == 'pr.comment').write
        assert p['egress'] == {
            'address': '127.0.0.1', 'port': server.port,
            'ca_file': str(server.files['ca']),
        }
        assert p['credential_source']['path'] == str(host / 'credential')
        assert p['host'] == HOSTNAME
        # The production Rust broker opens this through files::read_private.
        assert server.files['ca'].stat().st_mode & 0o777 == 0o600
        assert 'cli' not in p  # native guest CLI, not Python alias interpreter
        provider_config = bridge_config(host, server)['provider']
        assert provider_config['writes'] == 'deny'
        assert provider_config['profile'] == 'manifest-https-v1'
        # The real native Session::start validates these exact policy-to-I/O
        # bindings before announcing readiness. The Python policy parser does
        # not validate the separately constructed native bridge configuration.
        assert provider_config['credential_file'] == p['credential_source']['path']
        assert provider_config['authentication'] == p['authentication']
        assert provider_config['host'] == p['host']
        assert provider_config['address'] == p['egress']['address']
        assert provider_config['port'] == p['egress']['port']
        assert provider_config['server_ca'] == p['egress']['ca_file']
        rules = disclosure()
        validate_disclosure_coverage(p, rules)
        assert set(rules) == {operation.name for operation in parsed.operations}
        assert rules['pr.comment'] == {'body': {'at': ['body'], 'type': 'text'}}
        assert all(item['at'] != ['private_diagnostic']
                   for item in rules['pr.view'].values())


def test_disclosure_coverage_rejects_missing_or_extra_operations(tmp_path):
    host = mkdir(tmp_path / 'host')
    mkdir(host / 'provider')
    with LocalProvider(host / 'provider') as server:
        manifest = policy(host, server)
        rules = disclosure()
        without_denied_write = {name: value for name, value in rules.items()
                                if name != 'pr.comment'}
        with pytest.raises(DemoError, match='operation set'):
            validate_disclosure_coverage(manifest, without_denied_write)
        with pytest.raises(DemoError, match='operation set'):
            validate_disclosure_coverage(manifest, dict(rules, extra={'value': {}}))


def test_provider_uses_real_tls_and_exposes_no_local_credentials_in_logs(tmp_path):
    mkdir(tmp_path / 'provider')
    with LocalProvider(tmp_path / 'provider') as server:
        context = ssl.create_default_context(cafile=str(server.files['ca']))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection(('127.0.0.1', server.port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=HOSTNAME) as tls:
                tls.sendall((
                    f'GET {PULL_PATH} HTTP/1.1\r\n'
                    f'Host: {HOSTNAME}:{server.port}\r\n'
                    f'Accept: {GITHUB_JSON}\r\n'
                    f'Authorization: Bearer {FAKE_TOKEN}\r\n'
                    'X-GitHub-Api-Version: 2026-03-10\r\n'
                    'Connection: close\r\n\r\n'
                ).encode())
                response = bytearray()
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
        header, body = bytes(response).split(b'\r\n\r\n', 1)
        assert b'200' in header
        assert json.loads(body)['number'] == 13861
        assert len(server.seen()) == 1
        with pytest.raises(DemoError):
            validate_sent(server, expected_count=0)
        receipt = validate_sent(server, expected_count=1)
        assert receipt[0]['credential_substituted'] is True
        assert FAKE_TOKEN not in json.dumps(receipt)


def test_guest_manifest_excludes_host_credentials_and_admin_paths(tmp_path):
    host, guest = mkdir(tmp_path / 'host'), mkdir(tmp_path / 'guest')
    mkdir(host / 'provider')
    with LocalProvider(host / 'provider') as server:
        config = guest_config(host, guest)
        assert 'credential' not in json.dumps(config)
        assert 'authority' not in json.dumps(config)
        assert 'provider' not in json.dumps(config)
        assert config['socket'] == str(host / 'identity.sock')
        assert config['private_key'] == str(guest / 'client.key')


def test_exclusive_private_files_and_workspace(tmp_path):
    host = mkdir(tmp_path / 'host')
    target = write(host / 'credential', FAKE_TOKEN)
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write(target, 'other')
    with pytest.raises(FileExistsError):
        mkdir(host)


def test_missing_native_binaries_fails_closed(tmp_path):
    with pytest.raises(DemoError, match='missing native authority binary'):
        binaries(tmp_path)


def test_guest_certificates_are_private_for_native_client(tmp_path):
    guest = mkdir(tmp_path / 'guest')
    distribute_guest_certificates(guest, {
        'ca_pem_b64': base64.b64encode(b'public synthetic ca').decode(),
        'certificate_pem_b64': base64.b64encode(b'public synthetic leaf').decode(),
    })
    assert (guest / 'ca.pem').read_bytes() == b'public synthetic ca'
    assert (guest / 'client.pem').read_bytes() == b'public synthetic leaf'
    assert all(path.stat().st_mode & 0o777 == 0o600
               for path in (guest / 'ca.pem', guest / 'client.pem'))


def _fake_bridge(directory, body):
    return write(directory / 'fake-bridge', '#!/bin/sh\n' + body, mode=0o700)


def test_broker_startup_reports_native_exit_not_invalid_json(tmp_path):
    # Mirrors the observed original failure: Rust emits no readiness bytes and
    # writes a fixed public error code to stderr, so parsing b'' is incorrect.
    native = _fake_bridge(tmp_path, 'printf unsafe_file >&2\nexit 1\n')
    with pytest.raises(DemoError, match=r'status=1; native error=unsafe_file'):
        start_bridge(native, tmp_path)


def test_broker_startup_does_not_reflect_arbitrary_native_stderr(tmp_path):
    native = _fake_bridge(tmp_path, 'printf "secret path /tmp/private" >&2\nexit 1\n')
    with pytest.raises(DemoError) as caught:
        start_bridge(native, tmp_path)
    assert 'status=1' in str(caught.value)
    assert '/tmp/private' not in str(caught.value)


def test_broker_startup_non_json_is_a_public_demo_error(tmp_path):
    native = _fake_bridge(tmp_path, 'printf "NOT JSON\\n"\nexit 1\n')
    with pytest.raises(DemoError, match='invalid readiness JSON'):
        start_bridge(native, tmp_path)


def test_only_plain_native_error_codes_are_reported():
    assert native_error_code(b'unsafe_file\n') == 'unsafe_file'
    assert native_error_code(b'credential_source\n') == 'credential_source'
    assert native_error_code(b'user password=secret\n') is None
    assert native_error_code(b'private/path\n') is None
