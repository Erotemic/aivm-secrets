"""Native key/CSR publication, recovery and independent Python interoperability."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from aivm_secrets.identity.certificates import create_csr, inspect_csr
from aivm_secrets.primitives import codec
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
from tests.secrets_helpers import TLSService
from tests.test_rust_garrett_provider import provider_directory


def call(
    action, key=None, csr=None, *, limit=None, mode="software", extra=(), error=None
):
    command = [executable("AIVM_SECRETS_RUST_GARRETT_CLIENT"), action]
    if action != "inspect-csr":
        command += ["--key-mode", mode, "--key", str(key)]
    command += ["--csr", str(csr), *extra]
    if limit is not None:
        command = [
            sys.executable,
            str(Path(__file__).with_name("limited_exec.py")),
            str(limit),
            *command,
        ]
    done = subprocess.run(command, capture_output=True, timeout=15)
    assert b"PRIVATE KEY" not in done.stdout + done.stderr
    assert b"BEGIN CERTIFICATE REQUEST" not in done.stdout + done.stderr
    if error is not None:
        assert done.returncode == 1 and not done.stdout, done
        assert done.stderr == error.encode() + b"\n"
        return None
    assert done.returncode == 0 and not done.stderr, done
    return codec.loads(done.stdout)


def check_pair(key, csr, response):
    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    assert isinstance(private, ec.EllipticCurvePrivateKey)
    assert isinstance(private.curve, ec.SECP256R1)
    spki = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected = hashlib.sha256(spki).hexdigest()
    assert response == dict(
        key_fingerprint=expected,
        key=str(key),
        csr=str(csr),
        security="exportable software key; no VM attestation",
    )
    assert inspect_csr(csr.read_bytes()) == expected
    assert call("inspect-csr", csr=csr) == dict(key_fingerprint=expected)
    assert key.stat().st_mode & 0o777 == csr.stat().st_mode & 0o777 == 0o600
    return private


def test_native_software_request_is_python_compatible_and_not_replaced(tmp_path):
    key, csr = tmp_path / "client.key", tmp_path / "client.csr"
    response = call("request", key, csr)
    check_pair(key, csr, response)
    saved = key.read_bytes(), csr.read_bytes()
    call("request", key, csr, error="unsafe_file")
    assert saved == (key.read_bytes(), csr.read_bytes())


def test_python_software_key_can_generate_a_native_recovery_request(tmp_path):
    key, old, new = (
        tmp_path / "python.key",
        tmp_path / "python.csr",
        tmp_path / "new.csr",
    )
    expected = create_csr(private_key=key, request_file=old)
    saved = key.read_bytes()
    response = call("csr-from-key", key, new)
    assert response["key_fingerprint"] == expected
    assert saved == key.read_bytes()
    check_pair(key, new, response)


@pytest.mark.parametrize("target", ["key", "csr"])
@pytest.mark.parametrize("kind", ["regular", "symlink", "fifo", "hardlink"])
def test_existing_targets_are_refused_before_any_key_publication(
    tmp_path, target, kind
):
    key, csr = tmp_path / "client.key", tmp_path / "client.csr"
    path = key if target == "key" else csr
    other = tmp_path / "sentinel"
    other.write_bytes(b"keep existing material")
    other.chmod(0o600)
    if kind == "regular":
        path.write_bytes(b"existing")
    elif kind == "symlink":
        path.symlink_to(other)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        os.link(other, path)
    call("request", key, csr, error="unsafe_file")
    assert other.read_bytes() == b"keep existing material"
    assert not (csr if target == "key" else key).exists()
    assert not list(tmp_path.glob(".issued-*"))


def test_same_target_and_symlinked_parent_are_refused(tmp_path):
    key = tmp_path / "client.key"
    call("request", key, key, error="unsafe_file")
    assert not key.exists()
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    call("request", key, alias / "client.csr", error="unsafe_file")
    assert not key.exists()


@pytest.mark.parametrize(
    "mode,extra",
    [
        ("tpm2", ()),
        ("software", ("--key-mode", "software")),
        ("software", ("--unexpected", "x")),
    ],
)
def test_wrong_or_ambiguous_mode_never_generates_a_software_fallback(
    tmp_path, mode, extra
):
    key, csr = tmp_path / "client.key", tmp_path / "client.csr"
    call("request", key, csr, mode=mode, extra=extra, error="invalid_request")
    assert not key.exists() and not csr.exists()


def test_failed_key_write_never_publishes_csr(tmp_path):
    key, csr = tmp_path / "client.key", tmp_path / "client.csr"
    call("request", key, csr, limit=0, error="unsafe_file")
    assert not key.exists() and not csr.exists()


def test_csr_failure_keeps_the_key_and_has_an_explicit_recovery_path(tmp_path):
    key, csr = tmp_path / "client.key", tmp_path / "client.csr"
    call("request", key, csr, limit=300, error="outcome_unknown")
    assert key.exists() and not csr.exists()
    saved = key.read_bytes()
    call("request", key, csr, error="unsafe_file")
    response = call("csr-from-key", key, csr)
    assert saved == key.read_bytes()
    check_pair(key, csr, response)


def test_native_material_enrolls_and_performs_an_entire_native_provider_call(tmp_path):
    key, csr = tmp_path / "native.key", tmp_path / "native.csr"
    response = call("request", key, csr)
    authority = AuthorityCase(tmp_path)
    enrollment = authority.call(
        "enroll",
        subject="vm-test",
        csr_file=str(csr),
        approve_fingerprint=response["key_fingerprint"],
    )
    # Python only validates the generated material; the authority and protocol
    # operations exercised below are the normal Rust executables.
    check_pair(key, csr, response)
    certs = authority.certs(enrollment=enrollment)
    certs["client1"] = (certs["client1"][0], key, None)
    certs["client2"] = (certs["client2"][0], key, None)
    with TLSService(provider_directory(tmp_path)) as provider:
        provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
        with AuthorityProviderCase(
            tmp_path, provider, authority, certs=certs
        ) as session:
            assert session.invoke()["result"] == dict(id=42, active=True)


def test_recovery_rejects_exposed_or_wrong_algorithm_keys(tmp_path):
    key, csr = tmp_path / "client.key", tmp_path / "client.csr"
    old = tmp_path / "old.csr"
    create_csr(private_key=key, request_file=old)
    key.chmod(0o644)
    call("csr-from-key", key, csr, error="unsafe_file")
    assert not csr.exists()
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.generate()
    key.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key.chmod(0o600)
    call("csr-from-key", key, csr, error="invalid_capability")
    assert not csr.exists()


def test_concurrent_requests_never_replace_the_winning_identity(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    key, csr = tmp_path / "client.key", tmp_path / "client.csr"
    command = [
        executable("AIVM_SECRETS_RUST_GARRETT_CLIENT"),
        "request",
        "--key-mode",
        "software",
        "--key",
        str(key),
        "--csr",
        str(csr),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        done = list(
            pool.map(
                lambda _: subprocess.run(command, capture_output=True, timeout=15),
                range(2),
            )
        )
    assert sorted(item.returncode for item in done) == [0, 1]
    winner = next(item for item in done if item.returncode == 0)
    loser = next(item for item in done if item.returncode == 1)
    assert not loser.stdout and loser.stderr in [b"unsafe_file\n", b"outcome_unknown\n"]
    check_pair(key, csr, codec.loads(winner.stdout))
    assert all(
        path.stat().st_mode & 0o777 == 0o600 for path in tmp_path.glob(".issued-*")
    )
