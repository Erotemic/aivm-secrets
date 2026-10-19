"""Native CSR creation and enrollment with a provisioned isolated TPM key."""

import hashlib
import os
import select
import subprocess

import pytest

from aivm_secrets.identity.certificates import inspect_csr
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import (
    AuthorityCase,
    AuthorityProviderCase,
    private,
)
from tests.test_rust_garrett_certificates import creation_evidence
from tests.test_rust_garrett_provider import provider_directory
from tests.test_rust_garrett_tpm import SoftwareTPM, require_software_tpm_tools


@pytest.fixture
def provisioned(tmp_path):
    require_software_tpm_tools()
    state, work = tmp_path / "tpm", tmp_path / "work"
    state.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    with SoftwareTPM(state) as tpm:
        config = dict(
            schema=1,
            tcti=tpm.tcti,
            persistent_handle=0x81010011,
            authorization_file=str(state / "auth"),
            public_area_file=str(state / "public.tpmt"),
            work_directory=str(work),
        )
        yield tpm, config


def request(root, config, *, error=None):
    binary = executable("AIVM_SECRETS_RUST_GARRETT_CLIENT")
    path = private(root / "tpm-request.json", config)
    csr = root / "client.csr"
    done = subprocess.run(
        [
            binary,
            "request",
            "--key-mode",
            "tpm2",
            "--tpm-config",
            str(path),
            "--csr",
            str(csr),
        ],
        capture_output=True,
        timeout=20,
    )
    assert b"PRIVATE KEY" not in done.stdout + done.stderr
    if error:
        assert done.returncode == 1 and not done.stdout, done
        assert done.stderr == error.encode() + b"\n", done
        return None
    assert done.returncode == 0 and not done.stderr, done
    result = codec.loads(done.stdout)
    assert result == dict(
        key_fingerprint=inspect_csr(csr.read_bytes()),
        csr=str(csr),
        security="TPM2 signing key; provenance must be independently enrolled",
    )
    assert not (root / "client.key").exists()
    assert not list((root / "work").glob("sign-*"))
    assert csr.stat().st_mode & 0o777 == 0o600
    return result


def test_native_tpm_request_uses_the_pinned_public_key(tmp_path, provisioned):
    tpm, config = provisioned
    result = request(tmp_path, config)
    assert (
        result["key_fingerprint"]
        == hashlib.sha256((tpm.directory / "public.der").read_bytes()).hexdigest()
    )
    saved = (tmp_path / "client.csr").read_bytes()
    request(tmp_path, config, error="unsafe_file")
    assert saved == (tmp_path / "client.csr").read_bytes()


@pytest.mark.parametrize(
    "fault", ["authorization", "attributes", "key", "software_field"]
)
def test_failed_tpm_request_never_publishes_or_falls_back(tmp_path, provisioned, fault):
    tpm, config = provisioned
    if fault == "authorization":
        config["authorization_file"] = str(
            private(tmp_path / "wrong-auth", os.urandom(32))
        )
    elif fault in ("attributes", "key"):
        area = bytearray((tpm.directory / "public.tpmt").read_bytes())
        area[4 if fault == "attributes" else 22] ^= 1
        config["public_area_file"] = str(
            private(tmp_path / "wrong-public", bytes(area))
        )
    else:
        config["private_key"] = "never-a-fallback"
    request(tmp_path, config, error="invalid_capability")
    assert not (tmp_path / "client.csr").exists()
    assert not (tmp_path / "client.key").exists()


def enroll_tpm(authority, tpm, csr):
    state = tpm.directory
    creation_evidence(tpm)
    for name in ["ak.tpmt", "ak.qname"]:
        (state / name).chmod(0o600)
    command = authority.command(
        "enroll-tpm",
        dict(
            subject="vm-test",
            csr_file=str(csr),
            ak_public_area_file=str(state / "ak.tpmt"),
            ak_qualified_name_file=str(state / "ak.qname"),
        ),
    )
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        ready, _, _ = select.select([process.stdout], [], [], 10)
        assert ready
        challenge = codec.loads(process.stdout.readline())
        assert challenge["ok"]
        tpm.tool(
            "certifycreation",
            "-C",
            "0x81010012",
            "-c",
            "0x81010011",
            "-d",
            state / "creation.hash",
            "-t",
            state / "creation.ticket",
            "-g",
            "sha256",
            "-s",
            "ecdsa",
            "-f",
            "plain",
            "-q",
            challenge["challenge_hex"],
            "-o",
            state / "fresh.sig",
            "--attestation",
            state / "fresh.attestation",
        )
        frame = dict(
            version=1,
            public_area_hex=(state / "public.tpmt").read_bytes().hex(),
            attestation_hex=(state / "fresh.attestation").read_bytes().hex(),
            signature_hex=(state / "fresh.sig").read_bytes().hex(),
        )
        out, err = process.communicate(codec.dumps(frame) + b"\n", timeout=15)
        assert process.returncode == 0 and not err, (out, err)
        return codec.loads(out)["result"]
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def test_native_tpm_request_enrollment_and_provider_use_without_key_export(
    tmp_path, provisioned
):
    tpm, config = provisioned
    result = request(tmp_path, config)
    authority = AuthorityCase(tmp_path)
    enrolled = enroll_tpm(authority, tpm, tmp_path / "client.csr")
    assert enrolled["assurance"]["mode"] == "attested-tpm"
    assert result["key_fingerprint"] == enrolled["assurance"]["spki_sha256"]
    certs = authority.certs(enrollment=enrolled)
    with TLSService(provider_directory(tmp_path)) as provider:
        provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
        with AuthorityProviderCase(
            tmp_path, provider, authority, certs=certs, assurance="attested-tpm"
        ) as session:
            reply = session.invoke(key_configuration=dict(key_mode="tpm2", **config))
            assert reply["result"] == dict(id=42, active=True)
