"""Normal Rust authority operations, durable failures and live authorization.

Python is an independent store/crypto oracle and a synthetic HTTPS provider;
the authority, mTLS client and credential broker are native executables.
"""

from __future__ import annotations

import base64
import fcntl
import os
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from aivm_secrets.host.audit import verify
from aivm_secrets.identity.certificates import inspect_csr
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_certificates import request
from tests.test_rust_garrett_provider import ProviderCase, provider_directory


def private(path, data):
    path = Path(path)
    path.write_bytes(data if isinstance(data, bytes) else codec.dumps(data))
    path.chmod(0o600)
    return path


class AuthorityCase:
    def __init__(self, directory, *, initialize=True):
        self.directory = Path(directory)
        self.root = self.directory / "authority"
        self.binary = executable("AIVM_SECRETS_RUST_AUTHORITY_ADMIN")
        if initialize:
            self.call("init", issuer="aivm.test", audience="aivm-secrets.remote")

    def command(self, action, fields):
        # Unique requests also let concurrent operations exercise the real lock.
        handle, name = tempfile.mkstemp(dir=self.directory, prefix="admin-")
        with os.fdopen(handle, "wb") as stream:
            stream.write(codec.dumps(fields))
        return [self.binary, action, "--root", str(self.root), "--request", name]

    def call(self, action, *, error=None, limit=None, **fields):
        command = self.command(action, fields)
        if limit is not None:
            command = [
                sys.executable,
                str(Path(__file__).with_name("limited_exec.py")),
                str(limit),
                *command,
            ]
        result = subprocess.run(command, capture_output=True, timeout=20)
        assert result.returncode in (0, 1), result.stderr
        response = codec.loads(result.stdout)
        assert response["version"] == 1
        if error is None:
            assert result.returncode == 0 and response["ok"], response
            return response["result"]
        assert response == dict(version=1, ok=False, error=dict(code=error))
        assert result.returncode == 1
        return response

    def enroll(self, *, subject="vm-test", key=None, **options):
        key, csr = request(key)
        path = private(self.directory / (subject + ".csr"), csr.encode())
        result = self.call(
            "enroll",
            subject=subject,
            csr_file=str(path),
            approve_fingerprint=inspect_csr(csr.encode()),
            **options,
        )
        return key, csr, result

    def certs(self, *, key=None, enrollment=None):
        if enrollment is None:
            key, _, enrollment = self.enroll()
        public = self.call("public-client", subject="vm-test")
        ca = private(self.directory / "ca.pem", base64.b64decode(public["ca_pem_b64"]))
        cert = private(
            self.directory / "client.pem",
            base64.b64decode(public["certificate_pem_b64"]),
        )
        if key is not None:
            key = private(
                self.directory / "client.key",
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
        return dict(ca=ca, client1=(cert, key, None), client2=(cert, key, None))


class AuthorityProviderCase(ProviderCase):
    """Use ProviderCase's client driver with the normal authority-root backend."""

    def __init__(
        self,
        directory,
        provider,
        authority,
        *,
        assurance="any-enrolled",
        certs=None,
        lifetime=300,
        **changes,
    ):
        super().__init__(directory, provider)
        self.authority = authority
        self.assurance = assurance
        self.authority_certs = certs
        self.provider_changes = changes
        self.lifetime = lifetime

    def __enter__(self):
        self.bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
        self.client = executable("AIVM_SECRETS_RUST_GARRETT_CLIENT")
        p = self.directory
        self.certs = self.authority_certs or self.authority.certs()
        for path in self.provider.files.values():
            path.chmod(0o600)
        credential = private(p / "credential", TOKEN.encode())
        provider = dict(
            profile="account-status-v1",
            host=self.provider.host,
            address="127.0.0.1",
            port=self.provider.port,
            authentication="bearer",
            server_ca=str(self.provider.files["ca"]),
            credential_file=str(credential),
            audit_file=str(p / "provider-audit.jsonl"),
        )
        provider.update(self.provider_changes)
        config = dict(
            schema=1,
            authority_root=str(self.authority.root),
            client_assurance=self.assurance,
            subject="vm-test",
            listen=str(p / "identity.sock"),
            lifetime=self.lifetime,
            binding=dict(
                owner_uid=os.getuid(),
                access_identity="principal-test",
                vm="vm-test",
                channel="b" * 32,
            ),
            provider=provider,
        )
        path = private(p / "bridge.json", config)
        self.process = subprocess.Popen(
            [self.bridge, "--config", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            ready, _, _ = select.select([self.process.stdout], [], [], 10)
            assert ready, "native authority bridge did not become ready"
            line = self.process.stdout.readline()
            assert line, self.process.stderr.read()
            announcement = codec.loads(line)
            assert (
                announcement["ready"] and announcement["profile"] == "account-status-v1"
            )
            assert TOKEN.encode() not in line
            self.token = announcement["capability"]
            self.expires_at = announcement["expires_at"]
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise


def test_native_authority_python_store_and_key_interoperability(tmp_path):
    case = AuthorityCase(tmp_path)
    reference = IdentityAuthority(case.root)
    assert reference.status() == case.call("status")
    issuer = serialization.load_pem_private_key(
        (case.root / "issuer-keys/local-1.key").read_bytes(), None
    )
    public = serialization.load_pem_public_key(
        (case.root / "issuer-keys/local-1.pub").read_bytes()
    )
    assert issuer.public_key().public_bytes_raw() == public.public_bytes_raw()
    key, csr, enrolled = case.enroll()
    native_public = case.call("public-client", subject="vm-test")
    assurance = native_public.pop("assurance")
    assert assurance == enrolled["assurance"]
    assert assurance["mode"] == "operator-approved-software"
    assert native_public == reference.public_client("vm-test")
    assert reference.status() == case.call("status")
    for audit in (case.root / "audit").iterdir():
        assert verify(audit)[0] == 2
    # The Python authority can sign using the native CA, and Rust validates
    # its leaf and registry without inventing a TPM receipt for legacy writes.
    _, other = request()
    reference.enroll(
        subject="python-client",
        csr=other.encode(),
        approve_fingerprint=inspect_csr(other.encode()),
    )
    native = case.call("public-client", subject="python-client")
    assert native.pop("assurance") is None
    assert native == reference.public_client("python-client")
    before = case.call("status")
    case.call(
        "init", issuer="aivm.test", audience="aivm-secrets.remote", error="unsafe_file"
    )
    assert before == case.call("status")


def test_python_authority_native_enrollment_renewal_cas_and_revoke(tmp_path):
    case = AuthorityCase(tmp_path, initialize=False)
    reference = IdentityAuthority.initialize(
        case.root, issuer="aivm.test", audience="aivm-secrets.remote"
    )
    key, csr, first = case.enroll()
    assert reference.status() == case.call("status")
    fields = dict(
        subject="vm-test",
        csr_file=str(tmp_path / "vm-test.csr"),
        approve_fingerprint=inspect_csr(csr.encode()),
        expected_epoch=first["epoch"],
        expected_thumbprint=first["certificate_sha256"],
    )
    renewed = case.call("renew", **fields)
    assert renewed["epoch"] == first["epoch"] + 1
    case.call("renew", **fields, error="revoked")
    assert reference.status() == case.call("status")
    assert not case.call(
        "revoke-if-current",
        subject="vm-test",
        expected_epoch=first["epoch"],
        expected_thumbprint=first["certificate_sha256"],
    )["revoked"]
    case.call(
        "revoke-if-current",
        subject="vm-test",
        expected_epoch=renewed["epoch"],
        expected_thumbprint=renewed["certificate_sha256"],
    )
    assert not reference.status()["subjects"]["vm-test"]["active"]
    case.call("public-client", subject="vm-test", error="revoked")
    for audit in (case.root / "audit").iterdir():
        assert verify(audit)[0] == 2


@pytest.mark.parametrize(
    "attack",
    [
        "symlink-root",
        "symlink-registry",
        "hardlink-registry",
        "fifo-registry",
        "public-root",
        "relative-root",
    ],
)
def test_authority_refuses_unsafe_files_and_paths(tmp_path, attack):
    case = AuthorityCase(tmp_path)
    path = case.root / "enrollments.json"
    if attack == "symlink-root":
        link = tmp_path / "alias"
        link.symlink_to(case.root, target_is_directory=True)
        case.root = link
    elif attack in ("symlink-registry", "hardlink-registry", "fifo-registry"):
        saved = case.root / "saved"
        path.rename(saved)
        if attack == "symlink-registry":
            path.symlink_to(saved)
        elif attack == "hardlink-registry":
            os.link(saved, path)
        else:
            os.mkfifo(path, 0o600)
    elif attack == "public-root":
        case.root.chmod(0o755)
    else:
        case.root = Path(os.path.relpath(case.root))
    case.call("status", error="unsafe_file")


@pytest.mark.parametrize("phase", ["intent", "stage"])
def test_staging_failure_never_publishes_enrollment(tmp_path, phase):
    case = AuthorityCase(tmp_path)
    key, csr = request()
    csr_path = private(tmp_path / "request.csr", csr.encode())
    before = (case.root / "enrollments.json").read_bytes()
    if phase == "stage":
        (case.root / "clients").rename(case.root / "saved-clients")
        (case.root / "clients").symlink_to(
            case.root / "saved-clients", target_is_directory=True
        )
    case.call(
        "enroll",
        subject="vm-test",
        csr_file=str(csr_path),
        approve_fingerprint=inspect_csr(csr.encode()),
        limit=600 if phase == "intent" else None,
        error="internal_error",
    )
    assert (case.root / "enrollments.json").read_bytes() == before
    audits = list((case.root / "audit").iterdir())
    assert len(audits) == 1
    if phase == "intent":
        assert not audits[0].read_bytes().endswith(b"\n")
        return
    records = audits[0].read_bytes().splitlines()
    assert len(records) == 1
    assert codec.loads(records[0])["event"] == "identity_enroll_intent"
    assert verify(audits[0])[0] == 1
    (case.root / "clients").unlink()
    (case.root / "saved-clients").rename(case.root / "clients")
    # Preserved failed-stage coordinates do not reset the store or forbid a
    # deliberate later enrollment with fresh material names.
    case.enroll()
    assert case.call("status")["subjects"]["vm-test"]["active"]


def test_completion_failure_preserves_revocation_and_reports_uncertainty(tmp_path):
    case = AuthorityCase(tmp_path)
    case.enroll()
    probe = tmp_path / "probe"
    shutil.copytree(case.root, probe)
    case.root = probe
    existing = set((probe / "audit").iterdir())
    case.call("revoke", subject="vm-test")
    audit = next(iter(set((probe / "audit").iterdir()) - existing))
    intent, complete = audit.read_bytes().splitlines(keepends=True)
    # Derive a limit between the two writes from an equivalent disposable
    # operation. This avoids depending on timestamp or intent-format widths.
    limit = len(intent) + len(complete) // 2
    case.root = tmp_path / "authority"
    case.call("revoke", subject="vm-test", limit=limit, error="outcome_unknown")
    assert not case.call("status")["subjects"]["vm-test"]["active"]
    case.call("public-client", subject="vm-test", error="revoked")


def test_concurrent_initialize_publishes_exactly_one_authority(tmp_path):
    case = AuthorityCase(tmp_path, initialize=False)
    commands = [
        case.command("init", dict(issuer="aivm.test", audience="aivm-secrets.remote"))
        for _ in range(2)
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda cmd: subprocess.run(cmd, capture_output=True, timeout=20),
                commands,
            )
        )
    assert sorted(result.returncode for result in results) == [0, 1]
    assert IdentityAuthority(case.root).status() == case.call("status")
    winner = next(codec.loads(r.stdout)["result"] for r in results if r.returncode == 0)
    assert winner == case.call("status")


def test_native_authority_provider_action_and_live_revocation():
    with tempfile.TemporaryDirectory(prefix="agadmin-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(
                id=42, active=True, private=TOKEN
            )
            with AuthorityProviderCase(p, provider, authority) as case:
                assert case.invoke() == dict(
                    version=1, ok=True, result=dict(id=42, active=True)
                )
                assert (
                    provider.requests[-1]["headers"]["authorization"]
                    == "Bearer " + TOKEN
                )
                authority.call("revoke", subject="vm-test")
                calls = len(provider.requests)
                assert not case.invoke()["ok"]
                assert len(provider.requests) == calls


def test_live_issuer_retirement_and_ca_cutover_fence_old_bridge():
    with tempfile.TemporaryDirectory(prefix="agadmin-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        reference = IdentityAuthority(authority.root)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
            with AuthorityProviderCase(p, provider, authority) as case:
                assert case.invoke()["ok"]
                reference.rotate_issuer()
                assert case.invoke()["ok"]  # previous enabled kid remains usable
                reference.retire_issuer("local-1")
                calls = len(provider.requests)
                assert not case.invoke()["ok"]
                assert len(provider.requests) == calls

            # A freshly started bridge uses the new signer; a root cutover
            # invalidates its cached TLS context before another provider use.
            restart = p / "restart"
            restart.mkdir(mode=0o700)
            with AuthorityProviderCase(
                restart, provider, authority, certs=case.certs
            ) as restarted:
                assert restarted.invoke()["ok"]
                reference.rotate_ca(expected_ca_sha256=reference.ca_sha256)
                calls = len(provider.requests)
                assert not restarted.invoke()["ok"]
                assert len(provider.requests) == calls


def test_authority_revoke_drains_already_admitted_provider_use():
    with tempfile.TemporaryDirectory(prefix="agadmin-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        entered, release = threading.Event(), threading.Event()
        with TLSService(provider_directory(p)) as provider:

            def blocked(_request):
                entered.set()
                assert release.wait(8), "provider was not released"
                return 200, {}, codec.dumps(dict(id=42, active=True))

            provider.routes[("GET", "/v1/account")] = blocked
            with AuthorityProviderCase(p, provider, authority) as case:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    in_flight = pool.submit(case.invoke)
                    try:
                        assert entered.wait(5)
                        revoking = subprocess.Popen(
                            authority.command("revoke", dict(subject="vm-test")),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        with pytest.raises(subprocess.TimeoutExpired):
                            revoking.communicate(timeout=0.2)
                    finally:
                        release.set()
                    assert in_flight.result(timeout=5)["ok"]
                    out, err = revoking.communicate(timeout=5)
                    assert revoking.returncode == 0 and codec.loads(out)["ok"], err
                assert not case.invoke()["ok"]
                assert len(provider.requests) == 1


def test_tpm_requirement_rejects_software_before_credential_custody():
    with tempfile.TemporaryDirectory(prefix="agadmin-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        certs = authority.certs()
        with TLSService(provider_directory(p)) as provider:
            with pytest.raises(AssertionError):
                with AuthorityProviderCase(
                    p, provider, authority, assurance="attested-tpm", certs=certs
                ):
                    pytest.fail("software identity acquired a TPM-required session")
            assert not (p / "provider-audit.jsonl").exists()
            assert not provider.requests


def test_waiting_for_authority_lease_does_not_extend_token_lifetime():
    with tempfile.TemporaryDirectory(prefix="agadmin-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
            with AuthorityProviderCase(p, provider, authority, lifetime=2) as case:
                with (authority.root / ".enrollment.lock").open("rb") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        pending = pool.submit(case.invoke)
                        try:
                            with pytest.raises(TimeoutError):
                                pending.result(timeout=0.2)
                            time.sleep(max(0, case.expires_at + 1 - time.time()))
                        finally:
                            fcntl.flock(lock, fcntl.LOCK_UN)
                        assert not pending.result(timeout=5)["ok"]
                assert not provider.requests


def test_normal_authority_tpm_challenge_enrollment_and_provider_action():
    from tests.test_rust_garrett_certificates import creation_evidence, tpm_csr
    from tests.test_rust_garrett_tpm import SoftwareTPM

    if not shutil.which("swtpm"):
        if os.getenv("AIVM_SECRETS_REQUIRE_TPM_TESTS") == "1":
            pytest.fail("required swtpm is missing")
        pytest.skip("install swtpm and tpm2-tools")
    with tempfile.TemporaryDirectory(prefix="agadmin-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        state = p / "tpm"
        state.mkdir(mode=0o700)
        with SoftwareTPM(state) as tpm:
            csr = tpm_csr(tpm)
            creation_evidence(tpm)  # provision a synthetic, pinned attestation key
            for name in ["ak.tpmt", "ak.qname"]:
                (state / name).chmod(0o600)
            path = private(p / "tpm.csr", csr.encode())
            command = authority.command(
                "enroll-tpm",
                dict(
                    subject="vm-test",
                    csr_file=str(path),
                    ak_public_area_file=str(state / "ak.tpmt"),
                    ak_qualified_name_file=str(state / "ak.qname"),
                ),
            )
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                ready, _, _ = select.select([process.stdout], [], [], 10)
                assert ready
                challenge = codec.loads(process.stdout.readline())
                assert challenge["ok"] and len(challenge["challenge_hex"]) == 64
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
                assert process.returncode == 0, (out, err)
                enrolled = codec.loads(out)["result"]
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            # The exact previously valid creation statement is unusable in a
            # second normal enrollment, whose challenge is generated afresh.
            replay_command = authority.command(
                "enroll-tpm",
                dict(
                    subject="replay",
                    csr_file=str(path),
                    ak_public_area_file=str(state / "ak.tpmt"),
                    ak_qualified_name_file=str(state / "ak.qname"),
                ),
            )
            replay = subprocess.Popen(
                replay_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                ready, _, _ = select.select([replay.stdout], [], [], 10)
                assert ready
                second = codec.loads(replay.stdout.readline())
                assert second["challenge_hex"] != challenge["challenge_hex"]
                out, err = replay.communicate(codec.dumps(frame) + b"\n", timeout=15)
                assert replay.returncode == 1, err
                assert codec.loads(out) == dict(
                    version=1, ok=False, error=dict(code="invalid_capability")
                )
                assert "replay" not in authority.call("status")["subjects"]
            finally:
                if replay.poll() is None:
                    replay.kill()
                    replay.communicate()
            receipt = enrolled["assurance"]
            assert (
                receipt["mode"] == "attested-tpm"
                and len(receipt["ak_pin_sha256"]) == 64
            )
            certs = authority.certs(enrollment=enrolled)
            # Even deliberate replacement cannot silently lower an existing
            # TPM enrollment's recorded assurance to software approval.
            key, other = request()
            other_path = private(p / "other.csr", other.encode())
            authority.call(
                "enroll",
                subject="vm-test",
                csr_file=str(other_path),
                approve_fingerprint=inspect_csr(other.encode()),
                replace=True,
                error="denied",
            )
            with TLSService(provider_directory(p)) as provider:
                provider.routes[("GET", "/v1/account")] = dict(
                    id=42, active=True, secret=TOKEN
                )
                with AuthorityProviderCase(
                    p, provider, authority, assurance="attested-tpm", certs=certs
                ) as case:
                    config = dict(
                        key_mode="tpm2",
                        tcti=tpm.tcti,
                        persistent_handle=0x81010011,
                        authorization_file=str(state / "auth"),
                        public_area_file=str(state / "public.tpmt"),
                        work_directory=str(state),
                    )
                    assert case.invoke(key_configuration=config) == dict(
                        version=1, ok=True, result=dict(id=42, active=True)
                    )
                    assert (
                        provider.requests[-1]["headers"]["authorization"]
                        == "Bearer " + TOKEN
                    )
                    authority.call("revoke", subject="vm-test")
                    assert not case.invoke(key_configuration=config)["ok"]
