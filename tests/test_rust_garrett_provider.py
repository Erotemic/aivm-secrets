"""Rust owns the whole client-to-provider path; Python is only the test provider.

The account-status-v1 release projection is explicit and stronger than the
reference's general raw-result API. Compare the shared wire/route/envelope
semantics and the selected public fields, without claiming whole-broker parity.
"""

from __future__ import annotations

import json
import os
import sys
import base64
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import select
import subprocess
import tempfile
import time
import threading

from aivm_secrets.host.envelope import EnvelopeCodec
from aivm_secrets.host.egress import HTTPSExecutor
from aivm_secrets.kernel.model import Claims
from aivm_secrets.identity.token import certificate_thumbprint
from aivm_secrets.primitives import codec
from tests.secrets_helpers import Harness, TLSService, TOKEN
from tests.test_rust_garrett import certificates, executable, run


class ProviderCase:
    def __init__(
        self,
        directory,
        provider,
        certificate_factory=certificates,
        file_size_limit=None,
        **changes,
    ):
        self.directory = Path(directory)
        self.provider = provider
        self.changes = changes
        self.certificate_factory = certificate_factory
        self.file_size_limit = file_size_limit

    def __enter__(self):
        p = self.directory
        self.bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
        self.client = executable("AIVM_SECRETS_RUST_GARRETT_CLIENT")
        self.certs = self.certificate_factory(p)
        for item in p.iterdir():
            if item.is_file():
                item.chmod(0o600)
        for item in self.provider.files.values():
            item.chmod(0o600)
        (p / "credential").write_text(TOKEN)
        (p / "credential").chmod(0o600)
        (p / "seed").write_bytes(os.urandom(32))
        (p / "outer-key").write_bytes(os.urandom(32))
        now = int(time.time())
        self.registry = dict(
            schema=1,
            subjects={
                "vm-test": dict(
                    active=True,
                    epoch=0,
                    certificate_sha256=certificate_thumbprint(self.certs["client1"][2]),
                    not_after=now + 600,
                    key_sha256="1" * 64,
                    retired_keys=[],
                )
            },
        )
        self.registry_path = p / "registry.json"
        self.registry_path.write_bytes(codec.dumps(self.registry))
        backend = dict(
            profile="account-status-v1",
            host=self.provider.host,
            address="127.0.0.1",
            port=self.provider.port,
            authentication="bearer",
            server_ca=str(self.provider.files["ca"]),
            credential_file=str(p / "credential"),
            audit_file=str(p / "audit.jsonl"),
        )
        backend.update(self.changes)
        config = dict(
            schema=1,
            issuer="aivm.test",
            audience="aivm-secrets.remote",
            subject="vm-test",
            listen=str(p / "identity.sock"),
            registry_path=str(self.registry_path),
            kid="test-1",
            server_certificate=str(self.certs["server"][0]),
            server_key=str(self.certs["server"][1]),
            client_ca=str(self.certs["ca"]),
            encryption_key_file=str(p / "outer-key"),
            signing_key_file=str(p / "seed"),
            lifetime=300,
            binding=dict(
                owner_uid=os.getuid(),
                access_identity="principal-test",
                vm="vm-test",
                channel="b" * 32,
            ),
            provider=backend,
        )
        (p / "bridge.json").write_bytes(codec.dumps(config))
        for item in p.iterdir():
            if item.is_file():
                item.chmod(0o600)
        command = [self.bridge, "--config", str(p / "bridge.json")]
        if self.file_size_limit is not None:
            command = [
                sys.executable,
                str(Path(__file__).with_name("limited_exec.py")),
                str(self.file_size_limit),
                *command,
            ]
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            ready, _, _ = select.select([self.process.stdout], [], [], 10)
            assert ready, "Rust provider session did not become ready"
            line = self.process.stdout.readline()
            assert line, self.process.stderr.read()
            announcement = codec.loads(line)
            assert (
                announcement["ready"] and announcement["profile"] == "account-status-v1"
            )
            assert set(announcement) == {
                "version",
                "ready",
                "profile",
                "capability",
                "expires_at",
            }
            self.token = announcement["capability"]
            assert TOKEN.encode() not in line and "aivs1." not in self.token
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def invoke(
        self,
        *,
        role="client1",
        operation="profile.read",
        arguments=None,
        verb="request",
        key_configuration=None,
        **extra,
    ):
        p = self.directory
        config = dict(
            schema=1,
            key_mode="software",
            socket=str(p / "identity.sock"),
            server_name="localhost",
            certificate=str(self.certs[role][0]),
            private_key=str(self.certs[role][1]),
            server_ca=str(self.certs["ca"]),
        )
        if key_configuration is not None:
            config.pop("private_key")
            config.update(key_configuration)
        path = p / "client.json"
        path.write_bytes(codec.dumps(config))
        path.chmod(0o600)
        payload = (
            dict(operation=operation, arguments=arguments or {})
            if verb == "request"
            else True
        )
        frame = dict(version=1, capability=self.token, **{verb: payload}, **extra)
        done = subprocess.run(
            [self.client, "--config", str(path)],
            input=codec.dumps(frame),
            capture_output=True,
            timeout=15,
            check=True,
        )
        assert TOKEN.encode() not in done.stdout + done.stderr
        assert self.token.encode() not in done.stdout + done.stderr
        return codec.loads(done.stdout)

    def __exit__(self, *exc):
        self.process.terminate()
        try:
            stdout, stderr = self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            stdout, stderr = self.process.communicate()
        assert TOKEN.encode() not in stdout + stderr


def provider_directory(root):
    p = Path(root) / "provider"
    p.mkdir(mode=0o700)
    return p


def test_rust_owns_custody_and_matches_reference_provider_substitution(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="agp-") as directory:
        p = Path(directory)
        keylog = p / "traffic-keys.log"
        monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(
                id=42, active=True, email="not-agent-public@example.test"
            )
            with ProviderCase(p, provider) as case:
                assert case.invoke() == dict(
                    version=1, ok=True, result=dict(id=42, active=True)
                )
                rust_seen = provider.requests[-1]
                token_file = p / "credential"
                policy = provider.policy(
                    token_file,
                    operations=[
                        dict(
                            name="profile.read",
                            effect="read",
                            method="GET",
                            path="/v1/account",
                        )
                    ],
                )
                from aivm_secrets.kernel.service import parse_policy

                reference = Harness(
                    p / "reference",
                    policy=policy,
                    executor=HTTPSExecutor(parse_policy(policy).egress),
                )
                try:
                    reply = reference.invoke("profile.read")
                    assert reply["ok"]
                    assert {
                        k: reply["result"][k] for k in ["id", "active"]
                    } == case.invoke()["result"]
                    python_seen = provider.requests[-2]
                    assert {k: rust_seen[k] for k in ["method", "target", "body"]} == {
                        k: python_seen[k] for k in ["method", "target", "body"]
                    }
                    assert (
                        rust_seen["headers"]["authorization"]
                        == python_seen["headers"]["authorization"]
                        == "Bearer " + TOKEN
                    )
                    assert all(
                        TOKEN not in value
                        for key, value in rust_seen["headers"].items()
                        if key != "authorization"
                    )
                    assert not (
                        p / "broker.sock"
                    ).exists()  # no Python broker in the Rust path
                finally:
                    reference.broker.close()
                audit = (p / "audit.jsonl").read_bytes()
                assert TOKEN.encode() not in audit and case.token.encode() not in audit
                events = [codec.loads(line)["event"] for line in audit.splitlines()]
                assert events == [
                    "session_open",
                    "issued",
                    "dispatch",
                    "completed",
                    "dispatch",
                    "completed",
                ]
                identity = codec.loads(
                    base64.urlsafe_b64decode(case.token.split(".")[1] + "==")
                )
                records = [codec.loads(line) for line in audit.splitlines()]
                issuance = records[1]
                assert issuance["event"] == "issued"
                assert issuance["identity"] == {
                    k: v for k, v in identity.items() if k != "enc"
                }
                for record in [
                    codec.loads(line)
                    for line in audit.splitlines()
                    if codec.loads(line)["event"] == "dispatch"
                ]:
                    assert record["identity"] == {
                        k: v for k, v in identity.items() if k != "enc"
                    }
                    assert record["identity"] == issuance["identity"]
                    assert record["grant"] == issuance["grant"]
                    assert record["policy"] == issuance["policy"]
                    assert record["route"] == dict(
                        host=provider.host,
                        port=provider.port,
                        path="/v1/account",
                        method="GET",
                        authentication="bearer",
                    )
                    assert record["inner"]["binding"] == dict(
                        owner_uid=os.getuid(),
                        access_identity="principal-test",
                        vm="vm-test",
                        channel="b" * 32,
                    )
                assert not keylog.exists()


def test_stolen_surrogate_wrong_operation_and_revocation_do_not_reach_provider():
    with tempfile.TemporaryDirectory(prefix="agpa-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
            with ProviderCase(p, provider) as case:
                for request in [
                    dict(role="client2"),
                    dict(operation="issue.comment"),
                    dict(arguments={"host": "evil.test"}),
                    dict(peer_thumbprint="spoof"),
                    dict(verb="delegate"),
                ]:
                    assert not case.invoke(**request)["ok"]
                assert not provider.requests
                assert case.invoke()["ok"]
                case.registry["subjects"]["vm-test"]["active"] = False
                replacement = p / "new-registry.json"
                replacement.write_bytes(codec.dumps(case.registry))
                replacement.chmod(0o600)
                replacement.replace(case.registry_path)
                assert not case.invoke()["ok"]
                assert len(provider.requests) == 1


def test_inflight_request_may_finish_but_revoked_identity_cannot_dispatch_again():
    with tempfile.TemporaryDirectory(prefix="agp-flight-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            entered, release = threading.Event(), threading.Event()

            def blocked(_request):
                entered.set()
                assert release.wait(5), "test did not release the provider response"
                return 200, {}, codec.dumps(dict(id=42, active=True))

            provider.routes[("GET", "/v1/account")] = blocked
            with ProviderCase(p, provider) as case:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pending = pool.submit(case.invoke)
                    try:
                        assert entered.wait(5), "request did not reach provider"
                        case.registry["subjects"]["vm-test"]["active"] = False
                        replacement = p / "revoked.json"
                        replacement.write_bytes(codec.dumps(case.registry))
                        replacement.chmod(0o600)
                        replacement.replace(case.registry_path)
                    finally:
                        release.set()
                    assert pending.result(timeout=5)["ok"]
                assert not case.invoke()["ok"]
                assert len(provider.requests) == 1
                records = [
                    codec.loads(line)
                    for line in (p / "audit.jsonl").read_bytes().splitlines()
                ]
                assert [r["event"] for r in records] == [
                    "session_open",
                    "issued",
                    "dispatch",
                    "completed",
                ]
                assert records[1]["identity"] == records[2]["identity"]


def test_release_discards_reflected_credentials_and_provider_private_fields():
    with tempfile.TemporaryDirectory(prefix="agpr-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            with ProviderCase(p, provider) as case:
                for discarded in [
                    dict(credential=TOKEN),
                    dict(
                        refresh_token=TOKEN,
                        diagnostic={"Authorization": "Bearer " + TOKEN},
                    ),
                    dict(body=[TOKEN] * 100),
                ]:
                    provider.routes[("GET", "/v1/account")] = dict(
                        id=42, active=True, **discarded
                    )
                    assert case.invoke() == dict(
                        version=1, ok=True, result=dict(id=42, active=True)
                    )
                assert case.invoke(verb="describe")["description"]["release"] == [
                    "id",
                    "active",
                ]
                assert case.invoke(verb="renounce")["ok"]
                assert not case.invoke()["ok"]
                assert len(provider.requests) == 3


def test_provider_errors_malformed_json_and_redirects_release_no_body():
    with tempfile.TemporaryDirectory(prefix="agpe-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            with ProviderCase(p, provider) as case:
                bodies = [
                    b'{"id":true,"active":true}',
                    b'{"id":42,"active":"true"}',
                    b'{"id":42,"id":43,"active":true}',
                    b'{"id":-1,"active":true}',
                    b'{"id":42,"active":true,"bad":"\\ud800"}',
                ]
                for body in bodies:
                    provider.routes[("GET", "/v1/account")] = (
                        lambda request, body=body: (200, {}, body)
                    )
                    reply = case.invoke()
                    assert (
                        not reply["ok"]
                        and reply["error"]["code"] == "upstream_response"
                    )
                for status in [302, 401, 500]:
                    provider.routes[("GET", "/v1/account")] = (
                        lambda request, status=status: (
                            status,
                            {"Location": "https://evil.invalid/" + TOKEN},
                            TOKEN.encode(),
                        )
                    )
                    assert not case.invoke()["ok"]
                assert len(provider.requests) == len(bodies) + 3  # no follow/retry


def test_provider_certificate_failure_happens_before_credential_send():
    with tempfile.TemporaryDirectory(prefix="agpt-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
            with ProviderCase(p, provider, host="another.example.test") as case:
                assert not case.invoke()["ok"]
                assert not provider.requests


def test_inner_envelope_bidirectional_reference_interoperability():
    runner = executable("AIVM_SECRETS_RUST_GARRETT_RUNNER")
    key = os.urandom(32)
    c = dict(
        binding=dict(
            owner_uid=1000,
            access_identity="principal-test",
            vm="vm-test",
            channel="b" * 32,
        ),
        policy_digest="a" * 64,
        grant_id="c" * 32,
        issued_at=1000,
        expires_at=1200,
    )
    row = dict(action="inner-issue", key_hex=key.hex(), claims=c, credential=TOKEN)
    (issued,) = run(runner, [row], crypto=True)
    assert issued["ok"]
    opened = EnvelopeCodec(key).open(issued["token"])
    assert opened.claims.to_dict() == c and opened.credential == TOKEN
    token = EnvelopeCodec(key).seal(Claims.parse(c), TOKEN)
    base = dict(action="inner-open", key_hex=key.hex(), token=token)
    (answer,) = run(runner, [base], crypto=True)
    assert answer == dict(ok=True, claims=c, credential=TOKEN)
    rows = []
    for name, value in [
        ("key_hex", "ff" * 32),
        ("token", token + "="),
        ("token", "aivs1.bad"),
    ]:
        rows.append(dict(base, **{name: value}))
    assert (
        run(runner, rows, crypto=True)
        == [dict(ok=False, code="invalid_capability")] * 3
    )


def test_tpm_client_rust_custody_and_provider_without_python_broker():
    import shutil
    import pytest
    from tests.test_rust_garrett_tpm import SoftwareTPM

    executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
    executable("AIVM_SECRETS_RUST_GARRETT_CLIENT")
    if not shutil.which("swtpm"):
        if os.getenv("AIVM_SECRETS_REQUIRE_TPM_TESTS") == "1":
            pytest.fail("required swtpm is missing")
        pytest.skip("install swtpm and tpm2-tools")
    with tempfile.TemporaryDirectory(prefix="agpx-") as directory:
        p = Path(directory)
        state = p / "tpm"
        state.mkdir(mode=0o700)
        work = p / "work"
        work.mkdir(mode=0o700)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(
                id=42, active=True, credential=TOKEN
            )
            with SoftwareTPM(state) as tpm:
                with ProviderCase(
                    p, provider, certificate_factory=tpm.certificates
                ) as case:
                    key = dict(
                        key_mode="tpm2",
                        tcti=tpm.tcti,
                        persistent_handle=0x81010011,
                        authorization_file=str(state / "auth"),
                        public_area_file=str(state / "public.tpmt"),
                        work_directory=str(work),
                    )
                    assert case.invoke(key_configuration=key) == dict(
                        version=1, ok=True, result=dict(id=42, active=True)
                    )
                    assert len(provider.requests) == 1
                    assert not case.certs["client1"][1].exists()
                    assert not (p / "broker.sock").exists()
                    assert not list(work.iterdir())


def test_restart_invalidates_old_inner_authority():
    with tempfile.TemporaryDirectory(prefix="agps-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
            with ProviderCase(p, provider) as case:
                old = case.token
                assert case.invoke()["ok"]
                case.process.terminate()
                old_stdout, old_stderr = case.process.communicate(timeout=5)
                assert TOKEN.encode() not in old_stdout + old_stderr
                (p / "identity.sock").unlink()
                case.process = subprocess.Popen(
                    [case.bridge, "--config", str(p / "bridge.json")],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                ready, _, _ = select.select([case.process.stdout], [], [], 10)
                assert ready
                announcement = codec.loads(case.process.stdout.readline())
                assert announcement["ready"]
                assert not case.invoke()[
                    "ok"
                ]  # same outer keys/cert, old inner session key
                case.token = announcement["capability"]
                assert case.token != old and case.invoke()["ok"]
                assert len(provider.requests) == 2


def test_unsafe_audit_paths_fail_before_provider_io():
    with tempfile.TemporaryDirectory(prefix="agpf-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            with ProviderCase(p, provider) as case:
                case.process.terminate()
                old_stdout, old_stderr = case.process.communicate(timeout=5)
                assert TOKEN.encode() not in old_stdout + old_stderr
                path = p / "bridge.json"
                config = codec.loads(path.read_bytes())
                link = p / "audit-link"
                link.symlink_to(p / "credential")
                fifo = p / "audit-fifo"
                os.mkfifo(fifo, mode=0o600)
                for unsafe in [link, fifo, p / "provider"]:
                    config["provider"]["audit_file"] = str(unsafe)
                    path.write_bytes(codec.dumps(config))
                    done = subprocess.run(
                        [case.bridge, "--config", str(path)],
                        capture_output=True,
                        timeout=5,
                    )
                    assert (
                        done.returncode == 1
                        and not done.stdout
                        and done.stderr == b"unsafe_file\n"
                    )
                assert (p / "credential").read_text() == TOKEN
                assert not provider.requests


def test_secret_fifo_cannot_block_startup():
    with tempfile.TemporaryDirectory(prefix="agpb-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            with ProviderCase(p, provider) as case:
                case.process.terminate()
                old_stdout, old_stderr = case.process.communicate(timeout=5)
                assert TOKEN.encode() not in old_stdout + old_stderr
                fifo = p / "credential-fifo"
                os.mkfifo(fifo, mode=0o600)
                path = p / "bridge.json"
                config = codec.loads(path.read_bytes())
                config["provider"]["credential_file"] = str(fifo)
                path.write_bytes(codec.dumps(config))
                done = subprocess.run(
                    [case.bridge, "--config", str(path)], capture_output=True, timeout=5
                )
                assert (
                    done.returncode == 1
                    and not done.stdout
                    and done.stderr == b"unsafe_file\n"
                )
                assert not provider.requests


def test_audit_failure_prevents_dispatch_and_stays_failed_closed():
    with tempfile.TemporaryDirectory(prefix="agp-audit-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
            with ProviderCase(p, provider, file_size_limit=8192) as case:
                audit = p / "audit.jsonl"
                original = audit.read_bytes()
                with audit.open("ab") as stream:
                    stream.write(b" " * 8192)
                assert not case.invoke()["ok"]
                assert not provider.requests
                # Even if the host removes the triggering condition, a partial
                # write/sync failure cannot silently reactivate the audit sink.
                audit.write_bytes(original)
                assert not case.invoke()["ok"]
                assert not provider.requests


def test_issuance_audit_failure_never_releases_surrogate():
    with tempfile.TemporaryDirectory(prefix="agp-issue-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            with ProviderCase(p, provider) as case:
                first_line = (p / "audit.jsonl").read_bytes().splitlines()[0]
                alternate = codec.loads((p / "bridge.json").read_bytes())
                alternate["listen"] = str(p / "unreleased.sock")
                audit = p / "unreleased-audit.jsonl"
                alternate["provider"]["audit_file"] = str(audit)
                config = p / "unreleased.json"
                config.write_bytes(codec.dumps(alternate))
                config.chmod(0o600)
                # Session-open fits. Recording the signed public claims cannot
                # finish, exercising the acknowledgement after actual sealing.
                denied = subprocess.run(
                    [
                        sys.executable,
                        str(Path(__file__).with_name("limited_exec.py")),
                        str(len(first_line) + 65),
                        case.bridge,
                        "--config",
                        str(config),
                    ],
                    capture_output=True,
                    timeout=5,
                )
                assert denied.returncode == 1
                assert denied.stdout == b""
                assert denied.stderr == b"invalid_capability\n"
                first, partial = audit.read_bytes().split(b"\n", 1)
                assert codec.loads(first)["event"] == "session_open"
                assert partial and not partial.endswith(b"\n")
                assert TOKEN.encode() not in first + partial
                assert not provider.requests


def test_audit_file_excludes_other_sessions_and_rejects_partial_records():
    with tempfile.TemporaryDirectory(prefix="agp-lock-") as directory:
        p = Path(directory)
        with TLSService(provider_directory(p)) as provider:
            with ProviderCase(p, provider) as case:
                alternate = codec.loads((p / "bridge.json").read_bytes())
                alternate["listen"] = str(p / "other.sock")
                other = p / "other-bridge.json"
                other.write_bytes(codec.dumps(alternate))
                other.chmod(0o600)
                command = [case.bridge, "--config", str(other)]
                denied = subprocess.run(command, capture_output=True, timeout=5)
                assert (
                    denied.returncode == 1
                    and denied.stderr == b"unsafe_file\n"
                    and not denied.stdout
                )
                assert not provider.requests
                case.process.terminate()
                stdout, stderr = case.process.communicate(timeout=5)
                assert TOKEN.encode() not in stdout + stderr
                with (p / "audit.jsonl").open("ab") as stream:
                    stream.write(b'{"partial":')
                denied = subprocess.run(command, capture_output=True, timeout=5)
                assert (
                    denied.returncode == 1
                    and denied.stderr == b"unsafe_file\n"
                    and not denied.stdout
                )
                assert not provider.requests


def test_numeric_credential_cannot_be_reflected_through_public_id(
    tmp_path, monkeypatch
):
    secret = "1234567890123456"
    monkeypatch.setattr(sys.modules[__name__], "TOKEN", secret)
    with TLSService(provider_directory(tmp_path)) as provider:
        provider.routes[("GET", "/v1/account")] = dict(id=int(secret), active=True)
        with ProviderCase(tmp_path, provider) as case:
            reply = case.invoke()
            assert not reply["ok"], reply
            assert reply["error"]["code"] == "upstream_response"
            assert secret not in json.dumps(reply)
            from aivm_secrets.kernel.service import parse_policy

            policy = provider.policy(
                tmp_path / "credential",
                operations=[
                    dict(
                        name="profile.read",
                        effect="read",
                        method="GET",
                        path="/v1/account",
                    )
                ],
            )
            reference = Harness(
                tmp_path / "reference",
                policy=policy,
                token=secret,
                executor=HTTPSExecutor(parse_policy(policy).egress),
            )
            try:
                expected = reference.invoke("profile.read")
                assert expected["error"]["code"] == reply["error"]["code"]
                assert secret not in json.dumps(expected)
            finally:
                reference.broker.close()
        assert secret.encode() not in (tmp_path / "audit.jsonl").read_bytes()
