"""Independent Rust Garrett decisions, exact crypto and real mTLS/broker use.

All keys and provider credentials are synthetic. Optional runners never fall
back to Python when configured, and crypto fixtures are a test-only interface.
"""

from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import random
import select
import socket
import ssl
import subprocess
import tempfile
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from aivm_secrets.host.server import LocalServer
from aivm_secrets.identity.garrett.claims import IdentityClaims, IdentityExpectation
from aivm_secrets.identity.garrett_runner import evaluate
from aivm_secrets.identity.token import (
    IdentityTokenIssuer,
    IdentityTokenVerifier,
    certificate_thumbprint,
)
from aivm_secrets.primitives import codec
from tests.secrets_helpers import Harness, REPO, TOKEN, reply_while_open
from tests.test_secrets_identity_mtls import certificates

ROOT = Path(__file__).resolve().parents[1]


def executable(variable):
    value = os.getenv(variable)
    if not value:
        pytest.skip(f"configure {variable} for the independent Rust implementation")
    assert Path(value).is_file(), f"{variable} points to a missing executable"
    return value


@pytest.fixture
def runner():
    return executable("AIVM_SECRETS_RUST_GARRETT_RUNNER")


def run(runner, rows, *, crypto=False):
    child = subprocess.run(
        [runner, *(["--test-crypto"] if crypto else [])],
        input=b"".join(codec.dumps(row) + b"\n" for row in rows),
        capture_output=True,
        check=True,
        timeout=30,
    )
    replies = [codec.loads(line) for line in child.stdout.splitlines()]
    assert len(replies) == len(rows), child.stderr
    return replies


def crypto_fixture():
    return json.loads(
        (ROOT / "tests/secrets_vectors/identity-crypto-v1.json").read_text()
    )


def issue_input(f):
    return dict(
        action="issue",
        seed_hex=f["private_key_seed_hex"],
        encryption_key_hex=f["encryption_key_hex"],
        kid=f["kid"],
        claims=f["claims"],
        inner_capability=f["inner_capability"],
        nonce_hex=f["aes_gcm_nonce_hex"],
    )


def open_input(f):
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f["private_key_seed_hex"]))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    c = f["claims"]
    return dict(
        action="open",
        public_key_hex=public.hex(),
        encryption_key_hex=f["encryption_key_hex"],
        kid=f["kid"],
        token=f["expected_jwt"],
        certificate_der_hex=f["certificate_der_hex"],
        now=150,
        expected=dict(
            issuer=c["iss"], audience=c["aud"], subject=c["sub"], epoch=c["epoch"]
        ),
    )


def test_exact_crypto_fixture_and_bidirectional_interoperability(runner):
    f = crypto_fixture()
    (out,) = run(runner, [issue_input(f)], crypto=True)
    assert out["ok"] and out["token"] == f["expected_jwt"]
    (decoded,) = run(runner, [open_input(f)], crypto=True)
    assert decoded == dict(
        ok=True, claims=f["claims"], inner_capability=f["inner_capability"]
    )
    v = issue_input(f)
    v.pop("nonce_hex")
    first, second = run(runner, [v, v], crypto=True)
    assert first["token"] != second["token"]
    private = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(f["private_key_seed_hex"])
    )
    encryption = bytes.fromhex(f["encryption_key_hex"])
    claims = IdentityClaims.parse(f["claims"])
    expected = IdentityExpectation.parse(open_input(f)["expected"])
    verifier = IdentityTokenVerifier(
        private.public_key(), encryption, key_id=f["kid"], expected=expected
    )
    for reply in (first, second):
        assert (
            verifier.open(
                reply["token"],
                authenticated_peer_der=bytes.fromhex(f["certificate_der_hex"]),
                now=150,
            ).broker_capability
            == f["inner_capability"]
        )
    issuer = IdentityTokenIssuer(private, encryption, key_id=f["kid"])
    rows = []
    for _ in range(20):
        v = open_input(f)
        v["token"] = issuer.issue(claims, f["inner_capability"])
        rows.append(v)
    assert all(
        x["inner_capability"] == f["inner_capability"]
        for x in run(runner, rows, crypto=True)
    )


def test_crypto_rejects_tampering_and_wrong_binding(runner):
    f = crypto_fixture()
    base = open_input(f)
    rows = []
    for field, value in [
        ("certificate_der_hex", b"other certificate".hex()),
        ("now", 200),
        ("now", 99),
        ("encryption_key_hex", "ff" * 32),
        ("public_key_hex", "ff" * 32),
        ("kid", "other"),
    ]:
        row = copy.deepcopy(base)
        row[field] = value
        rows.append(row)
    for name, value in [
        ("issuer", "other"),
        ("audience", "other"),
        ("subject", "other"),
        ("epoch", 4),
    ]:
        row = copy.deepcopy(base)
        row["expected"][name] = value
        rows.append(row)
    for i in range(3):
        row = copy.deepcopy(base)
        parts = row["token"].split(".")
        part = parts[i]
        parts[i] = ("A" if part[0] != "A" else "B") + part[1:]
        row["token"] = ".".join(parts)
        rows.append(row)
    for bad in ["", f["expected_jwt"] + "=", f["expected_jwt"] + ".x", "aivs1.test"]:
        row = copy.deepcopy(base)
        row["token"] = bad
        rows.append(row)
    assert run(runner, rows, crypto=True) == [
        dict(ok=False, code="invalid_capability")
    ] * len(rows)


def test_generated_issue_and_present_parity(runner):
    rows = [
        json.loads(line)["input"]
        for line in (ROOT / "tests/secrets_vectors/garrett-protocol-v1.jsonl")
        .read_text()
        .splitlines()
    ]
    issue = next(r for r in rows if r.get("action") == "issue")
    present = next(r for r in rows if r.get("action") == "present")
    rng = random.Random(20261016)
    for _ in range(1200):
        row = copy.deepcopy(rng.choice([issue, present]))
        if row["action"] == "issue":
            row["now"] = rng.choice(
                [
                    -1,
                    0,
                    999,
                    1000,
                    1199,
                    1200,
                    2**63 - 3601,
                    2**63 - 1,
                    2**63,
                    True,
                    1.0,
                ]
            )
            row["lifetime"] = rng.choice([0, 1, 100, 3600, 3601, True])
            record = next(iter(row["state"]["subjects"].values()))
            record["active"] = rng.choice([False, True, True])
            record["epoch"] = rng.choice([0, 2, 2**31 - 1, 2**31, True])
        else:
            row["now"] = rng.choice(
                [-1, 0, 999, 1000, 1099, 1100, 2**63 - 1, 2**63, True, 1.0]
            )
            row["expected"]["epoch"] = rng.choice([0, 2, 3, 2**31 - 1, True])
            row["peer_thumbprint"] = rng.choice(
                [row["peer_thumbprint"], "A" * 43, "Z" * 43, "", False]
            )
        rows.append(row)
    actual = run(runner, rows)
    assert [codec.dumps(r) for r in actual] == [codec.dumps(evaluate(r)) for r in rows]


def test_runner_raw_json_bounds_recovery_and_flush(runner):
    valid = json.loads(
        (ROOT / "tests/secrets_vectors/garrett-protocol-v1.jsonl")
        .read_text()
        .splitlines()[0]
    )["input"]
    line = codec.dumps(valid) + b"\n"
    assert codec.loads(reply_while_open([runner], line)) == evaluate(valid)
    malformed = [
        b'{"version":1,"version":1}',
        b'{"x":{"a":1,"a":2}}',
        b'"\\ud800"',
        b'"' + b"x" * 32768 + b'"',
        b"\xff" * 32769,
    ]
    data = b"".join(raw + b"\n" + line for raw in malformed)
    child = subprocess.run(
        [runner], input=data, capture_output=True, check=True, timeout=30
    )
    actual = [codec.loads(x) for x in child.stdout.splitlines()]
    assert actual == [
        item
        for _ in malformed
        for item in (dict(ok=False, code="invalid_capability"), evaluate(valid))
    ]


class BoundBridge:
    def __init__(self, directory, runner, bridge, certificate_factory=certificates,
                 server_factory=LocalServer, python_issuer=False):
        self.directory = Path(directory)
        self.runner = runner
        self.bridge_program = bridge
        self.certificate_factory = certificate_factory
        self.server_factory = server_factory
        self.python_issuer = python_issuer

    def __enter__(self):
        p = self.directory
        self.harness = Harness(p)
        self.certs = self.certificate_factory(p)
        for item in p.iterdir():
            if item.is_file():
                item.chmod(0o600)
        self.server = self.server_factory(self.harness.broker, p / "broker")
        self.server.__enter__()
        now = int(time.time())
        cert = certificate_thumbprint(self.certs["client1"][2])
        self.claims = dict(
            iss="aivm.test",
            aud="aivm-secrets.remote",
            sub="vm-test",
            jti="f" * 32,
            iat=now - 5,
            exp=now + 60,
            epoch=0,
            cnf={"x5t#S256": cert},
        )
        self.seed = os.urandom(32)
        self.key = os.urandom(32)
        issue = dict(
            action="issue",
            seed_hex=self.seed.hex(),
            encryption_key_hex=self.key.hex(),
            kid="test-1",
            claims=self.claims,
            inner_capability=self.harness.capability,
        )
        if self.python_issuer:
            signing = Ed25519PrivateKey.from_private_bytes(self.seed)
            issuer = IdentityTokenIssuer(signing, self.key, key_id='test-1')
            answer = dict(ok=True,
                token=issuer.issue(IdentityClaims.parse(self.claims), self.harness.capability),
                public_key_hex=signing.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
        else:
            (answer,) = run(self.runner, [issue], crypto=True)
        assert answer["ok"]
        self.token = answer["token"]
        registry = {
            "schema": 1,
            "subjects": {
                "vm-test": dict(
                    active=True,
                    epoch=0,
                    certificate_sha256=cert,
                    not_after=now + 600,
                    key_sha256="1" * 64,
                    retired_keys=[],
                )
            },
        }
        (p / "registry.json").write_bytes(codec.dumps(registry))
        (p / "key.bin").write_bytes(self.key)
        self.listen = p / "identity.sock"
        config = dict(
            schema=1,
            issuer="aivm.test",
            audience="aivm-secrets.remote",
            subject="vm-test",
            kid="test-1",
            listen=str(self.listen),
            broker_socket=str(self.server.socket_path),
            registry_path=str(p / "registry.json"),
            server_certificate=str(self.certs["server"][0]),
            server_key=str(self.certs["server"][1]),
            client_ca=str(self.certs["ca"]),
            public_key_hex=answer["public_key_hex"],
            encryption_key_file=str(p / "key.bin"),
        )
        (p / "config.json").write_bytes(codec.dumps(config))
        for item in (p / "registry.json", p / "key.bin", p / "config.json"):
            item.chmod(0o600)
        self.process = subprocess.Popen(
            [self.bridge_program, "--config", str(p / "config.json")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert self.process.stdout is not None
        ready, _, _ = select.select([self.process.stdout], [], [], 10)
        assert ready, "Rust bridge did not announce readiness"
        announcement = self.process.stdout.readline()
        assert codec.loads(announcement) == dict(version=1, ready=True), (
            self.process.stderr.read().decode()
            if self.process.poll() is not None
            else announcement
        )
        return self

    def exchange(self, frame=None, *, client="client1", no_cert=False):
        if frame is None:
            frame = dict(
                version=1,
                capability=self.token,
                request={
                    "operation": "pr.view",
                    "arguments": {"repository": REPO, "pr": 13861},
                },
            )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(self.certs["ca"]))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if not no_cert:
            context.load_cert_chain(
                str(self.certs[client][0]), str(self.certs[client][1])
            )
        with socket.socket(socket.AF_UNIX) as raw:
            raw.settimeout(5)
            raw.connect(str(self.listen))
            with context.wrap_socket(raw, server_hostname="localhost") as channel:
                channel.sendall(codec.dumps(frame) + b"\n")
                reply = b""
                while not reply.endswith(b"\n"):
                    part = channel.recv(65536)
                    if not part:
                        break
                    reply += part
        return codec.loads(reply)

    def __exit__(self, typ, error, tb):
        self.process.terminate()
        try:
            self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
        self.server.__exit__(typ, error, tb)
        self.harness.broker.close()


def test_real_rust_tls_use_and_stolen_surrogate_denial(runner):
    bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
    with tempfile.TemporaryDirectory(prefix="agr-") as directory:
        with BoundBridge(directory, runner, bridge) as case:
            reply = case.exchange()
            assert reply["ok"] and reply["result"]["number"] == 13861
            assert len(case.harness.executor.calls) == 1
            assert TOKEN.encode() not in codec.dumps(reply)
            reply = case.exchange(client="client2")
            assert not reply["ok"] and reply["error"]["code"] == "invalid_capability"
            assert len(case.harness.executor.calls) == 1
            with pytest.raises((ssl.SSLError, OSError)):
                case.exchange(no_cert=True)
            assert len(case.harness.executor.calls) == 1
            for frame in [
                dict(version=1, capability=case.token, delegate={}),
                dict(version=1, capability=case.harness.capability, describe=True),
                dict(
                    version=1,
                    capability=case.token,
                    describe=True,
                    peer_thumbprint=case.claims["cnf"]["x5t#S256"],
                ),
            ]:
                assert not case.exchange(frame)["ok"]
            assert len(case.harness.executor.calls) == 1


def test_enrollment_selected_issuance_uses_extracted_controller(runner):
    f = crypto_fixture()
    vector = json.loads(
        (ROOT / "tests/secrets_vectors/garrett-protocol-v1.jsonl")
        .read_text()
        .splitlines()[0]
    )["input"]
    state = copy.deepcopy(vector["state"])
    state["subjects"][vector["subject"]]["certificate_sha256"] = f["claims"]["cnf"][
        "x5t#S256"
    ]
    row = dict(
        action="enrollment-issue",
        seed_hex=f["private_key_seed_hex"],
        encryption_key_hex=f["encryption_key_hex"],
        kid=f["kid"],
        state=state,
        issuer=vector["issuer"],
        audience=vector["audience"],
        subject=vector["subject"],
        now=1000,
        lifetime=300,
        inner_capability=f["inner_capability"],
    )
    (issued,) = run(runner, [row], crypto=True)
    assert (
        issued["ok"]
        and issued["claims"]["iat"] == 1000
        and issued["claims"]["exp"] == 1200
        and issued["claims"]["epoch"] == 2
    )
    expected = IdentityExpectation(
        vector["issuer"], vector["audience"], vector["subject"], 2
    )
    private = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(f["private_key_seed_hex"])
    )
    verifier = IdentityTokenVerifier(
        private.public_key(),
        bytes.fromhex(f["encryption_key_hex"]),
        key_id=f["kid"],
        expected=expected,
    )
    assert (
        verifier.open(
            issued["token"],
            authenticated_peer_der=bytes.fromhex(f["certificate_der_hex"]),
            now=1050,
        ).broker_capability
        == f["inner_capability"]
    )
    state["subjects"][vector["subject"]]["active"] = False
    (refused,) = run(runner, [row], crypto=True)
    assert refused == dict(ok=False, code="invalid_capability")


def test_rust_client_and_bridge_complete_the_wire_exchange(runner):
    bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
    client = executable("AIVM_SECRETS_RUST_GARRETT_CLIENT")
    with tempfile.TemporaryDirectory(prefix="agrc-") as directory:
        with BoundBridge(directory, runner, bridge) as case:
            path = Path(directory) / "client.json"
            config = dict(
                schema=1,
                key_mode="software",
                socket=str(case.listen),
                server_name="localhost",
                certificate=str(case.certs["client1"][0]),
                private_key=str(case.certs["client1"][1]),
                server_ca=str(case.certs["ca"]),
            )
            path.write_bytes(codec.dumps(config))
            path.chmod(0o600)
            frame = dict(
                version=1,
                capability=case.token,
                request={
                    "operation": "pr.view",
                    "arguments": {"repository": REPO, "pr": 13861},
                },
            )
            good = subprocess.run(
                [client, "--config", str(path)],
                input=codec.dumps(frame),
                capture_output=True,
                timeout=10,
                check=True,
            )
            reply = codec.loads(good.stdout)
            assert reply["ok"] and reply["result"]["number"] == 13861
            assert TOKEN.encode() not in good.stdout + good.stderr
            config.update(
                certificate=str(case.certs["client2"][0]),
                private_key=str(case.certs["client2"][1]),
            )
            path.write_bytes(codec.dumps(config))
            wrong = subprocess.run(
                [client, "--config", str(path)],
                input=codec.dumps(frame),
                capture_output=True,
                timeout=10,
                check=True,
            )
            assert codec.loads(wrong.stdout)["error"]["code"] == "invalid_capability"
            assert len(case.harness.executor.calls) == 1


def test_running_bridge_observes_revocation_and_fails_closed_on_bad_registry(runner):
    bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
    with tempfile.TemporaryDirectory(prefix="agrv-") as directory:
        with BoundBridge(directory, runner, bridge) as case:
            assert case.exchange()["ok"]
            registry_path = Path(directory) / "registry.json"
            registry = codec.loads(registry_path.read_bytes())
            registry["subjects"]["vm-test"]["active"] = False
            replacement = Path(directory) / "replacement.json"
            replacement.write_bytes(codec.dumps(registry))
            replacement.chmod(0o600)
            replacement.replace(registry_path)
            assert not case.exchange()["ok"]
            registry_path.write_bytes(b"invalid-json")
            assert not case.exchange()["ok"]
            registry_path.unlink()
            assert not case.exchange()["ok"]
            assert len(case.harness.executor.calls) == 1
