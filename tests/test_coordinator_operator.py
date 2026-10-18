"""Operator control: terminal state, typed receipts and lost-reply uncertainty."""

import json
from pathlib import Path
import socket
import subprocess

import pytest

from aivm_secrets.errors import SecretsError
from aivm_secrets.identity.coordination import _Handler
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import (
    AuthorityCase,
    AuthorityProviderCase,
    private,
)
from tests.test_rust_garrett_manifest import ManifestCase, provider_directory
from tests.test_rust_coordination import CoordinatorCase, coordinator_case
from tests.test_rust_coordinator_authority import NativeCoordinatorCase
from tests.test_secrets_coordination import KEY, DIGEST

VECTORS = (
    Path(__file__).parent / "secrets_vectors/coordination/operator-replies-v1.jsonl"
)
SENTINEL = "unreviewed-server-material"


def operator_call(coord, client, action, *, material=None, overrides=None):
    material = material or coord.operator_material
    config = coord.config(material)
    config.update(overrides or {})
    members = [coord.members[0][2]]
    if client == "python":
        from aivm_secrets.identity.coordination import (
            CoordinationClient,
            CoordinationConfig,
        )

        try:
            value = CoordinationClient(CoordinationConfig.parse(config))._call(
                action, **({"members": members} if action == "activate" else {})
            )
            return dict(version=1, **value)
        except SecretsError as error:
            assert SENTINEL not in str(error)
            return dict(version=1, ok=False, error=dict(code=error.code))
    path = private(coord.root / "operator-client.json", config)
    args = [
        executable("AIVM_SECRETS_RUST_COORDINATOR_CTL"),
        "--config",
        str(path),
        action,
    ]
    if action == "activate":
        args += ["--member", members[0]]
    done = subprocess.run(args, capture_output=True, timeout=12)
    assert not done.stderr, done
    assert SENTINEL.encode() not in done.stdout
    value = codec.loads(done.stdout)
    assert done.returncode == (0 if value["ok"] is True else 1), done
    return value


class LostReply(_Handler):
    """Drop only after the real handler has authorized and committed its action."""

    def end_headers(self):
        self.close_connection = True
        self.connection.shutdown(socket.SHUT_RDWR)
        raise ConnectionAbortedError

    def do_POST(self):
        self.server.operator_attempts += 1
        try:
            super().do_POST()
        except ConnectionAbortedError:
            pass


@pytest.mark.parametrize("action", ["activate", "revoke"])
@pytest.mark.parametrize("client", ["python", "rust"])
def test_operator_committed_action_with_lost_reply_is_uncertain(
    tmp_path, action, client
):
    with CoordinatorCase(tmp_path / "coord") as coord:
        if action == "revoke":
            coord.operator.activate([coord.members[0][2]])
        original = coord.server.RequestHandlerClass
        coord.server.RequestHandlerClass = LostReply
        coord.server.operator_attempts = 0
        try:
            reply = operator_call(coord, client, action)
        finally:
            coord.server.RequestHandlerClass = original
        assert coord.ledger.status("shared-principal") == {
            "active": action == "activate",
            "revision": 1 if action == "activate" else 2,
        }
        assert reply == dict(version=1, ok=False, error=dict(code="outcome_unknown"))
        assert coord.server.operator_attempts == 1


@pytest.mark.parametrize("client", ["python", "rust"])
def test_operator_roles_and_terminal_lifecycle(tmp_path, client, coordinator_case):
    with coordinator_case(tmp_path / "coord") as coord:
        absent = dict(version=1, ok=True, active=False, revision=None)
        assert operator_call(coord, client, "status") == absent
        for action in ["activate", "revoke", "status"]:
            denied = operator_call(coord, client, action, material=coord.members[0])
            assert denied == dict(version=1, ok=False, error=dict(code="denied"))
            assert operator_call(coord, client, "status") == absent
        assert operator_call(coord, client, "activate") == dict(
            version=1, ok=True, active=True, revision=1
        )
        coord.client(coord.members[0]).check()
        # Operator identity alone never grants the principal's member role.
        with pytest.raises(SecretsError):
            coord.operator.check()
        assert operator_call(coord, client, "revoke") == dict(
            version=1, ok=True, active=False, revision=2
        )
        with pytest.raises(SecretsError):
            coord.client(coord.members[0]).check()
        assert operator_call(coord, client, "activate")["error"]["code"] == "revoked"
        assert operator_call(coord, client, "status") == dict(
            version=1, ok=True, active=False, revision=2
        )


@pytest.mark.parametrize("client", ["python", "rust"])
def test_operator_preemptive_revocation_creates_a_terminal_receipt(
    tmp_path, client, coordinator_case
):
    with coordinator_case(tmp_path / "coord") as coord:
        assert operator_call(coord, client, "status")["revision"] is None
        assert operator_call(coord, client, "revoke") == dict(
            version=1, ok=True, active=False, revision=1
        )
        assert operator_call(coord, client, "activate")["error"]["code"] == "revoked"
        assert operator_call(coord, client, "status") == dict(
            version=1, ok=True, active=False, revision=1
        )


def test_native_operator_reads_a_tombstone_after_native_restart(tmp_path):
    with NativeCoordinatorCase(tmp_path / "coord") as coord:
        assert operator_call(coord, "rust", "revoke")["revision"] == 1
        coord.stop()
        coord.start()
        assert operator_call(coord, "rust", "status") == dict(
            version=1, ok=True, active=False, revision=1
        )
        assert operator_call(coord, "rust", "activate")["error"]["code"] == "revoked"


@pytest.mark.parametrize("profile", ["account", "manifest"])
def test_native_operator_fences_a_running_native_broker(
    tmp_path, profile, coordinator_case
):
    with (
        coordinator_case(tmp_path / "coord") as coord,
        TLSService(provider_directory(tmp_path), host="api.example.org") as provider,
    ):
        assert operator_call(coord, "rust", "activate")["ok"]
        options = dict(coordination_file=str(coord.member_file()))
        if profile == "account":
            session = AuthorityProviderCase(
                tmp_path, provider, AuthorityCase(tmp_path), **options
            )
            request = {}
            provider.routes[("GET", "/v1/account")] = dict(id=7, active=True)
        else:
            session = ManifestCase(tmp_path, provider, **options)
            request = dict(operation="ticket.view", arguments={"ticket": 7})
            provider.routes[("GET", "/v1/tickets/7")] = dict(id=7)
        with session:
            assert session.invoke(**request)["ok"]
            assert len(provider.seen()) == 1
            assert operator_call(coord, "rust", "revoke")["ok"]
            for fields in (request, dict(verb="describe"), dict(verb="renounce")):
                result = session.invoke(**fields)
                assert result["error"]["code"] == "revoked", result
            assert len(provider.seen()) == 1


class ReplyFixture(_Handler):
    def do_POST(self):
        request = codec.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.operator_attempts.append(request["action"])
        body = codec.dumps(self.server.operator_reply)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.parametrize("action", ["check", "reserve", "finish"])
def test_python_member_acknowledgements_are_complete_and_fail_closed(tmp_path, action):
    with CoordinatorCase(tmp_path / "coord") as coord:
        coord.server.RequestHandlerClass = ReplyFixture
        coord.server.operator_attempts = []
        member = coord.client(coord.members[0])
        extra = {} if action == "check" else dict(key=KEY, digest=DIGEST)
        valid = (
            {"ok": True, "active": True, "revision": 1}
            if action == "check"
            else {"ok": True, "reserved" if action == "reserve" else "recorded": True}
        )
        coord.server.operator_reply = valid
        assert member._call(action, **extra) == valid
        for reply in [
            {},
            {"ok": True},
            dict(valid, ok=1),
            dict(valid, private=SENTINEL),
            {"ok": False, "code": [SENTINEL]},
        ]:
            coord.server.operator_reply = reply
            with pytest.raises(SecretsError) as refused:
                member._call(action, **extra)
            assert refused.value.code == "revoked"
            assert SENTINEL not in str(refused.value)
        coord.server.operator_reply = {"ok": False, "code": "outcome_unknown"}
        with pytest.raises(SecretsError) as uncertain:
            member._call(action, **extra)
        assert uncertain.value.code == "outcome_unknown"


@pytest.mark.parametrize("client", ["python", "rust"])
def test_operator_reply_vectors_are_typed_and_sanitized(tmp_path, client):
    rows = [json.loads(line) for line in VECTORS.read_text().splitlines()]
    with CoordinatorCase(tmp_path / "coord") as coord:
        coord.server.RequestHandlerClass = ReplyFixture
        coord.server.operator_attempts = []
        for row in rows:
            coord.server.operator_reply = row["reply"]
            actual = operator_call(coord, client, row["action"])
            expected = (
                dict(version=1, ok=False, error=dict(code=row["error"]))
                if row["error"]
                else dict(version=1, **row["reply"])
            )
            assert codec.dumps(actual) == codec.dumps(expected), row
        assert coord.server.operator_attempts == [row["action"] for row in rows]
        assert coord.ledger.status("shared-principal") == {
            "active": False,
            "revision": None,
        }


@pytest.mark.parametrize("client", ["python", "rust"])
def test_operator_trust_failure_is_unsent(tmp_path, client):
    with (
        CoordinatorCase(tmp_path / "coord") as coord,
        CoordinatorCase(tmp_path / "other") as other,
    ):
        coord.server.RequestHandlerClass = ReplyFixture
        coord.server.operator_attempts = []
        result = operator_call(
            coord, client, "revoke", overrides={"ca_file": str(other.ca)}
        )
        assert result == dict(version=1, ok=False, error=dict(code="unreachable"))
        assert coord.server.operator_attempts == []
        assert coord.ledger.status("shared-principal") == {
            "active": False,
            "revision": None,
        }


@pytest.mark.parametrize(
    "words",
    [
        [],
        ["activate"],
        ["activate", "--member"],
        ["activate", "--unknown", "x"],
        ["activate", "--member", "g" * 64],
        ["activate", "--member", "a" * 64, "--member", "a" * 64],
        ["status", "--member", "a" * 64],
        ["revoke", "--force"],
        ["check"],
    ],
)
def test_native_operator_rejects_invalid_cli_before_config(words):
    done = subprocess.run(
        [
            executable("AIVM_SECRETS_RUST_COORDINATOR_CTL"),
            "--config",
            "/absent-config",
            *words,
        ],
        capture_output=True,
        timeout=8,
    )
    assert not done.stderr
    assert done.returncode == 1
    assert codec.loads(done.stdout) == dict(
        version=1, ok=False, error=dict(code="invalid_request")
    )
