"""Native operation CLI: real broker authority, keyed writes and reply outcomes."""

import json
import os
import subprocess

import pytest

from aivm_secrets import guest
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import (
    AuthorityCase,
    AuthorityProviderCase,
    private,
)
from tests.test_rust_garrett_manifest import (
    ManifestCase,
    policy,
    provider_directory,
    reference_compile,
)
from tests.test_rust_coordination import CoordinatorCase, coordinator_case


def client_config(case, bundle=False):
    config = dict(
        schema=1,
        key_mode="software",
        socket=str(case.directory / "identity.sock"),
        server_name="localhost",
        server_ca=str(case.certs["ca"]),
        private_key=str(case.certs["client1"][1]),
    )
    token = private(case.directory / "invoke-capability", case.token.encode())
    if bundle:
        from aivm_secrets.identity.bundle import install

        output = case.directory / "invoke-bundle.json"
        install(certificate=case.certs["client1"][0], jwt_file=token, output=output)
        config["identity_bundle"] = str(output)
        extra = []
    else:
        config["certificate"] = str(case.certs["client1"][0])
        extra = ["--capability-file", str(token)]
    return [
        case.client,
        "--config",
        str(private(case.directory / "invoke-client.json", config)),
        *extra,
    ]


def invoke(command, *words, input=None, code=0):
    done = subprocess.run(
        [*command, "invoke", *words], input=input, capture_output=True, timeout=15
    )
    assert done.returncode == code, done
    assert TOKEN.encode() not in done.stdout + done.stderr
    if done.stdout:
        assert not done.stderr, done
        return codec.loads(done.stdout)
    return done


@pytest.mark.parametrize("bundle", [False, True])
@pytest.mark.parametrize("source", ["inline", "file", "stdin", "symlink"])
def test_named_read_preserves_python_request_and_provider_effect(
    tmp_path, bundle, source
):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        provider.routes[("GET", "/v1/tickets/7")] = {"id": 7, "discarded": TOKEN}
        p = policy(tmp_path, provider)
        with ManifestCase(tmp_path, provider, p) as case:
            args = {"ticket": 7}
            raw = codec.dumps(args)
            data = None
            if source == "inline":
                options = ["--arguments", raw.decode()]
            elif source == "stdin":
                options, data = ["--arguments-file", "-"], raw
            else:
                folder = tmp_path / "public-input"
                folder.mkdir(mode=0o755)
                file = folder / "args.json"
                file.write_bytes(raw)
                file.chmod(0o644)
                if source == "symlink":
                    link = folder / "link.json"
                    link.symlink_to(file)
                    file = link
                options = ["--arguments-file", str(file)]
            reference = guest.parser().parse_args(
                ["invoke", "ticket.view", "--arguments", raw.decode()]
            )
            verb, request = guest.frame_from_args(reference)
            assert verb == "request" and request == {
                "operation": "ticket.view",
                "arguments": args,
            }
            expected = reference_compile(p, request)["result"]["effect"]
            reply = invoke(
                client_config(case, bundle), "ticket.view", *options, input=data
            )
            assert reply == {"version": 1, "ok": True, "result": {"id": 7}}
            [sent] = provider.seen()
            assert (sent["method"], sent["target"]) == (
                expected["method"],
                expected["target"],
            )
            assert sent["headers"]["authorization"] == "Bearer " + TOKEN
            assert case.token.encode() not in codec.dumps(reply)


@pytest.mark.parametrize("bundle", [False, True])
def test_named_read_with_no_arguments(tmp_path, bundle):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        provider.routes[("GET", "/v1/account")] = {"id": 7, "active": True}
        with AuthorityProviderCase(tmp_path, provider, AuthorityCase(tmp_path)) as case:
            assert invoke(client_config(case, bundle), "profile.read")["ok"]
            assert len(provider.seen()) == 1


@pytest.mark.parametrize("bundle", [False, True])
def test_named_write_keeps_broker_permission_gate(tmp_path, bundle):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        provider.routes[("PATCH", "/v1/tickets/7")] = {"id": 7}
        with ManifestCase(tmp_path, provider, writes="deny") as case:
            reply = invoke(
                client_config(case, bundle),
                "ticket.edit",
                "--arguments",
                '{"ticket":7,"text":"hello"}',
                code=1,
            )
            assert reply["error"]["code"] == "denied"
            assert provider.seen() == []


@pytest.mark.parametrize("bundle", [False, True])
def test_named_write_reservation_replay_and_terminal_revocation(
    tmp_path, bundle, coordinator_case
):
    with (
        coordinator_case(tmp_path / "coord") as coord,
        TLSService(provider_directory(tmp_path), host="api.example.org") as provider,
    ):
        coord.operator.activate([m[2] for m in coord.members[:2]])
        provider.routes[("PATCH", "/v1/tickets/7")] = {"id": 7}
        p = policy(tmp_path, provider)
        next(o for o in p["operations"] if o["name"] == "ticket.edit")[
            "idempotency_header"
        ] = "Idempotency-Key"
        with ManifestCase(
            tmp_path,
            provider,
            p,
            writes="allow",
            coordination_file=str(coord.member_file()),
        ) as case:
            command = client_config(case, bundle)
            args = ["ticket.edit", "--arguments", '{"ticket":7,"text":"hello"}']
            missing = invoke(command, *args, code=1)
            assert missing["error"]["code"] == "invalid_request"
            assert provider.seen() == []
            bad_read = invoke(
                command,
                "ticket.view",
                "--arguments",
                '{"ticket":7}',
                "--idempotency-key",
                "native-cli-read-key",
                code=1,
            )
            assert bad_read["error"]["code"] == "invalid_request"
            assert provider.seen() == []
            reference = guest.parser().parse_args(
                ["invoke", *args, "--idempotency-key", "native-cli-write-01"]
            )
            assert guest.frame_from_args(reference) == (
                "request",
                dict(
                    operation="ticket.edit",
                    arguments={"ticket": 7, "text": "hello"},
                    idempotency_key="native-cli-write-01",
                ),
            )
            assert invoke(command, *args, "--idempotency-key", "native-cli-write-01")[
                "ok"
            ]
            replay = invoke(
                command, *args, "--idempotency-key", "native-cli-write-01", code=1
            )
            assert replay["error"]["code"] == "outcome_unknown"
            assert len(provider.seen()) == 1
            [sent] = provider.seen()
            assert sent["headers"]["idempotency-key"] == codec.digest(
                dict(
                    schema=1,
                    principal="shared-principal",
                    client_key="native-cli-write-01",
                )
            )
            assert sent["headers"]["authorization"] == "Bearer " + TOKEN
            assert sent["body"] == {"text": "hello"} or json.loads(sent["body"]) == {
                "text": "hello"
            }
            assert invoke(command, *args, "--idempotency-key", "native-cli-write-02")[
                "ok"
            ]
            provider.routes[("PATCH", "/v1/tickets/7")] = lambda seen: (503, {}, b"{}")
            uncertain = invoke(
                command, *args, "--idempotency-key", "native-cli-uncertain", code=1
            )
            assert uncertain["error"]["code"] == "outcome_unknown"
            assert len(provider.seen()) == 3
            assert (
                invoke(
                    command, *args, "--idempotency-key", "native-cli-uncertain", code=1
                )["error"]["code"]
                == "outcome_unknown"
            )
            assert len(provider.seen()) == 3
            coord.operator.revoke()
            revoked = invoke(
                command, *args, "--idempotency-key", "native-cli-write-03", code=1
            )
            assert revoked["error"]["code"] == "revoked"
            assert len(provider.seen()) == 3


@pytest.mark.parametrize(
    "words",
    [
        [],
        ["profile.read", "--unknown", "x"],
        ["profile.read", "--arguments"],
        ["profile.read", "--arguments", "{}", "--arguments", "{}"],
        ["profile.read", "--arguments", "[]"],
        ["profile.read", "--arguments", '{"x":1,"x":2}'],
        ["profile.read", "--arguments", "{}", "--arguments-file", "missing"],
        ["bad\noperation"],
        ["profile.read", "--idempotency-key", "short"],
        ["profile.read", "--idempotency-key", "x" * 129],
        ["profile.read", "--idempotency-key", "with space"],
        ["profile.read", "--idempotency-key", "slash/name"],
        ["profile.read", "--idempotency-key", "unicode-é-key"],
    ],
)
def test_malformed_invocation_refused_before_config_or_transport(words):
    done = invoke(
        [executable("AIVM_SECRETS_RUST_GARRETT_CLIENT"), "--config", "/absent-config"],
        *words,
        code=1,
    )
    assert done.stderr == b"invalid_request\n"


@pytest.mark.parametrize("kind", ["oversize", "fifo", "directory", "nonobject"])
def test_argument_file_is_bounded_untrusted_data(tmp_path, kind):
    path = tmp_path / "args"
    if kind == "oversize":
        path.write_bytes(b" " * 16385)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"null")
    done = invoke(
        [executable("AIVM_SECRETS_RUST_GARRETT_CLIENT"), "--config", "/absent-config"],
        "profile.read",
        "--arguments-file",
        str(path),
        code=1,
    )
    assert done.stderr == b"invalid_request\n"


@pytest.mark.parametrize(
    "reply",
    [
        {"version": 1, "ok": True, "result": {"id": 7}},
        {"version": 1, "ok": False, "error": {"code": "outcome_unknown"}},
        {"version": 1, "ok": False, "error": {"code": "revoked"}},
        {},
        {"version": 2, "ok": True},
        {"version": 1, "ok": 7},
        {"version": 1},
        {"ok": True},
        {"version": True, "ok": True},
    ],
)
def test_invoke_retains_public_errors_and_invalid_replies_stay_uncertain(
    tmp_path, reply
):
    from tests.test_rust_line_framing import ReplyPeer, TOKEN as OUTER
    from tests.test_secrets_identity_mtls import certificates

    # Resolve (or skip) before the peer starts: a skip raised inside the peer
    # context would surface as the peer's own accept timeout.
    client = executable("AIVM_SECRETS_RUST_GARRETT_CLIENT")
    certs = certificates(tmp_path)
    for path in [certs["ca"], certs["client1"][0]]:
        path.chmod(0o600)
    token = private(tmp_path / "outer.jwt", OUTER.encode())
    with ReplyPeer(tmp_path, certs, [codec.dumps(reply) + b"\n"]) as peer:
        cfg = private(
            tmp_path / "client.json",
            dict(
                schema=1,
                key_mode="software",
                socket=str(peer.path),
                server_name="localhost",
                server_ca=str(certs["ca"]),
                certificate=str(certs["client1"][0]),
                private_key=str(certs["client1"][1]),
            ),
        )
        command = [
            client,
            "--config",
            str(cfg),
            "--capability-file",
            str(token),
        ]
        valid = (
            type(reply.get("version")) is int
            and reply["version"] == 1
            and type(reply.get("ok")) is bool
        )
        success = valid and reply["ok"]
        result = invoke(command, "profile.read", code=0 if success else 1)
        if valid:
            assert result == reply
        else:
            assert result.stderr == b"outcome_unknown\n"


def test_retry_key_validator_matches_python_grammar_for_all_bytes_and_boundaries():
    import random
    from tests.test_rust_garrett import run

    rng = random.Random(80127)
    cases = [b"x" * n for n in range(132)]
    cases += [b"prefix-" + bytes([byte]) + b"-suffix" for byte in range(256)]
    cases += [rng.randbytes(rng.randrange(132)) for _ in range(2000)]
    cases += [b"-key-name-0001", b"_key_name_0001", b"AZaz09_-" * 16]
    allowed = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    rows = [dict(action="retry-key", key_hex=key.hex()) for key in cases]
    actual = run(executable("AIVM_SECRETS_RUST_GARRETT_RUNNER"), rows, crypto=True)
    assert actual == [
        dict(ok=True, valid=8 <= len(key) <= 128 and all(b in allowed for b in key))
        for key in cases
    ]
