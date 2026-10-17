"""Independent effect compilation and real native multi-operation custody."""

from __future__ import annotations

import base64
import copy
import json
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.egress import HTTPSExecutor
from aivm_secrets.kernel.machine import AuthorizedEffect
from aivm_secrets.kernel.scope import check_arguments
from aivm_secrets.kernel.service import parse_policy
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import (
    AuthorityCase,
    AuthorityProviderCase,
    private,
)
from tests.test_rust_garrett_provider import provider_directory


def policy(directory, server=None):
    result = dict(
        schema=2,
        adapter="https",
        service="tracker",
        host="api.example.org",
        authentication="bearer",
        credential_source=dict(kind="file", path=str(directory / "credential")),
        lifetime_seconds=300,
        max_requests=200,
        max_body_bytes=100,
        operations=[
            dict(
                name="ticket.view",
                effect="read",
                method="GET",
                path="/v1/tickets/{ticket}",
                parameters={"ticket": [7, 8]},
            ),
            dict(
                name="ticket.edit",
                effect="write",
                method="PATCH",
                path="/v1/tickets/{ticket}",
                parameters={"ticket": [7, 8]},
                body_fields={"text": 20},
            ),
            dict(
                name="ticket.close",
                effect="write",
                method="GET",
                path="/v1/tickets/{ticket}/close",
                parameters={"ticket": [7, 8]},
            ),
            dict(
                name="ticket.list",
                effect="read",
                method="GET",
                path="/v1/tickets",
                parameters={"page": {"min": 1, "max": 3}, "state": ["open", "closed"]},
                query={"page": "{page}", "state": "{state}"},
                defaults={"page": 1, "state": "open"},
                fold=["state"],
                page={"size": 2, "at": ["rows"], "parameter": "page"},
            ),
        ],
    )
    if server is not None:
        result["egress"] = dict(
            address="127.0.0.1", port=server.port, ca_file=str(server.files["ca"])
        )
    return result


def disclosure():
    leaf = {"at": ["id"], "type": "integer"}
    return {
        "ticket.view": {"id": leaf},
        "ticket.edit": {"id": leaf},
        "ticket.close": {"id": leaf},
        "ticket.list": {
            "rows": {
                "at": ["rows"],
                "type": "array",
                "max_items": 2,
                "items": {"at": [], "type": "object", "fields": {"id": leaf}},
            }
        },
    }


def reference_effect(effect, write):
    if effect is None:
        return None
    body = None if effect.body is None else dict(effect.body)
    if effect.graphql:
        body = dict(
            query=body["query"],
            operationName=body["operation_name"],
            variables=codec.loads(body["variables"].encode()),
        )
    return dict(
        method=effect.method,
        target=effect.target,
        accept=effect.accept,
        response=effect.response,
        body=body,
        write=write,
    )


def reference_compile(p, request, facts=None):
    try:
        spec = parse_policy(p)
        request = spec.parse_request(request)
        op = next((o for o in spec.operations if o.name == request.operation), None)
        if op is None:
            raise SecretsError("denied")
        if check_arguments(op.scope(), request) > spec.max_body_bytes:
            raise SecretsError("denied")
        result = dict(
            request=request.to_dict(),
            preflight=reference_effect(spec.preflight(request), False),
            effect=reference_effect(spec.final(request, facts), op.write),
        )
        return dict(ok=True, result=result)
    except SecretsError as e:
        return dict(ok=False, code=e.code)


def compile_rows(rows):
    binary = executable("AIVM_SECRETS_RUST_MANIFEST_RUNNER")
    result = subprocess.run(
        [binary],
        input=b"".join(codec.dumps(dict(version=1, **r)) + b"\n" for r in rows),
        capture_output=True,
        check=True,
        timeout=20,
    )
    assert not result.stderr
    return [codec.loads(row) for row in result.stdout.splitlines()]


class ManifestCase(AuthorityProviderCase):
    def __init__(self, directory, server, p=None, releases=None, **changes):
        p = p or policy(directory, server)
        releases = releases or disclosure()
        self.policy_file = private(directory / "policy.json", p)
        self.disclosure_file = private(directory / "disclosure.json", releases)
        authority = AuthorityCase(directory)
        super().__init__(
            directory,
            server,
            authority,
            profile="manifest-https-v1",
            policy_file=str(self.policy_file),
            disclosure_file=str(self.disclosure_file),
            writes=changes.pop("writes", "deny"),
            request_limit="unbounded",
            **changes,
        )


def test_compiler_matches_independent_python_for_parameters_defaults_and_writes(
    tmp_path,
):
    p = policy(tmp_path)
    requests = []
    for op in ["ticket.view", "ticket.edit", "ticket.close"]:
        for value in [7, 8, 9, "7", True, None, "../outside", "x?token=y"]:
            args = {"ticket": value}
            if op == "ticket.edit":
                args["text"] = "hello"
            requests.append(dict(operation=op, arguments=args))
    requests += [
        dict(operation="ticket.list", arguments=args)
        for args in [
            {},
            {"page": 2, "state": "CLOSED"},
            {"page": 4},
            {"state": "x&other=y"},
            {"other": 1},
        ]
    ]
    rows = [dict(policy=p, request=r) for r in requests]
    assert compile_rows(rows) == [reference_compile(p, r) for r in requests]


def checked(p):
    p = copy.deepcopy(p)
    p["checks"] = {
        "ticket": dict(
            path="/v1/tickets/{ticket}",
            require=[{"at": ["owner"], "equals": "alice", "fold": True}],
            bind={"revision": {"at": ["revision"], "format": "hex"}},
        )
    }
    p["operations"] = [
        dict(
            name="revision.view",
            effect="read",
            method="GET",
            path="/v1/revisions/{revision}",
            parameters={"ticket": [7]},
            requires="ticket",
        ),
        dict(
            name="ticket.check",
            effect="read",
            parameters={"ticket": [7]},
            requires="ticket",
            returns="check",
        ),
    ]
    return p


def test_checked_fact_compiler_matches_python_and_refuses_substituted_facts(tmp_path):
    p = checked(policy(tmp_path))
    rows = []
    for op in ["revision.view", "ticket.check"]:
        for facts in [
            dict(owner="ALICE", revision="A" * 40),
            dict(owner="mallory", revision="a" * 40),
            dict(owner="alice", revision="../outside"),
            dict(owner="alice", revision=7),
            {},
        ]:
            rows.append(
                dict(
                    policy=p,
                    request=dict(operation=op, arguments={"ticket": 7}),
                    facts=facts,
                )
            )
    assert compile_rows(rows) == [
        reference_compile(r["policy"], r["request"], r["facts"]) for r in rows
    ]


def test_native_reads_and_writes_match_reference_wire_and_hide_extra_provider_fields(
    tmp_path,
):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("GET", "/v1/tickets/7")] = dict(
            id=7, secret=TOKEN, email="private@example.org"
        )
        server.routes[("PATCH", "/v1/tickets/7")] = dict(id=7, secret=TOKEN)
        p = policy(tmp_path, server)
        with ManifestCase(tmp_path, server, p, writes="allow") as session:
            assert session.invoke(operation="ticket.view", arguments={"ticket": 7})[
                "result"
            ] == {"id": 7}
            assert session.invoke(
                operation="ticket.edit", arguments={"ticket": 7, "text": "hello"}
            )["result"] == {"id": 7}
            assert [r["method"] for r in server.requests] == ["GET", "PATCH"]
            assert codec.loads(server.requests[1]["body"].encode()) == {"text": "hello"}
            assert all(
                r["headers"]["authorization"] == "Bearer " + TOKEN
                for r in server.requests
            )
            spec = parse_policy(p)
            executor = HTTPSExecutor(spec.egress)
            request = spec.parse_request(
                dict(operation="ticket.edit", arguments={"ticket": 7, "text": "hello"})
            )
            executor.execute(
                AuthorizedEffect(
                    1, "grant", "digest", True, True, spec.final(request, None)
                ),
                TOKEN,
            )
            assert {k: server.requests[1][k] for k in ["method", "target", "body"]} == {
                k: server.requests[2][k] for k in ["method", "target", "body"]
            }
        assert TOKEN.encode() not in (tmp_path / "provider-audit.jsonl").read_bytes()


@pytest.mark.parametrize(
    "operation,args,error",
    [
        ("ticket.view", {"ticket": 9}, "denied"),
        ("ticket.view", {"ticket": "7"}, "denied"),
        ("ticket.view", {"ticket": "../escape"}, "denied"),
        ("ticket.view", {"ticket": True}, "invalid_request"),
        ("ticket.view", {"ticket": 7, "host": "evil.example.org"}, "invalid_request"),
        ("ticket.edit", {"ticket": 7, "text": "hello"}, "denied"),
        ("ticket.close", {"ticket": 7}, "denied"),
        ("other", {}, "denied"),
    ],
)
def test_no_provider_call_for_denied_arguments_or_declared_write(
    tmp_path, operation, args, error
):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        with ManifestCase(tmp_path, server) as session:
            reply = session.invoke(operation=operation, arguments=args)
            assert not reply["ok"] and reply["error"]["code"] == error, reply
            assert not server.requests


def test_native_checked_capture_and_fact_return_have_no_unchecked_second_effect(
    tmp_path,
):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        facts = dict(owner="ALICE", revision="A" * 40, secret=TOKEN, id=7)
        server.routes[("GET", "/v1/tickets/7")] = facts
        server.routes[("GET", "/v1/revisions/" + "a" * 40)] = dict(id=42, secret=TOKEN)
        releases = {
            "revision.view": {"id": {"at": ["id"], "type": "integer"}},
            "ticket.check": {"id": {"at": ["id"], "type": "integer"}},
        }
        with ManifestCase(
            tmp_path, server, checked(policy(tmp_path, server)), releases
        ) as session:
            assert session.invoke(operation="revision.view", arguments={"ticket": 7})[
                "result"
            ] == {"id": 42}
            assert [r["target"] for r in server.requests] == [
                "/v1/tickets/7",
                "/v1/revisions/" + "a" * 40,
            ]
            assert session.invoke(operation="ticket.check", arguments={"ticket": 7})[
                "result"
            ] == {"id": 7}
            assert len(server.requests) == 3
            server.routes[("GET", "/v1/tickets/7")] = dict(
                owner="mallory", revision="a" * 40, id=7
            )
            reply = session.invoke(operation="revision.view", arguments={"ticket": 7})
            assert reply["error"]["code"] == "resource_mismatch"
            assert len(server.requests) == 4


def test_nested_array_release_and_pagination_preserve_only_declared_fields(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("GET", "/v1/tickets?page=1&state=closed")] = dict(
            rows=[dict(id=7, secret=TOKEN), dict(id=8, email="private")]
        )
        with ManifestCase(tmp_path, server) as session:
            reply = session.invoke(
                operation="ticket.list", arguments={"state": "CLOSED"}
            )
            assert reply["result"] == dict(rows=[dict(id=7), dict(id=8)])
            assert reply["meta"] == dict(
                pagination=dict(per_page=2, possibly_more=True, page=1)
            )


def graphql_policy(p):
    p = copy.deepcopy(p)
    p["operations"] = [
        dict(
            name="query.ticket",
            effect="read",
            method="POST",
            path="/graphql",
            parameters={"ticket": [7]},
            graphql=dict(
                document="query Ticket($ticket: Int!) { ticket(id: $ticket) { id } }",
                operation="Ticket",
                variables={"ticket": "ticket"},
            ),
        )
    ]
    return p


def test_pinned_graphql_read_uses_only_host_document_and_allowlisted_variables(
    tmp_path,
):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("POST", "/graphql")] = dict(
            data=dict(ticket=dict(id=7, secret=TOKEN))
        )
        p = graphql_policy(policy(tmp_path, server))
        releases = {
            "query.ticket": {"id": {"at": ["data", "ticket", "id"], "type": "integer"}}
        }
        request = dict(operation="query.ticket", arguments={"ticket": 7})
        assert compile_rows([dict(policy=p, request=request)]) == [
            reference_compile(p, request)
        ]
        with ManifestCase(tmp_path, server, p, releases) as session:
            assert session.invoke(operation="query.ticket", arguments={"ticket": 7})[
                "result"
            ] == {"id": 7}
            body = codec.loads(server.requests[0]["body"].encode())
            assert body == dict(
                query=p["operations"][0]["graphql"]["document"],
                operationName="Ticket",
                variables={"ticket": 7},
            )
            server.routes[("POST", "/graphql")] = dict(
                data=dict(ticket=dict(id=7)), errors=[dict(message=TOKEN)]
            )
            reply = session.invoke(operation="query.ticket", arguments={"ticket": 7})
            assert reply["error"]["code"] == "upstream_response"


@pytest.mark.parametrize("fault", ["error", "malformed", "release"])
def test_sent_write_failure_is_always_uncertain_without_provider_text(tmp_path, fault):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        if fault == "error":
            server.routes[("PATCH", "/v1/tickets/7")] = lambda _: (
                422,
                {},
                codec.dumps(dict(message=TOKEN)),
            )
        elif fault == "malformed":
            server.routes[("PATCH", "/v1/tickets/7")] = lambda _: (200, {}, b"{broken")
        else:
            server.routes[("PATCH", "/v1/tickets/7")] = dict(id=TOKEN)
        with ManifestCase(tmp_path, server, writes="allow") as session:
            reply = session.invoke(
                operation="ticket.edit", arguments={"ticket": 7, "text": "hello"}
            )
            assert not reply["ok"] and reply["error"]["code"] == "outcome_unknown", (
                reply
            )
            assert TOKEN not in json.dumps(reply)
            assert len(server.requests) == 1


def test_reflected_credential_in_approved_text_is_never_returned_or_audited(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("GET", "/v1/tickets/7")] = dict(
            id=7, title="prefix " + TOKEN + " suffix"
        )
        releases = disclosure()
        releases["ticket.view"] = {"title": {"at": ["title"], "type": "text"}}
        with ManifestCase(tmp_path, server, releases=releases) as session:
            reply = session.invoke(operation="ticket.view", arguments={"ticket": 7})
            assert reply["error"]["code"] == "upstream_response"
            assert TOKEN not in json.dumps(reply)
        assert TOKEN.encode() not in (tmp_path / "provider-audit.jsonl").read_bytes()


@pytest.mark.parametrize(
    "where,value",
    [
        ("source", {"kind": "file", "path": "/private/../credential"}),
        (
            "source",
            {"kind": "command", "argv": ["tool"], "inherit_env": ["LD_PRELOAD"]},
        ),
        ("source", {"kind": "command", "argv": []}),
        ("source", {"kind": "command", "argv": ["tool"], "inherit_env": ["OK", "OK"]}),
        ("source", {"kind": "file", "path": "/credential", "extra": True}),
        ("egress", {"port": True}),
        ("egress", {"port": 65536}),
        ("egress", {"address": "127.000.0.1"}),
        ("egress", {"address": "2001:0db8::1"}),
        ("egress", {"ca_file": "relative.pem"}),
        ("headers", {"Authorization": "secret"}),
        ("headers", {"X-Debug": "value\r\nAuthorization: bad"}),
        ("headers", {"X-Debug": " trailing "}),
        ("headers", {"X_Bad": "value"}),
        ("response", True),
        ("response", None),
        ("returns", False),
        ("returns", None),
        ("accept", "Application/Json"),
        ("accept", "application/json; charset=utf-8"),
        ("parameters", {"ticket": [7, True]}),
        ("parameters", {"ticket": [7, 7]}),
        ("parameters", {"ticket": {"min": 8, "max": 7}}),
        ("parameters", {"ticket": ["../outside"]}),
    ],
)
def test_malformed_policy_matches_reference_rejection(tmp_path, where, value):
    p = policy(tmp_path)
    if where == "source":
        p["credential_source"] = value
    elif where in ("egress", "headers"):
        p[where] = value
    else:
        p["operations"][0][where] = value
    request = dict(operation="ticket.view", arguments={"ticket": 7})
    expected = reference_compile(p, request)
    assert expected == dict(ok=False, code="invalid_policy")
    assert compile_rows([dict(policy=p, request=request)]) == [expected]


@pytest.mark.parametrize("value", ["é" * 11, "a" * 21, 42, "", "bad\x00text"])
def test_body_constraints_are_checked_before_any_send(tmp_path, value):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        p = policy(tmp_path, server)
        request = dict(operation="ticket.edit", arguments={"ticket": 7, "text": value})
        expected = reference_compile(p, request)
        assert compile_rows([dict(policy=p, request=request)]) == [expected]
        assert not expected["ok"]
        with ManifestCase(tmp_path, server, p, writes="allow") as session:
            reply = session.invoke(**request)
            assert reply["error"]["code"] == expected["code"]
            assert not server.requests


@pytest.mark.parametrize(
    "status,code",
    [(302, "upstream_error"), (422, "upstream_rejected"), (503, "upstream_error")],
)
def test_read_http_errors_do_not_release_or_follow_provider_diagnostics(
    tmp_path, status, code
):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("GET", "/v1/tickets/7")] = lambda _: (
            status,
            {"Location": "https://evil.example.org/"},
            codec.dumps(dict(message=TOKEN)),
        )
        with ManifestCase(tmp_path, server) as session:
            reply = session.invoke(operation="ticket.view", arguments={"ticket": 7})
            assert reply["error"]["code"] == code
            assert TOKEN not in json.dumps(reply)
            assert len(server.requests) == 1


def test_manifest_keeps_actual_peer_binding_and_renunciation(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("GET", "/v1/tickets/7")] = dict(id=7)
        with ManifestCase(tmp_path, server) as session:
            # This peer has another valid CA-signed certificate and the exact
            # stolen surrogate, but does not own the enrolled bound client key.
            key, _, _ = session.authority.enroll(subject="another-client")
            public = session.authority.call("public-client", subject="another-client")
            other_cert = private(
                tmp_path / "other-client.pem",
                base64.b64decode(public["certificate_pem_b64"]),
            )
            other_key = private(
                tmp_path / "other-client.key",
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
            assert other_cert.read_bytes() != session.certs["client1"][0].read_bytes()
            session.certs["client2"] = (other_cert, other_key, None)
            stolen = session.invoke(
                role="client2", operation="ticket.view", arguments={"ticket": 7}
            )
            assert not stolen["ok"]
            assert not server.requests
            assert session.invoke(operation="ticket.view", arguments={"ticket": 7})[
                "result"
            ] == {"id": 7}
            description = session.invoke(verb="describe")
            assert description["description"]["request_limit"] == "unbounded"
            assert session.invoke(verb="renounce")["renounced"]
            assert not session.invoke(operation="ticket.view", arguments={"ticket": 7})[
                "ok"
            ]
            assert len(server.requests) == 1


def test_secret_capture_never_becomes_a_route_or_an_audit_coordinate(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        p = checked(policy(tmp_path, server))
        p["checks"]["ticket"]["bind"]["revision"]["format"] = "segment"
        server.routes[("GET", "/v1/tickets/7")] = dict(owner="alice", revision=TOKEN)
        releases = {
            op["name"]: {"id": {"at": ["id"], "type": "integer"}}
            for op in p["operations"]
        }
        with ManifestCase(tmp_path, server, p, releases) as session:
            reply = session.invoke(operation="revision.view", arguments={"ticket": 7})
            assert reply["error"]["code"] == "upstream_response"
            assert len(server.requests) == 1
        assert TOKEN.encode() not in (tmp_path / "provider-audit.jsonl").read_bytes()


def test_oauth_revocation_drains_manifest_dispatch_and_blocks_further_uses(tmp_path):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    from tests.test_rust_garrett_oauth_vault import VaultCase

    vault = VaultCase(tmp_path)
    stamp = int(time.time())
    vault.enroll(access_token=TOKEN, expires_at=stamp + 3600)
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        entered, release = threading.Event(), threading.Event()

        def blocked(_):
            entered.set()
            assert release.wait(10)
            return 200, {}, b'{"id":7}'

        server.routes[("GET", "/v1/tickets/7")] = blocked
        source = dict(
            vault_root=str(vault.root),
            provider_file=str(vault.provider_file),
            subject="vm-test",
        )
        with ManifestCase(
            tmp_path,
            server,
            oauth=source,
            credential_file=None,
            source_override="oauth",
        ) as session:
            with ThreadPoolExecutor(max_workers=2) as pool:
                use = pool.submit(
                    session.invoke, operation="ticket.view", arguments={"ticket": 7}
                )
                try:
                    assert entered.wait(5)
                    revoke = pool.submit(vault.call, "revoke", now=stamp)
                    time.sleep(0.15)
                    assert not revoke.done()
                finally:
                    release.set()
                assert use.result(timeout=10)["result"] == {"id": 7}
                revoke.result(timeout=10)
            assert not session.invoke(operation="ticket.view", arguments={"ticket": 7})[
                "ok"
            ]
            assert len(server.requests) == 1
        vault.audit()


def test_waiting_for_facts_cannot_extend_identity_or_grant_lifetime(tmp_path):
    import time

    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        cutoff = []

        def expires_during_preflight(_):
            time.sleep(max(0, cutoff[0] - time.time() + 0.05))
            return 200, {}, codec.dumps(dict(owner="alice", revision="a" * 40, id=7))

        server.routes[("GET", "/v1/tickets/7")] = expires_during_preflight
        p = checked(policy(tmp_path, server))
        releases = {
            op["name"]: {"id": {"at": ["id"], "type": "integer"}}
            for op in p["operations"]
        }
        with ManifestCase(tmp_path, server, p, releases, lifetime=3) as session:
            cutoff.append(session.expires_at)
            reply = session.invoke(operation="revision.view", arguments={"ticket": 7})
            assert reply["error"]["code"] == "invalid_capability"
            assert len(server.requests) == 1


@pytest.mark.parametrize(
    "arguments", [True, {"ticket": True}, {"Bad": 1}, {"ticket": -1}, {"ticket": ""}]
)
def test_invalid_unknown_operation_is_still_parsed_like_reference(tmp_path, arguments):
    p = policy(tmp_path)
    request = dict(operation="unknown", arguments=arguments)
    expected = reference_compile(p, request)
    assert expected == dict(ok=False, code="invalid_request")
    assert compile_rows([dict(policy=p, request=request)]) == [expected]


def test_total_utf8_body_limit_is_enforced_in_addition_to_field_limits(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        p = policy(tmp_path, server)
        p["max_body_bytes"] = 3
        request = dict(operation="ticket.edit", arguments={"ticket": 7, "text": "éé"})
        expected = reference_compile(p, request)
        assert expected == dict(ok=False, code="denied")
        assert compile_rows([dict(policy=p, request=request)]) == [expected]
        with ManifestCase(tmp_path, server, p, writes="allow") as session:
            assert session.invoke(**request)["error"]["code"] == "denied"
            assert not server.requests


@pytest.mark.parametrize("kind", ["text", "json"])
def test_empty_write_reply_obeys_explicit_response_type(tmp_path, kind):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("PATCH", "/v1/tickets/7")] = lambda _: (204, {}, b"")
        p = policy(tmp_path, server)
        p["operations"][1]["response"] = kind
        releases = disclosure()
        releases["ticket.edit"] = {"message": {"at": [], "type": "text"}}
        with ManifestCase(tmp_path, server, p, releases, writes="allow") as session:
            reply = session.invoke(
                operation="ticket.edit", arguments={"ticket": 7, "text": "hello"}
            )
            if kind == "text":
                assert reply["result"] == {"message": ""}
            else:
                assert reply["error"]["code"] == "outcome_unknown"
            assert len(server.requests) == 1


def test_manifest_static_headers_and_api_key_are_host_selected(tmp_path, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "forbidden-keylog"))
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        p = policy(tmp_path, server)
        p["authentication"] = "x-api-key"
        p["headers"] = {"X-Provider-Version": "2026-10"}
        server.routes[("GET", "/v1/tickets/7")] = dict(id=7, token=TOKEN)
        with ManifestCase(tmp_path, server, p, authentication="x-api-key") as session:
            assert session.invoke(operation="ticket.view", arguments={"ticket": 7})[
                "result"
            ] == {"id": 7}
            assert server.requests[0]["headers"]["x-api-key"] == TOKEN
            assert "authorization" not in server.requests[0]["headers"]
            assert server.requests[0]["headers"]["x-provider-version"] == "2026-10"
        assert not (tmp_path / "forbidden-keylog").exists()


@pytest.mark.parametrize("write", [False, True])
def test_projection_expansion_is_bounded_before_returning_a_large_response(
    tmp_path, write
):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        method, operation = (
            ("PATCH", "ticket.edit") if write else ("GET", "ticket.view")
        )
        server.routes[(method, "/v1/tickets/7")] = dict(id=7, title="x" * 16000)
        releases = disclosure()
        fields = {f"title{n}": {"at": ["title"], "type": "text"} for n in range(32)}
        releases[operation] = {
            f"copy{n}": {"at": [], "type": "object", "fields": fields} for n in range(5)
        }
        with ManifestCase(
            tmp_path, server, releases=releases, writes="allow"
        ) as session:
            args = {"ticket": 7, **({"text": "hello"} if write else {})}
            reply = session.invoke(operation=operation, arguments=args)
            assert reply["error"]["code"] == (
                "outcome_unknown" if write else "upstream_response"
            )
            assert len(server.requests) == 1
