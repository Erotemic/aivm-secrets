"""Normal native PKCE login, hostile callbacks and independent vault readers."""

from __future__ import annotations

import base64
import hashlib
import http.client
import select
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from aivm_secrets.primitives import codec
from aivm_secrets.identity.garrett.oauth_contract import PendingAuthorization
from aivm_secrets.identity.oauth_transport import authorization_url
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
from tests.test_rust_garrett_oauth_vault import (
    ACCESS,
    REFRESH,
    SUCCESSOR,
    NEXT_REFRESH,
    VaultCase,
    profile,
    response,
)
from tests.test_rust_garrett_provider import provider_directory

CODE = "SYNTHETIC-AUTHORIZATION-CODE-PRIVATE&="


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def vault(directory, **changes):
    return VaultCase(directory, provider=profile(callback_port=free_port(), **changes))


class Login:
    def __init__(self, case, endpoint, **options):
        self.case = case
        self.command = case.command(
            "login",
            provider_file=str(case.provider_file),
            subject="vm-test",
            transport=case.transport(endpoint),
            **{"timeout": 12, **options},
        )

    def __enter__(self):
        self.child = subprocess.Popen(
            self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            ready, _, _ = select.select([self.child.stdout], [], [], 8)
            assert ready, "native login did not announce its bound callback"
            self.event = codec.loads(self.child.stdout.readline())
            assert self.event["event"] == "authorization_required", self.event
            assert set(self.event) == {
                "version",
                "event",
                "authorization_url",
                "expires_at",
            }
            self.url = self.event["authorization_url"]
            self.query = parse_qs(urlsplit(self.url).query)
            self.port = urlsplit(self.query["redirect_uri"][0]).port
            self.state = self.query["state"][0]
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def visit(self, fields=None, *, target=None, headers=None, method="GET", timeout=8):
        if target is None:
            target = "/oauth/callback?" + urlencode(
                fields or {"code": CODE, "state": self.state}
            )
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, target, headers=headers or {})
            reply = conn.getresponse()
            body = reply.read()
            assert CODE.encode() not in body and self.state.encode() not in body
            return reply.status, dict(reply.getheaders()), body
        finally:
            conn.close()

    def finish(self, *, error=None, reason=None):
        output, stderr = self.child.communicate(timeout=20)
        assert not stderr, stderr
        for secret in (CODE, ACCESS, REFRESH, SUCCESSOR, NEXT_REFRESH, TOKEN):
            assert secret.encode() not in output
        reply = codec.loads(output)
        assert reply["version"] == 1
        if error is None:
            assert self.child.returncode == 0 and reply["ok"], reply
            return reply["result"]
        assert self.child.returncode == 1 and not reply["ok"], reply
        assert reply["error"]["code"] == error, reply
        if reason is not None:
            assert reply["error"]["reason"] == reason, reply
        return reply["error"]

    def __exit__(self, *exc):
        if self.child.poll() is None:
            self.child.terminate()
        self.child.communicate(timeout=5)


def test_actual_pkce_exchange_installs_python_readable_grant_without_secret_output(
    tmp_path,
):
    case = vault(tmp_path)
    observed = []
    with TLSService(tmp_path, host="login.example.org") as endpoint:

        def issue(seen):
            form = parse_qs(seen["body"])
            observed.append(form)
            assert form["grant_type"] == ["authorization_code"]
            assert form["code"] == [CODE]
            assert seen["headers"]["host"] == "login.example.org"
            return 200, {}, codec.dumps(response())

        endpoint.routes[("POST", "/token")] = issue
        with Login(case, endpoint) as login:
            assert login.query["client_id"] == ["test-client"]
            assert login.query["scope"] == ["read"]
            assert login.query["code_challenge_method"] == ["S256"]
            assert "code_verifier" not in login.query
            assert len(login.state) == 43
            assert login.visit()[0] == 200
            result = login.finish()
            form = observed[0]
            verifier = form["code_verifier"][0]
            expected = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )
            assert login.query["code_challenge"] == [expected]
            assert form["redirect_uri"] == login.query["redirect_uri"]
            assert verifier not in login.url
            reference_pending = PendingAuthorization.create(
                login.state,
                verifier,
                form["redirect_uri"][0],
                now=login.event["expires_at"] - 12,
                ttl=12,
            )
            assert authorization_url(case.provider, reference_pending) == login.url
    assert len(observed) == 1
    assert result["epoch"] == 0 and result["scopes"] == ["read"]
    row = case.row()
    assert row["grant"]["access_token"] == SUCCESSOR
    assert row["grant"]["refresh_token"] == NEXT_REFRESH
    assert row["grant"]["generation"] == 0
    assert row["provider_digest"] == case.provider.digest
    for file in (case.root / "audit").glob("*.jsonl"):
        assert (
            CODE.encode() not in file.read_bytes()
            and verifier.encode() not in file.read_bytes()
        )
    case.audit()


@pytest.mark.parametrize(
    "noise",
    [
        "wrong_state",
        "missing_issuer",
        "wrong_issuer",
        "duplicate_state",
        "unknown_field",
        "both_code_and_error",
        "host",
        "fragment",
        "absolute_uri",
        "wrong_path",
        "post",
        "request_body",
        "duplicate_host",
        "wrong_denial",
    ],
)
def test_hostile_callback_does_not_consume_or_cancel_valid_login(tmp_path, noise):
    issuer = "https://login.example.org/issuer"
    case = vault(tmp_path, issuer_response=issuer)
    with TLSService(tmp_path, host="login.example.org") as endpoint:
        endpoint.routes[("POST", "/token")] = response()
        with Login(case, endpoint) as login:
            fields = {"code": CODE, "state": login.state, "iss": issuer}
            target, headers, method = None, {}, "GET"
            if noise == "wrong_state":
                fields["state"] = "x" * 43
            elif noise == "missing_issuer":
                fields.pop("iss")
            elif noise == "wrong_issuer":
                fields["iss"] = "https://other.example.org/issuer"
            elif noise == "duplicate_state":
                target = (
                    "/oauth/callback?" + urlencode(fields) + "&state=" + login.state
                )
            elif noise == "unknown_field":
                fields["redirect_uri"] = "https://other.example.org/"
            elif noise == "both_code_and_error":
                fields["error"] = "access_denied"
            elif noise == "host":
                headers["Host"] = "other.example.org"
            elif noise == "fragment":
                target = "/oauth/callback?" + urlencode(fields) + "#tail"
            elif noise == "absolute_uri":
                target = "https://other.example.org/oauth/callback?" + urlencode(fields)
            elif noise == "wrong_path":
                target = "/wrong?" + urlencode(fields)
            elif noise == "post":
                method = "POST"
            elif noise == "request_body":
                headers["Content-Length"] = "1"
            elif noise == "duplicate_host":
                target = "/oauth/callback?" + urlencode(fields)
                raw = (
                    f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{login.port}\r\nhost: other.example.org\r\n\r\n"
                ).encode()
                with socket.create_connection(
                    ("127.0.0.1", login.port), timeout=3
                ) as connection:
                    connection.sendall(raw)
                    assert b" 400 " in connection.recv(4096)
            elif noise == "wrong_denial":
                fields = {"error": "access_denied", "state": "x" * 43, "iss": issuer}
            if noise != "duplicate_host":
                assert (
                    login.visit(fields, target=target, headers=headers, method=method)[
                        0
                    ]
                    == 400
                )
            assert login.child.poll() is None
            assert not endpoint.requests
            assert (
                login.visit({"code": CODE, "state": login.state, "iss": issuer})[0]
                == 200
            )
            login.finish()
        assert len(endpoint.requests) == 1


def test_unexpected_issuer_is_refused_when_profile_has_none(tmp_path):
    case = vault(tmp_path)
    with TLSService(tmp_path, host="login.example.org") as endpoint:
        endpoint.routes[("POST", "/token")] = response()
        with Login(case, endpoint) as login:
            assert (
                login.visit(
                    {
                        "code": CODE,
                        "state": login.state,
                        "iss": "https://login.example.org/issuer",
                    }
                )[0]
                == 400
            )
            assert login.visit()[0] == 200
            login.finish()
        assert len(endpoint.requests) == 1


def test_matching_provider_denial_stops_without_secret_text_or_exchange(tmp_path):
    issuer = "https://login.example.org/issuer"
    case = vault(tmp_path, issuer_response=issuer)
    with TLSService(tmp_path, host="login.example.org") as endpoint:
        with Login(case, endpoint) as login:
            status, headers, body = login.visit(
                {
                    "state": login.state,
                    "error": "access_denied",
                    "iss": issuer,
                    "error_description": CODE,
                    "error_uri": "https://example.org/" + ACCESS,
                }
            )
            assert status == 200 and headers["Cache-Control"] == "no-store"
            assert headers["Referrer-Policy"] == "no-referrer"
            assert CODE.encode() not in body and ACCESS.encode() not in body
            login.finish(error="credential_source", reason="authorization_denied")
        assert not endpoint.requests
    assert not list(case.root.glob("*.json"))


@pytest.mark.parametrize("idle", [True, False])
def test_absolute_login_deadline_cuts_idle_and_trickling_clients(tmp_path, idle):
    case = vault(tmp_path)
    stop = threading.Event()
    with TLSService(tmp_path, host="login.example.org") as endpoint:
        with Login(case, endpoint, timeout=1) as login:
            connection = socket.create_connection(("127.0.0.1", login.port), timeout=2)

            def drip():
                for byte in b"GET /oauth/callback?" + b"x" * 100:
                    if stop.wait(0.05):
                        return
                    try:
                        connection.send(bytes([byte]))
                    except OSError:
                        return

            if not idle:
                threading.Thread(target=drip, daemon=True).start()
            started = time.monotonic()
            try:
                login.finish(error="expired")
                assert time.monotonic() - started < 2
            finally:
                stop.set()
                connection.close()
        assert not endpoint.requests


def test_slow_callback_is_cut_so_a_queued_valid_callback_can_succeed(tmp_path):
    case = vault(tmp_path)
    with TLSService(tmp_path, host="login.example.org") as endpoint:
        endpoint.routes[("POST", "/token")] = response()
        with Login(case, endpoint, timeout=12) as login:
            connection = socket.create_connection(("127.0.0.1", login.port), timeout=2)
            connection.sendall(b"GET /oauth/callback?")
            time.sleep(0.05)
            started = time.monotonic()
            try:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    visit = pool.submit(login.visit)
                    assert visit.result(timeout=8)[0] == 200
                login.finish()
                assert time.monotonic() - started < 7
            finally:
                connection.close()
        assert len(endpoint.requests) == 1


def test_preflight_occupied_subject_precedes_busy_port_or_browser_announcement(
    tmp_path,
):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        case = VaultCase(
            tmp_path, provider=profile(callback_port=busy.getsockname()[1])
        )
        case.enroll()
        case.call("login", timeout=1, error="denied")


def test_busy_callback_port_has_fixed_error_and_sends_nothing(tmp_path):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        case = VaultCase(
            tmp_path, provider=profile(callback_port=busy.getsockname()[1])
        )
        with TLSService(tmp_path, host="login.example.org") as endpoint:
            error = case.call(
                "login",
                timeout=1,
                transport=case.transport(endpoint),
                error="credential_source",
            )
            assert error["reason"] == "callback_port_unavailable"
            assert not endpoint.requests


@pytest.mark.parametrize(
    "kind", ["redirect", "invalid_grant", "scope", "truncated", "non_bearer"]
)
def test_exchange_failure_is_fixed_and_does_not_install_or_retry(tmp_path, kind):
    case = vault(tmp_path)
    with TLSService(tmp_path, host="login.example.org") as endpoint:
        if kind == "redirect":
            route = lambda _: (
                302,
                {"Location": "https://other.example.org/token"},
                b"",
            )
        elif kind == "invalid_grant":
            route = lambda _: (400, {}, b'{"error":"invalid_grant"}')
        elif kind == "scope":
            route = response(scope="read write")
        elif kind == "truncated":
            route = lambda _: (200, {"Content-Length": "999"}, b"")
        else:
            route = response(token_type="MAC")
        endpoint.routes[("POST", "/token")] = route
        with Login(case, endpoint) as login:
            assert login.visit()[0] == 200
            expected = (
                "exchange_rejected" if kind == "invalid_grant" else "exchange_in_doubt"
            )
            login.finish(error="credential_source", reason=expected)
            with pytest.raises(OSError):
                socket.create_connection(("127.0.0.1", login.port), timeout=1)
        assert len(endpoint.requests) == 1
    assert not list(case.root.glob("*.json"))


def test_wrong_tls_identity_is_definitely_not_sent(tmp_path):
    case = vault(tmp_path)
    with TLSService(tmp_path, host="wrong.example.org") as endpoint:
        with Login(case, endpoint) as login:
            assert login.visit()[0] == 200
            login.finish(error="credential_source", reason="exchange_not_sent")
        assert not endpoint.requests


@pytest.mark.parametrize("failure", ["race", "storage"])
def test_successful_exchange_with_failed_install_reports_orphan_without_overwrite(
    tmp_path, failure
):
    case = vault(tmp_path)
    with TLSService(tmp_path, host="login.example.org") as endpoint:

        def issue(_):
            if failure == "race":
                case.enroll(python=True)
            else:
                case.root.chmod(0o500)
            return 200, {}, codec.dumps(response())

        endpoint.routes[("POST", "/token")] = issue
        try:
            with Login(case, endpoint) as login:
                assert login.visit()[0] == 200
                login.finish(
                    error="denied" if failure == "race" else "unsafe_file",
                    reason="grant_orphaned_upstream",
                )
        finally:
            case.root.chmod(0o700)
        assert len(endpoint.requests) == 1
    if failure == "race":
        assert case.row()["grant"]["access_token"] == ACCESS
    else:
        assert not list(case.root.glob("*.json"))


def test_explicit_reauthorization_advances_epoch_and_resets_grant_generation(tmp_path):
    case = vault(tmp_path)
    case.enroll(generation=8)
    with TLSService(tmp_path, host="login.example.org") as endpoint:
        endpoint.routes[("POST", "/token")] = response()
        with Login(case, endpoint, replace=True) as login:
            login.visit()
            assert login.finish()["epoch"] == 1
    row = case.row()
    assert row["epoch"] == 1 and row["grant"]["generation"] == 0
    assert row["grant"]["access_token"] == SUCCESSOR


def test_native_login_to_provider_action_never_requires_a_plaintext_grant_file(
    tmp_path,
):
    case = vault(tmp_path)
    authdir = tmp_path / "oauth-service"
    authdir.mkdir(mode=0o700)
    with TLSService(authdir, host="login.example.org") as endpoint:
        endpoint.routes[("POST", "/token")] = response(access_token=TOKEN)
        with Login(case, endpoint) as login:
            login.visit()
            login.finish()
    assert not (tmp_path / "grant.json").exists()
    authority = AuthorityCase(tmp_path)
    with TLSService(provider_directory(tmp_path), host="api.example.org") as resource:
        resource.routes[("GET", "/v1/account")] = {
            "id": 42,
            "active": True,
            "secret": TOKEN,
        }
        source = {
            "vault_root": str(case.root),
            "provider_file": str(case.provider_file),
            "subject": "vm-test",
        }
        with AuthorityProviderCase(
            tmp_path, resource, authority, oauth=source, credential_file=None
        ) as session:
            assert session.invoke()["result"] == {"id": 42, "active": True}
        assert resource.requests[0]["headers"]["authorization"] == "Bearer " + TOKEN


def test_accepted_callback_cannot_redeem_again_while_exchange_is_blocked(tmp_path):
    case = vault(tmp_path)
    entered, release = threading.Event(), threading.Event()
    with TLSService(tmp_path, host="login.example.org") as endpoint:

        def issue(_):
            entered.set()
            assert release.wait(10)
            return 200, {}, codec.dumps(response())

        endpoint.routes[("POST", "/token")] = issue
        with Login(case, endpoint) as login:
            try:
                assert login.visit()[0] == 200
                assert entered.wait(5)
                with pytest.raises(OSError):
                    socket.create_connection(("127.0.0.1", login.port), timeout=1)
                assert login.child.poll() is None
                assert len(endpoint.requests) == 1
            finally:
                release.set()
            login.finish()
        assert len(endpoint.requests) == 1
