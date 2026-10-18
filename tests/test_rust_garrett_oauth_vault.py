"""Native OAuth custody against the independent Python store and real HTTPS."""

from __future__ import annotations

import fcntl
import os
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs

import pytest

from aivm_secrets.host.audit import verify
from aivm_secrets.identity.garrett.oauth_contract import parse_grant
from aivm_secrets.identity.oauth_provider import OAuthProvider
from aivm_secrets.identity.oauth_vault import OAuthVault
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import (
    AuthorityCase,
    AuthorityProviderCase,
    private,
)
from tests.test_rust_garrett_provider import provider_directory

ACCESS = "SYNTHETIC-OAUTH-ACCESS-PRIVATE"
REFRESH = "SYNTHETIC-OAUTH-REFRESH-PRIVATE"
SUCCESSOR = "SYNTHETIC-OAUTH-SUCCESSOR-PRIVATE"
NEXT_REFRESH = "SYNTHETIC-OAUTH-ROTATED-PRIVATE"


def profile(**changes):
    fields = {
        "schema": 1,
        "name": "synthetic",
        "client_id": "test-client",
        "authorization_url": "https://login.example.org/authorize",
        "token_url": "https://login.example.org/token",
        "resource_host": "api.example.org",
        "callback_port": 18765,
        "scopes": ["read"],
    }
    fields.update(changes)
    return OAuthProvider.parse(fields)


class VaultCase:
    def __init__(self, directory, *, python_init=False, provider=None):
        self.directory = directory
        self.root = directory / "vault"
        self.provider = provider or profile()
        self.provider_file = private(
            directory / "provider.json", self.provider.canonical()
        )
        self.binary = executable("AIVM_SECRETS_RUST_OAUTH_ADMIN")
        if python_init:
            OAuthVault.initialize(self.root)
        else:
            self.call("init", raw={})
        self.reference = OAuthVault(self.root)

    def command(self, action, **fields):
        handle, name = tempfile.mkstemp(dir=self.directory, prefix="oauth-request-")
        with os.fdopen(handle, "wb") as stream:
            stream.write(codec.dumps(fields))
        return [self.binary, action, "--root", str(self.root), "--request", name]

    def call(self, action, *, error=None, raw=None, **fields):
        if raw is None:
            raw = dict(
                provider_file=str(self.provider_file), subject="vm-test", **fields
            )
        result = subprocess.run(
            self.command(action, **raw), capture_output=True, timeout=25, check=False
        )
        assert result.returncode in (0, 1), result.stderr
        assert not result.stderr
        reply = codec.loads(result.stdout)
        for token in (ACCESS, REFRESH, SUCCESSOR, NEXT_REFRESH):
            assert token.encode() not in result.stdout
        if error is None:
            assert reply["ok"] and result.returncode == 0, reply
            return reply["result"]
        assert not reply["ok"] and result.returncode == 1, reply
        assert reply["error"]["code"] == error, reply
        return reply["error"]

    def enroll(self, *, python=False, **changes):
        grant = {
            "access_token": ACCESS,
            "refresh_token": REFRESH,
            "expires_at": 10000,
            "scopes": ["read"],
            "generation": 0,
        }
        grant.update(changes)
        if python:
            return self.reference.enroll(self.provider, "vm-test", parse_grant(grant))
        path = private(self.directory / "grant.json", grant)
        return self.call("enroll", grant_file=str(path), now=100)

    def row(self):
        return self.reference._read(self.provider, "vm-test")

    def transport(self, server):
        return {
            "address": "127.0.0.1",
            "port": server.port,
            "server_ca": str(server.files["ca"]),
        }

    def audit(self):
        for path in (self.root / "audit").glob("*.jsonl"):
            assert verify(path)[0] > 0
            for token in (ACCESS, REFRESH, SUCCESSOR, NEXT_REFRESH):
                assert token.encode() not in path.read_bytes()


@pytest.mark.parametrize("python_init", [False, True])
@pytest.mark.parametrize("python_enroll", [False, True])
def test_native_vault_cross_language_storage_and_revocation(
    tmp_path, python_init, python_enroll
):
    case = VaultCase(tmp_path, python_init=python_init)
    case.enroll(python=python_enroll)
    assert case.call("status") == case.reference.status(case.provider, "vm-test")
    assert case.row()["grant"]["access_token"] == ACCESS
    assert case.call("session-check", resource_host="api.example.org", now=100) == {
        "epoch": 0,
        "generation": 0,
        "expires_at": 10000,
    }
    case.call(
        "session-check",
        resource_host="other.example.org",
        now=100,
        error="credential_source",
    )
    case.call("revoke", now=100)
    assert case.call("status") == case.reference.status(case.provider, "vm-test")
    case.call(
        "session-check", resource_host="api.example.org", now=100, error="revoked"
    )
    case.audit()
    for path in case.root.glob("*.json"):
        assert ACCESS.encode() not in path.read_bytes()
        assert REFRESH.encode() not in path.read_bytes()


def test_profile_change_can_inspect_and_revoke_but_cannot_use(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll()
    old_digest = case.provider.digest
    case.provider = profile(client_id="replacement-client")
    private(case.provider_file, case.provider.canonical())
    status = case.call("status")
    assert status == case.reference.status(case.provider, "vm-test")
    assert not status["profile_current"]
    case.call(
        "session-check",
        resource_host="api.example.org",
        now=100,
        error="credential_source",
    )
    case.call("refresh", now=100, error="credential_source")
    case.call("revoke", now=100)
    assert case.call("status")["previous_digest"] == old_digest[:16]
    assert case.call("status")["profile_current"]


@pytest.mark.parametrize("change", ["ciphertext", "schema", "symlink", "mode"])
def test_authenticated_and_owned_files_required(tmp_path, change):
    case = VaultCase(tmp_path)
    case.enroll()
    record = next(case.root.glob("*.json"))
    if change in ("ciphertext", "schema"):
        value = codec.loads(record.read_bytes())
        value[change] = "AAAA" if change == "ciphertext" else 1
        private(record, value)
        error = "credential_source"
    elif change == "symlink":
        other = tmp_path / "record-copy"
        record.rename(other)
        record.symlink_to(other)
        error = "unsafe_file"
    else:
        record.chmod(0o644)
        error = "unsafe_file"
    case.call("status", error=error)


def response(**changes):
    value = {
        "access_token": SUCCESSOR,
        "refresh_token": NEXT_REFRESH,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read",
    }
    value.update(changes)
    return value


def test_refresh_quarantines_before_real_https_and_records_rotated_successor(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll()
    observed = []
    with TLSService(tmp_path, host="login.example.org") as server:

        def respond(seen):
            observed.append(case.row()["refresh_state"])
            form = parse_qs(seen["body"])
            assert form == {
                "grant_type": ["refresh_token"],
                "client_id": ["test-client"],
                "refresh_token": [REFRESH],
            }
            assert seen["headers"]["host"] == "login.example.org"
            return 200, {}, codec.dumps(response())

        server.routes[("POST", "/token")] = respond
        result = case.call("refresh", now=100, transport=case.transport(server))
    assert observed == ["in_doubt"]
    assert result == case.reference.status(case.provider, "vm-test")
    row = case.row()
    assert row["grant"] == {
        "access_token": SUCCESSOR,
        "refresh_token": NEXT_REFRESH,
        "expires_at": 3700,
        "scopes": ["read"],
        "generation": 1,
    }
    assert row["refresh_state"] == "none"
    case.audit()


@pytest.mark.parametrize(
    "kind", ["invalid_grant", "redirect", "malformed", "scope", "no_rotation"]
)
def test_provider_failure_never_silently_replays_refresh(tmp_path, kind):
    case = VaultCase(tmp_path)
    case.enroll()
    with TLSService(tmp_path, host="login.example.org") as server:
        if kind == "invalid_grant":
            route = lambda _: (400, {}, b'{"error":"invalid_grant"}')
        elif kind == "redirect":
            route = lambda _: (
                302,
                {"Location": "https://other.example.org/token"},
                b"",
            )
        elif kind == "malformed":
            route = lambda _: (200, {}, b"{broken")
        elif kind == "scope":
            route = response(scope="read write")
        else:
            route = response(refresh_token=REFRESH)
        server.routes[("POST", "/token")] = route
        failure = case.call(
            "refresh",
            now=100,
            transport=case.transport(server),
            error="credential_source",
        )
        expected = "reauth_required" if kind == "invalid_grant" else "in_doubt"
        assert case.row()["refresh_state"] == expected
        assert failure["reason"] in ("refresh_rejected", "refresh_in_doubt")
        case.call(
            "refresh",
            now=101,
            transport=case.transport(server),
            error="credential_source",
        )
        case.call(
            "session-check",
            resource_host="api.example.org",
            now=101,
            transport=case.transport(server),
            error="credential_source",
        )
        if kind == "invalid_grant":
            case.call(
                "refresh",
                now=101,
                retry_in_doubt=True,
                transport=case.transport(server),
                error="credential_source",
            )
        assert len(server.requests) == 1
    case.audit()


def test_definite_not_sent_restores_prior_state_including_explicit_retry(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll()
    # The server certificate cannot authenticate the pinned token-endpoint name.
    with TLSService(tmp_path, host="wrong.example.org") as server:
        transport = case.transport(server)
        assert (
            case.call(
                "refresh", now=100, transport=transport, error="credential_source"
            )["reason"]
            == "refresh_not_sent"
        )
        assert case.row()["refresh_state"] == "none"
        row = case.row()
        row["refresh_state"] = "in_doubt"
        case.reference._write(case.provider, "vm-test", row)
        case.call(
            "refresh",
            now=100,
            retry_in_doubt=True,
            transport=transport,
            error="credential_source",
        )
        assert case.row()["refresh_state"] == "in_doubt"
        assert not server.requests


def test_killed_refresh_leaves_durable_marker_and_requires_deliberate_retry(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll()
    entered, release = threading.Event(), threading.Event()
    with TLSService(tmp_path, host="login.example.org") as server:

        def blocked(_):
            assert case.row()["refresh_state"] == "in_doubt"
            entered.set()
            assert release.wait(10)
            return 200, {}, codec.dumps(response())

        server.routes[("POST", "/token")] = blocked
        command = case.command(
            "refresh",
            provider_file=str(case.provider_file),
            subject="vm-test",
            now=100,
            transport=case.transport(server),
        )
        child = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            assert entered.wait(10)
            child.kill()
            child.communicate(timeout=5)
        finally:
            child.kill()
            release.set()
        assert case.row()["refresh_state"] == "in_doubt"
        case.call(
            "refresh",
            now=101,
            transport=case.transport(server),
            error="credential_source",
        )
        assert len(server.requests) == 1
        server.routes[("POST", "/token")] = response()
        case.call(
            "refresh", now=102, retry_in_doubt=True, transport=case.transport(server)
        )
        assert len(server.requests) == 2
        assert case.row()["refresh_state"] == "none"
        assert case.row()["grant"]["generation"] == 1


def test_native_provider_uses_oauth_without_returning_it_and_revocation_drains(
    tmp_path,
):
    directory = tmp_path
    case = VaultCase(directory)
    stamp = int(time.time())
    case.enroll(access_token=TOKEN, expires_at=stamp + 3600)
    authority = AuthorityCase(directory)
    with TLSService(provider_directory(directory), host="api.example.org") as server:
        server.routes[("GET", "/v1/account")] = {
            "id": 42,
            "active": True,
            "token": TOKEN,
        }
        source = {
            "vault_root": str(case.root),
            "provider_file": str(case.provider_file),
            "subject": "vm-test",
        }
        # The legacy source must be explicitly absent; no fallback is permitted.
        with AuthorityProviderCase(
            directory, server, authority, oauth=source, credential_file=None
        ) as session:
            reply = session.invoke()
            assert reply.get("result") == {"id": 42, "active": True}, reply
            assert server.requests[0]["headers"]["authorization"] == "Bearer " + TOKEN
            entered, release = threading.Event(), threading.Event()

            def blocked(_):
                entered.set()
                assert release.wait(10)
                return 200, {}, b'{"id":42,"active":true}'

            server.routes[("GET", "/v1/account")] = blocked
            with ThreadPoolExecutor(max_workers=2) as pool:
                use = pool.submit(session.invoke)
                assert entered.wait(5)
                revoke = pool.submit(case.call, "revoke", now=stamp)
                time.sleep(0.15)
                assert not revoke.done()
                release.set()
                assert use.result(timeout=10)["ok"]
                revoke.result(timeout=10)
            assert not session.invoke()["ok"]
            assert len(server.requests) == 2


def test_successor_persistence_failure_keeps_spent_token_quarantined(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll()
    with TLSService(tmp_path, host="login.example.org") as server:

        def deny_successor_write(_):
            assert case.row()["refresh_state"] == "in_doubt"
            case.root.chmod(0o500)
            return 200, {}, codec.dumps(response())

        server.routes[("POST", "/token")] = deny_successor_write
        try:
            failure = case.call(
                "refresh",
                now=100,
                transport=case.transport(server),
                error="credential_source",
            )
            assert failure["reason"] == "refresh_in_doubt"
        finally:
            case.root.chmod(0o700)
        assert case.row()["refresh_state"] == "in_doubt"
        assert case.row()["grant"]["access_token"] == ACCESS
        case.call(
            "refresh",
            now=101,
            transport=case.transport(server),
            error="credential_source",
        )
        assert len(server.requests) == 1
    case.audit()


@pytest.mark.parametrize("change", ["refresh", "same_metadata_new_token"])
def test_native_session_uses_current_token_until_enrollment_is_revoked(tmp_path, change):
    case = VaultCase(tmp_path)
    stamp = int(time.time())
    case.enroll(access_token=TOKEN, expires_at=stamp + 3600)
    authority = AuthorityCase(tmp_path)
    provider_dir = provider_directory(tmp_path)
    token_dir = tmp_path / "tokens"
    token_dir.mkdir(mode=0o700)
    with (
        TLSService(provider_dir, host="api.example.org") as resource,
        TLSService(token_dir, host="login.example.org") as endpoint,
    ):
        resource.routes[("GET", "/v1/account")] = {"id": 42, "active": True}
        endpoint.routes[("POST", "/token")] = response()
        source = {
            "vault_root": str(case.root),
            "provider_file": str(case.provider_file),
            "subject": "vm-test",
        }
        with AuthorityProviderCase(
            tmp_path, resource, authority, oauth=source, credential_file=None
        ) as session:
            assert session.invoke()["ok"]
            if change == "refresh":
                case.call("refresh", now=stamp, transport=case.transport(endpoint))
            else:
                row = case.row()
                row["grant"]["access_token"] = SUCCESSOR
                case.reference._write(case.provider, "vm-test", row)
            # This intentionally follows Python's new current-epoch contract:
            # a trusted owner may update the vault credential without ending
            # the session. The independent session marker still pins epoch.
            assert session.invoke()["ok"]
            assert resource.requests[-1]["headers"]["authorization"] == "Bearer " + SUCCESSOR
            case.call("revoke", now=stamp)
            assert not session.invoke()["ok"]
            assert len(resource.requests) == 2


@pytest.mark.parametrize(
    "changes,error",
    [
        ({"refresh_token": None}, "expired"),
        ({"generation": 2**31 - 1}, "exhausted"),
    ],
)
def test_unrefreshable_grant_is_rejected_before_any_provider_send(
    tmp_path, changes, error
):
    case = VaultCase(tmp_path)
    case.enroll(**changes)
    with TLSService(tmp_path, host="login.example.org") as server:
        server.routes[("POST", "/token")] = response()
        case.call("refresh", now=100, transport=case.transport(server), error=error)
        assert not server.requests
        assert case.row()["refresh_state"] == "none"


def test_concurrent_automatic_snapshots_share_one_refreshed_generation(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll(expires_at=150)
    entered, release = threading.Event(), threading.Event()
    with TLSService(tmp_path, host="login.example.org") as server:

        def blocked(_):
            entered.set()
            assert release.wait(10)
            return 200, {}, codec.dumps(response())

        server.routes[("POST", "/token")] = blocked
        with ThreadPoolExecutor(max_workers=2) as pool:
            fields = {
                "now": 100,
                "resource_host": "api.example.org",
                "transport": case.transport(server),
            }
            first = pool.submit(case.call, "session-check", **fields)
            assert entered.wait(5)
            second = pool.submit(case.call, "session-check", **fields)
            time.sleep(0.1)
            assert not second.done()
            release.set()
            assert (
                first.result(timeout=10)
                == second.result(timeout=10)
                == {"epoch": 0, "generation": 1, "expires_at": 3700}
            )
        assert len(server.requests) == 1


def test_oauth_short_opaque_token_reaches_only_selected_provider(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll(access_token="x", expires_at=int(time.time()) + 3600)
    authority = AuthorityCase(tmp_path)
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("GET", "/v1/account")] = {"id": 42, "active": True}
        source = {
            "vault_root": str(case.root),
            "provider_file": str(case.provider_file),
            "subject": "vm-test",
        }
        with AuthorityProviderCase(
            tmp_path, server, authority, oauth=source, credential_file=None
        ) as session:
            assert session.invoke()["result"] == {"id": 42, "active": True}
        assert server.requests[0]["headers"]["authorization"] == "Bearer x"


def test_blocked_oauth_admission_resamples_clock_across_subsecond_expiry(tmp_path):
    case = VaultCase(tmp_path)
    case.enroll(access_token=TOKEN, expires_at=int(time.time()) + 3600)
    authority = AuthorityCase(tmp_path)
    with TLSService(provider_directory(tmp_path), host="api.example.org") as server:
        server.routes[("GET", "/v1/account")] = {"id": 42, "active": True}
        source = {
            "vault_root": str(case.root),
            "provider_file": str(case.provider_file),
            "subject": "vm-test",
        }
        with AuthorityProviderCase(
            tmp_path, server, authority, oauth=source, credential_file=None, lifetime=3
        ) as session:
            with (case.root / ".vault.lock").open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    try:
                        # Enter in the final second, then wait less than a full
                        # second across expiry. Adding floor(elapsed) is stale.
                        time.sleep(max(0, session.expires_at - time.time() - 0.8))
                        pending = pool.submit(session.invoke)
                        time.sleep(0.1)
                        assert not pending.done()
                        time.sleep(max(0, session.expires_at - time.time() + 0.05))
                    finally:
                        fcntl.flock(lock, fcntl.LOCK_UN)
                    assert not pending.result(timeout=10)["ok"]
            assert not server.requests
