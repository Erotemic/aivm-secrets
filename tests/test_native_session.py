"""The optional native-session process contract, end to end with a local guest."""

import json
import os
import select
import subprocess
import sys
from pathlib import Path

import pytest

from tests.secrets_helpers import TOKEN, TLSService
from tests.test_rust_garrett import executable
from tests.test_rust_garrett_authority import private
from tests.test_rust_garrett_manifest import disclosure, policy, provider_directory

ROOT = Path(__file__).resolve().parents[1]


def spec_for(tmp_path, provider, **changes):
    bin_dir = Path(executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")).parent
    # The bridge requires host-private provider trust files.
    for path in provider.files.values():
        path.chmod(0o600)
    credential = private(tmp_path / "credential", TOKEN.encode())
    p = policy(tmp_path, provider)
    spec = dict(
        version=1,
        bin_dir=str(bin_dir),
        workspace=str(tmp_path / "host"),
        policy_file=str(private(tmp_path / "policy.json", p)),
        disclosure_file=str(private(tmp_path / "disclosure.json", disclosure())),
        credential_file=str(credential),
        provider=dict(host=provider.host, address="127.0.0.1", port=provider.port,
                      server_ca=str(provider.files["ca"]), authentication="bearer"),
        binding=dict(access_identity="operator-test", vm="vm-native-session"),
        guest=dict(kind="local"),
        approve_session_key=True,
    )
    spec.update(changes)
    return private(tmp_path / "session.json", spec)


def start(spec_path):
    process = subprocess.Popen(
        [sys.executable, "-m", "aivm_secrets", "native-session", "--spec", str(spec_path)],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    ready, _, _ = select.select([process.stdout], [], [], 60)
    assert ready, "native-session did not announce"
    return process, json.loads(process.stdout.readline())


def guest_invoke(announcement, operation, arguments):
    g = announcement["guest"]
    return subprocess.run(
        [g["client"], "--config", g["config"], "--capability-file", g["capability"],
         "invoke", operation, "--arguments", arguments],
        capture_output=True, timeout=30,
    )


def test_native_session_serves_one_guest_and_tears_down(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        provider.routes[("GET", "/v1/tickets/7")] = {"id": 7, "private": TOKEN}
        process, announcement = start(spec_for(tmp_path, provider))
        try:
            assert announcement.get("ready") is True, announcement
            guest_dir = Path(announcement["guest"]["dir"])
            assert guest_dir.is_dir()
            allowed = guest_invoke(announcement, "ticket.view", '{"ticket":7}')
            assert allowed.returncode == 0, allowed
            assert json.loads(allowed.stdout) == {"version": 1, "ok": True, "result": {"id": 7}}
            [sent] = provider.seen()
            assert sent["headers"]["authorization"] == "Bearer " + TOKEN
            denied = guest_invoke(announcement, "ticket.view", '{"ticket":9}')
            assert denied.returncode != 0 or not json.loads(denied.stdout)["ok"]
            assert len(provider.seen()) == 1
            # The provider credential never entered the guest.
            for path in guest_dir.rglob("*"):
                if path.is_file():
                    assert TOKEN.encode() not in path.read_bytes(), path
            for output in (allowed, denied):
                assert TOKEN.encode() not in output.stdout + output.stderr
        finally:
            process.stdin.close()
            assert process.wait(timeout=30) == 0
        assert not guest_dir.exists()
        out, err = process.stdout.read(), process.stderr.read()
        assert TOKEN.encode() not in out + err



def test_revoking_the_guest_identity_mid_session_stops_the_next_request(tmp_path):
    """W8: revocation while the session is live, through the session's own
    authority, is honoured on the very next request with no provider call."""
    from aivm_secrets.native_session import SUBJECT

    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        provider.routes[("GET", "/v1/tickets/7")] = {"id": 7}
        process, announcement = start(spec_for(tmp_path, provider))
        try:
            assert announcement.get("ready") is True, announcement
            assert guest_invoke(announcement, "ticket.view", '{"ticket":7}').returncode == 0
            assert len(provider.seen()) == 1
            request = private(tmp_path / "revoke.json", {"subject": SUBJECT})
            revoked = subprocess.run(
                [executable("AIVM_SECRETS_RUST_AUTHORITY_ADMIN"), "revoke",
                 "--root", str(tmp_path / "host" / "authority"), "--request", str(request)],
                capture_output=True, timeout=30)
            assert revoked.returncode == 0, revoked
            assert json.loads(revoked.stdout)["ok"] is True
            after = guest_invoke(announcement, "ticket.view", '{"ticket":7}')
            assert after.returncode != 0 or not json.loads(after.stdout)["ok"], after
            assert len(provider.seen()) == 1
            assert TOKEN.encode() not in after.stdout + after.stderr
        finally:
            process.stdin.close()
            assert process.wait(timeout=30) == 0


@pytest.mark.skipif(__import__("shutil").which("curl") is None, reason="needs curl")
def test_constrained_proxy_serves_stock_curl_without_a_guest_credential(tmp_path):
    """HP-6 end to end: stock curl, only the published env file, through the
    guest-side translator and the native bridge to the provider."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        provider.routes[("GET", "/v1/tickets/7")] = {"id": 7, "private": TOKEN}
        provider.routes[("GET", "/v1/tickets?page=2&state=open")] = {"rows": [{"id": 3}]}
        spec = spec_for(tmp_path, provider, constrained_proxy={"guest_port": port})
        process, announcement = start(spec)
        try:
            assert announcement.get("ready") is True, announcement
            env = announcement["guest"]["env"]
            guest_dir = Path(announcement["guest"]["dir"])

            def curl(path):
                return subprocess.run(
                    ["sh", "-c", ". " + env + " && exec curl -sS --max-time 20 "
                     "-H 'Authorization: token guest-placeholder' "
                     "-w '\\n%{http_code}' https://api.example.org" + path],
                    capture_output=True, timeout=60)

            allowed = curl("/v1/tickets/7")
            body, _, code = allowed.stdout.rpartition(b"\n")
            assert code == b"200", allowed
            assert json.loads(body) == {"id": 7}
            [sent] = provider.seen()
            assert sent["headers"]["authorization"] == "Bearer " + TOKEN
            denied = curl("/v1/tickets/9")
            assert not denied.stdout.endswith(b"200"), denied
            unmatched = curl("/v1/users/7")
            assert unmatched.stdout.endswith(b"403"), unmatched
            assert len(provider.seen()) == 1
            # Query pairs in any order: the host sends its own (by key).
            listed = curl("'/v1/tickets?state=open&page=2'")
            assert listed.stdout.endswith(b"200"), listed
            assert provider.seen()[-1]["target"] == "/v1/tickets?page=2&state=open"
            for path in guest_dir.rglob("*"):
                if path.is_file():
                    assert TOKEN.encode() not in path.read_bytes(), path
            for output in (allowed, denied, unmatched):
                assert TOKEN.encode() not in output.stdout + output.stderr
        finally:
            process.stdin.close()
            assert process.wait(timeout=30) == 0
        assert not guest_dir.exists()
        out, err = process.stdout.read(), process.stderr.read()
        assert TOKEN.encode() not in out + err



@pytest.mark.skipif(__import__("shutil").which("curl") is None, reason="needs curl")
def test_constrained_proxy_reads_a_github_shaped_pull_request(tmp_path):
    """The real-VM acceptance flow with a local guest: a two-segment
    repository parameter, the diff media type set by the host, and an
    out-of-scope pull request that never reaches the provider."""
    import socket

    from dev import offline_native_guest as offline

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with offline.LocalProvider(tmp_path / "provider") as provider:
        for path in provider.files.values():
            path.chmod(0o600)
        spec = dict(
            version=1, bin_dir=str(Path(executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")).parent),
            workspace=str(tmp_path / "host"),
            policy_file=str(private(tmp_path / "policy.json", offline.policy(tmp_path, provider))),
            disclosure_file=str(private(tmp_path / "disclosure.json", offline.disclosure())),
            credential_file=str(private(tmp_path / "credential", offline.FAKE_TOKEN.encode())),
            provider=dict(host=provider.host, address="127.0.0.1", port=provider.port,
                          server_ca=str(provider.files["ca"]), authentication="bearer"),
            binding=dict(access_identity="operator-test", vm="vm-constrained"),
            guest=dict(kind="local"), approve_session_key=True,
            constrained_proxy=dict(guest_port=port),
        )
        process, announcement = start(private(tmp_path / "session.json", spec))
        try:
            assert announcement.get("ready") is True, announcement
            env = announcement["guest"]["env"]
            base = f"https://{provider.host}/repos/{offline.REPOSITORY.lower()}/pulls/"

            def curl(url):
                return subprocess.run(
                    ["sh", "-c", ". " + env + " && exec curl -sS --max-time 20 "
                     "-w '\\n%{http_code}' " + url],
                    capture_output=True, timeout=60)

            allowed = curl(base + str(offline.PR))
            body, _, code = allowed.stdout.rpartition(b"\n")
            assert code == b"200", allowed
            assert json.loads(body) == {"diff": offline.DIFF}
            # The host's own `pull` check, then the diff: both by the bridge.
            sent = provider.seen()
            assert [(r["path"], r["accept"]) for r in sent] == [
                (offline.PULL_PATH, offline.GITHUB_JSON), (offline.PULL_PATH, offline.GITHUB_DIFF)]
            assert {r["authorization"] for r in sent} == {"Bearer " + offline.FAKE_TOKEN}
            other = curl(base + str(offline.PR + 1))
            assert not other.stdout.endswith(b"200"), other
            assert len(provider.seen()) == 2
            for output in (allowed, other):
                assert offline.FAKE_TOKEN.encode() not in output.stdout + output.stderr
        finally:
            process.stdin.close()
            assert process.wait(timeout=30) == 0

def test_native_session_refuses_a_bad_constrained_proxy_spec(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        path = spec_for(tmp_path, provider)
        base = json.loads(path.read_text())
        for bad in ({"guest_port": 80}, {"guest_port": "8443"}, {"port": 8443}, True):
            path.write_text(json.dumps({**base, "constrained_proxy": bad}))
            done = subprocess.run(
                [sys.executable, "-m", "aivm_secrets", "native-session", "--spec", str(path)],
                cwd=ROOT, capture_output=True, timeout=60, input=b"")
            assert done.returncode == 1
            assert json.loads(done.stdout) == {"version": 1, "ready": False, "error": "invalid_spec"}

def test_native_session_refuses_a_spec_without_explicit_key_approval(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        process, announcement = start(spec_for(tmp_path, provider, approve_session_key=False))
        assert announcement == {"version": 1, "ready": False, "error": "invalid_spec"}
        assert process.wait(timeout=30) == 1
        assert not (tmp_path / "host").exists()


@pytest.mark.parametrize("line", [b"[1]", b'{"ready":true,"profile":"constrained-http"}',
                                  b'{"ready":true,"profile":"constrained-http","ca_pem":"x","proxy_token":"a b"}',
                                  b"not json"])
def test_a_malformed_translator_announcement_fails_closed(tmp_path, monkeypatch, line):
    """Over SSH the guest writes the translator's announcement; a bad one is
    reported as proxy_failed and the whole session is torn down."""
    import socket

    from aivm_secrets import native_session

    def fake_spawn(self, argv):
        return subprocess.Popen(["sh", "-c", "printf '%s\\n' \"$0\"; exec cat >/dev/null", line],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)

    monkeypatch.setattr(native_session.LocalGuest, "spawn", fake_spawn)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        spec = native_session.load_spec(spec_for(tmp_path, provider, constrained_proxy={"guest_port": port}))
        session = native_session.Session(spec)
        with pytest.raises(native_session.SessionError) as raised:
            session.__enter__()
        assert raised.value.code == "proxy_failed"
        assert session.translator is None and session.guest is not None
        assert not Path(session.guest.dir).exists()
        assert provider.seen() == []
