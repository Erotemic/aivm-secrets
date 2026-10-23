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


def test_native_session_refuses_a_spec_without_explicit_key_approval(tmp_path):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        process, announcement = start(spec_for(tmp_path, provider, approve_session_key=False))
        assert announcement == {"version": 1, "ready": False, "error": "invalid_spec"}
        assert process.wait(timeout=30) == 1
        assert not (tmp_path / "host").exists()
