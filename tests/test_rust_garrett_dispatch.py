"""Authorization is rechecked after TLS setup, before credentialed HTTP emission."""

from __future__ import annotations

import time

import pytest

from aivm_secrets.primitives import codec
from tests.secrets_helpers import TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
from tests.test_rust_garrett_manifest import ManifestCase, checked, policy
from tests.test_rust_garrett_provider import provider_directory


@pytest.mark.parametrize("profile", ["account", "read", "write", "checked-write"])
def test_provider_handshake_cannot_extend_authority(tmp_path, profile):
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        cutoff = []
        original = provider._server.get_request
        connections = []

        def delayed_handshake():
            # SSL accept performs the server handshake. Delay the initial
            # provider connection, or the final connection after checked facts.
            connections.append(None)
            if len(connections) == (2 if profile == "checked-write" else 1):
                time.sleep(max(0, cutoff[0] - time.time() + 0.05))
            return original()

        provider._server.get_request = delayed_handshake
        provider.routes[("GET", "/v1/account")] = dict(id=7, active=True)
        provider.routes[("GET", "/v1/tickets/7")] = dict(
            id=7, owner="alice", revision="a" * 40
        )
        provider.routes[("PATCH", "/v1/tickets/7")] = dict(id=7)
        if profile == "account":
            authority = AuthorityCase(tmp_path)
            session = AuthorityProviderCase(tmp_path, provider, authority, lifetime=3)
            request = {}
        else:
            p = policy(tmp_path, provider)
            operation = "ticket.view" if profile == "read" else "ticket.edit"
            arguments = {"ticket": 7}
            if profile != "read":
                arguments["text"] = "hello"
            if profile == "checked-write":
                p = checked(p)
                p["operations"].append(
                    dict(
                        name="revision.edit",
                        effect="write",
                        method="PATCH",
                        path="/v1/revisions/{revision}",
                        parameters={"ticket": [7]},
                        body_fields={"text": 20},
                        requires="ticket",
                    )
                )
                provider.routes[("PATCH", "/v1/revisions/" + "a" * 40)] = dict(id=7)
                operation = "revision.edit"
                arguments = {"ticket": 7, "text": "hello"}
            releases = {
                op["name"]: {"id": {"at": ["id"], "type": "integer"}}
                for op in p["operations"]
            }
            session = ManifestCase(
                tmp_path, provider, p, releases, writes="allow", lifetime=3
            )
            request = dict(operation=operation, arguments=arguments)
        with session:
            cutoff.append(session.expires_at)
            reply = session.invoke(**request)
            assert not reply["ok"], reply
            assert len(provider.requests) == (1 if profile == "checked-write" else 0)
            audit = tmp_path / "provider-audit.jsonl"
            records = [codec.loads(line) for line in audit.read_bytes().splitlines()]
            assert not any(row["event"] == "completed" for row in records)


def shorter_surrogate(session):
    """Trusted test operator reseals only the outer lifetime, leaving the inner live."""
    import base64
    from dataclasses import replace
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from aivm_secrets.identity.garrett.claims import IdentityClaims
    from aivm_secrets.identity.token import AAD_PREFIX, IdentityTokenIssuer

    def decode(text):
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

    payload = codec.loads(decode(session.token.split(".")[1]))
    encrypted = decode(payload.pop("enc"))
    root = session.authority.root / "issuer-keys"
    aes = (root / "local-1.aes256").read_bytes()
    inner = AESGCM(aes).decrypt(
        encrypted[:12], encrypted[12:], AAD_PREFIX + codec.dumps(payload)
    )
    signer = serialization.load_pem_private_key(
        (root / "local-1.key").read_bytes(), None
    )
    claims = replace(IdentityClaims.parse(payload), expires_at=payload["iat"] + 3)
    return IdentityTokenIssuer(signer, aes, key_id="local-1").issue(
        claims, inner.decode()
    ), claims.expires_at


@pytest.mark.parametrize("profile", ["account", "manifest"])
@pytest.mark.parametrize("verb", ["describe", "renounce"])
def test_vault_wait_cannot_extend_outer_control_authority(tmp_path, profile, verb):
    import fcntl
    from concurrent.futures import ThreadPoolExecutor
    from tests.secrets_helpers import TOKEN
    from tests.test_rust_garrett_oauth_vault import VaultCase

    vault = VaultCase(tmp_path)
    vault.enroll(access_token=TOKEN, expires_at=int(time.time()) + 3600)
    source = dict(
        vault_root=str(vault.root),
        provider_file=str(vault.provider_file),
        subject="vm-test",
    )
    with TLSService(provider_directory(tmp_path), host="api.example.org") as provider:
        if profile == "account":
            session = AuthorityProviderCase(
                tmp_path,
                provider,
                AuthorityCase(tmp_path),
                oauth=source,
                credential_file=None,
            )
        else:
            session = ManifestCase(
                tmp_path,
                provider,
                oauth=source,
                source_override="oauth",
                credential_file=None,
            )
        with session:
            original = session.token
            session.token, expires = shorter_surrogate(session)
            with (vault.root / ".vault.lock").open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    try:
                        pending = pool.submit(session.invoke, verb=verb)
                        time.sleep(0.1)
                        assert not pending.done()
                        time.sleep(max(0, expires - time.time() + 0.05))
                    finally:
                        fcntl.flock(lock, fcntl.LOCK_UN)
                    reply = pending.result(timeout=10)
                    assert not reply["ok"], reply
            session.token = original
            # A rejected renunciation cannot deactivate a still-live grant.
            assert session.invoke(verb="describe")["ok"]
            assert not provider.requests
