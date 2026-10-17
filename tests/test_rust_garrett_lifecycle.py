"""Native trust lifecycle, cross-language stores and explicit recovery CAS."""

from __future__ import annotations

import hashlib
import tempfile
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from aivm_secrets.errors import SecretsError
from aivm_secrets.host.audit import verify
from aivm_secrets.identity.enrollment import IdentityAuthority
from aivm_secrets.identity.garrett import registry as registry_model
from aivm_secrets.primitives import codec
from tests.secrets_helpers import TLSService
from tests.test_rust_garrett_authority import AuthorityCase, AuthorityProviderCase
from tests.test_rust_garrett_provider import provider_directory


def public_result(value):
    return {
        key: item
        for key, item in value.items()
        if key not in {"transaction", "plan_sha256", "recovered"}
    }


def test_native_issuer_and_server_lifecycle_python_interoperability(tmp_path):
    case = AuthorityCase(tmp_path)
    case.enroll()
    reference = IdentityAuthority(case.root)
    before = reference.status()
    rotated = case.call("rotate-issuer")
    assert public_result(rotated) == dict(
        active="local-2", enabled=["local-1", "local-2"]
    )
    assert reference._keyring()["active"] == "local-2"
    key = serialization.load_pem_private_key(
        (case.root / "issuer-keys/local-2.key").read_bytes(), None
    )
    public = serialization.load_pem_public_key(
        (case.root / "issuer-keys/local-2.pub").read_bytes()
    )
    assert key.public_key().public_bytes_raw() == public.public_bytes_raw()
    assert len((case.root / "issuer-keys/local-2.aes256").read_bytes()) == 32
    # Both writers continue the same on-disk key sequence without conversion.
    assert reference.rotate_issuer() == dict(
        active="local-3", enabled=["local-1", "local-2", "local-3"]
    )
    retired = case.call("retire-issuer", kid="local-1")
    assert public_result(retired) == dict(
        active="local-3", enabled=["local-2", "local-3"]
    )
    case.call("retire-issuer", kid="local-3", error="denied")
    assert (case.root / "issuer-keys/local-1.key").exists()  # no silent key deletion
    renewed = case.call("renew-server")
    assert renewed["generation"] == before["server_generation"] + 1
    assert renewed["restart_required"]
    cert_path, key_path, ca_path = reference.tls_paths()
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert int(cert.not_valid_after_utc.timestamp()) == renewed["not_after"]
    assert reference.status() == case.call("status")
    assert reference.status()["subjects"] == before["subjects"]
    for path in (case.root / "audit").iterdir():
        assert verify(path)[0] == 2
    for operation in [rotated, retired, renewed]:
        status = case.call("transaction-status", transaction=operation["transaction"])
        assert status["plan_sha256"] == operation["plan_sha256"]
        assert status["materials_ready"]


def test_native_ca_rollover_revokes_all_and_stale_cas_cannot_revoke_new_client(
    tmp_path,
):
    case = AuthorityCase(tmp_path)
    case.enroll()
    case.enroll(subject="second")
    reference = IdentityAuthority(case.root)
    before = codec.loads((case.root / "enrollments.json").read_bytes())
    root_before = reference.ca_sha256
    result = case.call("rotate-ca", expected_ca_sha256=root_before)
    after = codec.loads((case.root / "enrollments.json").read_bytes())
    assert after == registry_model.revoke_all(
        before, issuer="aivm.test", audience="aivm-secrets.remote"
    )
    assert result["ca_sha256"] != root_before and result["enrollments_revoked"]
    assert [r["subject"] for r in result["revoked"]] == ["second", "vm-test"]
    with pytest.raises(SecretsError, match="revoked"):
        reference.status()
    current_reference = IdentityAuthority(case.root)
    assert current_reference.status() == case.call("status")
    case.call("public-client", subject="vm-test", error="revoked")
    _, _, fresh = case.enroll()
    assert fresh["epoch"] > before["subjects"]["vm-test"]["epoch"]
    assert (
        case.call("public-client", subject="vm-test")["assurance"]["mode"]
        == "operator-approved-software"
    )
    files = {
        str(p.relative_to(case.root)): p.read_bytes()
        for p in case.root.rglob("*")
        if p.is_file()
    }
    case.call("rotate-ca", expected_ca_sha256=root_before, error="revoked")
    # A retry with an old root CAS has no staging/audit/registry side effects.
    assert files == {
        str(p.relative_to(case.root)): p.read_bytes()
        for p in case.root.rglob("*")
        if p.is_file()
    }
    case.call(
        "recover",
        transaction=result["transaction"],
        expected_plan_sha256=result["plan_sha256"],
        error="revoked",
    )
    assert case.call("status")["subjects"]["vm-test"]["active"]


def test_native_rotations_fence_running_provider_and_support_new_root_restart():
    with tempfile.TemporaryDirectory(prefix="agroll-") as directory:
        p = Path(directory)
        authority = AuthorityCase(p)
        with TLSService(provider_directory(p)) as provider:
            provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
            with AuthorityProviderCase(p, provider, authority) as case:
                assert case.invoke()["ok"]
                authority.call("rotate-issuer")
                assert case.invoke()["ok"]
                authority.call("retire-issuer", kid="local-1")
                calls = len(provider.requests)
                assert not case.invoke()["ok"]
                assert len(provider.requests) == calls
            next_path = p / "next"
            next_path.mkdir(mode=0o700)
            with AuthorityProviderCase(
                next_path, provider, authority, certs=case.certs
            ) as next_case:
                assert next_case.invoke()["ok"]
                root = authority.call("status")["ca_sha256"]
                authority.call("rotate-ca", expected_ca_sha256=root)
                calls = len(provider.requests)
                assert not next_case.invoke()["ok"]
                assert len(provider.requests) == calls
            # Use a new software key and its exact current certificate after
            # an explicit root change; no previous TLS/cert state is reused.
            key, _, enrollment = authority.enroll()
            certs = authority.certs(key=key, enrollment=enrollment)
            restart = p / "restart"
            restart.mkdir(mode=0o700)
            with AuthorityProviderCase(
                restart, provider, authority, certs=certs
            ) as restarted:
                assert restarted.invoke()["ok"]


def test_recovery_is_explicit_idempotent_and_binds_reviewed_public_plan(tmp_path):
    case = AuthorityCase(tmp_path)
    case.enroll()
    renewed = case.call("renew-server")
    status = case.call("transaction-status", transaction=renewed["transaction"])
    assert status["phase"] == "activated" and status["materials_ready"]
    assert (
        hashlib.sha256(codec.dumps(status["plan"])).hexdigest() == status["plan_sha256"]
    )
    assert b"PRIVATE KEY" not in codec.dumps(status)
    case.call(
        "recover",
        transaction=renewed["transaction"],
        expected_plan_sha256="0" * 64,
        error="revoked",
    )
    before = case.call("status")
    recovered = case.call(
        "recover",
        transaction=renewed["transaction"],
        expected_plan_sha256=status["plan_sha256"],
    )
    assert recovered["recovered"]
    assert public_result(recovered) == public_result(renewed)
    assert before == case.call("status")
    entries = case.call("transactions")["transactions"]
    assert len(entries) == 1 and entries[0]["phase"] == "activated"
    for path in (case.root / "audit").iterdir():
        assert verify(path)[0] == 2


@pytest.mark.parametrize(
    "target,suffix,action",
    [
        ("issuer-keys", "local-2.key", "rotate-issuer"),
        ("server-generations", "server-2.pem", "renew-server"),
        ("ca-generations", "ca-2.key", "rotate-ca"),
    ],
)
def test_failed_immutable_names_are_preserved_and_skipped(
    tmp_path, target, suffix, action
):
    case = AuthorityCase(tmp_path)
    path = case.root / target / suffix
    path.write_bytes(b"partial previous stage")
    path.chmod(0o600)
    fields = (
        dict(expected_ca_sha256=case.call("status")["ca_sha256"])
        if action == "rotate-ca"
        else {}
    )
    result = case.call(action, **fields)
    assert path.read_bytes() == b"partial previous stage"
    if action == "rotate-issuer":
        assert result["active"] == "local-3"
    elif action == "renew-server":
        assert result["generation"] == 3
    else:
        assert result["ca_generation"] == 3


def test_partial_plan_write_never_changes_selected_authority(tmp_path):
    case = AuthorityCase(tmp_path)
    case.enroll()
    before = case.call("status")
    case.call(
        "rotate-ca",
        expected_ca_sha256=before["ca_sha256"],
        limit=600,
        error="internal_error",
    )
    assert case.call("status") == before
    assert len(list((case.root / "ca-generations").iterdir())) == 2
    assert len(list((case.root / "server-generations").iterdir())) == 2
    assert len(list((case.root / "audit").iterdir())) == 1  # original enrollment only
    assert case.call("transactions")["transactions"][0]["phase"] == "invalid-plan"
    case.call("rotate-ca", expected_ca_sha256=before["ca_sha256"])
    assert len(case.call("transactions")["transactions"]) == 2


@pytest.mark.parametrize("prefix", ["unchanged", "retired", "activated"])
def test_native_recovery_from_each_surviving_rollover_prefix(tmp_path, prefix):
    case = AuthorityCase(tmp_path)
    case.enroll()
    result = case.call("rotate-ca", expected_ca_sha256=case.call("status")["ca_sha256"])
    plan = case.call("transaction-status", transaction=result["transaction"])["plan"]
    # Model the public pointer states that can survive an interruption, using
    # the normal writer's actual immutable material. This fixture restoration
    # is not a production recovery path or a power-loss experiment.
    for filename, key, snapshot in [
        ("authority.json", "authority", "after" if prefix == "activated" else "before"),
        (
            "enrollments.json",
            "registry",
            "before" if prefix == "unchanged" else "after",
        ),
    ]:
        path = case.root / filename
        path.write_bytes(codec.dumps(plan[snapshot][key]))
    assert (
        case.call("transaction-status", transaction=result["transaction"])["phase"]
        == prefix
    )
    before_material = {
        str(p): p.read_bytes()
        for folder in ["ca-generations", "server-generations", "issuer-keys"]
        for p in (case.root / folder).iterdir()
    }
    case.call(
        "recover",
        transaction=result["transaction"],
        expected_plan_sha256=result["plan_sha256"],
    )
    reference = IdentityAuthority(case.root)
    assert reference.ca_sha256 == result["ca_sha256"]
    assert not reference.status()["subjects"]["vm-test"]["active"]
    assert before_material == {
        str(p): p.read_bytes()
        for folder in ["ca-generations", "server-generations", "issuer-keys"]
        for p in (case.root / folder).iterdir()
    }


@pytest.mark.parametrize("attack", ["path", "resurrect", "audience", "private-field"])
def test_reviewed_hash_cannot_turn_recovery_plan_into_arbitrary_mutation(
    tmp_path, attack
):
    case = AuthorityCase(tmp_path)
    case.enroll()
    result = case.call("rotate-ca", expected_ca_sha256=case.call("status")["ca_sha256"])
    plan_path = case.root / "transactions" / result["transaction"] / "plan.json"
    plan = codec.loads(plan_path.read_bytes())
    if attack == "path":
        plan["materials"][0]["name"] = "../../credential"
    elif attack == "resurrect":
        plan["after"]["registry"] = plan["before"]["registry"]
    elif attack == "audience":
        plan["after"]["authority"]["audience"] = "different-audience"
    else:
        plan["materials"][0]["private_bytes"] = "never-allowed"
    data = codec.dumps(plan)
    plan_path.write_bytes(data)
    before = case.call("status")
    case.call(
        "recover",
        transaction=result["transaction"],
        expected_plan_sha256=hashlib.sha256(data).hexdigest(),
        error="invalid_capability",
    )
    assert case.call("status") == before


def test_recovery_refuses_expired_certificate_plan_without_mutation(tmp_path):
    case = AuthorityCase(tmp_path)
    now = int(time.time())
    result = case.call("renew-server", now=now)
    before = case.call("status")
    case.call(
        "recover",
        transaction=result["transaction"],
        expected_plan_sha256=result["plan_sha256"],
        now=now + 2592000,
        error="expired",
    )
    assert case.call("status") == before
