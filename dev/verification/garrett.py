#!/usr/bin/env python3
"""Reproduce the Rust Garrett port, extracted contracts, symbolic secrecy and parity.

Run bootstrap once, then check and mutate with the project's test Python.
No provider credentials, host authority state or hardware keys are read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import freshness as base

ROOT = base.ROOT
PROOFS = base.PROOFS
MANIFEST = PROOFS / "garrett-manifest.json"
PROFILES = [
    "nested-bridge-v1",
    "account-status-v1",
    "p256-client-enrollment-v1",
    "native-authority-v2",
]
THEOREMS = [
    "aivm_secrets_garrett_core.Proofs.bytes_ne_spec",
    "aivm_secrets_garrett_core.Proofs.issue_contract",
    "aivm_secrets_garrett_core.Proofs.present_contract",
    "aivm_secrets_garrett_core.Proofs.returned_of_spec",
    "aivm_secrets_garrett_core.Proofs.present_exact",
    "aivm_secrets_garrett_core.Proofs.present_accepted_iff",
    "aivm_secrets_garrett_core.Proofs.stolen_surrogate_wrong_peer",
    "aivm_secrets_garrett_core.Proofs.stolen_surrogate_cannot_be_used",
    "aivm_secrets_garrett_core.Proofs.issuance_cannot_outlive_enrollment",
    "aivm_secrets_garrett_core.Proofs.authorized_use_positive_witness",
    "aivm_secrets_garrett_core.Proofs.open_surrogate_contract",
    "aivm_secrets_garrett_core.Proofs.open_rejects_unbound_before_unsealing",
    "aivm_secrets_garrett_core.Proofs.open_stolen_surrogate_rejected",
    "aivm_secrets_garrett_core.Proofs.open_successful_use",
    "aivm_secrets_garrett_core.Proofs.prepare_issue_contract",
    "aivm_secrets_garrett_core.Proofs.issue_surrogate_contract",
    "aivm_secrets_garrett_core.Proofs.inactive_enrollment_never_sealed",
    "Garrett.Protocol.derivation_preserves_confinement",
    "Garrett.Protocol.provider_credential_not_derivable",
    "Garrett.Protocol.private_key_not_derivable",
    "Garrett.Protocol.surrogate_can_be_public",
    "Garrett.Protocol.every_trace_observation_safe",
    "Garrett.Protocol.all_traces_preserve_credential_secrecy",
]
THEOREMS += [
    "aivm_secrets_garrett_core.credential_use.Proofs.require_use_current_contract",
    "aivm_secrets_garrett_core.credential_use.Proofs.authorize_use_contract",
    "aivm_secrets_garrett_core.credential_use.Proofs.release_reply_exact",
    "aivm_secrets_garrett_core.credential_use.Proofs.release_noninterference",
    "aivm_secrets_garrett_core.credential_use.Proofs.authorize_use_exact",
    "aivm_secrets_garrett_core.credential_use.Proofs.credential_use_contract",
    "aivm_secrets_garrett_core.credential_use.Proofs.inactive_grant_never_executes",
    "aivm_secrets_garrett_core.credential_use.Proofs.unauthorized_operation_never_executes",
    "aivm_secrets_garrett_core.credential_use.Proofs.credential_use_successful",
    "aivm_secrets_garrett_core.credential_use.Proofs.credential_use_noninterference",
]

THEOREMS += [
    "aivm_secrets_garrett_core.protocol.Proofs.prepared_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.finish_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_outer_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_stolen_surrogate",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_inner_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_unauthorized_operation",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_after_prepared",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_observer_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.prepare_successful",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_successful",
    "aivm_secrets_garrett_core.protocol.Proofs.perform_projection_noninterference",
]

THEOREMS += [
    "aivm_secrets_garrett_core.protocol.Proofs.recorded_issuance_contract",
    "aivm_secrets_garrett_core.protocol.Proofs.recorded_issuance_failure",
    "aivm_secrets_garrett_core.protocol.Proofs.recorded_issuance_success",
    "Garrett.ControllerHistory.all_histories_correspond",
    "Garrett.ControllerHistory.dispatch_continuation",
    "Garrett.History.signature_origin_monotone",
    "Garrett.History.deduction_preserves_signature_origin",
    "Garrett.History.trace_is_public",
    "Garrett.History.every_observation_has_signature_origin",
    "Garrett.History.protected_signature_was_issued",
]

THEOREMS += [
    "aivm_secrets_garrett_core.enrollment.Proofs.approve_key_exact",
    "aivm_secrets_garrett_core.enrollment.Proofs.approve_key_contract",
    "aivm_secrets_garrett_core.enrollment.Proofs.authorize_client_contract",
    "aivm_secrets_garrett_core.enrollment.Proofs.enroll_client_contract",
    "aivm_secrets_garrett_core.enrollment.Proofs.tpm_substitution_never_signed",
    "aivm_secrets_garrett_core.enrollment.Proofs.unapproved_software_key_never_signed",
    "aivm_secrets_garrett_core.enrollment.Proofs.software_is_not_tpm",
    "aivm_secrets_garrett_core.enrollment.Proofs.tpm_plan_uses_attested_key",
    "aivm_secrets_garrett_core.enrollment.Proofs.enroll_client_successful",
    "aivm_secrets_garrett_core.enrollment.Proofs.authorize_tpm_success",
]

THEOREMS += [
    "aivm_secrets_garrett_core.authority.Proofs.require_peer_contract",
    "aivm_secrets_garrett_core.authority.Proofs.inactive_peer_denied",
    "aivm_secrets_garrett_core.authority.Proofs.wrong_peer_denied",
    "aivm_secrets_garrett_core.authority.Proofs.software_cannot_satisfy_tpm",
    "aivm_secrets_garrett_core.authority.Proofs.unrecorded_cannot_satisfy_tpm",
    "aivm_secrets_garrett_core.authority.Proofs.revoke_contract",
    "aivm_secrets_garrett_core.authority.Proofs.revoked_peer_never_admitted",
    "aivm_secrets_garrett_core.authority.Proofs.revoke_prevents_admission",
    "aivm_secrets_garrett_core.authority.Proofs.expired_peer_denied",
    "aivm_secrets_garrett_core.authority.Proofs.attested_peer_positive_witness",
    "aivm_secrets_garrett_core.authority.Proofs.commit_change_contract",
    "aivm_secrets_garrett_core.authority.Proofs.intent_failure_never_publishes",
    "aivm_secrets_garrett_core.authority.Proofs.staging_failure_never_publishes",
    "aivm_secrets_garrett_core.authority.Proofs.publication_failure_is_uncertain",
    "aivm_secrets_garrett_core.authority.Proofs.completion_failure_is_uncertain",
    "aivm_secrets_garrett_core.authority.Proofs.commit_change_positive_witness",
]

TESTS = [
    "tests/test_rust_garrett.py",
    "tests/test_rust_garrett_tpm.py",
    "tests/test_rust_garrett_provider.py",
    "tests/test_rust_garrett_certificates.py",
    "tests/test_rust_garrett_authority.py",
    "tests/test_secrets_garrett_modularity.py",
    "tests/test_secrets_identity_parity.py",
    "tests/test_secrets_identity_registry_parity.py",
    "tests/test_secrets_identity_renewal_parity.py",
    "tests/test_secrets_identity_revoke_cas_parity.py",
    "tests/test_secrets_authority_parity.py",
    "tests/test_secrets_identity_key_rotation_parity.py",
    "tests/test_secrets_vm_parity.py",
    "tests/test_secrets_garrett_oauth_parity.py",
]
RUNNERS = {
    "AIVM_SECRETS_RUST_GARRETT_RUNNER": "garrett-conformance",
    "AIVM_SECRETS_RUST_GARRETT_BRIDGE": "garrett-bridge",
    "AIVM_SECRETS_RUST_GARRETT_CLIENT": "garrett-client",
    "AIVM_SECRETS_RUST_IDENTITY_RUNNER": "identity-conformance",
    "AIVM_SECRETS_RUST_REGISTRY_RUNNER": "registry-conformance",
    "AIVM_SECRETS_RUST_AUTHORITY_RUNNER": "authority-conformance",
    "AIVM_SECRETS_RUST_AUTHORITY_ADMIN": "garrett-authority",
    "AIVM_SECRETS_RUST_KEY_ROTATION_RUNNER": "key-rotation-conformance",
    "AIVM_SECRETS_RUST_VM_RUNNER": "vm-conformance",
    "AIVM_SECRETS_RUST_OAUTH_RUNNER": "oauth-conformance",
}


def inputs() -> list[str]:
    files = {
        ".github/workflows/garrett.yml",
        "MANIFEST.in",
        "pyproject.toml",
        "rust/Cargo.toml",
        "rust/Cargo.lock",
        "rust/rust-toolchain.toml",
        "proofs/lakefile.lean",
        "proofs/lean-toolchain",
        "proofs/lake-manifest.json",
        "proofs/manifest.json",
        "proofs/generated/AivmSecretsGarrettCore.lean",
        "proofs/Garrett.lean",
        "proofs/GarrettSecrecy.lean",
        "proofs/GarrettCheck.lean",
        "proofs/GarrettProtocol.lean",
        "proofs/GarrettHistory.lean",
        "proofs/GarrettEnrollment.lean",
        "proofs/GarrettAuthority.lean",
        "tests/limited_exec.py",
        "dev/verification/garrett.py",
        "dev/verification/freshness.py",
        "tests/secrets_helpers.py",
        "tests/test_secrets_identity_mtls.py",
        *TESTS,
    }
    for name in ["aivm-secrets-garrett", "aivm-secrets-garrett-core"]:
        directory = ROOT / "rust/crates" / name
        files.add(str((directory / "Cargo.toml").relative_to(ROOT)))
        files.update(str(p.relative_to(ROOT)) for p in directory.rglob("*.rs"))
    files.update(
        str(p.relative_to(ROOT)) for p in (ROOT / "aivm_secrets").rglob("*.py")
    )
    for pattern in ["*.jsonl", "*.json"]:
        files.update(
            str(p.relative_to(ROOT))
            for p in (ROOT / "tests/secrets_vectors").glob(pattern)
        )
    return sorted(files)


def extract(destination: Path, rust_root: Path | None = None) -> Path:
    rust_root = ROOT / "rust" if rust_root is None else rust_root
    base.run(
        [
            base.TOOLS / "charon",
            "cargo",
            "--preset=aeneas",
            "--sysroot",
            "default",
            "--",
            "--lib",
            "--locked",
        ],
        cwd=rust_root / "crates/aivm-secrets-garrett-core",
    )
    destination.mkdir(parents=True, exist_ok=True)
    base.run(
        [
            base.TOOLS / "aeneas",
            "-backend",
            "lean",
            "-no-progress-bar",
            "-abort-on-error",
            "-warnings-as-errors",
            "-dest",
            destination,
            rust_root / "aivm_secrets_garrett_core.llbc",
        ]
    )
    generated = destination / "AivmSecretsGarrettCore.lean"
    if not generated.is_file():
        raise SystemExit("missing extracted Garrett module")
    return generated


def regeneration() -> None:
    with tempfile.TemporaryDirectory(
        prefix="garrett-extract-", dir=ROOT / ".tools"
    ) as scratch:
        generated = extract(Path(scratch))
        if (
            generated.read_bytes()
            != (PROOFS / "generated" / generated.name).read_bytes()
        ):
            raise SystemExit("Garrett extraction is stale; regenerate and review it")


def audit(output: str) -> None:
    found = {}
    for name, axioms in re.findall(
        r"'([^']+)' depends on axioms:\s*\[([^\]]*)\]", output
    ):
        found[name] = {item.strip() for item in axioms.split(",") if item.strip()}
    for name in re.findall(r"'([^']+)' does not depend on any axioms", output):
        found[name] = set()
    if set(found) != set(THEOREMS):
        raise SystemExit(
            f"theorem audit inventory differs: {set(found) ^ set(THEOREMS)}"
        )
    for name, axioms in found.items():
        if axioms - base.ALLOWED_AXIOMS:
            raise SystemExit(
                f"{name}: undeclared axioms {axioms - base.ALLOWED_AXIOMS}"
            )
    print(
        f"Audited {len(found)} named Garrett obligations; no admitted or project-specific security axiom.",
        flush=True,
    )


def prove() -> None:
    base.run([base.executable("lake"), "build"], cwd=PROOFS)
    result = base.run(
        [
            base.executable("lake"),
            "env",
            "lean",
            "-DwarningAsError=true",
            "GarrettCheck.lean",
        ],
        cwd=PROOFS,
        capture=True,
    )
    print(result.stdout, end="")
    audit(result.stdout)


def parity() -> None:
    base.run(
        [base.executable("cargo"), "+" + base.RUST, "fmt", "--all", "--", "--check"],
        cwd=ROOT / "rust",
    )
    for mode in ["--no-default-features", "--all-features"]:
        base.run(
            [
                base.executable("cargo"),
                "+" + base.RUST,
                "clippy",
                "--locked",
                "-p",
                "aivm-secrets-garrett",
                "--all-targets",
                mode,
                "--",
                "-D",
                "warnings",
            ],
            cwd=ROOT / "rust",
        )
    base.run(
        [
            base.executable("cargo"),
            "+" + base.RUST,
            "build",
            "--locked",
            "--release",
            "-p",
            "aivm-secrets-garrett",
            "--all-features",
        ],
        cwd=ROOT / "rust",
    )
    base.run(
        [
            base.executable("cargo"),
            "+" + base.RUST,
            "test",
            "--locked",
            "-p",
            "aivm-secrets-garrett",
            "--lib",
            "--all-features",
        ],
        cwd=ROOT / "rust",
    )
    env = dict(
        os.environ,
        **{
            name: str(ROOT / "rust/target/release" / program)
            for name, program in RUNNERS.items()
        },
    )
    env["AIVM_SECRETS_REQUIRE_TPM_TESTS"] = "1"
    base.run([sys.executable, "-m", "pytest", "-q", *TESTS], env=env)


def assurance_coordinates() -> dict:
    return {
        "schema": 1,
        "protocol": "nested Garrett surrogate profile v1",
        "profiles": PROFILES,
        "rust": base.RUST,
        "lean": base.LEAN,
        "aeneas_release": base.RELEASE,
        "theorems": THEOREMS,
        "allowed_axioms": sorted(base.ALLOWED_AXIOMS),
        "implementation_linked": "Aeneas-generated issuance, request preparation/observation/use/release, key-approval/client-enrollment, current-peer/assurance/revocation and ordered authority-publication controllers; exact byte/epoch/time decisions and typed public-result projection",
        "symbolic_model": "Dolev-Yao encrypted-message deduction, protected-signature origin and public protocol traces; conditional source-controller issuance/dispatch histories",
        "assumptions": [
            "Charon/Aeneas translation and supplied standard models, Lean kernel, Rust compiler and target ABI are trusted.",
            "Signature verification authenticates the exact envelope; sealing/unsealing implement their stated cryptographic contracts.",
            "ring AES-GCM/Ed25519/SHA-256, rustls/webpki, OS entropy and nonce discipline are trusted, not cryptographically re-proved.",
            "TLS peer evidence comes only from the completed certificate-verified connection; registry/trust inputs come from the trusted host.",
            "Independent-use prevention assumes no access to the enrolled signing/client oracle; non-exportability alone is insufficient.",
            "Symbolic secrecy assumes protected keys and the specified provider disclosure contract; lengths and public claims are observable.",
            "The legacy bridge uses the existing trusted local broker; account-status-v1 uses the Rust custody/executor and its declared id/active disclosure contract.",
            "Reply noninterference holds when parsed provider public fields agree; providers, errors, timing and metadata may disclose information outside that contract.",
            "TPM tools and silicon/emulator command semantics are trusted; the restricted AK pin must be independently provisioned and oracle access controlled.",
            "The native observer acknowledges only a complete, flushed record under the exclusive-writer and trusted host/filesystem assumptions; acknowledgement is not a client field.",
            "Presentation uses trusted entry/enrollment/clock snapshots; cross-process dispatch linearization and whole-service concurrent traces remain open.",
            "Native authority admission holds a shared flock through dispatch; participating administrators take its exclusive lease. Held directory/file checks, atomic rename and fsync implement assumed storage contracts, not a proved filesystem or anti-rollback boundary. Legacy independent-file bridges retain entry-snapshot semantics.",
            "TPM assurance receipts are trusted principal-owned host metadata bound to subject, certificate and SPKI. Missing receipts never imply TPM assurance; older Python administrators do not enforce the new assurance-downgrade policy.",
            "Controller histories assume signature verification has prior recorded issuer origin; the ideal signature-origin theorem does not establish a computational byte-level or concrete I/O refinement.",
            "CSR possession, CA constraints/key matching and X.509 signing use the stated rcgen/x509-parser/time adapter contracts; their ASN.1/crypto implementations are not formally refined. TPM approval consumes verified fresh evidence under a trusted AK pin.",
        ],
        "exclusions": [
            "Proof of Python or all-input cross-language equivalence",
            "Formal refinement of JSON, TLS, X.509, crypto, TPM evidence, HTTP and filesystem adapter implementations",
            "Physical TPM provenance, EK activation, PCR/firmware policy and anti-rollback deployment",
            "Provider non-disclosure, host compromise, snapshot rollback and side channels",
            "General Rust policy interpretation, native durable issuer/server/root rotation and recovery administration, complete OAuth vault/HTTP service",
        ],
    }


def check_manifest() -> None:
    # Shared tool/model/compiler identities are pinned by the independently
    # checked freshness manifest; no duplicate drifting provisioner is needed.
    base.check_hashes(json.loads(base.MANIFEST.read_text()))
    manifest = json.loads(MANIFEST.read_text())
    expected = assurance_coordinates()
    if set(manifest) != set(expected) | {"sha256"}:
        raise SystemExit("Garrett manifest metadata inventory differs")
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise SystemExit(f"Garrett assurance coordinate differs: {key}")
    if (
        manifest["theorems"] != THEOREMS
        or set(manifest["allowed_axioms"]) != base.ALLOWED_AXIOMS
    ):
        raise SystemExit("Garrett theorem or axiom policy differs")
    if (
        manifest["rust"] != base.RUST
        or manifest["lean"] != base.LEAN
        or manifest["aeneas_release"] != base.RELEASE
    ):
        raise SystemExit("Garrett toolchain pins differ")
    if set(manifest["sha256"]) != set(inputs()):
        raise SystemExit("Garrett manifest source coverage differs")
    for name, expected in manifest["sha256"].items():
        if base.sha256(ROOT / name) != expected:
            raise SystemExit(f"Garrett manifest is stale: {name}")


def record() -> None:
    base.check_hashes(json.loads(base.MANIFEST.read_text()))
    regeneration()
    prove()
    parity()
    manifest = assurance_coordinates()
    manifest["sha256"] = {name: base.sha256(ROOT / name) for name in inputs()}
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Recorded checked Garrett source, assumptions and proof coordinates.")


def mutate() -> None:
    source = ROOT / "rust/crates/aivm-secrets-garrett-core/src/lib.rs"
    changes = [
        ("missing peer binding", "|| claims.certificate != *peer", "|| false"),
        ("missing current epoch", "|| claims.epoch != expected.epoch", "|| false"),
        ("inclusive expiry", "now >= claims.expires_at", "now > claims.expires_at"),
        ("inactive enrollment", "!active || epoch < 0", "false || epoch < 0"),
        (
            "bypassed binding before unseal",
            "present(&envelope.claims, expected, peer, now)",
            "Ok::<(), Denial>(())",
        ),
        (
            "unissued token",
            "issuer.seal(&claims, secret)",
            "Ok::<Vec<u8>, Denial>(Vec::new())",
        ),
    ]
    mutations = [(source, *change) for change in changes]
    use_source = source.with_name("credential_use.rs")
    mutations += [
        (
            use_source,
            "missing inner binding",
            "|| claims.binding != current.binding",
            "|| false",
        ),
        (
            use_source,
            "bypassed credential authorization",
            "authorize_use(claims, grant, operation, now, elapsed)",
            "Ok::<(), UseDenial>(())",
        ),
        (
            use_source,
            "substituted provider route",
            "executor.execute(route, credential)",
            "executor.execute(&Route { host: Vec::new(), port: 443, path: Vec::new(), authentication: Authentication::Bearer }, credential)",
        ),
        (
            use_source,
            "private response length released",
            "account_id: reply.account_id,",
            "account_id: reply.discarded.len() as i64,",
        ),
    ]
    protocol_source = source.with_name("protocol.rs")
    mutations += [
        (
            protocol_source,
            "unrecorded issuance released",
            "observer.issued(&issued.claims)",
            "Ok::<(), Denial>(())",
        ),
        (
            protocol_source,
            "substituted issuance record",
            "observer.issued(&issued.claims)",
            "observer.issued(&Claims { issuer: Vec::new(), audience: Vec::new(), subject: Vec::new(), token_id: Vec::new(), certificate: Vec::new(), epoch: 0, issued_at: 0, expires_at: 1 })",
        ),
        (
            protocol_source,
            "composed authorization bypass",
            "authorize_use(\n        &inner.claims,\n        grant,\n        operation,\n        presentation.now,\n        presentation.elapsed,\n    )",
            "Ok::<(), UseDenial>(())",
        ),
        (
            protocol_source,
            "unrecorded composed dispatch",
            "observer.record(&ready.identity, &ready.claims, &grant.route, operation)",
            "Ok::<(), UseDenial>(())",
        ),
        (
            protocol_source,
            "substituted recorded identity",
            "observer.record(&ready.identity, &ready.claims, &grant.route, operation)",
            "observer.record(&Claims { certificate: Vec::new(), ..ready.identity }, &ready.claims, &grant.route, operation)",
        ),
        (
            protocol_source,
            "composed route substitution",
            "finish_use(executor, &ready.credential, &grant.route)",
            "finish_use(executor, &ready.credential, &Route { host: Vec::new(), port: 443, path: Vec::new(), authentication: crate::credential_use::Authentication::Bearer })",
        ),
    ]
    enrollment_source = source.with_name("enrollment.rs")
    mutations += [
        (
            enrollment_source,
            "TPM CSR key substitution accepted",
            "candidate.spki != *spki",
            "false",
        ),
        (
            enrollment_source,
            "software approval bypass",
            "candidate.fingerprint != *fingerprint",
            "false",
        ),
        (
            enrollment_source,
            "software assurance escalated",
            "Ok(Assurance::OperatorApproved)",
            "Ok(Assurance::AttestedTpm)",
        ),
        (
            enrollment_source,
            "approved client key replaced",
            "spki: input.candidate.spki,",
            "spki: Vec::new(),",
        ),
        (
            enrollment_source,
            "client expiry beyond CA",
            "not_after >= input.ca_not_after",
            "false",
        ),
        (
            enrollment_source,
            "client approval bypassed before signing",
            "authorize_client(input, approval)",
            "Ok::<ClientPlan, EnrollmentDenial>(ClientPlan { subject: input.subject, spki: input.candidate.spki, not_before: input.now, not_after: input.now, assurance: Assurance::AttestedTpm })",
        ),
    ]
    authority_source = source.with_name("authority.rs")
    mutations += [
        (
            authority_source,
            "current peer binding removed",
            "*certificate != *peer",
            "false",
        ),
        (
            authority_source,
            "expired authority admission accepted",
            "now >= not_after",
            "now > not_after",
        ),
        (
            authority_source,
            "software escalated at authority admission",
            "Requirement::AttestedTpm => match assurance {",
            "Requirement::AttestedTpm => match &Assurance::Tpm {",
        ),
        (
            authority_source,
            "revocation leaves client active",
            "active: false,",
            "active: true,",
        ),
        (
            authority_source,
            "authority intent bypassed",
            "store.intent()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            authority_source,
            "authority material staging bypassed",
            "store.stage()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            authority_source,
            "authority publication bypassed",
            "store.publish()",
            "Ok::<(), StorageFailure>(())",
        ),
        (
            authority_source,
            "published change reported unchanged",
            "if let Err(_) = store.complete() {\n        return Err(CommitDenial::OutcomeUnknown);",
            "if let Err(_) = store.complete() {\n        return Err(CommitDenial::Unpublished);",
        ),
    ]
    lean_path = base.run(
        [base.executable("lake"), "env", "printenv", "LEAN_PATH"],
        cwd=PROOFS,
        capture=True,
    ).stdout.strip()
    lean_path = os.pathsep.join(
        str((PROOFS / part).resolve()) for part in lean_path.split(os.pathsep)
    )

    def check_mutation(mutation) -> None:
        source, label, old, new = mutation
        if source.read_text().count(old) != 1:
            raise SystemExit(f"mutation no longer matches once: {label}")
        with tempfile.TemporaryDirectory(
            prefix="garrett-mutant-", dir=ROOT / ".tools"
        ) as scratch:
            temporary = Path(scratch)
            rust = temporary / "rust"
            shutil.copytree(
                source.parents[1], rust / "crates/aivm-secrets-garrett-core"
            )
            shutil.copy2(
                ROOT / "rust/rust-toolchain.toml", rust / "rust-toolchain.toml"
            )
            (rust / "Cargo.toml").write_text(
                '[workspace]\nmembers=["crates/aivm-secrets-garrett-core"]\nresolver="2"\n[workspace.package]\nversion="0.1.0"\nedition="2021"\nlicense="Apache-2.0"\n'
            )
            (rust / "Cargo.lock").write_text(
                'version = 4\n[[package]]\nname="aivm-secrets-garrett-core"\nversion="0.1.0"\n'
            )
            target = rust / "crates/aivm-secrets-garrett-core/src" / source.name
            target.write_text(source.read_text().replace(old, new))
            extract(temporary, rust)
            env = dict(os.environ, LEAN_PATH=str(temporary) + os.pathsep + lean_path)
            lean = [
                base.executable("elan"),
                "run",
                base.LEAN,
                "lean",
                "-DwarningAsError=true",
            ]
            base.run(
                [
                    *lean,
                    "-o",
                    temporary / "AivmSecretsGarrettCore.olean",
                    temporary / "AivmSecretsGarrettCore.lean",
                ],
                cwd=temporary,
                env=env,
            )
            rejected = False
            for module in [
                "Garrett",
                "GarrettProtocol",
                "GarrettHistory",
                "GarrettEnrollment",
                "GarrettAuthority",
            ]:
                proof = temporary / (module + ".lean")
                shutil.copy2(PROOFS / proof.name, proof)
                result = base.run(
                    [
                        *lean,
                        "-DmaxErrors=1",
                        "-o",
                        temporary / (module + ".olean"),
                        proof,
                    ],
                    cwd=temporary,
                    env=env,
                    capture=True,
                    check=False,
                )
                if result.returncode == 0:
                    continue
                infrastructure = any(
                    x in result.stdout
                    for x in [
                        "unknown module prefix",
                        "does not exist",
                        "cannot find file",
                    ]
                )
                resources = any(
                    x in (result.stdout + result.stderr).lower()
                    for x in [
                        "timeout",
                        "heartbeats",
                        "maximum recursion depth",
                        "out of memory",
                        "stack overflow",
                        "interrupted",
                    ]
                )
                if (
                    infrastructure
                    or resources
                    or not re.search(rf"{module}\.lean:\d+:\d+: error:", result.stdout)
                ):
                    raise SystemExit(
                        f"mutant failed for an unexpected reason: {label}\n{result.stdout}\n{result.stderr}"
                    )
                print(result.stdout, end="")
                print(
                    f"Lean rejected re-extracted Rust mutation: {label} ({module})",
                    flush=True,
                )
                rejected = True
                break
            if not rejected:
                raise SystemExit(f"mutant survived the proofs: {label}")

    # Each mutant has its own Rust workspace and Lean search/output directory.
    # Shared proof/model caches are read-only after the successful baseline.
    with ThreadPoolExecutor(max_workers=min(4, os.cpu_count() or 1)) as pool:
        list(pool.map(check_mutation, mutations))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["bootstrap", "extract", "record", "check", "mutate"]
    )
    args = parser.parse_args()
    if args.action == "bootstrap":
        base.bootstrap()
    elif args.action == "extract":
        extract(PROOFS / "generated")
    elif args.action == "record":
        record()
    else:
        check_manifest()
        regeneration()
        prove()
        if args.action == "mutate":
            mutate()
        else:
            parity()


if __name__ == "__main__":
    main()
