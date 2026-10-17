//! Cut-point simulation around real filesystem adapters. No production fault
//! flag exists; recovery below is the normal, exact-plan-CAS library API.
use super::*;
use std::os::unix::fs::PermissionsExt;
use trust::TrustStore;

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("ag-trust-unit-{}", files::random_id().unwrap()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn enroll(authority: &IdentityAuthority, now: i64) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    let request = ClientRequest::from_pem(csr.as_bytes()).unwrap();
    let fingerprint = request.fingerprint();
    authority
        .enroll_software(
            "unit-client",
            request,
            &fingerprint,
            EnrollmentOptions::new(now),
        )
        .unwrap();
}
#[derive(Clone, Copy)]
enum Cut {
    Stage,
    Retire,
    BeforeActivation,
    Activation,
    Completion,
}
struct Interrupted<'a, 'b> {
    inner: &'a PlannedChange<'b>,
    cut: Cut,
}
impl TrustStore for Interrupted<'_, '_> {
    fn intent(&self) -> Result<(), core::StorageFailure> {
        self.inner.intent()
    }
    fn stage(&self) -> Result<(), core::StorageFailure> {
        self.inner.stage()?;
        if matches!(self.cut, Cut::Stage) {
            Err(core::StorageFailure::Failed)
        } else {
            Ok(())
        }
    }
    fn retire(&self) -> Result<(), core::StorageFailure> {
        self.inner.retire()?;
        if matches!(self.cut, Cut::Retire) {
            Err(core::StorageFailure::Failed)
        } else {
            Ok(())
        }
    }
    fn activate(&self) -> Result<(), core::StorageFailure> {
        if matches!(self.cut, Cut::BeforeActivation) {
            return Err(core::StorageFailure::Failed);
        }
        self.inner.activate()?;
        if matches!(self.cut, Cut::Activation) {
            Err(core::StorageFailure::Failed)
        } else {
            Ok(())
        }
    }
    fn complete(&self) -> Result<(), core::StorageFailure> {
        self.inner.complete()?;
        if matches!(self.cut, Cut::Completion) {
            Err(core::StorageFailure::Failed)
        } else {
            Ok(())
        }
    }
}
#[test]
fn interrupted_rollovers_recover_only_forward_from_valid_prefixes() {
    for cut in [
        Cut::Stage,
        Cut::Retire,
        Cut::BeforeActivation,
        Cut::Activation,
        Cut::Completion,
    ] {
        let work = Workspace::new();
        let path = work.0.join("authority");
        let now = 1000;
        let authority =
            IdentityAuthority::initialize(&path, "aivm.test", "aivm-secrets.remote", now).unwrap();
        enroll(&authority, now);
        let result = authority
            .rotate_ca(text(&authority.pinned["ca"], "sha256").unwrap(), now)
            .unwrap();
        let id = text(&result, "transaction").unwrap();
        let plan = authority.read_plan(id).unwrap();
        // Test setup obtains an actual validated plan and immutable key pairs
        // from the normal writer, then reconstructs the old fixture snapshot.
        // Rollback here is confined to this disposable unit-test directory.
        for (name, key) in [
            ("authority.json", "authority"),
            ("enrollments.json", "registry"),
        ] {
            authority
                .root
                .replace(name, &json::canonical(&plan["before"][key]))
                .unwrap();
        }
        {
            let _lease = authority.root.lock(true).unwrap();
            let transaction = authority
                .planned_change(id, plan.clone(), None, now, false)
                .unwrap();
            let interrupted = Interrupted {
                inner: &transaction,
                cut,
            };
            let committed = trust::commit_trust(
                &interrupted,
                &anchor(&plan["before"]),
                &anchor(&plan["before"]),
            );
            if matches!(cut, Cut::Stage) {
                assert!(matches!(committed, Err(trust::TrustDenial::Unpublished)));
            } else {
                assert!(matches!(committed, Err(trust::TrustDenial::OutcomeUnknown)));
            }
            let current = snapshot(&authority.root).unwrap();
            let prefix = phase(&plan, &current).unwrap();
            match cut {
                Cut::Stage => assert!(matches!(prefix, RecoveryPhase::Unchanged)),
                Cut::Retire | Cut::BeforeActivation => {
                    assert!(matches!(prefix, RecoveryPhase::Retired));
                    assert_eq!(
                        current["registry"]["subjects"]["unit-client"]["active"],
                        false
                    );
                    assert_eq!(current["authority"], plan["before"]["authority"]);
                }
                Cut::Activation | Cut::Completion => {
                    assert!(matches!(prefix, RecoveryPhase::Activated))
                }
            }
        }
        let recovery = IdentityAuthority::open(&path).unwrap();
        recovery
            .recover_transaction(id, text(&result, "plan_sha256").unwrap(), now + 1)
            .unwrap();
        assert_eq!(snapshot(&recovery.root).unwrap(), plan["after"]);
        assert_eq!(
            IdentityAuthority::open(&path).unwrap().status().unwrap()["subjects"]["unit-client"]
                ["active"],
            false
        );
    }
}

#[test]
fn recovery_refuses_partial_private_material_and_new_enrollments() {
    let work = Workspace::new();
    let path = work.0.join("authority");
    let authority =
        IdentityAuthority::initialize(&path, "aivm.test", "aivm-secrets.remote", 1000).unwrap();
    enroll(&authority, 1000);
    let result = authority
        .rotate_ca(text(&authority.pinned["ca"], "sha256").unwrap(), 1000)
        .unwrap();
    let id = text(&result, "transaction").unwrap();
    let digest = text(&result, "plan_sha256").unwrap();
    let plan = authority.read_plan(id).unwrap();
    let recovery = IdentityAuthority::open(&path).unwrap();
    enroll(&recovery, 1001);
    let before = snapshot(&recovery.root).unwrap();
    assert!(matches!(
        recovery.recover_transaction(id, digest, 1001),
        Err(Error::Revoked)
    ));
    assert_eq!(snapshot(&recovery.root).unwrap(), before);
    // Restore a valid interrupted-prefix fixture, then corrupt one private
    // stage. Recovery must refuse instead of regenerating/adopting that key.
    recovery
        .root
        .replace(
            "enrollments.json",
            &json::canonical(&plan["after"]["registry"]),
        )
        .unwrap();
    let ca_key = path.join("ca-generations/ca-2.key");
    let original = Zeroizing::new(std::fs::read(&ca_key).unwrap());
    std::fs::write(&ca_key, b"partial key").unwrap();
    assert!(recovery.recover_transaction(id, digest, 1002).is_err());
    assert_eq!(std::fs::read(&ca_key).unwrap(), b"partial key");
    assert_eq!(snapshot(&recovery.root).unwrap(), plan["after"]);
    std::fs::write(&ca_key, &original).unwrap();
    recovery.recover_transaction(id, digest, 1002).unwrap();
}

#[test]
fn public_registry_mutation_cannot_override_held_authority_state() {
    let work = Workspace::new();
    let authority = IdentityAuthority::initialize(
        &work.0.join("authority"),
        "aivm.test",
        "aivm-secrets.remote",
        1000,
    )
    .unwrap();
    enroll(&authority, 1000);
    let before = snapshot(&authority.root).unwrap();
    for field in ["state", "issuer", "audience", "version", "action"] {
        let mut input = json!({"subject":"unit-client"});
        input[field] = json!("untrusted-override");
        assert!(matches!(
            authority.mutate_registry("revoke", input, 1001),
            Err(Error::InvalidRequest)
        ));
        assert_eq!(snapshot(&authority.root).unwrap(), before);
    }
}

#[test]
fn non_utf8_coordinates_are_refused_before_publication_or_reply_serialization() {
    use std::os::unix::ffi::OsStringExt;
    let work = Workspace::new();
    let invalid_parent = work
        .0
        .join(std::ffi::OsString::from_vec(b"invalid-\xff".to_vec()));
    std::fs::create_dir(&invalid_parent).unwrap();
    std::fs::set_permissions(&invalid_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let authority = IdentityAuthority::initialize(
        &work.0.join("authority"),
        "aivm.test",
        "aivm-secrets.remote",
        1000,
    )
    .unwrap();
    enroll(&authority, 1000);
    let output = invalid_parent.join("token");
    let before = snapshot(&authority.root).unwrap();
    assert!(matches!(
        authority.issue_to_file("unit-client", b"aivs1.synthetic", &output, 300, false, 1000),
        Err(Error::UnsafeFile)
    ));
    assert!(!output.exists());
    assert_eq!(snapshot(&authority.root).unwrap(), before);
    assert!(matches!(
        IdentityAuthority::initialize(
            &invalid_parent.join("authority"),
            "aivm.test",
            "aivm-secrets.remote",
            1000
        ),
        Err(Error::UnsafeFile)
    ));
    assert!(!invalid_parent.join("authority").exists());
}
