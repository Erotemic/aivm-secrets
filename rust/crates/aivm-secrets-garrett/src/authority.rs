//! Principal-owned v2 authority storage. No private key/capability reply API.
use crate::{
    attestation::VerifiedIdentity,
    certificates::{self, CertificateAuthority, ClientRequest},
    crypto::{self, Issuer, Verifier},
    files::{self, PrivateDirectory},
    json, lifecycle,
    model::Registry,
    registry, tls, Error, Outcome,
};
use aivm_secrets_garrett_core::authority as core;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::digest;
use serde_json::{json, Value};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}
fn text<'a>(v: &'a Value, key: &str) -> Outcome<&'a str> {
    v[key].as_str().ok_or(Error::InvalidCapability)
}
fn number(v: &Value, key: &str) -> Outcome<i64> {
    v[key].as_i64().ok_or(Error::InvalidCapability)
}
fn selection(root: &PrivateDirectory) -> Outcome<Value> {
    let value = json::parse(&root.read("authority.json", 4096)?, 4096)?;
    Ok(
        lifecycle::evaluate_authority(&json!({"version":1,"action":"validate","state":value}))?
            ["state"]
            .clone(),
    )
}
fn keyring(root: &PrivateDirectory) -> Outcome<Value> {
    let value = json::parse(&root.read("issuer-keyring.json", 4096)?, 4096)?;
    let m = json::keys(&value, &["schema", "active", "enabled", "next_number"], &[])?;
    json::integer(&m["schema"], 1, 1)?;
    json::integer(&m["next_number"], 2, 100000)?;
    let enabled = m["enabled"].as_array().ok_or(Error::InvalidCapability)?;
    if enabled.is_empty() || enabled.len() > 8 {
        return Err(Error::InvalidCapability);
    }
    let mut seen = std::collections::BTreeSet::new();
    for kid in enabled {
        let name = kid.as_str().ok_or(Error::InvalidCapability)?;
        if !name.starts_with("local-")
            || name.len() > 32
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || !seen.insert(name)
        {
            return Err(Error::InvalidCapability);
        }
    }
    if !enabled.contains(&m["active"]) {
        return Err(Error::InvalidCapability);
    }
    Ok(value)
}
fn ca_public(root: &PrivateDirectory, selected: &Value) -> Outcome<Vec<u8>> {
    let ca = root.child("ca-generations")?.read(
        &format!("ca-{}.pem", number(&selected["ca"], "generation")?),
        65536,
    )?;
    if sha(&certificates::checked_ca_der(&ca)?) != text(&selected["ca"], "sha256")? {
        return Err(Error::InvalidCapability);
    }
    Ok(ca)
}
fn read_registry(root: &PrivateDirectory, selected: &Value) -> Outcome<Value> {
    let value = json::parse(&root.read("enrollments.json", 131072)?, 131072)?;
    Registry::parse(
        &value,
        text(selected, "issuer")?,
        text(selected, "audience")?,
    )?;
    Ok(value)
}
fn receipt_mode(receipt: &Value) -> Outcome<core::Assurance> {
    match text(receipt, "mode")? {
        "attested-tpm" => Ok(core::Assurance::Tpm),
        "operator-approved-software" => Ok(core::Assurance::Software),
        _ => Err(Error::InvalidCapability),
    }
}

pub struct IdentityAuthority {
    root: PrivateDirectory,
    path: PathBuf,
    pinned: Value,
}
pub struct EnrollmentOptions {
    pub replace: bool,
    pub expected_epoch: Option<i64>,
    pub expected_thumbprint: Option<String>,
    pub renew: bool,
    pub require_new_key: bool,
    pub allow_assurance_downgrade: bool,
    pub now: i64,
}
impl EnrollmentOptions {
    pub fn new(now: i64) -> Self {
        Self {
            replace: false,
            expected_epoch: None,
            expected_thumbprint: None,
            renew: false,
            require_new_key: false,
            allow_assurance_downgrade: false,
            now,
        }
    }
}
enum Approval {
    Software(String),
    Tpm(VerifiedIdentity),
}
impl IdentityAuthority {
    pub fn open(path: &Path) -> Outcome<Self> {
        let root = PrivateDirectory::open(path)?;
        let _lock = root.lock(false)?;
        let pinned = selection(&root)?;
        ca_public(&root, &pinned)?;
        Ok(Self {
            root,
            path: path.to_owned(),
            pinned,
        })
    }
    pub fn initialize(path: &Path, issuer: &str, audience: &str, now: i64) -> Outcome<Self> {
        json::word(&json!(issuer), 128)?;
        json::word(&json!(audience), 128)?;
        let parent = PrivateDirectory::open(path.parent().ok_or(Error::UnsafeFile)?)?;
        let target = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(Error::UnsafeFile)?;
        if parent.exists(target)? {
            return Err(Error::UnsafeFile);
        }
        let staged = format!(".aivm-secrets-init-{}", files::random_id()?);
        let root = parent.create_directory(&staged)?;
        let ca = CertificateAuthority::generate(now)?;
        let (server, key) = ca.server_material(now)?;
        let (jwt_private, jwt_public, aes) = crypto::issuer_material()?;
        let ca_directory = root.create_directory("ca-generations")?;
        let server_directory = root.create_directory("server-generations")?;
        let keys = root.create_directory("issuer-keys")?;
        root.create_directory("clients")?;
        root.create_directory("audit")?;
        ca_directory.write_new("ca-1.key", ca.secret_pem().as_bytes())?;
        ca_directory.write_new("ca-1.pem", ca.certificate_pem().as_bytes())?;
        server_directory.write_new("server-1.key", key.as_bytes())?;
        server_directory.write_new("server-1.pem", server.as_bytes())?;
        keys.write_new("local-1.key", jwt_private.as_bytes())?;
        keys.write_new("local-1.pub", jwt_public.as_bytes())?;
        keys.write_new("local-1.aes256", &aes)?;
        root.write_new(".enrollment.lock", b"")?;
        root.write_new(
            "issuer-keyring.json",
            &json::canonical(
                &json!({"schema":1,"active":"local-1","enabled":["local-1"],"next_number":2}),
            ),
        )?;
        root.write_new(
            "enrollments.json",
            &json::canonical(&json!({"schema":1,"subjects":{}})),
        )?;
        let hash = sha(&certificates::checked_ca_der(
            ca.certificate_pem().as_bytes(),
        )?);
        let selected=lifecycle::evaluate_authority(&json!({"version":1,"action":"init","issuer":issuer,"audience":audience,"created_at":now,"ca_sha256":hash}))?["state"].clone();
        // The public selector is last. Publish only a complete, durable tree;
        // interrupted staging remains private and is never silently adopted.
        root.write_new("authority.json", &json::canonical(&selected))?;
        root.sync()?;
        parent.publish_directory(&staged, target)?;
        Ok(Self {
            root,
            path: path.to_owned(),
            pinned: selected,
        })
    }
    fn current(&self) -> Outcome<Value> {
        let selected = selection(&self.root)?;
        if selected["ca"] != self.pinned["ca"]
            || selected["issuer"] != self.pinned["issuer"]
            || selected["audience"] != self.pinned["audience"]
        {
            return Err(Error::Revoked);
        }
        ca_public(&self.root, &selected)?;
        Ok(selected)
    }
    fn ca(&self, selected: &Value) -> Outcome<CertificateAuthority> {
        let directory = self.root.child("ca-generations")?;
        let key = Zeroizing::new(directory.read(
            &format!("ca-{}.key", number(&selected["ca"], "generation")?),
            8192,
        )?);
        CertificateAuthority::from_pem(&ca_public(&self.root, selected)?, &key)
    }
    fn evaluate_registry(&self, state: &Value, action: &str, extra: Value) -> Outcome<Value> {
        let mut input = json!({"version":1,"action":action,"issuer":self.pinned["issuer"],"audience":self.pinned["audience"],"state":state});
        let object = input.as_object_mut().ok_or(Error::InvalidCapability)?;
        object.extend(extra.as_object().ok_or(Error::InvalidCapability)?.clone());
        registry::evaluate(&input)
    }
    fn certificate(&self, row: &Value, ca: &[u8]) -> Outcome<(Vec<u8>, certificates::ClientInfo)> {
        let thumb = text(row, "certificate_sha256")?;
        let digest = crypto::decode(thumb, 64)?;
        if digest.len() != 32 {
            return Err(Error::InvalidCapability);
        }
        let pem = self
            .root
            .child("clients")?
            .read(&format!("{}.pem", hex(&digest)), 65536)?;
        let info = certificates::inspect_client(&pem, ca)?;
        if crypto::certificate_thumbprint(&info.der)? != thumb
            || info.fingerprint != text(row, "key_sha256")?
            || info.not_after != number(row, "not_after")?
        {
            return Err(Error::InvalidCapability);
        }
        Ok((pem, info))
    }
    fn receipt(&self, subject: &str, row: &Value) -> Outcome<Option<Value>> {
        let digest = crypto::decode(text(row, "certificate_sha256")?, 64)?;
        let clients = self.root.child("clients")?;
        let name = format!("{}.assurance.json", hex(&digest));
        if !clients.exists(&name)? {
            return Ok(None);
        }
        let receipt = json::parse(&clients.read(&name, 4096)?, 4096)?;
        json::keys(
            &receipt,
            &[
                "schema",
                "subject",
                "certificate_sha256",
                "spki_sha256",
                "mode",
                "issued_at",
            ],
            &["ak_pin_sha256", "key_name_hex"],
        )?;
        json::integer(&receipt["schema"], 1, 1)?;
        json::integer(&receipt["issued_at"], 0, i64::MAX)?;
        if receipt["subject"] != subject
            || receipt["certificate_sha256"] != row["certificate_sha256"]
            || receipt["spki_sha256"] != row["key_sha256"]
        {
            return Err(Error::InvalidCapability);
        }
        if matches!(receipt_mode(&receipt)?, core::Assurance::Tpm) {
            json::hex(&receipt["ak_pin_sha256"], 64)?;
            json::hex(&receipt["key_name_hex"], 68)?;
        } else if receipt.get("ak_pin_sha256").is_some() || receipt.get("key_name_hex").is_some() {
            return Err(Error::InvalidCapability);
        }
        Ok(Some(receipt))
    }
    pub fn status(&self) -> Outcome<Value> {
        let _lock = self.root.lock(false)?;
        let selected = self.current()?;
        let registry = read_registry(&self.root, &selected)?;
        Ok(
            json!({"issuer":selected["issuer"],"audience":selected["audience"],"ca_sha256":selected["ca"]["sha256"],"ca_generation":selected["ca"]["generation"],"server_generation":selected["server"]["generation"],"subjects":registry["subjects"]}),
        )
    }
    pub fn public_client(&self, subject: &str, now: i64) -> Outcome<Value> {
        json::word(&json!(subject), 128)?;
        let _lock = self.root.lock(false)?;
        let selected = self.current()?;
        let state = read_registry(&self.root, &selected)?;
        let row = state["subjects"].get(subject).ok_or(Error::Revoked)?;
        if row["active"] != true || now < 0 || now >= number(row, "not_after")? {
            return Err(Error::Revoked);
        }
        let ca = ca_public(&self.root, &selected)?;
        let (pem, _) = self.certificate(row, &ca)?;
        let receipt = self.receipt(subject, row)?;
        Ok(
            json!({"subject":subject,"certificate_sha256":row["certificate_sha256"],"certificate_pem_b64":STANDARD.encode(pem),"ca_pem_b64":STANDARD.encode(ca),"epoch":row["epoch"],"not_after":row["not_after"],"assurance":receipt}),
        )
    }
    pub fn enroll_software(
        &self,
        subject: &str,
        request: ClientRequest,
        approved: &str,
        options: EnrollmentOptions,
    ) -> Outcome<Value> {
        self.enroll(
            subject,
            request,
            Approval::Software(approved.to_owned()),
            options,
        )
    }
    pub fn enroll_tpm(
        &self,
        subject: &str,
        request: ClientRequest,
        verified: VerifiedIdentity,
        options: EnrollmentOptions,
    ) -> Outcome<Value> {
        self.enroll(subject, request, Approval::Tpm(verified), options)
    }
    fn enroll(
        &self,
        subject: &str,
        request: ClientRequest,
        approval: Approval,
        options: EnrollmentOptions,
    ) -> Outcome<Value> {
        json::word(&json!(subject), 128)?;
        let cas = options.expected_epoch.is_some() || options.expected_thumbprint.is_some();
        if (cas
            && (!options.replace && !options.renew
                || options.expected_epoch.is_none()
                || options.expected_thumbprint.is_none()))
            || (options.renew && !cas)
            || (options.require_new_key && !options.renew)
            || (options.renew && options.replace)
            || options
                .expected_epoch
                .is_some_and(|e| !(0..=i32::MAX as i64).contains(&e))
        {
            return Err(Error::InvalidCapability);
        }
        let fingerprint = request.fingerprint();
        let _lock = self.root.lock(true)?;
        let selected = self.current()?;
        let state = read_registry(&self.root, &selected)?;
        if let Some(prior) = state["subjects"].get(subject) {
            if matches!(approval, Approval::Software(_))
                && !options.allow_assurance_downgrade
                && self
                    .receipt(subject, prior)?
                    .is_some_and(|r| r["mode"] == "attested-tpm")
            {
                return Err(Error::Denied);
            }
        }
        if cas {
            let prior = state["subjects"].get(subject).ok_or(Error::Revoked)?;
            if prior["epoch"] != options.expected_epoch.unwrap()
                || prior["certificate_sha256"]
                    != options.expected_thumbprint.as_ref().unwrap().as_str()
                || (options.renew && prior["active"] != true)
            {
                return Err(Error::Revoked);
            }
            if options.renew {
                let (_, current) = self.certificate(prior, &ca_public(&self.root, &selected)?)?;
                if (current.fingerprint == fingerprint) == options.require_new_key {
                    return Err(Error::Denied);
                }
            }
        }
        let ca = self.ca(&selected)?;
        let mut receipt =
            json!({"schema":1,"subject":subject,"spki_sha256":fingerprint,"issued_at":options.now});
        let issued = match approval {
            Approval::Software(fp) => ca.enroll_software(request, subject, &fp, options.now)?,
            Approval::Tpm(verified) => {
                receipt["ak_pin_sha256"] = json!(hex(verified.attestation_pin_sha256()));
                receipt["key_name_hex"] = json!(hex(verified.key_name()));
                ca.enroll_tpm(request, subject, verified, options.now)?
            }
        };
        receipt["mode"] = json!(match issued.plan.assurance {
            aivm_secrets_garrett_core::enrollment::Assurance::OperatorApproved =>
                "operator-approved-software",
            aivm_secrets_garrett_core::enrollment::Assurance::AttestedTpm => "attested-tpm",
        });
        let thumb = crypto::certificate_thumbprint(&issued.certificate)?;
        receipt["certificate_sha256"] = json!(thumb);
        let mut extra = json!({"subject":subject,"thumbprint":thumb,"key_sha256":fingerprint,"not_after":issued.plan.not_after});
        let action = if options.renew {
            extra["now"] = json!(options.now);
            "renew"
        } else if cas {
            "replace-if-current"
        } else {
            extra["replace"] = json!(options.replace);
            "enroll"
        };
        if cas {
            extra["expected_epoch"] = json!(options.expected_epoch);
            extra["expected_thumbprint"] = json!(options.expected_thumbprint);
        }
        let updated = self.evaluate_registry(&state, action, extra)?["state"].clone();
        let stem = sha(&issued.certificate);
        let material = vec![
            (
                format!("{stem}.pem"),
                certificates::client_certificate_pem(&issued).into_bytes(),
            ),
            (format!("{stem}.assurance.json"), json::canonical(&receipt)),
        ];
        self.commit(
            if options.renew {
                if options.require_new_key {
                    "identity_rekey_intent"
                } else {
                    "identity_renew_intent"
                }
            } else {
                "identity_enroll_intent"
            },
            subject,
            options.now,
            &state,
            &updated,
            material,
        )?;
        Ok(
            json!({"subject":subject,"epoch":updated["subjects"][subject]["epoch"],"certificate":self.path.join("clients").join(format!("{stem}.pem")),"certificate_sha256":thumb,"not_after":issued.plan.not_after,"assurance":receipt}),
        )
    }
    pub fn mutate_registry(&self, action: &str, extra: Value, now: i64) -> Outcome<Value> {
        json::integer(&json!(now), 0, i64::MAX)?;
        if !matches!(action, "revoke" | "revoke-if-current" | "forget" | "prune") {
            return Err(Error::InvalidRequest);
        }
        let _lock = self.root.lock(true)?;
        let selected = self.current()?;
        let before = read_registry(&self.root, &selected)?;
        let result = self.evaluate_registry(&before, action, extra.clone())?;
        if result["state"] != before {
            self.commit(
                match action {
                    "forget" => "identity_forget_intent",
                    "prune" => "identity_prune_intent",
                    _ => "identity_revoke_intent",
                },
                extra
                    .get("subject")
                    .and_then(Value::as_str)
                    .unwrap_or("all"),
                now,
                &before,
                &result["state"],
                Vec::new(),
            )?;
        }
        Ok(result)
    }
    fn commit(
        &self,
        event: &str,
        subject: &str,
        now: i64,
        before: &Value,
        after: &Value,
        material: Vec<(String, Vec<u8>)>,
    ) -> Outcome<()> {
        if json::canonical(after).len() > 131072 {
            return Err(Error::InvalidCapability);
        }
        let id = files::random_id()?;
        let directory = self.root.child("audit")?;
        let audit = directory.create_file(&format!("{id}.jsonl"))?;
        directory.sync()?;
        let intent = json!({"schema":2,"seq":0,"prev":"0".repeat(64),"channel":id,"event":event,"request_id":"","timestamp":now,"code":"","resource":{"subject":subject,"previous_sha256":sha(&json::canonical(before)),"next_sha256":sha(&json::canonical(after)),"materials":material.iter().map(|(n,_)|n).collect::<Vec<_>>()},"digest":sha(&json::canonical(after))});
        let transaction = Transaction {
            root: &self.root,
            audit: Mutex::new(audit),
            intent,
            next: json::canonical(after),
            material,
        };
        core::commit_change(&transaction).map_err(|e| match e {
            core::CommitDenial::Unpublished => Error::InternalError,
            core::CommitDenial::OutcomeUnknown => Error::OutcomeUnknown,
        })
    }
}

struct Transaction<'a> {
    root: &'a PrivateDirectory,
    audit: Mutex<File>,
    intent: Value,
    next: Vec<u8>,
    material: Vec<(String, Vec<u8>)>,
}
impl Transaction<'_> {
    fn record(&self, value: &Value) -> Result<(), core::StorageFailure> {
        let mut file = self
            .audit
            .lock()
            .map_err(|_| core::StorageFailure::Failed)?;
        file.write_all(&json::canonical(value))
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| core::StorageFailure::Failed)
    }
}
impl core::ChangeStore for Transaction<'_> {
    fn intent(&self) -> Result<(), core::StorageFailure> {
        self.record(&self.intent)
    }
    fn stage(&self) -> Result<(), core::StorageFailure> {
        let clients = self
            .root
            .child("clients")
            .map_err(|_| core::StorageFailure::Failed)?;
        for (name, data) in &self.material {
            clients
                .write_new(name, data)
                .map_err(|_| core::StorageFailure::Failed)?;
        }
        Ok(())
    }
    fn publish(&self) -> Result<(), core::StorageFailure> {
        self.root
            .replace("enrollments.json", &self.next)
            .map_err(|_| core::StorageFailure::Failed)
    }
    fn complete(&self) -> Result<(), core::StorageFailure> {
        self.record(&json!({"schema":2,"seq":1,"prev":sha(&json::canonical(&self.intent)),"channel":self.intent["channel"],"event":"identity_recorded","request_id":"","timestamp":self.intent["timestamp"],"code":"","digest":self.intent["digest"]}))
    }
}

pub(crate) struct AuthorityView {
    authority: IdentityAuthority,
    required: core::Requirement,
}
pub(crate) struct Bootstrap {
    pub _lease: File,
    pub view: Arc<AuthorityView>,
    pub registry: Registry,
    pub issuer: String,
    pub audience: String,
    pub tls: tls::AuthenticatedServerConfig,
    pub signer: Option<Issuer>,
    pub verifier: Verifier,
}
pub(crate) struct Admission {
    pub _lease: File,
    pub registry: Registry,
    pub verifier: Verifier,
}
impl AuthorityView {
    pub(crate) fn bootstrap(
        path: &Path,
        require_tpm: bool,
        needs_signer: bool,
    ) -> Outcome<Bootstrap> {
        let authority = IdentityAuthority::open(path)?;
        let lease = authority.root.lock(false)?;
        let selected = authority.current()?;
        let registry = Registry::parse(
            &read_registry(&authority.root, &selected)?,
            text(&selected, "issuer")?,
            text(&selected, "audience")?,
        )?;
        let ca = ca_public(&authority.root, &selected)?;
        let generation = number(&selected["server"], "generation")?;
        let servers = authority.root.child("server-generations")?;
        let certificate = servers.read(&format!("server-{generation}.pem"), 65536)?;
        let key = Zeroizing::new(servers.read(&format!("server-{generation}.key"), 8192)?);
        let tls = tls::server_config(&certificate, &key, &ca)?;
        let keys = keyring(&authority.root)?;
        let kid = text(&keys, "active")?;
        let (public, aes) = Self::keys(&authority.root, kid)?;
        let verifier = Verifier::new(&crypto::issuer_public(&public)?, &aes, kid)?;
        let signer = if needs_signer {
            Some(Issuer::from_pem(
                &Zeroizing::new(
                    authority
                        .root
                        .child("issuer-keys")?
                        .read(&format!("{kid}.key"), 4096)?,
                ),
                &public,
                &aes,
                kid,
            )?)
        } else {
            None
        };
        let issuer = text(&selected, "issuer")?.to_owned();
        let audience = text(&selected, "audience")?.to_owned();
        Ok(Bootstrap {
            _lease: lease,
            view: Arc::new(Self {
                authority,
                required: if require_tpm {
                    core::Requirement::AttestedTpm
                } else {
                    core::Requirement::Enrolled
                },
            }),
            registry,
            issuer,
            audience,
            tls,
            signer,
            verifier,
        })
    }
    fn keys(root: &PrivateDirectory, kid: &str) -> Outcome<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let directory = root.child("issuer-keys")?;
        Ok((
            directory.read(&format!("{kid}.pub"), 4096)?,
            Zeroizing::new(directory.read(&format!("{kid}.aes256"), 32)?),
        ))
    }
    pub(crate) fn admit(
        &self,
        token: &str,
        peer: &str,
        clock: &impl Fn() -> i64,
    ) -> Outcome<Admission> {
        let lease = self.authority.root.lock(false)?;
        // An administrative operation may have held the exclusive lease.
        // Sample the trusted clock after waiting, rather than extending expiry.
        let now = clock();
        let selected = self.authority.current()?;
        let ring = keyring(&self.authority.root)?;
        let kid = crypto::token_key_id(token)?;
        if !ring["enabled"]
            .as_array()
            .ok_or(Error::InvalidCapability)?
            .contains(&json!(kid))
        {
            return Err(Error::Revoked);
        }
        let state = read_registry(&self.authority.root, &selected)?;
        let registry = Registry::parse(
            &state,
            text(&selected, "issuer")?,
            text(&selected, "audience")?,
        )?;
        let expected = registry.expectation(
            text(&selected, "issuer")?,
            text(&selected, "audience")?,
            peer,
            now,
        )?;
        let subject =
            std::str::from_utf8(&expected.subject).map_err(|_| Error::InvalidCapability)?;
        let row = &state["subjects"][subject];
        let receipt = self.authority.receipt(subject, row)?;
        let assurance = receipt
            .as_ref()
            .map(receipt_mode)
            .transpose()?
            .unwrap_or(core::Assurance::Unrecorded);
        if matches!(self.required, core::Requirement::AttestedTpm) {
            self.authority
                .certificate(row, &ca_public(&self.authority.root, &selected)?)?;
        }
        core::require_peer(
            row["active"].as_bool().ok_or(Error::InvalidCapability)?,
            &text(row, "certificate_sha256")?.as_bytes().to_vec(),
            &peer.as_bytes().to_vec(),
            number(row, "not_after")?,
            now,
            &assurance,
            &self.required,
        )
        .map_err(|_| Error::Denied)?;
        let (public, aes) = Self::keys(&self.authority.root, &kid)?;
        let verifier = Verifier::new(&crypto::issuer_public(&public)?, &aes, &kid)?;
        Ok(Admission {
            _lease: lease,
            registry,
            verifier,
        })
    }
    fn check_issuance(&self, subject: &str, now: i64) -> Outcome<()> {
        let selected = self.authority.current()?;
        let state = read_registry(&self.authority.root, &selected)?;
        let row = state["subjects"]
            .get(subject)
            .ok_or(Error::InvalidCapability)?;
        let receipt = self.authority.receipt(subject, row)?;
        let assurance = receipt
            .as_ref()
            .map(receipt_mode)
            .transpose()?
            .unwrap_or(core::Assurance::Unrecorded);
        let peer = text(row, "certificate_sha256")?.as_bytes().to_vec();
        if matches!(self.required, core::Requirement::AttestedTpm) {
            self.authority
                .certificate(row, &ca_public(&self.authority.root, &selected)?)?;
        }
        core::require_peer(
            row["active"].as_bool().ok_or(Error::InvalidCapability)?,
            &peer,
            &peer,
            number(row, "not_after")?,
            now,
            &assurance,
            &self.required,
        )
        .map_err(|_| Error::Denied)
    }
}

/// Explicit native authority backend. Trust/key/registry paths come from the
/// held store and cannot be mixed with the legacy bridge's independent files.
pub fn bridge_from_config(config: &Value, now: i64) -> Outcome<(tls::Bridge, Value)> {
    let m = json::keys(
        config,
        &["schema", "authority_root", "client_assurance", "listen"],
        &[
            "subject",
            "broker_socket",
            "provider",
            "binding",
            "lifetime",
        ],
    )?;
    json::integer(&m["schema"], 1, 1)?;
    let require_tpm = match text(config, "client_assurance")? {
        "any-enrolled" => false,
        "attested-tpm" => true,
        _ => return Err(Error::InvalidCapability),
    };
    if m.contains_key("provider") == m.contains_key("broker_socket") {
        return Err(Error::InvalidCapability);
    }
    let subject = m
        .get("subject")
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidCapability)
        })
        .transpose()?;
    let boot = AuthorityView::bootstrap(
        Path::new(text(config, "authority_root")?),
        require_tpm,
        m.contains_key("provider"),
    )?;
    let (bridge, ready) = if let Some(provider_config) = m.get("provider") {
        let subject_name = subject.as_deref().ok_or(Error::InvalidCapability)?;
        boot.view.check_issuance(subject_name, now)?;
        let lifetime = json::integer(m.get("lifetime").ok_or(Error::InvalidCapability)?, 1, 3600)?;
        let provider = crate::ProviderSession::start(
            provider_config,
            m.get("binding").ok_or(Error::InvalidCapability)?,
            now,
            lifetime,
        )?;
        let signer = boot.signer.as_ref().ok_or(Error::InvalidCapability)?;
        let issued = provider.issue(
            signer,
            &boot.registry,
            &boot.issuer,
            &boot.audience,
            subject_name,
            now,
            lifetime,
        )?;
        let ready = json!({"version":1,"ready":true,"profile":"account-status-v1","capability":std::str::from_utf8(&issued.token).map_err(|_|Error::InternalError)?,"expires_at":issued.claims.expires_at});
        (
            tls::Bridge::new_provider(
                boot.tls,
                boot.verifier,
                boot.registry,
                boot.issuer,
                boot.audience,
                subject,
                provider,
            )?,
            ready,
        )
    } else {
        if m.contains_key("binding") || m.contains_key("lifetime") {
            return Err(Error::InvalidCapability);
        }
        (
            tls::Bridge::new(
                boot.tls,
                boot.verifier,
                boot.registry,
                boot.issuer,
                boot.audience,
                subject,
                PathBuf::from(text(config, "broker_socket")?),
            )?,
            json!({"version":1,"ready":true}),
        )
    };
    Ok((bridge.with_authority_view(boot.view)?, ready))
}
