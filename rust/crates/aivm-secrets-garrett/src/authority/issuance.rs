//! A host selects an existing inner capability by private file, and receives
//! only output coordinates. Source issuance is acknowledged before publication.
use super::*;
use aivm_secrets_garrett_core::{protocol::IssuanceObserver, Claims, Denial};

struct IssuanceLog {
    file: File,
    intent: Option<Value>,
    failed: bool,
}
impl IssuanceLog {
    fn record(&mut self, value: &Value) -> Outcome<()> {
        if self.failed {
            return Err(Error::InternalError);
        }
        let result = self
            .file
            .write_all(&json::canonical(value))
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.sync_all());
        if result.is_err() {
            self.failed = true;
            return Err(Error::InternalError);
        }
        Ok(())
    }
}
struct IssuanceAudit {
    log: Mutex<IssuanceLog>,
    channel: String,
    output: String,
    now: i64,
}
impl IssuanceObserver for IssuanceAudit {
    fn issued(&self, claims: &Claims) -> Result<(), Denial> {
        let issue = || -> Outcome<()> {
            let mut log = self.log.lock().map_err(|_| Error::InternalError)?;
            if log.intent.is_some() {
                return Err(Error::InternalError);
            }
            let public = crate::model::claims_json(claims)?;
            let intent = json!({"schema":2,"seq":0,"prev":"0".repeat(64),"channel":self.channel,"event":"identity_token_issue_intent","request_id":"","timestamp":self.now,"code":"","resource":{"subject":public["sub"],"certificate_sha256":public["cnf"]["x5t#S256"],"epoch":public["epoch"],"expires_at":public["exp"],"output":self.output},"digest":sha(&claims.token_id)});
            log.record(&intent)?;
            log.intent = Some(intent);
            Ok(())
        };
        issue().map_err(|_| Denial::InvalidCapability)
    }
}
impl IssuanceAudit {
    fn complete(&self) -> Outcome<()> {
        let mut log = self.log.lock().map_err(|_| Error::InternalError)?;
        let intent = log.intent.as_ref().ok_or(Error::InternalError)?.clone();
        log.record(&json!({"schema":2,"seq":1,"prev":sha(&json::canonical(&intent)),"channel":self.channel,"event":"identity_recorded","request_id":"","timestamp":self.now,"code":"","digest":intent["digest"]}))
    }
}
impl IdentityAuthority {
    /// The inner capability is trusted host input. No plaintext accessor or
    /// surrogate string is returned through the administrative reply interface.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_to_file(
        &self,
        subject: &str,
        inner: &[u8],
        output: &Path,
        lifetime: i64,
        require_tpm: bool,
        now: i64,
    ) -> Outcome<Value> {
        let output_text = output.to_str().ok_or(Error::UnsafeFile)?;
        let _lease = self.root.lock(false)?;
        let selected = self.current()?;
        let state = read_registry(&self.root, &selected)?;
        let registry = Registry::parse(
            &state,
            text(&selected, "issuer")?,
            text(&selected, "audience")?,
        )?;
        let row = state["subjects"]
            .get(subject)
            .ok_or(Error::InvalidCapability)?;
        let receipt = self.receipt(subject, row)?;
        let assurance = receipt
            .as_ref()
            .map(receipt_mode)
            .transpose()?
            .unwrap_or(core::Assurance::Unrecorded);
        if require_tpm {
            self.certificate(row, &ca_public(&self.root, &selected)?)?;
        }
        let certificate = text(row, "certificate_sha256")?.as_bytes().to_vec();
        core::require_peer(
            row["active"].as_bool().ok_or(Error::InvalidCapability)?,
            &certificate,
            &certificate,
            number(row, "not_after")?,
            now,
            &assurance,
            &if require_tpm {
                core::Requirement::AttestedTpm
            } else {
                core::Requirement::Enrolled
            },
        )
        .map_err(|_| Error::Denied)?;
        // Refuse invalid windows before creating an audit/output file. The
        // actual issuer repeats this check and selects its own random token ID.
        aivm_secrets_garrett_core::issue_window(
            row["active"].as_bool().ok_or(Error::InvalidCapability)?,
            number(row, "epoch")?,
            number(row, "not_after")?,
            now,
            lifetime,
        )
        .map_err(|_| Error::InvalidCapability)?;
        if inner.len() > crypto::MAX_INNER || !inner.starts_with(b"aivs1.") || !inner.is_ascii() {
            return Err(Error::InvalidCapability);
        }
        let parent = PrivateDirectory::open(output.parent().ok_or(Error::UnsafeFile)?)?;
        let name = output
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(Error::UnsafeFile)?;
        if parent.exists(name)? {
            return Err(Error::UnsafeFile);
        }
        let ring = keyring(&self.root)?;
        let kid = text(&ring, "active")?;
        let directory = self.root.child("issuer-keys")?;
        let key = Zeroizing::new(directory.read(&format!("{kid}.key"), 4096)?);
        let public = directory.read(&format!("{kid}.pub"), 4096)?;
        let aes = Zeroizing::new(directory.read(&format!("{kid}.aes256"), 32)?);
        let issuer = Issuer::from_pem(&key, &public, &aes, kid)?;
        let channel = files::random_id()?;
        let audit_directory = self.root.child("audit")?;
        let file = audit_directory.create_file(&format!("{channel}.jsonl"))?;
        audit_directory.sync()?;
        let audit = IssuanceAudit {
            log: Mutex::new(IssuanceLog {
                file,
                intent: None,
                failed: false,
            }),
            channel,
            output: output_text.to_owned(),
            now,
        };
        let issued = issuer
            .issue_observed(
                &audit,
                &registry,
                text(&selected, "issuer")?,
                text(&selected, "audience")?,
                subject,
                inner,
                now,
                lifetime,
            )
            .map_err(|error| {
                if audit.log.lock().map(|l| l.failed).unwrap_or(true) {
                    Error::InternalError
                } else {
                    error
                }
            })?;
        // The acknowledged source controller has returned. Atomic no-replace
        // publication never exposes a partial token or overwrites an old file.
        parent.publish_new(name, &issued.token)?;
        audit.complete().map_err(|_| Error::OutcomeUnknown)?;
        Ok(
            json!({"subject":subject,"expires_at":issued.claims.expires_at,"certificate_sha256":row["certificate_sha256"],"output":output_text}),
        )
    }
}
