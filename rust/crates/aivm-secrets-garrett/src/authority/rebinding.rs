//! Explicit host-only carry-forward after same-key certificate renewal.
//! No broker credential, inner capability or private key is returned to stdout.
use super::*;
use aivm_secrets_garrett_core::{rebinding as gate, EnvelopeVerifier, Expectation};

struct Reissue<'a> {
    authority: &'a IdentityAuthority,
    verifier: &'a Verifier,
    envelope: &'a aivm_secrets_garrett_core::AuthenticatedEnvelope,
    subject: &'a str,
    output: &'a Path,
    lifetime: i64,
    require_tpm: bool,
    now: i64,
}
impl gate::Rebinder for Reissue<'_> {
    type Secret = crypto::InnerCapability;
    type Output = Value;
    type Error = Error;
    fn rejected(&self) -> Error {
        Error::Revoked
    }
    fn open(&self) -> Outcome<Self::Secret> {
        self.verifier
            .unseal(self.envelope)
            .map_err(|_| Error::InvalidCapability)
    }
    fn issue(&self, secret: &Self::Secret) -> Outcome<Value> {
        self.authority.issue_to_file(
            self.subject,
            secret.bytes(),
            self.output,
            self.lifetime,
            self.require_tpm,
            self.now,
        )
    }
}

impl IdentityAuthority {
    #[allow(clippy::too_many_arguments)] // Explicit source, target CAS and publication policy.
    pub fn rebind_to_file(
        &self,
        subject: &str,
        source: &[u8],
        expected_epoch: i64,
        expected_thumbprint: &str,
        output: &Path,
        lifetime: i64,
        require_tpm: bool,
        clock: impl Fn() -> Outcome<i64>,
    ) -> Outcome<Value> {
        json::word(&json!(subject), 128)?;
        json::integer(&json!(expected_epoch), 0, i32::MAX as i64)?;
        json::thumbprint(&json!(expected_thumbprint))?;
        let token = std::str::from_utf8(source)
            .map_err(|_| Error::InvalidCapability)?
            .trim();
        // This lease spans verified source preparation, target comparison,
        // opening and no-replace output publication. Nested issuance also
        // takes a compatible shared lease; all enrollment writers take EX.
        let _lease = self.root.lock(false)?;
        let selected = self.current()?;
        let ring = keyring(&self.root)?;
        let kid = crypto::token_key_id(token)?;
        if !ring["enabled"]
            .as_array()
            .ok_or(Error::InvalidCapability)?
            .contains(&json!(kid))
        {
            return Err(Error::Revoked);
        }
        let (public, aes) = AuthorityView::keys(&self.root, &kid)?;
        let verifier = Verifier::new(&crypto::issuer_public(&public)?, &aes, &kid)?;
        let envelope = verifier
            .verify(&token.as_bytes().to_vec())
            .map_err(|_| Error::InvalidCapability)?;
        let state = read_registry(&self.root, &selected)?;
        Registry::parse(
            &state,
            text(&selected, "issuer")?,
            text(&selected, "audience")?,
        )?;
        let row = state["subjects"].get(subject).ok_or(Error::Revoked)?;
        let ca = ca_public(&self.root, &selected)?;
        let (_, current) = self.certificate(row, &ca)?;
        let old_thumb = std::str::from_utf8(&envelope.claims.certificate)
            .map_err(|_| Error::InvalidCapability)?;
        let old_digest = crypto::decode(old_thumb, 64)?;
        if old_digest.len() != 32 {
            return Err(Error::InvalidCapability);
        }
        let old_pem = self
            .root
            .child("clients")?
            .read(&format!("{}.pem", hex(&old_digest)), 65536)?;
        let prior = certificates::inspect_client(&old_pem, &ca)?;
        if crypto::certificate_thumbprint(&prior.der)? != old_thumb {
            return Err(Error::InvalidCapability);
        }
        let now = clock()?;
        let target = gate::Target {
            identity: Expectation {
                issuer: text(&selected, "issuer")?.as_bytes().to_vec(),
                audience: text(&selected, "audience")?.as_bytes().to_vec(),
                subject: subject.as_bytes().to_vec(),
                epoch: number(row, "epoch")?,
            },
            certificate: text(row, "certificate_sha256")?.as_bytes().to_vec(),
            key: current.fingerprint.as_bytes().to_vec(),
            active: row["active"].as_bool().ok_or(Error::InvalidCapability)?,
            not_after: number(row, "not_after")?,
        };
        let ops = Reissue {
            authority: self,
            verifier: &verifier,
            envelope: &envelope,
            subject,
            output,
            lifetime,
            require_tpm,
            now,
        };
        let mut result = gate::rebind(
            &ops,
            &envelope.claims,
            &prior.fingerprint.as_bytes().to_vec(),
            &target,
            expected_epoch,
            &expected_thumbprint.as_bytes().to_vec(),
            now,
        )?;
        result["source_epoch"] = json!(envelope.claims.epoch);
        result["epoch"] = json!(target.identity.epoch);
        Ok(result)
    }
}
