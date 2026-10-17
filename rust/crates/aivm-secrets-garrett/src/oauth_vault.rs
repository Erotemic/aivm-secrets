//! Principal-owned encrypted OAuth custody. Raw tokens have no public reply,
//! formatting or serialization interface; only private storage/network adapters
//! may borrow them. The reference schema-2 ciphertext format is preserved.
use crate::{
    files::{self, PrivateDirectory},
    json, oauth, Error, Outcome,
};
use aivm_secrets_garrett_core::oauth_state as core;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{
    aead, digest, hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::{json, Value};
use std::{fs::File, io::Write, path::Path, sync::Mutex};
use zeroize::Zeroizing;
pub mod provider;
pub mod transport;
use provider::Provider;
use transport::TokenEndpoint;

const MAX_RECORD: usize = 32768;
const AAD: &[u8] = b"aivm-secrets/oauth-vault/v1\0";
fn text<'a>(v: &'a Value, key: &str) -> Outcome<&'a str> {
    v[key].as_str().ok_or(Error::CredentialSource)
}
fn integer(v: &Value, key: &str) -> Outcome<i64> {
    v[key].as_i64().ok_or(Error::CredentialSource)
}
fn sha(data: &[u8]) -> String {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn random<const N: usize>() -> Outcome<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::InternalError)?;
    Ok(bytes)
}
fn scope_list(value: &Value) -> Outcome<Vec<String>> {
    oauth::scopes(value)
}
fn account(provider: &Provider, subject: &str) -> Outcome<String> {
    json::word(&json!(subject), 128)?;
    Ok(sha(format!("{}\0{subject}", provider.name).as_bytes()))
}
fn state_name(state: &core::RefreshState) -> &'static str {
    match state {
        core::RefreshState::Ready => "none",
        core::RefreshState::InDoubt => "in_doubt",
        core::RefreshState::Reauthorize => "reauth_required",
    }
}
fn state(value: &Value) -> Outcome<core::RefreshState> {
    match value.as_str() {
        Some("none") => Ok(core::RefreshState::Ready),
        Some("in_doubt") => Ok(core::RefreshState::InDoubt),
        Some("reauth_required") => Ok(core::RefreshState::Reauthorize),
        _ => Err(Error::CredentialSource),
    }
}

pub struct OAuthError {
    code: Error,
    reason: &'static str,
}
impl OAuthError {
    pub fn public_error(&self) -> Value {
        json!({"code":self.code.code(),"reason":self.reason})
    }
    fn refresh(error: core::RefreshDenial, prior: &core::RefreshState) -> Self {
        let (code, reason) = match error {
            core::RefreshDenial::Revoked => (Error::Revoked, ""),
            core::RefreshDenial::Unsettled => (
                Error::CredentialSource,
                if matches!(prior, core::RefreshState::Reauthorize) {
                    "reauth_required"
                } else {
                    "refresh_in_doubt"
                },
            ),
            core::RefreshDenial::Expired => (Error::Expired, ""),
            core::RefreshDenial::Exhausted => (Error::Exhausted, "refresh_exhausted"),
            core::RefreshDenial::Invalid => (Error::CredentialSource, ""),
            core::RefreshDenial::Storage => (Error::InternalError, ""),
            core::RefreshDenial::Uncertain => (Error::CredentialSource, "refresh_in_doubt"),
            core::RefreshDenial::NotSent => (Error::CredentialSource, "refresh_not_sent"),
            core::RefreshDenial::Rejected => (Error::CredentialSource, "refresh_rejected"),
        };
        Self { code, reason }
    }
}
impl From<Error> for OAuthError {
    fn from(code: Error) -> Self {
        Self { code, reason: "" }
    }
}
pub type OAuthOutcome<T> = Result<T, OAuthError>;

struct Grant {
    access: Zeroizing<String>,
    refresh: Option<Zeroizing<String>>,
    expires: i64,
    scopes: Vec<String>,
    generation: i64,
}
impl Grant {
    fn from_value(value: &Value) -> Outcome<Self> {
        oauth::evaluate(&json!({"version":1,"action":"active","grant":value,"now":0,"leeway":0}))?;
        Ok(Self {
            access: Zeroizing::new(text(value, "access_token")?.into()),
            refresh: value["refresh_token"]
                .as_str()
                .map(|s| Zeroizing::new(s.into())),
            expires: integer(value, "expires_at")?,
            scopes: scope_list(&value["scopes"])?,
            generation: integer(value, "generation")?,
        })
    }
    fn secret_value(&self) -> Value {
        json!({"access_token":&*self.access,"refresh_token":self.refresh.as_deref(),"expires_at":self.expires,"scopes":self.scopes,"generation":self.generation})
    }
    fn from_response(
        provider: &Provider,
        previous: &Grant,
        response: &Value,
        now: i64,
    ) -> Outcome<Self> {
        let meta = oauth::evaluate(
            &json!({"version":1,"action":"token","response":response,"allowed_scopes":provider.scopes,"now":now,"previous":previous.secret_value(),"fallback_ttl":provider.fallback_ttl,"require_rotation":provider.rotation}),
        )?;
        let refresh = response
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.into()))
            .or_else(|| {
                previous
                    .refresh
                    .as_ref()
                    .map(|s| Zeroizing::new((**s).to_owned()))
            });
        Ok(Self {
            access: Zeroizing::new(text(response, "access_token")?.into()),
            refresh,
            expires: integer(&meta, "expires_at")?,
            scopes: scope_list(&meta["scopes"])?,
            generation: integer(&meta, "generation")?,
        })
    }
}
struct Row {
    profile: String,
    active: bool,
    epoch: i64,
    grant: Option<Grant>,
    state: core::RefreshState,
    previous: String,
}
impl Row {
    fn from_value(value: &Value, subject: &str) -> Outcome<Self> {
        json::keys(
            value,
            &[
                "schema",
                "provider_digest",
                "subject",
                "active",
                "epoch",
                "grant",
                "refresh_state",
                "previous_digest",
            ],
            &[],
        )?;
        json::integer(&value["schema"], 2, 2)?;
        if value["subject"] != subject {
            return Err(Error::CredentialSource);
        }
        let profile = json::hex(&value["provider_digest"], 64)?;
        let previous = text(value, "previous_digest")?;
        if !previous.is_empty() {
            json::hex(&value["previous_digest"], 16)?;
        }
        Ok(Self {
            profile,
            active: value["active"].as_bool().ok_or(Error::CredentialSource)?,
            epoch: json::integer(&value["epoch"], 0, i32::MAX as i64)?,
            grant: if value["grant"].is_null() {
                None
            } else {
                Some(Grant::from_value(&value["grant"])?)
            },
            state: state(&value["refresh_state"])?,
            previous: previous.into(),
        })
    }
    fn public_status(
        &self,
        provider: &Provider,
        subject: &str,
        grant: Option<&Grant>,
        state: &core::RefreshState,
    ) -> Value {
        json!({"provider":provider.name,"subject":subject,"active":self.active,"epoch":self.epoch,"refresh_state":state_name(state),"expires_at":grant.map(|g|g.expires),"scopes":grant.map(|g|g.scopes.clone()).unwrap_or_default(),"generation":grant.map(|g|g.generation),"has_refresh":grant.is_some_and(|g|g.refresh.is_some()),"profile_current":self.profile==provider.digest,"previous_digest":self.previous})
    }
}
struct Audit {
    state: Mutex<AuditState>,
    channel: String,
    subject: String,
    digest: String,
}
struct AuditState {
    file: File,
    seq: u64,
    head: String,
    failed: bool,
}
impl Audit {
    fn new(root: &PrivateDirectory, provider: &Provider, subject: &str) -> Outcome<Self> {
        let directory = root.child("audit")?;
        let channel = files::random_id()?;
        let file = directory.create_file(&format!("{channel}.jsonl"))?;
        directory.sync()?;
        Ok(Self {
            state: Mutex::new(AuditState {
                file,
                seq: 0,
                head: "0".repeat(64),
                failed: false,
            }),
            channel,
            subject: subject.into(),
            digest: sha(format!("{}{subject}", provider.digest).as_bytes()),
        })
    }
    fn record(&self, event: &str, now: i64, code: &str) -> Outcome<()> {
        let mut state = self.state.lock().map_err(|_| Error::InternalError)?;
        if state.failed {
            return Err(Error::InternalError);
        }
        let value = json!({"schema":2,"seq":state.seq,"prev":state.head,"channel":self.channel,"event":event,"request_id":"","timestamp":now,"code":code,"resource":{"subject":self.subject},"digest":self.digest});
        let bytes = json::canonical(&value);
        let result = state
            .file
            .write_all(&bytes)
            .and_then(|_| state.file.write_all(b"\n"))
            .and_then(|_| state.file.sync_all());
        if result.is_err() {
            state.failed = true;
            return Err(Error::InternalError);
        }
        state.seq += 1;
        state.head = sha(&bytes);
        Ok(())
    }
}

pub struct OAuthVault {
    root: PrivateDirectory,
    cipher: aead::LessSafeKey,
    lease_key: hmac::Key,
}
pub(crate) struct Lease {
    credential: Zeroizing<String>,
    meta: core::LeaseMeta,
    tag: Vec<u8>,
}
impl Lease {
    pub(crate) fn credential(&self) -> &[u8] {
        self.credential.as_bytes()
    }
    pub(crate) fn expires_at(&self) -> i64 {
        self.meta.expires_at
    }
    fn public_metadata(&self) -> Value {
        json!({"epoch":self.meta.epoch,"generation":self.meta.generation,"expires_at":self.meta.expires_at})
    }
}
impl OAuthVault {
    pub fn open(path: &Path) -> Outcome<Self> {
        let root = PrivateDirectory::open(path)?;
        Self::from_directory(root)
    }
    fn from_directory(root: PrivateDirectory) -> Outcome<Self> {
        let _lease = root.lock_named(".vault.lock", false)?;
        let key = Zeroizing::new(root.read("vault.aes256", 32)?);
        let cipher = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| Error::UnsafeFile)?,
        );
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"aivm-secrets/oauth-lease/v1").extract(&key);
        let lease_key = hmac::Key::from(
            prk.expand(&[b"credential-equality"], hmac::HMAC_SHA256)
                .map_err(|_| Error::InternalError)?,
        );
        Ok(Self {
            root,
            cipher,
            lease_key,
        })
    }
    pub fn initialize(path: &Path) -> Outcome<Self> {
        path.to_str().ok_or(Error::UnsafeFile)?;
        let parent = PrivateDirectory::open(path.parent().ok_or(Error::UnsafeFile)?)?;
        let target = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::UnsafeFile)?;
        if parent.exists(target)? {
            return Err(Error::UnsafeFile);
        }
        let staged = format!(".oauth-init-{}", files::random_id()?);
        let root = parent.create_directory(&staged)?;
        root.write_new("vault.aes256", &Zeroizing::new(random::<32>()?)[..])?;
        root.write_new(".vault.lock", b"")?;
        root.create_directory("audit")?;
        root.sync()?;
        parent.publish_directory(&staged, target)?;
        Self::from_directory(root).map_err(|_| Error::OutcomeUnknown)
    }
    fn read(&self, provider: &Provider, subject: &str, any_profile: bool) -> Outcome<Row> {
        let account = account(provider, subject)?;
        let raw = self.root.read(&format!("{account}.json"), MAX_RECORD)?;
        let decode = || -> Outcome<Row> {
            let wrapper = json::parse(&raw, MAX_RECORD)?;
            json::keys(&wrapper, &["schema", "nonce", "ciphertext"], &[])?;
            json::integer(&wrapper["schema"], 2, 2)?;
            let nonce = STANDARD
                .decode(text(&wrapper, "nonce")?)
                .map_err(|_| Error::CredentialSource)?;
            let mut encrypted = Zeroizing::new(
                STANDARD
                    .decode(text(&wrapper, "ciphertext")?)
                    .map_err(|_| Error::CredentialSource)?,
            );
            let nonce: [u8; 12] = nonce.try_into().map_err(|_| Error::CredentialSource)?;
            let mut aad = AAD.to_vec();
            aad.extend_from_slice(account.as_bytes());
            let plain = self
                .cipher
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(&aad),
                    &mut encrypted,
                )
                .map_err(|_| Error::CredentialSource)?;
            let row = Row::from_value(&json::parse(plain, MAX_RECORD)?, subject)
                .map_err(|_| Error::CredentialSource)?;
            if !any_profile && row.profile != provider.digest {
                return Err(Error::CredentialSource);
            }
            Ok(row)
        };
        decode().map_err(|_| Error::CredentialSource)
    }
    fn write(
        &self,
        provider: &Provider,
        subject: &str,
        row: &Row,
        grant: Option<&Grant>,
        state: &core::RefreshState,
    ) -> Outcome<()> {
        let account = account(provider, subject)?;
        let nonce = random::<12>()?;
        let mut data = Zeroizing::new(json::canonical(
            &json!({"schema":2,"provider_digest":provider.digest,"subject":subject,"active":row.active,"epoch":row.epoch,"grant":grant.map(Grant::secret_value),"refresh_state":state_name(state),"previous_digest":row.previous}),
        ));
        let mut aad = AAD.to_vec();
        aad.extend_from_slice(account.as_bytes());
        self.cipher
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&aad),
                &mut *data,
            )
            .map_err(|_| Error::CredentialSource)?;
        let wrapper = json::canonical(
            &json!({"schema":2,"nonce":STANDARD.encode(nonce),"ciphertext":STANDARD.encode(&data)}),
        );
        if wrapper.len() > MAX_RECORD {
            return Err(Error::CredentialSource);
        }
        let name = format!("{account}.json");
        if self.root.exists(&name)? {
            self.root.replace(&name, &wrapper)
        } else {
            self.root.publish_new(&name, &wrapper)
        }
    }
    pub fn status(&self, provider: &Provider, subject: &str) -> Outcome<Value> {
        let _lease = self.root.lock_named(".vault.lock", false)?;
        let row = self.read(provider, subject, true)?;
        Ok(row.public_status(provider, subject, row.grant.as_ref(), &row.state))
    }
    pub fn enroll_file(
        &self,
        provider: &Provider,
        subject: &str,
        path: &Path,
        replace: bool,
        now: i64,
    ) -> Outcome<Value> {
        let raw = Zeroizing::new(files::read_private(path, 16384)?);
        let grant = Grant::from_value(&json::parse(&raw, 16384)?)?;
        if grant.scopes.iter().any(|s| !provider.scopes.contains(s)) {
            return Err(Error::CredentialSource);
        }
        let _lease = self.root.lock_named(".vault.lock", true)?;
        let (epoch, previous) = if self
            .root
            .exists(&format!("{}.json", account(provider, subject)?))?
        {
            let old = self.read(provider, subject, true)?;
            if old.active && !replace {
                return Err(Error::Denied);
            }
            if old.epoch >= i32::MAX as i64 {
                return Err(Error::Exhausted);
            }
            (
                old.epoch + 1,
                if old.profile != provider.digest {
                    old.profile[..16].to_owned()
                } else {
                    old.previous
                },
            )
        } else {
            (0, String::new())
        };
        let row = Row {
            profile: provider.digest.clone(),
            active: true,
            epoch,
            grant: None,
            state: core::RefreshState::Ready,
            previous,
        };
        let audit = Audit::new(&self.root, provider, subject)?;
        audit.record("oauth_enroll_intent", now, "")?;
        self.write(provider, subject, &row, Some(&grant), &row.state)?;
        audit
            .record("oauth_recorded", now, "")
            .map_err(|_| Error::OutcomeUnknown)?;
        Ok(
            json!({"provider":provider.name,"subject":subject,"expires_at":grant.expires,"epoch":epoch,"scopes":grant.scopes,"previous_digest":row.previous}),
        )
    }
    pub fn revoke(&self, provider: &Provider, subject: &str, now: i64) -> Outcome<Value> {
        let _lease = self.root.lock_named(".vault.lock", true)?;
        let mut row = self.read(provider, subject, true)?;
        if row.active || row.profile != provider.digest {
            row.epoch = (row.epoch + 1).min(i32::MAX as i64);
            if row.profile != provider.digest {
                row.previous = row.profile[..16].into();
            }
            row.active = false;
            let audit = Audit::new(&self.root, provider, subject)?;
            audit.record("oauth_revoke_intent", now, "")?;
            self.write(provider, subject, &row, None, &core::RefreshState::Ready)?;
            audit
                .record("oauth_recorded", now, "")
                .map_err(|_| Error::OutcomeUnknown)?;
        }
        Ok(
            json!({"provider":provider.name,"subject":subject,"active":false,"epoch":row.epoch,"previous_digest":row.previous}),
        )
    }
    fn refresh_locked(
        &self,
        provider: &Provider,
        subject: &str,
        row: &Row,
        now: i64,
        retry: bool,
        transport: &Value,
    ) -> OAuthOutcome<Grant> {
        let grant = row.grant.as_ref().ok_or(Error::Revoked)?;
        core::permit_refresh(
            row.active,
            &row.state,
            grant.refresh.is_some(),
            grant.generation,
            retry,
        )
        .map_err(|e| OAuthError::refresh(e, &row.state))?;
        let mut fields = vec![
            ("grant_type", "refresh_token"),
            (
                "refresh_token",
                &**grant.refresh.as_ref().ok_or(Error::Expired)?,
            ),
            ("client_id", provider.client_id.as_str()),
        ];
        let client_secret = provider.client_secret()?;
        if let Some(secret) = &client_secret {
            fields.push(("client_secret", secret));
        }
        let form = transport::form(&fields)?;
        let endpoint = TokenEndpoint::new(provider, transport)?;
        let work = RefreshWork {
            vault: self,
            provider,
            subject,
            row,
            grant,
            form,
            endpoint,
            audit: Audit::new(&self.root, provider, subject)?,
            now,
        };
        core::refresh_once(
            &work,
            row.active,
            &row.state,
            grant.refresh.is_some(),
            grant.generation,
            retry,
        )
        .map_err(|e| OAuthError::refresh(e, &row.state))
    }
    pub fn refresh(
        &self,
        provider: &Provider,
        subject: &str,
        now: i64,
        retry: bool,
        transport: &Value,
    ) -> OAuthOutcome<Value> {
        let _lease = self.root.lock_named(".vault.lock", true)?;
        let row = self.read(provider, subject, false)?;
        let successor = self.refresh_locked(provider, subject, &row, now, retry, transport)?;
        Ok(row.public_status(
            provider,
            subject,
            Some(&successor),
            &core::RefreshState::Ready,
        ))
    }
    fn lease_message(
        &self,
        provider: &Provider,
        subject: &str,
        row: &Row,
        grant: &Grant,
    ) -> Outcome<Zeroizing<Vec<u8>>> {
        let mut message = Zeroizing::new(account(provider, subject)?.into_bytes());
        message.extend_from_slice(provider.digest.as_bytes());
        message.extend_from_slice(&row.epoch.to_be_bytes());
        message.extend_from_slice(&grant.generation.to_be_bytes());
        message.extend_from_slice(&grant.expires.to_be_bytes());
        message.extend_from_slice(grant.access.as_bytes());
        Ok(message)
    }
    pub(crate) fn session_snapshot(
        &self,
        provider: &Provider,
        subject: &str,
        resource_host: &str,
        now: i64,
        force: bool,
        transport: &Value,
    ) -> OAuthOutcome<Lease> {
        if resource_host != provider.resource_host {
            return Err(Error::CredentialSource.into());
        }
        let _lease = self.root.lock_named(".vault.lock", true)?;
        let row = self.read(provider, subject, false)?;
        let grant = row.grant.as_ref().ok_or(Error::Revoked)?;
        core::require_lease(
            row.active,
            &row.state,
            &core::LeaseMeta {
                epoch: row.epoch,
                generation: grant.generation,
                expires_at: grant.expires,
            },
            &core::LeaseMeta {
                epoch: row.epoch,
                generation: grant.generation,
                expires_at: grant.expires,
            },
            0,
        )
        .map_err(|e| OAuthError::refresh(e, &row.state))?;
        let successor;
        let grant = if force || now.checked_add(60).is_none_or(|n| n >= grant.expires) {
            successor = self.refresh_locked(provider, subject, &row, now, false, transport)?;
            &successor
        } else {
            grant
        };
        if now < 0 || now >= grant.expires {
            return Err(Error::Expired.into());
        }
        let tag = hmac::sign(
            &self.lease_key,
            &self.lease_message(provider, subject, &row, grant)?,
        );
        Ok(Lease {
            credential: Zeroizing::new((*grant.access).to_owned()),
            meta: core::LeaseMeta {
                epoch: row.epoch,
                generation: grant.generation,
                expires_at: grant.expires,
            },
            tag: tag.as_ref().to_vec(),
        })
    }
    pub fn session_check(
        &self,
        provider: &Provider,
        subject: &str,
        resource_host: &str,
        now: i64,
        force: bool,
        transport: &Value,
    ) -> OAuthOutcome<Value> {
        Ok(self
            .session_snapshot(provider, subject, resource_host, now, force, transport)?
            .public_metadata())
    }
    pub(crate) fn active_lease(
        &self,
        provider: &Provider,
        subject: &str,
        lease: &Lease,
        clock: impl Fn() -> i64,
    ) -> OAuthOutcome<File> {
        let lock = self.root.lock_named(".vault.lock", true)?;
        let row = self.read(provider, subject, false)?;
        let grant = row.grant.as_ref().ok_or(Error::Revoked)?;
        core::require_lease(
            row.active,
            &row.state,
            &core::LeaseMeta {
                epoch: row.epoch,
                generation: grant.generation,
                expires_at: grant.expires,
            },
            &lease.meta,
            clock(),
        )
        .map_err(|e| OAuthError::refresh(e, &row.state))?;
        hmac::verify(
            &self.lease_key,
            &self.lease_message(provider, subject, &row, grant)?,
            &lease.tag,
        )
        .map_err(|_| Error::Revoked)?;
        Ok(lock)
    }
}
struct RefreshWork<'a> {
    vault: &'a OAuthVault,
    provider: &'a Provider,
    subject: &'a str,
    row: &'a Row,
    grant: &'a Grant,
    form: Zeroizing<Vec<u8>>,
    endpoint: TokenEndpoint,
    audit: Audit,
    now: i64,
}
impl core::RefreshOps for RefreshWork<'_> {
    type Successor = Grant;
    fn intent(&self) -> Result<(), core::StoreFailure> {
        self.audit
            .record("oauth_refresh_intent", self.now, "")
            .map_err(|_| core::StoreFailure::Failed)
    }
    fn quarantine(&self) -> Result<(), core::StoreFailure> {
        self.vault
            .write(
                self.provider,
                self.subject,
                self.row,
                Some(self.grant),
                &core::RefreshState::InDoubt,
            )
            .map_err(|_| core::StoreFailure::Failed)
    }
    fn exchange(&self) -> Result<Grant, core::ExchangeFailure> {
        let response = self.endpoint.post(&self.form)?;
        Grant::from_response(self.provider, self.grant, &response, self.now)
            .map_err(|_| core::ExchangeFailure::Uncertain)
    }
    fn commit(&self, successor: &Grant) -> Result<(), core::StoreFailure> {
        self.vault
            .write(
                self.provider,
                self.subject,
                self.row,
                Some(successor),
                &core::RefreshState::Ready,
            )
            .map_err(|_| core::StoreFailure::Failed)
    }
    fn settle(&self, state: &core::RefreshState) -> Result<(), core::StoreFailure> {
        self.vault
            .write(
                self.provider,
                self.subject,
                self.row,
                Some(self.grant),
                state,
            )
            .map_err(|_| core::StoreFailure::Failed)
    }
    fn observe(&self, event: core::RefreshEvent) -> Result<(), core::StoreFailure> {
        let (name, code) = match event {
            core::RefreshEvent::Recorded => ("oauth_recorded", ""),
            core::RefreshEvent::InDoubt => ("oauth_refresh_in_doubt", "credential_source"),
            core::RefreshEvent::NotSent => ("oauth_refresh_not_sent", "credential_source"),
            core::RefreshEvent::Rejected => ("oauth_refresh_rejected", "credential_source"),
        };
        self.audit
            .record(name, self.now, code)
            .map_err(|_| core::StoreFailure::Failed)
    }
}
