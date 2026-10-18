//! Host-only pending requests and approval slots. No provider credential or
//! capability enters this object; the guest reaches only `admit`/`remember`.
use super::*;
use aivm_secrets_garrett_core::approval::{self as core, Approval, Decision, Mode};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(super) struct Metadata {
    pub binding: Value,
    pub service: String,
    pub operations: Vec<String>,
    pub policy: String,
    pub expires_at: i64,
    pub audit_path: String,
}
struct State {
    pending: Vec<Value>,
    approvals: BTreeMap<String, Approval>,
}
pub(crate) struct Shared {
    metadata: Metadata,
    audit: Arc<Audit>,
    active: AtomicBool,
    used: AtomicU64,
    state: Mutex<State>,
}
impl Shared {
    pub(super) fn new(metadata: Metadata, audit: Arc<Audit>) -> Self {
        Self {
            metadata,
            audit,
            active: AtomicBool::new(true),
            used: AtomicU64::new(0),
            state: Mutex::new(State {
                pending: Vec::new(),
                approvals: BTreeMap::new(),
            }),
        }
    }
    pub(crate) fn revoke(&self) {
        self.active.store(false, Ordering::Release);
    }
    pub(crate) fn require_active(&self, now: i64) -> Outcome<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(Error::Revoked);
        }
        if now >= self.metadata.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub(super) fn admit(&self, wanted: &str, write: bool) -> Outcome<Decision> {
        let mut state = self.state.lock().map_err(|_| Error::InternalError)?;
        let now = host_time()?;
        self.require_active(now)?;
        let slot = state.approvals.remove(wanted);
        let (decision, remaining) =
            core::consume(Mode::Approve, write, &wanted.as_bytes().to_vec(), now, slot);
        if let Some(slot) = remaining {
            state.approvals.insert(wanted.into(), slot);
        }
        if matches!(decision, Decision::Allowed) {
            self.used.fetch_add(1, Ordering::Relaxed);
        }
        Ok(decision)
    }
    pub(super) fn remember(&self, wanted: &str, request: &Value) -> Outcome<()> {
        let mut state = self.state.lock().map_err(|_| Error::InternalError)?;
        let now = host_time()?;
        self.require_active(now)?;
        self.record(
            &json!({"schema":1,"event":"approval_requested","operation":request["operation"],
            "grant":self.audit.grant,"policy":self.audit.policy,"approval":{"digest":wanted}}),
        )?;
        state.pending.retain(|p| p["digest"] != wanted);
        if state.pending.len() >= 16 {
            state.pending.remove(0);
        }
        state
            .pending
            .push(json!({"digest":wanted,"grant":self.audit.grant,
            "operation":request["operation"],"arguments":request["arguments"],"requested_at":now}));
        Ok(())
    }
    fn record(&self, value: &Value) -> Outcome<()> {
        self.audit
            .write_record(value)
            .inspect_err(|_| self.revoke())
    }
    fn pending_digest(state: &State, value: &Value) -> Outcome<String> {
        let prefix = value.as_str().ok_or(Error::InvalidRequest)?;
        if !(8..=64).contains(&prefix.len()) {
            return Err(Error::InvalidRequest);
        }
        let matches: Vec<_> = state
            .pending
            .iter()
            .filter_map(|p| p["digest"].as_str())
            .filter(|digest| digest.starts_with(prefix))
            .collect();
        if matches.len() != 1 {
            return Err(Error::InvalidRequest);
        }
        Ok(matches[0].to_owned())
    }
    pub(crate) fn execute(&self, command: &Value) -> Outcome<Value> {
        match command.get("command").and_then(Value::as_str) {
            Some("status") => {
                json::keys(command, &["command"], &[]).map_err(|_| Error::InvalidRequest)?;
                let state = self.state.lock().map_err(|_| Error::InternalError)?;
                let now = host_time()?;
                let m = &self.metadata;
                Ok(json!({"version":1,"ok":true,"session":{
                    "implementation":"rust","channel":m.binding["channel"],
                    "access_identity":m.binding["access_identity"],"vm":m.binding["vm"],
                    "owner_uid":m.binding["owner_uid"],"service":m.service,"policy_digest":m.policy,
                    "operations":m.operations,"writes":"approve","active":self.require_active(now).is_ok(),
                    "expires_at":m.expires_at,"used":self.used.load(Ordering::Relaxed),
                    "max_requests":"unbounded","grants":1,"pending":state.pending.len(),"audit":m.audit_path}}))
            }
            Some("pending") => {
                json::keys(command, &["command"], &[]).map_err(|_| Error::InvalidRequest)?;
                let state = self.state.lock().map_err(|_| Error::InternalError)?;
                Ok(json!({"version":1,"ok":true,"pending":state.pending}))
            }
            Some("approve" | "deny") => {
                let m = json::keys(command, &["command", "digest"], &["ttl"])
                    .map_err(|_| Error::InvalidRequest)?;
                let mut state = self.state.lock().map_err(|_| Error::InternalError)?;
                let now = host_time()?;
                let digest = Self::pending_digest(&state, &m["digest"])?;
                if m["command"] == "approve" {
                    let ttl = json::integer(m.get("ttl").unwrap_or(&json!(300)), 1, 900)
                        .map_err(|_| Error::InvalidRequest)?;
                    let slot = core::issue(digest.as_bytes().to_vec(), now, ttl)
                        .ok_or(Error::InvalidRequest)?;
                    state
                        .approvals
                        .retain(|key, p| key != &digest && now < p.expires_at);
                    if state.approvals.len() >= 16 {
                        return Err(Error::Exhausted);
                    }
                    self.record(&json!({"schema":1,"event":"approved","digest":digest,
                        "grant":self.audit.grant,"policy":self.audit.policy}))?;
                    state.approvals.insert(digest.clone(), slot);
                }
                state.pending.retain(|p| p["digest"] != digest);
                Ok(json!({"version":1,"ok":true,"digest":digest}))
            }
            Some("revoke") => {
                let m = json::keys(command, &["command"], &["grant"])
                    .map_err(|_| Error::InvalidRequest)?;
                if let Some(value) = m.get("grant") {
                    let grant = value.as_str().ok_or(Error::InvalidRequest)?;
                    if !grant.is_empty() && grant != self.audit.grant {
                        return Err(Error::InvalidRequest);
                    }
                }
                // Authority changes before any audit wait and independently
                // of the provider mutex. Late dispatch/release reads this flag.
                self.revoke();
                self.record(&json!({"schema":1,"event":"revoked","grant":self.audit.grant,"policy":self.audit.policy}))?;
                Ok(json!({"version":1,"ok":true}))
            }
            _ => Err(Error::InvalidRequest),
        }
    }
}
