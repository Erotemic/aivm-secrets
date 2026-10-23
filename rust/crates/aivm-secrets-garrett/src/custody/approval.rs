//! Host-only pending requests and approval slots. No provider credential or
//! capability enters this object; the guest reaches only `admit`/`remember`.
use super::*;
use aivm_secrets_garrett_core::approval::{self as core, Approval, Decision, Mode};
use aivm_secrets_garrett_core::session_audit as core_audit;
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
    approvals: Vec<Approval>,
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
                approvals: Vec::new(),
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
        // The extracted store chooses the slot for exactly this digest and
        // returns it only if it was not spent.
        let admitted = core::admit(
            &state.approvals,
            Mode::Approve,
            write,
            &wanted.as_bytes().to_vec(),
            now,
        );
        state.approvals = admitted.store;
        let decision = admitted.decision;
        if matches!(decision, Decision::Allowed) {
            self.used.fetch_add(1, Ordering::Relaxed);
        }
        Ok(decision)
    }
    pub(super) fn remember(&self, wanted: &str, request: &Value) -> Outcome<()> {
        let mut state = self.state.lock().map_err(|_| Error::InternalError)?;
        let now = host_time()?;
        self.require_active(now)?;
        self.record(&core_audit::approval_requested_record(
            wire_text(wanted),
            wire_text(&self.audit.grant),
            crate::json::capture(&request["operation"]).into_wire(),
            wire_text(&self.audit.policy),
        ))?;
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
    /// Append an extracted record; a failed append revokes (fail closed).
    fn record(&self, value: &aivm_secrets_garrett_core::json_wire::Value) -> Outcome<()> {
        self.audit
            .append_value(value)
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
                    // Replaces any slot for this digest and drops expired
                    // ones; a full store or failed audit leaves it unchanged.
                    let store =
                        core::install(&state.approvals, slot, now).ok_or(Error::Exhausted)?;
                    self.record(&core_audit::approved_record(
                        wire_text(&digest),
                        wire_text(&self.audit.grant),
                        wire_text(&self.audit.policy),
                    ))?;
                    state.approvals = store;
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
                self.record(&core_audit::event_record(
                    wire_text("revoked"),
                    wire_text(&self.audit.grant),
                    wire_text(&self.audit.policy),
                    None,
                    None,
                ))?;
                Ok(json!({"version":1,"ok":true}))
            }
            _ => Err(Error::InvalidRequest),
        }
    }
}

#[cfg(test)]
mod store_oracle {
    //! Oracle: the extracted approval store against the `BTreeMap` slots it
    //! replaced, over pseudo-random admit/approve sequences. The one intended
    //! difference: a full store used to be pruned before refusing; now a
    //! refusal leaves the store unchanged, so the oracle resynchronizes there.
    use super::core::{self, Approval, Decision, Mode};
    use std::collections::BTreeMap;

    fn old_admit(
        map: &mut BTreeMap<String, Approval>,
        wanted: &str,
        write: bool,
        now: i64,
    ) -> Decision {
        let slot = map.remove(wanted);
        let (decision, remaining) =
            core::consume(Mode::Approve, write, &wanted.as_bytes().to_vec(), now, slot);
        if let Some(slot) = remaining {
            map.insert(wanted.into(), slot);
        }
        decision
    }

    fn old_install(map: &mut BTreeMap<String, Approval>, digest: &str, now: i64, ttl: i64) -> bool {
        let slot = core::issue(digest.as_bytes().to_vec(), now, ttl).unwrap();
        map.retain(|key, p| key != digest && now < p.expires_at);
        if map.len() >= 16 {
            return false;
        }
        map.insert(digest.into(), slot);
        true
    }

    fn view(store: &[Approval]) -> BTreeMap<String, i64> {
        let out: BTreeMap<_, _> = store
            .iter()
            .map(|s| (String::from_utf8(s.digest.clone()).unwrap(), s.expires_at))
            .collect();
        assert_eq!(out.len(), store.len(), "one slot per digest");
        out
    }

    fn old_view(map: &BTreeMap<String, Approval>) -> BTreeMap<String, i64> {
        map.iter().map(|(k, s)| (k.clone(), s.expires_at)).collect()
    }

    #[test]
    fn extracted_approval_records_match_the_serde_records() {
        use super::super::wire_text;
        use aivm_secrets_garrett_core::session_audit as audit;
        use serde_json::json;
        let bytes = |value: &aivm_secrets_garrett_core::json_wire::Value| {
            aivm_secrets_garrett_core::json_wire::encode(value)
                .ok()
                .expect("encodable record")
        };
        for text in ["g", "", "quote\"\\", "é😀"] {
            for operation in [json!("pull.comment"), json!(null), json!({"x":[1,"y"]})] {
                assert_eq!(
                    bytes(&audit::approval_requested_record(
                        wire_text(text),
                        wire_text("g1"),
                        crate::json::capture(&operation).into_wire(),
                        wire_text(text)
                    )),
                    crate::json::canonical(
                        &json!({"schema":1,"event":"approval_requested","operation":operation,
                        "grant":"g1","policy":text,"approval":{"digest":text}})
                    )
                );
            }
            assert_eq!(
                bytes(&audit::approved_record(
                    wire_text(text),
                    wire_text("g1"),
                    wire_text(text)
                )),
                crate::json::canonical(
                    &json!({"schema":1,"event":"approved","digest":text,"grant":"g1","policy":text})
                )
            );
            assert_eq!(
                bytes(&audit::event_record(
                    wire_text("revoked"),
                    wire_text(text),
                    wire_text("p"),
                    None,
                    None
                )),
                crate::json::canonical(
                    &json!({"schema":1,"event":"revoked","grant":text,"policy":"p"})
                )
            );
        }
    }

    #[test]
    fn extracted_store_matches_the_btreemap_slots() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        let mut exhausted = 0;
        for _run in 0..200 {
            let mut old = BTreeMap::new();
            let mut new: Vec<Approval> = Vec::new();
            let mut now = 1_000;
            for _step in 0..120 {
                now += next(6) as i64;
                let digest = format!("{:064x}", next(40));
                if next(2) == 0 {
                    let ttl = 1 + next(900) as i64;
                    let slot = core::issue(digest.as_bytes().to_vec(), now, ttl).unwrap();
                    match core::install(&new, slot, now) {
                        Some(store) => {
                            assert!(old_install(&mut old, &digest, now, ttl));
                            new = store;
                        }
                        None => {
                            assert!(!old_install(&mut old, &digest, now, ttl));
                            exhausted += 1;
                            old = new
                                .iter()
                                .map(|s| {
                                    (
                                        String::from_utf8(s.digest.clone()).unwrap(),
                                        Approval {
                                            digest: s.digest.clone(),
                                            expires_at: s.expires_at,
                                        },
                                    )
                                })
                                .collect();
                        }
                    }
                } else {
                    let write = next(4) != 0;
                    let admitted =
                        core::admit(&new, Mode::Approve, write, &digest.as_bytes().to_vec(), now);
                    let expected = old_admit(&mut old, &digest, write, now);
                    assert_eq!(admitted.decision as u8, expected as u8);
                    new = admitted.store;
                }
                assert_eq!(view(&new), old_view(&old));
            }
        }
        assert!(exhausted > 0, "the full-store refusal was exercised");
    }
}
