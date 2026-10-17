//! Typed adapters preserve the Python reference's exact grammar and errors.
use crate::{json, Error, Outcome};
use aivm_secrets_garrett_core::{self as core, Claims, Expectation};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ISSUED: i64 = i64::MAX - 3600;
fn bytes(s: String) -> Vec<u8> {
    s.into_bytes()
}
pub fn claims(value: &Value) -> Outcome<Claims> {
    let m = json::keys(
        value,
        &["iss", "aud", "sub", "jti", "iat", "exp", "epoch", "cnf"],
        &[],
    )?;
    let cnf = json::keys(&m["cnf"], &["x5t#S256"], &[])?;
    let issued_at = json::integer(&m["iat"], 0, MAX_ISSUED)?;
    Ok(Claims {
        issuer: bytes(json::word(&m["iss"], 128)?),
        audience: bytes(json::word(&m["aud"], 128)?),
        subject: bytes(json::word(&m["sub"], 128)?),
        token_id: bytes(json::hex(&m["jti"], 32)?),
        issued_at,
        expires_at: json::integer(&m["exp"], issued_at + 1, issued_at + 3600)?,
        epoch: json::integer(&m["epoch"], 0, i32::MAX as i64)?,
        certificate: bytes(json::thumbprint(&cnf["x5t#S256"])?),
    })
}
pub fn expectation(value: &Value) -> Outcome<Expectation> {
    let m = json::keys(value, &["issuer", "audience", "subject", "epoch"], &[])?;
    Ok(Expectation {
        issuer: bytes(json::word(&m["issuer"], 128)?),
        audience: bytes(json::word(&m["audience"], 128)?),
        subject: bytes(json::word(&m["subject"], 128)?),
        epoch: json::integer(&m["epoch"], 0, i32::MAX as i64)?,
    })
}
fn text(v: &[u8]) -> Outcome<&str> {
    std::str::from_utf8(v).map_err(|_| Error::InvalidCapability)
}
pub fn claims_json(c: &Claims) -> Outcome<Value> {
    Ok(
        json!({"iss":text(&c.issuer)?,"aud":text(&c.audience)?,"sub":text(&c.subject)?,"jti":text(&c.token_id)?,
    "iat":c.issued_at,"exp":c.expires_at,"epoch":c.epoch,"cnf":{"x5t#S256":text(&c.certificate)?}}),
    )
}
pub fn identity_json(c: &Claims) -> Outcome<Value> {
    Ok(
        json!({"subject":text(&c.subject)?,"token_id":text(&c.token_id)?,"epoch":c.epoch,"certificate_sha256":text(&c.certificate)?}),
    )
}

pub struct Enrollment {
    pub active: bool,
    pub epoch: i64,
    pub certificate: String,
    pub not_after: i64,
    pub key: String,
    pub retired: Vec<String>,
}
pub struct Registry {
    pub subjects: BTreeMap<String, Enrollment>,
}
impl Registry {
    pub fn parse(value: &Value, issuer: &str, audience: &str) -> Outcome<Self> {
        json::word(&json!(issuer), 128)?;
        json::word(&json!(audience), 128)?;
        let m = json::keys(value, &["schema", "subjects"], &[])?;
        json::integer(&m["schema"], 1, 1)?;
        let rows = m["subjects"].as_object().ok_or(Error::InvalidCapability)?;
        if rows.len() > 128 {
            return Err(Error::InvalidCapability);
        }
        let mut subjects = BTreeMap::new();
        let mut active_keys = BTreeSet::new();
        for (name, v) in rows {
            json::word(&json!(name), 128)?;
            let r = json::keys(
                v,
                &[
                    "epoch",
                    "active",
                    "certificate_sha256",
                    "not_after",
                    "key_sha256",
                    "retired_keys",
                ],
                &[],
            )?;
            let active = r["active"].as_bool().ok_or(Error::InvalidCapability)?;
            let key = json::hex(&r["key_sha256"], 64)?;
            let raw = r["retired_keys"]
                .as_array()
                .ok_or(Error::InvalidCapability)?;
            if raw.len() > 8 {
                return Err(Error::InvalidCapability);
            }
            let mut seen = BTreeSet::new();
            let mut retired = Vec::new();
            for item in raw {
                let k = json::hex(item, 64)?;
                if k == key || !seen.insert(k.clone()) {
                    return Err(Error::InvalidCapability);
                }
                retired.push(k);
            }
            if active && !active_keys.insert(key.clone()) {
                return Err(Error::InvalidCapability);
            }
            subjects.insert(
                name.clone(),
                Enrollment {
                    active,
                    epoch: json::integer(&r["epoch"], 0, i32::MAX as i64)?,
                    certificate: json::thumbprint(&r["certificate_sha256"])?,
                    not_after: json::integer(&r["not_after"], 0, i64::MAX)?,
                    key,
                    retired,
                },
            );
        }
        Ok(Self { subjects })
    }
    pub fn issue_inputs(
        &self,
        issuer: &str,
        audience: &str,
        subject: &str,
        token_id: &str,
    ) -> Outcome<core::IssueInputs> {
        json::word(&json!(issuer), 128)?;
        json::word(&json!(audience), 128)?;
        json::word(&json!(subject), 128)?;
        json::hex(&json!(token_id), 32)?;
        let row = self.subjects.get(subject).ok_or(Error::InvalidCapability)?;
        json::thumbprint(&json!(row.certificate))?;
        Ok(core::IssueInputs {
            issuer: issuer.as_bytes().to_vec(),
            audience: audience.as_bytes().to_vec(),
            subject: subject.as_bytes().to_vec(),
            token_id: token_id.as_bytes().to_vec(),
            certificate: row.certificate.as_bytes().to_vec(),
            active: row.active,
            epoch: row.epoch,
            not_after: row.not_after,
        })
    }
    pub fn expectation(
        &self,
        issuer: &str,
        audience: &str,
        peer: &str,
        now: i64,
    ) -> Outcome<Expectation> {
        if now < 0 {
            return Err(Error::InvalidCapability);
        }
        let mut matching = self
            .subjects
            .iter()
            .filter(|(_, r)| r.active && r.certificate == peer && now < r.not_after);
        let (subject, row) = matching.next().ok_or(Error::InvalidCapability)?;
        if matching.next().is_some() {
            return Err(Error::InvalidCapability);
        }
        Ok(Expectation {
            issuer: issuer.as_bytes().to_vec(),
            audience: audience.as_bytes().to_vec(),
            subject: subject.as_bytes().to_vec(),
            epoch: row.epoch,
        })
    }
}
pub fn evaluate(v: &Value) -> Outcome<Value> {
    let top = json::keys(
        v,
        &["version", "action"],
        &[
            "state",
            "issuer",
            "audience",
            "subject",
            "token_id",
            "now",
            "lifetime",
            "claims",
            "expected",
            "peer_thumbprint",
        ],
    )?;
    json::integer(&top["version"], 1, 1)?;
    match top["action"].as_str() {
        Some("issue") => {
            let m = json::keys(
                v,
                &[
                    "version", "action", "state", "issuer", "audience", "subject", "token_id",
                    "now", "lifetime",
                ],
                &[],
            )?;
            let issuer = json::word(&m["issuer"], 128)?;
            let audience = json::word(&m["audience"], 128)?;
            let registry = Registry::parse(&m["state"], &issuer, &audience)?;
            let subject = json::word(&m["subject"], 128)?;
            let token_id = json::hex(&m["token_id"], 32)?;
            let now = json::integer(&m["now"], 0, i64::MAX)?;
            let lifetime = json::integer(&m["lifetime"], 1, 3600)?;
            let input = registry.issue_inputs(&issuer, &audience, &subject, &token_id)?;
            let c =
                core::prepare_issue(input, now, lifetime).map_err(|_| Error::InvalidCapability)?;
            Ok(json!({"ok":true,"claims":claims_json(&c)?}))
        }
        Some("present") => {
            let m = json::keys(
                v,
                &[
                    "version",
                    "action",
                    "claims",
                    "expected",
                    "peer_thumbprint",
                    "now",
                ],
                &[],
            )?;
            let c = claims(&m["claims"])?;
            let expected = expectation(&m["expected"])?;
            let peer = json::thumbprint(&m["peer_thumbprint"])?;
            let now = json::integer(&m["now"], 0, i64::MAX)?;
            core::present(&c, &expected, &peer.into_bytes(), now)
                .map_err(|_| Error::InvalidCapability)?;
            Ok(json!({"ok":true,"identity":identity_json(&c)?}))
        }
        _ => Err(Error::InvalidCapability),
    }
}

/// The original binding-only runner has a smaller envelope and no identity output.
pub fn evaluate_identity(value: &Value) -> Outcome<Value> {
    let m = json::keys(
        value,
        &["version", "claims", "expected", "peer_thumbprint", "now"],
        &[],
    )?;
    json::integer(&m["version"], 1, 1)?;
    let mut full = value.clone();
    full.as_object_mut()
        .ok_or(Error::InvalidCapability)?
        .insert("action".into(), json!("present"));
    evaluate(&full)?;
    Ok(json!({"ok":true}))
}
