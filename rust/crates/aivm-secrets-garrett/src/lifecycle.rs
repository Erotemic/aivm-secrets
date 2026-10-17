//! Public trust-generation, key-custody and VM-subject decisions.
use crate::{json, Error, Outcome};
use ring::digest;
use serde_json::{json, Value};
fn text(v: &Value) -> Outcome<&str> {
    v.as_str().ok_or(Error::InvalidCapability)
}
fn authority(value: &Value) -> Outcome<Value> {
    let m = json::keys(
        value,
        &["schema", "issuer", "audience", "created_at", "ca", "server"],
        &[],
    )?;
    json::integer(&m["schema"], 2, 2)?;
    json::word(&m["issuer"], 128)?;
    json::word(&m["audience"], 128)?;
    json::integer(&m["created_at"], 0, i64::MAX)?;
    let ca = json::keys(&m["ca"], &["generation", "sha256"], &[])?;
    let server = json::keys(&m["server"], &["generation", "ca_generation"], &[])?;
    let generation = json::integer(&ca["generation"], 1, 64)?;
    json::hex(&ca["sha256"], 64)?;
    json::integer(&server["generation"], 1, 2048)?;
    json::integer(&server["ca_generation"], generation, generation)?;
    Ok(value.clone())
}
pub fn evaluate_authority(value: &Value) -> Outcome<Value> {
    let top = json::keys(
        value,
        &["version", "action"],
        &[
            "issuer",
            "audience",
            "created_at",
            "ca_sha256",
            "state",
            "ca_generation",
            "server_generation",
            "expected_ca_sha256",
        ],
    )?;
    json::integer(&top["version"], 1, 1)?;
    let action = text(&top["action"])?;
    let extra: &[&str] = match action {
        "init" => &["issuer", "audience", "created_at", "ca_sha256"],
        "validate" => &["state"],
        "rotate-ca" => &["state", "ca_generation", "ca_sha256", "server_generation"],
        "renew-server" => &["state", "server_generation"],
        "require-ca" => &["state", "expected_ca_sha256"],
        _ => return Err(Error::InvalidCapability),
    };
    let mut required = vec!["version", "action"];
    required.extend_from_slice(extra);
    let m = json::keys(value, &required, &[])?;
    let state = if action == "init" {
        authority(
            &json!({"schema":2,"issuer":m["issuer"],"audience":m["audience"],"created_at":m["created_at"],"ca":{"generation":1,"sha256":m["ca_sha256"]},"server":{"generation":1,"ca_generation":1}}),
        )?
    } else {
        let mut current = authority(&m["state"])?;
        match action {
            "require-ca" => {
                let expected = json::hex(&m["expected_ca_sha256"], 64)?;
                if current["ca"]["sha256"] != expected {
                    return Err(Error::Revoked);
                }
            }
            "rotate-ca" => {
                let ca = json::integer(
                    &m["ca_generation"],
                    current["ca"]["generation"]
                        .as_i64()
                        .ok_or(Error::InvalidCapability)?
                        + 1,
                    64,
                )?;
                let server = json::integer(
                    &m["server_generation"],
                    current["server"]["generation"]
                        .as_i64()
                        .ok_or(Error::InvalidCapability)?
                        + 1,
                    2048,
                )?;
                let thumb = json::hex(&m["ca_sha256"], 64)?;
                if current["ca"]["sha256"] == thumb {
                    return Err(Error::Denied);
                }
                current["ca"] = json!({"generation":ca,"sha256":thumb});
                current["server"] = json!({"generation":server,"ca_generation":ca});
            }
            "renew-server" => {
                let server = json::integer(
                    &m["server_generation"],
                    current["server"]["generation"]
                        .as_i64()
                        .ok_or(Error::InvalidCapability)?
                        + 1,
                    2048,
                )?;
                current["server"] =
                    json!({"generation":server,"ca_generation":current["ca"]["generation"]});
            }
            _ => {}
        }
        current
    };
    Ok(json!({"ok":true,"state":state}))
}
pub fn evaluate_key_rotation(value: &Value) -> Outcome<Value> {
    let fields = [
        "expected_epoch",
        "actual_epoch",
        "expected_thumbprint",
        "actual_thumbprint",
        "enrolled_key_fingerprint",
        "candidate_key_fingerprint",
    ];
    let mut optional = fields.to_vec();
    optional.push("action");
    let top = json::keys(value, &[], &optional)?;
    let action = top.get("action").map(text).transpose()?.unwrap_or("rotate");
    if action == "reuse" {
        let m = json::keys(
            value,
            &[
                "action",
                "enrolled_key_fingerprint",
                "candidate_key_fingerprint",
            ],
            &[],
        )?;
        let enrolled = json::hex(&m["enrolled_key_fingerprint"], 64)?;
        let candidate = json::hex(&m["candidate_key_fingerprint"], 64)?;
        if enrolled != candidate {
            return Err(Error::Denied);
        }
        return Ok(json!({"ok":true}));
    }
    if action != "rotate" {
        return Err(Error::InvalidCapability);
    }
    let m = json::keys(value, &fields, &["action"])?;
    let expected = json::integer(&m["expected_epoch"], 0, i32::MAX as i64)?;
    let actual = json::integer(&m["actual_epoch"], 0, i32::MAX as i64)?;
    let enrolled = json::hex(&m["enrolled_key_fingerprint"], 64)?;
    let candidate = json::hex(&m["candidate_key_fingerprint"], 64)?;
    let expected_cert = text(&m["expected_thumbprint"])?;
    let actual_cert = text(&m["actual_thumbprint"])?;
    if expected != actual || expected_cert != actual_cert {
        return Err(Error::Revoked);
    }
    if enrolled == candidate {
        return Err(Error::Denied);
    }
    if actual == i32::MAX as i64 {
        return Err(Error::Revoked);
    }
    Ok(json!({"ok":true,"next_epoch":actual+1}))
}
pub fn evaluate_vm(value: &Value) -> Outcome<Value> {
    let m = json::keys(
        value,
        &[
            "schema",
            "store",
            "vm",
            "domain_uuid",
            "principal",
            "host_uid",
            "guest_user",
        ],
        &[],
    )?;
    json::integer(&m["schema"], 1, 1)?;
    json::hex(&m["store"], 64)?;
    json::integer(&m["host_uid"], 1, i32::MAX as i64)?;
    for name in ["vm", "principal", "guest_user"] {
        let s = text(&m[name])?;
        if s.is_empty()
            || s.len() > 128
            || !(s.as_bytes()[0].is_ascii_alphanumeric() || s.as_bytes()[0] == b'_')
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
        {
            return Err(Error::InvalidCapability);
        }
    }
    let uuid = text(&m["domain_uuid"])?;
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(Error::InvalidCapability);
    }
    let mut bytes = b"aivm-secrets/managed-vm/v1\0".to_vec();
    bytes.extend(json::canonical(value));
    let digest = digest::digest(&digest::SHA256, &bytes);
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    Ok(json!({"ok":true,"subject":format!("vm-{hex}")}))
}
