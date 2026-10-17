//! Independent enrollment/CAS/renewal/revocation transitions over the v1 registry.
use crate::{json, model::Registry, Error, Outcome};
use serde_json::{json, Map, Value};
const MAX_EPOCH: i64 = i32::MAX as i64;
fn name(v: &Value) -> Outcome<String> {
    json::word(v, 128)
}
fn string(v: &Value) -> Outcome<&str> {
    v.as_str().ok_or(Error::InvalidCapability)
}
fn row_mut<'a>(state: &'a mut Value, subject: &str) -> Outcome<&'a mut Map<String, Value>> {
    state
        .get_mut("subjects")
        .and_then(|v| v.get_mut(subject))
        .and_then(Value::as_object_mut)
        .ok_or(Error::InvalidCapability)
}
fn deactivate(row: &mut Map<String, Value>) {
    row.insert("active".into(), json!(false));
    let epoch = row["epoch"].as_i64().expect("validated epoch");
    row.insert(
        "epoch".into(),
        json!(epoch.saturating_add(1).min(MAX_EPOCH)),
    );
}
fn enroll(
    state: &Value,
    subject: &str,
    thumb: &Value,
    key: &Value,
    not_after: &Value,
    replace: bool,
) -> Outcome<Value> {
    let thumb = json::thumbprint(thumb)?;
    let key = json::hex(key, 64)?;
    let expiry = json::integer(not_after, 0, i64::MAX)?;
    let rows = state["subjects"]
        .as_object()
        .ok_or(Error::InvalidCapability)?;
    let prior = rows.get(subject);
    if prior.is_some_and(|p| p["active"] == true) && !replace {
        return Err(Error::Denied);
    }
    if prior.is_some_and(|p| {
        p["retired_keys"]
            .as_array()
            .is_some_and(|retired| retired.contains(&json!(key)))
    }) {
        return Err(Error::Denied);
    }
    if rows
        .iter()
        .any(|(n, r)| n != subject && r["active"] == true && r["key_sha256"] == key)
    {
        return Err(Error::Denied);
    }
    if prior.is_some_and(|p| p["epoch"] == MAX_EPOCH) || (prior.is_none() && rows.len() >= 128) {
        return Err(Error::Exhausted);
    }
    let epoch = prior.map_or(0, |p| p["epoch"].as_i64().expect("validated epoch") + 1);
    let mut retired = prior
        .and_then(|p| p["retired_keys"].as_array())
        .cloned()
        .unwrap_or_default();
    if let Some(p) = prior {
        if p["key_sha256"] != key {
            retired.push(p["key_sha256"].clone());
        }
    }
    if retired.len() > 8 {
        retired.drain(..retired.len() - 8);
    }
    let row = json!({"epoch":epoch,"active":true,"certificate_sha256":thumb,"not_after":expiry,"key_sha256":key,"retired_keys":retired});
    let mut result = state.clone();
    result["subjects"]
        .as_object_mut()
        .ok_or(Error::InvalidCapability)?
        .insert(subject.to_owned(), row);
    Ok(result)
}
pub fn evaluate(value: &Value) -> Outcome<Value> {
    let common = ["version", "action", "issuer", "audience", "state"];
    let top = json::keys(
        value,
        &common,
        &[
            "subject",
            "thumbprint",
            "key_sha256",
            "not_after",
            "replace",
            "now",
            "expected_epoch",
            "expected_thumbprint",
        ],
    )?;
    json::integer(&top["version"], 1, 1)?;
    let action = string(&top["action"])?;
    let extra: &[&str] = match action {
        "enroll" => &[
            "subject",
            "thumbprint",
            "key_sha256",
            "not_after",
            "replace",
        ],
        "replace-if-current" => &[
            "subject",
            "thumbprint",
            "key_sha256",
            "not_after",
            "expected_epoch",
            "expected_thumbprint",
        ],
        "renew" => &[
            "subject",
            "thumbprint",
            "key_sha256",
            "not_after",
            "expected_epoch",
            "expected_thumbprint",
            "now",
        ],
        "revoke-if-current" => &["subject", "expected_epoch", "expected_thumbprint"],
        "revoke" => &["subject"],
        "revoke-all" => &[],
        "forget" => &["subject", "now"],
        "prune" => &["now"],
        "lookup" => &["thumbprint", "now"],
        _ => return Err(Error::InvalidCapability),
    };
    let mut required = common.to_vec();
    required.extend_from_slice(extra);
    let m = json::keys(value, &required, &[])?;
    let issuer = name(&m["issuer"])?;
    let audience = name(&m["audience"])?;
    let registry = Registry::parse(&m["state"], &issuer, &audience)?;
    let state = &m["state"];
    let subject = if let Some(v) = m.get("subject") {
        name(v)?
    } else {
        String::new()
    };
    let prior = registry.subjects.get(&subject);
    let updated = match action {
        "enroll" => enroll(
            state,
            &subject,
            &m["thumbprint"],
            &m["key_sha256"],
            &m["not_after"],
            m["replace"].as_bool().ok_or(Error::InvalidCapability)?,
        )?,
        "replace-if-current" | "renew" => {
            let epoch = json::integer(&m["expected_epoch"], 0, MAX_EPOCH)?;
            let expected = string(&m["expected_thumbprint"])?;
            let expiry = json::integer(&m["not_after"], 0, i64::MAX)?;
            if action == "renew" {
                let now = json::integer(&m["now"], 0, i64::MAX)?;
                if expiry <= now {
                    return Err(Error::InvalidCapability);
                }
            } else {
                json::thumbprint(&m["thumbprint"])?;
            }
            json::hex(&m["key_sha256"], 64)?;
            let row = prior.ok_or(Error::Revoked)?;
            if row.epoch != epoch
                || row.certificate != expected
                || (action == "renew" && !row.active)
            {
                return Err(Error::Revoked);
            }
            if action == "renew" {
                if m["thumbprint"] == expected {
                    return Err(Error::Denied);
                }
                if row.epoch == MAX_EPOCH {
                    return Err(Error::Revoked);
                }
            }
            enroll(
                state,
                &subject,
                &m["thumbprint"],
                &m["key_sha256"],
                &m["not_after"],
                true,
            )?
        }
        "revoke-if-current" => {
            let epoch = json::integer(&m["expected_epoch"], 0, MAX_EPOCH)?;
            let expected = string(&m["expected_thumbprint"])?;
            let revoked =
                prior.is_some_and(|r| r.active && r.epoch == epoch && r.certificate == expected);
            let mut result = state.clone();
            if revoked {
                deactivate(row_mut(&mut result, &subject)?);
            }
            return Ok(json!({"ok":true,"state":result,"revoked":revoked}));
        }
        "revoke" => {
            let row = prior.ok_or(Error::Denied)?;
            let mut result = state.clone();
            if row.active {
                deactivate(row_mut(&mut result, &subject)?);
            }
            result
        }
        "revoke-all" => {
            let mut result = state.clone();
            for (name, row) in &registry.subjects {
                if row.active {
                    deactivate(row_mut(&mut result, name)?);
                }
            }
            result
        }
        "forget" | "prune" => {
            let now = json::integer(&m["now"], 0, i64::MAX)?;
            if action == "forget" && !prior.is_some_and(|r| !r.active && now >= r.not_after) {
                return Err(Error::Denied);
            }
            let mut result = state.clone();
            let rows = result["subjects"]
                .as_object_mut()
                .ok_or(Error::InvalidCapability)?;
            for (name, row) in &registry.subjects {
                if (action == "prune" || name == &subject) && !row.active && now >= row.not_after {
                    rows.remove(name);
                }
            }
            result
        }
        "lookup" => {
            let now = json::integer(&m["now"], 0, i64::MAX)?;
            let peer = string(&m["thumbprint"])?;
            let expected = registry.expectation(&issuer, &audience, peer, now)?;
            return Ok(
                json!({"ok":true,"expected":{"issuer":issuer,"audience":audience,"subject":String::from_utf8(expected.subject).map_err(|_|Error::InvalidCapability)?,"epoch":expected.epoch}}),
            );
        }
        _ => return Err(Error::InvalidCapability),
    };
    Ok(json!({"ok":true,"state":updated}))
}
