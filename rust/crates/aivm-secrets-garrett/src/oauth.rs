//! Pure OAuth acquisition/refresh decisions. Outputs contain grant metadata only.
use crate::{json, Error, Outcome};
use serde_json::{json, Value};
use std::collections::BTreeSet;
const MAX_TTL: i64 = 86400 * 90;
fn text(v: &Value) -> Outcome<&str> {
    v.as_str().ok_or(Error::CredentialSource)
}
fn opaque(v: &Value, max: usize) -> Outcome<&str> {
    let s = text(v)?;
    if s.is_empty() || s.len() > max || !s.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Error::CredentialSource);
    }
    Ok(s)
}
fn pkce(v: &Value) -> Outcome<&str> {
    let s = text(v)?;
    if !(43..=128).contains(&s.len())
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return Err(Error::CredentialSource);
    }
    Ok(s)
}
fn scopes(v: &Value) -> Outcome<Vec<String>> {
    let a = v.as_array().ok_or(Error::CredentialSource)?;
    if a.len() > 32 {
        return Err(Error::CredentialSource);
    }
    let mut result = BTreeSet::new();
    for item in a {
        let s = json::word(item, 128)?;
        if !result.insert(s) {
            return Err(Error::CredentialSource);
        }
    }
    Ok(result.into_iter().collect())
}
struct Grant<'a> {
    refresh: Option<&'a str>,
    expires: i64,
    scopes: Vec<String>,
    generation: i64,
}
fn grant(v: &Value) -> Outcome<Grant<'_>> {
    let m = json::keys(
        v,
        &[
            "access_token",
            "refresh_token",
            "expires_at",
            "scopes",
            "generation",
        ],
        &[],
    )?;
    opaque(&m["access_token"], 4096)?;
    let refresh = if m["refresh_token"].is_null() {
        None
    } else {
        Some(opaque(&m["refresh_token"], 8192)?)
    };
    Ok(Grant {
        refresh,
        expires: json::integer(&m["expires_at"], 1, i64::MAX)?,
        scopes: scopes(&m["scopes"])?,
        generation: json::integer(&m["generation"], 0, i32::MAX as i64)?,
    })
}
pub fn evaluate(v: &Value) -> Outcome<Value> {
    let top = json::keys(
        v,
        &["version", "action"],
        &[
            "pending",
            "parameters",
            "now",
            "expected_issuer",
            "response",
            "allowed_scopes",
            "previous",
            "fallback_ttl",
            "require_rotation",
            "grant",
            "leeway",
            "sent",
            "status",
            "oauth_error",
        ],
    )?;
    json::integer(&top["version"], 1, 1)?;
    match top["action"].as_str() {
        Some("callback") => {
            let m = json::keys(
                v,
                &["version", "action", "pending", "parameters", "now"],
                &["expected_issuer"],
            )?;
            let p = json::keys(
                &m["pending"],
                &[
                    "state",
                    "verifier",
                    "redirect_uri",
                    "issued_at",
                    "expires_at",
                ],
                &[],
            )?;
            let issuer = m
                .get("expected_issuer")
                .map(text)
                .transpose()?
                .unwrap_or("");
            let issued = json::integer(&p["issued_at"], 0, i64::MAX)?;
            let expires = json::integer(&p["expires_at"], 0, i64::MAX)?;
            pkce(&p["state"])?;
            pkce(&p["verifier"])?;
            opaque(&p["redirect_uri"], 256)?;
            if issued > i64::MAX - 600 || !(1..=600).contains(&(expires - issued)) {
                return Err(Error::CredentialSource);
            }
            let params = m["parameters"].as_object().ok_or(Error::CredentialSource)?;
            let now = json::integer(&m["now"], 0, i64::MAX)?;
            if now < issued || now >= expires {
                return Err(Error::Expired);
            }
            let denied =
                if params.len() == 2 && params.contains_key("code") && params.contains_key("state")
                    || params.len() == 3
                        && params.contains_key("code")
                        && params.contains_key("state")
                        && params.contains_key("iss")
                {
                    false
                } else {
                    json::keys(
                        &m["parameters"],
                        &["error", "state"],
                        &["error_description", "error_uri", "iss"],
                    )?;
                    true
                };
            if params["state"] != p["state"]
                || (!issuer.is_empty() && params.get("iss") != Some(&json!(issuer)))
                || (issuer.is_empty() && params.contains_key("iss"))
            {
                return Err(Error::CredentialSource);
            }
            if !denied {
                opaque(&params["code"], 4096)?;
                return Ok(json!({"ok":true}));
            }
            opaque(&params["error"], 128)?;
            for name in ["error_description", "error_uri"] {
                if let Some(v) = params.get(name) {
                    let s = text(v)?;
                    if s.is_empty() || s.len() > 2048 || s.contains('\0') {
                        return Err(Error::CredentialSource);
                    }
                }
            }
            Err(Error::AuthorizationDenied)
        }
        Some("token") => {
            let m = json::keys(
                v,
                &["version", "action", "response", "allowed_scopes", "now"],
                &["previous", "fallback_ttl", "require_rotation"],
            )?;
            if !m["allowed_scopes"].is_array() {
                return Err(Error::CredentialSource);
            }
            let previous = m.get("previous").map(grant).transpose()?;
            let response = m["response"].as_object().ok_or(Error::CredentialSource)?;
            let now = json::integer(&m["now"], 0, i64::MAX - 1)?;
            let rotation = m
                .get("require_rotation")
                .map(|v| v.as_bool().ok_or(Error::CredentialSource))
                .transpose()?
                .unwrap_or(true);
            if !response
                .get("token_type")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case("bearer"))
            {
                return Err(Error::CredentialSource);
            }
            opaque(
                response
                    .get("access_token")
                    .ok_or(Error::CredentialSource)?,
                4096,
            )?;
            let provided = match response.get("refresh_token") {
                None | Some(Value::Null) => None,
                Some(v) => Some(opaque(v, 8192)?),
            };
            let (refresh, generation) = if let Some(prev) = &previous {
                if rotation
                    && prev.refresh.is_some()
                    && (provided.is_none() || provided == prev.refresh)
                {
                    return Err(Error::CredentialSource);
                }
                if prev.generation >= i32::MAX as i64 {
                    return Err(Error::CredentialSource);
                }
                (provided.or(prev.refresh), prev.generation + 1)
            } else {
                (provided, 0)
            };
            let fallback = m
                .get("fallback_ttl")
                .map(|v| json::integer(v, 1, MAX_TTL))
                .transpose()?
                .unwrap_or(3600);
            let ttl = response
                .get("expires_in")
                .map(|v| json::integer(v, 1, MAX_TTL))
                .transpose()?
                .unwrap_or(fallback);
            let expires = now.checked_add(ttl).ok_or(Error::CredentialSource)?;
            let allowed = scopes(&m["allowed_scopes"])?;
            let mut effective = previous
                .as_ref()
                .map_or_else(|| allowed.clone(), |p| p.scopes.clone());
            if let Some(v) = response.get("scope") {
                let tokens: Vec<_> = text(v)?
                    .split([' ', ','])
                    .filter(|s| !s.is_empty())
                    .collect();
                effective = scopes(&json!(tokens))?;
                if effective.iter().any(|s| !allowed.contains(s)) {
                    return Err(Error::CredentialSource);
                }
            }
            if previous
                .as_ref()
                .is_some_and(|p| effective.iter().any(|s| !p.scopes.contains(s)))
            {
                return Err(Error::CredentialSource);
            }
            Ok(
                json!({"ok":true,"expires_at":expires,"scopes":effective,"generation":generation,"has_refresh":refresh.is_some()}),
            )
        }
        Some("active") => {
            let m = json::keys(v, &["version", "action", "grant", "now"], &["leeway"])?;
            let grant = grant(&m["grant"])?;
            let now = json::integer(&m["now"], 0, i64::MAX)?;
            let leeway = m
                .get("leeway")
                .map(|v| json::integer(v, 0, 600))
                .transpose()?
                .unwrap_or(30);
            if now.checked_add(leeway).is_none_or(|n| n >= grant.expires) {
                return Err(Error::Expired);
            }
            Ok(json!({"ok":true}))
        }
        Some("classify") => {
            let m = json::keys(
                v,
                &["version", "action", "sent", "status", "oauth_error"],
                &[],
            )?;
            let sent = m["sent"].as_bool().ok_or(Error::CredentialSource)?;
            let status = json::integer(&m["status"], 0, 599)?;
            let error = text(&m["oauth_error"])?;
            if error.len() > 128
                || !error
                    .bytes()
                    .all(|b| (32..=126).contains(&b) && b != b'"' && b != b'\\')
                || (status != 0 && status < 100)
            {
                return Err(Error::CredentialSource);
            }
            let outcome = if !sent {
                if status != 0 || !error.is_empty() {
                    return Err(Error::CredentialSource);
                }
                "not_sent"
            } else if status == 400 && error == "invalid_grant" {
                "rejected_grant"
            } else {
                "in_doubt"
            };
            Ok(json!({"ok":true,"outcome":outcome}))
        }
        _ => Err(Error::CredentialSource),
    }
}
