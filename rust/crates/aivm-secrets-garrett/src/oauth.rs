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
pub(crate) fn scopes(v: &Value) -> Outcome<Vec<String>> {
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
fn bytes(scopes: &[String]) -> Vec<Vec<u8>> {
    scopes.iter().map(|s| s.as_bytes().to_vec()).collect()
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
            let issuer = m
                .get("expected_issuer")
                .map(text)
                .transpose()?
                .unwrap_or("");
            let stage = callback(
                &m["pending"],
                &m["parameters"],
                json::integer(&m["now"], 0, i64::MAX)?,
                issuer,
                &aivm_secrets_garrett_core::oauth_login::Stage::Pending,
            )?;
            match stage {
                aivm_secrets_garrett_core::oauth_login::Stage::Accepted => Ok(json!({"ok":true})),
                _ => Err(Error::AuthorizationDenied),
            }
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
                let generation = aivm_secrets_garrett_core::oauth_state::next_generation(
                    rotation,
                    prev.refresh.is_some(),
                    provided.is_some(),
                    provided == prev.refresh,
                    prev.generation,
                )
                .ok_or(Error::CredentialSource)?;
                (provided.or(prev.refresh), generation)
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
                if !aivm_secrets_garrett_core::oauth_state::within(
                    &bytes(&effective),
                    &bytes(&allowed),
                ) {
                    return Err(Error::CredentialSource);
                }
            }
            if previous.as_ref().is_some_and(|p| {
                !aivm_secrets_garrett_core::oauth_state::within(
                    &bytes(&effective),
                    &bytes(&p.scopes),
                )
            }) {
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
            if !aivm_secrets_garrett_core::oauth_state::fresh(now, leeway, grant.expires) {
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
            if !sent && (status != 0 || !error.is_empty()) {
                return Err(Error::CredentialSource);
            }
            let outcome = match aivm_secrets_garrett_core::oauth_state::classify(
                sent,
                status,
                error == "invalid_grant",
            ) {
                aivm_secrets_garrett_core::oauth_state::ExchangeFailure::NotSent => "not_sent",
                aivm_secrets_garrett_core::oauth_state::ExchangeFailure::Rejected => {
                    "rejected_grant"
                }
                aivm_secrets_garrett_core::oauth_state::ExchangeFailure::Uncertain => "in_doubt",
            };
            Ok(json!({"ok":true,"outcome":outcome}))
        }
        _ => Err(Error::CredentialSource),
    }
}

fn login_error(error: aivm_secrets_garrett_core::oauth_login::LoginDenial) -> Error {
    match error {
        aivm_secrets_garrett_core::oauth_login::LoginDenial::Expired => Error::Expired,
        _ => Error::CredentialSource,
    }
}
pub(crate) fn callback(
    pending: &Value,
    parameters: &Value,
    now: i64,
    issuer: &str,
    stage: &aivm_secrets_garrett_core::oauth_login::Stage,
) -> Outcome<aivm_secrets_garrett_core::oauth_login::Stage> {
    use aivm_secrets_garrett_core::oauth_login as login;
    let p = json::keys(
        pending,
        &[
            "state",
            "verifier",
            "redirect_uri",
            "issued_at",
            "expires_at",
        ],
        &[],
    )?;
    pkce(&p["state"])?;
    pkce(&p["verifier"])?;
    opaque(&p["redirect_uri"], 256)?;
    let bound = login::Pending {
        state: text(&p["state"])?.as_bytes().to_vec(),
        issuer: if issuer.is_empty() {
            login::IssuerRule::Absent
        } else {
            login::IssuerRule::Exact(issuer.as_bytes().to_vec())
        },
        issued_at: json::integer(&p["issued_at"], 0, i64::MAX)?,
        expires_at: json::integer(&p["expires_at"], 0, i64::MAX)?,
    };
    login::current(&bound, now).map_err(login_error)?;
    let params = parameters.as_object().ok_or(Error::CredentialSource)?;
    let denied = if params.len() == 2 && params.contains_key("code") && params.contains_key("state")
        || params.len() == 3
            && params.contains_key("code")
            && params.contains_key("state")
            && params.contains_key("iss")
    {
        false
    } else {
        json::keys(
            parameters,
            &["error", "state"],
            &["error_description", "error_uri", "iss"],
        )?;
        true
    };
    let received = login::Callback {
        state: text(&params["state"])?.as_bytes().to_vec(),
        issuer: params
            .get("iss")
            .map(text)
            .transpose()?
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
        has_issuer: params.contains_key("iss"),
        denied,
    };
    let claimed = login::claim(stage, &bound, &received, now).map_err(login_error)?;
    if !denied {
        opaque(&params["code"], 4096)?;
    } else {
        opaque(&params["error"], 128)?;
        for name in ["error_description", "error_uri"] {
            if let Some(v) = params.get(name) {
                let s = text(v)?;
                if s.is_empty() || s.len() > 2048 || s.contains('\0') {
                    return Err(Error::CredentialSource);
                }
            }
        }
    }
    Ok(claimed)
}
