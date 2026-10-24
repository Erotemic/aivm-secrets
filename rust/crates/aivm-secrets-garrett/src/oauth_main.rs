//! Host-only OAuth custody operations. Requests carry paths, never token bytes.
use aivm_secrets_garrett::{
    files, json,
    oauth_vault::{provider::Provider, OAuthOutcome, OAuthVault},
    Error, Outcome,
};
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn text<'a>(v: &'a Value, key: &str) -> Outcome<&'a str> {
    v[key].as_str().ok_or(Error::InvalidRequest)
}
fn flag(v: &Value, key: &str) -> Outcome<bool> {
    v.get(key)
        .map(|v| v.as_bool().ok_or(Error::InvalidRequest))
        .transpose()
        .map(|v| v.unwrap_or(false))
}
fn execute(action: &str, root: &Path, request: &Value) -> OAuthOutcome<Value> {
    let now = match request.get("now") {
        Some(v) => json::integer(v, 0, i64::MAX)?,
        None => i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::InternalError)?
                .as_secs(),
        )
        .map_err(|_| Error::InternalError)?,
    };
    if action == "init" {
        json::keys(request, &[], &[])?;
        OAuthVault::initialize(root)?;
        return Ok(json!({"initialized":true}));
    }
    let required = match action {
        "enroll" => vec!["provider_file", "subject", "grant_file"],
        "login" => vec!["provider_file", "subject"],
        "session-check" => vec!["provider_file", "subject", "resource_host"],
        "status" | "revoke" | "refresh" => vec!["provider_file", "subject"],
        _ => return Err(Error::InvalidRequest.into()),
    };
    let optional: &[&str] = match action {
        "status" => &[],
        "enroll" => &["replace", "now"],
        "login" => &["replace", "timeout", "transport"],
        "revoke" => &["now", "transport"],
        "refresh" => &["retry_in_doubt", "transport", "now"],
        _ => &["force_refresh", "transport", "now"],
    };
    json::keys(request, &required, optional)?;
    let vault = OAuthVault::open(root)?;
    let provider = Provider::from_file(Path::new(text(request, "provider_file")?))?;
    let subject = text(request, "subject")?;
    let empty = json!({});
    let transport = request.get("transport").unwrap_or(&empty);
    match action {
        "status" => Ok(vault.status(&provider, subject)?),
        "login" => vault.login(
            &provider,
            subject,
            flag(request, "replace")?,
            request
                .get("timeout")
                .map(|v| json::integer(v, 1, 600))
                .transpose()?
                .unwrap_or(180),
            transport,
            |event| {
                let mut output = io::stdout().lock();
                output
                    .write_all(&json::canonical(event))
                    .and_then(|_| output.write_all(b"\n"))
                    .and_then(|_| output.flush())
                    .map_err(|_| Error::InternalError)
            },
        ),
        "enroll" => Ok(vault.enroll_file(
            &provider,
            subject,
            Path::new(text(request, "grant_file")?),
            flag(request, "replace")?,
            now,
        )?),
        "revoke" => Ok(vault.revoke(&provider, subject, now, request.get("transport"))?),
        "refresh" => vault.refresh(
            &provider,
            subject,
            now,
            flag(request, "retry_in_doubt")?,
            transport,
        ),
        "session-check" => vault.session_check(
            &provider,
            subject,
            text(request, "resource_host")?,
            now,
            flag(request, "force_refresh")?,
            transport,
        ),
        _ => Err(Error::InvalidRequest.into()),
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("garrett-oauth ACTION --root ABSOLUTE_PRIVATE_ROOT [--request PRIVATE_JSON]\nActions: init, status, login, enroll, revoke, refresh, session-check. Login emits a host-only authorization URL after binding its callback; open it in your trusted browser.\nExperimental host custody only; replies never contain credentials. Refresh retry requires explicit retry_in_doubt.");
        return;
    }
    let result = (|| -> OAuthOutcome<Value> {
        if (args.len() != 3 && args.len() != 5) || args[1] != "--root" {
            return Err(Error::InvalidRequest.into());
        }
        let request = if args.len() == 5 {
            if args[3] != "--request" {
                return Err(Error::InvalidRequest.into());
            }
            json::parse(&files::read_private(Path::new(&args[4]), 16384)?, 16384)?
        } else {
            json!({})
        };
        execute(&args[0], Path::new(&args[2]), &request)
    })();
    let (reply, code) = match result {
        Ok(value) => (json!({"version":1,"ok":true,"result":value}), 0),
        Err(error) => (
            json!({"version":1,"ok":false,"error":error.public_error()}),
            1,
        ),
    };
    let mut output = io::stdout().lock();
    if output
        .write_all(&json::canonical(&reply))
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .is_err()
    {
        std::process::exit(1);
    }
    if code != 0 {
        std::process::exit(code);
    }
}
