//! Host-selected operator control over the existing coordinator mTLS protocol.
use aivm_secrets_garrett::{coordinator_admin::Client, json, Error, Outcome};
use serde_json::{json, Value};
use std::{io::Write, path::Path};

fn execute(args: &[String]) -> Outcome<Value> {
    if args.len() < 3 || args[0] != "--config" {
        return Err(Error::InvalidRequest);
    }
    let action = args[2].as_str();
    let mut members = Vec::new();
    match action {
        "activate" => {
            let rest = &args[3..];
            if rest.is_empty() || !rest.len().is_multiple_of(2) || rest.len() > 64 {
                return Err(Error::InvalidRequest);
            }
            for pair in rest.as_chunks::<2>().0 {
                if pair[0] != "--member" {
                    return Err(Error::InvalidRequest);
                }
                members.push(json::hex(&json!(pair[1]), 64).map_err(|_| Error::InvalidRequest)?);
            }
            members.sort();
            if members.windows(2).any(|v| v[0] == v[1]) {
                return Err(Error::InvalidRequest);
            }
        }
        "revoke" | "status" if args.len() == 3 => (),
        _ => return Err(Error::InvalidRequest),
    }
    let client = Client::from_file(Path::new(&args[1]))?;
    match action {
        "activate" => client.activate(&members),
        "revoke" => client.revoke(),
        "status" => client.status(),
        _ => Err(Error::InvalidRequest),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("garrett-coordinatorctl --config PRIVATE_JSON status\ngarrett-coordinatorctl --config PRIVATE_JSON activate --member LOWERCASE_CERTIFICATE_DER_SHA256 [--member ...]\ngarrett-coordinatorctl --config PRIVATE_JSON revoke\nThe private config selects the principal, CA and operator identity. No offline admission, automatic retry or Python fallback. After outcome_unknown, inspect status and reconcile before another action. An absent status is not a revocation receipt.");
        return;
    }
    let (mut reply, success) = match execute(&args) {
        Ok(value) => (value, true),
        Err(error) => (json!({"ok":false,"error":{"code":error.code()}}), false),
    };
    reply["version"] = json!(1);
    let mut bytes = json::canonical(&reply);
    bytes.push(b'\n');
    if std::io::stdout().lock().write_all(&bytes).is_err() || !success {
        std::process::exit(1);
    }
}
