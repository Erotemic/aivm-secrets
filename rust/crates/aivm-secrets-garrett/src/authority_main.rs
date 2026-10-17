//! Explicit host authority operations. Requests select public metadata/paths;
//! private CA/issuer keys are never returned or accepted as command arguments.
use aivm_secrets_garrett::{
    attestation,
    authority::{EnrollmentOptions, IdentityAuthority},
    certificates::ClientRequest,
    files, json, Error, Outcome,
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Read, Write},
    path::Path,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn text<'a>(value: &'a Value, key: &str) -> Outcome<&'a str> {
    value[key].as_str().ok_or(Error::InvalidRequest)
}
fn flag(value: &Value, key: &str) -> Outcome<bool> {
    value
        .get(key)
        .map(|v| v.as_bool().ok_or(Error::InvalidRequest))
        .unwrap_or(Ok(false))
}
fn stamp(value: &Value) -> Outcome<i64> {
    if let Some(now) = value.get("now") {
        json::integer(now, 0, i64::MAX)
    } else {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::InternalError)?
                .as_secs(),
        )
        .map_err(|_| Error::InternalError)
    }
}
fn reply(value: &Value) -> Outcome<()> {
    let mut output = io::stdout().lock();
    output
        .write_all(&json::canonical(value))
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .map_err(|_| Error::InternalError)
}
fn unhex(v: &Value, limit: usize) -> Outcome<Vec<u8>> {
    let s = v.as_str().ok_or(Error::InvalidCapability)?;
    if s.len() > limit * 2
        || !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidCapability);
    }
    s.as_bytes()
        .chunks(2)
        .map(|v| {
            u8::from_str_radix(
                std::str::from_utf8(v).map_err(|_| Error::InvalidCapability)?,
                16,
            )
            .map_err(|_| Error::InvalidCapability)
        })
        .collect()
}
fn evidence(request: &Value) -> Outcome<attestation::VerifiedIdentity> {
    let authority = attestation::Authority::from_trusted_pin(
        &files::read_private(Path::new(text(request, "ak_public_area_file")?), 1024)?,
        &files::read_private(Path::new(text(request, "ak_qualified_name_file")?), 128)?,
    )?;
    let pending = authority.begin()?;
    let challenge: String = pending
        .challenge()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    reply(&json!({"version":1,"ok":true,"challenge_hex":challenge,"expires_in":120}))?;
    // A stalled peer cannot leave a privileged authority process waiting
    // forever. The consuming verifier and later enrollment check the deadline.
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut raw = Vec::new();
        let result = io::stdin()
            .lock()
            .take(16385)
            .read_until(b'\n', &mut raw)
            .map(|_| raw);
        let _ = sender.send(result);
    });
    let raw = receiver
        .recv_timeout(Duration::from_secs(120))
        .map_err(|_| Error::Expired)?
        .map_err(|_| Error::InvalidCapability)?;
    let response = json::parse(&raw, 16384)?;
    let m = json::keys(
        &response,
        &[
            "version",
            "public_area_hex",
            "attestation_hex",
            "signature_hex",
        ],
        &[],
    )?;
    json::integer(&m["version"], 1, 1)?;
    pending.verify(attestation::Evidence {
        public_area: &unhex(&m["public_area_hex"], 1024)?,
        attestation: &unhex(&m["attestation_hex"], 4096)?,
        signature: &unhex(&m["signature_hex"], 80)?,
    })
}
fn execute(action: &str, root: &Path, request: &Value) -> Outcome<Value> {
    let now = stamp(request)?;
    if action == "init" {
        json::keys(request, &["issuer", "audience"], &["now"])?;
        return IdentityAuthority::initialize(
            root,
            text(request, "issuer")?,
            text(request, "audience")?,
            now,
        )?
        .status();
    }
    let authority = IdentityAuthority::open(root)?;
    match action {
        "status" => {
            json::keys(request, &[], &[])?;
            authority.status()
        }
        "public-client" => {
            json::keys(request, &["subject"], &["now"])?;
            authority.public_client(text(request, "subject")?, now)
        }
        "enroll" | "renew" | "enroll-tpm" | "renew-tpm" => {
            let tpm = action.ends_with("-tpm");
            let mut required = vec!["subject", "csr_file"];
            if tpm {
                required.extend(["ak_public_area_file", "ak_qualified_name_file"]);
            } else {
                required.push("approve_fingerprint");
            }
            json::keys(
                request,
                &required,
                &[
                    "now",
                    "replace",
                    "expected_epoch",
                    "expected_thumbprint",
                    "require_new_key",
                    "allow_assurance_downgrade",
                ],
            )?;
            let csr = ClientRequest::from_pem(&files::read_private(
                Path::new(text(request, "csr_file")?),
                8192,
            )?)?;
            let mut options = EnrollmentOptions::new(now);
            options.replace = flag(request, "replace")?;
            options.renew = action.starts_with("renew");
            options.require_new_key = flag(request, "require_new_key")?;
            options.allow_assurance_downgrade = flag(request, "allow_assurance_downgrade")?;
            options.expected_epoch = request
                .get("expected_epoch")
                .map(|v| json::integer(v, 0, i32::MAX as i64))
                .transpose()?;
            options.expected_thumbprint = request
                .get("expected_thumbprint")
                .map(|v| v.as_str().map(str::to_owned).ok_or(Error::InvalidRequest))
                .transpose()?;
            if options.require_new_key && !options.renew {
                return Err(Error::InvalidRequest);
            }
            if tpm {
                authority.enroll_tpm(text(request, "subject")?, csr, evidence(request)?, options)
            } else {
                authority.enroll_software(
                    text(request, "subject")?,
                    csr,
                    text(request, "approve_fingerprint")?,
                    options,
                )
            }
        }
        "revoke" | "revoke-if-current" | "forget" | "prune" => {
            let fields: &[&str] = match action {
                "revoke" => &["subject"],
                "revoke-if-current" => &["subject", "expected_epoch", "expected_thumbprint"],
                "forget" => &["subject"],
                _ => &[],
            };
            json::keys(request, fields, &["now"])?;
            let mut extra = request.clone();
            extra
                .as_object_mut()
                .ok_or(Error::InvalidRequest)?
                .remove("now");
            if matches!(action, "forget" | "prune") {
                extra["now"] = json!(now);
            }
            authority.mutate_registry(action, extra, now)
        }
        _ => Err(Error::InvalidRequest),
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("garrett-authority ACTION --root ABSOLUTE_PRIVATE_ROOT [--request PRIVATE_JSON]\nActions: init, status, enroll, renew, enroll-tpm, renew-tpm, public-client, revoke, revoke-if-current, forget, prune.\nTPM enrollment emits a fresh challenge, then accepts one bounded evidence frame on stdin.\nExperimental and unaudited; host operations only, no private-key output.");
        return;
    }
    let result = (|| -> Outcome<Value> {
        if (args.len() != 3 && args.len() != 5) || args[1] != "--root" {
            return Err(Error::InvalidRequest);
        }
        let request = if args.len() == 5 {
            if args[3] != "--request" {
                return Err(Error::InvalidRequest);
            }
            json::parse(&files::read_private(Path::new(&args[4]), 16384)?, 16384)?
        } else {
            json!({})
        };
        execute(&args[0], Path::new(&args[2]), &request)
    })();
    match result {
        Ok(value) => {
            if reply(&json!({"version":1,"ok":true,"result":value})).is_err() {
                std::process::exit(1);
            }
        }
        Err(error) => {
            let _ = reply(&json!({"version":1,"ok":false,"error":{"code":error.code()}}));
            std::process::exit(1);
        }
    }
}
