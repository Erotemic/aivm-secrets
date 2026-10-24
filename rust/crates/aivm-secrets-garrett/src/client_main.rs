//! One foreground call using an explicitly configured client identity.
mod client_alias;
mod client_invoke;
use aivm_secrets_garrett::{
    client, client_material, files, identity_bundle, json, tpm, Error, Outcome,
};
use std::{
    io::{Read, Write},
    path::Path,
};
struct Configured {
    client: client::AuthenticatedClientConfig,
    socket: std::path::PathBuf,
    server_name: String,
    bundle: Option<identity_bundle::GuestBundle>,
}
fn configure(path: &Path) -> Outcome<Configured> {
    let config = json::parse(&files::read_private(path, 65536)?, 65536)?;
    let m = json::keys(
        &config,
        &["schema", "socket", "server_name", "key_mode", "server_ca"],
        &[
            "certificate",
            "identity_bundle",
            "private_key",
            "tcti",
            "persistent_handle",
            "authorization_file",
            "public_area_file",
            "work_directory",
        ],
    )?;
    json::integer(&m["schema"], 1, 1)?;
    let field = |key: &str| {
        m.get(key)
            .and_then(|v| v.as_str())
            .ok_or(Error::InvalidCapability)
    };
    if m.contains_key("certificate") == m.contains_key("identity_bundle") {
        return Err(Error::InvalidCapability);
    }
    let bundle = if m.contains_key("identity_bundle") {
        Some(identity_bundle::load(Path::new(field("identity_bundle")?))?)
    } else {
        None
    };
    let certificate = if let Some(bundle) = &bundle {
        bundle.certificate.clone()
    } else {
        files::read_private(Path::new(field("certificate")?), 1048576)?
    };
    let ca = files::read_private(Path::new(field("server_ca")?), 1048576)?;
    let client = match field("key_mode")? {
        "software" => {
            if m.len() != 7 {
                return Err(Error::InvalidCapability);
            }
            let key = zeroize::Zeroizing::new(files::read_private(
                Path::new(field("private_key")?),
                1048576,
            )?);
            client::software_identity(&certificate, &key, &ca)?
        }
        "tpm2" => {
            if m.len() != 11 || m.contains_key("private_key") {
                return Err(Error::InvalidCapability);
            }
            tpm::identity(
                tpm::Configuration {
                    tcti: field("tcti")?.into(),
                    persistent_handle: json::integer(
                        m.get("persistent_handle").ok_or(Error::InvalidCapability)?,
                        0x81000000,
                        0x81ffffff,
                    )? as u32,
                    authorization_file: Path::new(field("authorization_file")?).into(),
                    public_area_file: Path::new(field("public_area_file")?).into(),
                    work_directory: Path::new(field("work_directory")?).into(),
                },
                &certificate,
                &ca,
            )?
        }
        _ => return Err(Error::InvalidCapability),
    };
    Ok(Configured {
        client,
        socket: Path::new(field("socket")?).into(),
        server_name: field("server_name")?.into(),
        bundle,
    })
}
impl Configured {
    fn select_capability(
        &self,
        mut frame: serde_json::Value,
        capability_file: Option<&Path>,
    ) -> Outcome<serde_json::Value> {
        match (&self.bundle, capability_file) {
            (Some(_), None) => (),
            (None, Some(path)) => {
                let bytes = zeroize::Zeroizing::new(files::read_private(path, 32768)?);
                let token = std::str::from_utf8(&bytes)
                    .map_err(|_| Error::InvalidRequest)?
                    .trim_end_matches(['\r', '\n']);
                if token.len() < 20
                    || token
                        .bytes()
                        .any(|b| b.is_ascii_whitespace() || !b.is_ascii_graphic())
                {
                    return Err(Error::InvalidRequest);
                }
                frame.as_object_mut().ok_or(Error::InvalidRequest)?.insert(
                    "capability".into(),
                    serde_json::Value::String(token.to_owned()),
                );
            }
            _ => return Err(Error::InvalidRequest),
        }
        Ok(frame)
    }
    fn exchange(&self, mut frame: serde_json::Value) -> Outcome<serde_json::Value> {
        if let Some(bundle) = &self.bundle {
            // The local bundle interface omits capability. Supplying another
            // one is an error, never a silent override or stale-pair fallback.
            let map = json::keys(
                &frame,
                &["version"],
                &["request", "describe", "delegate", "renounce"],
            )
            .map_err(|_| Error::InvalidRequest)?;
            if map.len() != 2 || map["version"] != 1 {
                return Err(Error::InvalidRequest);
            }
            frame.as_object_mut().ok_or(Error::InvalidRequest)?.insert(
                "capability".into(),
                serde_json::Value::String(bundle.capability.to_string()),
            );
        }
        client::exchange_unix(&self.client, &self.socket, &self.server_name, &frame)
    }
}
fn call(path: &Path) -> Outcome<serde_json::Value> {
    let config = configure(path)?;
    let mut input = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut input)
        .map_err(|_| Error::InvalidRequest)?;
    let frame = json::parse(&input, 65536).map_err(|_| Error::InvalidRequest)?;
    config.exchange(frame)
}
// The capability stays in a guest-owned private file, not in argv or ambient
// environment. The broker still authenticates the certificate and capability.
fn github_action(
    config: &Path,
    capability_file: Option<&Path>,
    words: &[String],
) -> Outcome<Vec<u8>> {
    let command = client_alias::GitHubCommand::parse(words)?;
    let config = configure(config)?;
    let mut frame = command.frame("");
    frame
        .as_object_mut()
        .ok_or(Error::InvalidRequest)?
        .remove("capability");
    let frame = config.select_capability(frame, capability_file)?;
    command.render(&config.exchange(frame)?)
}

fn invoke_action(
    config: &Path,
    capability_file: Option<&Path>,
    words: &[String],
) -> Outcome<serde_json::Value> {
    let command = client_invoke::Invoke::parse(words)?;
    let config = configure(config)?;
    let frame = config.select_capability(command.frame(), capability_file)?;
    let reply = config.exchange(frame)?;
    // Once sent, an unusable reply cannot establish that the operation failed.
    if reply.get("version").and_then(serde_json::Value::as_i64) != Some(1)
        || reply
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .is_none()
    {
        return Err(Error::OutcomeUnknown);
    }
    Ok(reply)
}
fn encoded_reply(reply: &serde_json::Value) -> Vec<u8> {
    let mut bytes = json::canonical(reply);
    bytes.push(b'\n');
    bytes
}

fn local_action(action: &str, args: &[String]) -> Outcome<serde_json::Value> {
    let mut options = std::collections::BTreeMap::new();
    if !args.len().is_multiple_of(2) {
        return Err(Error::InvalidRequest);
    }
    for pair in args.as_chunks::<2>().0 {
        if options.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(Error::InvalidRequest);
        }
    }
    if action == "install-bundle" {
        if options.keys().any(|key| {
            !matches!(
                *key,
                "--certificate" | "--jwt-file" | "--output" | "--expected-current"
            )
        }) {
            return Err(Error::InvalidRequest);
        }
        let field = |name| {
            options
                .get(name)
                .map(|value| Path::new(*value))
                .ok_or(Error::InvalidRequest)
        };
        return identity_bundle::install(
            field("--certificate")?,
            field("--jwt-file")?,
            field("--output")?,
            options.get("--expected-current").copied(),
        );
    }
    let csr = options.get("--csr").ok_or(Error::InvalidRequest)?;
    if action == "inspect-csr" && options.len() == 1 {
        return client_material::inspect_csr(Path::new(csr));
    }
    if action == "request" && options.len() == 3 && options.get("--key-mode") == Some(&"tpm2") {
        let config = options.get("--tpm-config").ok_or(Error::InvalidRequest)?;
        return client_material::request_tpm(Path::new(config), Path::new(csr));
    }
    if options.len() != 3 || options.get("--key-mode") != Some(&"software") {
        return Err(Error::InvalidRequest);
    }
    let key = options.get("--key").ok_or(Error::InvalidRequest)?;
    match action {
        "request" => client_material::request(Path::new(key), Path::new(csr)),
        "csr-from-key" => client_material::csr_from_key(Path::new(key), Path::new(csr)),
        _ => Err(Error::InvalidRequest),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("garrett-client --config ABSOLUTE_PRIVATE_JSON\nRead one version-1 broker frame from stdin; return the public reply.\n\ngarrett-client --config ABSOLUTE_PRIVATE_JSON --capability-file PRIVATE_TOKEN_FILE gh pr view 13861 --repo TauCetiProject/TauCeti --json number,title,headRefOid\nThe gh aliases translate only explicit pr view/diff/checks reads. No gh fallback or remote discovery.\ngarrett-client --config ABSOLUTE_PRIVATE_JSON [--capability-file PRIVATE_TOKEN_FILE] invoke OPERATION [--arguments JSON | --arguments-file FILE_OR_MINUS] [--idempotency-key RETRY_NAME]\nInvoke returns the full public broker reply; exit 0 on ok, 1 on denial or failure. Write permission and retry reservation are checked by the broker.\nSelect key_mode software or tpm2 explicitly; no automatic fallback. TPM provenance must be enrolled separately.\n\ngarrett-client request --key-mode software --key ABSOLUTE_NEW_KEY --csr ABSOLUTE_NEW_CSR\ngarrett-client request --key-mode tpm2 --tpm-config ABSOLUTE_PRIVATE_JSON --csr ABSOLUTE_NEW_CSR\ngarrett-client csr-from-key --key-mode software --key ABSOLUTE_EXISTING_KEY --csr ABSOLUTE_NEW_CSR\ngarrett-client inspect-csr --csr ABSOLUTE_CSR\ngarrett-client install-bundle --certificate PRIVATE_PEM --jwt-file PRIVATE_JWT --output ABSOLUTE_BUNDLE [--expected-current HEX_SHA256]\nA config may select identity_bundle instead of certificate. Then stdin omits capability and gh needs no --capability-file. The separately configured key is unchanged.\nSoftware request generation creates an exportable key and provides no VM attestation. Existing files are never replaced. If publication is uncertain, retain the key and inspect/recover its CSR.");
        return;
    }
    let result: Outcome<(Vec<u8>, bool)> =
        if args.len() >= 4 && args[0] == "--config" && args[2] == "invoke" {
            invoke_action(Path::new(&args[1]), None, &args[3..]).map(|reply| {
                let success = reply.get("ok") == Some(&serde_json::Value::Bool(true));
                (encoded_reply(&reply), success)
            })
        } else if args.len() >= 6
            && args[0] == "--config"
            && args[2] == "--capability-file"
            && args[4] == "invoke"
        {
            invoke_action(Path::new(&args[1]), Some(Path::new(&args[3])), &args[5..]).map(|reply| {
                let success = reply.get("ok") == Some(&serde_json::Value::Bool(true));
                (encoded_reply(&reply), success)
            })
        } else if args.len() == 2 && args[0] == "--config" {
            call(Path::new(&args[1])).map(|reply| {
                let mut output = json::canonical(&reply);
                output.push(b'\n');
                (output, true)
            })
        } else if args.len() >= 8
            && args[0] == "--config"
            && args[2] == "--capability-file"
            && args[4] == "gh"
        {
            github_action(Path::new(&args[1]), Some(Path::new(&args[3])), &args[4..])
                .map(|bytes| (bytes, true))
        } else if args.len() >= 6 && args[0] == "--config" && args[2] == "gh" {
            github_action(Path::new(&args[1]), None, &args[2..]).map(|bytes| (bytes, true))
        } else if let Some(action) = args.first().filter(|s| {
            matches!(
                s.as_str(),
                "request" | "csr-from-key" | "inspect-csr" | "install-bundle"
            )
        }) {
            local_action(action, &args[1..]).map(|reply| {
                let mut output = json::canonical(&reply);
                output.push(b'\n');
                (output, true)
            })
        } else {
            Err(Error::InvalidRequest)
        };
    match result {
        Ok((output_bytes, success)) => {
            let mut output = std::io::stdout().lock();
            if output.write_all(&output_bytes).is_err() {
                std::process::exit(1);
            }
            if !success {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{}", error.name());
            std::process::exit(1);
        }
    }
}
