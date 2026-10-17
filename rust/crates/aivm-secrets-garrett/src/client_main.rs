//! One foreground call using an explicitly configured client identity.
use aivm_secrets_garrett::{client, client_material, files, json, tpm, Error, Outcome};
use std::{
    io::{Read, Write},
    path::Path,
};
fn call(path: &Path) -> Outcome<serde_json::Value> {
    let config = json::parse(&files::read_private(path, 65536)?, 65536)?;
    let m = json::keys(
        &config,
        &[
            "schema",
            "socket",
            "server_name",
            "certificate",
            "key_mode",
            "server_ca",
        ],
        &[
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
    let certificate = files::read_private(Path::new(field("certificate")?), 1048576)?;
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
    let mut input = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut input)
        .map_err(|_| Error::InvalidRequest)?;
    let frame = json::parse(&input, 65536).map_err(|_| Error::InvalidRequest)?;
    client::exchange_unix(
        &client,
        Path::new(field("socket")?),
        field("server_name")?,
        &frame,
    )
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
        println!("garrett-client --config ABSOLUTE_PRIVATE_JSON\nRead one version-1 broker frame from stdin; return the public reply.\nSelect key_mode software or tpm2 explicitly; no automatic fallback. TPM provenance must be enrolled separately.\n\ngarrett-client request --key-mode software --key ABSOLUTE_NEW_KEY --csr ABSOLUTE_NEW_CSR\ngarrett-client request --key-mode tpm2 --tpm-config ABSOLUTE_PRIVATE_JSON --csr ABSOLUTE_NEW_CSR\ngarrett-client csr-from-key --key-mode software --key ABSOLUTE_EXISTING_KEY --csr ABSOLUTE_NEW_CSR\ngarrett-client inspect-csr --csr ABSOLUTE_CSR\nSoftware request generation creates an exportable key and provides no VM attestation. Existing files are never replaced. If publication is uncertain, retain the key and inspect/recover its CSR.");
        return;
    }
    let result = if args.len() == 2 && args[0] == "--config" {
        call(Path::new(&args[1]))
    } else if let Some(action) = args
        .first()
        .filter(|s| matches!(s.as_str(), "request" | "csr-from-key" | "inspect-csr"))
    {
        local_action(action, &args[1..])
    } else {
        Err(Error::InvalidRequest)
    };
    match result {
        Ok(reply) => {
            let mut output = std::io::stdout().lock();
            if output
                .write_all(&json::canonical(&reply))
                .and_then(|_| output.write_all(b"\n"))
                .is_err()
            {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{}", error.code());
            std::process::exit(1);
        }
    }
}
