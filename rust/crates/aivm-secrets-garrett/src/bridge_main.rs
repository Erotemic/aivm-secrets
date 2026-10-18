//! Foreground Rust mTLS bridge; host configuration is a private local file.
use aivm_secrets_garrett::{
    crypto::{Issuer, Verifier},
    files, json,
    model::Registry,
    tls, Error, Outcome,
};
use serde_json::Value;
use std::{
    fs,
    io::{self, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

fn field<'a>(m: &'a serde_json::Map<String, Value>, key: &str) -> Outcome<&'a str> {
    m.get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidCapability)
}
fn unhex(s: &str) -> Outcome<Vec<u8>> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidCapability);
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| {
            u8::from_str_radix(
                std::str::from_utf8(v).map_err(|_| Error::InvalidCapability)?,
                16,
            )
            .map_err(|_| Error::InvalidCapability)
        })
        .collect()
}
struct ListenerPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for ListenerPath {
    fn drop(&mut self) {
        if let Ok(info) = fs::symlink_metadata(&self.path) {
            if info.dev() == self.device && info.ino() == self.inode {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}
fn legacy_bridge(config: &Value) -> Outcome<(tls::Bridge, Value)> {
    let m = json::keys(
        config,
        &[
            "schema",
            "issuer",
            "audience",
            "listen",
            "registry_path",
            "server_certificate",
            "server_key",
            "client_ca",
            "encryption_key_file",
            "kid",
        ],
        &[
            "subject",
            "broker_socket",
            "public_key_hex",
            "provider",
            "signing_key_file",
            "binding",
            "lifetime",
        ],
    )?;
    json::integer(&m["schema"], 1, 1)?;
    let issuer = field(m, "issuer")?;
    let audience = field(m, "audience")?;
    let registry = Registry::parse(
        &json::parse(
            &files::read_private(Path::new(field(m, "registry_path")?), 1048576)?,
            1048576,
        )?,
        issuer,
        audience,
    )?;
    let key = zeroize::Zeroizing::new(files::read_private(
        Path::new(field(m, "encryption_key_file")?),
        32,
    )?);

    let private = zeroize::Zeroizing::new(files::read_private(
        Path::new(field(m, "server_key")?),
        1048576,
    )?);
    let tls = tls::server_config(
        &files::read_private(Path::new(field(m, "server_certificate")?), 1048576)?,
        &private,
        &files::read_private(Path::new(field(m, "client_ca")?), 1048576)?,
    )?;
    let subject = m
        .get("subject")
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidCapability)
        })
        .transpose()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InternalError)?
        .as_secs() as i64;
    let mut announcement = serde_json::json!({"version":1,"ready":true});
    let bridge = if let Some(provider_config) = m.get("provider") {
        if m.contains_key("broker_socket") || m.contains_key("public_key_hex") {
            return Err(Error::InvalidCapability);
        }
        let seed = zeroize::Zeroizing::new(files::read_private(
            Path::new(field(m, "signing_key_file")?),
            32,
        )?);
        let signer = Issuer::new(&seed, &key, field(m, "kid")?)?;
        let verifier = Verifier::new(signer.public_key(), &key, field(m, "kid")?)?;
        let lifetime = json::integer(m.get("lifetime").ok_or(Error::InvalidCapability)?, 1, 3600)?;
        let provider = aivm_secrets_garrett::ProviderSession::start(
            provider_config,
            m.get("binding").ok_or(Error::InvalidCapability)?,
            now,
            lifetime,
        )?;
        let issued = provider.issue(
            &signer,
            &registry,
            issuer,
            audience,
            field(m, "subject")?,
            now,
            lifetime,
        )?;
        announcement = serde_json::json!({"version":1,"ready":true,"profile":provider.profile(),"capability":std::str::from_utf8(&issued.token).map_err(|_|Error::InternalError)?,"expires_at":issued.claims.expires_at});
        tls::Bridge::new_provider(
            tls,
            verifier,
            registry,
            issuer.to_owned(),
            audience.to_owned(),
            subject,
            provider,
        )?
    } else {
        if ["signing_key_file", "binding", "lifetime"]
            .iter()
            .any(|k| m.contains_key(*k))
        {
            return Err(Error::InvalidCapability);
        }
        let verifier = Verifier::new(&unhex(field(m, "public_key_hex")?)?, &key, field(m, "kid")?)?;
        tls::Bridge::new(
            tls,
            verifier,
            registry,
            issuer.to_owned(),
            audience.to_owned(),
            subject,
            PathBuf::from(field(m, "broker_socket")?),
        )?
    };
    let bridge = bridge.with_registry_file(PathBuf::from(field(m, "registry_path")?))?;
    Ok((bridge, announcement))
}
fn serve(path: &Path, maximum: Option<usize>) -> Outcome<()> {
    let bytes = zeroize::Zeroizing::new(files::read_private(path, 65536)?);
    let config = json::parse(&bytes, 65536)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InternalError)?
        .as_secs() as i64;
    let (bridge, announcement) = if config.get("authority_root").is_some() {
        aivm_secrets_garrett::authority::bridge_from_config(&config, now)?
    } else {
        legacy_bridge(&config)?
    };
    let bridge = Arc::new(bridge);
    let listen = PathBuf::from(config["listen"].as_str().ok_or(Error::InvalidCapability)?);
    files::private_directory(listen.parent().ok_or(Error::UnsafeFile)?)?;
    let control = bridge.host_control()?;
    if let Some(control) = &control {
        if control.path() == listen {
            return Err(Error::InvalidPolicy);
        }
    }
    let _control = control.map(|c| c.listen()).transpose()?;
    let listener = UnixListener::bind(&listen).map_err(|_| Error::UnsafeFile)?;
    let info = fs::symlink_metadata(&listen).map_err(|_| Error::UnsafeFile)?;
    let _cleanup = ListenerPath {
        path: listen.clone(),
        device: info.dev(),
        inode: info.ino(),
    };
    fs::set_permissions(&listen, fs::Permissions::from_mode(0o600))
        .map_err(|_| Error::UnsafeFile)?;
    let (sender, receiver) = mpsc::sync_channel(16);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let receiver = receiver.clone();
        let bridge = bridge.clone();
        workers.push(std::thread::spawn(move || loop {
            let socket = match receiver.lock() {
                Ok(r) => r.recv(),
                Err(_) => return,
            };
            let Ok(socket) = socket else { return };
            let _ = bridge.serve_unix(socket, || {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|t| t.as_secs() as i64)
                    .unwrap_or(-1)
            });
        }));
    }
    io::stdout()
        .write_all(&json::canonical(&announcement))
        .and_then(|_| io::stdout().write_all(b"\n"))
        .map_err(|_| Error::InternalError)?;
    io::stdout().flush().map_err(|_| Error::InternalError)?;
    for (count, accepted) in listener.incoming().enumerate() {
        let socket = accepted.map_err(|_| Error::InternalError)?;
        sender.send(socket).map_err(|_| Error::InternalError)?;
        if maximum.is_some_and(|n| count + 1 >= n) {
            break;
        }
    }
    drop(sender);
    for worker in workers {
        worker.join().map_err(|_| Error::InternalError)?;
    }
    Ok(())
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] {
        println!("garrett-bridge --config ABSOLUTE_PRIVATE_JSON [--max-connections N]\nExperimental Rust certificate-bound bridge or explicit account-status-v1 provider session.\nRuns in the foreground; requires TLS 1.3 client authentication.");
        return;
    }
    let result = (|| {
        if args.len() != 2 && args.len() != 4 {
            return Err(Error::InvalidRequest);
        }
        if args[0] != "--config" {
            return Err(Error::InvalidRequest);
        }
        let maximum = if args.len() == 4 {
            if args[2] != "--max-connections" {
                return Err(Error::InvalidRequest);
            }
            let n = args[3]
                .parse::<usize>()
                .map_err(|_| Error::InvalidRequest)?;
            if n == 0 {
                return Err(Error::InvalidRequest);
            }
            Some(n)
        } else {
            None
        };
        serve(Path::new(&args[1]), maximum)
    })();
    if let Err(error) = result {
        eprintln!("{}", error.code());
        std::process::exit(1);
    }
}
