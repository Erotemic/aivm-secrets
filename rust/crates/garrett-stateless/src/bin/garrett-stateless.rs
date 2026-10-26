//! `garrett-stateless`: keys, development PKI, broker, proxy, operator
//! minting, token inspection and the agent client. The Python package's
//! `garrett-stateless` command has the same interface.
use garrett_stateless::agent::{Agent, Endpoint};
use garrett_stateless::broker::{self, Broker};
use garrett_stateless::config::BrokerConfig;
use garrett_stateless::error::{Error, Result};
use garrett_stateless::files::{read_private, read_public, replace_private, write_private};
use garrett_stateless::json::{self, Value};
use garrett_stateless::keys::BrokerKeys;
use garrett_stateless::pki;
use garrett_stateless::proxy::Proxy;
use garrett_stateless::tls::{self, ClientIdentity};
use garrett_stateless::token;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage: garrett-stateless <command> ...
  keys init --issuer ISSUER [--kid KID] --out FILE
  keys rotate --keys FILE --kid KID
  keys retire --keys FILE --kid KID
  keys export --keys FILE --out FILE
  pki ca --name NAME --cert FILE --key FILE [--days N]
  pki server --ca-cert FILE --ca-key FILE --name DNS [--name DNS]... --cert FILE --key FILE [--days N]
  pki client --ca-cert FILE --ca-key FILE --name CN [--uri URI] --cert FILE --key FILE [--days N]
  broker --config FILE [--until-stdin-eof]
  proxy --config FILE [--until-stdin-eof]
  mint --config BROKER --provider NAME --credential-file FILE --certificate PEM [--lifetime N] [--out FILE]
  inspect (--token-file FILE | TOKEN)
  agent login --broker URL [--connect ADDR] --ca FILE --cert FILE (--key FILE|--tpm FILE) --provider NAME [--scope S] [--timeout N] [--out FILE]
  agent renew --broker URL [--connect ADDR] --ca FILE --cert FILE (--key FILE|--tpm FILE) --token-file FILE [--out FILE]
  agent request --proxy URL [--connect ADDR] --ca FILE --cert FILE (--key FILE|--tpm FILE) --token-file FILE
                [-X METHOD] [-H 'Name: value']... [--data TEXT | --data-file FILE] TARGET";

struct Args {
    positional: Vec<String>,
    options: Vec<(String, String)>,
    flags: Vec<String>,
}

const FLAGS: [&str; 1] = ["--until-stdin-eof"];

impl Args {
    fn parse(raw: &[String]) -> Result<Self> {
        let mut args = Args {
            positional: Vec::new(),
            options: Vec::new(),
            flags: Vec::new(),
        };
        let mut iter = raw.iter();
        while let Some(arg) = iter.next() {
            if FLAGS.contains(&arg.as_str()) {
                args.flags.push(arg.clone());
            } else if arg.starts_with('-') && arg.len() > 1 {
                let value = iter
                    .next()
                    .ok_or_else(|| usage(&format!("{arg} needs a value")))?;
                args.options.push((arg.clone(), value.clone()));
            } else {
                args.positional.push(arg.clone());
            }
        }
        Ok(args)
    }
    fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn all(&self, name: &str) -> Vec<&str> {
        self.options
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn need(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| usage(&format!("{name} is required")))
    }
    fn path(&self, name: &str) -> Result<PathBuf> {
        Ok(PathBuf::from(self.need(name)?))
    }
    fn number(&self, name: &str, default: i64) -> Result<i64> {
        match self.get(name) {
            Some(text) => text
                .parse()
                .map_err(|_| usage(&format!("{name} must be an integer"))),
            None => Ok(default),
        }
    }
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
}

fn usage(message: &str) -> Error {
    Error::Config(format!("{message}\n{USAGE}"))
}

fn line(value: Value) {
    let mut out = json::canonical(&value).unwrap_or_default();
    out.push(b'\n');
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(&out);
    let _ = stdout.flush();
}

fn keys(args: &Args) -> Result<()> {
    match args.positional.get(1).map(String::as_str) {
        Some("init") => {
            let keys =
                BrokerKeys::generate(args.need("--issuer")?, args.get("--kid").unwrap_or("k1"))?;
            write_private(&args.path("--out")?, &keys.to_json())?;
            line(json::object([("active", json::text(&keys.active))]));
        }
        Some(action @ ("rotate" | "retire")) => {
            let path = args.path("--keys")?;
            let mut keys = BrokerKeys::load(&path)?;
            let kid = args.need("--kid")?;
            if action == "rotate" {
                let issuer = keys.active_entry().issuer.clone();
                keys.rotate(&issuer, kid)?;
            } else {
                keys.retire(kid)?;
            }
            replace_private(&path, &keys.to_json())?;
            let kids = keys.entries.iter().map(|e| json::text(&e.kid)).collect();
            line(json::object([
                ("active", json::text(&keys.active)),
                ("kids", Value::Array(kids)),
            ]));
        }
        Some("export") => {
            let keys = BrokerKeys::load(&args.path("--keys")?)?;
            // Re-exporting after a rotation replaces the previous proxy key set atomically.
            replace_private(&args.path("--out")?, &keys.export_proxy().to_json())?;
            let kids = keys.entries.iter().map(|e| json::text(&e.kid)).collect();
            line(json::object([("kids", Value::Array(kids))]));
        }
        _ => return Err(usage("unknown keys action")),
    }
    Ok(())
}

fn write_pair(args: &Args, issued: &pki::Issued) -> Result<()> {
    std::fs::write(args.path("--cert")?, issued.certificate.as_bytes())?;
    write_private(&args.path("--key")?, issued.key.as_bytes())
}

fn pki_command(args: &Args) -> Result<()> {
    let days = args.number("--days", 30)?;
    let issued = match args.positional.get(1).map(String::as_str) {
        Some("ca") => pki::create_ca(args.need("--name")?, days)?,
        Some(kind @ ("server" | "client")) => {
            let ca_cert = String::from_utf8_lossy(&read_public(&args.path("--ca-cert")?, 1 << 20)?)
                .into_owned();
            let ca_key = String::from_utf8_lossy(&read_private(&args.path("--ca-key")?, 1 << 20)?)
                .into_owned();
            let names: Vec<String> = args.all("--name").into_iter().map(str::to_owned).collect();
            let leaf = if kind == "server" {
                pki::Leaf::Server(&names)
            } else {
                pki::Leaf::Client {
                    name: args.need("--name")?,
                    uri: args.get("--uri"),
                }
            };
            pki::issue(&ca_cert, &ca_key, leaf, days)?
        }
        _ => return Err(usage("unknown pki action")),
    };
    write_pair(args, &issued)
}

/// Block until stdin closes (when asked) or forever.
fn hold(args: &Args) {
    if args.flag("--until-stdin-eof") {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
    } else {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

fn agent(args: &Args) -> Result<Agent> {
    let ca = read_public(&args.path("--ca")?, 1 << 20)?;
    let certificate = read_public(&args.path("--cert")?, 1 << 20)?;
    let identity = match (args.get("--key"), args.get("--tpm")) {
        (Some(key), None) => ClientIdentity::Software {
            certificate,
            key: read_private(Path::new(key), 1 << 20)?,
        },
        (None, Some(config)) => tpm_identity(Path::new(config), &certificate)?,
        _ => return Err(usage("exactly one of --key and --tpm is required")),
    };
    Agent::new(&ca, identity)
}

/// `--tpm CONFIG`: `{"tcti", "persistent_handle", "authorization_file",
/// "public_area_file", "work_directory"}`; the key never leaves the TPM.
#[cfg(feature = "tpm")]
fn tpm_identity(config: &Path, certificate: &[u8]) -> Result<ClientIdentity> {
    let value = json::parse(&read_private(config, 65536)?, 65536, 4)
        .map_err(|_| usage("--tpm: not strict JSON"))?;
    let text = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| usage(&format!("--tpm: {name}")))
    };
    let handle = value
        .get("persistent_handle")
        .and_then(Value::as_int)
        .and_then(|h| u32::try_from(h).ok())
        .ok_or_else(|| usage("--tpm: persistent_handle"))?;
    let configuration = aivm_secrets_garrett::tpm::Configuration {
        tcti: text("tcti")?,
        persistent_handle: handle,
        authorization_file: PathBuf::from(text("authorization_file")?),
        public_area_file: PathBuf::from(text("public_area_file")?),
        work_directory: PathBuf::from(text("work_directory")?),
    };
    ClientIdentity::tpm(configuration, certificate)
}

#[cfg(not(feature = "tpm"))]
fn tpm_identity(_config: &Path, _certificate: &[u8]) -> Result<ClientIdentity> {
    Err(usage(
        "--tpm needs a build with the tpm feature (cargo build --features tpm)",
    ))
}

fn token_file(args: &Args) -> Result<String> {
    let bytes = read_private(&args.path("--token-file")?, 32768)?;
    Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
}

fn deliver(args: &Args, issued: &broker::IssuedToken) -> Result<()> {
    match args.get("--out") {
        Some(path) => {
            write_private(Path::new(path), issued.token.as_bytes())?;
            line(json::object([
                ("expires_at", Value::Int(issued.expires_at)),
                ("renew_until", Value::Int(issued.renew_until)),
                ("token_file", json::text(path)),
            ]));
        }
        None => line(json::object([
            ("expires_at", Value::Int(issued.expires_at)),
            ("renew_until", Value::Int(issued.renew_until)),
            ("token", json::text(&issued.token)),
        ])),
    }
    Ok(())
}

fn agent_command(args: &Args) -> Result<()> {
    match args.positional.get(1).map(String::as_str) {
        Some("login") => {
            let client = agent(args)?;
            let endpoint = Endpoint::parse(args.need("--broker")?, args.get("--connect"))?;
            let started =
                client.begin_login(&endpoint, args.need("--provider")?, args.get("--scope"))?;
            line(json::object([
                ("authorization_url", json::text(&started.authorization_url)),
                ("confirmation", json::text(&started.confirmation)),
                ("expires_at", Value::Int(started.expires_at)),
                ("login", json::text(&started.login)),
            ]));
            let timeout = Duration::from_secs(args.number("--timeout", 600)?.max(0) as u64);
            let issued = client.wait_for_token(&endpoint, &started.login, timeout)?;
            deliver(args, &issued)
        }
        Some("renew") => {
            let client = agent(args)?;
            let endpoint = Endpoint::parse(args.need("--broker")?, args.get("--connect"))?;
            let issued = client.renew(&endpoint, &token_file(args)?)?;
            deliver(args, &issued)
        }
        Some("request") => {
            let client = agent(args)?;
            let endpoint = Endpoint::parse(args.need("--proxy")?, args.get("--connect"))?;
            let target = args
                .positional
                .get(2)
                .ok_or_else(|| usage("TARGET is required"))?;
            let body = match (args.get("--data"), args.get("--data-file")) {
                (Some(text), None) => text.as_bytes().to_vec(),
                (None, Some(path)) => read_public(Path::new(path), 16 << 20)?,
                (None, None) => Vec::new(),
                _ => return Err(usage("--data and --data-file are exclusive")),
            };
            let headers: Vec<(String, String)> = args
                .all("-H")
                .into_iter()
                .map(|h| {
                    h.split_once(':')
                        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
                        .ok_or_else(|| usage("bad -H"))
                })
                .collect::<Result<_>>()?;
            let borrowed: Vec<(&str, &str)> = headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            let method = args
                .get("-X")
                .unwrap_or(if body.is_empty() { "GET" } else { "POST" });
            let response = client.request(
                &endpoint,
                &token_file(args)?,
                method,
                target,
                &borrowed,
                &body,
            )?;
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "{{\"status\":{}}}", response.status);
            std::io::stdout().write_all(&response.body)?;
            if response.status >= 400 {
                std::process::exit(22);
            }
            Ok(())
        }
        _ => Err(usage("unknown agent action")),
    }
}

fn run(raw: &[String]) -> Result<()> {
    let args = Args::parse(raw)?;
    match args.positional.first().map(String::as_str) {
        Some("keys") => keys(&args),
        Some("pki") => pki_command(&args),
        Some("broker") => {
            let broker = Arc::new(Broker::from_file(&args.path("--config")?)?);
            let running = broker.serve()?;
            line(json::object([
                ("agent", json::text(&running.agent_address.to_string())),
                ("browser", json::text(&running.browser_address.to_string())),
                ("profile", json::text(garrett_stateless::PROFILE)),
                ("role", json::text("broker")),
            ]));
            hold(&args);
            running.stop();
            Ok(())
        }
        Some("proxy") => {
            let proxy = Arc::new(Proxy::from_file(&args.path("--config")?)?);
            let running = proxy.serve()?;
            line(json::object([
                ("address", json::text(&running.address.to_string())),
                ("profile", json::text(garrett_stateless::PROFILE)),
                ("role", json::text("proxy")),
            ]));
            hold(&args);
            running.stop();
            Ok(())
        }
        Some("mint") => {
            let config = BrokerConfig::load(&args.path("--config")?)?;
            let keys = BrokerKeys::load(&config.keys)?;
            let provider = args.need("--provider")?;
            let broker = Broker::new(config.clone(), keys, Box::new(broker::HttpsTokenEndpoint))?;
            let credential =
                zeroize::Zeroizing::new(read_private(&args.path("--credential-file")?, 8192)?);
            let text = std::str::from_utf8(&credential)
                .map_err(|_| Error::Rejected("invalid_credential"))?
                .trim();
            let pem = read_public(&args.path("--certificate")?, 1 << 20)?;
            let der = tls::certificates(&pem)?.remove(0);
            let lifetime = args
                .get("--lifetime")
                .map(|v| v.parse::<i64>())
                .transpose()
                .map_err(|_| usage("--lifetime"))?;
            let issued = broker.mint(provider, text.as_bytes(), der.as_ref(), lifetime)?;
            deliver(&args, &issued)
        }
        Some("inspect") => {
            let token = match args.get("--token-file") {
                Some(_) => token_file(&args)?,
                None => args
                    .positional
                    .get(1)
                    .cloned()
                    .ok_or_else(|| usage("TOKEN is required"))?,
            };
            let (header, payload) =
                token::inspect(&token).map_err(|_| Error::Rejected("malformed"))?;
            line(json::object([
                ("header", header),
                ("payload", payload),
                ("verified", Value::Bool(false)),
            ]));
            Ok(())
        }
        Some("agent") => agent_command(&args),
        _ => Err(usage("unknown command")),
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&raw) {
        let code = match &error {
            Error::Config(_) => 2,
            _ => 1,
        };
        let _ = writeln!(std::io::stderr(), "garrett-stateless: {error}");
        std::process::exit(code);
    }
}
