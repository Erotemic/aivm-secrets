//! `garrett-proxy`: the native credential-substitution HTTPS proxy (HP-4).
//!
//! A thin I/O shell around the Aeneas-extracted `proxy_http` core. Every
//! request is parsed by `parse_request` and handed to the extracted
//! controller `proxy_controller::serve`, which checks the session, encodes
//! upstream with `encode_upstream` (proved: the credential appears only as
//! one verified authentication line, no guest CR/LF), passes exactly those
//! bytes to [`Origin`]'s exchange, and releases the answer with
//! `guest_response` (proved: released bytes never contain the raw
//! credential) or a fixed refusal. This file only moves bytes: sockets,
//! TLS, the session CA, the audit and the process contract, which matches
//! `aivm-secrets proxy` (one announcement line; stdin EOF ends the session).
//! The profile makes no authority-confinement claim (PROXY-AUTHORITY-01).
//!
//! With `"profile": "constrained-http"`, `--routes` and `--bridge-client`
//! instead of a credential, the same binary is the **guest-side**
//! constrained translator (HP-6): it holds no credential, accepts a request
//! only if it is exactly one named operation of the route copy
//! (`manifest::Policy::translate`, over the proved `route_match::translate`)
//! and sends that operation through the guest's native `invoke`; the host
//! bridge authorizes it on its own policy.
use aivm_secrets_garrett::files;
use aivm_secrets_garrett_core::credential_use::Authentication;
use aivm_secrets_garrett_core::proxy_connect::{self as connect, Admission};
use aivm_secrets_garrett_core::proxy_controller::{self as controller, Stage, Upstream};
use aivm_secrets_garrett_core::proxy_http as core;
use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const TOTAL_DEADLINE: Duration = Duration::from_secs(45);
const MAX_POLICY: usize = 65536;
const MAX_CA: usize = 1 << 20;
const MAX_ROUTES: usize = 262144;
/// The bridge client's own argument limit, its reply bound and deadline.
const MAX_INVOKE_ARGUMENTS: usize = 16384;
const MAX_INVOKE_REPLY: usize = 4 << 20;
const INVOKE_DEADLINE: Duration = Duration::from_secs(60);
/// Concurrent guest connections; extra connections are closed at once.
const MAX_CONNECTIONS: usize = 32;
/// Whole-head and whole-request deadlines, so a slow guest cannot hold a
/// thread indefinitely.
const HEAD_DEADLINE: Duration = Duration::from_secs(30);
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

struct Origin {
    host: String,
    address: String,
    port: u16,
    authentication: Authentication,
    /// `None` in the constrained profile, which never connects upstream.
    upstream: Option<Arc<ClientConfig>>,
    guest: Arc<ServerConfig>,
}

/// The guest-side constrained translator's route copy and bridge client.
struct Translator {
    routes: aivm_secrets_garrett::manifest::Policy,
    client: Vec<String>,
}

struct Session {
    origins: BTreeMap<String, Origin>,
    /// `Some` exactly in the constrained-http profile (no credential).
    translator: Option<Translator>,
    rules: Vec<core::DenyRule>,
    request_limit: usize,
    response_limit: usize,
    secret: Vec<u8>,
    forms: Vec<core::Form>,
    token: Vec<u8>,
    expires: Instant,
    revoked: AtomicBool,
    audit: Mutex<Audit>,
    connections: AtomicUsize,
}

/// Hash-chained JSONL like the Python reference: `seq` and the SHA-256 of
/// the previous line, so truncation or edits are detectable.
struct Audit {
    file: std::fs::File,
    seq: u64,
    head: String,
}

fn fail(code: &str) -> String {
    code.to_owned()
}

fn exact_keys(value: &Value, required: &[&str], optional: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or_else(|| fail("invalid_policy"))?;
    for key in required {
        if !object.contains_key(*key) {
            return Err(fail("invalid_policy"));
        }
    }
    if object.keys().any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str())) {
        return Err(fail("invalid_policy"));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key].as_str().ok_or_else(|| fail("invalid_policy"))
}

fn number(value: &Value, key: &str, low: u64, high: u64) -> Result<u64, String> {
    match value[key].as_u64() {
        Some(n) if (low..=high).contains(&n) => Ok(n),
        _ => Err(fail("invalid_policy")),
    }
}

fn valid_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// The session CA (key held in memory only), name-constrained to the origins.
fn session_ca(hosts: &[String], lifetime: u64) -> Result<(String, Issuer<'static, KeyPair>), String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| fail("proxy_failed"))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "aivm-secrets proxy session CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts.iter().map(|h| GeneralSubtree::DnsName(h.clone())).collect(),
        excluded_subtrees: Vec::new(),
    });
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::seconds(lifetime as i64 + 60);
    let certificate = params.self_signed(&key).map_err(|_| fail("proxy_failed"))?;
    Ok((certificate.pem(), Issuer::new(params, key)))
}

fn leaf_config(host: &str, issuer: &Issuer<'static, KeyPair>, lifetime: u64) -> Result<Arc<ServerConfig>, String> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| fail("proxy_failed"))?;
    let mut params =
        CertificateParams::new(vec![host.to_owned()]).map_err(|_| fail("proxy_failed"))?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, host);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::seconds(lifetime as i64 + 60);
    let certificate = params.signed_by(&key, issuer).map_err(|_| fail("proxy_failed"))?;
    let chain = vec![CertificateDer::from(certificate.der().to_vec())];
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| fail("proxy_failed"))?
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .map_err(|_| fail("proxy_failed"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn upstream_config(ca_file: &Path) -> Result<Arc<ClientConfig>, String> {
    // A trust anchor may be public but must be held by root or this user.
    let pem = files::read_trusted_public(ca_file, MAX_CA).map_err(|_| fail("invalid_policy"))?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &*pem) {
        roots.add(cert.map_err(|_| fail("invalid_policy"))?).map_err(|_| fail("invalid_policy"))?;
    }
    if roots.is_empty() {
        return Err(fail("invalid_policy"));
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| fail("invalid_policy"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// Where the session's authority comes from: exactly one, never a fallback.
enum Authority<'a> {
    /// credential-substitution: the credential file.
    Credential(&'a Path),
    /// constrained-http, guest side: a route copy and the bridge client argv.
    Bridge(&'a Path, Vec<String>),
}

fn load(policy_path: &Path, authority: Authority<'_>, audit_path: &Path) -> Result<(Session, String), String> {
    let raw = files::read_private(policy_path, MAX_POLICY).map_err(|_| fail("invalid_policy"))?;
    let policy: Value = serde_json::from_slice(&raw).map_err(|_| fail("invalid_policy"))?;
    exact_keys(&policy, &["schema", "profile", "origins", "lifetime_seconds"], &["deny", "limits"])?;
    let constrained = match (policy["profile"].as_str(), &authority) {
        (Some("credential-substitution"), Authority::Credential(_)) => false,
        (Some("constrained-http"), Authority::Bridge(..)) => true,
        _ => return Err(fail("invalid_policy")),
    };
    if policy["schema"].as_u64() != Some(1) || (constrained && policy.get("deny").is_some()) {
        return Err(fail("invalid_policy"));
    }
    let lifetime = number(&policy, "lifetime_seconds", 1, 86400)?;
    let origins_value = policy["origins"].as_array().ok_or_else(|| fail("invalid_policy"))?;
    if origins_value.is_empty() || origins_value.len() > 16 {
        return Err(fail("invalid_policy"));
    }
    let mut hosts = Vec::new();
    for row in origins_value {
        if constrained {
            exact_keys(row, &["host"], &[])?;
        } else {
            exact_keys(row, &["host", "address", "port", "ca_file", "authentication"], &[])?;
        }
        let host = text(row, "host")?;
        if !valid_host(host) || hosts.iter().any(|h: &String| h == host) {
            return Err(fail("invalid_policy"));
        }
        hosts.push(host.to_owned());
    }
    let translator = match &authority {
        Authority::Bridge(routes, client) => {
            // The route copy is guest data, read with a bound; a wrong copy
            // can only change which named operation is asked for.
            let mut raw = Vec::new();
            std::fs::File::open(routes)
                .and_then(|file| file.take(MAX_ROUTES as u64 + 1).read_to_end(&mut raw))
                .map_err(|_| fail("invalid_policy"))?;
            if raw.len() > MAX_ROUTES {
                return Err(fail("invalid_policy"));
            }
            let routes = aivm_secrets_garrett::manifest::Policy::parse(
                &serde_json::from_slice(&raw).map_err(|_| fail("invalid_policy"))?,
            )
            .map_err(|_| fail("invalid_policy"))?;
            if hosts != [routes.host().to_owned()] || client.is_empty() || client.iter().any(String::is_empty) {
                return Err(fail("invalid_policy"));
            }
            Some(Translator { routes, client: client.clone() })
        }
        Authority::Credential(_) => None,
    };
    let (ca_pem, issuer) = session_ca(&hosts, lifetime)?;
    let mut origins = BTreeMap::new();
    for row in origins_value {
        let host = text(row, "host")?.to_owned();
        if constrained {
            let origin = Origin {
                port: 443,
                upstream: None,
                guest: leaf_config(&host, &issuer, lifetime)?,
                host: host.clone(),
                address: String::new(),
                authentication: Authentication::Bearer,
            };
            origins.insert(host, origin);
            continue;
        }
        let authentication = match text(row, "authentication")? {
            "bearer" => Authentication::Bearer,
            "x-api-key" => Authentication::ApiKey,
            _ => return Err(fail("invalid_policy")),
        };
        let address = text(row, "address")?.to_owned();
        if address.is_empty() {
            return Err(fail("invalid_policy"));
        }
        let origin = Origin {
            port: number(row, "port", 1, 65535)? as u16,
            upstream: Some(upstream_config(Path::new(text(row, "ca_file")?))?),
            guest: leaf_config(&host, &issuer, lifetime)?,
            host: host.clone(),
            address,
            authentication,
        };
        origins.insert(host, origin);
    }
    let mut rules = Vec::new();
    if let Some(deny) = policy.get("deny") {
        for row in deny.as_array().ok_or_else(|| fail("invalid_policy"))? {
            exact_keys(row, &["method", "path"], &[])?;
            let method = text(row, "method")?;
            let path = text(row, "path")?;
            if !(method == "*" || core::valid_method(method.as_bytes()))
                || !core::check_target(path.as_bytes())
            {
                return Err(fail("invalid_policy"));
            }
            rules.push(core::DenyRule {
                method: if method == "*" { Vec::new() } else { method.as_bytes().to_vec() },
                path: path.as_bytes().to_vec(),
            });
        }
    }
    let (mut request_limit, mut response_limit) = (1usize << 20, 8usize << 20);
    if let Some(limits) = policy.get("limits") {
        exact_keys(limits, &[], &["request_body", "response_body"])?;
        if limits.get("request_body").is_some() {
            request_limit = number(limits, "request_body", 1, 64 << 20)? as usize;
        }
        if limits.get("response_body").is_some() {
            response_limit = number(limits, "response_body", 1, 64 << 20)? as usize;
        }
    }
    let secret = match authority {
        Authority::Credential(credential_path) => {
            let mut secret =
                files::read_private(credential_path, 4097).map_err(|_| fail("credential_source"))?;
            while secret.last() == Some(&b'\n') || secret.last() == Some(&b'\r') {
                secret.pop();
            }
            if !aivm_secrets_garrett_core::http_auth::valid_credential(&secret) {
                return Err(fail("credential_source"));
            }
            secret
        }
        Authority::Bridge(..) => Vec::new(),
    };
    let mut random = [0u8; 32];
    SystemRandom::new().fill(&mut random).map_err(|_| fail("proxy_failed"))?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random).into_bytes();
    use std::os::unix::fs::OpenOptionsExt;
    let audit = std::fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(audit_path)
        .map_err(|_| fail("proxy_failed"))?;
    let forms = core::reflection_forms(&secret);
    Ok((
        Session {
            origins,
            translator,
            rules,
            request_limit,
            response_limit,
            secret,
            forms,
            token,
            expires: Instant::now() + Duration::from_secs(lifetime),
            revoked: AtomicBool::new(false),
            audit: Mutex::new(Audit { file: audit, seq: 0, head: "0".repeat(64) }),
            connections: AtomicUsize::new(0),
        },
        ca_pem,
    ))
}

impl Session {
    /// Append one hash-chained record and sync it; false if it was not
    /// durably written (the caller decides whether that stops the request).
    fn record(&self, event: &str, detail: Value) -> bool {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if let Ok(mut audit) = self.audit.lock() {
            let mut row = json!({"schema": "proxy-audit-1", "seq": audit.seq, "prev": audit.head,
                                 "event": event, "timestamp": stamp});
            if let (Some(row), Some(detail)) = (row.as_object_mut(), detail.as_object()) {
                for (k, v) in detail {
                    row.insert(k.clone(), v.clone());
                }
            }
            let line = row.to_string();
            if writeln!(audit.file, "{line}").is_ok() && audit.file.sync_data().is_ok() {
                audit.head = ring::digest::digest(&ring::digest::SHA256, line.as_bytes())
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                audit.seq += 1;
                return true;
            }
        }
        false
    }
    fn current(&self) -> bool {
        !self.revoked.load(Ordering::SeqCst) && Instant::now() < self.expires
    }
}

/// The fixed guest response for a refusal: the extracted `core::refusal`.
fn refusal(code: &str) -> Vec<u8> {
    let code = match code {
        "invalid_request" => core::Code::InvalidRequest,
        "too_large" => core::Code::TooLarge,
        "denied" => core::Code::Denied,
        "unknown_origin" => core::Code::UnknownOrigin,
        "unauthenticated" => core::Code::Unauthenticated,
        "revoked" => core::Code::Revoked,
        "reflected" => core::Code::Reflected,
        "unreachable" => core::Code::Unreachable,
        "credential_source" => core::Code::CredentialSource,
        "unsupported_request" => core::Code::UnsupportedRequest,
        "internal_error" => core::Code::InternalError,
        _ => core::Code::OutcomeUnknown,
    };
    core::refusal(&code)
}

fn code_name(code: &core::Code) -> &'static str {
    match code {
        core::Code::InvalidRequest => "invalid_request",
        core::Code::TooLarge => "too_large",
        core::Code::Denied => "denied",
        core::Code::UnknownOrigin => "unknown_origin",
        core::Code::Unauthenticated => "unauthenticated",
        core::Code::Revoked => "revoked",
        core::Code::Reflected => "reflected",
        core::Code::Unreachable => "unreachable",
        core::Code::OutcomeUnknown => "outcome_unknown",
        core::Code::CredentialSource => "credential_source",
        core::Code::UnsupportedRequest => "unsupported_request",
        core::Code::InternalError => "internal_error",
    }
}

/// The raw guest socket before TLS, for the extracted `connect_head`.
struct HeadReader<'a> {
    stream: &'a mut TcpStream,
    started: Instant,
}

impl controller::HeadSource for HeadReader<'_> {
    fn overdue(&mut self) -> bool {
        self.started.elapsed() > HEAD_DEADLINE
    }
    fn next_byte(&mut self) -> Option<u8> {
        let mut byte = [0u8; 1];
        match self.stream.read(&mut byte) {
            Ok(1) => Some(byte[0]),
            _ => None,
        }
    }
}

fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    // Byte-wise so nothing after the CONNECT head is consumed before TLS;
    // the loop is the extracted `proxy_controller::connect_head`.
    let mut source = HeadReader {
        stream,
        started: Instant::now(),
    };
    controller::connect_head(&mut source).ok_or_else(|| io::ErrorKind::InvalidData.into())
}

fn exchange(session: &Session, origin: &Origin, wire: &[u8]) -> Result<Vec<u8>, core::Code> {
    let started = Instant::now();
    let address = (origin.address.as_str(), origin.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or(core::Code::Unreachable)?;
    let socket = TcpStream::connect_timeout(&address, IO_TIMEOUT).map_err(|_| core::Code::Unreachable)?;
    socket.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| core::Code::Unreachable)?;
    socket.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| core::Code::Unreachable)?;
    let name = ServerName::try_from(origin.host.clone()).map_err(|_| core::Code::Unreachable)?;
    let upstream = origin.upstream.clone().ok_or(core::Code::Unreachable)?;
    let connection = ClientConnection::new(upstream, name).map_err(|_| core::Code::Unreachable)?;
    let mut tls = StreamOwned::new(connection, socket);
    // A completed handshake before the first byte keeps core::Code::Unreachable honest.
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(|_| core::Code::Unreachable)?;
    }
    tls.write_all(wire).map_err(|_| core::Code::OutcomeUnknown)?;
    tls.flush().map_err(|_| core::Code::OutcomeUnknown)?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        if started.elapsed() > TOTAL_DEADLINE {
            return Err(core::Code::OutcomeUnknown);
        }
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                if data.len() > session.response_limit + core::MAX_HEAD + 64 {
                    return Err(core::Code::TooLarge);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err(core::Code::OutcomeUnknown),
        }
    }
    Ok(data)
}

fn path_of(target: &[u8]) -> String {
    String::from_utf8_lossy(&target[..core::path_end(target)]).into_owned()
}

/// The native side of one request: the session clock, the admission audit
/// and the socket exchange. Every decision is the extracted controller's.
struct Native<'a> {
    session: &'a Session,
    origin: &'a Origin,
    method: &'a str,
    path: &'a str,
}

impl Upstream for Native<'_> {
    fn current(&mut self) -> bool {
        self.session.current()
    }

    fn admitted(&mut self) -> bool {
        self.session.record(
            "admitted",
            json!({"origin": self.origin.host, "method": self.method, "path": self.path}),
        )
    }

    fn completed(&mut self, status: u16) -> bool {
        self.session.record(
            "completed",
            json!({"origin": self.origin.host, "method": self.method, "path": self.path, "status": status}),
        )
    }

    fn exchange(&mut self, wire: &[u8]) -> Result<Vec<u8>, core::Code> {
        exchange(self.session, self.origin, wire)
    }
}

/// One accepted guest request through `proxy_controller::serve`. Returns the
/// guest bytes and whether to keep the tunnel open.
fn serve_one(session: &Session, origin: &Origin, request: &core::Request) -> (Vec<u8>, bool) {
    if let Some(translator) = &session.translator {
        return serve_translated(session, translator, origin, request);
    }
    let method = String::from_utf8_lossy(&request.method).into_owned();
    let path = path_of(&request.target);
    let mut native = Native { session, origin, method: &method, path: &path };
    let served = controller::serve(
        &mut native, request, origin.host.as_bytes(), &session.rules, &session.secret,
        &origin.authentication, &session.forms, session.response_limit,
    );
    let detail = json!({"origin": origin.host, "method": method, "path": path});
    match served.stage {
        // The completion record was written by `Upstream::completed` before
        // the extracted `serve` released the reply.
        Stage::Completed => {}
        Stage::Refused | Stage::Failed => {
            let mut detail = detail;
            detail["code"] = json!(code_name(&served.code));
            let event = if matches!(served.stage, Stage::Refused) { "refused" } else { "failed" };
            session.record(event, detail);
        }
    }
    (served.reply, served.keep)
}

/// The guest-side constrained profile: the one named operation the request
/// equals, sent through the guest's native `invoke`. No credential exists in
/// this process; the reply body is the operation's disclosure.
fn serve_translated(session: &Session, translator: &Translator, origin: &Origin, request: &core::Request) -> (Vec<u8>, bool) {
    let method = String::from_utf8_lossy(&request.method).into_owned();
    let target = String::from_utf8_lossy(&request.target).into_owned();
    let path = path_of(&request.target);
    if !session.current() {
        session.record("refused", json!({"code": "revoked", "origin": origin.host, "method": method, "path": path}));
        return (refusal("revoked"), false);
    }
    let Some((operation, arguments)) = translator.routes.translate(&method, &target, &request.body) else {
        session.record("refused", json!({"code": "unsupported_request", "origin": origin.host, "method": method, "path": path}));
        return (refusal("unsupported_request"), false);
    };
    // Fail closed: no acknowledged admission record, no bridge call.
    if !session.record("admitted", json!({"origin": origin.host, "method": method, "path": path, "operation": operation})) {
        return (refusal("internal_error"), false);
    }
    let body = arguments.to_string().into_bytes();
    if body.len() > MAX_INVOKE_ARGUMENTS {
        // The client would refuse it; say so instead of "outcome unknown".
        session.record("refused", json!({"code": "too_large", "origin": origin.host, "method": method, "path": path}));
        return (refusal("too_large"), false);
    }
    let reply = invoke_bridge(&translator.client, &operation, &body);
    match reply {
        Some(reply) if reply["ok"] == json!(true) && reply.get("result").is_some() => {
            let body = serde_json::to_vec(&reply["result"]).unwrap_or_default();
            if !session.record("completed", json!({"origin": origin.host, "method": method, "path": path, "operation": operation, "status": 200})) {
                return (refusal("outcome_unknown"), false);
            }
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                body.len(),
                if request.keep_alive { "keep-alive" } else { "close" }
            )
            .into_bytes();
            if request.method != b"HEAD" {
                out.extend_from_slice(&body);
            }
            (out, request.keep_alive)
        }
        reply => {
            let code = match reply.as_ref().and_then(|r| r["error"]["code"].as_str()) {
                Some("denied") => "denied",
                Some("invalid_request") => "invalid_request",
                Some("revoked" | "expired" | "invalid_capability") => "revoked",
                _ => "outcome_unknown",
            };
            session.record("failed", json!({"code": code, "origin": origin.host, "method": method, "path": path, "operation": operation}));
            (refusal(code), false)
        }
    }
}

/// Run the guest's bridge client once: arguments on stdin (not argv, which
/// other guest users can read), a deadline, and a bounded reply.
fn invoke_bridge(client: &[String], operation: &str, body: &[u8]) -> Option<Value> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(&client[0])
        .args(&client[1..])
        .args(["invoke", operation, "--arguments-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut input = child.stdin.take()?;
    let written = input.write_all(body).is_ok();
    drop(input);
    let mut output = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut data = Vec::new();
        let _ = (&mut output).take(MAX_INVOKE_REPLY as u64 + 1).read_to_end(&mut data);
        data
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < INVOKE_DEADLINE => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let data = reader.join().ok()?;
    if !written || data.len() > MAX_INVOKE_REPLY {
        return None;
    }
    serde_json::from_slice::<Value>(&data).ok()
}

struct GuestTunnel<'a> {
    session: &'a Session,
    origin: &'a Origin,
    tls: StreamOwned<ServerConnection, TcpStream>,
    started: Instant,
    chunk: Vec<u8>,
}

impl controller::Guest for GuestTunnel<'_> {
    fn overdue(&mut self) -> bool {
        self.started.elapsed() > REQUEST_DEADLINE
    }
    fn read(&mut self) -> Option<Vec<u8>> {
        match self.tls.read(&mut self.chunk) {
            Ok(n) => Some(self.chunk[..n].to_vec()),
            Err(_) => None,
        }
    }
    fn send(&mut self, bytes: &[u8]) -> bool {
        self.tls.write_all(bytes).and_then(|()| self.tls.flush()).is_ok()
    }
    fn refused(&mut self, code: &core::Code) {
        self.session.record("refused", json!({"code": code_name(code), "origin": self.origin.host}));
    }
    fn serve(&mut self, request: &core::Request) -> controller::Answer {
        let (reply, keep) = serve_one(self.session, self.origin, request);
        self.started = Instant::now();
        controller::Answer { reply, keep }
    }
}

fn tunnel(session: &Session, mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let data = read_head(&mut stream)?;
    let end = core::head_end(&data).unwrap_or(0);
    // The tunnel decision is the extracted `proxy_connect::admit`
    // (proofs/GarrettProxyConnect.lean): session token, configured origin on
    // port 443, current session.
    let hosts: Vec<Vec<u8>> = session.origins.keys().map(|host| host.as_bytes().to_vec()).collect();
    let origin = match connect::admit(&data[..end], &session.token, &hosts, session.current()) {
        Admission::Open(index) => match session.origins.values().nth(index) {
            Some(origin) => origin,
            None => return stream.write_all(&core::refusal(&core::Code::InvalidRequest)),
        },
        Admission::Refuse(code) => {
            if !matches!(code, core::Code::InvalidRequest) {
                session.record("refused", json!({"code": code_name(&code)}));
            }
            return stream.write_all(&core::refusal(&code));
        }
    };
    stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    let connection = ServerConnection::new(origin.guest.clone()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let tls = StreamOwned::new(connection, stream);
    // Each step (deadline, raw bound, strict parse, refusal, serve, keep-alive)
    // is the extracted `proxy_controller::step`; `GuestTunnel` only reads, writes,
    // keeps the clock and audits.
    let mut guest = GuestTunnel {
        session,
        origin,
        tls,
        started: Instant::now(),
        chunk: vec![0u8; 65536],
    };
    controller::tunnel(&mut guest, origin.host.as_bytes(), session.request_limit);
    let mut tls = guest.tls;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls.sock.shutdown(Shutdown::Write);
    Ok(())
}

fn emit(value: &Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options: BTreeMap<&str, &str> = BTreeMap::new();
    let mut index = 0;
    while index + 1 < args.len() {
        let key = args[index].as_str();
        if !["--policy", "--credential-file", "--audit", "--port", "--routes", "--bridge-client"].contains(&key)
            || options.contains_key(key)
        {
            emit(&json!({"version": 1, "ready": false, "error": "invalid_spec"}));
            std::process::exit(1);
        }
        options.insert(key, args[index + 1].as_str());
        index += 2;
    }
    // Exactly one authority source: a credential, or a route copy and bridge client.
    let bridge = options.contains_key("--routes") || options.contains_key("--bridge-client");
    let complete = if bridge {
        options.contains_key("--routes") && options.contains_key("--bridge-client")
            && !options.contains_key("--credential-file")
    } else {
        options.contains_key("--credential-file")
    };
    if index != args.len() || !complete || ["--policy", "--audit"].iter().any(|k| !options.contains_key(k)) {
        emit(&json!({"version": 1, "ready": false, "error": "invalid_spec"}));
        std::process::exit(1);
    }
    let port: u16 = match options.get("--port").map(|p| p.parse()) {
        None => 0,
        Some(Ok(p)) => p,
        Some(Err(_)) => {
            emit(&json!({"version": 1, "ready": false, "error": "invalid_spec"}));
            std::process::exit(1);
        }
    };
    let routes = options.get("--routes").map(PathBuf::from);
    let credential = options.get("--credential-file").map(PathBuf::from);
    let authority = match (&routes, &credential) {
        (Some(routes), None) => match serde_json::from_str::<Vec<String>>(options["--bridge-client"]) {
            Ok(client) => Authority::Bridge(routes, client),
            Err(_) => {
                emit(&json!({"version": 1, "ready": false, "error": "invalid_spec"}));
                std::process::exit(1);
            }
        },
        (None, Some(credential)) => Authority::Credential(credential),
        _ => {
            emit(&json!({"version": 1, "ready": false, "error": "invalid_spec"}));
            std::process::exit(1);
        }
    };
    let (session, ca_pem) = match load(&PathBuf::from(options["--policy"]), authority, &PathBuf::from(options["--audit"])) {
        Ok(loaded) => loaded,
        Err(code) => {
            emit(&json!({"version": 1, "ready": false, "error": code}));
            std::process::exit(1);
        }
    };
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(_) => {
            emit(&json!({"version": 1, "ready": false, "error": "proxy_failed"}));
            std::process::exit(1);
        }
    };
    let address = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
    let session = Arc::new(session);
    let profile = if session.translator.is_some() { "constrained-http" } else { "credential-substitution" };
    session.record("session_start", json!({"profile": profile,
        "origins": session.origins.keys().collect::<Vec<_>>()}));
    let token = String::from_utf8_lossy(&session.token).into_owned();
    let announcement = json!({
        "version": 1, "ready": true, "profile": profile,
        "listen": address, "origins": session.origins.keys().collect::<Vec<_>>(),
        "ca_pem": ca_pem, "proxy_token": token,
    });
    if !session.secret.is_empty()
        && announcement.to_string().as_bytes().windows(session.secret.len()).any(|w| w == session.secret.as_slice())
    {
        emit(&json!({"version": 1, "ready": false, "error": "credential_exposed"}));
        std::process::exit(1);
    }
    emit(&announcement);
    let acceptor = session.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if acceptor.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                acceptor.connections.fetch_sub(1, Ordering::SeqCst);
                drop(stream);
                continue;
            }
            let session = acceptor.clone();
            std::thread::spawn(move || {
                let _ = tunnel(&session, stream);
                session.connections.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    // The session lasts exactly as long as the parent's stdin lease.
    let mut sink = [0u8; 4096];
    let mut stdin = io::stdin().lock();
    while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    session.revoked.store(true, Ordering::SeqCst);
    session.record("session_end", json!({}));
    std::process::exit(0);
}

#[cfg(test)]
mod connect_oracle {
    //! Byte-equality oracle: the extracted CONNECT decision against the
    //! native checks it replaced (base64 crate decoding included).
    use super::*;

    struct Legacy {
        token: Vec<u8>,
    }
    impl Legacy {
        fn authenticated(&self, fields: &[core::Field]) -> bool {
            let values: Vec<&core::Field> = fields.iter().filter(|f| f.name == b"proxy-authorization").collect();
            if values.len() != 1 {
                return false;
            }
            let value = &values[0].value;
            let presented = if value.len() > 6 && value[..6].eq_ignore_ascii_case(b"basic ") {
                match base64::engine::general_purpose::STANDARD.decode(&value[6..]) {
                    Ok(decoded) => match decoded.iter().position(|b| *b == b':') {
                        Some(colon) => decoded[colon + 1..].to_vec(),
                        None => return false,
                    },
                    Err(_) => return false,
                }
            } else if value.len() > 7 && value[..7].eq_ignore_ascii_case(b"bearer ") {
                value[7..].to_vec()
            } else {
                return false;
            };
            // Compare without an early exit on the first differing byte.
            presented.len() == self.token.len()
                && presented.iter().zip(&self.token).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        }
    }

    fn legacy_admit(head: &[u8], token: &[u8], hosts: &[&str], current: bool) -> Result<usize, &'static str> {
        let first = core::line_end(head, 0);
        let line = &head[..first];
        let parts: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
        if !core::clean_head(head) || parts.len() != 3 || parts[0] != b"CONNECT" || parts[2] != b"HTTP/1.1" {
            return Err("invalid_request");
        }
        let fields = if first >= head.len() { Some(Vec::new()) } else { core::parse_fields(head, first + 2) };
        let Some(fields) = fields else { return Err("invalid_request") };
        if !(Legacy { token: token.to_vec() }).authenticated(&fields) {
            return Err("unauthenticated");
        }
        let authority = String::from_utf8_lossy(parts[1]).into_owned();
        let (host, port) = authority.rsplit_once(':').unwrap_or(("", ""));
        match hosts.iter().position(|h| *h == host) {
            Some(index) if port == "443" => {
                if current { Ok(index) } else { Err("revoked") }
            }
            _ => Err("unknown_origin"),
        }
    }

    fn admitted(head: &[u8], token: &[u8], hosts: &[&str], current: bool) -> Result<usize, &'static str> {
        let owned: Vec<Vec<u8>> = hosts.iter().map(|h| h.as_bytes().to_vec()).collect();
        match connect::admit(head, token, &owned, current) {
            Admission::Open(index) => Ok(index),
            Admission::Refuse(code) => Err(code_name(&code)),
        }
    }

    #[test]
    fn extracted_connect_decision_matches_the_native_checks() {
        let token = b"tok3n-Value_42".to_vec();
        let hosts = ["api.example.org", "uploads.example.org"];
        let b64 = |text: &[u8]| base64::engine::general_purpose::STANDARD.encode(text);
        let mut auths: Vec<String> = vec![
            format!("Basic {}", b64(b"aivm:tok3n-Value_42")),
            format!("basic {}", b64(b":tok3n-Value_42")),
            format!("BASIC {}", b64(b"a:b:tok3n-Value_42")),
            format!("Basic {}", b64(b"aivm:tok3n-Value_4")),
            format!("Basic {}", b64(b"aivmtok3n-Value_42")),
            format!("Basic {}", b64(b"aivm:tok3n-Value_42").trim_end_matches('=')),
            "Basic YWl2bTp0b2szbi1WYWx1ZV80Mg==".into(),
            "Basic YWl2bTp0b2szbi1WYWx1ZV80Mh==".into(),
            "Basic YWl2bTp0b2szbi1WYWx1ZV80Mg=".into(),
            "Basic ====".into(),
            "Basic a===".into(),
            "Basic ab=c".into(),
            "Basic Zg==".into(),
            "Basic Zh==".into(),
            "Basic Zm8=".into(),
            "Basic Zm9=".into(),
            "Basic ".into(),
            "Bearer tok3n-Value_42".into(),
            "bearer tok3n-Value_42".into(),
            "Bearer tok3n-Value_43".into(),
            "Bearer  tok3n-Value_42".into(),
            "Token tok3n-Value_42".into(),
        ];
        for (i, extra) in ["", "=", "-", "_", "*"].iter().enumerate() {
            auths.push(format!("Basic {}{}", b64(&[b'x'; 7][..i + 1]), extra));
        }
        let mut checked = 0;
        for connect_line in [
            "CONNECT api.example.org:443 HTTP/1.1",
            "CONNECT uploads.example.org:443 HTTP/1.1",
            "CONNECT api.example.org:8443 HTTP/1.1",
            "CONNECT evil.example.net:443 HTTP/1.1",
            "CONNECT api.example.org HTTP/1.1",
            "CONNECT api.example.org:443:443 HTTP/1.1",
            "CONNECT  api.example.org:443 HTTP/1.1",
            "GET api.example.org:443 HTTP/1.1",
            "CONNECT api.example.org:443 HTTP/1.0",
            "CONNECT api.example.org:443",
        ] {
            for auth in auths.iter().map(Some).chain([None]) {
                for twice in [false, true] {
                    for current in [true, false] {
                        let mut head = connect_line.as_bytes().to_vec();
                        if let Some(auth) = auth {
                            head.extend_from_slice(format!("\r\nProxy-Authorization: {auth}").as_bytes());
                            if twice {
                                head.extend_from_slice(format!("\r\nproxy-authorization: {auth}").as_bytes());
                            }
                        }
                        assert_eq!(
                            admitted(&head, &token, &hosts, current),
                            legacy_admit(&head, &token, &hosts, current),
                            "{}", String::from_utf8_lossy(&head)
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 800);
    }
}
