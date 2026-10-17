//! Authenticated transport and the closed bridge to the original broker protocol.
use crate::{
    crypto::{self, Verifier},
    files, json,
    model::Registry,
    Error, Outcome,
};
use rustls::{
    server::WebPkiClientVerifier, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

const MAX_FRAME: usize = 65536;
const MAX_REPLY: usize = 2 * 1024 * 1024 + 65536;
const DEADLINE: Duration = Duration::from_secs(55);

// Socket timeouts alone reset on each read. A fixed wall-clock watchdog also
// ends trickled handshakes/frames and exits promptly when an exchange ends.
pub(crate) struct Deadline {
    cancel: std::sync::mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Deadline {
    pub(crate) fn start(abort: impl FnOnce() + Send + 'static) -> Self {
        Self::start_for(DEADLINE, abort)
    }
    pub(crate) fn start_for(duration: Duration, abort: impl FnOnce() + Send + 'static) -> Self {
        let (cancel, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            if matches!(
                wait.recv_timeout(duration),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                abort();
            }
        });
        Self {
            cancel,
            worker: Some(worker),
        }
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Cannot be deserialized or constructed from a client-provided certificate.
pub(crate) struct VerifiedPeer {
    thumbprint: String,
}
impl VerifiedPeer {
    pub(crate) fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
    fn from_connection(connection: &ServerConnection) -> Outcome<Self> {
        if connection.is_handshaking() {
            return Err(Error::InvalidCapability);
        }
        let cert = connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or(Error::InvalidCapability)?;
        Ok(Self {
            thumbprint: crypto::certificate_thumbprint(cert.as_ref())?,
        })
    }
}

pub struct AuthenticatedServerConfig(Arc<ServerConfig>);
pub fn server_config(
    certificate: &[u8],
    private_key: &[u8],
    client_ca: &[u8],
) -> Outcome<AuthenticatedServerConfig> {
    let certificates = rustls_pemfile::certs(&mut &*certificate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidCapability)?;
    let key = rustls_pemfile::private_key(&mut &*private_key)
        .map_err(|_| Error::InvalidCapability)?
        .ok_or(Error::InvalidCapability)?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &*client_ca) {
        roots
            .add(cert.map_err(|_| Error::InvalidCapability)?)
            .map_err(|_| Error::InvalidCapability)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| Error::InvalidCapability)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::InvalidCapability)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .map_err(|_| Error::InvalidCapability)?;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.max_early_data_size = 0;
    Ok(AuthenticatedServerConfig(Arc::new(config)))
}
fn frame(stream: impl Read, limit: usize) -> Outcome<Vec<u8>> {
    let mut data = Vec::new();
    BufReader::new(stream)
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut data)
        .map_err(|_| Error::InvalidRequest)?;
    if data.is_empty() || data.len() > limit {
        return Err(Error::InvalidRequest);
    }
    Ok(data)
}
fn failure(error: Error) -> Value {
    let message = match error {
        Error::InvalidCapability => "Capability authentication failed.",
        Error::InvalidRequest => "Malformed or unsupported request.",
        Error::Denied => "Operation is outside the granted authority.",
        Error::UnsafeFile => "Host file ownership, permissions, or type is unsafe.",
        Error::OutcomeUnknown => {
            "A dispatched request may have completed; reconcile before retrying."
        }
        _ => "Broker failed closed.",
    };
    json!({"version":1,"ok":false,"error":{"code":error.code(),"message":message}})
}

enum Backend {
    Socket(PathBuf),
    Provider(Box<std::sync::Mutex<crate::ProviderSession>>),
}
/// Registry updates and use share this lock: revocation cannot race dispatch.
/// The issuer and registry are host inputs; no request can replace either.
pub struct Bridge {
    config: Arc<ServerConfig>,
    verifier: Verifier,
    registry: RwLock<Registry>,
    registry_file: Option<PathBuf>,
    issuer: String,
    audience: String,
    subject: Option<String>,
    backend: Backend,
}
impl Bridge {
    pub fn new(
        config: AuthenticatedServerConfig,
        verifier: Verifier,
        registry: Registry,
        issuer: String,
        audience: String,
        subject: Option<String>,
        broker: PathBuf,
    ) -> Outcome<Self> {
        files::broker_socket(&broker)?;
        Self::with_backend(
            config,
            verifier,
            registry,
            issuer,
            audience,
            subject,
            Backend::Socket(broker),
        )
    }
    pub fn new_provider(
        config: AuthenticatedServerConfig,
        verifier: Verifier,
        registry: Registry,
        issuer: String,
        audience: String,
        subject: Option<String>,
        provider: crate::ProviderSession,
    ) -> Outcome<Self> {
        Self::with_backend(
            config,
            verifier,
            registry,
            issuer,
            audience,
            subject,
            Backend::Provider(Box::new(std::sync::Mutex::new(provider))),
        )
    }
    fn with_backend(
        config: AuthenticatedServerConfig,
        verifier: Verifier,
        registry: Registry,
        issuer: String,
        audience: String,
        subject: Option<String>,
        backend: Backend,
    ) -> Outcome<Self> {
        json::word(&json!(issuer), 128)?;
        json::word(&json!(audience), 128)?;
        if let Some(name) = &subject {
            json::word(&json!(name), 128)?;
        }
        Ok(Self {
            config: config.0,
            verifier,
            registry: RwLock::new(registry),
            registry_file: None,
            issuer,
            audience,
            subject,
            backend,
        })
    }
    /// Re-read atomically replaced host state for every dispatch, as the Python
    /// service does. A request already past lookup may finish after revocation;
    /// filesystem-backed enrollment is not a distributed dispatch transaction.
    pub fn with_registry_file(mut self, path: PathBuf) -> Outcome<Self> {
        self.read_registry(&path)?;
        self.registry_file = Some(path);
        Ok(self)
    }
    fn read_registry(&self, path: &std::path::Path) -> Outcome<Registry> {
        Registry::parse(
            &json::parse(&files::read_private(path, 1048576)?, 1048576)?,
            &self.issuer,
            &self.audience,
        )
    }
    pub fn revoke(&self, subject: &str) -> Outcome<()> {
        if self.registry_file.is_some() {
            return Err(Error::InvalidRequest);
        }
        let mut registry = self.registry.write().map_err(|_| Error::InternalError)?;
        let row = registry
            .subjects
            .get_mut(subject)
            .ok_or(Error::InvalidCapability)?;
        row.active = false;
        if row.epoch < i32::MAX as i64 {
            row.epoch += 1;
        }
        Ok(())
    }
    pub fn serve_unix(&self, socket: UnixStream, now: impl Fn() -> i64) -> Outcome<()> {
        socket
            .set_read_timeout(Some(DEADLINE))
            .map_err(|_| Error::InternalError)?;
        socket
            .set_write_timeout(Some(DEADLINE))
            .map_err(|_| Error::InternalError)?;
        let killer = socket.try_clone().map_err(|_| Error::InternalError)?;
        let _deadline = Deadline::start(move || {
            let _ = killer.shutdown(std::net::Shutdown::Both);
        });
        self.serve(socket, now)
    }
    pub fn serve_tcp(&self, socket: std::net::TcpStream, now: impl Fn() -> i64) -> Outcome<()> {
        socket
            .set_read_timeout(Some(DEADLINE))
            .map_err(|_| Error::InternalError)?;
        socket
            .set_write_timeout(Some(DEADLINE))
            .map_err(|_| Error::InternalError)?;
        let killer = socket.try_clone().map_err(|_| Error::InternalError)?;
        let _deadline = Deadline::start(move || {
            let _ = killer.shutdown(std::net::Shutdown::Both);
        });
        self.serve(socket, now)
    }
    fn serve<S: Read + Write>(&self, mut socket: S, now: impl Fn() -> i64) -> Outcome<()> {
        let mut connection =
            ServerConnection::new(self.config.clone()).map_err(|_| Error::InternalError)?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut socket)
                .map_err(|_| Error::InvalidCapability)?;
        }
        let peer = VerifiedPeer::from_connection(&connection)?;
        let mut stream = StreamOwned::new(connection, socket);
        let answer = frame(&mut stream, MAX_FRAME)
            .and_then(|raw| json::parse(&raw, MAX_FRAME).map_err(|_| Error::InvalidRequest))
            .and_then(|v| self.answer(v, &peer, now()));
        let reply = answer.unwrap_or_else(failure);
        stream
            .write_all(&json::canonical(&reply))
            .map_err(|_| Error::InternalError)?;
        stream.write_all(b"\n").map_err(|_| Error::InternalError)?;
        stream.flush().map_err(|_| Error::InternalError)?;
        stream.conn.send_close_notify();
        let _ = stream.flush();
        Ok(())
    }
    fn answer(&self, value: Value, peer: &VerifiedPeer, now: i64) -> Outcome<Value> {
        let object = value.as_object().ok_or(Error::InvalidRequest)?;
        let verbs: Vec<_> = ["request", "describe", "renounce", "delegate"]
            .into_iter()
            .filter(|v| object.contains_key(*v))
            .collect();
        if verbs.len() != 1 || verbs[0] == "delegate" {
            return Err(Error::Denied);
        }
        let verb = verbs[0];
        let m = json::keys(&value, &["version", "capability", verb], &[])
            .map_err(|_| Error::InvalidRequest)?;
        json::integer(&m["version"], 1, 1).map_err(|_| Error::InvalidRequest)?;
        if verb != "request" && m[verb] != Value::Bool(true) {
            return Err(Error::InvalidRequest);
        }
        let token = m["capability"].as_str().ok_or(Error::InvalidRequest)?;
        // Hold the identity lease through forwarding. A completed revocation
        // means no older identity dispatch is still in this critical section.
        let lease = self.registry.read().map_err(|_| Error::InternalError)?;
        let snapshot;
        let registry = if let Some(path) = &self.registry_file {
            snapshot = self.read_registry(path)?;
            &snapshot
        } else {
            &*lease
        };
        let expected =
            registry.expectation(&self.issuer, &self.audience, peer.thumbprint(), now)?;
        if self
            .subject
            .as_ref()
            .is_some_and(|s| s.as_bytes() != expected.subject)
        {
            return Err(Error::InvalidCapability);
        }
        if let Backend::Provider(provider) = &self.backend {
            let mut provider = provider.lock().map_err(|_| Error::InternalError)?;
            if verb == "request" {
                return provider.request(&self.verifier, token, peer, expected, &m[verb], now);
            }
            let opened = self.verifier.open(token, peer, &expected, now)?;
            return provider.control(opened.inner.bytes(), verb, now);
        }
        let opened = self.verifier.open(token, peer, &expected, now)?;
        let inner =
            std::str::from_utf8(opened.inner.bytes()).map_err(|_| Error::InvalidCapability)?;
        let forwarded = json!({"version":1,"capability":inner,verb:m[verb]});
        self.forward(&forwarded)
    }
    fn forward(&self, request: &Value) -> Outcome<Value> {
        let Backend::Socket(broker) = &self.backend else {
            return Err(Error::InternalError);
        };
        files::broker_socket(broker)?;
        let mut socket = UnixStream::connect(broker).map_err(|_| Error::InternalError)?;
        socket
            .set_read_timeout(Some(DEADLINE))
            .map_err(|_| Error::InternalError)?;
        socket
            .set_write_timeout(Some(DEADLINE))
            .map_err(|_| Error::InternalError)?;
        let killer = socket.try_clone().map_err(|_| Error::InternalError)?;
        let _deadline = Deadline::start(move || {
            let _ = killer.shutdown(std::net::Shutdown::Both);
        });
        let bytes = zeroize::Zeroizing::new(json::canonical(request));
        socket
            .write_all(&bytes)
            .and_then(|_| socket.write_all(b"\n"))
            .map_err(|_| Error::OutcomeUnknown)?;
        let raw = frame(&mut socket, MAX_REPLY).map_err(|_| Error::OutcomeUnknown)?;
        let result = json::parse(&raw, MAX_REPLY).map_err(|_| Error::OutcomeUnknown)?;
        if !result.is_object() {
            return Err(Error::OutcomeUnknown);
        }
        Ok(result)
    }
}
