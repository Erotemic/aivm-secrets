//! The stateless mTLS reverse proxy (spec section 11).
//!
//! Per connection: a TLS 1.3 handshake requiring an agent certificate, then
//! the extracted `stateless_proxy::connection` for the peer of that
//! handshake. It frames the guest's bytes and, for each request, opens the
//! surrogate for this peer, picks the route of its authenticated provider,
//! encodes the upstream request and releases the reply. This module only
//! moves bytes and keeps no record of any token.
//!
//! The provider exchange is the core's `stateless_proxy::exchange`: it asks
//! this shell to connect to the egress's own destination (`Origin::connect`,
//! a TLS handshake that must authenticate the destination's host under its
//! trust anchors), then, only if that succeeded, to write the egress once
//! (`Origin::transmit`), then reads the answer (`Origin::receive`). The
//! destination comes from the route the core selected, so there is no table
//! here to get out of step with the core's routes. The only code that writes
//! to a provider is `transmit`, which needs an `Egress`, which only the
//! extracted controller can make.
use crate::broker::Clock;
use crate::config::{Authentication as RouteAuthentication, Operations, ProxyConfig};
use crate::error::{rejection_name, Error, Result};
use crate::files::{read_private, read_public};
use crate::json::{self, Value};
use crate::keys::ProxyKeys;
use crate::tls::{self, PeerIdentity};
use crate::token::RingKey;
use garrett_stateless_core::credential_use::Authentication;
use garrett_stateless_core::proxy_http::{self as core_http, Code, DenyRule, Request};
use garrett_stateless_core::stateless::{Acceptance, Rejection, SurrogateClaims};
use garrett_stateless_core::stateless_policy::{ReadOnly, Resource, Unrestricted};
use garrett_stateless_core::stateless_proxy::{
    self, egress_destination, egress_wire, routes_valid, Channel, Destination, Egress, Origin,
    Received, Route,
};
use garrett_stateless_core::stateless_token::KeySet;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_DEADLINE: Duration = Duration::from_secs(45);
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);
const MAX_CONNECTIONS: usize = 64;

pub struct Proxy {
    config: ProxyConfig,
    keys: KeySet<RingKey>,
    /// The core's routes, each with its own destination.
    routes: Vec<Route>,
    /// `Some` for a read-only proxy; Garrett's unrestricted policy otherwise.
    read_only: Option<ReadOnly>,
    acceptance: Acceptance,
    audit: Option<Mutex<std::fs::File>>,
    clock: Clock,
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Proxy {
    pub fn new(config: ProxyConfig, keys: ProxyKeys) -> Result<Self> {
        let mut routes = Vec::new();
        for route in &config.routes {
            let trust = match &route.ca_file {
                Some(path) => read_public(path, 1 << 20)?,
                None => Vec::new(),
            };
            // Refuse unusable trust anchors now rather than per request.
            upstream_tls(&trust)?;
            routes.push(Route {
                provider: route.provider.as_bytes().to_vec(),
                destination: Destination {
                    host: route.host.as_bytes().to_vec(),
                    address: route.address.as_bytes().to_vec(),
                    port: route.port,
                    trust,
                },
                rules: route
                    .deny
                    .iter()
                    .map(|r| DenyRule {
                        method: r.method.as_bytes().to_vec(),
                        path: r.path.as_bytes().to_vec(),
                    })
                    .collect(),
                authentication: match route.authentication {
                    RouteAuthentication::Bearer => Authentication::Bearer,
                    RouteAuthentication::ApiKey => Authentication::ApiKey,
                },
            });
        }
        if !routes_valid(&routes) {
            return Err(Error::Config("proxy: two routes for one provider".into()));
        }
        let acceptance = Acceptance {
            audiences: config
                .audiences
                .iter()
                .map(|a| a.as_bytes().to_vec())
                .collect(),
            providers: config
                .routes
                .iter()
                .map(|r| r.provider.as_bytes().to_vec())
                .collect(),
            max_lifetime: config.max_lifetime,
            skew: config.skew,
        };
        let read_only = match &config.operations {
            Operations::Unrestricted => None,
            Operations::ReadOnly(resources) => Some(ReadOnly {
                resources: resources
                    .iter()
                    .map(|r| Resource {
                        provider: r.provider.as_bytes().to_vec(),
                        method: r.method.as_bytes().to_vec(),
                        path: r.path.as_bytes().to_vec(),
                    })
                    .collect(),
            }),
        };
        let audit = match &config.audit {
            Some(path) => Some(Mutex::new(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(path)
                    .map_err(|e| Error::Io(format!("audit: {}", e.kind())))?,
            )),
            None => None,
        };
        Ok(Self {
            config,
            keys: keys.key_set()?,
            routes,
            read_only,
            acceptance,
            audit,
            clock: Arc::new(now_seconds),
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let config = ProxyConfig::load(path)?;
        let keys = ProxyKeys::load(&config.keys)?;
        Self::new(config, keys)
    }

    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }

    /// One line of diagnostics/audit; false if a configured audit file
    /// could not be written. Never contains token or credential bytes.
    fn record(&self, event: Value) -> bool {
        let mut line = json::canonical(&event).unwrap_or_default();
        line.push(b'\n');
        match &self.audit {
            Some(file) => match file.lock() {
                Ok(mut file) => file
                    .write_all(&line)
                    .and_then(|()| file.sync_data())
                    .is_ok(),
                Err(_) => false,
            },
            None => {
                let _ = std::io::stderr().write_all(&line);
                true
            }
        }
    }

    pub fn serve(self: Arc<Self>) -> Result<RunningProxy> {
        let certificate = read_public(&self.config.certificate, 1 << 20)?;
        let key = Zeroizing::new(read_private(&self.config.private_key, 1 << 20)?);
        let client_ca = read_public(&self.config.client_ca, 1 << 20)?;
        let server = tls::mtls_server(&certificate, &key, &client_ca)?;
        let listener = TcpListener::bind(&self.config.listen)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (stop, proxy) = (stop.clone(), self.clone());
            std::thread::spawn(move || {
                let active = Arc::new(AtomicUsize::new(0));
                for incoming in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(tcp) = incoming else { continue };
                    if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                        continue;
                    }
                    active.fetch_add(1, Ordering::SeqCst);
                    let (proxy, server, active) = (proxy.clone(), server.clone(), active.clone());
                    std::thread::spawn(move || {
                        let _ = proxy.connection(tcp, server);
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            })
        };
        Ok(RunningProxy {
            address,
            stop,
            worker,
        })
    }

    fn connection(&self, tcp: TcpStream, server: Arc<ServerConfig>) -> Result<()> {
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        let connection =
            ServerConnection::new(server).map_err(|_| Error::Tls("server connection".into()))?;
        let mut stream = StreamOwned::new(connection, tcp);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|e| Error::Tls(format!("handshake: {}", e.kind())))?;
        }
        // The peer is the certificate rustls verified in this handshake; the
        // extracted connection loop serves every request for it alone.
        let peer = PeerIdentity::from_connection(&stream.conn)?;
        let mut session = Session {
            proxy: self,
            stream,
            peer: peer.thumbprint.clone(),
            started: Instant::now(),
            chunk: vec![0; 65536],
            method: String::new(),
            claims: None,
            upstream: None,
        };
        // The configured policy is one of the core's two extracted ones.
        match &self.read_only {
            None => stateless_proxy::connection(
                &self.keys,
                &Unrestricted,
                &mut session,
                &self.routes,
                &self.acceptance,
                self.config.authority.as_bytes(),
                peer.thumbprint.as_bytes(),
                self.config.request_limit,
            ),
            Some(read_only) => stateless_proxy::connection(
                &self.keys,
                read_only,
                &mut session,
                &self.routes,
                &self.acceptance,
                self.config.authority.as_bytes(),
                peer.thumbprint.as_bytes(),
                self.config.request_limit,
            ),
        }
        session.stream.conn.send_close_notify();
        let _ = session.stream.conn.complete_io(&mut session.stream.sock);
        Ok(())
    }
}

/// The TLS client for a destination's trust anchors (PEM), or the default
/// web roots when it names none.
fn upstream_tls(trust: &[u8]) -> Result<Arc<ClientConfig>> {
    if trust.is_empty() {
        tls::upstream_client(None)
    } else {
        tls::upstream_client(Some(trust))
    }
}

/// A TLS connection to a provider whose server authenticated as the host
/// of `destination`.
struct Upstream {
    destination: Destination,
    tls: StreamOwned<ClientConnection, TcpStream>,
    started: Instant,
}

/// Connect to `destination` and complete a TLS handshake in which the server
/// proves `destination.host` under `destination.trust`.
fn open_upstream(destination: &Destination) -> std::result::Result<Upstream, ()> {
    let address = std::str::from_utf8(&destination.address).map_err(|_| ())?;
    let host = std::str::from_utf8(&destination.host).map_err(|_| ())?;
    let socket_address = (address, destination.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or(())?;
    let socket = TcpStream::connect_timeout(&socket_address, IO_TIMEOUT).map_err(|_| ())?;
    socket.set_read_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    socket.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ())?;
    let name = ServerName::try_from(host.to_string()).map_err(|_| ())?;
    let config = upstream_tls(&destination.trust).map_err(|_| ())?;
    let connection = ClientConnection::new(config, name).map_err(|_| ())?;
    let mut tls = StreamOwned::new(connection, socket);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(|_| ())?;
    }
    Ok(Upstream {
        destination: destination.clone(),
        tls,
        started: Instant::now(),
    })
}

fn text(bytes: &[u8]) -> Value {
    json::text(&String::from_utf8_lossy(bytes))
}

/// The native side of one authenticated connection.
struct Session<'a> {
    proxy: &'a Proxy,
    stream: StreamOwned<ServerConnection, TcpStream>,
    peer: String,
    started: Instant,
    chunk: Vec<u8>,
    method: String,
    claims: Option<(String, String)>,
    /// The provider connection of the request being served, if any.
    upstream: Option<Upstream>,
}

impl Origin for Session<'_> {
    fn rejected(&mut self, rejection: &Rejection) {
        self.proxy.record(json::object([
            ("event", json::text("rejected")),
            ("peer", json::text(&self.peer)),
            ("reason", json::text(rejection_name(rejection))),
        ]));
    }
    fn admitted(&mut self, claims: &SurrogateClaims, route: usize) -> bool {
        self.claims = Some((
            String::from_utf8_lossy(&claims.token_id).into_owned(),
            String::from_utf8_lossy(&claims.provider).into_owned(),
        ));
        self.proxy.record(json::object([
            ("event", json::text("admitted")),
            ("jti", text(&claims.token_id)),
            ("method", json::text(&self.method)),
            ("provider", text(&claims.provider)),
            ("route", Value::Int(route as i64)),
            ("sub", text(&claims.subject)),
        ]))
    }
    fn connect(&mut self, destination: &Destination) -> bool {
        self.upstream = open_upstream(destination).ok();
        self.upstream.is_some()
    }
    /// The one provider write: the egress bytes, once, on the connection
    /// `connect` opened to that egress's destination. No retry.
    fn transmit(&mut self, egress: Egress) -> bool {
        let Some(upstream) = self.upstream.as_mut() else {
            return false;
        };
        if &upstream.destination != egress_destination(&egress) {
            return false;
        }
        let written = upstream.tls.write_all(egress_wire(&egress));
        drop(egress);
        written.and_then(|()| upstream.tls.flush()).is_ok()
    }
    fn receive(&mut self) -> Received {
        let Some(upstream) = self.upstream.as_mut() else {
            return Received::Failed;
        };
        if upstream.started.elapsed() > UPSTREAM_DEADLINE {
            self.upstream = None;
            return Received::Failed;
        }
        match upstream.tls.read(&mut self.chunk) {
            Ok(0) => {
                self.upstream = None;
                Received::End
            }
            Ok(n) => Received::Bytes(self.chunk[..n].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.upstream = None;
                Received::End
            }
            Err(_) => {
                self.upstream = None;
                Received::Failed
            }
        }
    }
    fn completed(&mut self, status: u16) -> bool {
        let (jti, provider) = self.claims.take().unwrap_or_default();
        self.proxy.record(json::object([
            ("event", json::text("completed")),
            ("jti", json::text(&jti)),
            ("provider", json::text(&provider)),
            ("status", Value::Int(i64::from(status))),
        ]))
    }
}

impl Channel for Session<'_> {
    fn overdue(&mut self) -> bool {
        self.started.elapsed() > REQUEST_DEADLINE
    }
    fn read(&mut self) -> Option<Vec<u8>> {
        match self.stream.read(&mut self.chunk) {
            Ok(n) => Some(self.chunk[..n].to_vec()),
            Err(_) => None,
        }
    }
    fn send(&mut self, bytes: &[u8]) -> bool {
        self.stream
            .write_all(bytes)
            .and_then(|()| self.stream.flush())
            .is_ok()
    }
    fn refused(&mut self, code: &Code) {
        let mut name = Vec::new();
        core_http::append_code(&mut name, code);
        self.proxy.record(json::object([
            ("event", json::text("refused")),
            ("code", text(&name)),
        ]));
    }
    fn stopped(&mut self, code: &Code) {
        let mut name = Vec::new();
        core_http::append_code(&mut name, code);
        self.proxy.record(json::object([
            ("event", json::text("stopped")),
            ("code", text(&name)),
        ]));
    }
    fn begin(&mut self, request: &Request) -> i64 {
        self.method = String::from_utf8_lossy(&request.method).into_owned();
        self.claims = None;
        self.upstream = None;
        (self.proxy.clock)()
    }
    fn restart(&mut self) {
        self.started = Instant::now();
    }
}

pub struct RunningProxy {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: std::thread::JoinHandle<()>,
}

impl RunningProxy {
    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
        let _ = self.worker.join();
    }
    pub fn wait(self) {
        let _ = self.worker.join();
    }
}
