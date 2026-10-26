//! The stateless mTLS reverse proxy (spec section 11).
//!
//! Per connection: a TLS 1.3 handshake requiring an agent certificate,
//! then the extracted `proxy_controller::step` framing, and for each
//! request the extracted `stateless_proxy::serve`, which opens the
//! surrogate for this connection's peer, picks the route of its
//! authenticated provider and encodes the upstream request. This module only
//! moves bytes and keeps no record of any token.
use crate::broker::Clock;
use crate::config::{Authentication as RouteAuthentication, ProxyConfig};
use crate::error::{rejection_name, Error, Result};
use crate::files::{read_private, read_public};
use crate::json::{self, Value};
use crate::keys::ProxyKeys;
use crate::tls::{self, PeerIdentity};
use crate::token::Opener;
use aivm_secrets_garrett_core::credential_use::Authentication;
use aivm_secrets_garrett_core::proxy_controller::{self, Answer, Guest, Stage};
use aivm_secrets_garrett_core::proxy_http::{self as core_http, Code, DenyRule, Request};
use aivm_secrets_garrett_core::stateless::{Acceptance, Rejection, SurrogateClaims};
use aivm_secrets_garrett_core::stateless_proxy::{self, Origin, Route};
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

struct Upstream {
    address: String,
    port: u16,
    host: String,
    tls: Arc<ClientConfig>,
}

pub struct Proxy {
    config: ProxyConfig,
    keys: ProxyKeys,
    routes: Vec<Route>,
    upstream: Vec<Upstream>,
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
        let mut upstream = Vec::new();
        for route in &config.routes {
            let ca = match &route.ca_file {
                Some(path) => Some(read_public(path, 1 << 20)?),
                None => None,
            };
            routes.push(Route {
                provider: route.provider.as_bytes().to_vec(),
                host: route.host.as_bytes().to_vec(),
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
            upstream.push(Upstream {
                address: route.address.clone(),
                port: route.port,
                host: route.host.clone(),
                tls: tls::upstream_client(ca.as_deref())?,
            });
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
            keys,
            routes,
            upstream,
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

    /// Serve one request for `peer` (also usable without sockets, in tests).
    pub fn serve_request(
        &self,
        request: &Request,
        peer: &PeerIdentity,
    ) -> proxy_controller::Served {
        let opener = Opener {
            keys: &self.keys.entries,
        };
        let mut origin = Native {
            proxy: self,
            peer,
            method: String::from_utf8_lossy(&request.method).into_owned(),
            claims: None,
        };
        stateless_proxy::serve(
            &opener,
            &mut origin,
            request,
            &self.routes,
            &self.acceptance,
            peer.thumbprint.as_bytes(),
            (self.clock)(),
            self.config.request_limit,
        )
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
        // The peer is the certificate rustls verified in this handshake.
        let peer = PeerIdentity::from_connection(&stream.conn)?;
        let mut guest = Connection {
            proxy: self,
            stream,
            peer,
            started: Instant::now(),
            chunk: vec![0; 65536],
        };
        proxy_controller::tunnel(
            &mut guest,
            self.config.authority.as_bytes(),
            self.config.request_limit,
        );
        guest.stream.conn.send_close_notify();
        let _ = guest.stream.conn.complete_io(&mut guest.stream.sock);
        Ok(())
    }

    fn exchange(&self, route: usize, wire: &[u8]) -> std::result::Result<Vec<u8>, Code> {
        let upstream = self.upstream.get(route).ok_or(Code::UnknownOrigin)?;
        let started = Instant::now();
        let address = (upstream.address.as_str(), upstream.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .ok_or(Code::Unreachable)?;
        let socket =
            TcpStream::connect_timeout(&address, IO_TIMEOUT).map_err(|_| Code::Unreachable)?;
        socket
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| Code::Unreachable)?;
        socket
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|_| Code::Unreachable)?;
        let name = ServerName::try_from(upstream.host.clone()).map_err(|_| Code::Unreachable)?;
        let connection =
            ClientConnection::new(upstream.tls.clone(), name).map_err(|_| Code::Unreachable)?;
        let mut tls = StreamOwned::new(connection, socket);
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|_| Code::Unreachable)?;
        }
        tls.write_all(wire).map_err(|_| Code::OutcomeUnknown)?;
        tls.flush().map_err(|_| Code::OutcomeUnknown)?;
        let mut data = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            if started.elapsed() > UPSTREAM_DEADLINE {
                return Err(Code::OutcomeUnknown);
            }
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    data.extend_from_slice(&chunk[..n]);
                    if data.len() > self.config.request_limit + core_http::MAX_HEAD + 64 {
                        return Err(Code::TooLarge);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => return Err(Code::OutcomeUnknown),
            }
        }
        Ok(data)
    }
}

/// The native callbacks of one request.
struct Native<'a> {
    proxy: &'a Proxy,
    peer: &'a PeerIdentity,
    method: String,
    claims: Option<(String, String)>,
}

fn text(bytes: &[u8]) -> Value {
    json::text(&String::from_utf8_lossy(bytes))
}

impl Origin for Native<'_> {
    fn rejected(&mut self, rejection: &Rejection) {
        self.proxy.record(json::object([
            ("event", json::text("rejected")),
            ("peer", json::text(&self.peer.thumbprint)),
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
    fn exchange(&mut self, route: usize, wire: &[u8]) -> std::result::Result<Vec<u8>, Code> {
        self.proxy.exchange(route, wire)
    }
    fn completed(&mut self, status: u16) -> bool {
        let (jti, provider) = self.claims.clone().unwrap_or_default();
        self.proxy.record(json::object([
            ("event", json::text("completed")),
            ("jti", json::text(&jti)),
            ("provider", json::text(&provider)),
            ("status", Value::Int(i64::from(status))),
        ]))
    }
}

struct Connection<'a> {
    proxy: &'a Proxy,
    stream: StreamOwned<ServerConnection, TcpStream>,
    peer: PeerIdentity,
    started: Instant,
    chunk: Vec<u8>,
}

impl Guest for Connection<'_> {
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
    fn serve(&mut self, request: &Request) -> Answer {
        let served = self.proxy.serve_request(request, &self.peer);
        self.started = Instant::now();
        if !matches!(served.stage, Stage::Completed) {
            let mut name = Vec::new();
            core_http::append_code(&mut name, &served.code);
            self.proxy.record(json::object([
                ("event", json::text("stopped")),
                ("code", text(&name)),
            ]));
        }
        Answer {
            reply: served.reply,
            keep: served.keep,
        }
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
