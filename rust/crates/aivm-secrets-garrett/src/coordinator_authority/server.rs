use super::{AuthorityError, Ledger, Result};
use crate::{files, json, tls, Error};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use zeroize::Zeroizing;

const LIMIT: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(5);
const CLIENTS: usize = 32;
pub struct Server {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    ledger: Arc<Ledger>,
    operators: Arc<Vec<Vec<u8>>>,
}
impl Server {
    pub fn from_file(path: &Path) -> Result<Self> {
        let value = json::parse(&files::read_private(path, 16384)?, 16384)?;
        let m = json::keys(
            &value,
            &[
                "schema",
                "listen",
                "directory",
                "server_certificate_file",
                "server_key_file",
                "client_ca_file",
                "operator_fingerprints",
            ],
            &[],
        )
        .map_err(|_| Error::InvalidPolicy)?;
        json::integer(&m["schema"], 1, 1).map_err(|_| Error::InvalidPolicy)?;
        let text = |key: &str| m[key].as_str().ok_or(Error::InvalidPolicy);
        let address: SocketAddr = text("listen")?.parse().map_err(|_| Error::InvalidPolicy)?;
        let ledger = Arc::new(Ledger::open(Path::new(text("directory")?))?);
        let operators = m["operator_fingerprints"]
            .as_array()
            .ok_or(Error::InvalidPolicy)?;
        if operators.is_empty() {
            return Err(Error::InvalidPolicy.into());
        }
        let operators = operators
            .iter()
            .map(|v| json::hex(v, 64).map(String::into_bytes))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::InvalidPolicy)?;
        let certificate =
            files::read_trusted_public(Path::new(text("server_certificate_file")?), 1048576)?;
        let key = Zeroizing::new(files::read_private(
            Path::new(text("server_key_file")?),
            1048576,
        )?);
        let ca = files::read_trusted_public(Path::new(text("client_ca_file")?), 1048576)?;
        let tls = tls::server_config(&certificate, &key, &ca)?.shared();
        let listener = TcpListener::bind(address).map_err(|_| Error::Unreachable)?;
        Ok(Self {
            listener,
            tls,
            ledger,
            operators: Arc::new(operators),
        })
    }
    pub fn local_address(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|_| Error::InternalError.into())
    }
    pub fn serve(self) -> Result<()> {
        let active = Arc::new(AtomicUsize::new(0));
        for accepted in self.listener.incoming() {
            let socket = accepted.map_err(|_| Error::Unreachable)?;
            if active
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    if n < CLIENTS {
                        Some(n + 1)
                    } else {
                        None
                    }
                })
                .is_err()
            {
                drop(socket);
                continue;
            }
            let slot = Slot(active.clone());
            let (tls, ledger, operators) = (
                self.tls.clone(),
                self.ledger.clone(),
                self.operators.clone(),
            );
            // Take a slot before spawning or handshaking. A stalled anonymous
            // peer cannot hold the accept loop or create unbounded workers.
            std::thread::Builder::new()
                .name("coordinator-client".into())
                .spawn(move || {
                    let _slot = slot;
                    let _ = exchange(socket, tls, &ledger, &operators);
                })
                .map_err(|_| Error::InternalError)?;
        }
        Ok(())
    }
}
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
fn exchange(
    mut socket: TcpStream,
    config: Arc<ServerConfig>,
    ledger: &Ledger,
    operators: &[Vec<u8>],
) -> Result<()> {
    socket
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|_| Error::Unreachable)?;
    socket
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|_| Error::Unreachable)?;
    let abort = socket.try_clone().map_err(|_| Error::Unreachable)?;
    let _deadline = tls::Deadline::start_for(TIMEOUT, move || {
        let _ = abort.shutdown(std::net::Shutdown::Both);
    });
    let mut connection = ServerConnection::new(config).map_err(|_| Error::InvalidCapability)?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|_| Error::InvalidCapability)?;
    }
    let peer = tls::VerifiedPeer::from_connection(&connection)?;
    let mut stream = BufReader::new(StreamOwned::new(connection, socket));
    // Keep the admission/transaction call explicit in the compiled handler.
    let decision = match request(&mut stream) {
        Ok(value) => ledger.handle(&peer, operators, &value),
        Err(error) => Err(error),
    };
    let reply = match decision {
        Ok(result) => {
            let mut reply = result.as_object().ok_or(Error::InternalError)?.clone();
            reply.insert("ok".into(), json!(true));
            Value::Object(reply)
        }
        Err(error) => json!({"ok":false,"code":error.code()}),
    };
    let body = json::canonical(&reply);
    let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
    let stream = stream.get_mut();
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .and_then(|_| stream.flush())
        .map_err(|_| Error::Unreachable)?;
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(())
}
fn line(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|_| Error::InvalidRequest)?;
    if line.len() > limit || !line.ends_with(b"\r\n") {
        return Err(Error::InvalidRequest.into());
    }
    line.truncate(line.len() - 2);
    Ok(line)
}
fn request(reader: &mut impl BufRead) -> Result<Value> {
    let first = line(reader, 256)?;
    if first != b"POST /v1/coordinate HTTP/1.1" && first != b"POST /v1/coordinate HTTP/1.0" {
        return Err(Error::InvalidRequest.into());
    }
    let mut headers = BTreeMap::new();
    let mut used = 0;
    loop {
        let raw = line(reader, 1024)?;
        used += raw.len() + 2;
        if used > LIMIT {
            return Err(Error::InvalidRequest.into());
        }
        if raw.is_empty() {
            break;
        }
        let text = std::str::from_utf8(&raw).map_err(|_| Error::InvalidRequest)?;
        let (name, value) = text.split_once(':').ok_or(Error::InvalidRequest)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !value.bytes().all(|b| (32..=126).contains(&b))
            || headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
        {
            return Err(Error::InvalidRequest.into());
        }
    }
    if headers.contains_key("transfer-encoding")
        || headers.get("content-type").map(String::as_str) != Some("application/json")
    {
        return Err(Error::InvalidRequest.into());
    }
    let raw = headers.get("content-length").ok_or(Error::InvalidRequest)?;
    if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidRequest.into());
    }
    let length: usize = raw.parse().map_err(|_| Error::InvalidRequest)?;
    if length == 0 || length > LIMIT {
        return Err(Error::InvalidRequest.into());
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| Error::InvalidRequest)?;
    json::parse(&body, LIMIT).map_err(|_| AuthorityError::Public(Error::InvalidRequest))
}
