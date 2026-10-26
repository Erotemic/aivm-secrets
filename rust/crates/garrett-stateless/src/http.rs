//! A small, strict HTTP/1.1 subset for the broker's endpoints and for HTTPS
//! clients (one request per connection). Responses are parsed with the
//! extracted `proxy_http::parse_response`.
use crate::error::{Error, Result};
use aivm_secrets_garrett_core::proxy_http;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_HEAD: usize = 16384;
pub const MAX_BODY: usize = 65536;
pub const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// A request received by the broker.
#[derive(Debug, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// A query parameter that occurs at most once; a repeated one is an error.
    pub fn param(&self, name: &str) -> Result<Option<&str>> {
        let mut found = self.query.iter().filter(|(n, _)| n == name);
        let first = found.next().map(|(_, v)| v.as_str());
        if found.next().is_some() {
            return Err(bad());
        }
        Ok(first)
    }
}

fn bad() -> Error {
    Error::Protocol("invalid_request")
}

pub fn percent_decode(text: &str, plus_is_space: bool) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `a=b&c=d`, percent-encoded.
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn parse_query(text: &str) -> Option<Vec<(String, String)>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    text.split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Some((percent_decode(k, true)?, percent_decode(v, true)?))
        })
        .collect()
}

/// Read one request (head, then a `Content-Length` body).
pub fn read_request(stream: &mut impl Read) -> Result<Request> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        if data.len() > MAX_HEAD {
            return Err(bad());
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(bad());
        }
        data.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&data[..end]).map_err(|_| bad())?;
    let mut lines = head.split("\r\n");
    let line = lines.next().ok_or_else(bad)?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some("HTTP/1.1"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut request = Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: parse_query(query).ok_or_else(bad)?,
        ..Default::default()
    };
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        if name.is_empty() || name.contains(' ') {
            return Err(bad());
        }
        request
            .headers
            .push((name.to_owned(), value.trim().to_owned()));
    }
    if request.header("transfer-encoding").is_some() {
        return Err(bad());
    }
    let length = match request.header("content-length") {
        Some(text) => text.parse::<usize>().map_err(|_| bad())?,
        None => 0,
    };
    if length > MAX_BODY {
        return Err(bad());
    }
    let mut body = data[end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(bad());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if body.len() != length {
        return Err(bad());
    }
    request.body = body;
    Ok(request)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

/// One complete response with `Connection: close`.
pub fn response(status: u16, content_type: &str, extra: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        reason(status),
        body.len()
    );
    for (name, value) in extra {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Cache-Control: no-store\r\nConnection: close\r\n\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A parsed response from an HTTPS exchange.
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Connect to `address` (`host:port`), authenticate the server as
/// `server_name`, send `request` and read until the server closes.
pub fn exchange(
    config: Arc<ClientConfig>,
    address: &str,
    server_name: &str,
    request: &[u8],
    limit: usize,
) -> Result<Vec<u8>> {
    let addr = address
        .to_socket_addrs()
        .map_err(|_| Error::Protocol("unreachable"))?
        .next()
        .ok_or(Error::Protocol("unreachable"))?;
    let tcp = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .map_err(|_| Error::Protocol("unreachable"))?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::Tls("server name".into()))?;
    let connection =
        ClientConnection::new(config, name).map_err(|_| Error::Tls("client connection".into()))?;
    let mut stream = StreamOwned::new(connection, tcp);
    stream
        .write_all(request)
        .map_err(|e| Error::Tls(format!("send: {}", e.kind())))?;
    stream.flush()?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&chunk[..n]);
                if out.len() > limit {
                    return Err(Error::Protocol("response_too_large"));
                }
            }
            // A peer closing without close_notify after a complete response.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Error::Tls(format!("receive: {}", e.kind()))),
        }
    }
    Ok(out)
}

/// The request bytes for a client call.
pub fn request_bytes(
    method: &str,
    target: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Parse a complete response with the extracted strict parser.
pub fn parse_response(raw: &[u8], head: bool, limit: usize) -> Result<Response> {
    let parsed = proxy_http::parse_response(raw, head, limit)
        .map_err(|_| Error::Protocol("invalid_response"))?;
    Ok(Response {
        status: parsed.status,
        headers: parsed
            .fields
            .iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).into_owned(),
                    String::from_utf8_lossy(&f.value).into_owned(),
                )
            })
            .collect(),
        body: parsed.body,
    })
}
