//! One host-selected HTTPS token origin. No proxy, redirect, cookie, ambient
//! trust override or reusable authenticated connection. Send evidence is local.
use super::*;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};
const MAX_RESPONSE: usize = 16384;
fn encoded(value: &str, out: &mut Vec<u8>) {
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b),
            b' ' => out.push(b'+'),
            _ => out.extend_from_slice(format!("%{b:02X}").as_bytes()),
        }
    }
}
pub(crate) fn form(fields: &[(&str, &str)]) -> Outcome<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            data.push(b'&');
        }
        encoded(key, &mut data);
        data.push(b'=');
        encoded(value, &mut data);
    }
    if data.len() > 8192 {
        return Err(Error::CredentialSource);
    }
    Ok(data)
}
pub struct TokenEndpoint {
    tls: Arc<ClientConfig>,
    host: String,
    path: String,
    addresses: Vec<SocketAddr>,
}
impl TokenEndpoint {
    pub(crate) fn new(provider: &Provider, config: &Value) -> Outcome<Self> {
        let m = json::keys(config, &[], &["server_ca", "address", "port"])?;
        let port = m
            .get("port")
            .map(|v| json::integer(v, 1, 65535))
            .transpose()?
            .unwrap_or(443) as u16;
        let mut roots = RootCertStore::empty();
        let anchors = if let Some(path) = m.get("server_ca") {
            files::read_trusted_public(
                Path::new(path.as_str().ok_or(Error::CredentialSource)?),
                1048576,
            )?
        } else {
            let mut found = None;
            for path in [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/cert.pem",
            ] {
                if Path::new(path).exists() {
                    found = Some(files::read_trusted_public(Path::new(path), 1048576)?);
                    break;
                }
            }
            found.ok_or(Error::CredentialSource)?
        };
        for cert in rustls_pemfile::certs(&mut &*anchors) {
            roots
                .add(cert.map_err(|_| Error::CredentialSource)?)
                .map_err(|_| Error::CredentialSource)?;
        }
        if roots.is_empty() {
            return Err(Error::CredentialSource);
        }
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| Error::CredentialSource)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        let addresses = if let Some(address) = m.get("address") {
            vec![SocketAddr::new(
                address
                    .as_str()
                    .ok_or(Error::CredentialSource)?
                    .parse::<IpAddr>()
                    .map_err(|_| Error::CredentialSource)?,
                port,
            )]
        } else {
            let (sender, receiver) = mpsc::sync_channel(1);
            let host = provider.token_host.clone();
            std::thread::spawn(move || {
                let result = (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|a| a.take(16).collect::<Vec<_>>());
                let _ = sender.send(result);
            });
            receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| Error::CredentialSource)?
                .map_err(|_| Error::CredentialSource)?
        };
        if addresses.is_empty() {
            return Err(Error::CredentialSource);
        }
        Ok(Self {
            tls: Arc::new(tls),
            host: provider.token_host.clone(),
            path: provider.token_path.clone(),
            addresses,
        })
    }
    /// The same pinned origin, aimed at the provider's revocation endpoint.
    pub(crate) fn for_revocation(mut self, path: &str) -> Self {
        self.path = path.to_owned();
        self
    }
    /// One RFC 7009 request; never fails. `revoked` means the provider
    /// answered 200, `refused` any other answer, `not_sent` that no request
    /// byte left this host, `in_doubt` that it may have arrived.
    pub(crate) fn revoke(&self, form: &[u8]) -> &'static str {
        let mut sent = false;
        let mut attempt = || -> Outcome<i64> {
            let started = Instant::now();
            let mut connected = None;
            for address in &self.addresses {
                let remaining = Duration::from_secs(10).saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    break;
                }
                if let Ok(socket) =
                    TcpStream::connect_timeout(address, remaining.min(Duration::from_secs(5)))
                {
                    connected = Some(socket);
                    break;
                }
            }
            let mut socket = connected.ok_or(Error::CredentialSource)?;
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|_| Error::CredentialSource)?;
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .map_err(|_| Error::CredentialSource)?;
            let killer = socket.try_clone().map_err(|_| Error::CredentialSource)?;
            let _deadline = crate::tls::Deadline::start_for(Duration::from_secs(15), move || {
                let _ = killer.shutdown(std::net::Shutdown::Both);
            });
            let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|_| Error::CredentialSource)?;
            let mut connection = ClientConnection::new(self.tls.clone(), name)
                .map_err(|_| Error::CredentialSource)?;
            while connection.is_handshaking() {
                connection
                    .complete_io(&mut socket)
                    .map_err(|_| Error::CredentialSource)?;
            }
            sent = true;
            let mut stream = StreamOwned::new(connection, socket);
            let mut request=Zeroizing::new(format!("POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nContent-Type: application/x-www-form-urlencoded\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",self.path,self.host,form.len()).into_bytes());
            request.extend_from_slice(form);
            stream
                .write_all(&request)
                .and_then(|_| stream.flush())
                .map_err(|_| Error::CredentialSource)?;
            Ok(response(BufReader::new(stream), true)?.status)
        };
        match attempt() {
            Ok(200) => "revoked",
            Ok(_) => "refused",
            Err(_) if sent => "in_doubt",
            Err(_) => "not_sent",
        }
    }
    pub(crate) fn post(&self, form: &[u8]) -> Result<Value, core::ExchangeFailure> {
        let mut sent = false;
        let mut status = 0;
        let mut invalid_grant = false;
        let mut exchange = || -> Outcome<Value> {
            let started = Instant::now();
            let mut connected = None;
            for address in &self.addresses {
                let remaining = Duration::from_secs(10).saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    break;
                }
                if let Ok(socket) =
                    TcpStream::connect_timeout(address, remaining.min(Duration::from_secs(5)))
                {
                    connected = Some(socket);
                    break;
                }
            }
            let mut socket = connected.ok_or(Error::CredentialSource)?;
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|_| Error::CredentialSource)?;
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .map_err(|_| Error::CredentialSource)?;
            let killer = socket.try_clone().map_err(|_| Error::CredentialSource)?;
            let _deadline = crate::tls::Deadline::start_for(Duration::from_secs(15), move || {
                let _ = killer.shutdown(std::net::Shutdown::Both);
            });
            let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|_| Error::CredentialSource)?;
            let mut connection = ClientConnection::new(self.tls.clone(), name)
                .map_err(|_| Error::CredentialSource)?;
            while connection.is_handshaking() {
                connection
                    .complete_io(&mut socket)
                    .map_err(|_| Error::CredentialSource)?;
            }
            // No request bytes have been written before the verified handshake.
            // From here onward every failure may have spent a rotating token.
            sent = true;
            let mut stream = StreamOwned::new(connection, socket);
            let mut request=Zeroizing::new(format!("POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nContent-Type: application/x-www-form-urlencoded\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",self.path,self.host,form.len()).into_bytes());
            request.extend_from_slice(form);
            stream
                .write_all(&request)
                .and_then(|_| stream.flush())
                .map_err(|_| Error::CredentialSource)?;
            let response = response(BufReader::new(stream), false)?;
            status = response.status;
            if status == 400 {
                if response.content_type == "application/json" {
                    if let Ok(value) = json::parse(&response.body, MAX_RESPONSE) {
                        invalid_grant =
                            value.get("error").and_then(Value::as_str) == Some("invalid_grant");
                    }
                }
                return Err(Error::CredentialSource);
            }
            if status != 200 {
                return Err(Error::CredentialSource);
            }
            let value = match response.content_type.as_str() {
                "application/json" => json::parse(&response.body, MAX_RESPONSE)?,
                "application/x-www-form-urlencoded" => parse_form(&response.body)?,
                _ => return Err(Error::CredentialSource),
            };
            if !value.is_object() || value.get("error").is_some() {
                return Err(Error::CredentialSource);
            }
            Ok(value)
        };
        let result = exchange();
        result.map_err(|_| core::classify(sent, status, invalid_grant))
    }
}
pub(super) fn decode(value: &[u8]) -> Outcome<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'+' => out.push(b' '),
            b'%' => {
                if i + 2 >= value.len() {
                    return Err(Error::CredentialSource);
                }
                let hex = std::str::from_utf8(&value[i + 1..i + 3])
                    .map_err(|_| Error::CredentialSource)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::CredentialSource)?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(|_| Error::CredentialSource)
}
fn parse_form(body: &[u8]) -> Outcome<Value> {
    if !body.is_ascii() {
        return Err(Error::CredentialSource);
    }
    let mut map = serde_json::Map::new();
    for pair in body.split(|b| *b == b'&') {
        if map.len() >= 32 {
            return Err(Error::CredentialSource);
        }
        let split = pair
            .iter()
            .position(|b| *b == b'=')
            .ok_or(Error::CredentialSource)?;
        let key = decode(&pair[..split])?;
        let value = decode(&pair[split + 1..])?;
        let value = if key == "expires_in" {
            json!(value.parse::<i64>().map_err(|_| Error::CredentialSource)?)
        } else {
            json!(value)
        };
        if map.insert(key, value).is_some() {
            return Err(Error::CredentialSource);
        }
    }
    Ok(Value::Object(map))
}
struct Response {
    status: i64,
    content_type: String,
    body: Zeroizing<Vec<u8>>,
}
fn line(reader: &mut impl BufRead, limit: usize) -> Outcome<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| Error::CredentialSource)?;
    if bytes.len() > limit || !bytes.ends_with(b"\r\n") {
        return Err(Error::CredentialSource);
    }
    bytes.truncate(bytes.len() - 2);
    Ok(bytes)
}
/// `allow_empty`: an RFC 7009 revocation reply may have no body; a token
/// reply never may.
fn response(mut reader: impl BufRead, allow_empty: bool) -> Outcome<Response> {
    let raw = line(&mut reader, 4096)?;
    let status = std::str::from_utf8(&raw).map_err(|_| Error::CredentialSource)?;
    let mut fields = status.splitn(3, ' ');
    if !matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(Error::CredentialSource);
    }
    let status = fields.next().ok_or(Error::CredentialSource)?;
    if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::CredentialSource);
    }
    let status = status.parse::<i64>().map_err(|_| Error::CredentialSource)?;
    if !(100..=599).contains(&status) {
        return Err(Error::CredentialSource);
    }
    let mut headers = BTreeMap::new();
    let mut size = 0;
    loop {
        let raw = line(&mut reader, 32768 - size)?;
        size += raw.len() + 2;
        if raw.is_empty() {
            break;
        }
        if size >= 32768 {
            return Err(Error::CredentialSource);
        }
        let header = std::str::from_utf8(&raw).map_err(|_| Error::CredentialSource)?;
        let (name, value) = header.split_once(':').ok_or(Error::CredentialSource)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| (b < 32 && b != 9) || b == 127)
        {
            return Err(Error::CredentialSource);
        }
        let name = name.to_ascii_lowercase();
        // Repeated harmless headers do not override framing/content evidence.
        if headers.contains_key(&name)
            && matches!(
                name.as_str(),
                "content-length" | "transfer-encoding" | "content-type" | "content-encoding"
            )
        {
            return Err(Error::CredentialSource);
        }
        headers.insert(name, value.trim().to_owned());
    }
    if headers
        .get("content-encoding")
        .is_some_and(|s| s != "identity")
    {
        return Err(Error::CredentialSource);
    }
    let content_type = headers
        .get("content-type")
        .and_then(|s| s.split(';').next())
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut body = Zeroizing::new(Vec::new());
    match (
        headers.get("content-length"),
        headers.get("transfer-encoding"),
    ) {
        (Some(length), None) => {
            if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::CredentialSource);
            }
            let length = length
                .parse::<usize>()
                .map_err(|_| Error::CredentialSource)?;
            if length > MAX_RESPONSE {
                return Err(Error::CredentialSource);
            }
            body.resize(length, 0);
            reader
                .read_exact(&mut body)
                .map_err(|_| Error::CredentialSource)?;
        }
        (None, Some(encoding)) if encoding == "chunked" => loop {
            let raw = line(&mut reader, 32)?;
            if raw.is_empty() || !raw.iter().all(u8::is_ascii_hexdigit) {
                return Err(Error::CredentialSource);
            }
            let size = usize::from_str_radix(
                std::str::from_utf8(&raw).map_err(|_| Error::CredentialSource)?,
                16,
            )
            .map_err(|_| Error::CredentialSource)?;
            if size == 0 {
                if !line(&mut reader, 2)?.is_empty() {
                    return Err(Error::CredentialSource);
                }
                break;
            }
            if size > MAX_RESPONSE - body.len() {
                return Err(Error::CredentialSource);
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader
                .read_exact(&mut body[start..])
                .map_err(|_| Error::CredentialSource)?;
            if !line(&mut reader, 2)?.is_empty() {
                return Err(Error::CredentialSource);
            }
        },
        (None, None) => {
            reader
                .take((MAX_RESPONSE + 1) as u64)
                .read_to_end(&mut body)
                .map_err(|_| Error::CredentialSource)?;
            if body.len() > MAX_RESPONSE {
                return Err(Error::CredentialSource);
            }
        }
        _ => return Err(Error::CredentialSource),
    }
    if body.is_empty() && !allow_empty {
        return Err(Error::CredentialSource);
    }
    Ok(Response {
        status,
        content_type,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_response_framing_and_form_are_bounded() {
        let fixed =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            response(&fixed[..], false).ok().map(|r| r.body.to_vec()),
            Some(b"{}".to_vec())
        );
        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert!(response(&chunked[..], false).is_ok());
        for raw in [
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nSecret: private\r\n\r\n",
        ] { assert!(response(raw.as_bytes(), false).is_err()); }
        assert_eq!(
            &*form(&[("refresh_token", "a&b=+%")]).unwrap(),
            b"refresh_token=a%26b%3D%2B%25"
        );
        assert!(form(&[("refresh_token", &"x".repeat(8193))]).is_err());
        assert_eq!(
            parse_form(b"access_token=a%2Bb&expires_in=60").unwrap(),
            json!({"access_token":"a+b","expires_in":60})
        );
        assert!(parse_form(b"access_token=a&access_token=b").is_err());
        assert!(parse_form(b"access_token=%zz").is_err());
    }
}
