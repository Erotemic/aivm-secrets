//! Host-selected mTLS coordinator. No positive admission cache, proxy,
//! redirects, guest-selected principal or retry after an uncertain exchange.
use crate::{files, json, Error, Outcome};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const LIMIT: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(4);

pub(crate) struct Coordinator {
    tls: Arc<ClientConfig>,
    host: String,
    port: u16,
    principal: String,
}
impl Coordinator {
    pub(crate) fn from_file(path: &Path) -> Outcome<Self> {
        let value = json::parse(&files::read_private(path, LIMIT)?, LIMIT)?;
        Self::parse(&value).map_err(|_| Error::InvalidPolicy)
    }
    fn parse(value: &Value) -> Outcome<Self> {
        let m = json::keys(
            value,
            &[
                "schema",
                "host",
                "port",
                "ca_file",
                "certificate_file",
                "key_file",
                "principal",
            ],
            &[],
        )?;
        json::integer(&m["schema"], 1, 1)?;
        let text = |name: &str| m[name].as_str().ok_or(Error::InvalidPolicy);
        let host = text("host")?;
        if host != "localhost" {
            crate::oauth_vault::provider::hostname(host)?;
        }
        let principal = text("principal")?;
        if principal.is_empty()
            || principal.len() > 128
            || !principal.as_bytes()[0].is_ascii_alphanumeric()
            || !principal
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        {
            return Err(Error::InvalidPolicy);
        }
        let mut roots = RootCertStore::empty();
        let anchors = files::read_trusted_public(Path::new(text("ca_file")?), 1048576)?;
        for cert in rustls_pemfile::certs(&mut &*anchors) {
            roots
                .add(cert.map_err(|_| Error::InvalidPolicy)?)
                .map_err(|_| Error::InvalidPolicy)?;
        }
        if roots.is_empty() {
            return Err(Error::InvalidPolicy);
        }
        let pem = files::read_trusted_public(Path::new(text("certificate_file")?), 1048576)?;
        let certificates = rustls_pemfile::certs(&mut &*pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvalidPolicy)?;
        let secret = Zeroizing::new(files::read_private(Path::new(text("key_file")?), 1048576)?);
        let key = rustls_pemfile::private_key(&mut &**secret)
            .map_err(|_| Error::InvalidPolicy)?
            .ok_or(Error::InvalidPolicy)?;
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| Error::InvalidPolicy)?
                .with_root_certificates(roots)
                .with_client_auth_cert(certificates, key)
                .map_err(|_| Error::InvalidPolicy)?;
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        Ok(Self {
            tls: Arc::new(tls),
            host: host.into(),
            port: json::integer(&m["port"], 1, 65535)? as u16,
            principal: principal.into(),
        })
    }
    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }
    pub(crate) fn check(&self) -> Outcome<()> {
        self.call("check", None)
    }
    pub(crate) fn reserve(&self, key: &str, digest: &str) -> Outcome<()> {
        self.call("reserve", Some((key, digest)))
    }
    pub(crate) fn finish(&self, key: &str, digest: &str) -> Outcome<()> {
        self.call("finish", Some((key, digest)))
    }
    fn call(&self, action: &str, write: Option<(&str, &str)>) -> Outcome<()> {
        let mut value = json!({"action":action,"name":self.principal});
        if let Some((key, digest)) = write {
            value["key"] = json!(json::hex(&json!(key), 64).map_err(|_| Error::Revoked)?);
            value["digest"] = json!(json::hex(&json!(digest), 64).map_err(|_| Error::Revoked)?);
        }
        let reply = self.exchange(&value, Error::Revoked, Error::Revoked)?;
        acknowledge(action, &reply)
    }
    pub(crate) fn operator(
        &self,
        action: aivm_secrets_garrett_core::coordinator_authority::Action,
        members: Option<&[String]>,
    ) -> Outcome<Value> {
        use aivm_secrets_garrett_core::coordinator_authority::Action;
        let name = match action {
            Action::Activate => "activate",
            Action::Revoke => "revoke",
            Action::Status => "status",
            _ => return Err(Error::InvalidRequest),
        };
        let mut value = json!({"action":name,"name":self.principal});
        if matches!(action, Action::Activate) {
            let members = members.ok_or(Error::InvalidRequest)?;
            if members.is_empty() || members.len() > 32 {
                return Err(Error::InvalidRequest);
            }
            let mut names = members
                .iter()
                .map(|v| json::hex(&json!(v), 64).map_err(|_| Error::InvalidRequest))
                .collect::<Outcome<Vec<_>>>()?;
            names.sort();
            if names.windows(2).any(|v| v[0] == v[1]) {
                return Err(Error::InvalidRequest);
            }
            value["members"] = json!(names);
        } else if members.is_some() {
            return Err(Error::InvalidRequest);
        }
        let bad = if matches!(action, Action::Status) {
            Error::UpstreamResponse
        } else {
            Error::OutcomeUnknown
        };
        let reply = self.exchange(&value, Error::Unreachable, bad)?;
        operator_reply(action, reply, bad)
    }
    fn exchange(&self, value: &Value, before: Error, after: Error) -> Outcome<Value> {
        let body = json::canonical(value);
        if body.len() > LIMIT {
            return Err(before);
        }
        let mut bytes = format!("POST /v1/coordinate HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", self.host,self.port,body.len()).into_bytes();
        bytes.extend_from_slice(&body);
        let started = Instant::now();
        let host = self.host.clone();
        let port = self.port;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let addresses = (host.as_str(), port)
                .to_socket_addrs()
                .map(|a| a.take(16).collect::<Vec<SocketAddr>>());
            let _ = sender.send(addresses);
        });
        let addresses = receiver
            .recv_timeout(TIMEOUT)
            .map_err(|_| before)?
            .map_err(|_| before)?;
        let mut connected = None;
        for address in addresses {
            let remaining = TIMEOUT.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            if let Ok(socket) = TcpStream::connect_timeout(&address, remaining) {
                connected = Some(socket);
                break;
            }
        }
        let mut socket = connected.ok_or(before)?;
        let remaining = TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(before);
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| before)?;
        socket
            .set_write_timeout(Some(remaining))
            .map_err(|_| before)?;
        let killer = socket.try_clone().map_err(|_| before)?;
        let _deadline = crate::tls::Deadline::start_for(remaining, move || {
            let _ = killer.shutdown(std::net::Shutdown::Both);
        });
        let name =
            rustls::pki_types::ServerName::try_from(self.host.clone()).map_err(|_| before)?;
        let mut connection = ClientConnection::new(self.tls.clone(), name).map_err(|_| before)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket).map_err(|_| before)?;
        }
        let mut stream = StreamOwned::new(connection, socket);
        stream
            .write_all(&bytes)
            .and_then(|_| stream.flush())
            .map_err(|_| after)?;
        response(BufReader::new(stream)).map_err(|_| after)
    }
}

fn operator_reply(
    action: aivm_secrets_garrett_core::coordinator_authority::Action,
    value: Value,
    bad: Error,
) -> Outcome<Value> {
    if value.get("ok") == Some(&json!(false)) {
        json::keys(&value, &["ok", "code"], &[]).map_err(|_| bad)?;
        return Err(match value["code"].as_str() {
            Some("denied") => Error::Denied,
            Some("revoked") => Error::Revoked,
            Some("invalid_request") => Error::InvalidRequest,
            Some("outcome_unknown") => Error::OutcomeUnknown,
            _ => bad,
        });
    }
    let m = json::keys(&value, &["ok", "active", "revision"], &[]).map_err(|_| bad)?;
    if m["ok"] != json!(true) {
        return Err(bad);
    }
    let active = m["active"].as_bool().ok_or(bad)?;
    let revision = if m["revision"].is_null() {
        None
    } else {
        Some(json::integer(&m["revision"], 1, i64::MAX).map_err(|_| bad)?)
    };
    if !aivm_secrets_garrett_core::coordinator_authority::operator_acknowledged(
        action, active, revision,
    ) {
        return Err(bad);
    }
    Ok(value)
}

fn line(reader: &mut impl BufRead, maximum: usize) -> Outcome<String> {
    let mut bytes = Vec::new();
    reader
        .take((maximum + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| Error::Revoked)?;
    if bytes.len() > maximum || !bytes.ends_with(b"\r\n") {
        return Err(Error::Revoked);
    }
    bytes.truncate(bytes.len() - 2);
    String::from_utf8(bytes).map_err(|_| Error::Revoked)
}
fn response(mut reader: impl BufRead) -> Outcome<Value> {
    let status = line(&mut reader, 256)?;
    if !(status.starts_with("HTTP/1.1 200 ") || status.starts_with("HTTP/1.0 200 ")) {
        return Err(Error::Revoked);
    }
    let mut headers = BTreeMap::new();
    let mut used = 0;
    loop {
        let header = line(&mut reader, 1024)?;
        used += header.len() + 2;
        if used > LIMIT {
            return Err(Error::Revoked);
        }
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').ok_or(Error::Revoked)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !value.bytes().all(|b| (32..=126).contains(&b))
            || headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
        {
            return Err(Error::Revoked);
        }
    }
    if headers.get("content-type").map(String::as_str) != Some("application/json")
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("content-encoding")
    {
        return Err(Error::Revoked);
    }
    let length = headers.get("content-length").ok_or(Error::Revoked)?;
    if length.is_empty() || length.len() > 4 || !length.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Revoked);
    }
    let size = length.parse::<usize>().map_err(|_| Error::Revoked)?;
    if size == 0 || size > LIMIT {
        return Err(Error::Revoked);
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body).map_err(|_| Error::Revoked)?;
    json::parse(&body, LIMIT).map_err(|_| Error::Revoked)
}
fn acknowledge(action: &str, value: &Value) -> Outcome<()> {
    if value.get("ok") == Some(&json!(false)) {
        return Err(
            if value.get("code").and_then(Value::as_str) == Some("outcome_unknown") {
                Error::OutcomeUnknown
            } else {
                Error::Revoked
            },
        );
    }
    if value.get("ok") != Some(&json!(true)) {
        return Err(Error::Revoked);
    }
    use aivm_secrets_garrett_core::coordinator_authority::{member_acknowledged, Action};
    let (phase, fields, flag) = match action {
        "check" => (Action::Check, &["ok", "active", "revision"][..], "active"),
        "reserve" => (Action::Reserve, &["ok", "reserved"][..], "reserved"),
        "finish" => (Action::Finish, &["ok", "recorded"][..], "recorded"),
        _ => return Err(Error::Revoked),
    };
    json::keys(value, fields, &[]).map_err(|_| Error::Revoked)?;
    let revision = match value.get("revision") {
        None => None,
        Some(revision) => Some(json::integer(revision, 0, i64::MAX).map_err(|_| Error::Revoked)?),
    };
    // The acknowledgement decision is the extracted `member_acknowledged`.
    if !member_acknowledged(phase, value[flag] == json!(true), revision) {
        return Err(Error::Revoked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Legacy generic coordination contract fixture; production manifest
    // dispatch uses the owned controller in garrett-core::dispatch.
    pub(crate) struct PendingDispatch<C, R, E, F> {
        pub(crate) check: C,
        pub(crate) reserve: R,
        pub(crate) emit: E,
        pub(crate) finish: F,
    }
    impl<C, R, E, F> aivm_secrets_garrett_core::coordination::Dispatch for PendingDispatch<C, R, E, F>
    where
        C: Fn() -> Outcome<()>,
        R: Fn() -> Outcome<()>,
        E: Fn() -> Outcome<Value>,
        F: Fn() -> Outcome<()>,
    {
        type Output = Value;
        type Error = Error;
        fn check(&self) -> Outcome<()> {
            (self.check)()
        }
        fn reserve(&self) -> Outcome<()> {
            (self.reserve)()
        }
        fn emit(&self) -> Outcome<Value> {
            (self.emit)()
        }
        fn finish(&self) -> Outcome<()> {
            (self.finish)()
        }
        fn outcome_unknown(&self) -> Error {
            Error::OutcomeUnknown
        }
    }

    #[test]
    fn admission_requires_a_complete_typed_acknowledgement() {
        assert!(acknowledge("check", &json!({"ok":true,"active":true,"revision":1})).is_ok());
        assert!(acknowledge("reserve", &json!({"ok":true,"reserved":true})).is_ok());
        assert!(acknowledge("finish", &json!({"ok":true,"recorded":true})).is_ok());
        for value in [
            json!({"ok":true}),
            json!({"ok":1,"active":true,"revision":1}),
            json!({"ok":true,"active":false,"revision":1}),
            json!({"ok":true,"active":true,"revision":0}),
            json!({"ok":true,"active":true,"revision":true}),
            json!({"ok":true,"active":true,"revision":1,"secret":"untrusted"}),
        ] {
            assert_eq!(acknowledge("check", &value), Err(Error::Revoked));
        }
        assert_eq!(
            acknowledge("reserve", &json!({"ok":false,"code":"outcome_unknown"})),
            Err(Error::OutcomeUnknown)
        );
        assert_eq!(
            acknowledge(
                "check",
                &json!({"ok":false,"code":"arbitrary private text"})
            ),
            Err(Error::Revoked)
        );
    }

    #[test]
    fn coordinator_response_framing_refuses_ambiguous_or_unbounded_input() {
        let valid =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(response(valid.as_bytes()), Ok(json!({})));
        for raw in [
            valid.replace("200 OK", "302 Redirect"),
            valid.replace(
                "Content-Length: 2",
                "Content-Length: 2\r\ncontent-length: 2",
            ),
            valid.replace(
                "Content-Length: 2",
                "Content-Length: 2\r\nTransfer-Encoding: chunked",
            ),
            valid.replace(
                "Content-Length: 2",
                "Content-Length: 2\r\nContent-Encoding: gzip",
            ),
            valid.replace("Content-Length: 2", "Content-Length: 4097"),
            valid.replace("Content-Length: 2", "Content-Length: 3"),
            valid.replace("application/json", "text/plain"),
            valid.replace("\r\n", "\n"),
            valid.replace("{}", "x}"),
        ] {
            assert_eq!(response(raw.as_bytes()), Err(Error::Revoked));
        }
    }

    #[test]
    fn keyed_dispatch_calls_each_phase_once_and_quarantines_uncertain_completion() {
        use std::cell::RefCell;
        let events = RefCell::new(Vec::new());
        let ops = PendingDispatch {
            check: || {
                events.borrow_mut().push("check");
                Ok(())
            },
            reserve: || {
                events.borrow_mut().push("reserve");
                Ok(())
            },
            emit: || {
                events.borrow_mut().push("emit");
                Ok(json!(7))
            },
            finish: || {
                events.borrow_mut().push("finish");
                Err(Error::Revoked)
            },
        };
        assert_eq!(
            aivm_secrets_garrett_core::coordination::dispatch(&ops, true),
            Err(Error::OutcomeUnknown)
        );
        assert_eq!(&*events.borrow(), &["check", "reserve", "emit", "finish"]);
        events.borrow_mut().clear();
        let refusal = PendingDispatch {
            check: || {
                events.borrow_mut().push("check");
                Ok(())
            },
            reserve: || Err(Error::OutcomeUnknown),
            emit: || {
                events.borrow_mut().push("unexpected emit");
                Ok(json!(7))
            },
            finish: || {
                events.borrow_mut().push("unexpected finish");
                Ok(())
            },
        };
        assert_eq!(
            aivm_secrets_garrett_core::coordination::dispatch(&refusal, true),
            Err(Error::OutcomeUnknown)
        );
        assert_eq!(&*events.borrow(), &["check"]);
    }
}
