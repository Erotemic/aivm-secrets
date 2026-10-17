//! Host-only authorization-code acquisition. The authorization URL is the only
//! browser disclosure: verifier, returned code and grants stay in private types.
use super::*;
use aivm_secrets_garrett_core::oauth_login as flow;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read},
    net::{Ipv4Addr, TcpListener, TcpStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn stamp() -> Outcome<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Expired)?
            .as_secs(),
    )
    .map_err(|_| Error::Expired)
}
fn error(code: Error, reason: &'static str) -> OAuthError {
    OAuthError { code, reason }
}
fn transition(error: flow::LoginDenial) -> OAuthError {
    match error {
        flow::LoginDenial::Expired => Error::Expired.into(),
        _ => Error::CredentialSource.into(),
    }
}
struct Pending {
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
    redirect: String,
    binding: flow::Pending,
    stage: flow::Stage,
}
impl Pending {
    fn new(provider: &Provider, timeout: i64) -> Outcome<Self> {
        let now = stamp()?;
        if !(1..=600).contains(&timeout) || now > i64::MAX - 600 {
            return Err(Error::InvalidRequest);
        }
        let state = Zeroizing::new(URL_SAFE_NO_PAD.encode(random::<32>()?));
        let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(random::<32>()?));
        let profile = provider.public_profile();
        let issuer = text(&profile, "issuer_response")?;
        Ok(Self {
            binding: flow::Pending {
                state: state.as_bytes().to_vec(),
                issuer: if issuer.is_empty() {
                    flow::IssuerRule::Absent
                } else {
                    flow::IssuerRule::Exact(issuer.as_bytes().to_vec())
                },
                issued_at: now,
                expires_at: now + timeout,
            },
            redirect: format!(
                "http://127.0.0.1:{}/oauth/callback",
                profile["callback_port"]
            ),
            state,
            verifier,
            stage: flow::Stage::Pending,
        })
    }
    fn contract_value(&self) -> Value {
        json!({"state":&*self.state,"verifier":&*self.verifier,"redirect_uri":self.redirect,
            "issued_at":self.binding.issued_at,"expires_at":self.binding.expires_at})
    }
    fn url(&self, provider: &Provider) -> Outcome<String> {
        let challenge =
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, self.verifier.as_bytes()));
        let scopes = provider.scopes.join(" ");
        let query = transport::form(&[
            ("response_type", "code"),
            ("client_id", &provider.client_id),
            ("redirect_uri", &self.redirect),
            ("scope", &scopes),
            ("state", &self.state),
            ("code_challenge_method", "S256"),
            ("code_challenge", &challenge),
        ])?;
        Ok(format!(
            "{}?{}",
            text(&provider.public_profile(), "authorization_url")?,
            std::str::from_utf8(&query).map_err(|_| Error::CredentialSource)?
        ))
    }
}

impl Grant {
    fn initial(provider: &Provider, response: &Value, now: i64) -> Outcome<Self> {
        let meta = oauth::evaluate(&json!({"version":1,"action":"token","response":response,
            "allowed_scopes":provider.scopes,"now":now,"fallback_ttl":provider.fallback_ttl}))?;
        Ok(Self {
            access: Zeroizing::new(text(response, "access_token")?.into()),
            refresh: response
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(|v| Zeroizing::new(v.into())),
            expires: integer(&meta, "expires_at")?,
            scopes: scope_list(&meta["scopes"])?,
            generation: integer(&meta, "generation")?,
        })
    }
}

impl OAuthVault {
    /// Bind before announcing the URL. The callback receives only a host-facing
    /// event; it cannot select the token origin, return a code or access PKCE.
    pub fn login(
        &self,
        provider: &Provider,
        subject: &str,
        replace: bool,
        timeout: i64,
        transport: &Value,
        announce: impl FnOnce(&Value) -> Outcome<()>,
    ) -> OAuthOutcome<Value> {
        self.can_enroll(provider, subject, replace)?;
        let endpoint = TokenEndpoint::new(provider, transport)?;
        let secret = provider.client_secret()?;
        let mut pending = Pending::new(provider, timeout)?;
        let port = provider.public_profile()["callback_port"]
            .as_u64()
            .ok_or(Error::InvalidRequest)? as u16;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .map_err(|_| error(Error::CredentialSource, "callback_port_unavailable"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::CredentialSource)?;
        let deadline = Instant::now() + Duration::from_secs(timeout as u64);
        announce(
            &json!({"version":1,"event":"authorization_required","authorization_url":pending.url(provider)?,
                         "expires_at":pending.binding.expires_at}),
        )?;
        let code = wait(listener, provider, &mut pending, deadline)?;
        let now = stamp()?;
        pending.stage = flow::begin(&pending.stage, &pending.binding, now).map_err(transition)?;
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", &*code),
            ("redirect_uri", &pending.redirect),
            ("client_id", &provider.client_id),
            ("code_verifier", &*pending.verifier),
        ];
        if let Some(secret) = &secret {
            fields.push(("client_secret", secret));
        }
        let form = transport::form(&fields)
            .map_err(|_| error(Error::CredentialSource, "exchange_not_sent"))?;
        let received = endpoint.post(&form);
        let response = match received {
            Ok(response) => response,
            Err(failure) => {
                pending.stage = flow::finish(&pending.stage, false).map_err(transition)?;
                return Err(error(
                    Error::CredentialSource,
                    match failure {
                        core::ExchangeFailure::NotSent => "exchange_not_sent",
                        core::ExchangeFailure::Rejected => "exchange_rejected",
                        core::ExchangeFailure::Uncertain => "exchange_in_doubt",
                    },
                ));
            }
        };
        let grant = Grant::initial(provider, &response, now)
            .map_err(|_| error(Error::CredentialSource, "exchange_in_doubt"))?;
        let installed_at = stamp().map_err(|code| error(code, "grant_orphaned_upstream"))?;
        let result = self.enroll_grant(provider, subject, &grant, replace, installed_at);
        pending.stage = flow::finish(&pending.stage, result.is_ok()).map_err(transition)?;
        result.map_err(|code| error(code, "grant_orphaned_upstream"))
    }
}

fn wait(
    listener: TcpListener,
    provider: &Provider,
    pending: &mut Pending,
    deadline: Instant,
) -> OAuthOutcome<Zeroizing<String>> {
    let profile = provider.public_profile();
    let issuer = text(&profile, "issuer_response")?;
    let port = profile["callback_port"]
        .as_u64()
        .ok_or(Error::InvalidRequest)?;
    loop {
        if Instant::now() >= deadline || stamp()? >= pending.binding.expires_at {
            return Err(Error::Expired.into());
        }
        let mut socket = match listener.accept() {
            Ok((socket, address)) if address.ip().is_loopback() => socket,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(_) => return Err(Error::CredentialSource.into()),
        };
        let allowance = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        if allowance.is_zero() {
            return Err(Error::Expired.into());
        }
        socket
            .set_read_timeout(Some(allowance))
            .map_err(|_| Error::CredentialSource)?;
        socket
            .set_write_timeout(Some(allowance))
            .map_err(|_| Error::CredentialSource)?;
        let killer = socket.try_clone().map_err(|_| Error::CredentialSource)?;
        let _deadline = crate::tls::Deadline::start_for(allowance, move || {
            let _ = killer.shutdown(std::net::Shutdown::Both);
        });
        let fields = request(&mut socket, port);
        let mut accepted = None;
        if let Ok(fields) = fields {
            if let Ok(stage) = oauth::callback(
                &pending.contract_value(),
                &fields,
                stamp()?,
                issuer,
                &pending.stage,
            ) {
                // Consumption precedes the browser acknowledgement. A failed
                // write must not reopen this pending authorization for replay.
                let denied = matches!(stage, flow::Stage::Denied);
                pending.stage = stage;
                accepted = Some(if denied {
                    None
                } else {
                    Some(Zeroizing::new(text(&fields, "code")?.into()))
                });
            }
        }
        let (status, body) = match &accepted {
            Some(Some(_)) => (200, "Authorization received. You may close this tab."),
            Some(None) => (200, "Authorization was declined. Return to the terminal."),
            None => (400, "Authorization rejected."),
        };
        let reply = format!("HTTP/1.1 {status} Result\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let _ = socket
            .write_all(reply.as_bytes())
            .and_then(|_| socket.flush());
        if let Some(code) = accepted {
            // Dropping the listener before redeeming also closes queued replays.
            return code.ok_or_else(|| error(Error::AuthorizationDenied, "authorization_denied"));
        }
    }
}
fn line(reader: &mut impl BufRead, limit: usize) -> Outcome<Vec<u8>> {
    let mut raw = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut raw)
        .map_err(|_| Error::CredentialSource)?;
    if raw.len() > limit || !raw.ends_with(b"\r\n") {
        return Err(Error::CredentialSource);
    }
    raw.truncate(raw.len() - 2);
    Ok(raw)
}
fn request(socket: &mut TcpStream, port: u64) -> Outcome<Value> {
    let mut reader = BufReader::new(socket);
    let raw = Zeroizing::new(line(&mut reader, 32768)?);
    if !raw.is_ascii() {
        return Err(Error::CredentialSource);
    }
    let first = std::str::from_utf8(&raw).map_err(|_| Error::CredentialSource)?;
    let parts: Vec<_> = first.split(' ').collect();
    if parts.len() != 3 || parts[0] != "GET" || !matches!(parts[2], "HTTP/1.1" | "HTTP/1.0") {
        return Err(Error::CredentialSource);
    }
    let target = parts[1];
    if !target.bytes().all(|b| (33..=126).contains(&b)) || target.contains(['#', '\\']) {
        return Err(Error::CredentialSource);
    }
    let query = target
        .strip_prefix("/oauth/callback?")
        .ok_or(Error::CredentialSource)?;
    let mut headers = BTreeMap::new();
    let mut size = 0;
    loop {
        let row = line(&mut reader, 16384 - size)?;
        size += row.len() + 2;
        if row.is_empty() {
            break;
        }
        if size >= 16384 {
            return Err(Error::CredentialSource);
        }
        let row = std::str::from_utf8(&row).map_err(|_| Error::CredentialSource)?;
        let (name, value) = row.split_once(':').ok_or(Error::CredentialSource)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
        {
            return Err(Error::CredentialSource);
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err(Error::CredentialSource);
        }
    }
    if headers.get("host") != Some(&format!("127.0.0.1:{port}"))
        || headers.contains_key("transfer-encoding")
        || headers.get("content-length").is_some_and(|v| v != "0")
    {
        return Err(Error::CredentialSource);
    }
    let mut fields = serde_json::Map::new();
    for pair in query.split('&') {
        if fields.len() >= 5 {
            return Err(Error::CredentialSource);
        }
        let (name, value) = pair.split_once('=').ok_or(Error::CredentialSource)?;
        let name = transport::decode(name.as_bytes())?;
        let value = transport::decode(value.as_bytes())?;
        if fields.insert(name, json!(value)).is_some() {
            return Err(Error::CredentialSource);
        }
    }
    Ok(Value::Object(fields))
}
