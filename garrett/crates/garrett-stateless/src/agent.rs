//! The agent side: mTLS calls to a broker and requests through a proxy.
//! The agent holds surrogates only; no call here can return a provider
//! credential, because none is ever sent to it.
use crate::broker::{IssuedToken, LoginStarted};
use crate::config::HttpsUrl;
use crate::error::{Error, Result};
use crate::http::{self, Response};
use crate::json::{self, Value};
use crate::tls::{self, ClientIdentity};
use rustls::ClientConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Where to reach a broker's agent API or a proxy.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// The URL's authority, sent as `Host` and verified as the TLS name.
    pub url: HttpsUrl,
    /// `host:port` to connect to (defaults to the URL's).
    pub connect: String,
}

impl Endpoint {
    pub fn parse(url: &str, connect: Option<&str>) -> Result<Self> {
        let url = HttpsUrl::parse(url)?;
        let connect = connect
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{}:{}", url.host, url.port));
        Ok(Self { url, connect })
    }
}

pub struct Agent {
    tls: Arc<ClientConfig>,
}

fn body_value(response: &Response) -> Result<Value> {
    json::parse(&response.body, 1 << 20, 8).map_err(|_| Error::Protocol("invalid_response"))
}

fn refusal(response: &Response) -> Error {
    let code = body_value(response)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned));
    Error::Protocol(match code.as_deref() {
        Some("wrong_certificate") => "wrong_certificate",
        Some("login_denied") => "login_denied",
        Some("login_failed") => "login_failed",
        Some("login_expired") => "login_expired",
        Some("login_unknown") => "login_unknown",
        Some("unknown_provider") => "unknown_provider",
        Some("invalid_scope") => "invalid_scope",
        Some("invalid_token") => "invalid_token",
        Some("too_many_logins") => "too_many_logins",
        _ => "broker_error",
    })
}

/// A broker's issuance reply: the surrogate and both of its limits. A reply
/// without either limit is refused rather than read as time 0.
fn issued(value: &Value) -> Result<IssuedToken> {
    let invalid = || Error::Protocol("invalid_response");
    let token = value.get("token").and_then(Value::as_str).ok_or_else(invalid)?;
    let expires_at = value.get("expires_at").and_then(Value::as_int).ok_or_else(invalid)?;
    let renew_until = value.get("renew_until").and_then(Value::as_int).ok_or_else(invalid)?;
    Ok(IssuedToken {
        token: token.to_owned(),
        expires_at,
        renew_until,
    })
}

impl Agent {
    /// `server_ca` authenticates the broker and proxy; `identity` is the
    /// agent's certificate and key (software or TPM).
    pub fn new(server_ca: &[u8], identity: ClientIdentity) -> Result<Self> {
        Ok(Self {
            tls: tls::agent_client(server_ca, identity)?,
        })
    }

    fn call(
        &self,
        endpoint: &Endpoint,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response> {
        let request = http::request_bytes(method, target, &endpoint.url.authority(), headers, body);
        let raw = http::exchange(
            self.tls.clone(),
            &endpoint.connect,
            &endpoint.url.host,
            &request,
            32 << 20,
        )?;
        http::parse_response(&raw, method == "HEAD", 32 << 20)
    }

    fn json_call(
        &self,
        endpoint: &Endpoint,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Response> {
        let bytes = match body {
            Some(value) => {
                json::canonical(&value).map_err(|_| Error::Protocol("invalid_request"))?
            }
            None => Vec::new(),
        };
        let target = format!("{}{}", endpoint.url.path.trim_end_matches('/'), path);
        self.call(
            endpoint,
            method,
            &target,
            &[("Content-Type", "application/json")],
            &bytes,
        )
    }

    /// Ask the broker to start a login for `provider`.
    pub fn begin_login(
        &self,
        broker: &Endpoint,
        provider: &str,
        scope: Option<&str>,
    ) -> Result<LoginStarted> {
        let mut request = vec![("provider", json::text(provider))];
        if let Some(scope) = scope {
            request.push(("scope", json::text(scope)));
        }
        let value = Value::Object(
            request
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        );
        let response = self.json_call(broker, "POST", "/v1/logins", Some(value))?;
        if response.status != 201 {
            return Err(refusal(&response));
        }
        let value = body_value(&response)?;
        let text = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(Error::Protocol("invalid_response"))
        };
        Ok(LoginStarted {
            login: text("login")?,
            authorization_url: text("authorization_url")?,
            confirmation: text("confirmation")?,
            expires_at: value.get("expires_at").and_then(Value::as_int).unwrap_or(0),
        })
    }

    /// One poll; `None` while the human has not finished.
    pub fn poll(&self, broker: &Endpoint, login: &str, wait: u64) -> Result<Option<IssuedToken>> {
        let response = self.json_call(
            broker,
            "GET",
            &format!("/v1/logins/{login}?wait={wait}"),
            None,
        )?;
        match response.status {
            200 => issued(&body_value(&response)?).map(Some),
            202 => Ok(None),
            _ => Err(refusal(&response)),
        }
    }

    /// Poll until the login completes or `timeout` passes.
    pub fn wait_for_token(
        &self,
        broker: &Endpoint,
        login: &str,
        timeout: Duration,
    ) -> Result<IssuedToken> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
                .min(crate::broker::MAX_WAIT);
            if let Some(token) = self.poll(broker, login, left)? {
                return Ok(token);
            }
            if Instant::now() >= deadline {
                return Err(Error::Protocol("login_pending"));
            }
        }
    }

    /// Exchange a valid surrogate for a fresh one (same binding and credential).
    pub fn renew(&self, broker: &Endpoint, token: &str) -> Result<IssuedToken> {
        let response = self.json_call(
            broker,
            "POST",
            "/v1/renewals",
            Some(json::object([("token", json::text(token))])),
        )?;
        if response.status != 200 {
            return Err(refusal(&response));
        }
        issued(&body_value(&response)?)
    }

    /// An ordinary API request through the proxy, with the surrogate as the
    /// bearer token. `target` is the provider path and query.
    pub fn request(
        &self,
        proxy: &Endpoint,
        token: &str,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response> {
        let authorization = format!("Bearer {token}");
        let mut all: Vec<(&str, &str)> = vec![("Authorization", &authorization)];
        all.extend_from_slice(headers);
        self.call(proxy, method, target, &all, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(text: &str) -> Value {
        json::parse(text.as_bytes(), 1 << 20, 8).ok().unwrap()
    }

    #[test]
    fn an_issuance_reply_needs_both_limits() {
        let full = issued(&reply(r#"{"expires_at":10,"renew_until":20,"token":"t"}"#)).ok().unwrap();
        assert_eq!((full.expires_at, full.renew_until), (10, 20));
        for partial in [
            r#"{"renew_until":20,"token":"t"}"#,
            r#"{"expires_at":10,"token":"t"}"#,
            r#"{"expires_at":"10","renew_until":20,"token":"t"}"#,
        ] {
            assert!(matches!(issued(&reply(partial)), Err(Error::Protocol("invalid_response"))));
        }
    }
}
