//! The OAuth broker (spec sections 7 and 8).
//!
//! Every decision is an extracted `stateless`/`stateless_login` controller,
//! and the transient mailbox is the extracted `stateless_mailbox`, changed
//! only through its transitions. This module supplies randomness, the clock,
//! sealing, the token request, and serves the two HTTPS listeners.
use crate::config::{BrokerConfig, ProviderConfig};
use crate::encoding::{is_credential, is_scope, random_id};
use crate::error::{rejection_name, Error, Result};
use crate::files::{read_private, read_public};
use crate::http::{self, Request};
use crate::json::{self, Value};
use crate::keys::BrokerKeys;
use crate::login;
use crate::tls::{self, PeerIdentity};
use crate::token::{self, Informational, Opener, Sealer};
use aivm_secrets_garrett_core::oauth_login::{IssuerRule, LoginDenial};
use aivm_secrets_garrett_core::stateless::{self, Acceptance, Grant, IssuePolicy, MAX_TIME};
use aivm_secrets_garrett_core::stateless_login::LoginPolicy;
use aivm_secrets_garrett_core::stateless_mailbox::{
    self, CodeExchange, Mailbox, MailboxError, Polled, Token,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// The longest an agent's poll waits for a pending login.
pub const MAX_WAIT: u64 = 30;
const MAX_CONNECTIONS: usize = 64;

/// What the token endpoint returned, after validation (spec section 8.1 step 7).
pub struct TokenResponse {
    pub access_token: Zeroizing<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

/// The authorization-code exchange. The default is [`HttpsTokenEndpoint`];
/// tests and alternative providers can supply their own.
pub trait TokenEndpoint: Send + Sync {
    fn exchange(&self, provider: &ProviderConfig, form: &str) -> Result<TokenResponse>;
}

/// Validate a token endpoint's JSON body.
pub fn token_response(status: u16, body: &[u8]) -> Result<TokenResponse> {
    if status != 200 {
        return Err(Error::Protocol("token_rejected"));
    }
    let value = json::parse(body, 65536, 8).map_err(|_| Error::Protocol("token_invalid"))?;
    let access = value
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or(Error::Protocol("token_invalid"))?;
    if !is_credential(access.as_bytes()) {
        return Err(Error::Protocol("token_invalid"));
    }
    let kind = value
        .get("token_type")
        .and_then(Value::as_str)
        .ok_or(Error::Protocol("token_invalid"))?;
    if !kind.eq_ignore_ascii_case("bearer") {
        return Err(Error::Protocol("token_invalid"));
    }
    let expires_in = match value.get("expires_in") {
        None | Some(Value::Null) => None,
        Some(Value::Int(seconds)) if *seconds >= 1 => Some(*seconds),
        Some(_) => return Err(Error::Protocol("token_invalid")),
    };
    let scope = value
        .get("scope")
        .and_then(Value::as_str)
        .filter(|s| is_scope(s))
        .map(str::to_owned);
    // A refresh_token, if any, is dropped here: never stored, never sealed.
    Ok(TokenResponse {
        access_token: Zeroizing::new(access.to_owned()),
        expires_in,
        scope,
    })
}

/// The broker's side of one permitted code exchange: the token request to the
/// provider the permit names, with the login's verifier.
struct ProviderExchange<'a> {
    broker: &'a Broker,
    scope: Option<String>,
    error: Option<Error>,
}

impl CodeExchange for ProviderExchange<'_> {
    fn token(&mut self, provider: &[u8], code: &[u8], verifier: &[u8]) -> Option<Token> {
        let attempt = (|| {
            let name =
                std::str::from_utf8(provider).map_err(|_| Error::Protocol("unknown_provider"))?;
            let (index, config) = self.broker.provider(name)?;
            let code =
                std::str::from_utf8(code).map_err(|_| Error::Protocol("invalid_callback"))?;
            let verifier = Zeroizing::new(
                std::str::from_utf8(verifier)
                    .map_err(|_| Error::Protocol("internal_error"))?
                    .to_owned(),
            );
            let redirect = self.broker.redirect_uri();
            let mut fields = vec![
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect.as_str()),
                ("client_id", config.client_id.as_str()),
                ("code_verifier", verifier.as_str()),
            ];
            if let Some(secret) = &self.broker.secrets[index] {
                fields.push(("client_secret", secret.as_str()));
            }
            let form = Zeroizing::new(http::form(&fields));
            self.broker.endpoint.exchange(config, &form)
        })();
        match attempt {
            Ok(response) => {
                self.scope = response.scope.clone();
                Some(Token {
                    credential: response.access_token.as_bytes().to_vec(),
                    has_expires_in: response.expires_in.is_some(),
                    expires_in: response.expires_in.unwrap_or(0),
                })
            }
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }
}

/// POST the form to the provider's pinned token endpoint.
pub struct HttpsTokenEndpoint;

impl TokenEndpoint for HttpsTokenEndpoint {
    fn exchange(&self, provider: &ProviderConfig, form: &str) -> Result<TokenResponse> {
        let ca = match &provider.token_ca_file {
            Some(path) => Some(read_public(path, 1 << 20)?),
            None => None,
        };
        let config = tls::upstream_client(ca.as_deref())?;
        let url = &provider.token_url;
        let address = provider
            .token_address
            .clone()
            .unwrap_or_else(|| format!("{}:{}", url.host, url.port));
        let request = http::request_bytes(
            "POST",
            &url.path,
            &url.authority(),
            &[
                ("Accept", "application/json"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            form.as_bytes(),
        );
        let raw = Zeroizing::new(http::exchange(
            config,
            &address,
            &url.host,
            &request,
            1 << 20,
        )?);
        let response = http::parse_response(&raw, false, 1 << 20)?;
        token_response(response.status, &response.body)
    }
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A started login, as returned to the agent.
#[derive(Clone, Debug)]
pub struct LoginStarted {
    pub login: String,
    pub authorization_url: String,
    pub confirmation: String,
    pub expires_at: i64,
}

/// An issued surrogate.
#[derive(Clone, Debug)]
pub struct IssuedToken {
    pub token: String,
    pub expires_at: i64,
    pub renew_until: i64,
}

/// The answer to an agent's poll.
#[derive(Debug)]
pub enum Poll {
    Pending,
    Ready(IssuedToken),
    Refused(u16, &'static str),
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct Broker {
    config: BrokerConfig,
    keys: BrokerKeys,
    mailbox: Mutex<Mailbox>,
    endpoint: Box<dyn TokenEndpoint>,
    secrets: Vec<Option<Zeroizing<String>>>,
    clock: Clock,
}

fn denial(denial: LoginDenial) -> Error {
    Error::Protocol(match denial {
        LoginDenial::Invalid => "invalid_callback",
        LoginDenial::Expired => "login_expired",
        LoginDenial::Consumed => "login_consumed",
    })
}

/// The stable public code of a refused mailbox transition.
fn mailbox_error(error: MailboxError) -> Error {
    match error {
        MailboxError::Rejected(rejection) => Error::Rejected(rejection_name(&rejection)),
        MailboxError::Refused(refused) => denial(refused),
        MailboxError::TooMany => Error::Protocol("too_many_logins"),
        MailboxError::Duplicate | MailboxError::Exhausted => Error::Protocol("internal_error"),
        MailboxError::Unknown => Error::Protocol("login_unknown"),
        MailboxError::Consumed => Error::Protocol("login_consumed"),
        MailboxError::Expired => Error::Protocol("login_expired"),
        MailboxError::Denied => Error::Protocol("login_denied"),
    }
}

impl Broker {
    pub fn new(
        config: BrokerConfig,
        keys: BrokerKeys,
        endpoint: Box<dyn TokenEndpoint>,
    ) -> Result<Self> {
        if keys.active_entry().issuer != config.issuer {
            return Err(Error::Config(
                "the active key is not for the broker's issuer".into(),
            ));
        }
        let mut secrets = Vec::new();
        for provider in &config.providers {
            secrets.push(match &provider.client_secret_file {
                Some(path) => {
                    let bytes = Zeroizing::new(read_private(path, 4096)?);
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| Error::Config("client secret".into()))?;
                    Some(Zeroizing::new(text.trim().to_owned()))
                }
                None => None,
            });
        }
        Ok(Self {
            config,
            keys,
            mailbox: Mutex::new(stateless_mailbox::empty()),
            endpoint,
            secrets,
            clock: Arc::new(now_seconds),
        })
    }

    /// A broker from its configuration file and the HTTPS token endpoint.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let config = BrokerConfig::load(path)?;
        let keys = BrokerKeys::load(&config.keys)?;
        Self::new(config, keys, Box::new(HttpsTokenEndpoint))
    }

    /// Replace the clock (tests, conformance).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn config(&self) -> &BrokerConfig {
        &self.config
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Mailbox>> {
        self.mailbox
            .lock()
            .map_err(|_| Error::Protocol("internal_error"))
    }

    fn provider(&self, name: &str) -> Result<(usize, &ProviderConfig)> {
        self.config
            .providers
            .iter()
            .enumerate()
            .find(|(_, p)| p.name == name)
            .ok_or(Error::Protocol("unknown_provider"))
    }

    fn names(&self) -> Vec<Vec<u8>> {
        self.config
            .providers
            .iter()
            .map(|p| p.name.as_bytes().to_vec())
            .collect()
    }

    pub fn issue_policy(&self) -> IssuePolicy {
        IssuePolicy {
            issuer: self.config.issuer.as_bytes().to_vec(),
            audience: self.config.audience.as_bytes().to_vec(),
            providers: self.names(),
            max_lifetime: self.config.max_lifetime,
            max_renew: self.config.max_renew,
        }
    }

    /// What renewal accepts: this broker's own audience and providers.
    pub fn acceptance(&self) -> Acceptance {
        Acceptance {
            audiences: vec![self.config.audience.as_bytes().to_vec()],
            providers: self.names(),
            max_lifetime: self.config.max_lifetime,
            skew: 60,
        }
    }

    fn login_policy(&self) -> LoginPolicy {
        LoginPolicy {
            replica: self.config.replica.as_bytes().to_vec(),
            providers: self.names(),
            ttl: self.config.login_ttl,
        }
    }

    fn issuer_rule(provider: &ProviderConfig) -> IssuerRule {
        match &provider.issuer {
            Some(issuer) => IssuerRule::Exact(issuer.as_bytes().to_vec()),
            None => IssuerRule::Absent,
        }
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}callback", self.config.public_url.to_url())
    }

    /// Spec section 8.1 steps 1-2, for the authenticated `peer`.
    pub fn begin_login(
        &self,
        peer: &PeerIdentity,
        provider: &str,
        scope: Option<&str>,
    ) -> Result<LoginStarted> {
        let (_, config) = self.provider(provider)?;
        let scope = config.requested_scope(scope)?;
        let login = random_id()?;
        let verifier = login::pkce_verifier()?;
        let now = self.now();
        let state = stateless_mailbox::start(
            &mut *self.locked()?,
            &self.login_policy(),
            provider.as_bytes(),
            peer.thumbprint.as_bytes(),
            peer.subject.as_bytes(),
            peer.not_after,
            login.as_bytes(),
            verifier.as_bytes(),
            scope.as_bytes(),
            now,
        )
        .map_err(mailbox_error)?;
        let sealed = login::seal_state(self.keys.state_key(), &state)?;
        Ok(LoginStarted {
            authorization_url: format!(
                "{}authorize?{}",
                self.config.public_url.to_url(),
                http::form(&[("state", &sealed)])
            ),
            confirmation: login::confirmation(&login),
            expires_at: state.expires_at,
            login,
        })
    }

    /// The provider authorization URL for an open state (the interstitial's link).
    fn provider_url(
        &self,
        provider: &ProviderConfig,
        state_text: &str,
        scope: &str,
        verifier: &str,
    ) -> String {
        format!(
            "{}?{}",
            provider.authorization_url.to_url(),
            http::form(&[
                ("response_type", "code"),
                ("client_id", &provider.client_id),
                ("redirect_uri", &self.redirect_uri()),
                ("scope", scope),
                ("state", state_text),
                ("code_challenge", &login::pkce_challenge(verifier)),
                ("code_challenge_method", "S256"),
            ])
        )
    }

    /// Spec section 8.1 step 3: the interstitial for a pending login.
    pub fn authorize(&self, state_text: &str) -> Result<(String, String)> {
        let state = login::open_state(self.keys.state_key(), state_text)
            .map_err(|_| Error::Protocol("invalid_state"))?;
        let now = self.now();
        let login = String::from_utf8_lossy(&state.login).into_owned();
        stateless_mailbox::pending(&*self.locked()?, &self.login_policy(), &state, now)
            .map_err(mailbox_error)?;
        let provider_name = String::from_utf8_lossy(&state.provider).into_owned();
        let (_, provider) = self.provider(&provider_name)?;
        let url = self.provider_url(
            provider,
            state_text,
            &String::from_utf8_lossy(&state.scope),
            &String::from_utf8_lossy(&state.verifier),
        );
        let page = format!(
            "<!doctype html><meta charset=utf-8><title>Authorize agent</title>\
             <h1>An agent requests access</h1>\
             <p>Agent: <code>{}</code></p><p>Provider: <code>{}</code></p><p>Scope: <code>{}</code></p>\
             <p>Confirmation code: <strong id=confirmation>{}</strong>. Continue only if your agent shows the same code.</p>\
             <p><a id=continue href=\"{}\">Continue to {}</a></p>",
            escape(&String::from_utf8_lossy(&state.subject)),
            escape(&provider_name),
            escape(&String::from_utf8_lossy(&state.scope)),
            login::confirmation(&login),
            escape(&url),
            escape(&provider_name),
        );
        Ok((url, page))
    }

    /// Spec section 8.1 steps 5-8: one provider redirect.
    pub fn callback(&self, request: &Request) -> Result<()> {
        let bad = |_: Error| Error::Protocol("invalid_callback");
        let state_text = request
            .param("state")
            .map_err(bad)?
            .ok_or(Error::Protocol("invalid_callback"))?;
        let code = request.param("code").map_err(bad)?;
        let issuer = request.param("iss").map_err(bad)?;
        let denied = request.param("error").map_err(bad)?.is_some();
        if !denied && code.is_none_or(|c| c.is_empty() || c.len() > 4096) {
            return Err(Error::Protocol("invalid_callback"));
        }
        let state = login::open_state(self.keys.state_key(), state_text)
            .map_err(|_| Error::Protocol("invalid_state"))?;
        let provider_name = String::from_utf8_lossy(&state.provider).into_owned();
        let (_, provider) = self.provider(&provider_name)?;
        let rule = Self::issuer_rule(provider);
        let policy = self.login_policy();
        let permit = stateless_mailbox::accept(
            &mut *self.locked()?,
            &policy,
            &state,
            &rule,
            issuer.unwrap_or("").as_bytes(),
            issuer.is_some(),
            denied,
            self.now(),
        )
        .map_err(mailbox_error)?;
        // The mailbox is unlocked during the network exchange. The answer
        // can only reach the login the permit was made for.
        let mut exchanger = ProviderExchange {
            broker: self,
            scope: None,
            error: None,
        };
        let exchanged =
            stateless_mailbox::exchange(&mut exchanger, permit, code.unwrap_or("").as_bytes());
        let info = match stateless_mailbox::exchanged_token(&exchanged) {
            Some(token) => Informational {
                scope: Some(
                    exchanger
                        .scope
                        .clone()
                        .unwrap_or_else(|| String::from_utf8_lossy(&state.scope).into_owned()),
                )
                .filter(|s| !s.is_empty()),
                upstream: std::str::from_utf8(&token.credential)
                    .ok()
                    .and_then(|text| token::copy_upstream(text, &provider.copy_claims)),
            },
            None => Informational::default(),
        };
        let sealer = Sealer {
            entry: self.keys.active_entry(),
            info,
        };
        // A failed random draw leaves an invalid `jti`, which fails issuance.
        let token_id = random_id().unwrap_or_default();
        let finished = stateless_mailbox::finish(
            &mut *self.locked()?,
            exchanged,
            &sealer,
            &self.issue_policy(),
            token_id.as_bytes(),
            self.now(),
            self.config.max_lifetime,
        );
        match exchanger.error {
            Some(error) => Err(error),
            None => finished.map_err(mailbox_error),
        }
    }

    /// Spec section 8.1 step 9: one poll by `peer`.
    pub fn poll(&self, peer: &PeerIdentity, login: &str) -> Poll {
        let Ok(mut mailbox) = self.mailbox.lock() else {
            return Poll::Refused(502, "internal_error");
        };
        let now = self.now();
        match stateless_mailbox::poll(
            &mut mailbox,
            peer.thumbprint.as_bytes(),
            login.as_bytes(),
            now,
        ) {
            Polled::Pending => Poll::Pending,
            Polled::Unknown => Poll::Refused(404, "login_unknown"),
            Polled::WrongCertificate => Poll::Refused(403, "wrong_certificate"),
            Polled::Denied => Poll::Refused(410, "login_denied"),
            Polled::Failed => Poll::Refused(410, "login_failed"),
            Polled::Expired => Poll::Refused(410, "login_expired"),
            Polled::Ready {
                token,
                expires_at,
                renew_until,
            } => match String::from_utf8(token) {
                Ok(token) => Poll::Ready(IssuedToken {
                    token,
                    expires_at,
                    renew_until,
                }),
                Err(_) => Poll::Refused(410, "login_failed"),
            },
        }
    }

    /// Stateless renewal (spec section 7) for the authenticated `peer`.
    pub fn renew(&self, peer: &PeerIdentity, token: &str) -> Result<IssuedToken> {
        let info = token::informational(token.as_bytes())
            .map_err(|r| Error::Rejected(rejection_name(&r)))?;
        let opener = Opener {
            keys: self.keys.verification(),
        };
        let sealer = Sealer {
            entry: self.keys.active_entry(),
            info,
        };
        let token_id = random_id()?;
        let issued = stateless::renew(
            &opener,
            &sealer,
            &self.acceptance(),
            &self.issue_policy(),
            token.as_bytes(),
            peer.thumbprint.as_bytes(),
            peer.not_after,
            token_id.as_bytes(),
            self.now(),
            self.config.max_lifetime,
        )?;
        Ok(IssuedToken {
            token: String::from_utf8(issued.token)
                .map_err(|_| Error::Protocol("internal_error"))?,
            expires_at: issued.claims.expires_at,
            renew_until: issued.claims.renew_until,
        })
    }

    /// Trusted operator issuance for a credential the operator supplies
    /// (an API key, a synthetic test token), bound to `certificate_der`.
    pub fn mint(
        &self,
        provider: &str,
        credential: &[u8],
        certificate_der: &[u8],
        lifetime: Option<i64>,
    ) -> Result<IssuedToken> {
        let (_, config) = self.provider(provider)?;
        mint_with(
            &self.keys,
            &self.issue_policy(),
            provider,
            credential,
            certificate_der,
            &config.copy_claims,
            lifetime.unwrap_or(self.config.max_lifetime),
            self.now(),
        )
    }

    /// The agent API: `peer` is the verified client of this connection.
    pub fn handle_agent(&self, request: &Request, peer: &PeerIdentity) -> Vec<u8> {
        let path = request.path.as_str();
        match (request.method.as_str(), path) {
            ("POST", "/v1/logins") => {
                let parsed = json::parse(&request.body, 4096, 2).ok();
                let provider = parsed
                    .as_ref()
                    .and_then(|v| v.get("provider"))
                    .and_then(Value::as_str);
                let scope = parsed
                    .as_ref()
                    .and_then(|v| v.get("scope"))
                    .and_then(Value::as_str);
                let Some(provider) = provider else {
                    return error(400, "invalid_request");
                };
                match self.begin_login(peer, provider, scope) {
                    Ok(started) => reply(
                        201,
                        json::object([
                            ("authorization_url", json::text(&started.authorization_url)),
                            ("confirmation", json::text(&started.confirmation)),
                            ("expires_at", Value::Int(started.expires_at)),
                            ("login", json::text(&started.login)),
                        ]),
                    ),
                    Err(Error::Protocol(code)) => {
                        error(if code == "too_many_logins" { 429 } else { 400 }, code)
                    }
                    Err(Error::Rejected(code)) => error(400, code),
                    Err(_) => error(502, "internal_error"),
                }
            }
            ("POST", "/v1/renewals") => {
                let parsed = json::parse(&request.body, 32768, 2).ok();
                let Some(token) = parsed
                    .as_ref()
                    .and_then(|v| v.get("token"))
                    .and_then(Value::as_str)
                else {
                    return error(400, "invalid_request");
                };
                match self.renew(peer, token) {
                    Ok(issued) => token_reply(200, &issued),
                    Err(_) => error(401, "invalid_token"),
                }
            }
            ("GET", _) if path.starts_with("/v1/logins/") => {
                let login = &path["/v1/logins/".len()..];
                if !crate::encoding::is_id(login) {
                    return error(404, "login_unknown");
                }
                let wait = match request.param("wait") {
                    Ok(Some(w)) => w.parse::<u64>().unwrap_or(0).min(MAX_WAIT),
                    Ok(None) => 0,
                    Err(_) => return error(400, "invalid_request"),
                };
                let deadline = std::time::Instant::now() + Duration::from_secs(wait);
                loop {
                    match self.poll(peer, login) {
                        Poll::Pending if std::time::Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(100))
                        }
                        Poll::Pending => {
                            return reply(202, json::object([("status", json::text("pending"))]))
                        }
                        Poll::Ready(issued) => return token_reply(200, &issued),
                        Poll::Refused(status, code) => return error(status, code),
                    }
                }
            }
            _ => error(404, "not_found"),
        }
    }

    /// The browser endpoint.
    pub fn handle_browser(&self, request: &Request) -> Vec<u8> {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/authorize") => match request.param("state") {
                Ok(Some(state)) => match self.authorize(state) {
                    Ok((_, page)) => http::response(200, "text/html; charset=utf-8", &[], page.as_bytes()),
                    Err(Error::Protocol(code)) => page(400, code),
                    Err(_) => page(400, "invalid_state"),
                },
                _ => page(400, "invalid_state"),
            },
            ("GET", "/callback") => match self.callback(request) {
                Ok(()) => http::response(
                    200,
                    "text/html; charset=utf-8",
                    &[],
                    b"<!doctype html><meta charset=utf-8><title>Done</title><h1 id=done>Authorized</h1><p>You can close this page; the agent now has its surrogate.</p>",
                ),
                Err(Error::Protocol(code)) | Err(Error::Rejected(code)) => page(400, code),
                Err(_) => page(400, "login_failed"),
            },
            _ => page(404, "not_found"),
        }
    }

    /// Bind both listeners and serve until [`RunningBroker::stop`].
    pub fn serve(self: Arc<Self>) -> Result<RunningBroker> {
        let certificate = read_public(&self.config.certificate, 1 << 20)?;
        let key = Zeroizing::new(read_private(&self.config.private_key, 1 << 20)?);
        let agent_ca = read_public(&self.config.agent_ca, 1 << 20)?;
        let agent_tls = tls::mtls_server(&certificate, &key, &agent_ca)?;
        let browser_tls = tls::server(&certificate, &key)?;
        let agent = TcpListener::bind(&self.config.agent_listen)?;
        let browser = TcpListener::bind(&self.config.browser_listen)?;
        let stop = Arc::new(AtomicBool::new(false));
        let agent_address = agent.local_addr()?;
        let browser_address = browser.local_addr()?;
        let mut workers = Vec::new();
        for (listener, config, mutual) in [(agent, agent_tls, true), (browser, browser_tls, false)]
        {
            let broker = self.clone();
            let stop = stop.clone();
            workers.push(std::thread::spawn(move || {
                accept_loop(listener, config, stop, move |stream, peer| {
                    let request = http::read_request(stream);
                    match (request, peer) {
                        (Ok(request), Some(peer)) if mutual => broker.handle_agent(&request, &peer),
                        (Ok(request), None) if !mutual => broker.handle_browser(&request),
                        _ => error(400, "invalid_request"),
                    }
                })
            }));
        }
        Ok(RunningBroker {
            agent_address,
            browser_address,
            stop,
            workers,
        })
    }
}

/// Operator issuance without a running broker (the `mint` command).
#[allow(clippy::too_many_arguments)]
pub fn mint_with(
    keys: &BrokerKeys,
    policy: &IssuePolicy,
    provider: &str,
    credential: &[u8],
    certificate_der: &[u8],
    copy: &token::ClaimCopy,
    lifetime: i64,
    now: i64,
) -> Result<IssuedToken> {
    let peer = PeerIdentity::from_der(certificate_der)?;
    let text =
        std::str::from_utf8(credential).map_err(|_| Error::Rejected("invalid_credential"))?;
    let sealer = Sealer {
        entry: keys.active_entry(),
        info: Informational {
            scope: None,
            upstream: token::copy_upstream(text, copy),
        },
    };
    let grant = Grant {
        provider: provider.as_bytes().to_vec(),
        subject: peer.subject.into_bytes(),
        certificate: peer.thumbprint.into_bytes(),
        certificate_expires: peer.not_after,
        credential_expires: MAX_TIME,
    };
    let token_id = random_id()?;
    let issued = stateless::issue(
        &sealer,
        policy,
        grant,
        credential,
        token_id.as_bytes(),
        now,
        lifetime,
    )?;
    Ok(IssuedToken {
        token: String::from_utf8(issued.token).map_err(|_| Error::Protocol("internal_error"))?,
        expires_at: issued.claims.expires_at,
        renew_until: issued.claims.renew_until,
    })
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn reply(status: u16, value: Value) -> Vec<u8> {
    let mut body = json::canonical(&value).unwrap_or_default();
    body.push(b'\n');
    http::response(status, "application/json", &[], &body)
}

fn error(status: u16, code: &str) -> Vec<u8> {
    reply(status, json::object([("error", json::text(code))]))
}

fn page(status: u16, code: &str) -> Vec<u8> {
    let body = format!("<!doctype html><meta charset=utf-8><title>Error</title><h1>Authorization failed</h1><p id=error>{}</p>", escape(code));
    http::response(status, "text/html; charset=utf-8", &[], body.as_bytes())
}

fn token_reply(status: u16, issued: &IssuedToken) -> Vec<u8> {
    reply(
        status,
        json::object([
            ("expires_at", Value::Int(issued.expires_at)),
            ("renew_until", Value::Int(issued.renew_until)),
            ("token", json::text(&issued.token)),
        ]),
    )
}

/// A served broker; dropping it does not stop it.
pub struct RunningBroker {
    pub agent_address: SocketAddr,
    pub browser_address: SocketAddr,
    stop: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl RunningBroker {
    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        for address in [self.agent_address, self.browser_address] {
            let _ = TcpStream::connect_timeout(&address, Duration::from_secs(1));
        }
        for worker in self.workers {
            let _ = worker.join();
        }
    }
    /// Block until the process is killed.
    pub fn wait(self) {
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

type Stream = StreamOwned<ServerConnection, TcpStream>;

/// Accept TLS connections; one request per connection, one thread each.
pub(crate) fn accept_loop<F>(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    stop: Arc<AtomicBool>,
    handler: F,
) where
    F: Fn(&mut Stream, Option<PeerIdentity>) -> Vec<u8> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
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
        let (config, handler, active) = (config.clone(), handler.clone(), active.clone());
        std::thread::spawn(move || {
            let _ = serve_one(tcp, config, &*handler);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn serve_one<F>(tcp: TcpStream, config: Arc<ServerConfig>, handler: &F) -> Result<()>
where
    F: Fn(&mut Stream, Option<PeerIdentity>) -> Vec<u8>,
{
    tcp.set_read_timeout(Some(Duration::from_secs(MAX_WAIT + 15)))?;
    tcp.set_write_timeout(Some(http::IO_TIMEOUT))?;
    let connection =
        ServerConnection::new(config).map_err(|_| Error::Tls("server connection".into()))?;
    let mut stream = StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|e| Error::Tls(format!("handshake: {}", e.kind())))?;
    }
    let peer = PeerIdentity::from_connection(&stream.conn).ok();
    let answer = handler(&mut stream, peer);
    stream.write_all(&answer)?;
    stream.flush()?;
    stream.conn.send_close_notify();
    let _ = stream.conn.complete_io(&mut stream.sock);
    Ok(())
}
