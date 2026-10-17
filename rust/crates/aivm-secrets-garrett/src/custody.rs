//! Private inner-envelope and provider custody. No plaintext credential API.
use crate::{
    crypto::{self, InnerCapability, Issuer, Verifier},
    files, json,
    model::Registry,
    tls::Deadline,
    Error, Outcome,
};
use aivm_secrets_garrett_core::{credential_use as core, protocol, Expectation, IssuedSurrogate};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const INNER_AAD: &[u8] = b"aivm-secrets/local-session/service-neutral/v1";
const MAX_BODY: usize = 2 * 1024 * 1024;
struct Credential(Zeroizing<Vec<u8>>);
fn credential(data: &[u8]) -> Outcome<Credential> {
    credential_at_least(data, 16)
}
fn credential_at_least(data: &[u8], minimum: usize) -> Outcome<Credential> {
    if !(minimum..=4096).contains(&data.len()) || !data.iter().all(|b| (b'!'..=b'~').contains(b)) {
        return Err(Error::CredentialSource);
    }
    Ok(Credential(Zeroizing::new(data.to_vec())))
}
fn text<'a>(v: &'a Value, key: &str) -> Outcome<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidCapability)
}
fn random<const N: usize>() -> Outcome<[u8; N]> {
    let mut data = [0; N];
    SystemRandom::new()
        .fill(&mut data)
        .map_err(|_| Error::InternalError)?;
    Ok(data)
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn binding(value: &Value) -> Outcome<Vec<u8>> {
    let m = json::keys(
        value,
        &["owner_uid", "access_identity", "vm", "channel"],
        &[],
    )?;
    json::integer(&m["owner_uid"], 0, u32::MAX as i64)?;
    for name in ["access_identity", "vm", "channel"] {
        let s = text(value, name)?;
        if s.is_empty() || s.len() > 128 || s.contains('\0') {
            return Err(Error::InvalidCapability);
        }
    }
    Ok(json::canonical(value))
}
fn claims(value: &Value) -> Outcome<core::UseClaims> {
    let m = json::keys(
        value,
        &[
            "binding",
            "policy_digest",
            "grant_id",
            "issued_at",
            "expires_at",
        ],
        &[],
    )?;
    let issued = json::integer(&m["issued_at"], 0, i64::MAX - 3600)?;
    let expires = json::integer(&m["expires_at"], issued + 1, issued + 3600)?;
    for (name, length) in [("policy_digest", 64), ("grant_id", 32)] {
        let s = text(value, name)?;
        if s.len() != length
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidCapability);
        }
    }
    Ok(core::UseClaims {
        binding: binding(&m["binding"])?,
        policy: text(value, "policy_digest")?.as_bytes().to_vec(),
        grant: text(value, "grant_id")?.as_bytes().to_vec(),
        issued_at: issued,
        expires_at: expires,
    })
}
// Ephemeral inner keys make restart invalidate prior credential authority,
// even when the trusted operator retains the outer issuer and TLS identity.
struct InnerEnvelope(aead::LessSafeKey, usize);
impl InnerEnvelope {
    fn new(key: &[u8]) -> Outcome<Self> {
        Ok(Self(
            aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, key)
                    .map_err(|_| Error::InvalidCapability)?,
            ),
            16,
        ))
    }
    fn seal(&self, claims: &Value, secret: &Credential) -> Outcome<String> {
        let nonce = random::<12>()?;
        let mut payload = Zeroizing::new(json::canonical(
            &json!({"claims":claims,"credential":std::str::from_utf8(&secret.0).map_err(|_|Error::InvalidCapability)?}),
        ));
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(INNER_AAD),
                &mut *payload,
            )
            .map_err(|_| Error::InvalidCapability)?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&payload);
        Ok(format!("aivs1.{}", crypto::b64(&sealed)))
    }
    fn open(&self, token: &[u8]) -> Outcome<(core::UseClaims, Credential)> {
        let token = std::str::from_utf8(token).map_err(|_| Error::InvalidCapability)?;
        if token.len() > 16384 {
            return Err(Error::InvalidCapability);
        }
        let mut data = Zeroizing::new(crypto::decode(
            token
                .strip_prefix("aivs1.")
                .ok_or(Error::InvalidCapability)?,
            16384,
        )?);
        if data.len() < 29 {
            return Err(Error::InvalidCapability);
        }
        let nonce: [u8; 12] = data[..12]
            .try_into()
            .map_err(|_| Error::InvalidCapability)?;
        let plain = self
            .0
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(INNER_AAD),
                &mut data[12..],
            )
            .map_err(|_| Error::InvalidCapability)?;
        let payload = json::parse(plain, 16384)?;
        let m = json::keys(&payload, &["claims", "credential"], &[])?;
        Ok((
            claims(&m["claims"])?,
            credential_at_least(text(&payload, "credential")?.as_bytes(), self.1)
                .map_err(|_| Error::InvalidCapability)?,
        ))
    }
}

struct AuditState {
    file: File,
    failed: bool,
}
struct Audit {
    state: Mutex<AuditState>,
    grant: String,
    policy: String,
}
impl Audit {
    fn new(path: &Path, claims: &Value) -> Outcome<Self> {
        use rustix::fs::{flock, open, openat, FlockOperation, Mode, OFlags};
        use std::os::unix::fs::{FileExt, MetadataExt};
        let parent = path.parent().ok_or(Error::UnsafeFile)?;
        files::private_directory(parent)?;
        let directory = File::from(
            open(
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::UnsafeFile)?,
        );
        let fd = openat(
            &directory,
            path.file_name().ok_or(Error::UnsafeFile)?,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::APPEND
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::UnsafeFile)?;
        let file = File::from(fd);
        let m = file.metadata().map_err(|_| Error::UnsafeFile)?;
        if !m.is_file() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
            return Err(Error::UnsafeFile);
        }
        // A whole-session lock prevents interleaved records from another Rust
        // session. An interrupted write must be repaired explicitly by the host.
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::UnsafeFile)?;
        let length = file.metadata().map_err(|_| Error::UnsafeFile)?.len();
        if length > 0 {
            let mut tail = [0u8];
            file.read_exact_at(&mut tail, length - 1)
                .map_err(|_| Error::UnsafeFile)?;
            if tail != *b"\n" {
                return Err(Error::UnsafeFile);
            }
        }
        // Persist a newly created log's directory entry before its first
        // durable dispatch record can authorize any external provider I/O.
        directory.sync_all().map_err(|_| Error::InternalError)?;
        Ok(Self {
            state: Mutex::new(AuditState {
                file,
                failed: false,
            }),
            grant: text(claims, "grant_id")?.into(),
            policy: text(claims, "policy_digest")?.into(),
        })
    }
    fn record(&self, event: &str) -> Outcome<()> {
        self.write_record(&json!({"schema":1,"event":event,"operation":"profile.read","grant":self.grant,"policy":self.policy}))
    }
    fn write_record(&self, value: &Value) -> Outcome<()> {
        let mut state = self.state.lock().map_err(|_| Error::InternalError)?;
        if state.failed {
            return Err(Error::InternalError);
        }
        let result = state
            .file
            .write_all(&json::canonical(value))
            .and_then(|_| state.file.write_all(b"\n"))
            .and_then(|_| state.file.sync_all());
        if result.is_err() {
            state.failed = true;
            return Err(Error::InternalError);
        }
        Ok(())
    }
}
// This private adapter alone turns the opaque credential into provider wire
// bytes. Every route field comes from the immutable host-selected grant.
struct Executor {
    tls: Arc<ClientConfig>,
    address: IpAddr,
    audit: Audit,
}
impl Executor {
    fn exchange(&self, route: &core::Route, secret: &Credential) -> Outcome<core::ProviderReply> {
        let host = std::str::from_utf8(&route.host).map_err(|_| Error::InternalError)?;
        let path = std::str::from_utf8(&route.path).map_err(|_| Error::InternalError)?;
        let port = u16::try_from(route.port).map_err(|_| Error::InternalError)?;
        let mut socket = TcpStream::connect_timeout(
            &SocketAddr::new(self.address, port),
            Duration::from_secs(5),
        )
        .map_err(|_| Error::Unreachable)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|_| Error::Unreachable)?;
        socket
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|_| Error::Unreachable)?;
        let killer = socket.try_clone().map_err(|_| Error::Unreachable)?;
        let _deadline = Deadline::start_for(Duration::from_secs(40), move || {
            let _ = killer.shutdown(std::net::Shutdown::Both);
        });
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| Error::InternalError)?;
        let mut conn =
            ClientConnection::new(self.tls.clone(), name).map_err(|_| Error::InternalError)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut socket)
                .map_err(|_| Error::Unreachable)?;
        }
        let mut stream = StreamOwned::new(conn, socket);
        let auth = match route.authentication {
            core::Authentication::Bearer => "Authorization: Bearer ",
            core::Authentication::ApiKey => "X-API-Key: ",
        };
        let mut request=Zeroizing::new(format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\n{auth}").into_bytes());
        request.extend_from_slice(&secret.0);
        request.extend_from_slice(b"\r\n\r\n");
        stream
            .write_all(&request)
            .and_then(|_| stream.flush())
            .map_err(|_| Error::UpstreamResponse)?;
        let body = Zeroizing::new(response(BufReader::new(stream))?);
        let value = json::parse(&body, MAX_BODY).map_err(|_| Error::UpstreamResponse)?;
        let id = value.get("id").ok_or(Error::UpstreamResponse)?;
        let id = json::integer(id, 0, i64::MAX).map_err(|_| Error::UpstreamResponse)?;
        let active = value
            .get("active")
            .and_then(Value::as_bool)
            .ok_or(Error::UpstreamResponse)?;
        Ok(core::ProviderReply {
            account_id: id,
            active,
            discarded: body.to_vec(),
        })
    }
}
impl core::CredentialExecutor for Executor {
    type Credential = Credential;
    fn execute(
        &self,
        route: &core::Route,
        credential: &Credential,
    ) -> Result<core::ProviderReply, core::UseDenial> {
        self.exchange(route, credential)
            .map_err(|_| core::UseDenial::Upstream)
    }
}

fn line(reader: &mut impl BufRead, limit: usize) -> Outcome<Vec<u8>> {
    let mut line = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|_| Error::UpstreamResponse)?;
    if line.len() > limit || !line.ends_with(b"\r\n") {
        return Err(Error::UpstreamResponse);
    }
    line.truncate(line.len() - 2);
    Ok(line)
}
// One response per connection: ambiguous framing and extra protocol features
// fail closed, and provider headers/error bodies never become public output.
fn response(mut reader: impl BufRead) -> Outcome<Vec<u8>> {
    let status = line(&mut reader, 4096)?;
    let status = std::str::from_utf8(&status).map_err(|_| Error::UpstreamResponse)?;
    let mut fields = status.splitn(3, ' ');
    if !matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0")) || fields.next() != Some("200") {
        return Err(Error::UpstreamResponse);
    }
    let mut headers = BTreeMap::new();
    let mut size = 0;
    loop {
        let raw = line(&mut reader, 32768 - size)?;
        size += raw.len() + 2;
        if raw.is_empty() {
            break;
        }
        let header = std::str::from_utf8(&raw).map_err(|_| Error::UpstreamResponse)?;
        let (name, value) = header.split_once(':').ok_or(Error::UpstreamResponse)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 32 && b != 9 || b == 127)
        {
            return Err(Error::UpstreamResponse);
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err(Error::UpstreamResponse);
        }
        if size >= 32768 {
            return Err(Error::UpstreamResponse);
        }
    }
    if headers
        .get("content-type")
        .and_then(|s| s.split(';').next())
        .map(str::trim)
        != Some("application/json")
        || headers
            .get("content-encoding")
            .is_some_and(|s| s != "identity")
    {
        return Err(Error::UpstreamResponse);
    }
    let mut body = Vec::new();
    match (
        headers.get("content-length"),
        headers.get("transfer-encoding"),
    ) {
        (Some(length), None) => {
            if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::UpstreamResponse);
            }
            let length: usize = length.parse().map_err(|_| Error::UpstreamResponse)?;
            if length > MAX_BODY {
                return Err(Error::UpstreamResponse);
            }
            body.resize(length, 0);
            reader
                .read_exact(&mut body)
                .map_err(|_| Error::UpstreamResponse)?;
        }
        (None, Some(encoding)) if encoding == "chunked" => loop {
            let raw = line(&mut reader, 32)?;
            if raw.is_empty() || !raw.iter().all(u8::is_ascii_hexdigit) {
                return Err(Error::UpstreamResponse);
            }
            let size = usize::from_str_radix(
                std::str::from_utf8(&raw).map_err(|_| Error::UpstreamResponse)?,
                16,
            )
            .map_err(|_| Error::UpstreamResponse)?;
            if size == 0 {
                if !line(&mut reader, 2)?.is_empty() {
                    return Err(Error::UpstreamResponse);
                }
                break;
            }
            if size > MAX_BODY - body.len() {
                return Err(Error::UpstreamResponse);
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader
                .read_exact(&mut body[start..])
                .map_err(|_| Error::UpstreamResponse)?;
            if !line(&mut reader, 2)?.is_empty() {
                return Err(Error::UpstreamResponse);
            }
        },
        _ => return Err(Error::UpstreamResponse),
    }
    Ok(body)
}

fn host_time() -> Outcome<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidCapability)?
            .as_secs(),
    )
    .map_err(|_| Error::InvalidCapability)
}
struct OAuthSource {
    vault: crate::oauth_vault::OAuthVault,
    provider: crate::oauth_vault::provider::Provider,
    subject: String,
    lease: crate::oauth_vault::Lease,
}
impl OAuthSource {
    fn active(&self) -> Outcome<std::fs::File> {
        // Sample after blocking: adding rounded elapsed seconds can admit a
        // request on the wrong side of a wall-clock expiry boundary.
        self.vault
            .active_lease(&self.provider, &self.subject, &self.lease, || {
                host_time().unwrap_or(i64::MAX)
            })
            .map_err(|_| Error::CredentialSource)
    }
}
/// Explicit account-status-v1 custody profile. This is a development provider
/// session, not a replacement for the general Python policy interpreter.
pub struct ProviderSession {
    envelope: InnerEnvelope,
    grant: core::UseGrant,
    executor: Executor,
    started: Instant,
    inner: String,
    oauth: Option<OAuthSource>,
}
impl ProviderSession {
    pub fn start(
        config: &Value,
        identity_binding: &Value,
        now: i64,
        lifetime: i64,
    ) -> Outcome<Self> {
        let m = json::keys(
            config,
            &[
                "profile",
                "host",
                "address",
                "port",
                "authentication",
                "server_ca",
                "audit_file",
            ],
            &["credential_file", "oauth"],
        )?;
        if m.contains_key("credential_file") == m.contains_key("oauth") {
            return Err(Error::InvalidCapability);
        }
        if m["profile"] != "account-status-v1" {
            return Err(Error::InvalidCapability);
        }
        binding(identity_binding)?;
        if !(0..=i64::MAX - 3600).contains(&now) || !(1..=3600).contains(&lifetime) {
            return Err(Error::InvalidCapability);
        }
        let host = text(config, "host")?;
        if host.len() > 253
            || !host.contains('.')
            || !host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        {
            return Err(Error::InvalidCapability);
        }
        if !matches!(
            rustls::pki_types::ServerName::try_from(host),
            Ok(rustls::pki_types::ServerName::DnsName(_))
        ) {
            return Err(Error::InvalidCapability);
        }
        let port = json::integer(&m["port"], 1, 65535)?;
        let address = text(config, "address")?
            .parse()
            .map_err(|_| Error::InvalidCapability)?;
        let authentication = match text(config, "authentication")? {
            "bearer" => core::Authentication::Bearer,
            "x-api-key" => core::Authentication::ApiKey,
            _ => return Err(Error::InvalidCapability),
        };
        let mut roots = RootCertStore::empty();
        let ca = files::read_private(Path::new(text(config, "server_ca")?), 1048576)?;
        for cert in rustls_pemfile::certs(&mut &*ca) {
            roots
                .add(cert.map_err(|_| Error::InvalidCapability)?)
                .map_err(|_| Error::InvalidCapability)?;
        }
        if roots.is_empty() {
            return Err(Error::InvalidCapability);
        }
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| Error::InvalidCapability)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        let (secret, oauth, lifetime) = if let Some(source) = m.get("oauth") {
            let fields = json::keys(
                source,
                &["vault_root", "provider_file", "subject"],
                &["transport", "force_refresh"],
            )?;
            if !matches!(authentication, core::Authentication::Bearer) {
                return Err(Error::InvalidCapability);
            }
            let vault =
                crate::oauth_vault::OAuthVault::open(Path::new(text(source, "vault_root")?))?;
            let provider = crate::oauth_vault::provider::Provider::from_file(Path::new(text(
                source,
                "provider_file",
            )?))?;
            let subject = text(source, "subject")?.to_owned();
            let force = fields
                .get("force_refresh")
                .map(|v| v.as_bool().ok_or(Error::InvalidCapability))
                .transpose()?
                .unwrap_or(false);
            let lease = vault
                .session_snapshot(
                    &provider,
                    &subject,
                    host,
                    now,
                    force,
                    fields.get("transport").unwrap_or(&json!({})),
                )
                .map_err(|_| Error::CredentialSource)?;
            let lifetime = lifetime.min(lease.expires_at() - now);
            let secret = Credential(Zeroizing::new(lease.credential().to_vec()));
            (
                secret,
                Some(OAuthSource {
                    vault,
                    provider,
                    subject,
                    lease,
                }),
                lifetime,
            )
        } else {
            let raw = Zeroizing::new(files::read_private(
                Path::new(text(config, "credential_file")?),
                4096,
            )?);
            (credential(&raw)?, None, lifetime)
        };
        let policy = hex(digest::digest(&digest::SHA256, &json::canonical(config)).as_ref());
        let c = json!({"binding":identity_binding,"policy_digest":policy,"grant_id":hex(&random::<16>()?),"issued_at":now,"expires_at":now+lifetime});
        let mut envelope = InnerEnvelope::new(&random::<32>()?)?;
        // OAuth's validated opaque-token grammar permits short synthetic or
        // provider-issued tokens; legacy file/fixture validation stays intact.
        if oauth.is_some() {
            envelope.1 = 1;
        }
        let inner = envelope.seal(&c, &secret)?;
        let grant = core::UseGrant {
            claims: claims(&c)?,
            operation: b"profile.read".to_vec(),
            active: true,
            route: core::Route {
                host: host.as_bytes().to_vec(),
                port,
                path: b"/v1/account".to_vec(),
                authentication,
            },
        };
        let executor = Executor {
            tls: Arc::new(tls),
            address,
            audit: Audit::new(Path::new(text(config, "audit_file")?), &c)?,
        };
        executor.audit.record("session_open")?;
        Ok(Self {
            envelope,
            grant,
            executor,
            started: Instant::now(),
            inner,
            oauth,
        })
    }
    #[allow(clippy::too_many_arguments)] // Mirrors the enrollment issuer contract.
    pub fn issue(
        &self,
        issuer: &Issuer,
        registry: &Registry,
        issuer_name: &str,
        audience: &str,
        subject: &str,
        now: i64,
        lifetime: i64,
    ) -> Outcome<IssuedSurrogate> {
        let _vault_lease = self.oauth.as_ref().map(OAuthSource::active).transpose()?;
        let now = if self.oauth.is_some() {
            host_time()?
        } else {
            now
        };
        if !self.grant.active
            || now < self.grant.claims.issued_at
            || now >= self.grant.claims.expires_at
        {
            return Err(Error::InvalidCapability);
        }
        issuer.issue_observed(
            &self.executor.audit,
            registry,
            issuer_name,
            audience,
            subject,
            self.inner.as_bytes(),
            now,
            lifetime.min(self.grant.claims.expires_at - now),
        )
    }
    /// Actual TLS evidence, not client-provided identity, enters the same
    /// extracted controller that opens both envelopes and dispatches the effect.
    pub(crate) fn request(
        &mut self,
        verifier: &Verifier,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: Expectation,
        value: &Value,
        now: i64,
    ) -> Outcome<Value> {
        let _vault_lease = self.oauth.as_ref().map(OAuthSource::active).transpose()?;
        let now = if self.oauth.is_some() {
            host_time()?
        } else {
            now
        };
        let operation = parse_operation(value)?;
        let presentation = protocol::Presentation {
            expected,
            peer: peer.thumbprint().as_bytes().to_vec(),
            now,
            elapsed: self.elapsed()?,
        };
        let result = protocol::perform(
            verifier,
            &self.envelope,
            &self.executor.audit,
            &self.executor,
            &token.as_bytes().to_vec(),
            &self.grant,
            &operation,
            &presentation,
        );
        match result {
            Ok(released) => {
                self.executor.audit.record("completed")?;
                Ok(
                    json!({"version":1,"ok":true,"result":{"id":released.account_id,"active":released.active}}),
                )
            }
            Err(error) => {
                self.executor.audit.record("failed")?;
                Err(use_error(error))
            }
        }
    }
    fn elapsed(&self) -> Outcome<i64> {
        i64::try_from(self.started.elapsed().as_secs()).map_err(|_| Error::InvalidCapability)
    }
    pub(crate) fn control(&mut self, inner: &[u8], verb: &str, now: i64) -> Outcome<Value> {
        let _vault_lease = self.oauth.as_ref().map(OAuthSource::active).transpose()?;
        let now = if self.oauth.is_some() {
            host_time()?
        } else {
            now
        };
        if !matches!(verb, "describe" | "renounce") {
            return Err(Error::Denied);
        }
        let (opened, _secret) = self.envelope.open(inner)?;
        core::authorize_use(
            &opened,
            &self.grant,
            &self.grant.operation,
            now,
            self.elapsed()?,
        )
        .map_err(use_error)?;
        if verb == "renounce" {
            self.executor.audit.record("revoked")?;
            self.grant.active = false;
            return Ok(json!({"version":1,"ok":true,"renounced":true}));
        }
        Ok(
            json!({"version":1,"ok":true,"description":{"profile":"account-status-v1","operations":["profile.read"],"release":["id","active"]}}),
        )
    }
}
fn use_error(error: core::UseDenial) -> Error {
    match error {
        core::UseDenial::InvalidCapability => Error::InvalidCapability,
        core::UseDenial::Denied => Error::Denied,
        core::UseDenial::Upstream => Error::UpstreamResponse,
    }
}

#[cfg(feature = "conformance")]
pub(crate) fn fixture_envelope(v: &Value) -> Outcome<Value> {
    let action = text(v, "action")?;
    let names = if action == "inner-issue" {
        vec!["action", "key_hex", "claims", "credential"]
    } else {
        vec!["action", "key_hex", "token"]
    };
    let m = json::keys(v, &names, &[])?;
    let key = crate::conformance::unhex(text(v, "key_hex")?)?;
    let envelope = InnerEnvelope::new(&key)?;
    if action == "inner-issue" {
        claims(&m["claims"])?;
        let secret = credential(text(v, "credential")?.as_bytes())?;
        Ok(json!({"ok":true,"token":envelope.seal(&m["claims"],&secret)?}))
    } else {
        let (c, secret) = envelope.open(text(v, "token")?.as_bytes())?;
        let binding = json::parse(&c.binding, 4096)?;
        Ok(
            json!({"ok":true,"claims":{"binding":binding,"policy_digest":std::str::from_utf8(&c.policy).map_err(|_|Error::InvalidCapability)?,"grant_id":std::str::from_utf8(&c.grant).map_err(|_|Error::InvalidCapability)?,"issued_at":c.issued_at,"expires_at":c.expires_at},"credential":std::str::from_utf8(&secret.0).map_err(|_|Error::InvalidCapability)?}),
        )
    }
}

impl protocol::IssuanceObserver for Audit {
    fn issued(
        &self,
        claims: &aivm_secrets_garrett_core::Claims,
    ) -> Result<(), aivm_secrets_garrett_core::Denial> {
        let identity = crate::model::claims_json(claims)
            .map_err(|_| aivm_secrets_garrett_core::Denial::InvalidCapability)?;
        self.write_record(&json!({"schema":1,"event":"issued","grant":self.grant,"policy":self.policy,"identity":identity}))
            .map_err(|_| aivm_secrets_garrett_core::Denial::InvalidCapability)
    }
}
impl protocol::CredentialOpener for InnerEnvelope {
    type Capability = InnerCapability;
    type Credential = Credential;
    fn open(
        &self,
        capability: &InnerCapability,
    ) -> Result<protocol::OpenedCredential<Credential>, core::UseDenial> {
        let (claims, credential) = self
            .open(capability.bytes())
            .map_err(|_| core::UseDenial::InvalidCapability)?;
        Ok(protocol::OpenedCredential { claims, credential })
    }
}
impl protocol::DispatchObserver for Audit {
    fn record(
        &self,
        identity: &aivm_secrets_garrett_core::Claims,
        claims: &core::UseClaims,
        route: &core::Route,
        operation: &Vec<u8>,
    ) -> Result<(), core::UseDenial> {
        let prepare = || -> Outcome<Value> {
            Ok(
                json!({"schema":1,"event":"dispatch","operation":std::str::from_utf8(operation).map_err(|_|Error::InternalError)?,"grant":self.grant,"policy":self.policy,
                    "identity":crate::model::claims_json(identity)?,
                    "inner":{"binding":json::parse(&claims.binding,4096)?,"issued_at":claims.issued_at,"expires_at":claims.expires_at},
                    "route":{"host":std::str::from_utf8(&route.host).map_err(|_|Error::InternalError)?,"port":route.port,"method":"GET","path":std::str::from_utf8(&route.path).map_err(|_|Error::InternalError)?,"authentication":match route.authentication {core::Authentication::Bearer=>"bearer",core::Authentication::ApiKey=>"x-api-key"}}
                }),
            )
        };
        self.write_record(&prepare().map_err(|_| core::UseDenial::Upstream)?)
            .map_err(|_| core::UseDenial::Upstream)
    }
}
fn parse_operation(value: &Value) -> Outcome<Vec<u8>> {
    let m = json::keys(value, &["operation"], &["arguments"]).map_err(|_| Error::InvalidRequest)?;
    if m.get("arguments")
        .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
    {
        return Err(Error::Denied);
    }
    let operation = text(value, "operation").map_err(|_| Error::InvalidRequest)?;
    if operation.is_empty()
        || operation.len() > 64
        || !operation.as_bytes()[0].is_ascii_lowercase()
        || !operation
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
    {
        return Err(Error::InvalidRequest);
    }
    Ok(operation.as_bytes().to_vec())
}
#[cfg(test)]
mod tests {
    use super::response;

    #[test]
    fn https_framing_is_bounded_and_unambiguous() {
        let fixed =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(response(&fixed[..]).ok(), Some(b"{}".to_vec()));
        let chunked=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n";
        assert_eq!(response(&chunked[..]).ok(), Some(b"{}".to_vec()));
        for raw in [
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2097153\r\n\r\n",
            "HTTP/1.1 302 Redirect\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n200001\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nAuthorization: private\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Encoding: gzip\r\n\r\n{}",
        ] { assert!(response(raw.as_bytes()).is_err()); }
    }
}
