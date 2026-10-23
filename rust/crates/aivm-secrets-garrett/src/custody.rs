//! Private inner-envelope and provider custody. No plaintext credential API.
use crate::{
    crypto::{self, InnerCapability, Issuer, Verifier},
    files, json,
    model::Registry,
    tls::Deadline,
    Error, Outcome,
};
use aivm_secrets_garrett_core::{
    credential_use as core, http_auth, http_wire, protocol, Expectation, IssuedSurrogate,
};
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
    if data.len() < minimum || !http_auth::valid_credential(data) {
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

// Native File methods remain the deliberate external append/fsync primitives.
// The entire fail-stop callback schedule is now source-owned and Aeneas-
// extracted in `audit_record::append_durable_record`.
struct AuditFile<'a>(&'a mut File);
impl aivm_secrets_garrett_core::audit_record::Sink for AuditFile<'_> {
    type Error = Error;
    const POISONED: Error = Error::InternalError;
    fn append(&mut self, bytes: &Vec<u8>) -> Outcome<()> {
        self.0.write_all(bytes).map_err(|_| Error::InternalError)
    }
    fn sync_record(&mut self) -> Outcome<()> {
        self.0.sync_all().map_err(|_| Error::InternalError)
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
        let bytes = json::canonical(value);
        let AuditState { file, failed } = &mut *state;
        let mut sink = AuditFile(file);
        aivm_secrets_garrett_core::audit_record::append_durable_record(&mut sink, failed, &bytes)
    }
}
// This private adapter alone turns the opaque credential into provider wire
// bytes. Every route field comes from the immutable host-selected grant.
struct Executor {
    tls: Arc<ClientConfig>,
    address: IpAddr,
    audit: Arc<Audit>,
}
struct PendingEmission<C, E> {
    check: C,
    emit: E,
}
impl<C, E, T> aivm_secrets_garrett_core::emission::PendingEmission for PendingEmission<C, E>
where
    C: Fn() -> Outcome<()>,
    E: FnOnce() -> Outcome<T>,
{
    type Output = T;
    type Error = Error;
    fn recheck(&self) -> Outcome<()> {
        (self.check)()
    }
    fn emit(self) -> Outcome<T> {
        (self.emit)()
    }
}
fn emit_current<T>(
    check: impl Fn() -> Outcome<()>,
    emit: impl FnOnce() -> Outcome<T>,
) -> Outcome<T> {
    aivm_secrets_garrett_core::emission::emit_current(PendingEmission { check, emit })
}
fn provider_request_bytes(
    head: &http_wire::Head,
    secret: &Credential,
    authentication: &core::Authentication,
    body: Option<&[u8]>,
) -> Outcome<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::new());
    http_wire::append_request(&mut request, head, &secret.0, authentication, body).map_err(
        |error| match error {
            http_wire::EncodingDenial::InvalidRequest => Error::InvalidPolicy,
            http_wire::EncodingDenial::InvalidCredential => Error::CredentialSource,
        },
    )?;
    Ok(request)
}
fn account_request_bytes(route: &core::Route, secret: &Credential) -> Outcome<Zeroizing<Vec<u8>>> {
    let head = http_wire::Head {
        method: b"GET".to_vec(),
        target: route.path.clone(),
        host: route.host.clone(),
        port: u16::try_from(route.port).map_err(|_| Error::InternalError)?,
        accept: b"application/json".to_vec(),
        headers: Vec::new(),
    };
    provider_request_bytes(&head, secret, &route.authentication, None)
}

impl Executor {
    fn exchange(
        &self,
        route: &core::Route,
        secret: &Credential,
        fresh: &impl Fn() -> Outcome<()>,
    ) -> Outcome<core::ProviderReply> {
        // Assemble and validate in the zeroizing buffer before any connection.
        let request = account_request_bytes(route, secret)?;
        let host = std::str::from_utf8(&route.host).map_err(|_| Error::InternalError)?;
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
        emit_current(fresh, || {
            stream
                .write_all(&request)
                .and_then(|_| stream.flush())
                .map_err(|_| Error::UpstreamResponse)
        })?;
        let body = Zeroizing::new(response(BufReader::new(stream))?);
        let value = json::parse(&body, MAX_BODY).map_err(|_| Error::UpstreamResponse)?;
        let id = value.get("id").ok_or(Error::UpstreamResponse)?;
        let id = json::integer(id, 0, i64::MAX).map_err(|_| Error::UpstreamResponse)?;
        let active = value
            .get("active")
            .and_then(Value::as_bool)
            .ok_or(Error::UpstreamResponse)?;
        // A typed integer can still be a literal credential. Check the complete
        // success frame before the selected values can leave credential custody.
        crate::manifest::disclosure::ensure_safe(
            &json!({"version":1,"ok":true,"result":{"id":id,"active":active}}),
            &secret.0,
        )?;
        Ok(core::ProviderReply {
            account_id: id,
            active,
            discarded: body.to_vec(),
        })
    }
}
struct CurrentExecutor<'a, F> {
    executor: &'a Executor,
    fresh: F,
}
impl<F: Fn() -> Outcome<()>> core::CredentialExecutor for CurrentExecutor<'_, F> {
    type Credential = Credential;
    fn execute(
        &self,
        route: &core::Route,
        credential: &Credential,
    ) -> Result<core::ProviderReply, core::UseDenial> {
        self.executor
            .exchange(route, credential, &self.fresh)
            .map_err(|error| match error {
                Error::InvalidCapability => core::UseDenial::InvalidCapability,
                Error::Denied => core::UseDenial::Denied,
                Error::Revoked => core::UseDenial::Revoked,
                _ => core::UseDenial::Upstream,
            })
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
fn response_status(raw: &[u8]) -> Outcome<u16> {
    // Keep the native HTTP profile octet-based: integer parsing and Unicode
    // whitespace must not normalize malformed provider framing into success.
    if raw.len() < 13
        || !matches!(&raw[..8], b"HTTP/1.1" | b"HTTP/1.0")
        || raw[8] != b' '
        || raw[12] != b' '
        || !raw[9..12].iter().all(u8::is_ascii_digit)
        || raw[13..].iter().any(|b| *b < 32 && *b != 9 || *b == 127)
        || std::str::from_utf8(raw).is_err()
    {
        return Err(Error::UpstreamResponse);
    }
    Ok(u16::from(raw[9] - b'0') * 100 + u16::from(raw[10] - b'0') * 10 + u16::from(raw[11] - b'0'))
}

fn response_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

// One response per connection: ambiguous framing and extra protocol features
// fail closed, and provider headers/error bodies never become public output.
fn response(mut reader: impl BufRead) -> Outcome<Vec<u8>> {
    let status = response_status(&line(&mut reader, 4096)?)?;
    if status != 200 {
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
            .insert(name.to_ascii_lowercase(), response_ows(value).to_owned())
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
        .map(response_ows)
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
    binding: crate::oauth_vault::SessionBinding,
}
impl OAuthSource {
    fn active(&self) -> Outcome<crate::oauth_vault::CurrentCredential> {
        // Sample after blocking: adding rounded elapsed seconds can admit a
        // request on the wrong side of a wall-clock expiry boundary.
        self.vault
            .current_lease(&self.provider, &self.subject, &self.binding, || {
                host_time().unwrap_or(i64::MAX)
            })
            .map_err(|_| Error::CredentialSource)
    }
}
/// Explicit account-status-v1 custody profile. This is a development provider
/// session, not a replacement for the general Python policy interpreter.
struct AccountSession {
    envelope: InnerEnvelope,
    grant: core::UseGrant,
    executor: Executor,
    started: Instant,
    inner: String,
    oauth: Option<OAuthSource>,
    coordinator: Option<crate::coordination::Coordinator>,
}
impl AccountSession {
    pub fn start(
        config: &Value,
        identity_binding: &Value,
        now: i64,
        lifetime: i64,
    ) -> Outcome<Self> {
        Self::start_with_policy(
            config,
            config,
            identity_binding,
            now,
            lifetime,
            "account-status-v1",
        )
    }
    fn start_with_policy(
        config: &Value,
        effective: &Value,
        identity_binding: &Value,
        now: i64,
        lifetime: i64,
        profile: &str,
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
            &["credential_file", "oauth", "coordination_file"],
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
            let session_binding = vault.bind_session(&provider, &subject, &lease)?;
            let secret = Credential(Zeroizing::new(session_binding.marker().to_vec()));
            (
                secret,
                Some(OAuthSource {
                    vault,
                    provider,
                    subject,
                    binding: session_binding,
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
        let policy = hex(digest::digest(&digest::SHA256, &json::canonical(effective)).as_ref());
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
            audit: Arc::new(Audit::new(Path::new(text(config, "audit_file")?), &c)?),
        };
        if profile == "account-status-v1" {
            executor.audit.record("session_open")?;
        } else {
            executor.audit.write_record(&json!({"schema":1,"event":"session_open","profile":profile,"grant":executor.audit.grant,"policy":executor.audit.policy}))?;
        }
        let coordinator = m
            .get("coordination_file")
            .map(|v| {
                crate::coordination::Coordinator::from_file(Path::new(
                    v.as_str().ok_or(Error::InvalidPolicy)?,
                ))
            })
            .transpose()?;
        Ok(Self {
            envelope,
            grant,
            executor,
            started: Instant::now(),
            inner,
            oauth,
            coordinator,
        })
    }
    fn check_coordination(&self) -> Outcome<()> {
        self.coordinator.as_ref().map_or(Ok(()), |c| c.check())
    }
    fn opener<'a>(
        &'a self,
        current: Option<&'a crate::oauth_vault::CurrentCredential>,
    ) -> SessionOpener<'a> {
        SessionOpener {
            envelope: &self.envelope,
            source: self.oauth.as_ref(),
            current,
        }
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
            self.executor.audit.as_ref(),
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
        self.check_coordination()?;
        let now = if self.oauth.is_some() || self.coordinator.is_some() {
            host_time()?
        } else {
            now
        };
        let opener = self.opener(_vault_lease.as_ref());
        let operation = parse_operation(value)?;
        let presentation = protocol::Presentation {
            expected,
            peer: peer.thumbprint().as_bytes().to_vec(),
            now,
            elapsed: self.elapsed()?,
        };
        let current_executor = CurrentExecutor {
            executor: &self.executor,
            fresh: || {
                // Both audit persistence and provider TLS setup can block.
                // Re-open and re-authorize at the actual emission boundary.
                self.check_coordination()?;
                let current = protocol::Presentation {
                    expected: Expectation {
                        issuer: presentation.expected.issuer.clone(),
                        audience: presentation.expected.audience.clone(),
                        subject: presentation.expected.subject.clone(),
                        epoch: presentation.expected.epoch,
                    },
                    peer: presentation.peer.clone(),
                    now: host_time()?,
                    elapsed: self.elapsed()?,
                };
                if let Some(lease) = &_vault_lease {
                    lease.require_current(current.now)?;
                }
                protocol::recheck(
                    verifier,
                    &opener,
                    &token.as_bytes().to_vec(),
                    &self.grant,
                    &operation,
                    &current,
                )
                .map_err(use_error)
            },
        };
        let result = protocol::perform(
            verifier,
            &opener,
            self.executor.audit.as_ref(),
            &current_executor,
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
    pub(crate) fn control(
        &mut self,
        verifier: &Verifier,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: Expectation,
        verb: &str,
    ) -> Outcome<Value> {
        let _vault_lease = self.oauth.as_ref().map(OAuthSource::active).transpose()?;
        self.check_coordination()?;
        let now = host_time()?;
        if let Some(lease) = &_vault_lease {
            lease.require_current(now)?;
        }
        let outer = verifier.open(token, peer, &expected, now)?;
        if !matches!(verb, "describe" | "renounce") {
            return Err(Error::Denied);
        }
        let opened =
            protocol::CredentialOpener::open(&self.opener(_vault_lease.as_ref()), &outer.inner)
                .map_err(use_error)?
                .claims;
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
        core::UseDenial::Revoked => Error::Revoked,
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
struct SessionOpener<'a> {
    envelope: &'a InnerEnvelope,
    source: Option<&'a OAuthSource>,
    current: Option<&'a crate::oauth_vault::CurrentCredential>,
}
impl protocol::CredentialOpener for SessionOpener<'_> {
    type Capability = InnerCapability;
    type Credential = Credential;
    fn open(
        &self,
        capability: &InnerCapability,
    ) -> Result<protocol::OpenedCredential<Credential>, core::UseDenial> {
        let mut opened = protocol::CredentialOpener::open(self.envelope, capability)?;
        match (self.source, self.current) {
            (None, None) => (),
            (Some(source), Some(current)) => {
                source
                    .vault
                    .verify_session_marker(
                        &source.provider,
                        &source.subject,
                        &source.binding,
                        &opened.credential.0,
                    )
                    .map_err(|_| core::UseDenial::InvalidCapability)?;
                opened.credential = Credential(Zeroizing::new(current.credential().to_vec()));
            }
            _ => return Err(core::UseDenial::InvalidCapability),
        }
        Ok(opened)
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
    use super::*;

    struct FaultAuditSink {
        steps: Vec<&'static str>,
        accepted: Vec<u8>,
        fail_at: Option<&'static str>,
    }
    impl aivm_secrets_garrett_core::audit_record::Sink for FaultAuditSink {
        type Error = Error;
        const POISONED: Error = Error::InternalError;
        fn append(&mut self, bytes: &Vec<u8>) -> Outcome<()> {
            let step = if bytes.as_slice() == b"\n" { "newline" } else { "payload" };
            self.steps.push(step);
            if self.fail_at == Some("partial") && step == "payload" {
                self.accepted.extend_from_slice(&bytes[..bytes.len().min(3)]);
                return Err(Error::InternalError);
            }
            if self.fail_at == Some(step) {
                return Err(Error::InternalError);
            }
            self.accepted.extend_from_slice(bytes);
            Ok(())
        }
        fn sync_record(&mut self) -> Outcome<()> {
            self.steps.push("sync");
            if self.fail_at == Some("sync") {
                Err(Error::InternalError)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn durable_audit_ack_only_after_payload_delimiter_and_sync() {
        for (fault, calls, accepted) in [
            (Some("payload"), vec!["payload"], b"".as_slice()),
            (Some("partial"), vec!["payload"], b"{\"x".as_slice()),
            (Some("newline"), vec!["payload", "newline"], b"{\"x\":1}".as_slice()),
            (Some("sync"), vec!["payload", "newline", "sync"], b"{\"x\":1}\n".as_slice()),
            (None, vec!["payload", "newline", "sync"], b"{\"x\":1}\n".as_slice()),
        ] {
            let mut sink = FaultAuditSink {
                steps: vec![], accepted: vec![], fail_at: fault,
            };
            let mut poisoned = false;
            let result = aivm_secrets_garrett_core::audit_record::append_durable_record(&mut sink, &mut poisoned, &b"{\"x\":1}".to_vec());
            assert_eq!(result.is_ok(), fault.is_none());
            assert_eq!(sink.steps, calls);
            assert_eq!(sink.accepted, accepted);
            assert_eq!(poisoned, fault.is_some());
            let steps = sink.steps.clone();
            if fault.is_some() {
                assert!(matches!(aivm_secrets_garrett_core::audit_record::append_durable_record(&mut sink, &mut poisoned, &b"second".to_vec()),
                    Err(Error::InternalError)));
                assert_eq!(sink.steps, steps, "poisoned audit replayed I/O");
            } else {
                aivm_secrets_garrett_core::audit_record::append_durable_record(&mut sink, &mut poisoned, &b"second".to_vec()).unwrap();
                assert!(!poisoned);
                assert_eq!(&sink.accepted, b"{\"x\":1}\nsecond\n");
            }
        }
    }

    #[test]
    fn panic_during_audit_append_leaves_attempt_poisoned() {
        struct Panicking;
        impl aivm_secrets_garrett_core::audit_record::Sink for Panicking {
            type Error = Error;
            const POISONED: Error = Error::InternalError;
            fn append(&mut self, _bytes: &Vec<u8>) -> Outcome<()> {
                panic!("synthetic sink panic")
            }
            fn sync_record(&mut self) -> Outcome<()> { unreachable!() }
        }
        let mut failed = false;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = aivm_secrets_garrett_core::audit_record::append_durable_record(&mut Panicking, &mut failed, &b"private".to_vec());
        }));
        assert!(caught.is_err());
        assert!(failed);
    }

    #[test]
    fn account_wire_authentication_is_exact_and_host_selected() {
        for (authentication, expected) in [
            (core::Authentication::Bearer, "Authorization: Bearer "),
            (core::Authentication::ApiKey, "X-API-Key: "),
        ] {
            let route = core::Route {
                host: b"api.example.org".to_vec(),
                port: 443,
                path: b"/v1/account".to_vec(),
                authentication,
            };
            let secret = Credential(Zeroizing::new(b"SYNTHETIC:token/~+=".to_vec()));
            let bytes = account_request_bytes(&route, &secret).unwrap();
            assert_eq!(bytes.as_slice(), format!(
                "GET /v1/account HTTP/1.1\r\nHost: api.example.org:443\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\n{expected}SYNTHETIC:token/~+=\r\n\r\n"
            ).as_bytes());
        }
    }

    #[test]
    fn account_wire_refuses_header_splitting_credentials() {
        let route = core::Route {
            host: b"api.example.org".to_vec(),
            port: 443,
            path: b"/v1/account".to_vec(),
            authentication: core::Authentication::Bearer,
        };
        for value in [
            b"".as_slice(),
            b"TOKEN\r\nHost: attacker.test",
            b"TOKEN\n\nGET /",
            b"TOKEN\0",
            b"TOKEN ",
            &[255],
        ] {
            let secret = Credential(Zeroizing::new(value.to_vec()));
            assert!(matches!(
                account_request_bytes(&route, &secret),
                Err(Error::CredentialSource)
            ));
        }
    }

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

pub(crate) mod approval;
mod manifest_session;
enum Backend {
    Account(Box<AccountSession>),
    Manifest(Box<manifest_session::Session>),
}
pub struct ProviderSession(Backend);
impl ProviderSession {
    pub fn start(config: &Value, binding: &Value, now: i64, lifetime: i64) -> Outcome<Self> {
        if config["profile"] == "manifest-https-v1" {
            Ok(Self(Backend::Manifest(Box::new(
                manifest_session::Session::start(config, binding, now, lifetime)?,
            ))))
        } else {
            Ok(Self(Backend::Account(Box::new(AccountSession::start(
                config, binding, now, lifetime,
            )?))))
        }
    }
    pub fn host_control(&self) -> Option<crate::host_control::Control> {
        match &self.0 {
            Backend::Manifest(s) => s.host_control(),
            Backend::Account(_) => None,
        }
    }
    pub fn profile(&self) -> &'static str {
        match &self.0 {
            Backend::Account(_) => "account-status-v1",
            Backend::Manifest(_) => "manifest-https-v1",
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        issuer: &Issuer,
        registry: &Registry,
        name: &str,
        audience: &str,
        subject: &str,
        now: i64,
        lifetime: i64,
    ) -> Outcome<IssuedSurrogate> {
        match &self.0 {
            Backend::Account(s) => {
                s.issue(issuer, registry, name, audience, subject, now, lifetime)
            }
            Backend::Manifest(s) => {
                s.issue(issuer, registry, name, audience, subject, now, lifetime)
            }
        }
    }
    pub(crate) fn request(
        &mut self,
        verifier: &Verifier,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: Expectation,
        value: &Value,
        now: i64,
    ) -> Outcome<json::Reply> {
        match &mut self.0 {
            Backend::Account(s) => s
                .request(verifier, token, peer, expected, value, now)
                .map(json::Reply::Native),
            Backend::Manifest(s) => s.request(verifier, token, peer, expected, value, now),
        }
    }
    pub(crate) fn control(
        &mut self,
        verifier: &Verifier,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: Expectation,
        verb: &str,
    ) -> Outcome<Value> {
        match &mut self.0 {
            Backend::Account(s) => s.control(verifier, token, peer, expected, verb),
            Backend::Manifest(s) => s.control(verifier, token, peer, expected, verb),
        }
    }
}
