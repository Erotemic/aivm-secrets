//! Native manifest session. Only this private adapter borrows the credential;
//! policy compilation, disclosure and source-controller gates remain inspectable.
use super::*;
use crate::manifest::{disclosure::Disclosure, Effect, Policy};
use aivm_secrets_garrett_core::{manifest as guards, open_surrogate};

// W3 dispatch vocabulary: these two effects are the only credentialed HTTPS
// phases exposed by the native manifest guest-request path. A PreparedDispatch
// is constructed only after the policy compiler selects an Effect. It is not a
// proof witness by itself; the enclosing request checks admission, fresh grant,
// durable audit and selected route before the interpreter runs.
#[derive(Clone, Copy)]
enum DispatchPhase {
    Preflight,
    Final,
}
impl DispatchPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Final => "final",
        }
    }
}
struct PreparedDispatch<'a> {
    phase: DispatchPhase,
    effect: &'a Effect,
}
impl<'a> PreparedDispatch<'a> {
    fn preflight(effect: &'a Effect) -> Self {
        Self { phase: DispatchPhase::Preflight, effect }
    }
    fn final_effect(effect: &'a Effect) -> Self {
        Self { phase: DispatchPhase::Final, effect }
    }
}

pub(crate) struct Session {
    base: AccountSession,
    policy: Policy,
    disclosure: Disclosure,
    writes: bool,
}
impl Session {
    pub(super) fn start(config: &Value, binding: &Value, now: i64, lifetime: i64) -> Outcome<Self> {
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
                "policy_file",
                "disclosure_file",
                "writes",
                "request_limit",
            ],
            &["credential_file", "oauth", "source_override"],
        )?;
        if m["request_limit"] != "unbounded" {
            return Err(Error::InvalidPolicy);
        }
        let writes = match m["writes"].as_str() {
            Some("allow") => true,
            Some("deny") => false,
            _ => return Err(Error::InvalidPolicy),
        };
        let policy = Policy::from_file(Path::new(text(config, "policy_file")?))?;
        if policy.host != text(config, "host")?
            || policy.authentication != text(config, "authentication")?
        {
            return Err(Error::InvalidPolicy);
        }
        let pins = &policy.document()["egress"];
        let port = pins.get("port").and_then(Value::as_i64).unwrap_or(443);
        if m["port"].as_i64() != Some(port)
            || pins.get("address").is_some_and(|v| v != &m["address"])
            || pins.get("ca_file").is_some_and(|v| v != &m["server_ca"])
        {
            return Err(Error::InvalidPolicy);
        }
        if m.contains_key("oauth") {
            if m.get("source_override") != Some(&json!("oauth")) {
                return Err(Error::InvalidPolicy);
            }
        } else {
            let source = &policy.document()["credential_source"];
            json::keys(source, &["kind", "path"], &[]).map_err(|_| Error::InvalidPolicy)?;
            if source["kind"] != "file"
                || source.get("path") != m.get("credential_file")
                || m.contains_key("source_override")
            {
                return Err(Error::InvalidPolicy);
            }
        }
        let disclosure_value = json::parse(
            &files::read_trusted_public(Path::new(text(config, "disclosure_file")?), 65536)?,
            65536,
        )?;
        let disclosure = Disclosure::parse(&disclosure_value, &policy.operations())?;
        let mut common = config.clone();
        let fields = common.as_object_mut().ok_or(Error::InvalidPolicy)?;
        for key in [
            "policy_file",
            "disclosure_file",
            "writes",
            "request_limit",
            "source_override",
        ] {
            fields.remove(key);
        }
        common["profile"] = json!("account-status-v1");
        let effective = json!({"configuration":config,"policy":policy.document(),"disclosure":disclosure_value});
        let base = AccountSession::start_with_policy(
            &common,
            &effective,
            binding,
            now,
            lifetime.min(policy.lifetime),
            "manifest-https-v1",
        )?;
        Ok(Self {
            base,
            policy,
            disclosure,
            writes,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue(
        &self,
        issuer: &Issuer,
        registry: &Registry,
        name: &str,
        audience: &str,
        subject: &str,
        now: i64,
        lifetime: i64,
    ) -> Outcome<IssuedSurrogate> {
        self.base
            .issue(issuer, registry, name, audience, subject, now, lifetime)
    }
    pub(super) fn request(
        &mut self,
        verifier: &Verifier,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: Expectation,
        value: &Value,
        _now: i64,
    ) -> Outcome<Value> {
        let _vault = self
            .base
            .oauth
            .as_ref()
            .map(OAuthSource::active)
            .transpose()?;
        let now = host_time()?;
        let outer = open_surrogate(
            verifier,
            &token.as_bytes().to_vec(),
            &expected,
            &peer.thumbprint().as_bytes().to_vec(),
            now,
        )
        .map_err(|_| Error::InvalidCapability)?;
        let (claims, secret) = self.base.envelope.open(outer.secret.bytes())?;
        let (op, args) = self.policy.operation(value)?;
        guards::authorize(
            &claims,
            &self.base.grant,
            &value["operation"]
                .as_str()
                .ok_or(Error::InvalidRequest)?
                .as_bytes()
                .to_vec(),
            &op.name.as_bytes().to_vec(),
            op.write,
            self.writes,
            now,
            self.base.elapsed()?,
        )
        .map_err(use_error)?;
        let request_hash = hex(digest::digest(
            &digest::SHA256,
            &json::canonical(&json!({"operation":op.name,"arguments":args})),
        )
        .as_ref());
        let fresh = || -> Outcome<()> {
            let current = host_time()?;
            aivm_secrets_garrett_core::present(
                &outer.claims,
                &expected,
                &peer.thumbprint().as_bytes().to_vec(),
                current,
            )
            .map_err(|_| Error::InvalidCapability)?;
            guards::authorize(
                &claims,
                &self.base.grant,
                &op.name.as_bytes().to_vec(),
                &op.name.as_bytes().to_vec(),
                op.write,
                self.writes,
                current,
                self.base.elapsed()?,
            )
            .map_err(use_error)?;
            Ok(())
        };
        // Single admission-to-I/O boundary for preflight and final effects.
        // Neither raw facts nor a guest-provided URL is a PreparedDispatch.
        let dispatch = |prepared: PreparedDispatch<'_>| -> Outcome<Value> {
            let effect = prepared.effect;
            // A hostile fact must never turn a captured secret into a public
            // route/audit coordinate. Request bodies stay off the audit sink.
            crate::manifest::disclosure::ensure_safe(&json!({"target":effect.target}), &secret.0)?;
            self.base.executor.audit.write_record(&json!({"schema":1,"event":"dispatch","phase":prepared.phase.as_str(),"grant":self.base.executor.audit.grant,"policy":self.base.executor.audit.policy,
                "identity":crate::model::claims_json(&outer.claims)?,"operation":op.name,"request_digest":request_hash,
                "route":{"host":self.policy.host,"port":self.base.grant.route.port,"method":effect.method,"path":effect.target}}))?;
            // Durable audit and a fresh grant both precede credentialed I/O.
            // Waiting for either must not extend identity or grant lifetime.
            fresh()?;
            self.base.executor.exchange_manifest(
                &self.base.grant.route,
                &secret,
                effect,
                &self.policy.headers,
            )
        };
        let facts = if let Some(effect) = self.policy.preflight(op, &args)? {
            dispatch(PreparedDispatch::preflight(&effect))?
        } else {
            Value::Null
        };
        let effect = self.policy.final_effect(op, &args, &facts)?;
        // Returning checked facts also requires a fresh grant, even when
        // there is no final network effect.
        fresh()?;
        let sent_write = effect.as_ref().is_some_and(|e| e.write);
        let raw = if let Some(effect) = effect {
            dispatch(PreparedDispatch::final_effect(&effect))?
        } else {
            facts
        };
        let release = (|| -> Outcome<Value> {
            let meta = self.policy.pagination(op, &args, &raw)?;
            let result = self.disclosure.project(&op.name, &raw, &secret.0)?;
            let mut reply = json!({"version":1,"ok":true,"result":result});
            if let Some(meta) = meta {
                reply["meta"] = meta;
            }
            crate::manifest::disclosure::ensure_safe(&reply, &secret.0)?;
            self.base.executor.audit.write_record(&json!({"schema":1,"event":"completed","operation":op.name,"grant":self.base.executor.audit.grant,"policy":self.base.executor.audit.policy,"request_digest":request_hash}))?;
            Ok(reply)
        })();
        if sent_write {
            release.map_err(|_| Error::OutcomeUnknown)
        } else {
            release
        }
    }
    pub(super) fn control(&mut self, inner: &[u8], verb: &str, _now: i64) -> Outcome<Value> {
        let _vault = self
            .base
            .oauth
            .as_ref()
            .map(OAuthSource::active)
            .transpose()?;
        let (claims, _secret) = self.base.envelope.open(inner)?;
        core::require_use_current(
            &claims,
            &self.base.grant,
            host_time()?,
            self.base.elapsed()?,
        )
        .map_err(use_error)?;
        if verb == "renounce" {
            self.base.executor.audit.write_record(&json!({"schema":1,"event":"revoked","grant":self.base.executor.audit.grant,"policy":self.base.executor.audit.policy}))?;
            self.base.grant.active = false;
            return Ok(json!({"version":1,"ok":true,"renounced":true}));
        }
        if verb != "describe" {
            return Err(Error::Denied);
        }
        Ok(
            json!({"version":1,"ok":true,"description":{"profile":"manifest-https-v1","operations":self.policy.operations(),"writes":if self.writes{"allow"}else{"deny"},"request_limit":"unbounded"}}),
        )
    }
}

// W6 concrete provider-wire boundary. Policy construction normally checks
// these fields already, but the adapter must not trust that its caller has
// preserved those checks. In particular OAuthSource can construct Credential
// directly rather than calling credential_at_least. Reject CR/LF in the final
// bytes, before a single provider write, to prevent HTTP request injection.
fn manifest_request_bytes(
    route: &core::Route,
    secret: &Credential,
    effect: &Effect,
    headers: &BTreeMap<String, String>,
) -> Outcome<Zeroizing<Vec<u8>>> {
    let host = std::str::from_utf8(&route.host).map_err(|_| Error::InvalidPolicy)?;
    if host.is_empty() || host.len() > 253
        || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(Error::InvalidPolicy);
    }
    let port = u16::try_from(route.port).map_err(|_| Error::InvalidPolicy)?;
    if port == 0 || !matches!(effect.method.as_str(), "GET" | "POST" | "PATCH")
        || !effect.target.starts_with('/') || effect.target.starts_with("//")
        || effect.target.len() > 8192 || effect.target.bytes().any(|b| !(33..=126).contains(&b) || b == b'#')
        || effect.accept.is_empty() || effect.accept.len() > 96
        || !effect.accept.bytes().all(|b| (33..=126).contains(&b))
    {
        return Err(Error::InvalidPolicy);
    }
    if secret.0.is_empty() || secret.0.len() > 4096
        || !secret.0.iter().all(|b| (b'!'..=b'~').contains(b))
    {
        return Err(Error::CredentialSource);
    }
    let body = effect.body.as_ref().map(|value| Zeroizing::new(json::canonical(value)));
    if body.as_ref().is_some_and(|value| value.len() > MAX_BODY) {
        return Err(Error::InvalidPolicy);
    }
    let mut request = Zeroizing::new(
        format!(
            "{} {} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: {}\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\n",
            effect.method, effect.target, effect.accept,
        ).into_bytes(),
    );
    if headers.len() > 8 {
        return Err(Error::InvalidPolicy);
    }
    let mut seen_headers = std::collections::BTreeSet::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if name.is_empty() || name.len() > 64 || !seen_headers.insert(lower.clone())
            || !name.bytes().enumerate().all(|(index, b)| b.is_ascii_alphanumeric() || index > 0 && b == b'-')
            || value.is_empty() || value.len() > 256
            || !value.bytes().all(|b| (32..=126).contains(&b))
            || value.starts_with(' ') || value.ends_with(' ')
            || ["accept", "accept-encoding", "authorization", "connection", "content-encoding",
                "content-length", "content-type", "cookie", "expect", "forwarded", "host",
                "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer",
                "transfer-encoding", "upgrade", "user-agent", "via", "x-api-key"]
                .contains(&lower.as_str())
            || lower.starts_with("proxy-") || lower.starts_with("sec-")
            || lower.starts_with("x-forwarded-")
        {
            return Err(Error::InvalidPolicy);
        }
        request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    request.extend_from_slice(match route.authentication {
        core::Authentication::Bearer => b"Authorization: Bearer ",
        core::Authentication::ApiKey => b"X-API-Key: ",
    });
    request.extend_from_slice(&secret.0);
    request.extend_from_slice(b"\r\n");
    if let Some(body) = &body {
        request.extend_from_slice(
            format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()).as_bytes(),
        );
    }
    request.extend_from_slice(b"\r\n");
    if let Some(body) = &body {
        request.extend_from_slice(body);
    }
    Ok(request)
}

impl Executor {
    fn exchange_manifest(
        &self,
        route: &core::Route,
        secret: &Credential,
        effect: &Effect,
        headers: &BTreeMap<String, String>,
    ) -> Outcome<Value> {
        // Validate all outbound bytes before connecting to any provider.
        // A malformed OAuth-issued credential must not reach a socket at all.
        let request = manifest_request_bytes(route, secret, effect, headers)?;
        let host = std::str::from_utf8(&route.host).map_err(|_| Error::InvalidPolicy)?;
        let mut socket = TcpStream::connect_timeout(
            &SocketAddr::new(
                self.address,
                u16::try_from(route.port).map_err(|_| Error::InvalidPolicy)?,
            ),
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
            .map_err(|_| Error::InvalidPolicy)?;
        let mut conn =
            ClientConnection::new(self.tls.clone(), name).map_err(|_| Error::Unreachable)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut socket)
                .map_err(|_| Error::Unreachable)?;
        }
        let mut stream = StreamOwned::new(conn, socket);
        let exchange = || -> Outcome<Value> {
            // The exact bytes handed to TLS are generated by one pure,
            // independently testable encoder. Never serialize a credential
            // through a public JSON or diagnostic interface.
            stream
                .write_all(&request)
                .and_then(|_| stream.flush())
                .map_err(|_| Error::UpstreamResponse)?;
            let body = Zeroizing::new(manifest_response(BufReader::new(stream), &effect.response)?);
            if effect.response == "text" {
                Ok(json!(
                    String::from_utf8(body.to_vec()).map_err(|_| Error::UpstreamResponse)?
                ))
            } else {
                let value = json::parse(&body, MAX_BODY).map_err(|_| Error::UpstreamResponse)?;
                if effect.method == "POST" && !effect.write {
                    let errors = value.get("errors").is_some_and(|v| match v {
                        Value::Null => false,
                        Value::Bool(b) => *b,
                        Value::String(s) => !s.is_empty(),
                        Value::Array(a) => !a.is_empty(),
                        Value::Object(m) => !m.is_empty(),
                        Value::Number(n) => n.as_f64().is_none_or(|x| x != 0.0),
                    });
                    if errors || !value.get("data").is_some_and(Value::is_object) {
                        return Err(Error::UpstreamResponse);
                    }
                }
                Ok(value)
            }
        };
        if effect.write {
            exchange().map_err(|_| Error::OutcomeUnknown)
        } else {
            exchange()
        }
    }
}

fn manifest_response(mut reader: impl BufRead, format: &str) -> Outcome<Vec<u8>> {
    let status = line(&mut reader, 4096)?;
    let status = std::str::from_utf8(&status).map_err(|_| Error::UpstreamResponse)?;
    let mut fields = status.splitn(3, ' ');
    let version = fields.next();
    let status = fields
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(Error::UpstreamResponse)?;
    if !matches!(version, Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(Error::UpstreamResponse);
    }
    if (400..500).contains(&status) {
        return Err(Error::UpstreamRejected);
    }
    if !(200..300).contains(&status) {
        return Err(Error::UpstreamError);
    }
    // A partial representation cannot be treated as a complete policy-
    // selected JSON/text result. Range/partial-content semantics are not
    // part of the native manifest contract.
    if status == 206 {
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
    let kind = headers
        .get("content-type")
        .and_then(|s| s.split(';').next())
        .map(str::trim);
    if status != 204
        && (format == "json" && kind != Some("application/json")
            || format == "text" && kind != Some("text/plain"))
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
        (None, None) => {
            reader
                .take((MAX_BODY + 1) as u64)
                .read_to_end(&mut body)
                .map_err(|_| Error::UpstreamResponse)?;
            if body.len() > MAX_BODY {
                return Err(Error::UpstreamResponse);
            }
        }
        _ => return Err(Error::UpstreamResponse),
    }
    if status == 204 && !body.is_empty() || format == "json" && body.is_empty() {
        return Err(Error::UpstreamResponse);
    }
    Ok(body)
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    fn route() -> core::Route {
        core::Route {
            host: b"api.example.org".to_vec(),
            port: 443,
            path: b"/".to_vec(),
            authentication: core::Authentication::Bearer,
        }
    }
    fn effect() -> Effect {
        Effect {
            method: "GET".into(), target: "/v1/pull/7?state=open".into(),
            accept: "application/json".into(), response: "json".into(),
            body: None, write: false,
        }
    }
    fn secret(bytes: &[u8]) -> Credential {
        Credential(Zeroizing::new(bytes.to_vec()))
    }
    #[test]
    fn manifest_wire_is_one_origin_form_request_without_proxy_routing() {
        let mut headers = BTreeMap::new();
        headers.insert("X-GitHub-Api-Version".into(), "2026-03-10".into());
        let request = manifest_request_bytes(&route(), &secret(b"SYNTHETIC_TOKEN_123456"), &effect(), &headers).unwrap();
        let wire = String::from_utf8(request.to_vec()).unwrap();
        assert!(wire.starts_with("GET /v1/pull/7?state=open HTTP/1.1\r\nHost: api.example.org:443\r\n"));
        assert!(wire.contains("\r\nAuthorization: Bearer SYNTHETIC_TOKEN_123456\r\n"));
        assert!(wire.contains("\r\nX-GitHub-Api-Version: 2026-03-10\r\n"));
        assert!(wire.ends_with("\r\n\r\n"));
        assert_eq!(wire.matches("Authorization:").count(), 1);
        assert!(!wire.contains("Proxy-Authorization:"));
    }
    #[test]
    fn manifest_wire_api_key_uses_only_the_host_chosen_auth_header() {
        let mut api_route = route();
        api_route.authentication = core::Authentication::ApiKey;
        let request = manifest_request_bytes(
            &api_route, &secret(b"SYNTHETIC_TOKEN_123456"), &effect(), &BTreeMap::new(),
        ).unwrap();
        let wire = String::from_utf8(request.to_vec()).unwrap();
        assert!(wire.contains("\r\nX-API-Key: SYNTHETIC_TOKEN_123456\r\n"));
        assert!(!wire.contains("Authorization:"));
        assert_eq!(wire.matches("SYNTHETIC_TOKEN_123456").count(), 1);
    }
    #[test]
    fn manifest_wire_rejects_injected_credential_or_header() {
        for value in [b"TOKEN\r\nHost: attacker.test".as_slice(), b"TOKEN\nX-Other: evil", b"", b"TOKEN "] {
            assert!(matches!(manifest_request_bytes(&route(), &secret(value), &effect(), &BTreeMap::new()), Err(Error::CredentialSource)));
        }
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".into(), "Bearer attacker".into());
        assert!(matches!(manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &effect(), &headers), Err(Error::InvalidPolicy)));
        headers.clear();
        headers.insert("X-Allowed".into(), "ok\r\nHost: attacker".into());
        assert!(matches!(manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &effect(), &headers), Err(Error::InvalidPolicy)));
        headers.clear();
        headers.insert("X-Scope".into(), "a".into());
        headers.insert("x-scope".into(), "b".into());
        assert!(matches!(manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &effect(), &headers), Err(Error::InvalidPolicy)));
    }
    #[test]
    fn manifest_wire_rejects_unreviewed_target_and_renders_bounded_body() {
        let mut bad = effect();
        for path in ["//attacker.test/", "/ok\r\nX-Injected: yes", "/unsafe#fragment"] {
            bad.target = path.into();
            assert!(matches!(manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &bad, &BTreeMap::new()), Err(Error::InvalidPolicy)));
        }
        let mut post = effect();
        post.method = "POST".into();
        post.target = "/graphql".into();
        post.body = Some(json!({"operationName":"Pull","variables":{"pr":7}}));
        let bytes = manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &post, &BTreeMap::new()).unwrap();
        let wire = String::from_utf8(bytes.to_vec()).unwrap();
        let (head, body) = wire.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert_eq!(serde_json::from_str::<Value>(body).unwrap(), post.body.unwrap());
    }
    #[test]
    fn manifest_response_rejects_redirect_partial_and_ambiguous_framing() {
        use std::io::Cursor;
        let bad = [
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 206 Partial Content\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}",
        ];
        for response in bad {
            assert!(manifest_response(Cursor::new(response), "json").is_err());
        }
    }
    #[test]
    fn manifest_response_accepts_only_bounded_complete_representation() {
        use std::io::Cursor;
        let bytes = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 8\r\n\r\n{\"ok\":1}";
        assert_eq!(manifest_response(Cursor::new(bytes), "json").unwrap(), b"{\"ok\":1}");
        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nDATA\r\n0\r\n\r\n";
        assert_eq!(manifest_response(Cursor::new(chunked), "text").unwrap(), b"DATA");
    }

}
