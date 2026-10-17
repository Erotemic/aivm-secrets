//! Native manifest session. Only this private adapter borrows the credential;
//! policy compilation, disclosure and source-controller gates remain inspectable.
use super::*;
use crate::manifest::{disclosure::Disclosure, Effect, Policy};
use aivm_secrets_garrett_core::{manifest as guards, open_surrogate};

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
        let observe = |effect: &Effect, phase: &str| -> Outcome<()> {
            // A hostile fact must never turn a captured secret into a public
            // route/audit coordinate. Request bodies stay off the audit sink.
            crate::manifest::disclosure::ensure_safe(&json!({"target":effect.target}), &secret.0)?;
            self.base.executor.audit.write_record(&json!({"schema":1,"event":"dispatch","phase":phase,"grant":self.base.executor.audit.grant,"policy":self.base.executor.audit.policy,
                "identity":crate::model::claims_json(&outer.claims)?,"operation":op.name,"request_digest":request_hash,
                "route":{"host":self.policy.host,"port":self.base.grant.route.port,"method":effect.method,"path":effect.target}}))?;
            // Audit persistence can block too. Sample again at dispatch, after
            // its acknowledgement and any preflight wait, before network I/O.
            fresh()
        };
        let facts = if let Some(effect) = self.policy.preflight(op, &args)? {
            observe(&effect, "preflight")?;
            self.base.executor.exchange_manifest(
                &self.base.grant.route,
                &secret,
                &effect,
                &self.policy.headers,
            )?
        } else {
            Value::Null
        };
        let effect = self.policy.final_effect(op, &args, &facts)?;
        // Returning checked facts also requires a fresh grant, even when
        // there is no final network effect.
        fresh()?;
        let sent_write = effect.as_ref().is_some_and(|e| e.write);
        let raw = if let Some(effect) = effect {
            observe(&effect, "final")?;
            self.base.executor.exchange_manifest(
                &self.base.grant.route,
                &secret,
                &effect,
                &self.policy.headers,
            )?
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

impl Executor {
    fn exchange_manifest(
        &self,
        route: &core::Route,
        secret: &Credential,
        effect: &Effect,
        headers: &BTreeMap<String, String>,
    ) -> Outcome<Value> {
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
            let body = effect
                .body
                .as_ref()
                .map(|v| Zeroizing::new(json::canonical(v)));
            let mut request=Zeroizing::new(format!("{} {} HTTP/1.1\r\nHost: {host}:{}\r\nAccept: {}\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\n",effect.method,effect.target,route.port,effect.accept).into_bytes());
            for (n, v) in headers {
                request.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
            }
            request.extend_from_slice(match route.authentication {
                core::Authentication::Bearer => b"Authorization: Bearer ",
                core::Authentication::ApiKey => b"X-API-Key: ",
            });
            request.extend_from_slice(&secret.0);
            request.extend_from_slice(b"\r\n");
            if let Some(body) = &body {
                request.extend_from_slice(
                    format!(
                        "Content-Type: application/json\r\nContent-Length: {}\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
            request.extend_from_slice(b"\r\n");
            if let Some(body) = &body {
                request.extend_from_slice(body);
            }
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
