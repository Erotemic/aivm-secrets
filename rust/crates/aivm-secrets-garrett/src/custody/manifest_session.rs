//! Native manifest session. Only this private adapter borrows the credential;
//! policy compilation, disclosure and source-controller gates remain inspectable.
use super::*;
use crate::manifest::{disclosure::Disclosure, Effect, Policy};
use aivm_secrets_garrett_core::{manifest as guards, open_surrogate};

// W3 dispatch vocabulary. A policy-compiled effect is not enough to invoke
// credential-bearing I/O. The native executor takes an AuditedDispatch, which
// can only be constructed by recording the selected phase, request identity and
// route in the private host audit. This is a source-level boundary, not a
// substitute for the late authority check or a proof of compiler reachability.
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
// Deliberately non-Copy and with private fields. Neither guest arguments nor
// the manifest compiler can manufacture this type: only the private audited
// transition below constructs it. The separate fresh check still runs after
// provider TLS setup, immediately before credential-bearing network I/O.
struct AuditedDispatch<'a> {
    phase: DispatchPhase,
    effect: &'a Effect,
}
impl<'a> PreparedDispatch<'a> {
    fn preflight(effect: &'a Effect) -> Outcome<Self> {
        // Preflight exists to check host facts, never to perform a write.
        if effect.write {
            return Err(Error::InvalidPolicy);
        }
        Ok(Self {
            phase: DispatchPhase::Preflight,
            effect,
        })
    }
    fn final_effect(effect: &'a Effect, admitted_write: bool) -> Outcome<Self> {
        // A read-only authorized operation cannot introduce a write while
        // expanding a checked fact into its final effect.
        if effect.write && !admitted_write {
            return Err(Error::InvalidPolicy);
        }
        Ok(Self {
            phase: DispatchPhase::Final,
            effect,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn audit(
        self,
        audit: &Audit,
        policy: &Policy,
        route: &core::Route,
        identity: &Value,
        operation: &str,
        request_digest: &str,
        secret: &Credential,
    ) -> Outcome<AuditedDispatch<'a>> {
        // A hostile provider fact cannot turn a credential into a route or
        // an audit field. The body is intentionally absent from this record.
        crate::manifest::disclosure::ensure_safe(
            &json!({"target":self.effect.target}), &secret.0,
        )?;
        audit.write_record(&json!({
            "schema":1,
            "event":"dispatch",
            "phase":self.phase.as_str(),
            "grant":audit.grant,
            "policy":audit.policy,
            "identity":identity,
            "operation":operation,
            "request_digest":request_digest,
            "route":{
                "host":policy.host,
                "port":route.port,
                "method":self.effect.method,
                "path":self.effect.target,
            }
        }))?;
        Ok(AuditedDispatch { phase: self.phase, effect: self.effect })
    }
}

// W5/W6 guest-release boundary for successful manifest requests. A selected
// result is not a completed public reply until its exact fixed envelope has
// passed the reflection check (at the call site) and completion has been
// durably audited. This type does not itself prove response-byte refinement.
struct CompletedRelease(Value);
impl CompletedRelease {
    fn after_completion(
        reply: Value,
        audit: &Audit,
        operation: &str,
        request_digest: &str,
    ) -> Outcome<Self> {
        audit.write_record(&json!({
            "schema":1,
            "event":"completed",
            "operation":operation,
            "grant":audit.grant,
            "policy":audit.policy,
            "request_digest":request_digest,
        }))?;
        Ok(Self(reply))
    }
    fn into_public(self) -> Value {
        self.0
    }
}

pub(crate) struct Session {
    base: AccountSession,
    policy: Policy,
    disclosure: Disclosure,
    writes: aivm_secrets_garrett_core::approval::Mode,
    control: Option<crate::host_control::Control>,
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
            &[
                "credential_file",
                "oauth",
                "source_override",
                "coordination_file",
                "control_socket",
            ],
        )?;
        if m["request_limit"] != "unbounded" {
            return Err(Error::InvalidPolicy);
        }
        let writes = match m["writes"].as_str() {
            Some("allow") => aivm_secrets_garrett_core::approval::Mode::Allow,
            Some("deny") => aivm_secrets_garrett_core::approval::Mode::Deny,
            Some("approve") => aivm_secrets_garrett_core::approval::Mode::Approve,
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
            "control_socket",
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
        let control = if matches!(writes, aivm_secrets_garrett_core::approval::Mode::Approve) {
            if binding["owner_uid"].as_u64() != Some(rustix::process::geteuid().as_raw() as u64) {
                return Err(Error::InvalidPolicy);
            }
            let path = Path::new(text(config, "control_socket")?).to_path_buf();
            if path.file_name() != Some(std::ffi::OsStr::new("control.sock")) {
                return Err(Error::InvalidPolicy);
            }
            files::private_directory(path.parent().ok_or(Error::UnsafeFile)?)?;
            let state = Arc::new(super::approval::Shared::new(
                super::approval::Metadata {
                    binding: binding.clone(),
                    service: policy.normalized_document()["service"]
                        .as_str()
                        .ok_or(Error::InvalidPolicy)?
                        .into(),
                    operations: policy.operations(),
                    policy: policy.digest().into(),
                    expires_at: base.grant.claims.expires_at,
                    audit_path: text(config, "audit_file")?.into(),
                },
                base.executor.audit.clone(),
            ));
            Some(crate::host_control::Control { path, state })
        } else {
            if m.contains_key("control_socket") {
                return Err(Error::InvalidPolicy);
            }
            None
        };
        Ok(Self {
            base,
            policy,
            disclosure,
            writes,
            control,
        })
    }
    pub(super) fn host_control(&self) -> Option<crate::host_control::Control> {
        self.control.clone()
    }
    fn writes_allowed(&self) -> bool {
        !matches!(self.writes, aivm_secrets_garrett_core::approval::Mode::Deny)
    }
    fn require_control_active(&self, now: i64) -> Outcome<()> {
        self.control
            .as_ref()
            .map_or(Ok(()), |c| c.state.require_active(now))
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
        self.base.check_coordination()?;
        let now = host_time()?;
        self.require_control_active(now)?;
        let outer = open_surrogate(
            verifier,
            &token.as_bytes().to_vec(),
            &expected,
            &peer.thumbprint().as_bytes().to_vec(),
            now,
        )
        .map_err(|_| Error::InvalidCapability)?;
        let opened =
            protocol::CredentialOpener::open(&self.base.opener(_vault.as_ref()), &outer.secret)
                .map_err(use_error)?;
        let claims = opened.claims;
        let secret = opened.credential;
        // The retry name is transport metadata, never an authorization or
        // route parameter. Preserve the canonical kernel request without it.
        let mut request = value.clone();
        let retry = request
            .as_object_mut()
            .ok_or(Error::InvalidRequest)?
            .remove("idempotency_key");
        let retry = retry
            .as_ref()
            .map(|v| {
                let key = v.as_str().ok_or(Error::InvalidRequest)?;
                if !aivm_secrets_garrett_core::coordination::valid_retry_key(key.as_bytes()) {
                    return Err(Error::InvalidRequest);
                }
                Ok(key)
            })
            .transpose()?;
        let (op, args) = self.policy.operation(&request)?;
        if retry.is_some() && (!op.write || self.base.coordinator.is_none())
            || op.write
                && (self.base.coordinator.is_some() || op.idempotency_header)
                && retry.is_none()
        {
            return Err(Error::InvalidRequest);
        }
        if op.idempotency_header
            && self
                .policy
                .headers
                .keys()
                .any(|h| h.eq_ignore_ascii_case("idempotency-key"))
        {
            return Err(Error::InvalidPolicy);
        }
        let reservation = retry.map(|key| {
            let coordinator = self.base.coordinator.as_ref().ok_or(Error::InvalidRequest)?;
            let provider_key = hex(digest::digest(&digest::SHA256,
                &json::canonical(&json!({"schema":1,"principal":coordinator.principal(),"client_key":key}))).as_ref());
            // Reuse the identity of parsed policy meaning: omitted defaults
            // and reordered set members must match the reference broker.
            let policy_hash = self.policy.digest();
            let fingerprint = hex(digest::digest(&digest::SHA256,
                &json::canonical(&json!({"policy":policy_hash,"request":{"operation":op.name,"arguments":args}}))).as_ref());
            Ok((provider_key,fingerprint))
        }).transpose()?;
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
            self.writes_allowed(),
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
            self.base.check_coordination()?;
            let current = host_time()?;
            self.require_control_active(current)?;
            if let Some(lease) = &_vault {
                lease.require_current(current)?;
            }
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
                self.writes_allowed(),
                current,
                self.base.elapsed()?,
            )
            .map_err(use_error)?;
            Ok(())
        };
        let canonical_request = json!({"operation":op.name,"arguments":args});
        let approval_digest = hex(digest::digest(&digest::SHA256, &json::canonical(
            &json!({"policy":self.policy.digest(),"grant":self.base.executor.audit.grant,"request":canonical_request}))).as_ref());
        let decision = if let Some(control) = &self.control {
            control.state.admit(&approval_digest, op.write)?
        } else {
            aivm_secrets_garrett_core::approval::consume(
                self.writes,
                op.write,
                &approval_digest.as_bytes().to_vec(),
                now,
                None,
            )
            .0
        };
        match decision {
            aivm_secrets_garrett_core::approval::Decision::Allowed => (),
            aivm_secrets_garrett_core::approval::Decision::Denied => return Err(Error::Denied),
            aivm_secrets_garrett_core::approval::Decision::Required => {
                fresh()?;
                let reply = json!({"version":1,"ok":false,"error":{"code":"approval_required", "message":"Exact write needs host approval."},"approval":{"digest":approval_digest}});
                crate::manifest::disclosure::ensure_safe(&reply, &secret.0)?;
                self.control
                    .as_ref()
                    .ok_or(Error::InternalError)?
                    .state
                    .remember(&approval_digest, &canonical_request)?;
                return Ok(reply);
            }
        }
        // Single admission-to-I/O boundary for preflight and final effects.
        // Neither raw facts nor a guest-provided URL is a PreparedDispatch.
        let dispatch = |prepared: PreparedDispatch<'_>| -> Outcome<Value> {
            let recorded = prepared.audit(
                &self.base.executor.audit,
                &self.policy,
                &self.base.grant.route,
                &crate::model::claims_json(&outer.claims)?,
                &op.name,
                &request_hash,
                &secret,
            )?;
            let effect = recorded.effect;
            // Durable audit and a fresh grant both precede credentialed I/O.
            // Waiting for either must not extend identity or grant lifetime.
            let keyed_write = matches!(recorded.phase, DispatchPhase::Final)
                && effect.write
                && self.base.coordinator.is_some();
            let mut headers = self.policy.headers.clone();
            if keyed_write && op.idempotency_header {
                let (key, _) = reservation.as_ref().ok_or(Error::InvalidRequest)?;
                headers.insert("Idempotency-Key".into(), key.clone());
            }
            let reservation_call = |finish: bool| -> Outcome<()> {
                let (key, fingerprint) = reservation.as_ref().ok_or(Error::InvalidRequest)?;
                let coordinator = self
                    .base
                    .coordinator
                    .as_ref()
                    .ok_or(Error::InvalidRequest)?;
                if finish {
                    coordinator.finish(key, fingerprint)
                } else {
                    coordinator.reserve(key, fingerprint)
                }
            };
            let pending = crate::coordination::PendingDispatch {
                check: &fresh,
                reserve: || reservation_call(false),
                emit: || {
                    self.base.executor.exchange_manifest(
                        &self.base.grant.route,
                        &secret,
                        &recorded,
                        &headers,
                        &fresh,
                    )
                },
                finish: || reservation_call(true),
            };
            aivm_secrets_garrett_core::coordination::dispatch(&pending, keyed_write)
        };
        let facts = if let Some(effect) = self.policy.preflight(op, &args)? {
            dispatch(PreparedDispatch::preflight(&effect)?)?
        } else {
            Value::Null
        };
        let effect = self.policy.final_effect(op, &args, &facts)?;
        // Returning checked facts also requires a fresh grant, even when
        // there is no final network effect.
        fresh()?;
        let sent_write = effect.as_ref().is_some_and(|e| e.write);
        let raw = if let Some(effect) = effect {
            dispatch(PreparedDispatch::final_effect(&effect, op.write)?)?
        } else {
            facts
        };
        let release = (|| -> Outcome<CompletedRelease> {
            self.require_control_active(host_time()?)?;
            let meta = self.policy.pagination(op, &args, &raw)?;
            let result = self.disclosure.project(&op.name, &raw, &secret.0)?;
            let mut reply = json!({"version":1,"ok":true,"result":result});
            if let Some(meta) = meta {
                reply["meta"] = meta;
            }
            crate::manifest::disclosure::ensure_safe(&reply, &secret.0)?;
            CompletedRelease::after_completion(
                reply, &self.base.executor.audit, &op.name, &request_hash,
            )
        })();
        if sent_write {
            release.map_err(|_| Error::OutcomeUnknown).map(CompletedRelease::into_public)
        } else {
            release.map(CompletedRelease::into_public)
        }
    }
    pub(super) fn control(
        &mut self,
        verifier: &Verifier,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: Expectation,
        verb: &str,
    ) -> Outcome<Value> {
        let _vault = self
            .base
            .oauth
            .as_ref()
            .map(OAuthSource::active)
            .transpose()?;
        self.base.check_coordination()?;
        let now = host_time()?;
        self.require_control_active(now)?;
        if let Some(lease) = &_vault {
            lease.require_current(now)?;
        }
        let outer = verifier.open(token, peer, &expected, now)?;
        let claims =
            protocol::CredentialOpener::open(&self.base.opener(_vault.as_ref()), &outer.inner)
                .map_err(use_error)?
                .claims;
        core::require_use_current(&claims, &self.base.grant, now, self.base.elapsed()?)
            .map_err(use_error)?;
        if verb == "renounce" {
            if let Some(control) = &self.control {
                control.state.revoke();
            }

            self.base.executor.audit.write_record(&json!({"schema":1,"event":"revoked","grant":self.base.executor.audit.grant,"policy":self.base.executor.audit.policy}))?;
            self.base.grant.active = false;
            return Ok(json!({"version":1,"ok":true,"renounced":true}));
        }
        if verb != "describe" {
            return Err(Error::Denied);
        }
        Ok(
            json!({"version":1,"ok":true,"description":{"profile":"manifest-https-v1","operations":self.policy.operations(),"writes":match self.writes { aivm_secrets_garrett_core::approval::Mode::Allow=>"allow", aivm_secrets_garrett_core::approval::Mode::Deny=>"deny", aivm_secrets_garrett_core::approval::Mode::Approve=>"approve" },"request_limit":"unbounded"}}),
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
    let head = http_wire::Head {
        method: effect.method.as_bytes().to_vec(),
        target: effect.target.as_bytes().to_vec(),
        host: route.host.clone(),
        port: u16::try_from(route.port).map_err(|_| Error::InvalidPolicy)?,
        accept: effect.accept.as_bytes().to_vec(),
        // BTreeMap preserves the existing deterministic wire order. The core
        // independently checks case-insensitive uniqueness and reserved names.
        headers: headers
            .iter()
            .map(|(name, value)| http_wire::Header {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            })
            .collect(),
    };
    let body = effect
        .body
        .as_ref()
        .map(|value| Zeroizing::new(json::canonical(value)));
    provider_request_bytes(
        &head,
        secret,
        &route.authentication,
        body.as_ref().map(|v| v.as_slice()),
    )
}

impl Executor {
    fn exchange_manifest(
        &self,
        route: &core::Route,
        secret: &Credential,
        audited: &AuditedDispatch<'_>,
        headers: &BTreeMap<String, String>,
        fresh: &impl Fn() -> Outcome<()>,
    ) -> Outcome<Value> {
        let effect = audited.effect;
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
        // TLS setup has completed. Sample authority again immediately before
        // credential-bearing HTTP; a denial here has sent no provider request.
        emit_current(fresh, || {
            if effect.write {
                exchange().map_err(|_| Error::OutcomeUnknown)
            } else {
                exchange()
            }
        })
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
    // RFC 9110: a 204 response ends at the header terminator. Neither a
    // Content-Length nor Transfer-Encoding field is permitted, even if it
    // declares a zero-length body.
    if status == 204
        && (headers.contains_key("content-length") || headers.contains_key("transfer-encoding"))
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
        // A successful representation must have an explicit, unambiguous
        // length or chunk framing. HTTP 204 has no representation by
        // definition; a bodyless 204 remains valid for a text operation.
        (None, None) if status == 204 => {
            // HTTP 204 ends at the blank line after the headers. Do not
            // read for EOF: the peer may keep the TLS connection open or
            // close without a TLS close_notify, and neither changes the
            // empty response's framing. No extra upstream bytes are released.
        }
        (None, None) => return Err(Error::UpstreamResponse),
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
            method: "GET".into(),
            target: "/v1/pull/7?state=open".into(),
            accept: "application/json".into(),
            response: "json".into(),
            body: None,
            write: false,
        }
    }
    fn secret(bytes: &[u8]) -> Credential {
        Credential(Zeroizing::new(bytes.to_vec()))
    }
    #[test]
    fn unapproved_read_or_preflight_cannot_become_write_dispatch() {
        let read = effect();
        assert!(PreparedDispatch::preflight(&read).is_ok());
        assert!(PreparedDispatch::final_effect(&read, false).is_ok());
        let mut write = effect();
        write.write = true;
        assert!(matches!(PreparedDispatch::preflight(&write), Err(Error::InvalidPolicy)));
        assert!(matches!(PreparedDispatch::final_effect(&write, false), Err(Error::InvalidPolicy)));
        assert!(PreparedDispatch::final_effect(&write, true).is_ok());
    }

    #[test]
    fn manifest_wire_is_one_origin_form_request_without_proxy_routing() {
        let mut headers = BTreeMap::new();
        headers.insert("X-GitHub-Api-Version".into(), "2026-03-10".into());
        let request = manifest_request_bytes(
            &route(),
            &secret(b"SYNTHETIC_TOKEN_123456"),
            &effect(),
            &headers,
        )
        .unwrap();
        let wire = String::from_utf8(request.to_vec()).unwrap();
        assert!(
            wire.starts_with("GET /v1/pull/7?state=open HTTP/1.1\r\nHost: api.example.org:443\r\n")
        );
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
            &api_route,
            &secret(b"SYNTHETIC_TOKEN_123456"),
            &effect(),
            &BTreeMap::new(),
        )
        .unwrap();
        let wire = String::from_utf8(request.to_vec()).unwrap();
        assert!(wire.contains("\r\nX-API-Key: SYNTHETIC_TOKEN_123456\r\n"));
        assert!(!wire.contains("Authorization:"));
        assert_eq!(wire.matches("SYNTHETIC_TOKEN_123456").count(), 1);
    }
    #[test]
    fn manifest_wire_rejects_injected_credential_or_header() {
        for value in [
            b"TOKEN\r\nHost: attacker.test".as_slice(),
            b"TOKEN\nX-Other: evil",
            b"",
            b"TOKEN ",
        ] {
            assert!(matches!(
                manifest_request_bytes(&route(), &secret(value), &effect(), &BTreeMap::new()),
                Err(Error::CredentialSource)
            ));
        }
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".into(), "Bearer attacker".into());
        assert!(matches!(
            manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &effect(), &headers),
            Err(Error::InvalidPolicy)
        ));
        headers.clear();
        headers.insert("X-Allowed".into(), "ok\r\nHost: attacker".into());
        assert!(matches!(
            manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &effect(), &headers),
            Err(Error::InvalidPolicy)
        ));
        headers.clear();
        headers.insert("X-Scope".into(), "a".into());
        headers.insert("x-scope".into(), "b".into());
        assert!(matches!(
            manifest_request_bytes(&route(), &secret(b"GOOD_TOKEN_123456"), &effect(), &headers),
            Err(Error::InvalidPolicy)
        ));
    }
    #[test]
    fn manifest_wire_rejects_unreviewed_target_and_renders_bounded_body() {
        let mut bad = effect();
        for path in [
            "//attacker.test/",
            "/ok\r\nX-Injected: yes",
            "/unsafe#fragment",
        ] {
            bad.target = path.into();
            assert!(matches!(
                manifest_request_bytes(
                    &route(),
                    &secret(b"GOOD_TOKEN_123456"),
                    &bad,
                    &BTreeMap::new()
                ),
                Err(Error::InvalidPolicy)
            ));
        }
        let mut post = effect();
        post.method = "POST".into();
        post.target = "/graphql".into();
        post.body = Some(json!({"operationName":"Pull","variables":{"pr":7}}));
        let bytes = manifest_request_bytes(
            &route(),
            &secret(b"GOOD_TOKEN_123456"),
            &post,
            &BTreeMap::new(),
        )
        .unwrap();
        let wire = String::from_utf8(bytes.to_vec()).unwrap();
        let (head, body) = wire.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            post.body.unwrap()
        );
    }
    #[test]
    fn manifest_response_rejects_redirect_partial_and_ambiguous_framing() {
        use std::io::Cursor;
        let bad = [
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 206 Partial Content\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
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
        assert_eq!(
            manifest_response(Cursor::new(bytes), "json").unwrap(),
            b"{\"ok\":1}"
        );
        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nDATA\r\n0\r\n\r\n";
        assert_eq!(
            manifest_response(Cursor::new(chunked), "text").unwrap(),
            b"DATA"
        );
        let no_content = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        assert_eq!(manifest_response(Cursor::new(no_content), "text").unwrap(), b"");
        assert!(manifest_response(Cursor::new(no_content), "json").is_err());
        // Any stray upstream bytes after a 204 header are not part of the
        // representation and must never appear in the selected guest text.
        let invalid_extra = b"HTTP/1.1 204 No Content\r\n\r\nDO-NOT-RELEASE";
        assert_eq!(manifest_response(Cursor::new(invalid_extra), "text").unwrap(), b"");
        let illegal_204_length = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        assert!(manifest_response(Cursor::new(illegal_204_length), "text").is_err());
        let illegal_204_transfer = b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(manifest_response(Cursor::new(illegal_204_transfer), "text").is_err());
    }

    #[test]
    fn manifest_204_text_does_not_wait_for_transport_eof() {
        use std::io::{self, BufReader, Cursor, Read};

        // A valid HTTP/1.1 204 need not close its underlying connection.
        // Simulate a TLS peer that delivers all headers but never delivers
        // clean EOF: any read after the header terminator fails immediately.
        struct OpenConnection(Cursor<&'static [u8]>);
        impl Read for OpenConnection {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.position() == self.0.get_ref().len() as u64 {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "no EOF"));
                }
                self.0.read(buf)
            }
        }
        let wire: &'static [u8] = b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
        let response = BufReader::new(OpenConnection(Cursor::new(wire)));
        assert_eq!(manifest_response(response, "text").unwrap(), b"");
    }
}
