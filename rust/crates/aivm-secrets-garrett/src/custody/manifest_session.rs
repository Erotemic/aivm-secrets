//! Native manifest session. Only this private adapter borrows the credential;
//! policy compilation, disclosure and source-controller gates remain inspectable.
use super::*;
use crate::manifest::{disclosure::Disclosure, Effect, Policy};
use aivm_secrets_garrett_core::{manifest as guards, open_surrogate};

// W3/NR-1: the single phase/write authority is the extractable production
// core. The private adapter alone can acknowledge a real host audit write.
// Filesystem durability and late authorization remain external contracts.
use aivm_secrets_garrett_core::read_transition::{self, Phase as DispatchPhase};
use aivm_secrets_garrett_core::request_effects::RequestEffects;
use std::{cell::RefCell, rc::Rc};
type EffectsCell = Rc<RefCell<RequestEffects>>;

struct PreparedDispatch<'a> {
    effect: &'a Effect,
    transition: read_transition::Prepared,
}
struct AuditedDispatch<'a> {
    effect: &'a Effect,
    transition: read_transition::Audited,
}
impl<'a> PreparedDispatch<'a> {
    fn preflight(effect: &'a Effect) -> Outcome<Self> {
        let transition = read_transition::prepare(DispatchPhase::Preflight, false, effect.write)
            .map_err(|_| Error::InvalidPolicy)?;
        Ok(Self { effect, transition })
    }
    fn final_effect(effect: &'a Effect, admitted_write: bool) -> Outcome<Self> {
        let transition =
            read_transition::prepare(DispatchPhase::Final, admitted_write, effect.write)
                .map_err(|_| Error::InvalidPolicy)?;
        Ok(Self { effect, transition })
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
        effects: &EffectsCell,
    ) -> Outcome<AuditedDispatch<'a>> {
        // A hostile provider fact cannot turn a credential into a route or
        // an audit field. The body is intentionally absent from this record.
        crate::manifest::disclosure::ensure_safe(&json!({"target":self.effect.target}), &secret.0)?;
        if !effects.borrow_mut().begin_dispatch_audit(&self.transition) {
            return Err(Error::InternalError);
        }
        audit.write_record(&json!({
            "schema":1,
            "event":"dispatch",
            "phase":self.transition.phase().as_str(),
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
        // The adapter can assert success only after write_record returns.
        // fsync/IO acknowledgement is an explicit external proof premise.
        let transition = read_transition::acknowledge(self.transition, true)
            .map_err(|_| Error::InternalError)?;
        if !effects.borrow_mut().acknowledge_dispatch(&transition) {
            return Err(Error::InternalError);
        }
        Ok(AuditedDispatch {
            effect: self.effect,
            transition,
        })
    }
}

// W5/W6 guest-release boundary for successful manifest requests. A selected
// result is not a completed public reply until its exact fixed envelope has
// passed the reflection check (at the call site) and completion has been
// durably audited. This type does not itself prove response-byte refinement.
struct CompletedRelease(Value);
struct PendingCompletion<'a> {
    reply: Value,
    audit: &'a Audit,
    operation: &'a str,
    request_digest: &'a str,
    fresh: &'a dyn Fn() -> Outcome<()>,
    effects: EffectsCell,
}
impl read_transition::Completion for PendingCompletion<'_> {
    type Output = CompletedRelease;
    type Error = Error;

    fn recheck(&mut self, phase: read_transition::CompletionPhase) -> Outcome<()> {
        if !self.effects.borrow_mut().begin_completion_check(phase) {
            return Err(Error::InternalError);
        }
        (self.fresh)()?;
        if !self.effects.borrow_mut().finish_completion_check(phase) {
            return Err(Error::InternalError);
        }
        Ok(())
    }

    fn audit(&mut self) -> Outcome<()> {
        if !self.effects.borrow_mut().begin_completion_audit() {
            return Err(Error::InternalError);
        }
        self.audit.write_record(&json!({
            "schema":1,
            "event":"completed",
            "operation":self.operation,
            "grant":self.audit.grant,
            "policy":self.audit.policy,
            "request_digest":self.request_digest,
        }))?;
        if !self.effects.borrow_mut().acknowledge_completion_audit() {
            return Err(Error::InternalError);
        }
        Ok(())
    }

    fn release(self) -> Outcome<CompletedRelease> {
        if !self.effects.borrow_mut().value_ready() {
            return Err(Error::InternalError);
        }
        Ok(CompletedRelease(self.reply))
    }
}
impl CompletedRelease {
    fn into_public(self) -> Value {
        self.0
    }
}

// The core chooses phases and reply data; these adapters retain custody and
// the existing policy/audit/authority/TLS/disclosure implementations.
struct PendingRequest<P, D, F, C, R> {
    preflight: P,
    dispatch: D,
    final_effect: F,
    complete: C,
    fresh: R,
    effects: EffectsCell,
    snapshot: RequestEffects,
}

impl<P, D, F, C, R> read_transition::Request for PendingRequest<P, D, F, C, R>
where
    P: Fn() -> Outcome<Option<Effect>>,
    D: Fn(DispatchPhase, &Effect) -> Outcome<Value>,
    F: Fn(&Value) -> Outcome<Option<Effect>>,
    C: Fn(Value) -> Outcome<CompletedRelease>,
    R: Fn() -> Outcome<()>,
{
    type Facts = Value;
    type Effect = Effect;
    type Output = CompletedRelease;
    type Error = Error;
    const INVALID_TRANSITION: Error = Error::InternalError;

    fn preflight(&self) -> Outcome<Option<Effect>> {
        (self.preflight)()
    }
    fn empty_facts(&self) -> Value {
        Value::Null
    }
    fn dispatch(&mut self, phase: DispatchPhase, effect: Effect) -> Outcome<Value> {
        let out = (self.dispatch)(phase, &effect);
        self.snapshot = *self.effects.borrow();
        out
    }
    fn final_effect(&self, facts: &Value) -> Outcome<Option<Effect>> {
        (self.final_effect)(facts)
    }
    fn recheck(&mut self) -> Outcome<()> {
        let out = (self.fresh)();
        self.snapshot = *self.effects.borrow();
        out
    }
    fn effect_write(&self, effect: &Effect) -> bool {
        effect.write
    }
    fn complete(&mut self, raw: Value) -> Outcome<CompletedRelease> {
        let out = (self.complete)(raw);
        self.snapshot = *self.effects.borrow();
        if out.is_ok() && !self.snapshot.can_return_value() {
            return Err(Error::InternalError);
        }
        out
    }
    fn outcome_unknown(&self) -> Error {
        Error::OutcomeUnknown
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
        let current = || -> Outcome<guards::AdmissionStamp> {
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
            guards::current(
                &claims,
                &self.base.grant,
                &op.name.as_bytes().to_vec(),
                &op.name.as_bytes().to_vec(),
                op.write,
                self.writes_allowed(),
                current,
                self.base.elapsed()?,
            )
            .map_err(use_error)
        };
        let fresh = || current().map(|_| ());
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
        let effects = Rc::new(RefCell::new(RequestEffects::new()));
        let dispatch = |prepared: PreparedDispatch<'_>| -> Outcome<Value> {
            let recorded = prepared.audit(
                &self.base.executor.audit,
                &self.policy,
                &self.base.grant.route,
                &crate::model::claims_json(&outer.claims)?,
                &op.name,
                &request_hash,
                &secret,
                &effects,
            )?;
            let effect = recorded.effect;
            // Durable audit and a fresh grant both precede credentialed I/O.
            // Waiting for either must not extend identity or grant lifetime.
            let keyed_write = matches!(recorded.transition.phase(), DispatchPhase::Final)
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
                        &current,
                        &effects,
                    )
                },
                finish: || reservation_call(true),
            };
            let out = aivm_secrets_garrett_core::coordination::dispatch(&pending, keyed_write);
            if out.is_ok()
                && !effects
                    .borrow_mut()
                    .finish_dispatch(recorded.transition.phase())
            {
                return Err(Error::InternalError);
            }
            out
        };
        let release = |raw: Value| -> Outcome<CompletedRelease> {
            if !effects.borrow_mut().begin_completion() {
                return Err(Error::InternalError);
            }
            self.require_control_active(host_time()?)?;
            let meta = self.policy.pagination(op, &args, &raw)?;
            let result = self.disclosure.project(&op.name, &raw, &secret.0)?;
            let mut reply = json!({"version":1,"ok":true,"result":result});
            if let Some(meta) = meta {
                reply["meta"] = meta;
            }
            crate::manifest::disclosure::ensure_safe(&reply, &secret.0)?;
            if !effects.borrow_mut().selected() {
                return Err(Error::InternalError);
            }
            read_transition::complete_current(PendingCompletion {
                reply,
                audit: &self.base.executor.audit,
                operation: &op.name,
                request_digest: &request_hash,
                fresh: &fresh,
                effects: effects.clone(),
            })
        };
        let pending = PendingRequest {
            preflight: || self.policy.preflight(op, &args),
            final_effect: |facts: &Value| self.policy.final_effect(op, &args, facts),
            dispatch: |phase, effect: &Effect| match phase {
                DispatchPhase::Preflight => dispatch(PreparedDispatch::preflight(effect)?),
                DispatchPhase::Final => dispatch(PreparedDispatch::final_effect(effect, op.write)?),
            },
            complete: release,
            fresh: &fresh,
            effects: effects.clone(),
            snapshot: RequestEffects::new(),
        };
        read_transition::run_current(pending).map(CompletedRelease::into_public)
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

// The standard Write contract includes partial acceptance before an error.
// Keep the raw credential-bearing primitive this small and separately tested.
fn send_manifest_bytes(
    state: &mut aivm_secrets_garrett_core::provider_exchange::SendState,
    writer: &mut impl Write,
    request: &[u8],
    write: bool,
    effects: &EffectsCell,
    phase: DispatchPhase,
) -> Outcome<()> {
    if !effects.borrow_mut().begin_send(phase, state, write) {
        return Err(Error::InternalError);
    }
    writer
        .write_all(request)
        .and_then(|_| writer.flush())
        .map_err(|_| Error::UpstreamResponse)
}

struct ManifestChannel {
    stream: StreamOwned<ClientConnection, TcpStream>,
    request: Zeroizing<Vec<u8>>,
    _deadline: Deadline,
}
struct ManifestProvider<'a, F> {
    executor: &'a Executor,
    route: &'a core::Route,
    secret: &'a Credential,
    effect: &'a Effect,
    headers: &'a BTreeMap<String, String>,
    current: &'a F,
    send_state: aivm_secrets_garrett_core::provider_exchange::SendState,
    effects: EffectsCell,
    phase: DispatchPhase,
}
impl<F: Fn() -> Outcome<guards::AdmissionStamp>>
    aivm_secrets_garrett_core::provider_exchange::Provider for ManifestProvider<'_, F>
{
    type Channel = ManifestChannel;
    type Output = Value;
    type Error = Error;
    const INVALID_POLICY: Error = Error::InvalidPolicy;
    const OUTCOME_UNKNOWN: Error = Error::OutcomeUnknown;

    fn setup(&mut self) -> Outcome<ManifestChannel> {
        let request = manifest_request_bytes(self.route, self.secret, self.effect, self.headers)?;
        let host = std::str::from_utf8(&self.route.host).map_err(|_| Error::InvalidPolicy)?;
        let mut socket = TcpStream::connect_timeout(
            &SocketAddr::new(
                self.executor.address,
                u16::try_from(self.route.port).map_err(|_| Error::InvalidPolicy)?,
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
        let deadline = Deadline::start_for(Duration::from_secs(40), move || {
            let _ = killer.shutdown(std::net::Shutdown::Both);
        });
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| Error::InvalidPolicy)?;
        let mut conn = ClientConnection::new(self.executor.tls.clone(), name)
            .map_err(|_| Error::Unreachable)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut socket)
                .map_err(|_| Error::Unreachable)?;
        }
        let stream = StreamOwned::new(conn, socket);

        Ok(ManifestChannel {
            stream,
            request,
            _deadline: deadline,
        })
    }
    fn recheck(&mut self) -> Outcome<guards::AdmissionStamp> {
        if !self.send_state.begin_check() {
            return Err(Error::InternalError);
        }
        let stamp = (self.current)()?;
        if !self.send_state.finish_check(stamp) {
            return Err(Error::InternalError);
        }
        Ok(stamp)
    }
    fn send(&mut self, channel: &mut ManifestChannel) -> Outcome<()> {
        // The only credential-bearing write in this manifest adapter. The
        // core has already obtained a current stamp after verified TLS setup.
        send_manifest_bytes(
            &mut self.send_state,
            &mut channel.stream,
            &channel.request,
            self.effect.write,
            &self.effects,
            self.phase,
        )
    }
    fn receive(&mut self, channel: ManifestChannel) -> Outcome<Value> {
        let ManifestChannel {
            stream,
            request: _request,
            _deadline,
        } = channel;
        let effect = self.effect;
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
    }
}
impl Executor {
    fn exchange_manifest(
        &self,
        route: &core::Route,
        secret: &Credential,
        audited: &AuditedDispatch<'_>,
        headers: &BTreeMap<String, String>,
        current: &impl Fn() -> Outcome<guards::AdmissionStamp>,
        effects: &EffectsCell,
    ) -> Outcome<Value> {
        let effect = audited.effect;
        if audited.transition.is_write() != effect.write {
            return Err(Error::InvalidPolicy);
        }
        if !effects.borrow_mut().begin_provider(&audited.transition) {
            return Err(Error::InternalError);
        }
        let mut provider = ManifestProvider {
            executor: self,
            route,
            secret,
            effect,
            headers,
            current,
            send_state: aivm_secrets_garrett_core::provider_exchange::SendState::new(),
            effects: effects.clone(),
            phase: audited.transition.phase(),
        };
        let report = aivm_secrets_garrett_core::provider_exchange::exchange(
            &mut provider,
            &audited.transition,
        );
        if report.stage() == aivm_secrets_garrett_core::provider_exchange::Stage::Complete
            && !effects
                .borrow_mut()
                .provider_completed(audited.transition.phase())
        {
            return Err(Error::InternalError);
        }
        report.into_result()
    }
}

fn manifest_response(mut reader: impl BufRead, format: &str) -> Outcome<Vec<u8>> {
    let status = response_status(&line(&mut reader, 4096)?)?;
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
            .insert(name.to_ascii_lowercase(), response_ows(value).to_owned())
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
        .map(response_ows);
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

    #[test]
    fn completion_snapshot_tracks_real_audit_and_late_denial() {
        use std::os::unix::fs::OpenOptionsExt;
        // Exercise the actual audit primitive and mutable request adapter,
        // including an acknowledged completion followed by fresh denial.
        for (audit_failed, late_denial) in [(false, false), (true, false), (false, true)] {
            let path = std::env::temp_dir().join(format!(
                "garrett-completion-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            struct Cleanup(std::path::PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(&self.0);
                }
            }
            let _cleanup = Cleanup(path.clone());
            let audit = Audit {
                state: Mutex::new(AuditState {
                    file,
                    failed: audit_failed,
                }),
                grant: "synthetic-grant".into(),
                policy: "synthetic-policy".into(),
            };
            let effects = Rc::new(RefCell::new(RequestEffects::new()));
            assert!(effects.borrow_mut().begin_completion());
            assert!(effects.borrow_mut().selected());
            let checks = std::cell::Cell::new(0);
            let fresh = || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    let bytes = std::fs::read(&path).unwrap();
                    let row: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(row["event"], "completed");
                    assert!(effects.borrow().completion().audit_acknowledged());
                    if late_denial {
                        return Err(Error::Revoked);
                    }
                }
                Ok(())
            };
            let mut adapter = PendingRequest {
                preflight: || Ok(None),
                dispatch: |_: DispatchPhase, _: &Effect| Ok(Value::Null),
                final_effect: |_: &Value| Ok(None),
                complete: |reply| {
                    read_transition::complete_current(PendingCompletion {
                        reply,
                        audit: &audit,
                        operation: "synthetic.read",
                        request_digest: "synthetic-request",
                        fresh: &fresh,
                        effects: effects.clone(),
                    })
                },
                fresh: || Ok(()),
                effects: effects.clone(),
                snapshot: RequestEffects::new(),
            };
            let out = read_transition::Request::complete(&mut adapter, json!({"ok":true}));
            let recorded = adapter.snapshot.completion();
            assert!(recorded.selected() && recorded.before_checked() && recorded.audit_attempted());
            assert_eq!(recorded.audit_acknowledged(), !audit_failed);
            assert_eq!(recorded.after_checked(), !audit_failed && !late_denial);
            assert_eq!(
                adapter.snapshot.can_return_value(),
                !audit_failed && !late_denial
            );
            if audit_failed {
                assert!(matches!(out, Err(Error::InternalError)));
                assert_eq!(checks.get(), 1);
                assert!(std::fs::read(&path).unwrap().is_empty());
            } else if late_denial {
                assert!(matches!(out, Err(Error::Revoked)));
                assert_eq!(checks.get(), 2);
            } else {
                assert_eq!(out.unwrap().into_public(), json!({"ok":true}));
                assert_eq!(checks.get(), 2);
            }
        }
    }

    struct PartialWriter {
        accepted: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        limit: usize,
        flush_error: bool,
    }
    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut accepted = self.accepted.borrow_mut();
            if accepted.len() >= self.limit {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            let count = bytes.len().min(self.limit - accepted.len());
            accepted.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.flush_error {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            } else {
                Ok(())
            }
        }
    }
    struct FaultProvider {
        accepted: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        limit: usize,
        flush_error: bool,
        current: guards::AdmissionStamp,
        send_state: aivm_secrets_garrett_core::provider_exchange::SendState,
        effects: EffectsCell,
        parsed: bool,
    }
    impl aivm_secrets_garrett_core::provider_exchange::Provider for FaultProvider {
        type Channel = PartialWriter;
        type Output = Value;
        type Error = Error;
        const INVALID_POLICY: Error = Error::InvalidPolicy;
        const OUTCOME_UNKNOWN: Error = Error::OutcomeUnknown;
        fn setup(&mut self) -> Outcome<PartialWriter> {
            Ok(PartialWriter {
                accepted: self.accepted.clone(),
                limit: self.limit,
                flush_error: self.flush_error,
            })
        }
        fn recheck(&mut self) -> Outcome<guards::AdmissionStamp> {
            assert!(self.send_state.begin_check());
            assert!(self.send_state.finish_check(self.current));
            Ok(self.current)
        }
        fn send(&mut self, writer: &mut PartialWriter) -> Outcome<()> {
            send_manifest_bytes(
                &mut self.send_state,
                writer,
                b"synthetic-request",
                self.current.write(),
                &self.effects,
                DispatchPhase::Final,
            )
        }
        fn receive(&mut self, _writer: PartialWriter) -> Outcome<Value> {
            self.parsed = true;
            Ok(json!({"selected":true}))
        }
    }
    #[test]
    fn partial_native_write_and_flush_failures_are_attempts_and_never_parse_or_retry() {
        use aivm_secrets_garrett_core::{
            credential_use::{UseClaims, UseGrant},
            provider_exchange,
        };
        let claims = || UseClaims {
            binding: b"client".to_vec(),
            policy: b"policy".to_vec(),
            grant: b"grant".to_vec(),
            issued_at: 1,
            expires_at: 100,
        };
        let grant = UseGrant {
            claims: claims(),
            operation: b"read".to_vec(),
            route: route(),
            active: true,
        };
        for write in [false, true] {
            for (limit, flush_error) in [(0, false), (5, false), (usize::MAX, true)] {
                let current = guards::current(
                    &claims(),
                    &grant,
                    &b"read".to_vec(),
                    &b"read".to_vec(),
                    write,
                    true,
                    2,
                    1,
                )
                .ok()
                .unwrap();
                let prepared = read_transition::prepare(DispatchPhase::Final, write, write)
                    .ok()
                    .unwrap();
                let effects = Rc::new(RefCell::new(RequestEffects::new()));
                assert!(effects.borrow_mut().begin_dispatch_audit(&prepared));
                let audited = read_transition::acknowledge(prepared, true).ok().unwrap();
                assert!(effects.borrow_mut().acknowledge_dispatch(&audited));
                assert!(effects.borrow_mut().begin_provider(&audited));
                let accepted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
                let mut provider = FaultProvider {
                    accepted: accepted.clone(),
                    limit,
                    flush_error,
                    current,
                    send_state: provider_exchange::SendState::new(),
                    effects: effects.clone(),
                    parsed: false,
                };
                let report = provider_exchange::exchange(&mut provider, &audited);
                assert_eq!(report.stage(), provider_exchange::Stage::Send);
                assert!(report.stage().attempted());
                assert_eq!(
                    report.into_result(),
                    Err(if write {
                        Error::OutcomeUnknown
                    } else {
                        Error::UpstreamResponse
                    })
                );
                assert!(!provider.parsed);
                let before = accepted.borrow().clone();
                let mut retry = PartialWriter {
                    accepted: accepted.clone(),
                    limit: usize::MAX,
                    flush_error: false,
                };
                assert_eq!(
                    send_manifest_bytes(
                        &mut provider.send_state,
                        &mut retry,
                        b"synthetic-request",
                        write,
                        &effects,
                        DispatchPhase::Final,
                    ),
                    Err(Error::InternalError)
                );
                assert_eq!(*accepted.borrow(), before);
                assert_eq!(
                    &*accepted.borrow(),
                    &b"synthetic-request"[..limit.min(b"synthetic-request".len())]
                );
            }
        }
    }

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
        assert!(matches!(
            PreparedDispatch::preflight(&write),
            Err(Error::InvalidPolicy)
        ));
        assert!(matches!(
            PreparedDispatch::final_effect(&write, false),
            Err(Error::InvalidPolicy)
        ));
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
        assert_eq!(
            manifest_response(Cursor::new(no_content), "text").unwrap(),
            b""
        );
        assert!(manifest_response(Cursor::new(no_content), "json").is_err());
        // Any stray upstream bytes after a 204 header are not part of the
        // representation and must never appear in the selected guest text.
        let invalid_extra = b"HTTP/1.1 204 No Content\r\n\r\nDO-NOT-RELEASE";
        assert_eq!(
            manifest_response(Cursor::new(invalid_extra), "text").unwrap(),
            b""
        );
        let illegal_204_length = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        assert!(manifest_response(Cursor::new(illegal_204_length), "text").is_err());
        let illegal_204_transfer =
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
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
