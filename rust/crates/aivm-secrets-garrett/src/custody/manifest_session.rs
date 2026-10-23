//! Native manifest session. Only this private adapter borrows the credential;
//! policy compilation, disclosure and source-controller gates remain inspectable.
use super::*;
use crate::manifest::{disclosure::Disclosure, Effect, Policy};
use aivm_secrets_garrett_core::{manifest as guards, open_surrogate};

// The core owns phase/write permits and receipt transitions. Native work
// supplies the actual authority, audit, TLS and selected-value primitives.
// Their context, durability and I/O semantics retain separate contracts.
use aivm_secrets_garrett_core::read_transition::{self, Phase as DispatchPhase};
use aivm_secrets_garrett_core::request_adapter;

// Native factories retain custody and conversion/I/O semantics. The extracted
// request adapter owns the one receipt across dispatch and completed release.
struct PendingCompletion<'a, S> {
    select: S,
    audit: &'a Audit,
    operation: &'a str,
    request_digest: &'a str,
    fresh: &'a dyn Fn() -> Outcome<()>,
}
impl<O, S: FnMut() -> Outcome<O>> aivm_secrets_garrett_core::completion::Work
    for PendingCompletion<'_, S>
{
    type Output = O;
    type Error = Error;
    const INVALID_TRANSITION: Error = Error::InternalError;

    fn select(&mut self) -> Outcome<O> {
        (self.select)()
    }
    fn recheck(&mut self, _phase: read_transition::CompletionPhase) -> Outcome<()> {
        (self.fresh)()
    }
    fn audit(&mut self) -> Outcome<()> {
        // The record's shape is the extracted `session_audit::event_record`.
        self.audit.append_value(&aivm_secrets_garrett_core::session_audit::event_record(
            super::wire_text("completed"),
            super::wire_text(&self.audit.grant),
            super::wire_text(&self.audit.policy),
            Some(super::wire_text(self.operation)),
            Some(super::wire_text(self.request_digest)),
        ))
    }
}
struct PendingRequest<P, D, F, C, R> {
    preflight: P,
    dispatch: D,
    final_effect: F,
    complete: C,
    fresh: R,
    operation_write: bool,
}
impl<P, D, F, C, R, DP, CP> request_adapter::Work for PendingRequest<P, D, F, C, R>
where
    P: Fn() -> Outcome<Option<Effect>>,
    D: FnMut(DispatchPhase, Effect) -> request_adapter::DispatchPlan<DP>,
    F: Fn(&Value) -> Outcome<Option<Effect>>,
    C: FnMut(Value) -> CP,
    R: Fn() -> Outcome<()>,
    DP: aivm_secrets_garrett_core::dispatch::Work<Output = Value, Error = Error>,
    CP: aivm_secrets_garrett_core::completion::Work<Error = Error>,
{
    type Facts = Value;
    type Effect = Effect;
    type Output = CP::Output;
    type Error = Error;
    type Dispatch = DP;
    type Completion = CP;
    const INVALID_TRANSITION: Error = Error::InternalError;
    const INVALID_POLICY: Error = Error::InvalidPolicy;

    fn preflight(&self) -> Outcome<Option<Effect>> {
        (self.preflight)()
    }
    fn empty_facts(&self) -> Value {
        Value::Null
    }
    fn final_effect(&self, facts: &Value) -> Outcome<Option<Effect>> {
        (self.final_effect)(facts)
    }
    fn effect_write(&self, effect: &Effect) -> bool {
        effect.write
    }
    fn operation_write(&self) -> bool {
        self.operation_write
    }
    fn dispatch(
        &mut self,
        phase: DispatchPhase,
        effect: Effect,
    ) -> request_adapter::DispatchPlan<DP> {
        (self.dispatch)(phase, effect)
    }
    fn complete(&mut self, raw: Value) -> CP {
        (self.complete)(raw)
    }
    fn recheck(&mut self) -> Outcome<()> {
        (self.fresh)()
    }
    fn outcome_unknown(&self) -> Error {
        Error::OutcomeUnknown
    }
}

// Pagination, projection, assembly, both reflection checks and the wire value
// are extracted `selected_release::Manifest`; only the current-control check
// and the mapping of its refusals to public errors remain native.
struct ManifestCurrent<'a> {
    session: &'a Session,
}
impl aivm_secrets_garrett_core::selected_release::Current for ManifestCurrent<'_> {
    type Error = Error;

    fn current(&mut self) -> Outcome<()> {
        self.session.require_control_active(host_time()?)
    }
    fn refuse(&mut self, denial: aivm_secrets_garrett_core::selected_release::Denial) -> Error {
        use aivm_secrets_garrett_core::selected_release::Denial;
        match denial {
            Denial::Denied => Error::Denied,
            Denial::UpstreamResponse => Error::UpstreamResponse,
            Denial::InvalidRequest => Error::InvalidRequest,
        }
    }
}

// Only external observations remain native; the context and validation order
// are owned by the extracted current-admission controller.
struct CurrentChecks<'a, L> {
    session: &'a Session,
    lease: L,
}
impl<L: Fn(i64) -> Outcome<()>> aivm_secrets_garrett_core::current_admission::Checks
    for CurrentChecks<'_, L>
{
    type Error = Error;
    const INVALID_CAPABILITY: Error = Error::InvalidCapability;
    fn coordination(&mut self) -> Outcome<()> {
        self.session.base.check_coordination()
    }
    fn clock(&mut self) -> Outcome<i64> {
        host_time()
    }
    fn control(&mut self, now: i64) -> Outcome<()> {
        self.session.require_control_active(now)
    }
    fn lease(&mut self, now: i64) -> Outcome<()> {
        (self.lease)(now)
    }
    fn elapsed(&mut self) -> Outcome<i64> {
        self.session.base.elapsed()
    }
    fn use_error(error: aivm_secrets_garrett_core::credential_use::UseDenial) -> Error {
        use_error(error)
    }
}

// This factory supplies observations only. The extracted request wrapper
// chooses the one context used by every produced provider adapter.
struct CurrentFactory<'a, L> {
    session: &'a Session,
    lease: L,
}
impl<'a, L: Copy + Fn(i64) -> Outcome<()>> aivm_secrets_garrett_core::request_context::CheckFactory
    for CurrentFactory<'a, L>
{
    type Error = Error;
    type Checks = CurrentChecks<'a, L>;
    fn checks(&mut self) -> Self::Checks {
        CurrentChecks {
            session: self.session,
            lease: self.lease,
        }
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
    ) -> Outcome<json::Reply> {
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
        let current_peer = peer.thumbprint().as_bytes().to_vec();
        let current_operation = op.name.as_bytes().to_vec();
        let current_context = aivm_secrets_garrett_core::current_admission::Context::new(
            &outer.claims,
            &expected,
            &current_peer,
            &claims,
            &self.base.grant,
            &current_operation,
            op.write,
            self.writes_allowed(),
        );
        let current_lease = |current| {
            if let Some(lease) = &_vault {
                lease.require_current(current)?;
            }
            Ok(())
        };
        let current = || -> Outcome<guards::AdmissionStamp> {
            current_context.current(&mut CurrentChecks {
                session: self,
                lease: &current_lease,
            })
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
        // Factories return primitive adapters only. Receipt ownership, phase
        // preparation, controller calls and every error post-state are core.
        let dispatch = |phase: DispatchPhase, effect: Effect| {
            let keyed_write = matches!(phase, DispatchPhase::Final)
                && effect.write
                && self.base.coordinator.is_some();
            let work = ManifestProvider {
                executor: &self.base.executor,
                effect,
                headers: BTreeMap::new(),
                dispatch: ManifestDispatch {
                    policy: &self.policy,
                    identity: None,
                    claims: &outer.claims,
                    operation: &op.name,
                    request_digest: &request_hash,
                    fresh: &fresh,
                    coordinator: self.base.coordinator.as_ref(),
                    reservation: reservation
                        .as_ref()
                        .map(|(key, fingerprint)| (key.as_str(), fingerprint.as_str())),
                    idempotency_header: op.idempotency_header,
                },
            };
            request_adapter::DispatchPlan {
                work: aivm_secrets_garrett_core::channel_work::Submitting::new(work, &secret.0),
                keyed_write,
            }
        };
        let session = &*self;
        let selection_fields = self.disclosure.fields(&op.name);
        let page = self.policy.page(op, &args);
        let selection_page = &page;
        let selection_secret = &secret;
        let release = |raw: Value| PendingCompletion {
            select: move || {
                let document = crate::manifest::disclosure::document(&raw);
                let mut selection = aivm_secrets_garrett_core::selected_release::Manifest {
                    current: ManifestCurrent { session },
                    document: &document,
                    fields: selection_fields,
                    page: selection_page,
                    secret: &selection_secret.0,
                };
                aivm_secrets_garrett_core::selected_release::select(&mut selection)
            },
            audit: &self.base.executor.audit,
            operation: &op.name,
            request_digest: &request_hash,
            fresh: &fresh,
        };
        let work = PendingRequest {
            preflight: || self.policy.preflight(op, &args),
            final_effect: |facts: &Value| self.policy.final_effect(op, &args, facts),
            dispatch,
            complete: release,
            fresh: &fresh,
            operation_write: op.write,
        };
        let work = aivm_secrets_garrett_core::request_context::ScopedRequest::new(
            &current_context,
            work,
            CurrentFactory {
                session: self,
                lease: &current_lease,
            },
        );
        let pending = request_adapter::Pending::new(work);
        // The extracted gate runs the production controller only when the
        // exact-write approval decision is `Allowed`; nothing above performs
        // provider I/O.
        match aivm_secrets_garrett_core::write_gate::run_approved(decision, pending) {
            aivm_secrets_garrett_core::write_gate::Gated::Ran(result) => result
                .map(aivm_secrets_garrett_core::completion::Completed::into_value)
                .map(|wire| json::Reply::Released(json::Captured::released(wire))),
            aivm_secrets_garrett_core::write_gate::Gated::Denied => Err(Error::Denied),
            aivm_secrets_garrett_core::write_gate::Gated::Required => {
                fresh()?;
                let reply = json!({"version":1,"ok":false,"error":{"code":"approval_required", "message":"Exact write needs host approval."},"approval":{"digest":approval_digest}});
                crate::manifest::disclosure::ensure_safe(&reply, &secret.0)?;
                self.control
                    .as_ref()
                    .ok_or(Error::InternalError)?
                    .state
                    .remember(&approval_digest, &canonical_request)?;
                Ok(json::Reply::Native(reply))
            }
        }
    }

    pub(super) fn control(
        &mut self,
        verifier: &Verifier,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: Expectation,
        verb: &str,
    ) -> Outcome<crate::json::Reply> {
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
        let operations: Vec<Vec<u8>> = self
            .policy
            .operations()
            .into_iter()
            .map(String::into_bytes)
            .collect();
        let description =
            aivm_secrets_garrett_core::control::manifest_description(&operations, &self.writes);
        let audit = &self.base.executor.audit;
        let revoked = aivm_secrets_garrett_core::control::revoked_record(
            super::wire_text(&audit.grant),
            super::wire_text(&audit.policy),
            None,
        );
        let mut native = ManifestControl(self);
        super::controlled(aivm_secrets_garrett_core::control::control(
            &mut native,
            verb.as_bytes(),
            description,
            revoked,
        ))
    }
}
/// The manifest session's control side effects (`proofs/GarrettControl.lean`).
struct ManifestControl<'a>(&'a mut Session);
impl aivm_secrets_garrett_core::control::Control for ManifestControl<'_> {
    type Error = Error;
    fn revoke(&mut self) {
        if let Some(control) = &self.0.control {
            control.state.revoke();
        }
    }
    fn record(&mut self, record: &[u8]) -> Outcome<()> {
        self.0.base.executor.audit.append_bytes(&record.to_vec())
    }
    fn deactivate(&mut self) {
        self.0.base.grant.active = false;
    }
}

// W6 concrete provider-wire boundary. Policy construction normally checks
// these fields already, but the adapter must not trust that its caller has
// preserved those checks. In particular OAuthSource can construct Credential
// directly rather than calling credential_at_least. Reject CR/LF in the final
// bytes, before a single provider write, to prevent HTTP request injection.
// Host-selected request fields; the extracted encoder adds the credential.
fn manifest_fields(
    effect: &Effect,
    headers: &BTreeMap<String, String>,
) -> aivm_secrets_garrett_core::provider_wire::Fields {
    aivm_secrets_garrett_core::provider_wire::Fields {
        method: effect.method.as_bytes().to_vec(),
        target: effect.target.as_bytes().to_vec(),
        accept: effect.accept.as_bytes().to_vec(),
        // Preserve BTreeMap order; the checked encoder rejects overrides and
        // case-insensitive duplicates after conversion.
        headers: headers
            .iter()
            .map(|(name, value)| http_wire::Header {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            })
            .collect(),
    }
}
fn encoding_error(error: http_wire::EncodingDenial) -> Error {
    match error {
        http_wire::EncodingDenial::InvalidRequest => Error::InvalidPolicy,
        http_wire::EncodingDenial::InvalidCredential => Error::CredentialSource,
    }
}

// The standard Write contract includes partial acceptance before an error.
// Keep the raw credential-bearing primitive this small and separately tested.
struct ManifestWire(Zeroizing<Vec<u8>>);
impl aivm_secrets_garrett_core::provider_io::WireBytes for ManifestWire {
    fn bytes(&self) -> &Vec<u8> {
        &self.0
    }
}
struct ProviderWriter<W: Write>(W);
impl<W: Write> aivm_secrets_garrett_core::provider_io::Writer for ProviderWriter<W> {
    type Error = Error;
    const INVALID_TRANSITION: Error = Error::InternalError;
    fn write_all(&mut self, bytes: &Vec<u8>) -> Outcome<()> {
        self.0.write_all(bytes).map_err(|_| Error::UpstreamResponse)
    }
    fn flush(&mut self) -> Outcome<()> {
        self.0.flush().map_err(|_| Error::UpstreamResponse)
    }
}

struct ManifestDispatch<'a> {
    policy: &'a Policy,
    identity: Option<Value>,
    claims: &'a aivm_secrets_garrett_core::Claims,
    operation: &'a str,
    request_digest: &'a str,
    fresh: &'a dyn Fn() -> Outcome<()>,
    coordinator: Option<&'a crate::coordination::Coordinator>,
    reservation: Option<(&'a str, &'a str)>,
    idempotency_header: bool,
}
// Holds no credential: the extracted `channel_work::Submitting` owns it, the
// request encoding, the target reflection check, the channel construction,
// the send (`Channel::submit`) and the response gate.
struct ManifestProvider<'a> {
    executor: &'a Executor,
    effect: Effect,
    headers: BTreeMap<String, String>,
    dispatch: ManifestDispatch<'a>,
}
impl aivm_secrets_garrett_core::channel_work::ChannelWork for ManifestProvider<'_> {
    type Body = ManifestWire;
    type Writer = ProviderWriter<StreamOwned<ClientConnection, TcpStream>>;
    type Meta = Deadline;
    type Output = Value;
    type Error = Error;
    const INVALID_TRANSITION: Error = Error::InternalError;
    const INVALID_POLICY: Error = Error::InvalidPolicy;
    const OUTCOME_UNKNOWN: Error = Error::OutcomeUnknown;
    const REFLECTED: Error = Error::UpstreamResponse;

    fn effect_write(&self) -> bool {
        self.effect.write
    }
    fn prepare(&mut self) -> Outcome<()> {
        self.dispatch.identity = Some(crate::model::claims_json(self.dispatch.claims)?);
        Ok(())
    }
    fn target(&self) -> Vec<u8> {
        self.effect.target.as_bytes().to_vec()
    }
    fn configure(&mut self, keyed_write: bool) -> Outcome<()> {
        self.headers = self.dispatch.policy.headers.clone();
        if keyed_write && self.dispatch.idempotency_header {
            let (key, _) = self.dispatch.reservation.ok_or(Error::InvalidRequest)?;
            self.headers.insert("Idempotency-Key".into(), key.into());
        }
        Ok(())
    }
    fn check(&mut self) -> Outcome<()> {
        (self.dispatch.fresh)()
    }
    fn reserve(&mut self) -> Outcome<()> {
        let (key, fingerprint) = self.dispatch.reservation.ok_or(Error::InvalidRequest)?;
        self.dispatch
            .coordinator
            .ok_or(Error::InvalidRequest)?
            .reserve(key, fingerprint)
    }
    fn finish(&mut self) -> Outcome<()> {
        let (key, fingerprint) = self.dispatch.reservation.ok_or(Error::InvalidRequest)?;
        self.dispatch
            .coordinator
            .ok_or(Error::InvalidRequest)?
            .finish(key, fingerprint)
    }
    fn parse(
        &mut self,
        released: aivm_secrets_garrett_core::response_gate::Released<
            ManifestWire,
            ProviderWriter<StreamOwned<ClientConnection, TcpStream>>,
            Deadline,
        >,
    ) -> Outcome<Value> {
        let mut parser = ManifestResponse { effect: &self.effect };
        parser.parse(released)
    }
    fn audit_route(&mut self, route: &core::Route, phase: DispatchPhase) -> Outcome<()> {
        let audit = &self.executor.audit;
        audit.write_record(&json!({
            "schema":1,
            "event":"dispatch",
            "phase":phase.as_str(),
            "grant":audit.grant,
            "policy":audit.policy,
            "identity":self.dispatch.identity.as_ref().ok_or(Error::InternalError)?,
            "operation":self.dispatch.operation,
            "request_digest":self.dispatch.request_digest,
            "route":{
                "host":std::str::from_utf8(&route.host).map_err(|_| Error::InvalidPolicy)?,
                "port":route.port,
                "method":self.effect.method,
                "path":self.effect.target,
            }
        }))
    }
    fn request_fields(&mut self) -> Outcome<aivm_secrets_garrett_core::channel_work::RequestParts> {
        Ok(aivm_secrets_garrett_core::channel_work::RequestParts {
            fields: manifest_fields(&self.effect, &self.headers),
            body: self.effect.body.as_ref().map(json::canonical),
        })
    }
    fn wrap_body(&mut self, encoded: Vec<u8>) -> ManifestWire {
        ManifestWire(Zeroizing::new(encoded))
    }
    fn encoding_error(&mut self, denial: http_wire::EncodingDenial) -> Error {
        encoding_error(denial)
    }
    fn connect(
        &mut self,
        endpoint: &aivm_secrets_garrett_core::provider_wire::Endpoint,
    ) -> Outcome<(ProviderWriter<StreamOwned<ClientConnection, TcpStream>>, Deadline)> {
        let host = std::str::from_utf8(endpoint.host()).map_err(|_| Error::InvalidPolicy)?;
        let mut socket = TcpStream::connect_timeout(
            &SocketAddr::new(self.executor.address, endpoint.port()),
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

        Ok((ProviderWriter(stream), deadline))
    }
}
// The native parser consumes a non-forgeable, non-cloneable Released token.
// It has no Channel input and cannot construct a Released token itself.
struct ManifestResponse<'a> {
    effect: &'a Effect,
}
impl ManifestResponse<'_> {
    fn parse(
        &mut self,
        released: aivm_secrets_garrett_core::response_gate::Released<
            ManifestWire,
            ProviderWriter<StreamOwned<ClientConnection, TcpStream>>,
            Deadline,
        >,
    ) -> Outcome<Value> {
        let (ProviderWriter(stream), _request, _deadline) = released.into_parts();
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
fn manifest_response(mut reader: impl BufRead, format: &str) -> Outcome<Vec<u8>> {
    let status = response_status(&line(&mut reader, 4096)?)?;
    // 4xx, other non-2xx and partial (206) responses are refused by the
    // extracted classification; partial content is never a complete result.
    aivm_secrets_garrett_core::provider_status::manifest(status).map_err(status_error)?;
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
    // Test oracle: production encodes in `channel_work::Submitting`.
    fn manifest_request_bytes(
        route: &core::Route,
        secret: &Credential,
        effect: &Effect,
        headers: &BTreeMap<String, String>,
    ) -> Outcome<(
        Zeroizing<Vec<u8>>,
        aivm_secrets_garrett_core::provider_wire::Endpoint,
    )> {
        let fields = manifest_fields(effect, headers);
        let body = effect
            .body
            .as_ref()
            .map(|value| Zeroizing::new(json::canonical(value)));
        let mut output = Zeroizing::new(Vec::new());
        let endpoint = aivm_secrets_garrett_core::provider_wire::append(
            &mut output,
            route,
            fields,
            &secret.0,
            body.as_ref().map(|value| value.as_slice()),
        )
        .map_err(encoding_error)?;
        Ok((output, endpoint))
    }
    use aivm_secrets_garrett_core::request_effects::RequestEffects;

    #[test]
    fn completion_receipt_tracks_real_audit_and_late_denial() {
        use std::os::unix::fs::OpenOptionsExt;
        // Exercise the actual audit primitive and mutable request adapter,
        // including an acknowledged completion followed by fresh denial.
        for (selection_failed, audit_failed, late_denial) in [
            (true, false, false),
            (false, false, false),
            (false, true, false),
            (false, false, true),
        ] {
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
            let checks = std::cell::Cell::new(0);
            let fresh = || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    let bytes = std::fs::read(&path).unwrap();
                    let row: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(row["event"], "completed");
                    if late_denial {
                        return Err(Error::Revoked);
                    }
                }
                Ok(())
            };
            let work = PendingRequest {
                preflight: || Ok(None),
                dispatch: |_: DispatchPhase,
                           _: Effect|
                 -> request_adapter::DispatchPlan<FaultProvider> {
                    panic!("completion-only fixture must not construct a provider")
                },
                final_effect: |_: &Value| Ok(None),
                complete: |reply: Value| PendingCompletion {
                    select: move || {
                        if selection_failed {
                            Err(Error::Denied)
                        } else {
                            Ok(reply.clone())
                        }
                    },
                    audit: &audit,
                    operation: "synthetic.read",
                    request_digest: "synthetic-request",
                    fresh: &fresh,
                },
                fresh: || Ok(()),
                operation_write: false,
            };
            let mut adapter = request_adapter::Pending::new(work);
            let out = read_transition::Request::complete(&mut adapter, json!({"ok":true}));
            let recorded = adapter.effects().completion();
            assert_eq!(recorded.selected(), !selection_failed);
            assert_eq!(recorded.before_checked(), !selection_failed);
            assert_eq!(recorded.audit_attempted(), !selection_failed);
            assert_eq!(
                recorded.audit_acknowledged(),
                !selection_failed && !audit_failed
            );
            assert_eq!(
                recorded.after_checked(),
                !selection_failed && !audit_failed && !late_denial
            );
            assert_eq!(
                adapter.effects().can_return_value(),
                !selection_failed && !audit_failed && !late_denial
            );
            if selection_failed {
                assert!(matches!(out, Err(Error::Denied)));
                assert_eq!(checks.get(), 0);
                assert!(std::fs::read(&path).unwrap().is_empty());
                // An all-false flag record still retains the attempted
                // selection progress; losing copy-back would reopen it.
                assert!(matches!(
                    read_transition::Request::complete(&mut adapter, json!({"ok":true})),
                    Err(Error::InternalError)
                ));
                assert_eq!(checks.get(), 0);
            } else if audit_failed {
                assert!(matches!(out, Err(Error::InternalError)));
                assert_eq!(checks.get(), 1);
                assert!(std::fs::read(&path).unwrap().is_empty());
            } else if late_denial {
                assert!(matches!(out, Err(Error::Revoked)));
                assert_eq!(checks.get(), 2);
            } else {
                assert_eq!(out.unwrap().into_value(), json!({"ok":true}));
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
        parsed: bool,
        audit: Option<Arc<Audit>>,
        deny_after_audit: bool,
    }
    impl aivm_secrets_garrett_core::provider_exchange::Provider for FaultProvider {
        type Channel = aivm_secrets_garrett_core::provider_io::Channel<
            ManifestWire,
            ProviderWriter<PartialWriter>,
            (),
        >;
        type Output = Value;
        type Error = Error;
        const INVALID_POLICY: Error = Error::InvalidPolicy;
        const OUTCOME_UNKNOWN: Error = Error::OutcomeUnknown;
        fn setup(&mut self) -> Outcome<Self::Channel> {
            Ok(aivm_secrets_garrett_core::provider_io::Channel::new(
                ManifestWire(Zeroizing::new(b"synthetic-request".to_vec())),
                ProviderWriter(PartialWriter {
                    accepted: self.accepted.clone(),
                    limit: self.limit,
                    flush_error: self.flush_error,
                }),
                (),
            ))
        }
        fn recheck(&mut self) -> Outcome<guards::AdmissionStamp> {
            if self.deny_after_audit {
                return Err(Error::Revoked);
            }
            Ok(self.current)
        }
        fn send(&mut self, channel: &mut Self::Channel) -> Outcome<()> {
            channel.submit()
        }
        fn receive(&mut self, channel: Self::Channel) -> Outcome<Value> {
            let _parts = channel.into_parts()?;
            self.parsed = true;
            Ok(json!({"selected":true}))
        }
    }
    impl aivm_secrets_garrett_core::dispatch::Work for FaultProvider {
        const INVALID_TRANSITION: Error = Error::InternalError;
        fn effect_write(&self) -> bool {
            self.current.write()
        }
        fn prepare(&mut self) -> Outcome<()> {
            Ok(())
        }
        fn audit(&mut self, phase: DispatchPhase) -> Outcome<()> {
            if let Some(audit) = &self.audit {
                audit.write_record(&json!({
                    "schema":1, "event":"dispatch", "phase":phase.as_str(),
                    "operation":"synthetic.read", "request_digest":"synthetic-request",
                    "grant":audit.grant, "policy":audit.policy,
                }))
            } else {
                Ok(())
            }
        }
        fn configure(&mut self, _: bool) -> Outcome<()> {
            Ok(())
        }
        fn check(&mut self) -> Outcome<()> {
            Ok(())
        }
        fn reserve(&mut self) -> Outcome<()> {
            Ok(())
        }
        fn finish(&mut self) -> Outcome<()> {
            Ok(())
        }
    }
    #[test]
    fn captured_native_request_cannot_replay_after_partial_write_or_flush_error() {
        for (limit, flush_error) in [
            (0, false),
            (5, false),
            (usize::MAX, true),
            (usize::MAX, false),
        ] {
            let accepted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let writer = PartialWriter {
                accepted: accepted.clone(),
                limit,
                flush_error,
            };
            let mut channel = aivm_secrets_garrett_core::provider_io::Channel::new(
                ManifestWire(Zeroizing::new(b"synthetic-request".to_vec())),
                ProviderWriter(writer),
                (),
            );
            let first = channel.submit();
            assert_eq!(first.is_ok(), limit == usize::MAX && !flush_error);
            let before = accepted.borrow().clone();
            assert!(matches!(
                channel.submit(),
                Err(Error::InternalError)
            ));
            assert_eq!(*accepted.borrow(), before);
            assert!(matches!(channel.into_parts(), Err(Error::InternalError)));
        }
    }
    // std::io::Write::write_all is one extracted Writer callback but may
    // perform several underlying writes, retry Interrupted and accept a prefix
    // before a terminal WriteZero. Neither case arms a second provider attempt.
    #[test]
    fn native_writer_callback_retries_interrupted_but_never_retries_spent_request() {
        use std::cell::{Cell, RefCell};
        use std::rc::Rc;

        struct InterruptedWriter {
            calls: Rc<Cell<usize>>,
            flushes: Rc<Cell<usize>>,
            accepted: Rc<RefCell<Vec<u8>>>,
            stop_after_prefix: bool,
        }
        impl Write for InterruptedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let call = self.calls.get();
                self.calls.set(call + 1);
                if call == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
                }
                let mut accepted = self.accepted.borrow_mut();
                if self.stop_after_prefix && accepted.len() >= 3 {
                    return Ok(0);
                }
                let count = if self.stop_after_prefix { bytes.len().min(3) } else { bytes.len() };
                accepted.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes.set(self.flushes.get() + 1);
                Ok(())
            }
        }
        for stop_after_prefix in [false, true] {
            let calls = Rc::new(Cell::new(0));
            let flushes = Rc::new(Cell::new(0));
            let accepted = Rc::new(RefCell::new(Vec::new()));
            let mut channel = aivm_secrets_garrett_core::provider_io::Channel::new(
                ManifestWire(Zeroizing::new(b"synthetic-request".to_vec())),
                ProviderWriter(InterruptedWriter {
                    calls: calls.clone(), flushes: flushes.clone(),
                    accepted: accepted.clone(), stop_after_prefix,
                }),
                89,
            );
            let result = channel.submit();
            assert_eq!(result.is_ok(), !stop_after_prefix);
            assert_eq!(calls.get(), if stop_after_prefix { 3 } else { 2 });
            assert_eq!(flushes.get(), if stop_after_prefix { 0 } else { 1 });
            assert_eq!(&*accepted.borrow(), if stop_after_prefix {
                &b"syn"[..]
            } else {
                &b"synthetic-request"[..]
            });
            let before = (calls.get(), flushes.get(), accepted.borrow().clone());
            assert!(matches!(channel.submit(), Err(Error::InternalError)));
            assert_eq!((calls.get(), flushes.get(), accepted.borrow().clone()), before);
            // A refused replay also withdraws a formerly successful receipt.
            assert!(matches!(channel.into_parts(), Err(Error::InternalError)));
        }
    }
    #[test]
    fn native_channel_only_releases_exact_response_parts_after_successful_flush() {
        for (limit, flush_error) in [
            (0, false),
            (5, false),
            (usize::MAX, true),
            (usize::MAX, false),
        ] {
            let accepted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let writer = PartialWriter {
                accepted: accepted.clone(),
                limit,
                flush_error,
            };
            let mut channel = aivm_secrets_garrett_core::provider_io::Channel::new(
                ManifestWire(Zeroizing::new(b"synthetic-request".to_vec())),
                ProviderWriter(writer),
                731,
            );
            let success = limit == usize::MAX && !flush_error;
            assert_eq!(channel.submit().is_ok(), success);
            match channel.into_parts() {
                Ok((ProviderWriter(writer), request, metadata)) => {
                    assert!(success);
                    assert!(request.attempted());
                    assert_eq!(metadata, 731);
                    assert!(std::rc::Rc::ptr_eq(&writer.accepted, &accepted));
                    assert_eq!(*accepted.borrow(), b"synthetic-request");
                }
                Err(error) => assert!(matches!(error, Error::InternalError) && !success),
            }
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
                let accepted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
                let provider = FaultProvider {
                    accepted: accepted.clone(),
                    limit,
                    flush_error,
                    current,
                    parsed: false,
                    audit: None,
                    deny_after_audit: false,
                };
                let report = aivm_secrets_garrett_core::dispatch::dispatch(
                    provider,
                    Ok(prepared),
                    RequestEffects::new(),
                    false,
                );
                assert_eq!(report.provider_stage, Some(provider_exchange::Stage::Send));
                assert!(report.local.attempted());
                assert!(report
                    .effects
                    .phase(DispatchPhase::Final)
                    .provider_attempted());
                assert_eq!(
                    report.outcome,
                    Err(if write {
                        Error::OutcomeUnknown
                    } else {
                        Error::UpstreamResponse
                    })
                );
                assert!(!report.work.parsed);
                let before = accepted.borrow().clone();
                let repeat = aivm_secrets_garrett_core::dispatch::dispatch(
                    report.work,
                    read_transition::prepare(DispatchPhase::Final, write, write)
                        .map_err(|_| Error::InvalidPolicy),
                    report.effects,
                    false,
                );
                assert_eq!(repeat.outcome, Err(Error::InternalError));
                assert_eq!(*accepted.borrow(), before);
                assert_eq!(
                    &*accepted.borrow(),
                    &b"synthetic-request"[..limit.min(b"synthetic-request".len())]
                );
            }
        }
    }

    #[test]
    fn real_durable_dispatch_audit_precedes_each_native_write_prefix() {
        use aivm_secrets_garrett_core::{
            credential_use::{UseClaims, UseGrant}, provider_exchange,
        };
        use std::os::unix::fs::OpenOptionsExt;
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
        }
        let claims = || UseClaims {
            binding: b"client".to_vec(), policy: b"policy".to_vec(),
            grant: b"grant".to_vec(), issued_at: 1, expires_at: 100,
        };
        let grant = UseGrant {
            claims: claims(), operation: b"read".to_vec(),
            route: route(), active: true,
        };
        // This matrix observes real host-audit file bytes and a native Writer
        // reached through the production dispatch/controller entry point.
        for (audit_failed, late_denial, limit, flush_error) in [
            (true, false, usize::MAX, false),
            (false, true, usize::MAX, false),
            (false, false, 0, false),
            (false, false, 5, false),
            (false, false, usize::MAX, true),
            (false, false, usize::MAX, false),
        ] {
            let path = std::env::temp_dir().join(format!(
                "garrett-dispatch-{}-{}", std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            let _cleanup = Cleanup(path.clone());
            let file = std::fs::OpenOptions::new().write(true).create_new(true)
                .mode(0o600).open(&path).unwrap();
            let audit = Arc::new(Audit {
                state: Mutex::new(AuditState { file, failed: audit_failed }),
                grant: "synthetic-grant".into(),
                policy: "synthetic-policy".into(),
            });
            let current = guards::current(
                &claims(), &grant, &b"read".to_vec(), &b"read".to_vec(),
                false, false, 2, 1,
            ).ok().unwrap();
            let accepted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let report = aivm_secrets_garrett_core::dispatch::dispatch(
                FaultProvider {
                    accepted: accepted.clone(), limit, flush_error, current,
                    parsed: false, audit: Some(audit), deny_after_audit: late_denial,
                },
                Ok(read_transition::prepare(DispatchPhase::Final, false, false).ok().unwrap()),
                RequestEffects::new(), false,
            );
            let receipt = report.effects.phase(DispatchPhase::Final);
            assert!(receipt.audit_attempted());
            assert_eq!(receipt.audit_acknowledged(), !audit_failed);
            assert_eq!(receipt.provider_attempted(), !audit_failed && !late_denial);
            assert_eq!(report.local.attempted(), !audit_failed && !late_denial);
            assert_eq!(report.provider_stage, if audit_failed {
                None
            } else if late_denial {
                Some(provider_exchange::Stage::Admission)
            } else if limit < b"synthetic-request".len() || flush_error {
                Some(provider_exchange::Stage::Send)
            } else {
                Some(provider_exchange::Stage::Complete)
            });
            let lines = std::fs::read(&path).unwrap();
            if audit_failed {
                assert!(matches!(report.outcome, Err(Error::InternalError)));
                assert!(lines.is_empty());
                assert!(accepted.borrow().is_empty());
            } else {
                let record: Value = serde_json::from_slice(&lines).unwrap();
                assert_eq!(record["event"], "dispatch");
                assert_eq!(record["phase"], "final");
                assert_eq!(record["grant"], "synthetic-grant");
                assert_eq!(record["request_digest"], "synthetic-request");
                let successful = !late_denial && limit == usize::MAX && !flush_error;
                if late_denial {
                    assert!(matches!(&report.outcome, Err(Error::Revoked)));
                }
                assert_eq!(report.outcome.is_ok(), successful);
                assert_eq!(report.work.parsed, successful);
                let expected_prefix = if late_denial {
                    &b""[..]
                } else {
                    &b"synthetic-request"[..limit.min(b"synthetic-request".len())]
                };
                assert_eq!(&*accepted.borrow(), expected_prefix);
            }
            // The gate's previous receipt cannot be reused to append another
            // audit or to repeat the credential-bearing writer callback.
            let before = accepted.borrow().clone();
            let repeat = aivm_secrets_garrett_core::dispatch::dispatch(
                report.work,
                Ok(read_transition::prepare(DispatchPhase::Final, false, false).ok().unwrap()),
                report.effects, false,
            );
            assert!(matches!(repeat.outcome, Err(Error::InternalError)));
            assert_eq!(*accepted.borrow(), before);
            assert_eq!(std::fs::read(&path).unwrap(), lines);
        }
    }

    // Exercise the complete returned dispatch path with a real audit File and
    // the *production* ProviderWriter -> Channel::submit callback, observing
    // the moment of each underlying Write call (not just the final buffers).
    // The test writer asserts the audit acknowledgement already exists before
    // the first provider byte can be accepted.
    #[test]
    fn native_read_dispatch_audit_to_writer_callback_chronology() {
        use aivm_secrets_garrett_core::{
            credential_use::{UseClaims, UseGrant}, provider_exchange,
        };
        use std::cell::RefCell;
        use std::os::unix::fs::OpenOptionsExt;
        use std::rc::Rc;

        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Fault {
            Prepare, Audit, Configure, Check, Recheck,
            WriteZero, PartialWrite, Flush, None,
        }
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        struct ObservedWriter {
            path: std::path::PathBuf,
            trace: Rc<RefCell<Vec<&'static str>>>,
            accepted: Rc<RefCell<Vec<u8>>>,
            fault: Fault,
        }
        impl Write for ObservedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                // This assertion runs at the actual native write callback,
                // rather than checking audit order only after dispatch.
                let record: Value = serde_json::from_slice(&std::fs::read(&self.path)?)
                    .map_err(std::io::Error::other)?;
                assert_eq!(record["event"], "dispatch");
                assert_eq!(record["operation"], "synthetic.read");
                assert_eq!(record["request_digest"], "synthetic-request");
                assert!(self.trace.borrow().contains(&"audit-ack"));
                self.trace.borrow_mut().push("write");
                if self.fault == Fault::WriteZero {
                    return Ok(0);
                }
                let mut accepted = self.accepted.borrow_mut();
                if self.fault == Fault::PartialWrite && !accepted.is_empty() {
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
                }
                let count = if self.fault == Fault::PartialWrite {
                    bytes.len().min(7)
                } else {
                    bytes.len()
                };
                accepted.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.trace.borrow_mut().push("flush");
                if self.fault == Fault::Flush {
                    Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
                } else {
                    Ok(())
                }
            }
        }
        struct ObservedProvider {
            audit: Arc<Audit>,
            audit_path: std::path::PathBuf,
            trace: Rc<RefCell<Vec<&'static str>>>,
            accepted: Rc<RefCell<Vec<u8>>>,
            current: guards::AdmissionStamp,
            fault: Fault,
        }
        impl provider_exchange::Provider for ObservedProvider {
            type Channel = aivm_secrets_garrett_core::provider_io::Channel<
                ManifestWire, ProviderWriter<ObservedWriter>, (),
            >;
            type Output = Value;
            type Error = Error;
            const INVALID_POLICY: Error = Error::InvalidPolicy;
            const OUTCOME_UNKNOWN: Error = Error::OutcomeUnknown;
            fn setup(&mut self) -> Outcome<Self::Channel> {
                self.trace.borrow_mut().push("setup");
                // The real native request encoder is exercised on this path.
                let (wire, _) = manifest_request_bytes(
                    &route(), &secret(b"SYNTHETIC_TOKEN_123456"),
                    &effect(), &BTreeMap::new(),
                )?;
                Ok(aivm_secrets_garrett_core::provider_io::Channel::new(
                    ManifestWire(wire),
                    ProviderWriter(ObservedWriter {
                        path: self.audit_path.clone(),
                        trace: self.trace.clone(),
                        accepted: self.accepted.clone(),
                        fault: self.fault,
                    }),
                    (),
                ))
            }
            fn recheck(&mut self) -> Outcome<guards::AdmissionStamp> {
                self.trace.borrow_mut().push("current");
                if self.fault == Fault::Recheck {
                    Err(Error::Revoked)
                } else {
                    Ok(self.current.clone())
                }
            }
            fn send(&mut self, channel: &mut Self::Channel) -> Outcome<()> {
                self.trace.borrow_mut().push("send");
                channel.submit()
            }
            fn receive(&mut self, channel: Self::Channel) -> Outcome<Value> {
                self.trace.borrow_mut().push("receive");
                let _parts = channel.into_parts()?;
                Ok(json!({"selected":true}))
            }
        }
        impl aivm_secrets_garrett_core::dispatch::Work for ObservedProvider {
            const INVALID_TRANSITION: Error = Error::InternalError;
            fn effect_write(&self) -> bool { false }
            fn prepare(&mut self) -> Outcome<()> {
                self.trace.borrow_mut().push("prepare");
                if self.fault == Fault::Prepare {
                    Err(Error::InvalidPolicy)
                } else { Ok(()) }
            }
            fn audit(&mut self, phase: DispatchPhase) -> Outcome<()> {
                self.trace.borrow_mut().push("audit");
                self.audit.write_record(&json!({
                    "schema":1, "event":"dispatch", "phase":phase.as_str(),
                    "operation":"synthetic.read", "request_digest":"synthetic-request",
                    "grant":self.audit.grant, "policy":self.audit.policy,
                }))?;
                self.trace.borrow_mut().push("audit-ack");
                Ok(())
            }
            fn configure(&mut self, _: bool) -> Outcome<()> {
                self.trace.borrow_mut().push("configure");
                if self.fault == Fault::Configure {
                    Err(Error::InvalidPolicy)
                } else { Ok(()) }
            }
            fn check(&mut self) -> Outcome<()> {
                self.trace.borrow_mut().push("check");
                if self.fault == Fault::Check {
                    Err(Error::Revoked)
                } else { Ok(()) }
            }
            fn reserve(&mut self) -> Outcome<()> {
                panic!("read dispatch must not reserve a write")
            }
            fn finish(&mut self) -> Outcome<()> {
                panic!("read dispatch must not finish a write")
            }
        }

        let claims = || UseClaims {
            binding: b"client".to_vec(), policy: b"policy".to_vec(),
            grant: b"grant".to_vec(), issued_at: 1, expires_at: 100,
        };
        let grant = UseGrant {
            claims: claims(), operation: b"read".to_vec(),
            route: route(), active: true,
        };
        let phases = [DispatchPhase::Preflight, DispatchPhase::Final];
        let faults = [
            Fault::Prepare, Fault::Audit, Fault::Configure, Fault::Check,
            Fault::Recheck, Fault::WriteZero, Fault::PartialWrite,
            Fault::Flush, Fault::None,
        ];
        for (phase_index, phase) in phases.into_iter().enumerate() {
            for (fault_index, fault) in faults.into_iter().enumerate() {
                let path = std::env::temp_dir().join(format!(
                    "garrett-timeline-{}-{}-{}-{}", std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
                    phase_index, fault_index,
                ));
                let _cleanup = Cleanup(path.clone());
                let file = std::fs::OpenOptions::new().write(true).create_new(true)
                    .mode(0o600).open(&path).unwrap();
                let audit = Arc::new(Audit {
                    state: Mutex::new(AuditState { file, failed: fault == Fault::Audit }),
                    grant: "synthetic-grant".into(),
                    policy: "synthetic-policy".into(),
                });
                let current = guards::current(
                    &claims(), &grant, &b"read".to_vec(), &b"read".to_vec(),
                    false, false, 2, 1,
                ).ok().unwrap();
                let trace = Rc::new(RefCell::new(Vec::new()));
                let accepted = Rc::new(RefCell::new(Vec::new()));
                let report = aivm_secrets_garrett_core::dispatch::dispatch(
                    ObservedProvider {
                        audit, audit_path: path.clone(), trace: trace.clone(),
                        accepted: accepted.clone(), current, fault,
                    },
                    Ok(read_transition::prepare(phase, false, false).ok().unwrap()),
                    RequestEffects::new(), false,
                );
                let mut expected = vec!["prepare"];
                if fault != Fault::Prepare {
                    expected.push("audit");
                }
                if fault != Fault::Prepare && fault != Fault::Audit {
                    expected.extend(["audit-ack", "configure"]);
                    if fault != Fault::Configure {
                        expected.push("check");
                        if fault != Fault::Check {
                            expected.extend(["setup", "current"]);
                            if fault != Fault::Recheck {
                                expected.extend(["send", "write"]);
                                if fault == Fault::PartialWrite {
                                    expected.push("write");
                                }
                                if !matches!(fault, Fault::WriteZero | Fault::PartialWrite) {
                                    expected.push("flush");
                                    if fault == Fault::None {
                                        expected.push("receive");
                                    }
                                }
                            }
                        }
                    }
                }
                assert_eq!(*trace.borrow(), expected, "{phase:?} {fault:?}");
                let receipt = report.effects.phase(phase);
                let audit_called = fault != Fault::Prepare;
                let audited = audit_called && fault != Fault::Audit;
                let sent = !matches!(fault,
                    Fault::Prepare | Fault::Audit | Fault::Configure |
                    Fault::Check | Fault::Recheck);
                assert_eq!(receipt.audit_attempted(), audit_called);
                assert_eq!(receipt.audit_acknowledged(), audited);
                assert_eq!(receipt.provider_attempted(), sent);
                assert_eq!(report.local.attempted(), sent);
                assert_eq!(report.outcome.is_ok(), fault == Fault::None);
                let audit_bytes = std::fs::read(&path).unwrap();
                if audited {
                    let row: Value = serde_json::from_slice(&audit_bytes).unwrap();
                    assert_eq!(row["phase"], phase.as_str());
                } else {
                    assert!(audit_bytes.is_empty());
                }
                let (wire, _) = manifest_request_bytes(
                    &route(), &secret(b"SYNTHETIC_TOKEN_123456"),
                    &effect(), &BTreeMap::new(),
                ).unwrap();
                let prefix_len = match fault {
                    Fault::WriteZero | Fault::Prepare | Fault::Audit |
                    Fault::Configure | Fault::Check | Fault::Recheck => 0,
                    Fault::PartialWrite => 7,
                    _ => wire.len(),
                };
                assert_eq!(&*accepted.borrow(), &wire[..prefix_len]);
                // A returned dispatch that already crossed its audit gate
                // must not audit or write again, even after failed send/flush.
                if fault != Fault::Prepare {
                    let before = trace.borrow().clone();
                    let again = aivm_secrets_garrett_core::dispatch::dispatch(
                        report.work,
                        Ok(read_transition::prepare(phase, false, false).ok().unwrap()),
                        report.effects, false,
                    );
                    assert!(matches!(again.outcome, Err(Error::InternalError)));
                    assert_eq!(&*trace.borrow(), &[before, vec!["prepare"]].concat());
                    assert_eq!(std::fs::read(&path).unwrap(), audit_bytes);
                    assert_eq!(&*accepted.borrow(), &wire[..prefix_len]);
                }
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
        let mut write = effect();
        write.write = true;
        // Exercise the actual owned request callback: rejected preparation
        // must not even construct a native provider adapter.
        for (phase, admitted, effect) in [
            (DispatchPhase::Preflight, true, write.clone()),
            (DispatchPhase::Final, false, write),
        ] {
            let work = PendingRequest {
                preflight: || Ok(None),
                final_effect: |_: &Value| Ok(None),
                dispatch: |_: DispatchPhase,
                           _: Effect|
                 -> request_adapter::DispatchPlan<FaultProvider> {
                    panic!("forbidden effect reached provider factory")
                },
                complete: |_: Value| -> PendingCompletion<fn() -> Outcome<Value>> {
                    panic!("forbidden effect reached completion factory")
                },
                fresh: || Ok(()),
                operation_write: admitted,
            };
            let mut pending = request_adapter::Pending::new(work);
            assert!(matches!(
                read_transition::Request::dispatch(&mut pending, phase, effect),
                Err(Error::InvalidPolicy)
            ));
            assert!(!pending.effects().phase(phase).audit_attempted());
        }
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
        let wire = String::from_utf8(request.0.to_vec()).unwrap();
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
        let wire = String::from_utf8(request.0.to_vec()).unwrap();
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
        let wire = String::from_utf8(bytes.0.to_vec()).unwrap();
        let (head, body) = wire.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            post.body.unwrap()
        );
    }
    #[test]
    fn native_encoder_endpoint_matches_captured_channel_bytes() {
        let mut route = route();
        route.port = 9443;
        route.authentication = core::Authentication::ApiKey;
        let (bytes, endpoint) = manifest_request_bytes(
            &route,
            &secret(b"SYNTHETIC_TOKEN_123456"),
            &effect(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(endpoint.host(), &route.host);
        assert_eq!(endpoint.port(), 9443);
        let expected = bytes.to_vec();
        assert!(String::from_utf8(expected.clone())
            .unwrap()
            .contains("\r\nHost: api.example.org:9443\r\n"));
        assert!(String::from_utf8(expected.clone())
            .unwrap()
            .contains("\r\nX-API-Key: SYNTHETIC_TOKEN_123456\r\n"));
        let accepted = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let writer = PartialWriter {
            accepted: accepted.clone(),
            limit: usize::MAX,
            flush_error: false,
        };
        let mut channel = aivm_secrets_garrett_core::provider_io::Channel::new(
            ManifestWire(bytes),
            ProviderWriter(writer),
            endpoint,
        );
        assert!(channel.submit().is_ok());
        let (_, request, returned) = channel.into_parts().ok().unwrap();
        assert!(request.attempted());
        assert_eq!(*accepted.borrow(), expected);
        assert_eq!(returned.host(), &route.host);
        assert_eq!(returned.port(), 9443);
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
