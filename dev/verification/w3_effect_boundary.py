#!/usr/bin/env python3
"""W3 reviewed-source and high-risk sink guard for native Garrett effects.

The snapshot fingerprints force re-review on changes to the covered modules.
The independent structural checks catch selected bypass mutants even if their
fingerprints have been updated. This is neither a Rust call-graph proof nor
transitive I/O coverage of dependencies; see the W3 review document.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


HERE = Path(__file__).resolve()
DEFAULT_ROOT = HERE.parents[2]
INVENTORY_PATH = 'docs/planning/aivm-secrets-w3-reachability.json'
RUST = 'rust/crates/aivm-secrets-garrett/src/'
# Pin repository-owned Rust sources and workspace/package build manifests,
# including new untracked Rust modules. Cargo output is NOT source under review.
# A normal `cargo build` creates rust/target/**, potentially including generated
# *.rs files. Traversing that tree would make the inventory change after every
# build, and can be extremely expensive. This still does not provide sound
# interprocedural call-graph or external-dependency coverage.
def rust_sources(root: Path) -> set[str]:
    rust_root = root / 'rust'
    result: set[str] = set()
    for directory, subdirectories, filenames in os.walk(rust_root):
        # Ignore local Cargo build outputs at any package/workspace depth,
        # but continue checking all repository-owned sources (tracked or not).
        subdirectories[:] = [name for name in subdirectories if name != 'target']
        for name in filenames:
            if not (name.endswith('.rs') or name in {
                'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
            }):
                continue
            path = Path(directory) / name
            if path.is_file():
                result.add(path.relative_to(root).as_posix())
    return result


EXPECTED_SOURCES = rust_sources(DEFAULT_ROOT)


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def part(source: str, first: str, last: str) -> str:
    require(first in source, 'missing reviewed boundary: ' + first)
    tail = source.split(first, 1)[1]
    require(last in tail, 'missing reviewed boundary: ' + last)
    return tail.split(last, 1)[0]


def same_order(source: str, *markers: str) -> bool:
    positions = [source.find(marker) for marker in markers]
    return all(p >= 0 for p in positions) and positions == sorted(positions) and len(set(positions)) == len(positions)


def review_semantics(contents: dict[str, str]) -> None:
    approval = contents[RUST + 'custody/approval.rs']
    admission = part(approval, 'pub(super) fn admit(', 'pub(super) fn remember(')
    require(same_order(admission, 'self.state.lock()', 'let now = host_time()?;',
                       'self.require_active(now)?;', 'state.approvals.remove(wanted)',
                       'core::consume(Mode::Approve, write,', 'if let Some(slot) = remaining'),
            'approval consumption bypasses current clock, unique slot or extracted decision')
    require('state.approvals.insert(wanted.into(), slot)' in admission
            and approval.count('core::issue(') == 1,
            'approval slot can be refunded or issued through an unreviewed path')
    host_control = contents[RUST + 'host_control.rs']
    serve_control = part(host_control, 'fn serve(', 'impl Drop for Running')
    require(same_order(serve_control, 'socket_peercred(&socket)',
                       'if peer.uid != rustix::process::geteuid()',
                       'tls::frame(&mut socket, 65536)', 'state.execute(&value)'),
            'host control bypasses kernel peer credentials or bounded framing')
    revoke = part(approval, 'Some("revoke") =>', '_ => Err(Error::InvalidRequest)')
    require(same_order(revoke, 'self.revoke();', 'self.record(')
            and 'self.active.store(false, Ordering::Release)' in approval,
            'host revocation waits for audit before withdrawing authority')
    decoded = contents[RUST + 'json.rs']
    parse = part(decoded, 'pub fn parse(', '\nfn string(')
    require('decode(&raw, 0)' in parse and 'Ok(Value::Object(' in decoded,
            'JSON objects can bypass explicit structure-preserving decoding')
    # The sole native manifest call to the credential-bearing HTTP adapter is
    # after policy compilation, durable audit and current grant revalidation.
    m = contents[RUST + 'custody/manifest_session.rs']
    request = part(m, 'pub(super) fn request(', 'pub(super) fn control(')
    require(same_order(request, 'control.state.admit(&approval_digest, op.write)?',
                       'Decision::Required =>', 'fresh()?;',
                       '.remember(&approval_digest, &canonical_request)?;',
                       'let dispatch = |prepared: PreparedDispatch', 'preflight: || self.policy.preflight('),
            'approval is not enforced before credentialed preflight/final effects')
    require('self.policy.digest()' in request and '"grant":self.base.executor.audit.grant' in request
            and 'self.require_control_active(current)?;' in request
            and 'fresh: &fresh,' in request,
            'approval identity or late revocation fencing bypassed')
    control = part(m, 'pub(super) fn control(', '\nfn manifest_request_bytes(')
    dispatch = part(request, 'let dispatch = |prepared: PreparedDispatch', 'let release = |raw: Value|')
    release = part(request, 'let release = |raw: Value| -> Outcome<CompletedRelease> {', 'let pending = PendingRequest {')
    plan = part(request, 'let pending = PendingRequest {', 'read_transition::run_current(pending)')
    reviewed = part(m, "impl<'a> PreparedDispatch<'a> {", 'pub(crate) struct Session {')
    require('struct PreparedDispatch<' in m and 'Phase as DispatchPhase' in m
            and 'struct AuditedDispatch<' in m and m.count('AuditedDispatch {') == 1,
            'native executor permit can be manufactured outside the audit transition')
    transition = contents['rust/crates/aivm-secrets-garrett-core/src/read_transition.rs']
    require(same_order(reviewed, "fn preflight(effect: &'a Effect) -> Outcome<Self>",
                       'read_transition::prepare(DispatchPhase::Preflight, false, effect.write)',
                       "fn final_effect(effect: &'a Effect, admitted_write: bool) -> Outcome<Self>",
                       'read_transition::prepare(DispatchPhase::Final, admitted_write, effect.write)',
                       'fn audit(', 'ensure_safe(', 'audit.write_record(',
                       'read_transition::acknowledge(self.transition, true)',
                       'Ok(AuditedDispatch {'),
            'native dispatch bypasses extracted phase gate or audit acknowledgment')
    require('Ok(AuditedDispatch{effect:self.effect,transition,})' in ''.join(reviewed.split())
            and reviewed.count('read_transition::acknowledge(self.transition, true)') == 1,
            'audited permit lost the same core transition after host audit')
    require(same_order(transition, 'pub fn prepare(', 'if effect_write',
                       'matches!(phase, Phase::Preflight)',
                       'pub fn acknowledge(', 'if !ack', 'Ok(Audited {'),
            'extracted core permits preflight writes, unadmitted writes or failed audits')
    require('|| !admitted_operation_write' in transition
            and transition.count('if !ack {') == 1,
            'extracted core gate bypasses write admission or audit acknowledgement')
    require('pub mod read_transition;' in contents[
        'rust/crates/aivm-secrets-garrett-core/src/lib.rs'],
        'reviewed transition is no longer exported by native core')
    require(request.count('exchange_manifest(') == 1,
            'unexpected direct manifest HTTP dispatch outside the sole gated closure')
    require(request.count('PreparedDispatch::preflight(effect)?') == 1
            and request.count('PreparedDispatch::final_effect(effect, op.write)?') == 1,
            'preflight/final not constrained to the reviewed write gate')
    require(same_order(dispatch,
                       'let recorded = prepared.audit(', 'let effect = recorded.effect;',
                       'let pending = crate::coordination::PendingDispatch',
                       'executor.exchange_manifest(', 'coordination::dispatch(&pending, keyed_write)'),
            'provider dispatch bypasses durable audit or fresh authorization')
    require('&recorded,' in dispatch and 'matches!(recorded.transition.phase(), DispatchPhase::Final)' in dispatch,
            'executor is not passed the reviewed audited dispatch permit')
    require('check: &fresh,' in dispatch and 'reserve: || reservation_call(false),' in dispatch
            and 'finish: || reservation_call(true),' in dispatch
            and 'matches!(recorded.transition.phase(), DispatchPhase::Final)' in dispatch
            and '&& effect.write' in dispatch and '&& self.base.coordinator.is_some()' in dispatch,
            'coordinated final write bypasses check/reserve/finish or phase classification')
    require('self.base.check_coordination()?;' in request
            and same_order(control, 'self.base.check_coordination()?;',
                           'let now = host_time()?;', 'lease.require_current(now)?;',
                           'verifier.open(token, peer, &expected, now)?;')
            and '.as_object_mut()' in request and '.remove("idempotency_key")' in request
            and 'self.base.coordinator.is_some() || op.idempotency_header' in request,
            'coordinator control/request admission or keyed-write requirement bypassed')
    reservation = part(request, 'let reservation = retry.map(', 'guards::authorize(')
    require('let policy_hash = self.policy.digest();' in reservation,
            'coordinated request no longer uses normalized policy identity')
    completed = part(m, 'struct CompletedRelease(Value);', 'pub(crate) struct Session {')
    require(completed.count('Ok(CompletedRelease(self.reply))') == 1 and
            same_order(completed, 'fn recheck(', '(self.fresh)()', 'fn audit(',
                       'self.audit.write_record(', 'fn release(',
                       'Ok(CompletedRelease(self.reply))', 'fn into_public('),
            'completed guest release can be manufactured before the completion audit')
    require(same_order(release, 'self.disclosure.project(', 'ensure_safe(&reply',
                       'read_transition::complete_current(PendingCompletion {'),
            'guest release bypasses selected disclosure/reflection/completion')
    completion = part(transition, 'pub fn complete_current<', 'pub trait Request {')
    require(same_order(completion, 'pending.recheck(CompletionPhase::BeforeAudit)',
                       'pending.audit()', 'pending.recheck(CompletionPhase::BeforeRelease)',
                       'pending.release()') and
            completion.count('Err(error) => return Err(error)') == 3,
            'completion bypasses current authority, audit or post-audit freshness')
    require(request.count('read_transition::run_current(pending).map(CompletedRelease::into_public)') == 1
            and 'complete: release,' in plan and 'fresh: &fresh,' in plan
            and 'fresh: &fresh,' in release,
            'guest result bypasses audited release or sent-write uncertainty')
    require('guards::authorize(' in request and 'open_surrogate(' in request
            and 'self.policy.operation(&request)' in request,
            'native request missing authorizing guard / policy compiler')
    require('final_effect: |facts: &Value| self.policy.final_effect(op, &args, facts)' in request,
            'final effect is not compiled from checked facts')
    require('preflight: || self.policy.preflight(op, &args)' in request,
            'preflight is no longer compiled from host policy')
    orchestration = part(transition, 'fn request_facts<', '#[cfg(test)]')
    require(same_order(orchestration, 'ops.preflight()', 'ops.dispatch(Phase::Preflight, effect)',
                       'ops.final_effect(&facts)', 'ops.recheck()', 'ops.effect_write(&effect)',
                       'ops.dispatch(Phase::Final, effect)', 'if sent_write', 'ops.complete(raw)',
                       'Err(ops.outcome_unknown())', 'pub fn request_current<',
                       'match request_facts(ops)', 'Ok(facts) => finish_request(ops, facts)')
            and 'None => (facts, false)' in orchestration
            and 'Ok(raw) => (raw, write)' in orchestration,
            'extracted request bypasses provider outcomes, fresh admission or exact completion input')
    invocations = contents['rust/crates/aivm-secrets-garrett-core/src/read_transition/invocation.rs']
    require('mod invocation;' in transition and 'pub use invocation::{Invocation, Trace};' in transition
            and same_order(orchestration, 'pub fn run_current<', 'Invocation::new(adapter)',
                           'request_current(&mut invocation)', 'invocation.into_result(result)')
            and 'pub adapter:' not in invocations and 'adapter: R,' in invocations,
            'request invocation receipt or private adapter/consuming gate bypassed')
    require(invocations.count('self.adapter.') == 8 and
            all(invocations.count('self.adapter.' + name + '(') == 1 for name in
                ('preflight', 'empty_facts', 'dispatch', 'final_effect', 'recheck',
                 'effect_write', 'complete', 'outcome_unknown')) and
            'self.progress = Progress::Halted;\n        Err(R::INVALID_TRANSITION)' in invocations and
            'if matches!(self.progress, Progress::Finished)' in invocations,
            'reviewed invocation wrapper/callback multiplicity or terminal gate changed')
    adapter = part(m, 'impl<P, D, F, C, R> read_transition::Request', 'pub(crate) struct Session {')
    require('fn effect_write(&self, effect: &Effect) -> bool' in adapter
            and 'effect.write' in adapter and 'Error::OutcomeUnknown' in adapter
            and 'Value::Null' in adapter,
            'write uncertainty boundary altered')
    # W6: the exact provider bytes are validated by a pure encoder BEFORE any
    # TCP/TLS effect. This also covers OAuthSource-created Credential values.
    require(m.count('fn manifest_request_bytes(') == 1
            and m.count('let request = manifest_request_bytes(self.route, self.secret, self.effect, self.headers)?;') == 1
            and m.index('let request = manifest_request_bytes(') < m.index('TcpStream::connect_timeout('),
            'provider socket opened before outbound wire validation')
    wire = part(m, 'fn manifest_request_bytes(', '// The standard Write contract')
    require(wire.count('provider_request_bytes(') == 1
            and 'method: effect.method.as_bytes().to_vec()' in wire
            and 'target: effect.target.as_bytes().to_vec()' in wire
            and 'host: route.host.clone()' in wire and '&route.authentication,' in wire
            and 'body.as_ref().map(|v| v.as_slice())' in wire
            and 'request.extend_from_slice(' not in wire and 'format!(' not in wire,
            'manifest HTTP bypasses the shared complete request encoder')
    c = contents[RUST + 'custody.rs']
    shared_wire = part(c, 'fn provider_request_bytes(', 'fn account_request_bytes(')
    require(shared_wire.count('http_wire::append_request(') == 1
            and 'Zeroizing::new(Vec::new())' in shared_wire
            and '&secret.0,' in shared_wire and 'authentication,' in shared_wire
            and 'Error::CredentialSource' in shared_wire
            and 'request.extend_from_slice(' not in shared_wire,
            'provider HTTP bypasses the borrowed credential/full encoder boundary')
    full_wire = contents['rust/crates/aivm-secrets-garrett-core/src/http_wire.rs']
    full_wire = full_wire.split('#[cfg(test)]', 1)[0]
    append = full_wire.split('pub fn append_request(', 1)[1]
    require(same_order(append, '!valid_start(head)', '!http_auth::valid_credential(secret)',
                       '!valid_body(body)', '!valid_headers(&head.headers)',
                       'http_request::append_line(')
            and append.count('http_auth::append_header(output, secret, authentication)') == 1
            and append.count('append_decimal(output, bytes.len());') == 1
            and append.count('output.extend_from_slice(bytes);') == 1
            and 'output.extend_from_slice(secret)' not in full_wire
            and '!reserved_name(name)' in full_wire
            and '!unique_before(headers, i, &headers[i].name)' in full_wire
            and all('b"' + name + '"' in full_wire for name in
                    ['host','authorization','x-api-key','content-length','transfer-encoding',
                     'proxy-','sec-','x-forwarded-']),
            'complete HTTP encoder lost validation, header separation or body-length framing')
    require('if status == 206 {' in m, 'unreviewed partial response release')
    runtime = m.split('#[cfg(test)]', 1)[0]
    require(runtime.count('TcpStream::connect_timeout(') == 1 and
            runtime.count('.write_all(') == 1 and
            ''.join(runtime.split()).count('send_manifest_bytes(&mutself.send_state,&mutchannel.stream,&channel.request,self.effect.write,)') == 1,
            'native module added a credentialed socket or HTTP writer')
    require(runtime.count('exchange_manifest(') == 2,
            'extra native manifest executor call site')
    transport = part(runtime, '    fn exchange_manifest(', '\nfn manifest_response(')
    require('audited: &AuditedDispatch<' in transport
            and 'let effect = audited.effect;' in transport
            and 'audited.transition.is_write() != effect.write' in transport,
            'manifest provider executor accepts a raw, unaudited policy effect')
    require('provider_exchange::exchange(&mut provider, &audited.transition)' in transport
            and 'current: &impl Fn() -> Outcome<guards::AdmissionStamp>' in transport
            and '.into_result()' in transport and '&current,' in dispatch,
            'manifest provider bypasses the extracted staged continuation')
    setup = part(runtime, 'fn setup(&mut self)', 'fn recheck(&mut self)')
    primitive = part(runtime, 'fn send_manifest_bytes(', 'struct ManifestChannel {')
    sender = part(runtime, 'fn send(&mut self, channel:', 'fn receive(&mut self, channel:')
    require(same_order(setup, 'let request = manifest_request_bytes(',
                       'TcpStream::connect_timeout(', 'while conn.is_handshaking()',
                       'StreamOwned::new(conn, socket)', 'Ok(ManifestChannel {')
            and 'self.executor.address,' in setup
            and 'ClientConnection::new(self.executor.tls.clone(), name)' in setup,
            'provider setup bypasses wire validation or host route / TLS identity')
    require('writer.write_all(request)' in ''.join(primitive.split()) and 'writer.flush()' in primitive
            and same_order(primitive, 'if !state.begin_send(write)', '.write_all(request)')
            and 'send_manifest_bytes(&mutself.send_state,&mutchannel.stream,&channel.request,self.effect.write,)' in ''.join(sender.split())
            and same_order(part(runtime, 'fn recheck(&mut self)', 'fn send(&mut self, channel:'),
                           'self.send_state.begin_check()', '(self.current)()?',
                           'self.send_state.finish_check(stamp)'),
            'native credential-bearing primitive or current stamp binding changed')
    sampled = part(request, 'let current = || -> Outcome<guards::AdmissionStamp>',
                   'let canonical_request')
    require('guards::current(' in sampled and 'let fresh = || current().map(|_| ());' in sampled
            and 'self.base.check_coordination()?;' in sampled
            and 'aivm_secrets_garrett_core::present(' in sampled
            and 'lease.require_current(current)?;' in sampled
            and 'self.require_control_active(current)?;' in sampled,
            'current stamp bypasses full native late authority checks')
    provider = contents['rust/crates/aivm-secrets-garrett-core/src/provider_exchange.rs'].split('#[cfg(test)]', 1)[0]
    require(same_order(provider, 'pub fn exchange<', 'ops.setup()', 'ops.recheck()',
                       'if write && !current.write()', 'ops.send(&mut channel)', 'ops.receive(channel)')
            and provider.count('ops.send(&mut channel)') == 1
            and provider.count('P::OUTCOME_UNKNOWN') == 2,
            'provider stage order, current stamp or post-attempt uncertainty bypassed')
    stamp = contents['rust/crates/aivm-secrets-garrett-core/src/manifest.rs']
    require('pub struct AdmissionStamp {' in stamp and
            same_order(stamp, 'pub fn current(', 'match authorize(', 'Ok(()) => Ok(AdmissionStamp {'),
            'native current stamp can be constructed without the extracted authorization')
    # Review of known alternate primitives remains separate from whole-service
    # transitive reachability and contracts for std/rustls/drop/timeout effects.
    for bypass in ('.write(', '.write_vectored(', '.send(', '.send_to(',
                   'TcpStream::connect(', 'UnixStream::connect('):
        require(bypass not in runtime,
                'manifest provider added an alternate socket send/connect: ' + bypass)
    for forbidden in ('println!(', 'eprintln!(', 'std::fs::write(', 'std::net::TcpStream::connect('):
        require(forbidden not in runtime, 'unreviewed output path in manifest custody: ' + forbidden)

    t = contents[RUST + 'tls.rs']
    guest = part(t, 'struct GuestFrame(Value);', 'impl Bridge {')
    serve = part(t, 'fn serve<S: Read + Write>', 'fn answer(')
    answer = part(t, 'fn answer(', 'fn forward(')
    require(guest.count('.write_all(&json::canonical(&self.0))') == 1
            and guest.count('writer.write_all(b"\\n")') == 1,
            'guest frame serializer was changed or duplicated')
    require('GuestFrame::from_answer(answer).send(&mut stream)?;' in serve
            and '.write_all(' not in serve,
            'authenticated guest writer bypasses GuestFrame')
    require('answer.unwrap_or_else(failure)' in guest,
            'guest failure is not the fixed Error::code mapper')
    require('verbs[0] == "delegate"' in answer
            and 'if let Backend::Provider(provider)' in answer
            and 'return provider.request(' in answer,
            'backend selector/unsupported guest delegation changed')
    require(t.count('self.forward(&forwarded)') == 1,
            'additional legacy forwarding may be guest reachable')
    require(t.count('write_all(&json::canonical(') == 1,
            'extra guest stream serialization outside reviewed GuestFrame')
    for forbidden in ('println!(', 'eprintln!('):
        require(forbidden not in t, 'unreviewed TLS diagnostic: ' + forbidden)

    # These are auxiliary high-risk entrypoints. Hashes on all reviewed files
    # below force re-review when their call graph/output path changes.
    b = contents[RUST + 'bridge_main.rs']
    require('let (bridge, announcement)' in b and 'with_registry_file(' in b,
            'bridge startup / authority selector changed')
    require('write_all(&json::canonical(&announcement))' in b,
            'host-only startup stdout channel changed')
    c = contents[RUST + 'custody.rs']
    account_wire = part(c, 'fn account_request_bytes(', 'impl Executor {')
    account_transport = part(c, '    fn exchange(', 'struct CurrentExecutor')
    require(account_wire.count('provider_request_bytes(&head, secret, &route.authentication, None)') == 1
            and 'method: b"GET".to_vec()' in account_wire
            and 'target: route.path.clone()' in account_wire
            and 'host: route.host.clone()' in account_wire
            and 'request.extend_from_slice(&secret.0)' not in account_wire
            and same_order(account_transport, 'let request = account_request_bytes(route, secret)?;',
                           'TcpStream::connect_timeout(', 'emit_current(fresh, || {'),
            'account HTTP bypasses the complete encoder or validates after connection')
    account_control = part(c, 'pub(crate) fn control(', '\nfn use_error(')
    require(same_order(account_control, 'self.check_coordination()?;',
                       'let now = host_time()?;', 'lease.require_current(now)?;',
                       'verifier.open(token, peer, &expected, now)?;'),
            'account control samples authority before the coordinator wait')
    require('fn write_record(&self, value: &Value)' in c and '.sync_all()' in c,
            'audit persistence acknowledgement changed')
    require('aivm_secrets_garrett_core::emission::emit_current(PendingEmission { check, emit })' in c
            and '(self.check)()' in c and '(self.emit)()' in c,
            'native emission bypasses the extracted admission controller')
    # Current OAuth tokens are selected under a held lease before entering
    # the proved controller, rather than substituted by the HTTP interpreter.
    vault = contents[RUST + 'oauth_vault.rs']
    current = part(vault, 'pub(crate) fn current_lease(', '\nstruct RefreshWork')
    require(same_order(current, 'lock_named(".vault.lock", true)',
                       'verify_session_marker(', 'self.read(', 'core::require_current_lease(',
                       'Ok(CurrentCredential {', '_lock: lock,'),
            'OAuth current credential bypasses locking, marker or epoch admission')
    require('self.refresh(' not in current and 'session_snapshot(' not in current,
            'guest current-token lease attempts implicit refresh')
    opener = part(c, 'impl protocol::CredentialOpener for SessionOpener',
                  'impl protocol::CredentialOpener for InnerEnvelope')
    require(same_order(opener, 'verify_session_marker(', 'opened.credential = Credential('),
            'OAuth capability marker not checked before credential substitution')
    require('Credential(Zeroizing::new(session_binding.marker().to_vec()))' in c
            and 'lease.require_current(current.now)?;' in c
            and 'lease.require_current(current)?;' in request,
            'OAuth session lost opaque sealing or late token-expiry admission')
    coordinate = contents[RUST + 'coordination.rs']
    require(coordinate.count('TcpStream::connect_timeout(') == 1
            and coordinate.count('.write_all(&bytes)') == 1
            and same_order(coordinate, 'with_client_auth_cert(', 'fn call(',
                           '.complete_io(&mut socket)', '.write_all(&bytes)'),
            'coordinator transport bypasses mTLS or adds an unreviewed send')
    require('self.call("check", None)' in coordinate
            and 'value.get("ok") != Some(&json!(true))' in coordinate
            and 'value[flag] != json!(true)' in coordinate
            and 'fn outcome_unknown(&self) -> Error' in coordinate,
            'coordinator admission caches or accepts an untyped acknowledgement')
    require('if !aivm_secrets_garrett_core::coordination::valid_retry_key(key.as_bytes())' in request,
            'host retry-name admission bypasses the shared extracted validator')
    invoke = contents[RUST + 'client_invoke.rs']
    require('if !valid_retry_key(key.as_bytes())' in invoke
            and 'json::parse(&bytes, MAX_ARGUMENTS)' in invoke
            and 'if !arguments.is_object()' in invoke
            and 'OFlags::NONBLOCK' in invoke
            and '.is_file()' in invoke
            and '"idempotency_key".into()' in invoke,
            'guest invoke lost bounded object input or retry-name validation')
    guest_call = part(contents[RUST + 'client_main.rs'], 'fn invoke_action(', 'fn encoded_reply(')
    require(same_order(guest_call, 'client_invoke::Invoke::parse(words)?',
                       'let config = configure(config)?', 'config.select_capability(',
                       'config.exchange(frame)?')
            and guest_call.count('configure(config)?') == 1
            and 'return Err(Error::OutcomeUnknown)' in guest_call,
            'guest invoke changed snapshot selection or post-send uncertainty')
    member_call = part(coordinate, '    fn call(', '    pub(crate) fn operator(')
    operator_call = part(coordinate, '    pub(crate) fn operator(', '    fn exchange(')
    exchange_call = part(coordinate, '    fn exchange(', '\nfn operator_reply(')
    require('self.exchange(&value, Error::Revoked, Error::Revoked)?' in member_call
            and 'self.exchange(&value, Error::Unreachable, bad)?' in operator_call
            and 'Error::OutcomeUnknown' in operator_call
            and same_order(exchange_call, 'while connection.is_handshaking()',
                           '.write_all(&bytes)', '.map_err(|_| after)?',
                           'response(BufReader::new(stream)).map_err(|_| after)'),
            'coordinator caller/phase error classification or single submission changed')
    receipt = part(coordinate, 'fn operator_reply(', '\nfn line(')
    require('if !aivm_secrets_garrett_core::coordinator_authority::operator_acknowledged(' in receipt
            and 'json::keys(&value, &["ok", "active", "revision"], &[])' in receipt
            and 'm["active"].as_bool().ok_or(bad)?' in receipt
            and 'json::integer(&m["revision"], 1, i64::MAX)' in receipt,
            'operator receipt bypasses exact shape/type or extracted validation')
    admin = contents[RUST + 'coordinator_admin.rs']
    require(admin.count('.operator(') == 3
            and all('self.0.operator(Action::' + name in admin
                    for name in ['Activate', 'Revoke', 'Status'])
            and '.operator(' not in request and '.operator(' not in c,
            'operator client broadened or entered guest custody paths')
    # Host renewal may carry only the source certificate's verified key
    # identity; substituting the current fingerprint would defeat continuity.
    rebinding = contents[RUST + 'authority/rebinding.rs']
    prepare = part(rebinding, 'pub fn rebind_to_file(', '        Ok(result)')
    require(same_order(prepare, 'self.root.lock(false)?;',
                       'self.current()?;', '.verify(&token.as_bytes().to_vec())',
                       'read_registry(', 'certificates::inspect_client(&old_pem, &ca)?;',
                       'let now = clock()?;', 'gate::rebind('),
            'host rebinding bypasses stable state, signature or certificate preparation')
    require('crypto::certificate_thumbprint(&prior.der)? != old_thumb' in prepare
            and '&prior.fingerprint.as_bytes().to_vec(),' in prepare
            and '&expected_thumbprint.as_bytes().to_vec(),' in prepare
            and '.unseal(' not in prepare,
            'host rebinding forges source key/CAS evidence or opens before its guard')
    require(rebinding.count('.unseal(self.envelope)') == 1
            and 'secret.bytes(),' in rebinding and 'self.authority.issue_to_file(' in rebinding,
            'rebinding does not carry exactly the guarded opaque capability')
    host = contents[RUST + 'authority_main.rs']
    handler = part(host, '"rebind" => {', '"issue" => {')
    require('files::read_private(' in handler and '"expected_epoch"' in handler
            and '"expected_thumbprint"' in handler and '"client_assurance"' in handler,
            'host rebinding lost private input or explicit target/assurance selection')
    d = contents[RUST + 'manifest/disclosure.rs']
    require('filter::project_fields(' in d and 'ensure_safe(&value, credential)?;' in d,
            'native disclosure no longer selects and reflection-checks public fields')
    a = contents[RUST + 'client_alias.rs']
    require('"view" => CommandKind::View' in a
            and '"diff" => CommandKind::Diff' in a
            and '"checks" => CommandKind::Checks' in a
            and 'return Err(Error::Denied)' in a
            and 'reply.get("result")' in a,
            'guest-owned alias broadened or lost selected-result handling')

    # The shared reader keeps the buffer that read_until may fill beyond LF.
    # Request errors are pre-dispatch; reply errors remain post-send uncertainty.
    transport = contents[RUST + 'tls.rs']
    framed = part(transport, 'pub(crate) fn frame(', '\nfn failure(')
    require('limit.checked_add(1)' in framed
            and 'BufReader::with_capacity(16384, stream.take(bound as u64))' in framed
            and same_order(framed, '.read_until(',
                'if !aivm_secrets_garrett_core::line_frame::complete(&data, reader.buffer(), limit)',
                'Ok(data)'), 'framed transport lost bounded terminal/trailing admission')
    core_frame = contents['rust/crates/aivm-secrets-garrett-core/src/line_frame.rs'].split('#[cfg(test)]', 1)[0]
    require('if data.len() > limit || buffered.len() != 0 {' in core_frame
            and "if data[i] == b'\\n'" in core_frame
            and 'return i + 1 == data.len();' in core_frame
            and core_frame.rstrip().endswith('false\n}'),
            'core framing lost size, buffered suffix, terminal LF or EOF refusal')
    client = contents[RUST + 'client.rs']
    require(client.count('crate::tls::frame(&mut stream, limit).map_err(|_| Error::OutcomeUnknown)?') == 1
            and 'read_until(' not in client,
            'client reply bypasses shared framing or loses post-send uncertainty')
    require('let answer = frame(&mut stream, MAX_FRAME)' in transport
            and 'let raw = frame(&mut socket, MAX_REPLY).map_err(|_| Error::OutcomeUnknown)?;' in transport,
            'bridge ingress/reply no longer share frame admission with phase-correct errors')

    disclosure = contents[RUST + 'manifest/disclosure.rs']
    guard = part(disclosure, 'pub(crate) fn ensure_safe(', '#[cfg(test)]')
    require(same_order(guard,
                'json_reflection::safe(&document(v), secret, 65)',
                'contains(&json::canonical(v), secret)', 'Ok(())')
            and 'fn reject_reflection(' not in disclosure,
            'decoded tree or final serialized-byte reflection admission bypassed')
    tree_guard = contents['rust/crates/aivm-secrets-garrett-core/src/json_reflection.rs'].split('#[cfg(test)]', 1)[0]
    require('Json::Text(text) => !contains(text, secret)' in tree_guard
            and 'if contains(&fields[i].0, secret)' in tree_guard
            and 'if !safe(&values[i], secret, fuel - 1)' in tree_guard
            and 'if !safe(&fields[i].1, secret, fuel - 1)' in tree_guard,
            'recursive decoded reflection lost a key/text/child branch')

    # Guest-owned publication is separate from broker authority and provider
    # effects. Keep the concrete lock/controller and single-snapshot call sites.
    bundle = contents[RUST + 'identity_bundle.rs']
    installer = part(bundle, 'pub fn install(', '#[cfg(test)]')
    require(same_order(installer, '.lock_named(LOCK, true)',
                       'match core::install(&publication, expected)'),
            'bundle publication bypasses cooperating writer lock or extracted CAS')
    require('.lock_named(LOCK, false)' in bundle
            and '.activate_file(name, &self.at.name, self.replace)?;' in bundle
            and 'parse(&bytes)?;' in bundle,
            'bundle reader/staged publication/current-file validation contract removed')
    guest = contents[RUST + 'client_main.rs']
    require(guest.count('identity_bundle::load(') == 1
            and 'm.contains_key("certificate") == m.contains_key("identity_bundle")' in guest
            and '.insert(' in guest and 'bundle.capability.to_string()' in guest,
            'guest lost exclusive bundle selection or one-snapshot credential loading')

    authority = contents[RUST + 'coordinator_authority/ledger.rs']
    handler = part(authority, '    pub(super) fn handle(', '\nfn principal_name(')
    require('peer.certificate_sha256_hex().as_bytes().to_vec()' in handler
            and 'core::require_operator_for(action, operators, &peer)?;' in handler
            and handler.count('core::authorize(action, operators, &peer, current.as_ref())?;') == 1
            and 'core::admit(' not in handler
            and all(f'Some("{name}") => core::Action::{name.title()}' in handler
                    for name in ['activate', 'revoke', 'status', 'check', 'reserve', 'finish'])
            and same_order(handler, 'let current = read_principal(',
                           'core::authorize(action, operators, &peer, current.as_ref())?;',
                           'let result = match action {', 'tx.commit()?;')
            and all('core::' + name + '(' in handler for name in
                    ['activate', 'revoke', 'reserve', 'finish']),
            'coordinator authority bypasses extracted peer/operator/ledger decisions')
    initialization = part(authority, '        tx.execute_batch(', '    pub fn open(')
    require(same_order(initialization, 'tx.commit()?;', 'root.sync()?;', 'Ok(Self'),
            'coordinator initialization acknowledged before durable schema commit')
    require(handler.count('tx.commit()?;') == 1
            and same_order(handler, 'let result = match action {', 'tx.commit()?;', 'Ok(result)')
            and 'DELETE FROM' not in authority.upper()
            and 'Connection::open_with_flags(' in authority
            and 'OpenFlags::SQLITE_OPEN_NOFOLLOW' in authority,
            'coordinator acknowledgement precedes commit or loses retained/private state')
    server = contents[RUST + 'coordinator_authority/server.rs']
    exchange = part(server, 'fn exchange(', '\nfn line(')
    require(same_order(exchange, 'while connection.is_handshaking()',
                       'tls::VerifiedPeer::from_connection(&connection)?', 'ledger.handle(',
                       '.write_all(header.as_bytes())')
            and exchange.count('ledger.handle(') == 1
            and 'json::canonical(&reply)' in exchange,
            'coordinator reply bypasses authenticated peer or committed ledger')


    require(same_order(exchange, 'stream.conn.send_close_notify()',
                       'if stream.flush().is_ok()', 'stream.sock.shutdown(Shutdown::Write)',
                       'discard_after_reply(&mut stream.sock)')
            and 'reader.take(32768)' in server
            and 'tls::Deadline::start_for(TIMEOUT' in exchange,
            'coordinator reply lost bounded, deadline-protected transport shutdown')


def check(root: Path) -> dict:
    inventory = json.loads((root / INVENTORY_PATH).read_text())
    require(inventory.get('schema_version') == 1, 'unknown W3 inventory version')
    require(inventory.get('scope') == 'native-manifest-https-v1', 'invalid W3 scope')
    fingerprints = inventory.get('source_sha256', {})
    actual_sources = rust_sources(root)
    unreviewed = sorted(actual_sources - set(fingerprints))
    absent = sorted(set(fingerprints) - actual_sources)
    require(not (unreviewed or absent),
            'incomplete reviewed Rust source/build manifest inventory; '
            f'new/unreviewed ({len(unreviewed)}): {unreviewed[:10]}; '
            f'listed-but-absent ({len(absent)}): {absent[:10]}')
    contents = {}
    for source, expected in sorted(fingerprints.items()):
        path = root / source
        require(path.is_file(), f'missing {source}')
        data = path.read_bytes()
        require(hashlib.sha256(data).hexdigest() == expected, f'changed source needs re-review: {source}')
        contents[source] = data.decode('utf-8')
    effects = inventory.get('effect_classes')
    require(isinstance(effects, list) and {e['id'] for e in effects} == {
        'provider-preflight', 'provider-final', 'guest-reply', 'guest-denial',
        'host-audit', 'host-announcement', 'legacy-forward', 'oauth-startup',
        'host-private', 'host-control', 'guest-close', 'authority-coordinate',
        'coordination-authority', 'operator-coordinate', 'write-approval-control',
    }, 'missing effect class or newly unreviewed channel')
    sinks = json.loads((root / 'docs/planning/aivm-secrets-w0-boundaries.json').read_text())
    w0_ids = {row['id'] for row in sinks['sinks']}
    for effect in effects:
        require(effect.get('sink') in w0_ids, 'unknown W0 sink in W3 effects')
        require(effect.get('scope') in {'primary', 'delegated', 'operator_only'},
                'unclassified W3 effect scope')
        require(effect.get('constructor') and effect.get('interpreter')
                and effect.get('reachable_from'), 'missing W3 effect source chain')
    review_semantics(contents)
    return {'sources': len(fingerprints), 'effects': len(effects), 'scope': inventory['scope']}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check'])
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    try:
        summary = check(args.root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('W3 boundary check FAILED:', error)
        return 1
    print('W3 reviewed boundary check:', summary, '(not a completeness or formal proof)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
