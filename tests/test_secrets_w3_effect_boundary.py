"""W3 reviewed boundary structure and independent deliberate bypass mutants.

These assertions check source-change gates and selected known dangerous edits.
They deliberately do not assert theorem names or user-facing documentation.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from dev.verification.w3_effect_boundary import (
    ContractError, EXPECTED_SOURCES, INVENTORY_PATH, RUST, check,
)

ROOT = Path(__file__).resolve().parents[1]


def test_w3_current_reviewed_effect_boundary():
    assert check(ROOT) == {
        'sources': len(EXPECTED_SOURCES), 'effects': 15, 'scope': 'native-manifest-https-v1',
    }


def fake_checkout(tmp_path):
    repo = tmp_path / 'repo'
    for name in [*EXPECTED_SOURCES, INVENTORY_PATH,
                 'docs/planning/aivm-secrets-w0-boundaries.json']:
        output = repo / name
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, output)
    return repo


def mutate(repo, filename, before, after):
    path = repo / filename
    original = path.read_text()
    assert before in original
    path.write_text(original.replace(before, after, 1))
    # Intentionally re-baseline the fingerprint to ensure the semantic source
    # guard rejects bypasses, not merely that every edit changes a SHA-256.
    inventory_path = repo / INVENTORY_PATH
    inventory = json.loads(inventory_path.read_text())
    inventory['source_sha256'][filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    inventory_path.write_text(json.dumps(inventory))


@pytest.mark.parametrize('file,old,new', [
    ('rust/crates/aivm-secrets-garrett-core/src/audit_record.rs', 'sink.append(bytes)?;', 'Ok(())?;'),
    ('rust/crates/aivm-secrets-garrett-core/src/audit_record.rs', 'sink.append(&delimiter)?;', 'Ok(())?;'),
    ('rust/crates/aivm-secrets-garrett-core/src/audit_record.rs', 'sink.sync_record()?;', 'Ok(())?;'),
    ('rust/crates/aivm-secrets-garrett-core/src/audit_record.rs', '*poisoned = true;', '*poisoned = false;'),
    (RUST + 'custody.rs', 'self.0.sync_all().map_err(|_| Error::InternalError)', 'Ok(())'),
    (RUST + 'custody.rs', 'append_durable_record(&mut sink, failed, &bytes)', 'Ok(())'),
    (RUST + 'custody.rs', 'self.0.write_all(bytes).map_err(|_| Error::InternalError)', 'Ok(())'),
    (RUST + 'custody/manifest_session.rs',
     'self.0.write_all(bytes).map_err(|_| Error::UpstreamResponse)', 'Ok(())'),
    (RUST + 'custody/manifest_session.rs',
     'self.0.flush().map_err(|_| Error::UpstreamResponse)', 'Ok(())'),
    (RUST + 'custody/manifest_session.rs',
     'self.0.write_all(bytes).map_err(|_| Error::UpstreamResponse)',
     'self.0.write_all(&Vec::new()).map_err(|_| Error::UpstreamResponse)'),
    (RUST + 'custody/manifest_session.rs',
     'self.0.flush().map_err(|_| Error::UpstreamResponse)',
     'self.0.flush().map_err(|_| Error::InternalError)'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', '    ready: bool,', '    pub ready: bool,'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'ready: false,', 'ready: true,'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'self.ready = false;', 'self.ready = true;'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'self.ready = true;', 'self.ready = false;'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'self.request.submit(&mut self.writer)', 'self.writer.flush()'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'if !self.ready {', 'if false {'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'Ok((self.writer, self.request, self.metadata))', 'Ok((self.writer, Request::new(self.request.body), self.metadata))'),
    ('rust/crates/aivm-secrets-garrett-core/src/response_gate.rs', 'channel.into_parts()?', 'unchecked_parts(channel)?'),
    ('rust/crates/aivm-secrets-garrett-core/src/selected_conversion.rs',
     'Json::Opaque => Err(builder.invalid())', 'Json::Opaque => Ok(builder.null())'),
    ('rust/crates/aivm-secrets-garrett-core/src/selected_conversion.rs',
     'if bytes.len() == 0 || bytes.len() > 32', 'if false'),
    ('rust/crates/aivm-secrets-garrett/src/manifest/disclosure.rs',
     'if !selected_conversion::public_field_name(&name)', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/selected_conversion.rs',
     'let name = builder.name(&field.0)?;', 'let name = invalid_unchecked_name(&field.0);'),
    (RUST + 'manifest/disclosure.rs',
     'selected_conversion::render_wire(v)', 'Ok(aivm_secrets_garrett_core::json_wire::Value::Null)'),
    (RUST + 'manifest/disclosure.rs',
     'selected: selected_bytes', 'selected: json::canonical(response)'),
    (RUST + 'manifest/disclosure.rs',
     'ensure_selected_safe(&selected.value, &selected_bytes, credential)?;', 'Ok::<(), Error>(())?;'),
    (RUST + 'manifest/disclosure.rs',
     'json_reflection::safe(v, secret, 65)', 'true'),
    (RUST + 'manifest/disclosure.rs',
     'contains(wire, secret)', 'false'),
    ('rust/crates/aivm-secrets-garrett-core/src/selected_conversion.rs',
     'return Err(WireDenial::DuplicateName);', 'return Ok(());'),
    ('rust/crates/aivm-secrets-garrett-core/src/selected_conversion.rs',
     'if first < 0x80 {', 'if true {'),
    ('rust/crates/aivm-secrets-garrett-core/src/response_gate.rs', '    writer: W,', '    pub writer: W,'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'parser.parse(released)', 'unsafe_parse_without_token()'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', '    host: Vec<u8>,', '    pub host: Vec<u8>,'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', '    port: u16,', '    pub port: u16,'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', 'if route.port <= 0 || route.port > 65535', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', 'host: route.host.clone()', 'host: route.path.clone()'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', 'port: route.port as u16', 'port: 443'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', 'target: fields.target', 'target: route.path.clone()'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', '&route.authentication, body', '&crate::credential_use::Authentication::ApiKey, body'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs', 'host: head.host,', 'host: route.path.clone(),'),
    (RUST + 'custody/manifest_session.rs', 'std::str::from_utf8(endpoint.host())', 'std::str::from_utf8(&route.host)'),
    (RUST + 'custody/manifest_session.rs', 'SocketAddr::new(self.executor.address, endpoint.port())', 'SocketAddr::new(self.executor.address, 443)'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_string.rs', 'value <= 0x10ffff && (value < 0xd800 || value > 0xdfff)', 'value <= 0x10ffff'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_string.rs', 'if !valid_scalar(values[index])', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_string.rs', "b'a' + (value - 10) as u8", "b'A' + (value - 10) as u8"),
    ('rust/crates/aivm-secrets-garrett-core/src/json_string.rs', '55296 + remaining / 1024', '56320 + remaining / 1024'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_string.rs', '56320 + remaining % 1024', '55296 + remaining % 1024'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_string.rs', 'if !valid_text(values)', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_string.rs', 'append_scalar(output, values[index])', 'append_scalar(output, 65)'),
    ('rust/crates/aivm-secrets-garrett/src/json.rs', 'json_wire::encode(&capture(value).0)', 'unchecked_encode(value)'),
    ('rust/crates/aivm-secrets-garrett/src/json.rs', 'value.chars().map(u32::from).collect()', 'value.chars().map(|_| 65).collect()'),
    ('rust/crates/aivm-secrets-garrett/src/json.rs', 'json_wire::prepare(&self.0, limit)', 'guest_frame::prepare(Vec::new(), limit)'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'Value::Null => output.extend_from_slice(b"null")', 'Value::Null => output.extend_from_slice(b"false")'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'output.extend_from_slice(b"true")', 'output.extend_from_slice(b"null")'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'Value::Number(token) => output.extend_from_slice(token)', 'Value::Number(_) => output.extend_from_slice(b"0")'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'if !append(output, &values[index])', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'if !append_field(output, &fields[index])', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'if !crate::json_string::append(output, &field.0)', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', "output.push(b':');", "output.push(b',');"),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', "output.push(b']');", "output.push(b'}');"),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'if !append(&mut output, value)', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'crate::guest_frame::prepare(payload, limit)', 'crate::guest_frame::prepare(Vec::new(), limit)'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_wire.rs', 'crate::guest_frame::prepare(payload, limit)', 'crate::guest_frame::prepare(payload, usize::MAX)'),
    ('rust/crates/aivm-secrets-garrett/src/json.rs', 'Captured(convert(value))', 'Captured(Wire::Null)'),
    ('rust/crates/aivm-secrets-garrett/src/json.rs', 'name.chars().map(u32::from).collect()', 'name.chars().map(|_| 65).collect()'),
    ('rust/crates/aivm-secrets-garrett/src/tls.rs', '.prepare(MAX_REPLY)', '.prepare(usize::MAX)'),
    ('rust/crates/aivm-secrets-garrett/src/tls.rs', 'Ok(value) => self.answer(value, &peer, &now)', 'Ok(_) => self.answer(Value::Null, &peer, &now)'),
    ('rust/crates/aivm-secrets-garrett/src/tls.rs', 'Ok(value) => self.answer(value, &peer, &now),', 'Ok(value) => { let _ = self.answer(value.clone(), &peer, &now); self.answer(value, &peer, &now) },'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_context.rs', 'provider_io::Routed::new(self.context.route(), plan.work)', 'provider_io::Routed::new(other_route(), plan.work)'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'self.work.setup_route(self.route)', 'self.work.setup()'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'self.work.audit_route(self.route, phase)', 'self.work.audit(phase)'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'if self.attempted {', 'if false {'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'self.attempted = true;', 'self.attempted = false;'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'writer.write_all(bytes)', 'writer.write_all(&Vec::new())'),
    ('rust/crates/aivm-secrets-garrett-core/src/provider_io.rs', 'writer.flush()', 'Ok(())'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_context.rs', "context: &'a current_admission::Context<'a>", "pub context: &'a current_admission::Context<'a>"),
    ('rust/crates/aivm-secrets-garrett-core/src/request_context.rs', 'current_admission::Bound::new(self.context, routed, checks)', 'current_admission::Bound::new(unchecked_context(), routed, checks)'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_context.rs', 'self.factory.checks()', 'unchecked_checks()'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_context.rs', 'keyed_write: plan.keyed_write', 'keyed_write: false'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_context.rs', 'self.work.recheck()', 'Ok(())'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_context.rs', 'self.work.complete(raw)', 'self.work.complete(self.work.empty_facts())'),
    ('rust/crates/aivm-secrets-garrett-core/src/current_admission.rs', 'checks.coordination()', 'unchecked_coordination()'),
    ('rust/crates/aivm-secrets-garrett-core/src/current_admission.rs', 'checks.clock()', 'unchecked_clock()'),
    ('rust/crates/aivm-secrets-garrett-core/src/current_admission.rs', 'checks.control(now)', 'checks.control(0)'),
    ('rust/crates/aivm-secrets-garrett-core/src/current_admission.rs', 'checks.lease(now)', 'checks.lease(0)'),
    ('rust/crates/aivm-secrets-garrett-core/src/current_admission.rs', 'crate::present(self.identity, self.expected, self.peer, now)', 'crate::present(self.identity, self.expected, self.operation, now)'),
    ('rust/crates/aivm-secrets-garrett-core/src/current_admission.rs', 'self.context.current(&mut self.checks)', 'self.work.recheck()'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs', 'let report = completion::complete(pending, self.effects);\n        self.effects = report.effects;', 'let report = completion::complete(pending, self.effects);'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs', 'completion::complete(pending, self.effects)', 'unchecked_complete(pending, self.effects)'),
    ('rust/crates/aivm-secrets-garrett-core/src/guest_frame.rs', 'if payload.len() >= limit', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/guest_frame.rs', "payload.push(b'\\n');", "payload.push(b'\\r');"),
    ('rust/crates/aivm-secrets-garrett-core/src/guest_frame.rs', 'line_frame::complete(&payload, b"", limit)', 'unchecked_complete(&payload, b"", limit)'),
    ('rust/crates/aivm-secrets-garrett-core/src/guest_frame.rs', 'if self.attempted', 'if false'),
    ('rust/crates/aivm-secrets-garrett-core/src/guest_frame.rs', 'self.attempted = true;', 'self.attempted = false;'),
    ('rust/crates/aivm-secrets-garrett-core/src/guest_frame.rs', 'writer.write_frame(&self.wire)', 'writer.write_frame(b"{}\\n")'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'begin_dispatch_audit(&prepared)', 'unchecked_audit(&prepared)'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'acknowledge_dispatch(&audited)', 'unchecked_ack(&audited)'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'begin_provider(audited)', 'unchecked_provider(audited)'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', '.provider_completed(pending.phase)', '.unchecked_completed(pending.phase)'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', '.finish_dispatch(pending.phase)', '.unchecked_finished(pending.phase)'),
    ('rust/crates/aivm-secrets-garrett-core/src/completion.rs', 'begin_completion_check(phase)', 'unchecked_completion_check(phase)'),
    ('rust/crates/aivm-secrets-garrett-core/src/completion.rs', 'finish_completion_check(phase)', 'unchecked_completion_checked(phase)'),
    ('rust/crates/aivm-secrets-garrett-core/src/completion.rs', 'begin_completion_audit()', 'unchecked_completion_audit()'),
    ('rust/crates/aivm-secrets-garrett-core/src/completion.rs', 'acknowledge_completion_audit()', 'unchecked_completion_ack()'),
    ('rust/crates/aivm-secrets-garrett-core/src/completion.rs', 'value_ready()', 'unchecked_value_ready()'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs', 'let report = dispatch::dispatch(plan.work, Ok(prepared), self.effects, plan.keyed_write);\n        self.effects = report.effects;', 'let report = dispatch::dispatch(plan.work, Ok(prepared), self.effects, plan.keyed_write);'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'request_adapter::Pending::new(work)', 'unchecked_pending(work)'),

    ('rust/crates/aivm-secrets-garrett/src/host_control.rs', 'if peer.uid != rustix::process::geteuid() {', 'if false {'),
    ('rust/crates/aivm-secrets-garrett/src/custody/approval.rs', 'let now = host_time()?;', 'let now = 0;'),
    ('rust/crates/aivm-secrets-garrett/src/custody/approval.rs', 'self.active.store(false, Ordering::Release)', 'self.active.store(true, Ordering::Release)'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'control.state.admit(&approval_digest, op.write)?', 'aivm_secrets_garrett_core::approval::Decision::Allowed'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'fresh: &fresh,', 'fresh: &|| Ok(()),'),

    ('rust/crates/aivm-secrets-garrett-core/src/read_transition.rs',
     'pending.recheck(CompletionPhase::BeforeRelease)', 'Ok::<(), C::Error>(())'),

    (RUST + 'coordination.rs', 'self.exchange(&value, Error::Unreachable, bad)?',
     'self.exchange(&value, Error::Unreachable, Error::Revoked)?'),
    (RUST + 'coordination.rs', 'if !aivm_secrets_garrett_core::coordinator_authority::operator_acknowledged(',
     'if false && !aivm_secrets_garrett_core::coordinator_authority::operator_acknowledged('),
    (RUST + 'coordinator_authority/server.rs', 'discard_after_reply(&mut stream.sock);', 'let _ = &stream.sock;'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', '.begin_send(self.phase, &mut self.local, self.write)', '.unchecked_send(self.phase, &mut self.local, self.write)'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'self.local.finish_check(stamp)', 'true'),
    (RUST + 'custody/manifest_session.rs',
     'if !aivm_secrets_garrett_core::coordination::valid_retry_key(key.as_bytes())', 'if false'),
    (RUST + 'client_invoke.rs', 'if !valid_retry_key(key.as_bytes())', 'if false'),
    (RUST + 'client_main.rs', 'let command = client_invoke::Invoke::parse(words)?;',
     'let command = unchecked_invoke(words)?;'),
    (RUST + 'manifest/disclosure.rs', 'json_reflection::safe(&document(v), secret, 65)', 'true'),
    (RUST + 'manifest/disclosure.rs', 'contains(&json::canonical(v), secret)', 'false'),
    ('rust/crates/aivm-secrets-garrett-core/src/json_reflection.rs',
     'if contains(&fields[i].0, secret)', 'if false'),
    (RUST + 'tls.rs', 'complete(&data, reader.buffer(), limit)', 'complete(&data, &[], limit)'),
    (RUST + 'tls.rs', 'if !aivm_secrets_garrett_core::line_frame::complete', 'if false && !aivm_secrets_garrett_core::line_frame::complete'),
    (RUST + 'client.rs', 'crate::tls::frame(&mut stream, limit).map_err(|_| Error::OutcomeUnknown)?', 'Ok::<_, Error>(b"{}".to_vec())?'),
    (RUST + 'coordinator_authority/ledger.rs', 'core::require_operator_for(action, operators, &peer)?;', 'let _ = operators;'),
    (RUST + 'coordinator_authority/ledger.rs', 'let admission = core::authorize(action, operators, &peer, current.as_ref())?;', 'let admission = Some(1);'),
    (RUST + 'coordinator_authority/ledger.rs', 'Some("reserve") => core::Action::Reserve,', 'Some("reserve") => core::Action::Status,'),
    (RUST + 'coordinator_authority/ledger.rs', 'tx.commit()?;', 'drop(tx);'),
    (RUST + 'coordinator_authority/ledger.rs',
     '// No positive response leaves this function before COMMIT acknowledges.\n        tx.commit()?;',
     '// No positive response leaves this function before COMMIT acknowledges.\n        drop(tx);'),
    (RUST + 'coordinator_authority/ledger.rs', 'peer.certificate_sha256_hex().as_bytes().to_vec()', 'peer.thumbprint().as_bytes().to_vec()'),
    (RUST + 'coordinator_authority/server.rs', 'ledger.handle(&peer, operators, &value)', 'unreviewed_reply(&value)'),
    (RUST + 'custody.rs', 'http_wire::append_request(', 'unchecked_request('),
    (RUST + 'custody/manifest_session.rs',
     'provider_wire::append(', 'unchecked_request_bytes('),
    ('rust/crates/aivm-secrets-garrett-core/src/http_wire.rs',
     '!http_auth::valid_credential(secret)', 'http_auth::valid_credential(secret)'),
    ('rust/crates/aivm-secrets-garrett-core/src/http_wire.rs',
     '!reserved_name(name)', 'true'),
    ('rust/crates/aivm-secrets-garrett-core/src/http_wire.rs',
     '!unique_before(headers, i, &headers[i].name)', 'false'),
    ('rust/crates/aivm-secrets-garrett-core/src/http_wire.rs',
     'append_decimal(output, bytes.len());', 'append_decimal(output, bytes.len() + 1);'),
    (RUST + 'json.rs', 'decode(&raw, 0)',
     'serde_json::from_slice(bytes).map_err(|_| Error::InvalidCapability)'),
    (RUST + 'authority/rebinding.rs',
     'let now = clock()?;', 'let now = 0;'),
    (RUST + 'authority/rebinding.rs',
     '&prior.fingerprint.as_bytes().to_vec(),', '&current.fingerprint.as_bytes().to_vec(),'),
    (RUST + 'authority/rebinding.rs',
     'let _lease = self.root.lock(false)?;', 'let _lease = ();'),
    (RUST + 'authority/rebinding.rs',
     '&expected_thumbprint.as_bytes().to_vec(),', '&target.certificate,'),
    (RUST + 'custody.rs',
     'self.check_coordination()?;\n        let now = host_time()?;',
     'let now = host_time()?;\n        self.check_coordination()?;'),
    (RUST + 'custody/manifest_session.rs',
     'lease.require_current(now)?;', 'let _ = now;'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'pending.work.reserve()', 'Ok::<(), W::Error>(())'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'pending.work.finish()', 'Ok::<(), W::Error>(())'),
    (RUST + 'custody/manifest_session.rs',
     'self.audit.write_record(&json!({\n            "schema":1,\n            "event":"completed",',
     'unchecked_release(&json!({\n            "schema":1,\n            "event":"completed",'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'read_transition::run_current(pending)\n            .map(aivm_secrets_garrett_core::completion::Completed::into_value)', 'unchecked_reply(&pending)'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs', 'self.work.operation_write(),', 'true,'),
    ('rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs', '            phase,\n            self.work.operation_write(),', '            read_transition::Phase::Final,\n            self.work.operation_write(),'),
    (RUST + 'custody/manifest_session.rs',
     'audit.write_record(&json!({', 'let _ = audit; // bypass\n        unchecked_record(&json!({'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'read_transition::acknowledge(prepared, true)', 'unchecked_acknowledge(prepared, true)'),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'audited: &read_transition::Audited', 'audited: &Effect'),
    (RUST + 'custody/manifest_session.rs',
     'let policy_hash = self.policy.digest();',
     'let policy_hash = "raw-policy-digest";'),
    (RUST + 'coordination.rs',
     'value.get("ok") != Some(&json!(true))', 'false'),

    (
        RUST + 'oauth_vault.rs',
        'core::require_current_lease(row.active, &row.state, &meta, binding.epoch, clock())',
        'Ok::<(), core::RefreshDenial>(())',
    ),
    (
        RUST + 'custody.rs',
        '.verify_session_marker(',
        '.unchecked_marker(',
    ),
    (
        RUST + 'custody/manifest_session.rs',
        'lease.require_current(current)?;',
        'let _ = current;',
    ),
    (
        RUST + 'custody.rs',
        'lease.require_current(current.now)?;',
        'let _ = current.now;',
    ),
    ('rust/crates/aivm-secrets-garrett-core/src/dispatch.rs', 'provider_exchange::exchange(pending, audited)', 'unchecked_exchange(pending, audited)'),
    (
        RUST + 'custody.rs',
        'aivm_secrets_garrett_core::emission::emit_current(PendingEmission { check, emit })',
        'emit()',
    ),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'operation_write: op.write,', 'operation_write: true,'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', '(self.dispatch.fresh)()', 'Ok(())'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'self.session.disclosure.project(', 'Ok(self.raw.clone()) // unsafe raw projection'),
    (
        RUST + 'custody/manifest_session.rs',
        '        audit.write_record(&json!({',
        '        println!("{:?}", &secret.0);\n        audit.write_record(&json!({',
    ),
    (
        RUST + 'tls.rs',
        'GuestFrame::from_answer(answer)?.send(&mut stream)?;',
        'GuestFrame::from_answer(answer)?.send(&mut stream)?;\n        stream.write_all(b"bypass")?;',
    ),
    (
        RUST + 'tls.rs',
        'let value = answer.unwrap_or_else(failure);',
        'let value = answer.unwrap_or_else(|error| json!({"detail": format!("{:?}", error)}));',
    ),
])
def test_w3_bypass_mutants_fail_even_with_updated_source_digest(
    tmp_path, file, old, new,
):
    repo = fake_checkout(tmp_path)
    mutate(repo, file, old, new)
    with pytest.raises(ContractError):
        check(repo)


def test_w3_rejects_unreviewed_module_change(tmp_path):
    repo = fake_checkout(tmp_path)
    path = repo / (RUST + 'custody.rs')
    path.write_text(path.read_text() + '\n// An unreviewed change.\n')
    with pytest.raises(ContractError, match='changed source needs re-review'):
        check(repo)


def test_w3_rejects_inventory_without_legacy_and_oauth_sinks(tmp_path):
    repo = fake_checkout(tmp_path)
    path = repo / INVENTORY_PATH
    inventory = json.loads(path.read_text())
    inventory['effect_classes'] = [
        e for e in inventory['effect_classes'] if e['id'] != 'legacy-forward'
    ]
    path.write_text(json.dumps(inventory))
    with pytest.raises(ContractError, match='missing effect class'):
        check(repo)


def test_w3_rejects_added_rust_module(tmp_path):
    repo = fake_checkout(tmp_path)
    added = repo / (RUST + 'unreviewed_output.rs')
    added.write_text('pub fn bypass() {}\n')
    with pytest.raises(ContractError, match='incomplete reviewed Rust source'):
        check(repo)


def test_w3_ignores_cargo_generated_rust_sources(tmp_path):
    repo = fake_checkout(tmp_path)
    # Cargo and build scripts legitimately create Rust files under target/.
    # They cannot be treated as repository-owned source inventory changes.
    for path in [
        repo / 'rust/target/debug/build/example/out/bindings.rs',
        repo / 'rust/crates/aivm-secrets-garrett/target/debug/generated.rs',
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('pub fn generated() {}\n')
    assert check(repo)['sources'] == len(EXPECTED_SOURCES)


def test_w3_reports_new_unreviewed_rust_source(tmp_path):
    repo = fake_checkout(tmp_path)
    path = repo / (RUST + 'unexpected_sink.rs')
    path.write_text('pub fn unexpected_sink() {}\n')
    with pytest.raises(ContractError, match=r'new/unreviewed .*unexpected_sink\.rs'):
        check(repo)


def test_nr1_production_called_transition_rejects_core_gate_mutations(tmp_path):
    core = 'rust/crates/aivm-secrets-garrett-core/src/read_transition.rs'
    for before, after in [
        ('|| !admitted_operation_write', '|| false'),
        ('matches!(phase, Phase::Preflight)', 'false'),
        ('if !ack {', 'if false {'),
    ]:
        checkout = fake_checkout(tmp_path / before.replace(' ', '_').replace('!', 'not').replace('|', 'or').replace('(', '').replace(')', '')[:60])
        mutate(checkout, core, before, after)
        with pytest.raises(ContractError, match='extracted core'):
            check(checkout)


@pytest.mark.parametrize('filename,before,after', [
    ('rust/crates/aivm-secrets-garrett-core/src/read_transition.rs',
     'invocation.into_result(result)', 'result'),
    ('rust/crates/aivm-secrets-garrett-core/src/read_transition/invocation.rs',
     'if matches!(self.progress, Progress::Finished)', 'if true'),
    ('rust/crates/aivm-secrets-garrett-core/src/read_transition/invocation.rs',
     'self.adapter.preflight()', '{ let _ignored = self.adapter.preflight(); self.adapter.preflight() }'),
])
def test_request_invocation_review_guard_rejects_rebaselined_bypasses(tmp_path, filename, before, after):
    checkout = fake_checkout(tmp_path)
    mutate(checkout, filename, before, after)
    with pytest.raises(ContractError, match='invocation'):
        check(checkout)
