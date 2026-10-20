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
    ('rust/crates/aivm-secrets-garrett/src/host_control.rs', 'if peer.uid != rustix::process::geteuid() {', 'if false {'),
    ('rust/crates/aivm-secrets-garrett/src/custody/approval.rs', 'let now = host_time()?;', 'let now = 0;'),
    ('rust/crates/aivm-secrets-garrett/src/custody/approval.rs', 'self.active.store(false, Ordering::Release)', 'self.active.store(true, Ordering::Release)'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'control.state.admit(&approval_digest, op.write)?', 'aivm_secrets_garrett_core::approval::Decision::Allowed'),
    ('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs', 'self.require_control_active(host_time()?)?;', ''),

    (RUST + 'coordination.rs', 'self.exchange(&value, Error::Unreachable, bad)?',
     'self.exchange(&value, Error::Unreachable, Error::Revoked)?'),
    (RUST + 'coordination.rs', 'if !aivm_secrets_garrett_core::coordinator_authority::operator_acknowledged(',
     'if false && !aivm_secrets_garrett_core::coordinator_authority::operator_acknowledged('),
    (RUST + 'coordinator_authority/server.rs', 'discard_after_reply(&mut stream.sock);', 'let _ = &stream.sock;'),
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
     'provider_request_bytes(', 'unchecked_request_bytes('),
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
    (RUST + 'custody/manifest_session.rs',
     'reserve: || reservation_call(false),', 'reserve: || Ok(()),'),
    (RUST + 'custody/manifest_session.rs',
     'finish: || reservation_call(true),', 'finish: || Ok(()),'),
    (RUST + 'custody/manifest_session.rs',
     '    ) -> Outcome<Self> {\n        audit.write_record(&json!({\n            "schema":1,\n            "event":"completed",',
     '    ) -> Outcome<Self> {\n        unchecked_release(&json!({\n            "schema":1,\n            "event":"completed",'),
    (RUST + 'custody/manifest_session.rs',
     'release.map(CompletedRelease::into_public)',
     'release.map(|r| r.0)'),
    (RUST + 'custody/manifest_session.rs',
     'read_transition::prepare(DispatchPhase::Final, admitted_write, effect.write)',
     'read_transition::prepare(DispatchPhase::Final, true, effect.write)'),
    (RUST + 'custody/manifest_session.rs',
     'read_transition::prepare(DispatchPhase::Preflight, false, effect.write)',
     'read_transition::prepare(DispatchPhase::Preflight, true, false)'),
    (RUST + 'custody/manifest_session.rs',
     'audit.write_record(&json!({', 'let _ = audit; // bypass\n        unchecked_record(&json!({'),
    (RUST + 'custody/manifest_session.rs',
     'Ok(AuditedDispatch { effect: self.effect, transition })',
     'Ok(AuditedDispatch { effect: self.effect, transition: unchecked_transition() })'),
    (RUST + 'custody/manifest_session.rs',
     "audited: &AuditedDispatch<'_>", 'audited: &Effect'),
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
    (
        RUST + 'custody/manifest_session.rs',
        'emit_current(fresh, || {',
        '(|| {',
    ),
    (
        RUST + 'custody.rs',
        'aivm_secrets_garrett_core::emission::emit_current(PendingEmission { check, emit })',
        'emit()',
    ),
    (
        RUST + 'custody/manifest_session.rs',
        'dispatch(PreparedDispatch::final_effect(&effect, op.write)?)?',
        'self.base.executor.exchange_manifest(&self.base.grant.route, &secret, &effect, &self.policy.headers)?',
    ),
    (
        RUST + 'custody/manifest_session.rs',
        'check: &fresh,',
        'check: || Ok(()),',
    ),
    (
        RUST + 'custody/manifest_session.rs',
        'let result = self.disclosure.project(&op.name, &raw, &secret.0)?;',
        'let result = raw.clone();',
    ),
    (
        RUST + 'custody/manifest_session.rs',
        '        audit.write_record(&json!({',
        '        println!("{:?}", &secret.0);\n        audit.write_record(&json!({',
    ),
    (
        RUST + 'tls.rs',
        'GuestFrame::from_answer(answer).send(&mut stream)?;',
        'GuestFrame::from_answer(answer).send(&mut stream)?;\n        stream.write_all(b"bypass")?;',
    ),
    (
        RUST + 'tls.rs',
        'Self(answer.unwrap_or_else(failure))',
        'Self(answer.unwrap_or_else(|error| json!({"detail": format!("{:?}", error)})))',
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
