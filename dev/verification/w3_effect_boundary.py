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
    decoded = contents[RUST + 'json.rs']
    parse = part(decoded, 'pub fn parse(', '\nfn string(')
    require('decode(&raw, 0)' in parse and 'Ok(Value::Object(' in decoded,
            'JSON objects can bypass explicit structure-preserving decoding')
    # The sole native manifest call to the credential-bearing HTTP adapter is
    # after policy compilation, durable audit and current grant revalidation.
    m = contents[RUST + 'custody/manifest_session.rs']
    request = part(m, 'pub(super) fn request(', 'pub(super) fn control(')
    control = part(m, 'pub(super) fn control(', '\nfn manifest_request_bytes(')
    dispatch = part(request, 'let dispatch = |prepared: PreparedDispatch', 'let facts = if let Some(effect)')
    release = part(request, 'let release = (|| -> Outcome<Value> {', 'if sent_write {')
    require('struct PreparedDispatch<' in m and 'enum DispatchPhase {' in m,
            'native dispatch has no typed phase boundary')
    require(request.count('exchange_manifest(') == 1,
            'unexpected direct manifest HTTP dispatch outside the sole gated closure')
    require(request.count('PreparedDispatch::preflight(&effect)') == 1
            and request.count('PreparedDispatch::final_effect(&effect)') == 1,
            'preflight/final not constrained to the reviewed dispatch constructor')
    require(same_order(dispatch,
                       'ensure_safe(&json!({"target":effect.target})',
                       'audit.write_record(', 'let pending = crate::coordination::PendingDispatch',
                       'executor.exchange_manifest(', 'coordination::dispatch(&pending, keyed_write)'),
            'provider dispatch bypasses reflection, durable audit, or fresh authorization')
    require('check: &fresh,' in dispatch and 'reserve: || reservation_call(false),' in dispatch
            and 'finish: || reservation_call(true),' in dispatch
            and 'matches!(prepared.phase, DispatchPhase::Final)' in dispatch
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
    require(same_order(release, 'self.disclosure.project(', 'ensure_safe(&reply',
                       'audit.write_record(', 'Ok(reply)'),
            'guest release bypasses selected disclosure/reflection/audit')
    require('guards::authorize(' in request and 'open_surrogate(' in request
            and 'self.policy.operation(&request)' in request,
            'native request missing authorizing guard / policy compiler')
    require('let effect = self.policy.final_effect(op, &args, &facts)?;' in request,
            'final effect is not compiled from checked facts')
    require('self.policy.preflight(op, &args)?' in request,
            'preflight is no longer compiled from host policy')
    require('let sent_write = effect.as_ref().is_some_and(|e| e.write);' in request
            and 'release.map_err(|_| Error::OutcomeUnknown)' in request,
            'write uncertainty boundary altered')
    # W6: the exact provider bytes are validated by a pure encoder BEFORE any
    # TCP/TLS effect. This also covers OAuthSource-created Credential values.
    require(m.count('fn manifest_request_bytes(') == 1
            and m.count('let request = manifest_request_bytes(route, secret, effect, headers)?;') == 1
            and m.index('let request = manifest_request_bytes(') < m.index('TcpStream::connect_timeout('),
            'provider socket opened before outbound wire validation')
    wire = part(m, 'fn manifest_request_bytes(', 'impl Executor {')
    auth_append = 'http_auth::append_header(&mut request, &secret.0, &route.authentication)'
    require('!http_auth::valid_credential(&secret.0)' in wire
            and wire.count(auth_append) == 1 and 'Error::CredentialSource' in wire
            and 'request.extend_from_slice(&secret.0)' not in wire
            and wire.count("http_request::append_line(") == 1
            and "effect.method.as_bytes()," in wire and "effect.target.as_bytes()," in wire
            and '"authorization"' in wire and '"content-length"' in wire,
            'provider wire encoder lost injection / reserved-header refusal')
    require('if status == 206 {' in m, 'unreviewed partial response release')
    require(m.count('TcpStream::connect_timeout(') == 1 and m.count('.write_all(&request)') == 1,
            'native module added a credentialed socket or HTTP writer')
    require(m.count('exchange_manifest(') == 2,
            'extra native manifest executor call site')
    transport = part(m, '    fn exchange_manifest(', '\nfn manifest_response(')
    require(same_order(transport, 'let request = manifest_request_bytes(',
                       'TcpStream::connect_timeout(', 'while conn.is_handshaking()',
                       'let exchange = || -> Outcome<Value>', 'emit_current(fresh, || {'),
            'final authority admission does not follow provider TLS setup')
    emit = transport.split('emit_current(fresh, || {', 1)[1]
    require(transport.count('emit_current(fresh, || {') == 1
            and transport.count('exchange()') == 2 and emit.count('exchange()') == 2,
            'manifest provider write bypasses late admission continuation')
    require('self.address,' in m and 'route.authentication' in m
            and 'ClientConnection::new(self.tls.clone(), name)' in m,
            'provider request no longer uses the reviewed host route / TLS identity')
    for forbidden in ('println!(', 'eprintln!(', 'std::fs::write(', 'std::net::TcpStream::connect('):
        require(forbidden not in m, 'unreviewed output path in manifest custody: ' + forbidden)

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
    require(account_wire.count('http_request::append_line(&mut request, b"GET", path.as_bytes())') == 1
            and account_wire.count(auth_append) == 1
            and 'request.extend_from_slice(&secret.0)' not in account_wire
            and same_order(account_transport, 'let request = account_request_bytes(route, secret)?;',
                           'TcpStream::connect_timeout(', 'emit_current(fresh, || {'),
            'account HTTP bypasses the extracted auth encoder or validates after connection')
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
