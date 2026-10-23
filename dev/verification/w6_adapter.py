"""Review guard for W6's concrete Rust I/O adapter boundary.

This is a source/fixture consistency check, not a theorem. No Lean axiom logs,
file hash dump, or whole-workspace build is part of normal iteration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = 'docs/planning/aivm-secrets-w6-adapters.json'
SOURCE = 'rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs'
TESTS = 'tests/test_rust_w6_adapter.py'
CORE_ROUTE = 'rust/crates/aivm-secrets-garrett-core/src/provider_wire.rs'
CORE_ENCODER = 'rust/crates/aivm-secrets-garrett-core/src/http_wire.rs'
CORE_DISPATCH = 'rust/crates/aivm-secrets-garrett-core/src/dispatch.rs'
CORE_REQUEST = 'rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs'
CORE_IO = 'rust/crates/aivm-secrets-garrett-core/src/provider_io.rs'
CORE_GATE = 'rust/crates/aivm-secrets-garrett-core/src/response_gate.rs'
CORE_RELEASE = 'rust/crates/aivm-secrets-garrett-core/src/selected_release.rs'
CORE_CHANNEL = 'rust/crates/aivm-secrets-garrett-core/src/channel_work.rs'
CORE_STATUS = 'rust/crates/aivm-secrets-garrett-core/src/provider_status.rs'
CORE_CONTEXT = 'rust/crates/aivm-secrets-garrett-core/src/request_context.rs'
CORE_CURRENT = 'rust/crates/aivm-secrets-garrett-core/src/current_admission.rs'
COMMON_ENCODER = 'rust/crates/aivm-secrets-garrett/src/custody.rs'


class ContractError(ValueError):
    pass


def ensure(value: bool, reason: str) -> None:
    if not value:
        raise ContractError(reason)


def check(root: Path = ROOT) -> dict[str, int | str]:
    contract = json.loads((root / CONTRACT).read_text())
    w0 = json.loads((root / 'docs/planning/aivm-secrets-w0-boundaries.json').read_text())
    ledger = json.loads((root / 'docs/planning/aivm-secrets-assumptions.json').read_text())
    ensure(contract['schema_version'] == 1 and contract['scope'] == 'native-manifest-https-v1',
           'W6 scope/version unexpectedly changed')
    channels = contract['channels']
    ensure(len({c['sink'] for c in channels}) == len(channels)
           and {c['sink'] for c in channels} == {s['id'] for s in w0['sinks']},
           'W6 leaves a W0 I/O sink unclassified')
    assumptions = {a['id'] for a in ledger['assumptions']}
    for channel in channels:
        evidence_path = channel.get('evidence_path', TESTS)
        ensure((root / evidence_path).is_file(), 'missing adapter evidence: ' + evidence_path)
        test_source = (root / evidence_path).read_text()
        ensure((root / channel['path']).is_file(), 'missing adapter implementation: ' + channel['path'])
        ensure(all(a in assumptions for a in channel['trust']), 'unknown environment/adaptor premise')
        ensure(bool(channel['contract']) and bool(channel['model_event']), 'channel missing semantic contract')
        ensure(all(('def ' + name + '(' in test_source or 'def ' + name + '\n' in test_source)
                   for name in channel['evidence']), 'claimed W6 test not present')
    ensure(len(contract['remaining_obligations']) >= 5,
           'W6 silently removed outstanding correspondence obligations')
    source = (root / SOURCE).read_text()
    channel_core = (root / CORE_CHANNEL).read_text().split('#[cfg(test)]', 1)[0]
    setup_core = channel_core.split('fn setup_route(', 1)[1].split('fn audit_route(', 1)[0]
    ensure(setup_core.index('encode(&mut encoded, route, parts, self.secret)')
           < setup_core.index('self.work.connect(&endpoint)'),
           'TCP effect before request-byte validation')
    native = source.split('mod wire_tests {', 1)[0]
    ensure(native.count('provider_wire::append(') == 0
           and channel_core.split('pub fn encode(', 1)[1].split('pub struct Submitting', 1)[0].count('crate::provider_wire::append(') == 2,
           'native manifest adapter has additional unreviewed encoder')
    # The real credential-bearing executor only accepts the type constructed
    # after durable audit. This checks the reviewed source topology; it cannot
    # prove what a compiler or an external dependency ultimately executes.
    entry = source.split('pub(super) fn request(', 1)[1].split('pub(super) fn control(', 1)[0]
    dispatch_core = (root / CORE_DISPATCH).read_text().split('#[cfg(test)]', 1)[0]
    request_core = (root / CORE_REQUEST).read_text().split('impl<W: Work> read_transition::Request', 1)[1].split('#[cfg(test)]', 1)[0]
    ensure('read_transition::prepare(phase,self.work.operation_write(),self.work.effect_write(&effect),)' in ''.join(request_core.split())
           and 'dispatch::dispatch(plan.work, Ok(prepared), self.effects, plan.keyed_write)' in request_core
           and request_core.count('self.effects = report.effects;') == 2
           and 'request_adapter::Pending::new(work)' in entry
           and 'operation_write: op.write,' in entry
           and 'pending.work.audit(prepared.phase())' in dispatch_core
           and 'read_transition::acknowledge(prepared, true)' in dispatch_core
           and dispatch_core.index('pending.work.audit(prepared.phase())') < dispatch_core.index('read_transition::acknowledge(prepared, true)'),
           'provider effect not typed as audited/phase-authorized before dispatch')
    ensure('audited: &read_transition::Audited' in dispatch_core
           and 'audited.is_write() != pending.work.effect_write()' in dispatch_core
           and 'begin_provider(audited)' in dispatch_core,
           'provider executor accepts an unaudited policy effect')
    io = (root / CORE_IO).read_text().split('#[cfg(test)]', 1)[0]
    ensure('route: &' in io and 'pub route:' not in io
           and 'self.work.setup_route(self.route)' in io
           and 'self.work.audit_route(self.route, phase)' in io
           and 'body: B,' in io and 'pub body:' not in io
           and 'if self.attempted {' in io and 'self.attempted = true;' in io
           and io.index('self.attempted = true;') < io.index('writer.write_all(bytes)')
           and 'writer.flush()' in io
           and 'channel.submit()' in (root / CORE_CHANNEL).read_text().split('fn receive(', 1)[0]
           and 'ManifestWire(Zeroizing::new(encoded))' in source
           and 'channel_work::Submitting::new(work, &secret.0)' in source,
           'captured route/buffer submission bypassed')
    channel = io.split('pub struct Channel<', 1)[1]
    receiver = source.split('fn parse(\n        &mut self,\n        released:', 1)[1].split('fn manifest_response(', 1)[0]
    core_receive = (root / CORE_CHANNEL).read_text().split('fn receive(', 1)[1].split('impl<W: ChannelWork> dispatch::Work', 1)[0]
    ensure('request: Request::new(body)' in channel and 'ready: false,' in channel
           and 'self.ready = false;' in channel and 'self.request.submit(&mut self.writer)' in channel
           and 'self.ready = true;' in channel and 'if !self.ready {' in channel
           and 'Ok((self.writer, self.request, self.metadata))' in channel
           and 'match response_gate::receive(channel) {' in core_receive
           and 'Ok(released) => self.work.parse(released)' in core_receive
           and 'let mut parser = ManifestResponse { effect: &self.effect };' in receiver
           and 'parser.parse(released)' in receiver
           and 'released: aivm_secrets_garrett_core::response_gate::Released<' in receiver
           and 'released.into_parts()' in receiver
           and 'channel.into_parts()?' in (root / CORE_GATE).read_text()
           and 'Ok(Released {' in (root / CORE_GATE).read_text()
           and (root / CORE_GATE).read_text().split('#[cfg(test)]', 1)[0].count('Ok(Released {') == 1
           and receiver.index('parser.parse(released)') < receiver.index('manifest_response('),
           'captured channel or successful-flush response gate bypassed')
    admission = (root / CORE_CURRENT).read_text().split('#[cfg(test)]', 1)[0]
    scope = (root / CORE_CONTEXT).read_text().split('#[cfg(test)]', 1)[0]
    ensure('request_context::ScopedRequest::new(' in entry
           and 'current_admission::Bound::new(self.context, routed, checks)' in scope
           and 'provider_io::Routed::new(self.context.route(), plan.work)' in scope
           and 'self.factory.checks()' in scope
           and '&current_context,' in entry and 'self.context.current(&mut self.checks)' in admission
           and 'crate::present(self.identity, self.expected, self.peer, now)' in admission
           and 'manifest::current(' in admission and 'self.work.recheck()' not in admission,
           'native provider bypasses the source-owned bound current check')
    runtime = source.split('#[cfg(test)]', 1)[0]
    ensure(runtime.count('.write_all(') == 1 and 'self.0.write_all(bytes)' in ''.join(runtime.split())
           and 'provider_exchange::exchange(pending, audited)' in dispatch_core
           and 'self.work.send(channel)' in dispatch_core and '.begin_send(self.phase, &mut self.local, self.write)' in dispatch_core
           and runtime.count('TcpStream::connect_timeout(') == 1,
           'native manifest adapter has another provider send')
    routed_wire = (root / CORE_ROUTE).read_text().split('#[cfg(test)]', 1)[0]
    setup = source.split('fn request_fields(&mut self)', 1)[1].split('fn manifest_response(', 1)[0]
    ensure('host: route.host.clone()' in routed_wire and 'port: route.port as u16' in routed_wire
           and 'if route.port <= 0 || route.port > 65535' in routed_wire
           and 'http_wire::append_request(output, &head, secret, &route.authentication, body)' in routed_wire
           and 'host: head.host,' in routed_wire and 'port: head.port,' in routed_wire
           and 'pub host:' not in routed_wire and 'pub port:' not in routed_wire
           and 'std::str::from_utf8(endpoint.host())' in setup
           and 'SocketAddr::new(self.executor.address, endpoint.port())' in setup,
           'route-bound encoder/endpoint bypassed')
    encoder = source.split('fn manifest_fields(', 1)[1].split('fn encoding_error(', 1)[0]
    channel_encode = (root / CORE_CHANNEL).read_text().split('pub fn encode(', 1)[1].split('pub struct Submitting', 1)[0]
    shared = (root / COMMON_ENCODER).read_text().split('fn provider_request_bytes(', 1)[1].split('fn account_request_bytes(', 1)[0]
    core = (root / CORE_ENCODER).read_text().split('#[cfg(test)]', 1)[0]
    ensure('!http_auth::valid_credential(secret)' in core
           and shared.count('http_wire::append_request(') == 1
           and '&secret.0,' in shared and 'Error::CredentialSource' in shared
           and 'request.extend_from_slice(&secret.0)' not in shared,
           'HTTP header may contain unvalidated OAuth/credential bytes')
    ensure(channel_encode.count('crate::provider_wire::append(') == 2
           and 'method: effect.method.as_bytes().to_vec()' in encoder
           and 'target: effect.target.as_bytes().to_vec()' in encoder
           and 'Some(bytes) => crate::provider_wire::append(output, route, parts.fields, secret, Some(&bytes))' in channel_encode
           and core.count('http_request::append_line(') == 1
           and 'ascii_equal(name, b"authorization")' in core
           and '!reserved_name(name)' in core and '!unique_before(headers, i, &headers[i].name)' in core
           and 'append_decimal(output, bytes.len());' in core,
           'origin-form request/header override or body-length restrictions removed')
    ensure('aivm_secrets_garrett_core::provider_status::manifest(status).map_err(status_error)?;' in source
           and 'if status == 206 {' in (root / CORE_STATUS).read_text()
           and 'return Err(StatusDenial::Partial);' in (root / CORE_STATUS).read_text(),
           'partial response is no longer refused')
    parser = source.split('fn manifest_response(', 1)[1].split('#[cfg(test)]', 1)[0]
    branch = parser.split('(None, None) if status == 204 => {', 1)
    ensure(len(branch) == 2
           and not any(effect in branch[1].split('}', 1)[0]
                       for effect in ('reader.', 'read_to_end(', 'fill_buf('))
           and '(None, None) => return Err(Error::UpstreamResponse)' in parser
           and 'headers.contains_key("content-length")' in parser
           and 'headers.contains_key("transfer-encoding")' in parser,
           'native HTTP parser accepts unframed success, framed 204, or waits for EOF after 204')
    release = entry.split('let release = |raw: Value| PendingCompletion {', 1)
    ensure(len(release) == 2, 'native read must have a typed public-release boundary')
    release[1] = release[1].split('let work = PendingRequest {', 1)[0]
    release[1] = ''.join(release[1].split())
    selector = (root / CORE_RELEASE).read_text()
    native_selector = source.split('struct ManifestCurrent', 1)[1].split('// Only external observations remain native;', 1)[0]
    ensure('selected_release::select(&mutselection)' in release[1]
           and 'audit:&self.base.executor.audit,' in release[1]
           and 'selected_release::Manifest{' in release[1]
           and 'document:&document,' in release[1]
           and 'fields:selection_fields,' in release[1]
           and all(marker in native_selector for marker in
                   ('fn current(', 'require_control_active(host_time()?)', 'fn refuse('))
           and 'fn pagination(' not in native_selector and 'fn project(' not in native_selector
           and all(marker in selector for marker in
                   ('work.current()?;', 'work.pagination()?;', 'work.project()?;',
                    'work.assemble(selected, metadata);', 'work.check_safe(reply)',
                    'metadata(self.document, page)',
                    'crate::disclosure::project_fields(self.document, fields, 9,',
                    'match checked(reply, self.secret) {',
                    'crate::json_reflection::safe(&reply, secret, 65)',
                    'crate::reflection::contains(&bytes, secret)')),
           'raw provider body may be returned without extracted selection/reflection checks')
    completed = source.split("struct PendingCompletion<'a, S>", 1)[1].split('struct PendingRequest<', 1)[0]
    ensure('self.audit.write_record(' in completed and '(self.fresh)()' in completed
           and 'completion::complete(pending, self.effects)' in request_core
           and 'let pending = self.work.complete(raw);' in request_core
           and 'fresh:&fresh,' in release[1]
           and 'write_gate::Gated::Ran(result)=>result.map(aivm_secrets_garrett_core::completion::Completed::into_value).map(|wire|json::Reply::Released(json::Captured::released(wire)))' in ''.join(entry.split()),
           'native success can reach guest without completion audit')
    return {'channels': len(channels), 'remaining': len(contract['remaining_obligations']),
            'status': 'review guard only; runtime/formal gates are separate'}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['check'])
    options = parser.parse_args()
    try:
        print(json.dumps(check(), sort_keys=True))
    except (ContractError, OSError, ValueError, KeyError) as exc:
        parser.exit(1, str(exc) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
