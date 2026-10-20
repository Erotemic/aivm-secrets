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
CORE_ENCODER = 'rust/crates/aivm-secrets-garrett-core/src/http_wire.rs'
CORE_DISPATCH = 'rust/crates/aivm-secrets-garrett-core/src/dispatch.rs'
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
    request = source.index('        let request = manifest_request_bytes(self.route, self.secret, self.effect, &self.headers)?;')
    connect = source.index('TcpStream::connect_timeout(')
    ensure(request < connect, 'TCP effect before request-byte validation')
    ensure(source.count('fn manifest_request_bytes(') == 1
           and source.count('let request = manifest_request_bytes(self.route, self.secret, self.effect, &self.headers)?;') == 1,
           'native manifest adapter has additional unreviewed encoder')
    # The real credential-bearing executor only accepts the type constructed
    # after durable audit. This checks the reviewed source topology; it cannot
    # prove what a compiler or an external dependency ultimately executes.
    constructor = source.split("impl<'a> PreparedDispatch<'a> {", 1)[1].split('pub(crate) struct Session {', 1)[0]
    entry = source.split('pub(super) fn request(', 1)[1].split('pub(super) fn control(', 1)[0]
    dispatch_core = (root / CORE_DISPATCH).read_text().split('#[cfg(test)]', 1)[0]
    ensure('transition: Outcome<read_transition::Prepared>' in source
           and 'read_transition::prepare(DispatchPhase::Preflight, false, effect.write)' in constructor
           and 'read_transition::prepare(DispatchPhase::Final,admitted_write,effect.write,)' in ''.join(constructor.split())
           and 'dispatch::dispatch(' in entry and '*effects.borrow_mut() = report.effects;' in entry
           and 'pending.work.audit(prepared.phase())' in dispatch_core
           and 'read_transition::acknowledge(prepared, true)' in dispatch_core
           and dispatch_core.index('pending.work.audit(prepared.phase())') < dispatch_core.index('read_transition::acknowledge(prepared, true)'),
           'provider effect not typed as audited/phase-authorized before dispatch')
    ensure('audited: &read_transition::Audited' in dispatch_core
           and 'audited.is_write() != pending.work.effect_write()' in dispatch_core
           and 'begin_provider(audited)' in dispatch_core,
           'provider executor accepts an unaudited policy effect')
    runtime = source.split('#[cfg(test)]', 1)[0]
    ensure(runtime.count('.write_all(') == 1 and 'writer.write_all(request)' in ''.join(runtime.split())
           and 'provider_exchange::exchange(pending, audited)' in dispatch_core
           and 'self.work.send(channel)' in dispatch_core and '.begin_send(self.phase, &mut self.local, self.write)' in dispatch_core
           and runtime.count('TcpStream::connect_timeout(') == 1,
           'native manifest adapter has another provider send')
    encoder = source.split('fn manifest_request_bytes(', 1)[1].split('// The standard Write contract', 1)[0]
    shared = (root / COMMON_ENCODER).read_text().split('fn provider_request_bytes(', 1)[1].split('fn account_request_bytes(', 1)[0]
    core = (root / CORE_ENCODER).read_text().split('#[cfg(test)]', 1)[0]
    ensure('!http_auth::valid_credential(secret)' in core
           and shared.count('http_wire::append_request(') == 1
           and '&secret.0,' in shared and 'Error::CredentialSource' in shared
           and 'request.extend_from_slice(&secret.0)' not in shared,
           'HTTP header may contain unvalidated OAuth/credential bytes')
    ensure(encoder.count('provider_request_bytes(') == 1
           and 'method: effect.method.as_bytes().to_vec()' in encoder
           and 'target: effect.target.as_bytes().to_vec()' in encoder
           and 'body.as_ref().map(|v| v.as_slice())' in encoder
           and core.count('http_request::append_line(') == 1
           and 'ascii_equal(name, b"authorization")' in core
           and '!reserved_name(name)' in core and '!unique_before(headers, i, &headers[i].name)' in core
           and 'append_decimal(output, bytes.len());' in core,
           'origin-form request/header override or body-length restrictions removed')
    ensure('if status == 206 {' in source, 'partial response is no longer refused')
    parser = source.split('fn manifest_response(', 1)[1].split('#[cfg(test)]', 1)[0]
    branch = parser.split('(None, None) if status == 204 => {', 1)
    ensure(len(branch) == 2
           and not any(effect in branch[1].split('}', 1)[0]
                       for effect in ('reader.', 'read_to_end(', 'fill_buf('))
           and '(None, None) => return Err(Error::UpstreamResponse)' in parser
           and 'headers.contains_key("content-length")' in parser
           and 'headers.contains_key("transfer-encoding")' in parser,
           'native HTTP parser accepts unframed success, framed 204, or waits for EOF after 204')
    release = entry.split('let release = |raw: Value| -> Outcome<CompletedRelease> {', 1)
    ensure(len(release) == 2, 'native read must have a typed public-release boundary')
    release[1] = release[1].split('let pending = PendingRequest {', 1)[0]
    selected = 'self.disclosure.project(&op.name, &raw, &secret.0)?'
    checked = 'ensure_safe(&reply, &secret.0)?'
    finished = 'complete_pending('
    ensure(all(marker in release[1] for marker in (selected, checked, finished)) and
           release[1].index(selected) < release[1].index(checked) <
           release[1].index(finished),
           'raw provider body may be returned without selected/reflection-checked release')
    completed = source.split('struct CompletedRelease(Value);', 1)
    ensure(len(completed) == 2 and
           'audit.write_record(' in completed[1].split('pub(crate) struct Session {', 1)[0] and
           completed[1].split('pub(crate) struct Session {', 1)[0].index('audit.write_record(') <
               completed[1].split('pub(crate) struct Session {', 1)[0].index('CompletedRelease(completed.into_value())') and
           'completion::complete(pending, before)' in completed[1] and
           '*effects.borrow_mut() = report.effects;' in completed[1] and
           'fresh: &fresh,' in release[1] and '(self.fresh)()' in completed[1] and
           'read_transition::run_current(pending).map(CompletedRelease::into_public)' in entry,
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
