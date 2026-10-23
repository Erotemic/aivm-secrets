"""Opt-in, source-shape checks for the NR-2/NR-3 native adapter handoff.

This is deliberately NOT a call-graph completeness or semantic proof.  It
pins the source anchors that the Lean obligations refer to and fails if those
anchors change without review.  OS/TLS callbacks, macro expansion, dispatch,
Drop/unwind and feature reachability require independent evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs'
CUSTODY = 'rust/crates/aivm-secrets-garrett/src/custody.rs'
TLS = 'rust/crates/aivm-secrets-garrett/src/tls.rs'
CORE = 'rust/crates/aivm-secrets-garrett-core/src/provider_io.rs'
CORE_AUDIT = 'rust/crates/aivm-secrets-garrett-core/src/audit_record.rs'
CORE_RESPONSE = 'rust/crates/aivm-secrets-garrett-core/src/response_gate.rs'


@dataclass(frozen=True)
class Edge:
    file: str
    label: str
    start: str
    stop: str
    sequence: tuple[str, ...]


EDGES = (
    Edge(MANIFEST, 'request-authorization-before-controller',
         'pub(super) fn request(', 'pub(super) fn control(',
         ('guards::authorize(', 'let current_context =',
          'let dispatch =', 'let release =', 'let work = PendingRequest {',
          'request_adapter::Pending::new(work)', 'read_transition::run_current(pending)')),
    Edge(MANIFEST, 'manifest-wire-encoder-before-TLS',
         'fn setup_route(&mut self, route:', '\n}\nfn manifest_response(',
         ('manifest_request_bytes(route, self.secret, &self.effect, &self.headers)',
          'let request = ManifestWire(bytes)', 'TcpStream::connect_timeout(',
          'ClientConnection::new(', 'while conn.is_handshaking()',
          'StreamOwned::new(conn, socket)',
          'aivm_secrets_garrett_core::provider_io::Channel::new(',
          'ProviderWriter(stream)', 'deadline')),
    Edge(MANIFEST, 'provider-send-enters-extracted-channel',
         'fn send(&mut self, channel: &mut ManifestChannel)',
         'fn receive(&mut self, channel:',
         ('send_manifest_bytes(channel)',)),
    Edge(MANIFEST, 'native-send-helper-is-only-submit',
         'fn send_manifest_bytes<W: Write, M>', 'type ManifestChannel',
         ('channel.submit()',)),
    Edge(MANIFEST, 'writer-forwards-exact-byte-vector',
         'impl<W: Write> aivm_secrets_garrett_core::provider_io::Writer for ProviderWriter<W>',
         'fn send_manifest_bytes<W: Write, M>',
         ('fn write_all(&mut self, bytes: &Vec<u8>)',
          'self.0.write_all(bytes)', 'fn flush(&mut self)', 'self.0.flush()')),
    Edge(MANIFEST, 'native-receive-enters-extracted-response-gate',
         'fn receive(&mut self, channel: ManifestChannel)',
         '// The native parser consumes',
         ('let released = aivm_secrets_garrett_core::response_gate::receive(channel)?;',
          'let mut parser = ManifestResponse { effect: &self.effect };',
          'parser.parse(released)')),
    Edge(CORE_RESPONSE, 'extracted-response-gate-before-token-mint',
         'pub fn receive<B: WireBytes', '#[cfg(test)]',
         ('channel.into_parts()?;', 'Ok(Released {', 'writer,', 'request,', 'metadata,')),
    Edge(MANIFEST, 'native-parser-only-receives-released-parts',
         'struct ManifestResponse',
         'impl aivm_secrets_garrett_core::provider_io::RouteWork',
         ('fn parse(', 'response_gate::Released<',
          'released.into_parts()', 'manifest_response(BufReader::new(stream)',)),
    Edge(MANIFEST, 'audit-route-records-request-binding',
         'fn audit_route(&mut self, route:', 'fn setup_route(&mut self, route:',
         ('audit.write_record(&json!({', '"event":"dispatch"',
          '"phase":phase.as_str()', '"grant":audit.grant',
          '"identity":self.dispatch.identity',
          '"operation":self.dispatch.operation',
          '"request_digest":self.dispatch.request_digest',
          '"route":{')),
    Edge(CORE_AUDIT, 'fail-stop-audit-prepoison-and-sync',
         'pub fn append_durable_record<S: Sink>', '#[cfg(test)]',
         ('if *poisoned {', '*poisoned = true;', 'sink.append(bytes)?;',
          'let delimiter = record_delimiter();', 'sink.append(&delimiter)?;', 'sink.sync_record()?;',
          '*poisoned = false;', 'Ok(())')),
    Edge(CUSTODY, 'host-audit-requires-single-mutex-and-failed-state',
         'fn write_record(&self, value: &Value)', '// This private adapter alone',
         ('self.state.lock()', 'if state.failed {', 'json::canonical(value)',
          'let mut sink = AuditFile(file);',
          'aivm_secrets_garrett_core::audit_record::append_durable_record(&mut sink, failed, &bytes)')),
    Edge(TLS, 'guest-frame-from-actual-answer-and-error',
         'fn from_answer(answer: Outcome<Value>)',
         'fn send(&mut self, writer: &mut impl Write)',
         ('Ok(value) => json::capture(&value).prepare(MAX_REPLY)', 'Err(error) =>',
          'aivm_secrets_garrett_core::public_error::denial_frame(error.into(), MAX_REPLY)', '.map(Self)')),
    Edge(TLS, 'guest-writer-flush-follows-write',
         'impl<W: Write> aivm_secrets_garrett_core::guest_frame::Writer for GuestWriter',
         'impl GuestFrame {',
         ('fn write_frame(&mut self, wire: &[u8])', 'self.0',
          '.write_all(wire)', '.and_then(|_| self.0.flush())')),
    Edge(TLS, 'authenticated-bridge-writes-one-reviewed-frame',
         'fn serve<S: Read + Write>', 'fn answer(',
         ('ServerConnection::new(', 'VerifiedPeer::from_connection(&connection)',
          'let answer = match frame(', 'self.answer(value, &peer, &now)',
          'GuestFrame::from_answer(answer)?.send(&mut stream)?',
          'stream.conn.send_close_notify()', 'stream.flush()')),
    Edge(TLS, 'provider-backend-forwarding-under-lease',
         'fn answer(', 'fn forward(',
         ('self.registry.read()', 'let admission =',
          'registry.expectation(', 'if let Backend::Provider(provider)',
          'provider.lock()', 'provider.request(verifier, token, peer, expected, &m[verb], now)')),
    Edge(CORE, 'extracted-provider-channel-prevents-retry',
         'pub struct Request<B: WireBytes>', '/// Keep the captured request',
         ('attempted: bool', 'pub fn submit<W: Writer>',
          'if self.attempted {', 'self.attempted = true;',
          'self.body.bytes()', 'writer.write_all(bytes)', 'writer.flush()')),
    Edge(CORE, 'extracted-provider-channel-response-only-after-flush',
         'pub struct Channel<B: WireBytes, W: Writer, M>', '#[cfg(test)]',
         ('ready: bool', 'pub fn submit(&mut self)', 'self.ready = false;',
          'self.request.submit(&mut self.writer)', 'self.ready = true;',
          'pub fn into_parts(self)', 'if !self.ready {')),
)


def scan(sources: dict[str, str]) -> list[str]:
    """Return human-readable failures; no source mutation or subprocesses."""
    problems: list[str] = []
    for edge in EDGES:
        content = sources.get(edge.file, '')
        start = content.find(edge.start)
        stop = content.find(edge.stop, start + len(edge.start)) if start >= 0 else -1
        if start < 0 or stop < 0:
            problems.append(f'{edge.label}: cannot delimit reviewed {edge.file} region')
            continue
        region = content[start:stop]
        cursor = 0
        for anchor in edge.sequence:
            at = region.find(anchor, cursor)
            if at < 0:
                problems.append(f'{edge.label}: missing/out-of-order {anchor!r}')
                break
            cursor = at + len(anchor)
    return problems


def read_sources(root: Path = ROOT) -> dict[str, str]:
    return {name: (root / name).read_text() for name in (MANIFEST, CUSTODY, TLS, CORE, CORE_AUDIT, CORE_RESPONSE)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check'])
    args = parser.parse_args()
    assert args.command == 'check'
    problems = scan(read_sources())
    if problems:
        print('\n'.join(problems))
        return 1
    print(f'NR-2/NR-3 reviewed native adapter anchors: {len(EDGES)} matched')
    print('This is a source-shape check, NOT a transitive I/O/OS/TLS proof.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
