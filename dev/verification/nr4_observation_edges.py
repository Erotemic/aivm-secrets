"""Opt-in source drift guard for the NR-4 native guest observation boundary.

Only checks that reviewed Rust code regions still contain an expected
sequence of anchors. It is NOT semantic extraction, transitive reachability,
noninterference, a whole-service sink inventory, or an operating-system/TLS
transport guarantee. Even code inserted between intact anchors can invalidate
an intended correspondence. The Lean contracts remain independent proof
obligations until the precise native adapter semantics are discharged.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TLS = 'rust/crates/aivm-secrets-garrett/src/tls.rs'
JSON_CORE = 'rust/crates/aivm-secrets-garrett-core/src/guest_frame.rs'
SESSION = 'rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs'


@dataclass(frozen=True)
class Edge:
    name: str
    file: str
    start: str
    stop: str
    anchors: tuple[str, ...]


EDGES = (
    Edge('bounded-error-taxonomy', TLS, 'fn failure(error: Error)', 'enum Backend', (
        'Error::InvalidCapability =>',
        'Error::InvalidRequest =>',
        'Error::Denied =>',
        'Error::UnsafeFile =>',
        'Error::OutcomeUnknown =>',
        '_ => "Broker failed closed."',
        '"code":error.code()',
    )),
    Edge('answer-conversion', TLS,
         'fn from_answer(answer: Outcome<Value>)',
         'fn send(&mut self, writer: &mut impl Write)', (
             'answer.unwrap_or_else(failure)',
             'json::capture(&value)',
             '.prepare(MAX_REPLY)',
         )),
    Edge('guest-frame-single-writer', TLS,
         'impl<W: Write> aivm_secrets_garrett_core::guest_frame::Writer',
         'impl GuestFrame {', (
             'fn write_frame(&mut self, wire: &[u8])',
             '.write_all(wire)',
             '.and_then(|_| self.0.flush())',
         )),
    Edge('guest-auth-before-public-framing', TLS,
         'fn serve<S: Read + Write>', 'fn answer(', (
             'ServerConnection::new(',
             'while connection.is_handshaking()',
             'VerifiedPeer::from_connection(&connection)',
             'let answer = match frame(',
             'json::parse(&raw, MAX_FRAME)',
             'self.answer(value, &peer, &now)',
             'GuestFrame::from_answer(answer)?.send(&mut stream)?',
             'stream.conn.send_close_notify()',
             'let _ = stream.flush()',
         )),
    Edge('bridge-auth-before-provider', TLS,
         'fn answer(', 'fn forward(', (
             'if verbs.len() != 1 || verbs[0] == "delegate"',
             'json::keys(&value, &[' ,
             'let token =',
             'self.registry.read()',
             'let admission =',
             'let now = clock()',
             'registry.expectation(',
             'if let Backend::Provider(provider)',
             'let mut provider = provider.lock()',
             'if verb == "request"',
             'provider.request(verifier, token, peer, expected, &m[verb], now)',
         )),
    Edge('socket-forwarding-uncertainty', TLS,
         'fn forward(&self, request:', '\n}\n\n#[cfg(test)]', (
             'files::broker_socket(broker)?',
             'UnixStream::connect(broker)',
             'let bytes = zeroize::Zeroizing::new(json::canonical(request))',
             '.write_all(&bytes)',
             'Error::OutcomeUnknown',
             'frame(&mut socket, MAX_REPLY)',
             'json::parse(&raw, MAX_REPLY)',
         )),
    Edge('core-frame-single-use', JSON_CORE,
         'pub struct Frame', '#[cfg(test)]', (
             'attempted: bool',
             'pub fn send',
             'if self.attempted',
             'self.attempted = true',
         )),
    Edge('manifest-completion-only-selected', SESSION,
         'pub(super) fn request(', 'pub(super) fn control(', (
             'guards::authorize(',
             'let current_context =',
             'let dispatch =',
             'let release =',
             'read_transition::run_current(pending)',
         )),
)


def scan(sources: dict[str, str]) -> list[str]:
    issues: list[str] = []
    for edge in EDGES:
        source = sources.get(edge.file, '')
        start = source.find(edge.start)
        stop = source.find(edge.stop, start + len(edge.start)) if start >= 0 else -1
        if start < 0 or stop < 0:
            issues.append(f'{edge.name}: cannot delimit reviewed {edge.file} region')
            continue
        region = source[start:stop]
        cursor = 0
        for anchor in edge.anchors:
            pos = region.find(anchor, cursor)
            if pos < 0:
                issues.append(f'{edge.name}: missing/out-of-order {anchor!r}')
                break
            cursor = pos + len(anchor)
    return issues


def read_sources(root: Path = ROOT) -> dict[str, str]:
    return {
        path: (root / path).read_text()
        for path in (TLS, JSON_CORE, SESSION)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check'])
    args = parser.parse_args()
    assert args.command == 'check'
    issues = scan(read_sources())
    if issues:
        print('\n'.join(issues))
        return 1
    print(f'NR-4 reviewed guest-observation anchors: {len(EDGES)} matched')
    print('Source-shape drift check ONLY: NOT a transitive Rust/TLS/OS or secrecy proof.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
