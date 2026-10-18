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
    request = source.index('        let request = manifest_request_bytes(route, secret, effect, headers)?;')
    connect = source.index('TcpStream::connect_timeout(')
    ensure(request < connect, 'TCP effect before request-byte validation')
    ensure(source.count('fn manifest_request_bytes(') == 1
           and source.count('let request = manifest_request_bytes(route, secret, effect, headers)?;') == 1,
           'native manifest adapter has additional unreviewed encoder')
    provider_interpreter = source.split('impl Executor {', 1)[1].split('fn manifest_response(', 1)[0]
    ensure(provider_interpreter.count('.write_all(') == 1
           and provider_interpreter.count('.write_all(&request)') == 1
           and provider_interpreter.count('TcpStream::connect_timeout(') == 1,
           'native manifest adapter has another provider send')
    encoder = source.split('fn manifest_request_bytes(', 1)[1].split('impl Executor {', 1)[0]
    ensure('!http_auth::valid_credential(&secret.0)' in encoder
           and encoder.count('http_auth::append_header(&mut request, &secret.0, &route.authentication)') == 1
           and 'request.extend_from_slice(&secret.0)' not in encoder
           and 'Error::CredentialSource' in encoder,
           'HTTP header may contain unvalidated OAuth/credential bytes')
    ensure('effect.target.starts_with("//")' in encoder and '"authorization"' in encoder,
           'origin-form request/header override restrictions removed')
    ensure('if status == 206 {' in source, 'partial response is no longer refused')
    ensure('self.disclosure.project(&op.name, &raw, &secret.0)?' in source
           and 'ensure_safe(&reply, &secret.0)?' in source,
           'raw provider body may be returned without projection')
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
