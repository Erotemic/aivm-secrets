#!/usr/bin/env python3
"""Portable reviewed-source guard for the native W6 public-error leaf.

This checks a concrete source shape, not execution, compiler reachability,
Rust/Lean refinement, or independently verified error mapping. Its purpose is
to fail early if the bounded native error/guest-frame boundary changes without
an explicit review and matching regression updates.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path('docs/planning/aivm-secrets-read-failure-scope.json')
TLS = Path('rust/crates/aivm-secrets-garrett/src/tls.rs')
ERROR = Path('rust/crates/aivm-secrets-garrett/src/lib.rs')
MANIFEST_SESSION = Path('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs')
CLASSES = {
    'http-4xx': 'upstream_rejected',
    'http-other': 'upstream_error',
    'bad-representation': 'upstream_response',
    'disclosure-veto': 'upstream_response',
}
PATHS = {'final', 'preflight', 'preflight-final'}
OBSERVATIONS = {
    'audit-dispatch-before-provider-arrival',
    'no-completion-audit-on-failure',
    'exact-provider-headers-and-target',
    'closed-host-audit-schema-and-identity-consistency',
    'host-normalized-request-digest',
    'fixed-public-error-with-no-result-or-metadata',
    'canonical-single-guest-jsonl-frame',
    'paired-private-diagnostics-invisible',
}
EXCLUSIONS = {
    'pre-egress-and-post-audit-no-send-failures',
    'fresh-lease-and-revocation-races',
    'write-uncertainty-and-coordinator-retries',
    'transport-EOF-timing-and-side-channels',
    'all-arbitrary-HTTP-responses-and-program-executions',
    'full-native-to-Lean-simulation',
    'complete-compiler-I/O-reachability',
}


class ReviewError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewError(message)


def check(root: Path = ROOT) -> dict:
    manifest = json.loads((root / MANIFEST).read_text())
    require(manifest['schema'] == 1 and
            manifest['scope'] == 'native-manifest-read-failure-observations-v1',
            'unreviewed failure oracle scope')
    require(manifest['status'] == 'portable-validated-native-pending',
            'failure observability scope misstates native evidence')
    require(set(manifest['paths']) == PATHS and
            manifest['declassified_classes'] == CLASSES,
            'failure observation/declassification contract changed')
    require(set(manifest['expected_observations']) == OBSERVATIONS,
            'reviewed failure observation set changed')
    require(set(manifest['excluded']) == EXCLUSIONS,
            'failure observation scope silently dropped an open obligation')

    tls = (root / TLS).read_text()
    error = (root / ERROR).read_text()
    session = (root / MANIFEST_SESSION).read_text()
    require('fn failure(error: Error) -> Value {' in tls and '\nenum Backend' in tls,
            'fixed public denial function changed')
    body = tls.split('fn failure(error: Error) -> Value {', 1)[1].split('\nenum Backend', 1)[0]
    require('match error {' in body and '_ => "Broker failed closed."' in body,
            'guest denial fallback is not fixed')
    require('json!({"version":1,"ok":false,"error":{"code":error.code(),"message":message}})' in body,
            'guest denial schema no longer consists of fixed code/message')
    require('format!(' not in body and 'to_string(' not in body,
            'guest failure message may include nonfixed diagnostics')
    require('let value = answer.unwrap_or_else(failure);' in tls
            and 'guest_frame::prepare(json::canonical(&value), MAX_REPLY)' in tls
            and 'self.0.send(&mut GuestWriter(writer))' in tls
            and 'write_all(wire)' in tls and 'self.0.flush()' in tls,
            'guest reply bypasses the canonical bounded single-attempt writer')
    for variant, code in [
        ('UpstreamRejected', 'upstream_rejected'),
        ('UpstreamError', 'upstream_error'),
        ('UpstreamResponse', 'upstream_response'),
    ]:
        require(f'Self::{variant} => "{code}"' in error,
                f'{variant} public error code changed')
    require('if (400..500).contains(&status) {' in session and
            'return Err(Error::UpstreamRejected);' in session and
            'if !(200..300).contains(&status) {' in session and
            'return Err(Error::UpstreamError);' in session,
            'upstream status declassification branch changed')
    return {
        'profile': manifest['scope'],
        'paths': len(PATHS),
        'public_classes': len(CLASSES),
        'excluded': len(EXCLUSIONS),
        'status': 'review guard only; native/Lean correspondence unproved',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['check'], default='check')
    parser.parse_args()
    print(json.dumps(check(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
