#!/usr/bin/env python3
"""Cheap reviewed-source check for audited-but-unsent native read behavior.

Only rejects selected source drifts. It is not a Rust CFG/dominance analysis,
compiler call-graph proof, concurrency proof or check of network causality.
The real Rust/mTLS experiments remain the acceptance witness for this scope.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCOPE = Path('docs/planning/aivm-secrets-read-pending-scope.json')
RUST = Path('rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs')
EXPECTED_PROFILES = {
    'final-audited-no-provider-send',
    'preflight-audited-no-provider-send',
    'preflight-sent-final-audited-unsent',
}
EXPECTED_DENIALS = {'revoked', 'unreachable', 'expired', 'invalid_capability'}
EXPECTED_OBSERVATIONS = {
    'exact-host-compiled-authorization-effect',
    'one-audit-row-per-audited-phase',
    'at-most-one-unsent-terminal-dispatch',
    'causal-audit-at-each-actual-provider-arrival',
    'zero-credentialed-requests-for-unsent-tail',
    'same-bound-client-grant-policy-and-request-digest',
    'no-guest-completion-or-selected-result',
    'exact-fixed-public-error-and-canonical-one-frame',
    'no-private-data-in-audit-or-guest-output',
}
EXPECTED_EXCLUSIONS = {
    'pre-audit-authorization-denials',
    'writes-and-coordinator-reservations',
    'concurrent-dispatches-and-provider-retries',
    'sent-but-not-observed-TLS-application-data',
    'authorization-atomic-with-network-syscall',
    'wall-clock-timing-packet-size-and-EOF-side-channels',
    'all-native-executions-and-Rust-to-Lean-refinement',
    'complete-call-graph-and-dependency-reachability',
}


class ReviewError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewError(message)


def check(root: Path = ROOT) -> dict:
    manifest = json.loads((root / SCOPE).read_text())
    require(manifest.get('schema') == 1 and
            manifest.get('scope') == 'native-manifest-read-audited-unsent-prefix-v1' and
            manifest.get('status') == 'portable-validated-native-pending',
            'pending-read assurance status or scope silently changed')
    for key, expected in (
        ('profiles', EXPECTED_PROFILES),
        ('public_denials', EXPECTED_DENIALS),
        ('observations', EXPECTED_OBSERVATIONS),
        ('exclusions', EXPECTED_EXCLUSIONS),
    ):
        require(set(manifest.get(key, [])) == expected,
                f'pending-read {key} contract changed without review')
    source = (root / RUST).read_text()
    request = source.split('    pub(super) fn request(', 1)[1].split('\n    pub(super) fn control(', 1)[0]
    exchange = source.split('    fn exchange_manifest(', 1)[1].split('\nfn manifest_response(', 1)[0]
    audited = request.find('let recorded = prepared.audit(')
    executor = request.find('self.base.executor.exchange_manifest(')
    require(audited != -1 and executor > audited,
            'native manifest might execute a provider effect before dispatch audit')
    require('let dispatch = |prepared: PreparedDispatch' in request and
            'dispatch(PreparedDispatch::preflight(&effect)?)?' in request and
            'dispatch(PreparedDispatch::final_effect(&effect, op.write)?)?' in request,
            'manifest preflight/final no longer share the audited dispatcher')
    fresh = request.split('let fresh = || -> Outcome<()> {', 1)[-1].split('let canonical_request', 1)[0]
    for checked in ('self.base.check_coordination()?;',
                    'self.require_control_active(current)?;',
                    'lease.require_current(current)?;',
                    'aivm_secrets_garrett_core::present(',
                    'guards::authorize('):
        require(checked in fresh, f'last-admission closure dropped {checked}')
    require('let mut stream = StreamOwned::new(conn, socket);' in exchange and
            'let exchange = || -> Outcome<Value> {' in exchange and
            '.write_all(&request)' in exchange and
            'emit_current(fresh, || {' in exchange,
            'native provider may emit credentialed bytes without the last-admission gate')
    require('fn after_completion(' in source and
            'CompletedRelease::after_completion(' in request,
            'guest completion no longer requires the host audit boundary')
    return {'scope': manifest['scope'], 'profiles': len(EXPECTED_PROFILES),
            'excluded': len(EXPECTED_EXCLUSIONS),
            'status': 'source-shape guard, not a verified native control-flow proof'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('check',), default='check')
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(check(args.root), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except ReviewError as error:
        raise SystemExit(f'W6 pending boundary: {error}') from error
