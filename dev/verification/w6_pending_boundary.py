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
    controller = (root / 'rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs').read_text().split('#[cfg(test)]', 1)[0]
    require('request_adapter::Pending::new(work)' in request
            and 'dispatch::dispatch(plan.work, Ok(prepared), self.effects, plan.keyed_write)' in controller
            and controller.count('self.effects = report.effects;') == 2
            and 'audit.write_record(' in source and 'phase.as_str()' in source,
            'native manifest might execute a provider effect before dispatch audit')
    require('let dispatch = |phase: DispatchPhase, effect: Effect|' in request
            and 'request_adapter::DispatchPlan { work, keyed_write }' in request
            and 'operation_write: op.write,' in request,
            'manifest preflight/final no longer share the audited dispatcher')
    fresh = request.split('let current_peer =', 1)[-1].split('let canonical_request', 1)[0]
    native_checks = source.split("struct CurrentChecks<'a, L>", 1)[1].split('pub(crate) struct Session {', 1)[0]
    admission = (root / 'rust/crates/aivm-secrets-garrett-core/src/current_admission.rs').read_text().split('#[cfg(test)]', 1)[0]
    for checked in ('checks.coordination()', 'checks.clock()', 'checks.control(now)', 'checks.lease(now)',
                    'crate::present(self.identity, self.expected, self.peer, now)', 'checks.elapsed()', 'manifest::current('):
        require(checked in admission, f'last-admission closure dropped {checked}')
    require('self.session.base.check_coordination()' in native_checks
            and 'self.session.require_control_active(now)' in native_checks
            and 'host_time()' in native_checks and 'self.session.base.elapsed()' in native_checks
            and '(self.lease)(now)' in native_checks
            and 'lease.require_current(current)?;' in fresh
            and 'current_context.current(&mut CurrentChecks' in fresh,
            'last-admission primitives detached from host state')
    scope = (root / 'rust/crates/aivm-secrets-garrett-core/src/request_context.rs').read_text().split('#[cfg(test)]', 1)[0]
    primitive = source.split('fn send_manifest_bytes(', 1)[1].split('struct ManifestChannel {', 1)[0]
    require('let stream = StreamOwned::new(conn, socket);' in source and
            'writer.write_all(request)' in ''.join(primitive.split()) and
            'send_manifest_bytes(&mutchannel.stream,&channel.request)' in ''.join(source.split()) and
            'aivm_secrets_garrett_core::dispatch::WorkforManifestProvider' in ''.join(source.split()) and
            'fn recheck(&mut self) -> Outcome<guards::AdmissionStamp>' in source and
            'request_context::ScopedRequest::new(' in request
            and 'current_admission::Bound::new(self.context, plan.work, checks)' in scope
            and 'self.factory.checks()' in scope and 'self.context.current(&mut self.checks)' in admission and
            'let fresh = || current().map(|_| ());' in fresh,
            'native provider may emit credentialed bytes without the last-admission gate')
    require('aivm_secrets_garrett_core::completion::Work' in source
            and 'completion::complete(pending, self.effects)' in controller
            and 'self.audit.write_record(' in source
            and 'let release = |raw: Value| PendingCompletion {' in request,
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
