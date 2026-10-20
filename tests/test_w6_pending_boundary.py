"""Fail-closed mutations for the reviewed, intentionally non-formal W6 source gate."""
from __future__ import annotations

import json

import pytest

from dev.verification.w6_pending_boundary import ReviewError, check


def test_pending_source_guard_accepts_reviewed_native_boundary():
    assert check()['profiles'] == 3


@pytest.mark.parametrize('mutation', [
    'no-fresh-before-emit', 'skip-coordinate-check',
    'skip-active-check', 'skip-lease-check',
    'skip-current-token-check', 'skip-authorization',
    'skip-audit-construction', 'skip-completion-audit',
    'scope-status-upgrade', 'scope-dropped-exclusion',
])
def test_pending_source_guard_rejects_unreviewed_boundary_mutation(tmp_path, mutation):
    from dev.verification.w6_pending_boundary import ROOT, RUST, SCOPE

    (tmp_path / RUST).parent.mkdir(parents=True)
    (tmp_path / SCOPE).parent.mkdir(parents=True)
    source = (ROOT / RUST).read_text()
    scope = json.loads((ROOT / SCOPE).read_text())
    if mutation == 'no-fresh-before-emit':
        source = source.replace('provider_exchange::exchange(\n            &mut provider,\n            &audited.transition,\n        )', 'unchecked_exchange(&mut provider)')
    elif mutation == 'skip-coordinate-check':
        source = source.replace('let current = || -> Outcome<guards::AdmissionStamp> {\n            self.base.check_coordination()?;',
                                'let current = || -> Outcome<guards::AdmissionStamp> {\n            // no late coordination check')
    elif mutation == 'skip-active-check':
        source = source.replace('self.require_control_active(current)?;', 'Ok(())?;')
    elif mutation == 'skip-lease-check':
        source = source.replace('lease.require_current(current)?;', 'Ok(())?;')
    elif mutation == 'skip-current-token-check':
        source = source.replace('aivm_secrets_garrett_core::present(', 'broken_gate(')
    elif mutation == 'skip-authorization':
        source = source.replace('guards::current(', 'unchecked_authorize(')
    elif mutation == 'skip-audit-construction':
        source = source.replace('let recorded = prepared.audit(', 'let recorded = prepared.unchecked(')
    elif mutation == 'skip-completion-audit':
        source = source.replace('complete_pending(',
                                'unchecked_completion(')
    elif mutation == 'scope-status-upgrade':
        scope['status'] = 'whole-service-formally-proved'
    elif mutation == 'scope-dropped-exclusion':
        scope['exclusions'].remove('sent-but-not-observed-TLS-application-data')
    (tmp_path / RUST).write_text(source)
    (tmp_path / SCOPE).write_text(json.dumps(scope))
    with pytest.raises(ReviewError):
        check(tmp_path)
