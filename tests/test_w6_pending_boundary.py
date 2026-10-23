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
    'unbound-provider', 'unbound-current', 'wrong-control-time', 'wrong-lease-time',
])
def test_pending_source_guard_rejects_unreviewed_boundary_mutation(tmp_path, mutation):
    from dev.verification.w6_pending_boundary import ROOT, RUST, SCOPE

    (tmp_path / RUST).parent.mkdir(parents=True)
    (tmp_path / SCOPE).parent.mkdir(parents=True)
    controller_path = 'rust/crates/aivm-secrets-garrett-core/src/request_adapter.rs'
    (tmp_path / controller_path).parent.mkdir(parents=True)
    controller = (ROOT / controller_path).read_text()
    admission_path = 'rust/crates/aivm-secrets-garrett-core/src/current_admission.rs'
    admission = (ROOT / admission_path).read_text()
    scope_path = 'rust/crates/aivm-secrets-garrett-core/src/request_context.rs'
    scope_source = (ROOT / scope_path).read_text()
    channel_path = 'rust/crates/aivm-secrets-garrett-core/src/channel_work.rs'
    (tmp_path / channel_path).write_text((ROOT / channel_path).read_text())
    source = (ROOT / RUST).read_text()
    scope = json.loads((ROOT / SCOPE).read_text())
    if mutation == 'no-fresh-before-emit':
        controller = controller.replace('dispatch::dispatch(', 'unchecked_dispatch(')
    elif mutation == 'skip-coordinate-check':
        admission = admission.replace('checks.coordination()', 'unchecked_coordination()')
    elif mutation == 'skip-active-check':
        source = source.replace('self.session.require_control_active(now)', 'Ok(())?;')
    elif mutation == 'skip-lease-check':
        source = source.replace('lease.require_current(current)?;', 'Ok(())?;')
    elif mutation == 'skip-current-token-check':
        admission = admission.replace('crate::present(', 'broken_gate(')
    elif mutation == 'skip-authorization':
        admission = admission.replace('manifest::current(', 'unchecked_authorize(')
    elif mutation == 'skip-audit-construction':
        source = source.replace('audit.write_record(', 'audit.unchecked_record(')
    elif mutation == 'skip-completion-audit':
        controller = controller.replace('completion::complete(', 'unchecked_completion(')
    elif mutation == 'unbound-provider':
        source = source.replace('request_context::ScopedRequest::new(', 'unchecked_provider(')
    elif mutation == 'unbound-current':
        admission = admission.replace('self.context.current(&mut self.checks)', 'self.work.recheck()')
    elif mutation == 'wrong-control-time':
        admission = admission.replace('checks.control(now)', 'checks.control(0)')
    elif mutation == 'wrong-lease-time':
        admission = admission.replace('checks.lease(now)', 'checks.lease(0)')
    elif mutation == 'scope-status-upgrade':
        scope['status'] = 'whole-service-formally-proved'
    elif mutation == 'scope-dropped-exclusion':
        scope['exclusions'].remove('sent-but-not-observed-TLS-application-data')
    (tmp_path / controller_path).write_text(controller)
    (tmp_path / admission_path).write_text(admission)
    (tmp_path / scope_path).write_text(scope_source)
    (tmp_path / RUST).write_text(source)
    (tmp_path / SCOPE).write_text(json.dumps(scope))
    with pytest.raises(ReviewError):
        check(tmp_path)
