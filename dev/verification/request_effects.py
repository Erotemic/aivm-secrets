#!/usr/bin/env python3
"""Non-core development verifier for the production request-wide receipt.

Default: exact pinned regeneration, focused Lean compilation and named axiom
audit. --no-regenerate is for proof iteration only. Native primitive/world
contracts and whole-service I/O correspondence remain separate obligations.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import tempfile

import freshness
import garrett
import lean_step

THEOREMS = (
    'aivm_secrets_garrett_core.request_effects.Proofs.audited_unsent_cannot_complete',
    'aivm_secrets_garrett_core.request_effects.Proofs.attempted_cannot_submit_again',
    'aivm_secrets_garrett_core.request_effects.Proofs.completion_ack_is_not_return_permission',
    'aivm_secrets_garrett_core.request_effects.Proofs.initial_is_sound',
    'aivm_secrets_garrett_core.request_effects.Proofs.begin_dispatch_audit_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.acknowledge_dispatch_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.begin_provider_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.provider_completed_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.finish_dispatch_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.begin_completion_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.selected_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.begin_completion_check_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.finish_completion_check_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.begin_completion_audit_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.acknowledge_completion_audit_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.value_ready_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.begin_send_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.step_preserves',
    'aivm_secrets_garrett_core.request_effects.Proofs.steps_preserve',
    'aivm_secrets_garrett_core.request_effects.Proofs.reachable_is_sound',
    'aivm_secrets_garrett_core.request_effects.Proofs.provider_attempt_requires_audit_and_stamp',
    'aivm_secrets_garrett_core.request_effects.Proofs.can_return_value_iff',
    'aivm_secrets_garrett_core.request_effects.Proofs.completed_value_requires_selection_checks_and_audit',
    'aivm_secrets_garrett_core.request_effects.Proofs.late_denial_retains_ack_with_no_return',
    'aivm_secrets_garrett_core.request_effects.Proofs.rejected_call_closes_return_gate',
    'aivm_secrets_garrett_core.request_effects.Simulation.facts_callback_steps',
    'aivm_secrets_garrett_core.request_effects.Simulation.finishing_callback_steps',
    'aivm_secrets_garrett_core.request_effects.Simulation.request_forward_simulation',
    'aivm_secrets_garrett_core.request_effects.Simulation.successful_entry_has_completed_receipt',
)


def audit(output: str) -> None:
    reported = {
        name: {item.strip() for item in axioms.split(',') if item.strip()}
        for name, axioms in re.findall(
            r"'([^']+)' depends on axioms:\s*\[([^\]]*)\]", output)
    }
    for name in re.findall(r"'([^']+)' does not depend on any axioms", output):
        reported[name] = set()
    if set(reported) != set(THEOREMS):
        raise RuntimeError(f'incomplete request-effect theorem audit: {set(reported) ^ set(THEOREMS)}')
    for name, axioms in reported.items():
        if axioms - freshness.ALLOWED_AXIOMS:
            raise RuntimeError(f'{name}: unreviewed axioms {axioms}')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-regenerate', action='store_true')
    args = parser.parse_args()
    if not args.no_regenerate:
        freshness.check_hashes(json.loads(freshness.MANIFEST.read_text()))
        garrett.regeneration()
    directory = freshness.PROOFS
    lake = freshness.executable('lake')
    lean_step.run([lake, 'build', '+GarrettReadInvocations', '+GarrettRequestEffects'],
                  directory, 'actual stateful request and receipt dependencies')
    output = directory / '.lake/build/lib/lean/GarrettRequestSimulation.olean'
    lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', '-o', str(output),
                   'GarrettRequestSimulation.lean'], directory,
                  'conditional actual-request receipt simulation')
    with tempfile.TemporaryDirectory(prefix='request-effects-', dir=directory / '.lake') as scratch:
        check = Path(scratch) / 'Audit.lean'
        check.write_text('import GarrettRequestSimulation\n' + ''.join(
            f'#print axioms {name}\n' for name in THEOREMS))
        audit(lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', str(check)],
                            directory, 'named request-effect theorem axiom audit'))
    print(f'Kernel checked {len(THEOREMS)} request-wide gate/simulation obligations; '
          f'source regeneration {"omitted" if args.no_regenerate else "matched"}. '
          'Native callback contracts, W4/W5 event/history correspondence and transitive I/O remain open.')


if __name__ == '__main__':
    main()
