#!/usr/bin/env python3
"""Non-core development verifier for the production provider continuation.

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
    'aivm_secrets_garrett_core.manifest.StampProofs.current_success_iff',
    'aivm_secrets_garrett_core.manifest.StampProofs.denied_current_preserves_error',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.read_run_iff',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.returned_phase_is_input_phase',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.attempted_read_has_actual_current_origin',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.setup_failure_is_unsent',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.denied_current_is_unsent',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.read_send_failure_is_attempted',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.read_response_failure_is_attempted',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.completed_read_witness',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.read_stamp_cannot_authorize_writing_effect',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.writing_send_failure_is_uncertain',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.writing_response_failure_is_uncertain',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.new_send_state_is_empty',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.checking_is_required_to_record_stamp',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.empty_is_required_to_begin_check',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.successful_send_gate_iff',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.attempted_cannot_check_again',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.attempted_cannot_replace_stamp',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.attempted_cannot_send_again',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.halted_cannot_send',
    'aivm_secrets_garrett_core.provider_exchange.Proofs.attempted_retains_exact_stamp',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.issued_snapshot_is_accepted',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.related_trace_is_sound',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.related_trace_counts_attempts',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.read_driver_forward_simulation',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.extends_sound_observed_prefix',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.checked_send_state_records_one_attempt',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.repeated_send_preserves_record',
    'aivm_secrets_garrett_core.provider_exchange.Simulation.audited_read_driver_simulation',
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
        raise RuntimeError(f'incomplete provider theorem audit: {set(reported) ^ set(THEOREMS)}')
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
    lean_step.run([lake, 'build', '+GarrettProviderExchange', '+GarrettConfinement'],
                  directory, 'production provider and event-model dependencies')
    output = directory / '.lake/build/lib/lean/GarrettProviderSimulation.olean'
    lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', '-o', str(output),
                   'GarrettProviderSimulation.lean'], directory,
                  'conditional production provider forward simulation')
    with tempfile.TemporaryDirectory(prefix='provider-exchange-', dir=directory / '.lake') as scratch:
        check = Path(scratch) / 'Audit.lean'
        check.write_text('import GarrettProviderSimulation\n' + ''.join(
            f'#print axioms {name}\n' for name in THEOREMS))
        audit(lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', str(check)],
                            directory, 'named provider theorem axiom audit'))
    print(f'Kernel checked {len(THEOREMS)} provider/stamp/send-state obligations; '
          f'source regeneration {"omitted" if args.no_regenerate else "matched"}. '
          'Native primitive contracts, full request/history simulation and transitive I/O remain open.')


if __name__ == '__main__':
    main()
