#!/usr/bin/env python3
"""Kernel-check the production-called Rust dispatch/completion/request decisions.

By default, regenerate the core with pinned Charon/Aeneas and compare the
entire generated module before compiling the proof. --no-regenerate is useful
while editing the Lean proof, but does not establish fresh source linkage.
Checks decisions, data flow, mutable invocation receipts and the consuming
entry gate. Raw callback/native I/O simulation remains a separate obligation.
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

NAMESPACE = 'aivm_secrets_garrett_core.read_transition.Proofs.'
THEOREMS = (
    'request_facts_returned_iff',
    'finish_request_returned_iff',
    'request_current_returned_iff',
    'run_current_returned_iff',
    'prepare_success_iff', 'acknowledge_success_iff',
    'prepared_to_audited_preservation', 'refused_audit_has_no_permit',
    'preflight_write_has_no_prepared', 'unadmitted_final_write_has_no_prepared',
    'authorized_read_witness',
    'denied_before_completion', 'completion_audit_refusal',
    'revoked_after_completion_audit', 'current_completion_continuation',
    'completion_preservation', 'authorized_completion_witness',
    'request_facts_success_iff', 'finish_request_success_iff', 'request_current_success_iff',
    'failed_preflight_compilation_stops', 'failed_preflight_provider_stops',
    'failed_final_compilation_stops', 'stale_after_preflight_stops',
    'final_provider_failure_stops_completion', 'final_read_continuation',
    'checked_only_continuation', 'sent_write_completion_failure_is_uncertain',
    'two_phase_read_successful_witness',
    'constructor_starts_empty',
    'run_current_success_iff',
    'successful_request_receipt',
    'finished_dispatch_is_rejected',
    'invalid_progress_rejects_saved_success',
    'ignored_extra_dispatch_rejects_saved_reply',
    'halted_dispatch_is_rejected',
    'unfinished_value_is_not_public',
)


def audit(output: str) -> None:
    reported = {
        name: {item.strip() for item in axioms.split(',') if item.strip()}
        for name, axioms in re.findall(
            r"'([^']+)' depends on axioms:\s*\[([^\]]*)\]", output)
    }
    for name in re.findall(r"'([^']+)' does not depend on any axioms", output):
        reported[name] = set()
    expected = {NAMESPACE + name for name in THEOREMS}
    if set(reported) != expected:
        raise RuntimeError(f'incomplete theorem audit: {set(reported) ^ expected}')
    for name, axioms in reported.items():
        if axioms - freshness.ALLOWED_AXIOMS:
            raise RuntimeError(f'{name}: unreviewed axioms {axioms}')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-regenerate', action='store_true')
    parser.add_argument('--audit-axioms', action='store_true',
                        help='Explicit end-of-formalization axiom dependency review')
    args = parser.parse_args()
    if not args.no_regenerate:
        freshness.check_hashes(json.loads(freshness.MANIFEST.read_text()))
        garrett.regeneration()
    directory = freshness.PROOFS
    lake = freshness.executable('lake')
    lean_step.run([lake, 'build', '+AivmSecretsGarrettCore', '+GarrettFoundation'], directory,
                  'extracted Rust import')
    output = directory / '.lake/build/lib/lean/GarrettReadTransition.olean'
    lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', '-o', str(output),
                   'GarrettReadTransition.lean'], directory,
                  'production transition and orchestration preservation')
    output = directory / '.lake/build/lib/lean/GarrettReadInvocations.olean'
    lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', '-o', str(output),
                   'GarrettReadInvocations.lean'], directory,
                  'stateful production invocation and consuming reply gate')
    # Keep the axiom report separate from the proof source and normal compiler
    # output. A successful import alone cannot replace the named axiom audit.
    if args.audit_axioms:
        with tempfile.TemporaryDirectory(prefix='read-transition-', dir=directory / '.lake') as scratch:
            check = Path(scratch) / 'Audit.lean'
            check.write_text('import GarrettReadInvocations\n' + ''.join(
                f'#print axioms {NAMESPACE}{name}\n' for name in THEOREMS))
            audit(lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', str(check)],
                                directory, 'named theorem axiom audit'))
    print(f'Kernel checked {len(THEOREMS)} extracted transition obligations; '
          f'source regeneration {"omitted" if args.no_regenerate else "matched"}. '
          'Audit durability, adapter correspondence and native I/O simulation remain open.')


if __name__ == '__main__':
    main()
