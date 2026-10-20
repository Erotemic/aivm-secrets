#!/usr/bin/env python3
"""Kernel-check preservation of the production-called Rust read dispatch seam.

By default, regenerate the core with pinned Charon/Aeneas and compare the
entire generated module before compiling the proof. --no-regenerate is useful
while editing the Lean proof, but does not establish fresh source linkage.
This is NR-1 dispatch preservation, not complete request/I/O simulation.
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
    'prepare_success_iff', 'acknowledge_success_iff',
    'prepared_to_audited_preservation', 'refused_audit_has_no_permit',
    'preflight_write_has_no_prepared', 'unadmitted_final_write_has_no_prepared',
    'authorized_read_witness',
    'denied_before_completion', 'completion_audit_refusal',
    'revoked_after_completion_audit', 'current_completion_continuation',
    'completion_preservation', 'authorized_completion_witness',
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
                  'production dispatch preservation')
    # Keep the axiom report separate from the proof source and normal compiler
    # output. A successful import alone cannot replace the named axiom audit.
    with tempfile.TemporaryDirectory(prefix='read-transition-', dir=directory / '.lake') as scratch:
        check = Path(scratch) / 'Audit.lean'
        check.write_text('import GarrettReadTransition\n' + ''.join(
            f'#print axioms {NAMESPACE}{name}\n' for name in THEOREMS))
        audit(lean_step.run([lake, 'env', 'lean', '-DwarningAsError=true', str(check)],
                            directory, 'named theorem axiom audit'))
    print(f'Kernel checked {len(THEOREMS)} extracted dispatch obligations; '
          f'source regeneration {"omitted" if args.no_regenerate else "matched"}. '
          'Audit durability, adapter correspondence and native I/O simulation remain open.')


if __name__ == '__main__':
    main()
