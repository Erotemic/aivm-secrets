#!/usr/bin/env python3
"""Guard and (optionally) kernel-check the scoped W5 two-run Lean model.

`check` validates the reviewed proof/assumption inventory only. `prove`
compiles the W4 dependency and W5 module with Lean, printing diagnostics on
failure instead of a theorem-by-theorem axiom report. Neither action claims
concrete TLS/HTTP/serialization or VM information-flow refinement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = 'docs/planning/aivm-secrets-w5-proof-scope.json'
W4_SPEC = 'docs/planning/aivm-secrets-w4-proof-scope.json'
W4 = 'proofs/GarrettConfinement.lean'
PROOF = 'proofs/GarrettNoninterference.lean'
EXPECTED_RELEASES = {
    'preAdmission', 'finalAdmission', 'preAudit', 'finalAudit',
    'preflightResult', 'providerResult', 'completedAudit', 'schema',
    'fuel', 'budget', 'projected', 'reflectionStatus', 'metadata',
}
EXPECTED_EXCLUSIONS = {
    'wall_clock_and_microarchitectural_timing',
    'concrete_transport_bytes_and_error_codes',
    'other_execution_profiles',
    'unmodeled_private_observers',
}
REQUIRED_LINKS = [
    'import GarrettConfinement',
    'observeTrace (caseTrace r)',
    'requestTrace r.pre r.final',
    'disclosure.Proofs.ProjectionAgreement',
    'disclosure.Proofs.recursive_projection_noninterference',
    'a.pre.accepted <-> b.pre.accepted',
    'a.final.accepted <-> b.final.accepted',
    'reflectionStatus : a.reflectionBlocked = b.reflectionBlocked',
    'metadata : a.metadata = b.metadata',
    'step_preserves : forall a b request',
    'history ++ [observed result.1]',
    'literal_reflection_is_observable',
    'metadata_difference_is_observable',
    'allowed_request_witness',
    'denied_request_witness',
]


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root: Path = ROOT) -> dict:
    spec = json.loads((root / SPEC).read_text())
    w4 = json.loads((root / W4_SPEC).read_text())
    require(spec.get('schema') == 1, 'invalid W5 manifest schema')
    require(spec.get('scope') == 'adaptive-modeled-guest-observations-v1',
            'W5 proof scope changed')
    require(spec.get('status') == 'local-kernel-checked-refinement-open',
            'W5 claim status changed without review')
    require(set(spec.get('explicit_release_premises', [])) == EXPECTED_RELEASES,
            'W5 release classification changed without review')
    require(set(spec.get('excluded_properties', [])) == EXPECTED_EXCLUSIONS,
            'W5 exclusions changed without review')
    require(spec.get('w4_proof_sha256') == digest(root / W4),
            'W4 source changed since W5 review')
    require(w4.get('proof_sha256') == digest(root / W4),
            'W4 proof differs from its reviewed fingerprint')
    require(spec.get('generated_sha256') == digest(root / 'proofs/generated/AivmSecretsGarrettCore.lean'),
            'extracted source changed since W5 review')
    require(spec.get('proof_sha256') == digest(root / PROOF),
            'W5 proof changed without review')
    proof = (root / PROOF).read_text()
    for forbidden in (r'(?m)^\s*axiom\b', r'(?m)^\s*constant\b'):
        require(re.search(forbidden, proof) is None,
                f'W5 proof has an unsupported escape: {forbidden}')
    require(re.search(r'/--(?:(?!-/)[\s\S])*-/\s*#(?:check|print|eval)\b', proof) is None,
            'Lean doc comment cannot attach to a command')
    for marker in REQUIRED_LINKS:
        require(marker in proof, f'missing W5 reviewed binding: {marker}')
    names = spec.get('theorems')
    require(isinstance(names, list) and len(names) >= 10 and len(set(names)) == len(names),
            'missing or duplicate W5 theorem names')
    declared = set(re.findall(r'(?m)^theorem ([a-zA-Z0-9_]+)\b', proof))
    require(declared == set(names),
            f'unreviewed W5 theorem changes: {declared ^ set(names)}')
    return {'scope': spec['scope'], 'theorems': len(names),
            'status': 'structure only; run `prove` for kernel checking'}


def _run_lean(cmd: list[str], cwd: Path, label: str) -> None:
    """Show diagnostics on failure; successful imported proof logs are noise."""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='')
        raise ContractError(f'{label} failed')


def prove(root: Path = ROOT) -> None:
    """Compile only W5 and its imports, without a full suite or axiom audit.

    No source-hash/manifest check is performed here, so normal proof edits
    can be compiled immediately. Use `check` separately for review provenance.
    """
    lake = shutil.which('lake')
    require(lake is not None,
            'pinned Lean v4.35.0/Lake required to compile W5')
    require((root / '.tools/aeneas/backends/lean/lakefile.lean').is_file(),
            'pinned Aeneas backend missing; run `python dev/verification/garrett.py bootstrap`')
    proofs = root / 'proofs'
    # W4 is deliberately outside the default Lake module roots. Build only
    # the three imported proof roots, avoiding GarrettCheck and its axiom
    # printout, then compile W4 into the module path imported by W5.
    _run_lean([lake, 'build', '+GarrettProtocol', '+GarrettManifest',
               '+GarrettDisclosure'], proofs, 'W4 dependency build')
    olean = proofs / '.lake/build/lib/lean/GarrettConfinement.olean'
    olean.parent.mkdir(parents=True, exist_ok=True)
    _run_lean([lake, 'env', 'lean', '-DwarningAsError=true',
               '-o', str(olean), 'GarrettConfinement.lean'],
              proofs, 'W4 compilation')
    _run_lean([lake, 'env', 'lean', '-DwarningAsError=true',
               'GarrettNoninterference.lean'], proofs, 'W5 Lean compilation')
    print('W5 Lean compilation passed.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'prove'])
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    if args.action == 'check':
        print(json.dumps(check(args.root), sort_keys=True))
    else:
        prove(args.root)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except ContractError as error:
        raise SystemExit(f'W5 check failed: {error}') from error
