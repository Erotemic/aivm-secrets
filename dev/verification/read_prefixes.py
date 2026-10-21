#!/usr/bin/env python3
"""Focused generic read-prefix Lean source review and optional kernel check.

`check` is fast and portable. `prove` builds the existing pinned W4/W5/read-path
imports, compiles this new scoped module without an axiom report.
Neither mode proves that actual Rust dependency/I/O events refine the model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

import lean_step
import read_paths

ROOT = Path(__file__).resolve().parents[2]
PROOF = 'proofs/GarrettReadPrefixes.lean'
SPEC = 'docs/planning/aivm-secrets-read-prefix-proof-scope.json'
MODULE = 'aivm_secrets_garrett_core.confinement.ReadPrefixes.'
REQUIRED = {
    'blocked_has_no_provider', 'attempt_sound',
    'attempt_send_requires_admission', 'history_sound',
    'coupled_history_noninterference',
}
ALLOWED_AXIOMS = {'propext', 'Classical.choice', 'Quot.sound'}


class PrefixReviewError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PrefixReviewError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root: Path = ROOT) -> dict:
    read_paths.check(root)
    manifest = json.loads((root / SPEC).read_text())
    require(manifest.get('schema') == 1, 'unreviewed prefix theorem schema')
    require(manifest.get('scope') == 'abstract-native-read-prefix-history-v1',
            'read-prefix assurance scope changed')
    require(manifest.get('status') == 'source-reviewed-kernel-verification-required',
            'unjustified Lean kernel completion claim')
    require(set(manifest.get('theorems', [])) == REQUIRED,
            'read-prefix theorem audit list changed')
    require(manifest.get('proof_sha256') == sha(root / PROOF),
            'Lean source changed without proof-scope review')
    require(manifest.get('dependency_sha256') == sha(root / 'proofs/GarrettReadPaths.lean'),
            'read-path proof dependency changed')
    require(set(manifest.get('open_obligations', [])) == {
        'ALL-NATIVE-IO-REFINEMENT', 'AUDIT-FSYNC-SEMANTICS',
        'TLS-RECORD-AND-SEND-BOUNDARY', 'RUNTIME-LEASE-MAPPING',
        'ERROR-CLOSE-TIMING', 'ARBITRARY-CONCURRENCY',
    }, 'a security assumption was silently removed')
    source = (root / PROOF).read_text()
    require('import GarrettReadPaths' in source and
            'accepted_implies_admission' in source and
            'read_observation_noninterference' in source,
            'source-linked W4/W5 proof obligations are missing')
    require('providerReached' in source and 'blocked_has_no_provider' in source,
            'audited-but-unsent branch was dropped')
    for pattern in (r'(?m)^\s*axiom\b',
                    r'(?m)^\s*constant\b', r'\bunsafe\b'):
        require(re.search(pattern, source) is None,
                f'unreviewed Lean proof escape: {pattern}')
    names = set(re.findall(r'(?m)^theorem\s+([a-zA-Z0-9_]+)\b', source))
    require(names == REQUIRED, f'theorems differ from reviewed scope: {names ^ REQUIRED}')
    return {'theorems': len(REQUIRED), 'status': 'source check (kernel pending)',
            'coverage': 'generic model phases and sequential declassification'}


def _run(command: list[str], cwd: Path, name: str) -> str:
    try:
        return lean_step.run(command, cwd, name)
    except lean_step.LeanStepError as error:
        raise PrefixReviewError(str(error)) from error


def prove(root: Path = ROOT) -> None:
    lake = shutil.which('lake')
    require(lake is not None, 'pinned Lean/lake toolchain not available')
    # Reuse the W4/W5 prerequisite compilation and the read-path import object.
    try:
        read_paths.prove(root)
    except read_paths.ReviewError as error:
        raise PrefixReviewError(f'read-path prerequisite: {error}') from error
    directory = root / 'proofs'
    # read_paths.prove compiled this exact source with -o;
    # no second compilation is needed just to produce an import object.
    olean = directory / '.lake/build/lib/lean/GarrettReadPaths.olean'
    require(olean.is_file(), f'read-path import object missing: {olean}')
    _run([lake, 'env', 'lean', '-DwarningAsError=true',
          'GarrettReadPrefixes.lean'], directory,
         'generic read-prefix Lean compilation')
    print('Read-prefix Lean compilation passed; native I/O simulation remains open.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'prove'))
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(check(args.root), sort_keys=True))
    if args.action == 'prove':
        prove(args.root)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except PrefixReviewError as error:
        raise SystemExit(f'W4/W5 read-prefix proof: {error}') from error
