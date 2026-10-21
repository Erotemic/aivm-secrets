#!/usr/bin/env python3
"""Focused W4/W5 native-read-path review and optional Lean compilation.

`check` is portable and validates only explicit proof provenance and shape.
`prove` compiles the pinned W4/W5 imports and this module without
per-theorem reports; it avoids Charon, Cargo and the complete verification suite.
Neither proves native TLS/HTTP/file I/O refinement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

import lean_step
import w4_trace
import w5_noninterference

ROOT = Path(__file__).resolve().parents[2]
PROOF = 'proofs/GarrettReadPaths.lean'
SPEC = 'docs/planning/aivm-secrets-read-path-proof-scope.json'
MODULE = 'aivm_secrets_garrett_core.confinement.ReadPaths.'
REQUIRED = {
    'final_only_sound', 'check_only_sound', 'read_trace_sound',
    'final_only_requires_admission', 'final_only_noninterference',
    'observe_check_only', 'check_only_noninterference',
    'read_observation_noninterference',
}
ALLOWED_AXIOMS = {'propext', 'Classical.choice', 'Quot.sound'}


class ReviewError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ReviewError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root: Path = ROOT) -> dict:
    # These checks reject silently swapped extracted controller or W4/W5
    # proof sources. They do not prove anything about the new Lean source.
    w4_trace.check(root)
    w5_noninterference.check(root)
    manifest = json.loads((root / SPEC).read_text())
    require(manifest.get('schema') == 1, 'invalid read-path manifest')
    require(manifest.get('scope') == 'abstract-native-manifest-read-shapes-v1',
            'unreviewed read-path scope')
    require(manifest.get('status') == 'source-reviewed-kernel-verification-required',
            'overstated proof status')
    require(set(manifest.get('theorems', [])) == REQUIRED, 'theorem list changed')
    require(set(manifest.get('paths', [])) == {
        'no-preflight-final-read', 'preflight-only-check-return',
        'preflight-then-final-read',
    }, 'missing read execution shape')
    require(set(manifest.get('open_obligations', [])) == {
        'NATIVE-IO-REFINE', 'ADAPTER-OUTCOMES', 'REAL-LEASE-CORRESPONDENCE',
        'ERROR-CLOSE-TIMING', 'LARGE-DATA-AND-ALL-PROFILES',
    }, 'an open proof obligation was dropped')
    for name in ('proofs/GarrettConfinement.lean', 'proofs/GarrettNoninterference.lean',
                 'proofs/generated/AivmSecretsGarrettCore.lean'):
        require(manifest.get('dependencies', {}).get(name) == sha(root / name),
                f'proof dependency changed: {name}')
    require(manifest.get('proof_sha256') == sha(root / PROOF),
            'Lean source changed without proof-scope review')
    source = (root / PROOF).read_text()
    require('import GarrettNoninterference' in source, 'missing extracted-core linkage')
    require('afterFinal r.final' in source and 'afterPreflight r.pre' in source,
            'missing read-path/controller construction')
    require('observe_disclose_noninterference' in source,
            'proof does not reuse the extracted recursive projection theorem')
    for pattern in (r'(?m)^\s*axiom\b',
                    r'(?m)^\s*constant\b', r'\bunsafe\b'):
        require(re.search(pattern, source) is None,
                f'unsupported Lean escape: {pattern}')
    declared = set(re.findall(r'(?m)^theorem ([a-zA-Z0-9_]+)\b', source))
    require(declared == REQUIRED, f'Lean declarations not in review: {declared ^ REQUIRED}')
    return {'theorems': len(REQUIRED), 'shapes': 3,
            'status': 'portable source review only (Lean compilation required)'}


def _run(cmd: list[str], cwd: Path, label: str) -> str:
    try:
        return lean_step.run(cmd, cwd, label)
    except lean_step.LeanStepError as error:
        raise ReviewError(str(error)) from error


def prove(root: Path = ROOT) -> None:
    lake = shutil.which('lake')
    require(lake is not None, 'pinned lake/Lean v4.35.0 required for proof')
    require((root / '.tools/aeneas/backends/lean/lakefile.lean').exists(),
            'Aeneas backend missing; run repository bootstrap in your provisioned VM')
    directory = root / 'proofs'
    _run([lake, 'build', '+GarrettProtocol', '+GarrettManifest', '+GarrettDisclosure'],
         directory, 'W4 dependencies')
    oleans = directory / '.lake/build/lib/lean'
    oleans.mkdir(parents=True, exist_ok=True)
    for name in ('GarrettConfinement', 'GarrettNoninterference'):
        _run([lake, 'env', 'lean', '-DwarningAsError=true',
              '-o', str(oleans / f'{name}.olean'), f'{name}.lean'],
             directory, name)
    # Emit the importable olean during the SAME successful compilation. The
    # read-prefix verifier reuses this object; recompiling this large module
    # merely to supply its import wastes time and memory.
    _run([lake, 'env', 'lean', '-DwarningAsError=true',
          '-o', str(oleans / 'GarrettReadPaths.olean'),
          'GarrettReadPaths.lean'], directory,
         'read-path Lean compilation and import object')
    print('Read-path Lean compilation passed; native-to-trace refinement remains open.')

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
    except ReviewError as error:
        raise SystemExit(f'W4/W5 read paths: {error}') from error
