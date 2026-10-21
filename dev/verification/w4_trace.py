#!/usr/bin/env python3
"""W4 scoped source/proof guard; `prove` additionally requires pinned Lean.

`check` validates provenance and review markers, NOT a Lean derivation.
`prove` compiles the candidate proof without dumping axiom dependencies.
Neither action proves concrete W3 TLS/HTTP/file I/O refinement (W6).
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
MANIFEST = 'docs/planning/aivm-secrets-w4-proof-scope.json'
PROOF = 'proofs/GarrettConfinement.lean'
EXPECTED_CORE = {
    'rust/crates/aivm-secrets-garrett-core/src/credential_use.rs',
    'rust/crates/aivm-secrets-garrett-core/src/protocol.rs',
    'rust/crates/aivm-secrets-garrett-core/src/manifest.rs',
    'rust/crates/aivm-secrets-garrett-core/src/disclosure.rs',
    'proofs/generated/AivmSecretsGarrettCore.lean',
}
EXPECTED_TODO = {'IO-REFINE', 'NO-PREFLIGHT', 'CHECKED-FACTS', 'METADATA', 'OTHER-PROFILES'}
REQUIRED_MARKERS = [
    'aivm_secrets_garrett_core.manifest.authorize',
    'aivm_secrets_garrett_core.manifest.parameter',
    'aivm_secrets_garrett_core.disclosure.project',
    'manifest.Proofs.Admission',
    'manifest.Proofs.parameter_contract',
    'manifest.Proofs.authorize_contract',
    'providerSend (phase : Phase) (gate : Gate) (auditOK : Bool)',
    'gate.accepted ∧ auditOK = true',
    'refused_preflight_audit_stops',
    'revoked_after_preflight_stops_final',
    'request_trace_sound',
]
ALLOWED_AXIOMS = {'propext', 'Classical.choice', 'Quot.sound'}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root: Path = ROOT) -> dict:
    info = json.loads((root / MANIFEST).read_text())
    require(info.get('schema') == 1, 'invalid W4 schema')
    require(info.get('scope') == 'modeled-native-manifest-two-phase-v1', 'incorrect W4 scope')
    require(info.get('status') == 'local-kernel-checked-refinement-open', 'incorrect W4 claim status')
    require(set(info.get('core_sha256', {})) == EXPECTED_CORE, 'extracted Rust input coverage changed')
    require(set(info.get('open_obligations', [])) == EXPECTED_TODO, 'missing unproved W4/W6 obligations')
    for name, expected in info['core_sha256'].items():
        require(digest(root / name) == expected, f'core/extraction changed: {name}')
    require(digest(root / PROOF) == info.get('proof_sha256'), 'W4 proof changed without review')
    proof = (root / PROOF).read_text()
    # Lean documentation comments must precede declarations, not tactic/command directives.
    # Catch this syntax error even in environments without the Lean toolchain.
    require(re.search(r'/--(?:(?!-/)[\s\S])*-/\s*#(?:check|print|eval)\b', proof) is None,
            'Lean doc comment cannot attach to a #check/#print/#eval command')
    for forbidden in (r'(?m)^\s*axiom\b', r'(?m)^\s*constant\b'):
        require(re.search(forbidden, proof) is None, f'W4 proof has an unsupported escape: {forbidden}')
    for marker in REQUIRED_MARKERS:
        require(marker in proof, f'missing W4 reviewed binding: {marker}')
    names = info.get('theorems', [])
    require(isinstance(names, list) and len(names) >= 12 and len(set(names)) == len(names),
            'W4 theorem names missing/duplicated')
    defined = set(re.findall(r'(?m)^theorem ([a-zA-Z0-9_]+)\b', proof))
    require(defined == set(names), f'unreviewed W4 theorem changes: {defined ^ set(names)}')
    for source, symbol in [('credential_use.rs','fn require_use_current('),
                           ('protocol.rs','pub fn perform<'),
                           ('manifest.rs','pub fn authorize('),
                           ('disclosure.rs','pub fn project(')]:
        src = root / 'rust/crates/aivm-secrets-garrett-core/src' / source
        require(symbol in src.read_text(), f'Rust extraction source missing {source}:{symbol}')
    generated = (root / 'proofs/generated/AivmSecretsGarrettCore.lean').read_text()
    for symbol in ('def credential_use.require_use_current', 'def protocol.perform',
                   'def manifest.parameter', 'def manifest.authorize', 'def disclosure.project'):
        require(symbol in generated, f'generated Aeneas binding missing: {symbol}')
    return {'source_inputs': len(EXPECTED_CORE), 'theorems': len(names),
            'status': 'structure only; requires `prove` for Lean kernel checking'}


def audit(output: str, names: list[str]) -> None:
    prefix = 'aivm_secrets_garrett_core.confinement.Proofs.'
    found = {}
    for name, axioms in re.findall(r"'([^']+)' depends on axioms:\s*\[([^\]]*)\]", output):
        found[name] = {x.strip() for x in axioms.split(',') if x.strip()}
    for name in re.findall(r"'([^']+)' does not depend on any axioms", output):
        found[name] = set()
    expected = {prefix + name for name in names}
    require(set(found) == expected, f'W4 Lean axiom audit incomplete: {expected ^ set(found)}')
    for name, axioms in found.items():
        require(not (axioms - ALLOWED_AXIOMS), f'unreviewed axioms in {name}: {axioms - ALLOWED_AXIOMS}')


def prove(root: Path = ROOT) -> None:
    lake = shutil.which('lake')
    require(lake is not None, 'pinned `lake` / Lean v4.35.0 required; do not count structural checks as a proof')
    backend = root / '.tools/aeneas/backends/lean'
    require((backend / 'lakefile.lean').is_file(),
            'pinned Aeneas Lean backend missing at .tools/aeneas/backends/lean; '
            'run `python dev/verification/garrett.py bootstrap` from the repository root '
            '(requires network access), then retry `python dev/verification/w4_trace.py prove`')
    proofs = root / 'proofs'
    subprocess.run([lake, 'build', 'GarrettConfinement'], cwd=proofs, check=True)
    result = subprocess.run([lake, 'env', 'lean', '-DwarningAsError=true',
                             'GarrettConfinement.lean'], cwd=proofs,
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout, end='')
        print(result.stderr, end='')
        raise ContractError('W4 Lean kernel check failed')
    print('W4 model proofs compiled (not native I/O refinement).')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check','prove'])
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    result = check(args.root)
    print(json.dumps(result, sort_keys=True))
    if args.action == 'prove':
        prove(args.root)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except ContractError as ex:
        raise SystemExit(f'W4 check failed: {ex}') from ex
