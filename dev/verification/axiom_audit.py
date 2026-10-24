#!/usr/bin/env python3
"""Opt-in final axiom audit: every theorem in every proof module.

This is the end-of-formalization audit that AGENTS.md describes. It is not a
build step: run it only when a review asks for it.

It writes a temporary Lean file that imports every root module of the
`proofs/` Lake package and, with a small metaprogram, lists every theorem
declared in those modules with the axioms it depends on transitively. The
raw listing goes to a file. Standard output shows only what differs from the
reviewed baseline (`docs/assurance/axiom-baseline.json`):

* theorems that depend on anything outside the allowed set (Lean's three
  standard axioms plus the named axioms of the extracted model);
* new or removed theorems, and theorems whose axiom set changed.

    python dev/verification/axiom_audit.py run [--raw FILE]
    python dev/verification/axiom_audit.py baseline     # after review only
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROOFS = ROOT / 'proofs'
BASELINE = ROOT / 'docs/assurance/axiom-baseline.json'
STANDARD = {'propext', 'Classical.choice', 'Quot.sound'}
# Lemmas Lean generates for definitions and structures (equations, sizes,
# injectivity); they are not statements anyone wrote or reviews.
GENERATED = re.compile(r'\.(eq_\d+|eq_def|sizeOf_spec|congr_simp|injEq|inj|noConfusion\w*)$')


def modules() -> list[str]:
    text = (PROOFS / 'lakefile.lean').read_text()
    found = []
    for block in re.findall(r'roots := #\[([^\]]*)\]', text):
        found += re.findall(r'`([A-Za-z0-9_.]+)', block)
    return list(dict.fromkeys(found))


def lean_source(names: list[str]) -> str:
    imports = '\n'.join(f'import {name}' for name in names)
    ours = ', '.join(f'`{name}' for name in names)
    return imports + '''
open Lean Elab Command

/-- One tab-separated line per theorem of ours: module, name, axioms. -/
def auditLine (ours : List Name) (env : Environment) (decl : Name) (info : ConstantInfo) :
    CoreM (Option String) := do
  match info with
  | .thmInfo _ =>
    match env.getModuleIdxFor? decl with
    | some idx =>
      let modName := env.header.moduleNames[idx.toNat]!
      if ours.contains modName && !decl.isInternal then
        let axioms ← Lean.collectAxioms decl
        let sorted := (axioms.map toString).qsort (· < ·)
        return some s!"{modName}\\t{decl}\\t{String.intercalate "," sorted.toList}"
      else return none
    | none => return none
  | _ => return none

#eval show CommandElabM Unit from do
  let env ← getEnv
  let ours : List Name := [''' + ours + ''']
  let lines ← liftCoreM <| env.constants.toList.foldlM (init := #[]) fun acc entry => do
    match ← auditLine ours env entry.1 entry.2 with
    | some line => return acc.push line
    | none => return acc
  IO.println (String.intercalate "\\n" (lines.qsort (· < ·)).toList)
'''


def generated_axioms() -> set[str]:
    """The axioms Aeneas emitted for the extracted model (opaque Rust items)."""
    found = set()
    for path in (PROOFS / 'generated').glob('*.lean'):
        found |= set(re.findall(r'^axiom\s+(\S+)', path.read_text(), re.M))
    return found


# The two extracted libraries define some of the same instance names, so no
# single Lean file can import both. Each group is audited in its own file.
PRIMITIVES = ('AivmSecretsPrimitives', 'Freshness')


def groups() -> list[list[str]]:
    names = modules()
    first = [name for name in names if name in PRIMITIVES]
    return [first, [name for name in names if name not in PRIMITIVES]]


def collect() -> dict[str, dict]:
    theorems: dict[str, dict] = {}
    for group in groups():
        theorems.update(collect_group(group))
    return theorems


def collect_group(names: list[str]) -> dict[str, dict]:
    lake = shutil.which('lake') or str(Path.home() / '.elan/bin/lake')
    with tempfile.NamedTemporaryFile('w', suffix='.lean', dir=PROOFS, prefix='AxiomAudit',
                                     delete=False) as handle:
        handle.write(lean_source(names))
        path = Path(handle.name)
    try:
        result = subprocess.run([lake, 'env', 'lean', path.name], cwd=PROOFS,
                                capture_output=True, text=True, timeout=7200)
    finally:
        path.unlink(missing_ok=True)
    if result.returncode:
        sys.stderr.write(result.stderr[-4000:] + result.stdout[-4000:])
        raise SystemExit('the audit file did not compile')
    theorems = {}
    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) == 3 and not GENERATED.search(parts[1]):
            module, name, axioms = parts
            theorems[name] = {'module': module,
                              'axioms': [a for a in axioms.split(',') if a]}
    return theorems


def summarize(theorems: dict[str, dict]) -> dict:
    allowed = STANDARD | generated_axioms()
    outside = {name: sorted(set(t['axioms']) - allowed)
               for name, t in theorems.items() if set(t['axioms']) - allowed}
    uses_model_axioms = Counter(a for t in theorems.values() for a in t['axioms']
                                if a in generated_axioms())
    return {
        'theorems': len(theorems),
        'modules': len({t['module'] for t in theorems.values()}),
        'allowed': sorted(allowed),
        'outside_allowed': outside,
        'model_axiom_use': dict(sorted(uses_model_axioms.items())),
    }


def compare(theorems: dict[str, dict], baseline: dict) -> dict:
    old = baseline.get('theorems', {})
    return {
        'added': sorted(set(theorems) - set(old)),
        'removed': sorted(set(old) - set(theorems)),
        'changed': sorted(name for name in set(theorems) & set(old)
                          if sorted(theorems[name]['axioms']) != sorted(old[name]['axioms'])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['run', 'baseline'])
    parser.add_argument('--raw', type=Path, help='write the full listing here')
    args = parser.parse_args(argv)
    theorems = collect()
    summary = summarize(theorems)
    if args.raw:
        args.raw.write_text(json.dumps(theorems, indent=1, sort_keys=True))
    if args.action == 'baseline':
        BASELINE.write_text(json.dumps({'summary': summary, 'theorems': theorems},
                                       indent=1, sort_keys=True) + '\n')
        print(json.dumps(summary, indent=2))
        return 1 if summary['outside_allowed'] else 0
    diff = compare(theorems, json.loads(BASELINE.read_text())) if BASELINE.exists() else None
    report = {'theorems': summary['theorems'], 'outside_allowed': summary['outside_allowed'],
              'model_axiom_use': summary['model_axiom_use']}
    if diff is not None:
        report['against_baseline'] = {key: (value if len(value) <= 40 else value[:40] + ['...'])
                                      for key, value in diff.items()}
    print(json.dumps(report, indent=2))
    return 1 if summary['outside_allowed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
