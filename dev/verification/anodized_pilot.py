#!/usr/bin/env python3
"""Opt-in Anodized 0.7 contract pilot on the pinned Charon/Aeneas pipeline.

Reproduces the 2026-10-23 compatibility test without changing production
code or the authoritative extraction (``garrett.py extract`` and
``proofs/generated`` are untouched):

1. copy ``aivm-secrets-garrett-core`` under ``.tools/anodized-pilot`` as a
   standalone crate, add ``anodized = "=0.7.0"`` behind a
   ``verification-specs`` feature, and annotate
   ``selected_conversion::public_field_name`` with the necessary-condition
   ``ensures`` contract;
2. run the validator test with and without the feature (same verdicts);
3. expand the crate with ``--cfg anodized_charon``: report the items
   Anodized inserts into the function body (unused loop-spec closures), that
   the body is otherwise unchanged, and that the contract items carry
   ``#[charon::contract(..., for = "public_field_name")]``;
4. run the pinned Charon (``--cfg anodized_charon``) and Aeneas into
   ``.tools/anodized-pilot/lean`` and report what the extracted
   ``public_field_name`` became and which axioms appeared.

Prints a JSON report. ``verdict`` is ``"no-go"`` when the extracted
production function depends on uninterpreted Anodized axioms, which is the
observed result with Charon/Aeneas ``nightly-2026.10.16-d95aeac``.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / 'rust/crates/aivm-secrets-garrett-core'
TOOLS = ROOT / '.tools/aeneas'
PILOT = ROOT / '.tools/anodized-pilot'
# Same depth as the real crate, so its relative test-vector includes resolve.
WORK = PILOT / 'rust/crates/aivm-secrets-garrett-core'
LEAN = PILOT / 'lean'
BASELINE_AXIOMS = {'core.mem.maybe_uninit.MaybeUninit', 'core.result.Result.is_err'}

MANIFEST = '''[package]
name = "aivm-secrets-garrett-core"
version = "0.1.0"
edition = "2021"

[features]
verification-specs = ["dep:anodized"]

[dependencies]
anodized = { version = "=0.7.0", optional = true }

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(anodized_charon)"] }

[workspace]
'''

CRATE_ATTRS = '''#![cfg_attr(anodized_charon, feature(register_tool))]
#![cfg_attr(anodized_charon, register_tool(charon))]
'''

SIGNATURE = 'pub fn public_field_name(bytes: &Vec<u8>) -> bool {'
CONTRACT = '''#[cfg_attr(
    feature = "verification-specs",
    anodized::spec(ensures: |output| [
        !output || (
            bytes.len() >= 1 &&
            bytes.len() <= 32 &&
            bytes[0] >= b'a' &&
            bytes[0] <= b'z'
        ),
    ])
)]
'''


def run(argv, *, cwd, env=None, capture=False):
    done = subprocess.run([str(a) for a in argv], cwd=cwd, env=env, text=True,
                          capture_output=True, timeout=1800)
    if done.returncode:
        sys.stderr.write(done.stdout[-4000:] + done.stderr[-4000:])
        raise SystemExit(f'failed: {" ".join(map(str, argv))}')
    return done.stdout if capture else None


def prepare() -> None:
    shutil.rmtree(PILOT, ignore_errors=True)
    shutil.copytree(CORE, WORK, ignore=shutil.ignore_patterns('target'))
    shutil.copytree(ROOT / 'tests/secrets_vectors', PILOT / 'tests/secrets_vectors')
    shutil.copy(ROOT / 'rust/rust-toolchain.toml', WORK / 'rust-toolchain.toml')
    (WORK / 'Cargo.toml').write_text(MANIFEST)
    lib = WORK / 'src/lib.rs'
    text = lib.read_text()
    anchor = '#![forbid(unsafe_code)]\n'
    assert anchor in text
    lib.write_text(text.replace(anchor, anchor + CRATE_ATTRS, 1))
    source = WORK / 'src/selected_conversion.rs'
    text = source.read_text()
    assert text.count(SIGNATURE) == 1
    source.write_text(text.replace(SIGNATURE, CONTRACT + SIGNATURE))


def main() -> int:
    prepare()
    env = dict(os.environ, PATH=f"{Path.home() / '.cargo/bin'}:{os.environ['PATH']}",
               CARGO_TARGET_DIR=str(PILOT / 'target'))
    report: dict = {'anodized': '=0.7.0', 'function': 'selected_conversion::public_field_name'}
    test = ['cargo', 'test', '-q', '--lib', 'public_field_name_accepts_exactly_the_documented_language']
    run(test, cwd=WORK, env=env)
    run([*test, '--features', 'verification-specs'], cwd=WORK, env=env)
    report['same_verdicts_with_and_without_contract'] = True

    charon_env = dict(env, RUSTFLAGS='--cfg anodized_charon')
    expanded = run(['cargo', 'rustc', '-q', '--lib', '--features', 'verification-specs', '--',
                    '-Zunpretty=expanded'], cwd=WORK, env=charon_env, capture=True)
    body = (CORE / 'src/selected_conversion.rs').read_text()
    original = body[body.index(SIGNATURE):body.index('\n}\n', body.index(SIGNATURE))]
    flat = lambda text: re.sub(r'\s+', '', text)
    start = expanded.index(SIGNATURE.split('(')[0])
    annotated = expanded[start:expanded.index('\n    }\n', start)]
    inserted = re.findall(r'let (__anodized_\w+)\s*=', annotated)
    # Anodized inserts unused per-iteration loop-spec closures into the body.
    stripped = re.sub(r'let __anodized_\w+\s*=\s*\|\|[^;]*?(\{[^{}]*\}|\{\})\s*;', '', annotated)
    report['body_items_inserted_by_anodized'] = inserted
    report['body_unchanged_apart_from_inserted_items'] = flat(original) in flat(stripped)
    report['contract_items'] = sorted(set(re.findall(
        r'#\[charon::contract\(kind = "(\w+)", for = "public_field_name"\)\]', expanded)))

    llbc = PILOT / 'core.llbc'
    run([TOOLS / 'charon', 'cargo', '--preset=aeneas', '--sysroot', 'default', '--dest-file', llbc,
         '--', '--lib', '--features', 'verification-specs'], cwd=WORK, env=charon_env)
    LEAN.mkdir(parents=True, exist_ok=True)
    run([TOOLS / 'aeneas', '-backend', 'lean', '-no-progress-bar', '-loops-to-rec', '-dest', LEAN, llbc],
        cwd=ROOT)
    [module] = sorted(LEAN.glob('*.lean'))
    lean = module.read_text()
    start = lean.index('def selected_conversion.public_field_name\n')
    definition = lean[start:lean.index('\n\n', start)]
    report['extracted_definition'] = definition
    report['definition_uses_anodized_axioms'] = 'anodized.__.' in definition
    axioms = set(re.findall(r'^axiom\s+([\w.]+)', lean, re.M))
    report['new_axioms'] = sorted(axioms - BASELINE_AXIOMS)
    report['verdict'] = 'no-go' if report['definition_uses_anodized_axioms'] or report['new_axioms'] \
        else 'contract-carried'
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
