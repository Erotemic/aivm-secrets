#!/usr/bin/env python3
"""Provision, regenerate, prove and test the scoped Rust freshness primitive.

Requires Python 3.12+, curl, tar, rustup and elan. No root operations or default
toolchain changes are needed. Run with the project's test environment Python.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROOFS = ROOT / 'proofs'
TOOLS = ROOT / '.tools/aeneas'
MANIFEST = PROOFS / 'manifest.json'
RUST = 'nightly-2026-09-17'
LEAN = 'leanprover/lean4:v4.35.0'
RELEASE = 'nightly-2026.10.16-d95aeac'
ARCHIVE_SHA256 = '664e9ccadbeac9eb28284c1a89d1d587725596630c06f980451514a6d478d3cf'
URL = f'https://github.com/AeneasVerif/aeneas/releases/download/{RELEASE}/aeneas-linux-x86_64.tar.gz'
THEOREMS = [
    'advance_contract', 'current_exact', 'active_exact', 'fresh_exact',
    'fresh_accepted_iff', 'fresh_rejects_stale', 'fresh_rejects_expired',
    'advance_invalidates_old_epoch', 'fresh_positive_witness', 'advance_positive_witness',
]
ALLOWED_AXIOMS = {'propext', 'Classical.choice', 'Quot.sound'}


SOURCE_FILES = [
    '.github/workflows/freshness.yml',
    'rust/Cargo.toml', 'rust/Cargo.lock', 'rust/rust-toolchain.toml',
    'rust/crates/aivm-secrets-primitives/Cargo.toml',
    'rust/crates/aivm-secrets-primitives/src/lib.rs',
    'rust/crates/freshness-conformance/Cargo.toml',
    'rust/crates/freshness-conformance/src/main.rs',
    'proofs/lean-toolchain', 'proofs/lakefile.lean', 'proofs/lake-manifest.json',
    'proofs/generated/AivmSecretsPrimitives.lean', 'proofs/Freshness.lean', 'proofs/Check.lean',
    'dev/verification/freshness.py', 'tests/test_rust_freshness.py',
    'aivm_secrets/primitives/epochs.py', 'aivm_secrets/primitives/validity.py',
    'tests/secrets_vectors/primitives/epochs-v1.jsonl',
    'tests/secrets_vectors/primitives/validity-v1.jsonl',
    'tests/secrets_vectors/primitives/runner-v1.jsonl',
]


def executable(name: str) -> str:
    selected = shutil.which(name)
    if selected:
        return selected
    for directory in ['.cargo/bin', '.elan/bin']:
        candidate = Path.home() / directory / name
        if candidate.is_file():
            return str(candidate)
    raise SystemExit(f'{name} is required; install its toolchain manager first')


def run(argv: list[str | Path], *, cwd: Path = ROOT, env=None, capture=False,
        check=True, timeout=1800) -> subprocess.CompletedProcess:
    args = [str(arg) for arg in argv]
    print('+ ' + shlex.join(args), flush=True)
    effective_env = dict(os.environ) if env is None else dict(env)
    effective_env['PATH'] = os.pathsep.join([
        str(Path(executable('cargo')).parent), str(Path(executable('lake')).parent),
        effective_env.get('PATH', ''),
    ])
    return subprocess.run(args, cwd=cwd, env=effective_env, capture_output=capture,
                          text=True, check=check, timeout=timeout)


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bootstrap() -> None:
    if sys.platform != 'linux' or os.uname().machine != 'x86_64':
        raise SystemExit('this pinned binary bundle supports Linux x86_64 only')
    archive = ROOT / '.tools/aeneas-linux-x86_64.tar.gz'
    archive.parent.mkdir(exist_ok=True)
    if not archive.exists():
        partial = archive.with_suffix('.part')
        run([executable('curl'), '--fail', '--location', '--output', partial, URL])
        if sha256(partial) != ARCHIVE_SHA256:
            raise SystemExit('downloaded Aeneas archive has the wrong SHA-256')
        partial.replace(archive)
    if sha256(archive) != ARCHIVE_SHA256:
        raise SystemExit('Aeneas archive has the wrong SHA-256')
    if not TOOLS.exists():
        # Publish the installation only after extraction succeeds, so an
        # interrupted setup never leaves a directory mistaken for a full bundle.
        with tempfile.TemporaryDirectory(prefix='aeneas-install-', dir=archive.parent) as path:
            installation = Path(path)
            run(['tar', '-xzf', archive, '-C', installation])
            if not all((installation / name).is_file() for name in ['aeneas', 'charon', 'charon-driver']):
                raise SystemExit('Aeneas bundle is incomplete')
            installation.rename(TOOLS)
    run([executable('rustup'), 'toolchain', 'install', RUST, '--profile', 'minimal',
         '--component', 'rustc-dev,rust-src,llvm-tools'])
    run([executable('elan'), 'run', '--install', LEAN, 'lean', '--version'])
    # The committed Lake manifest fixes the revisions; do not run lake update.
    run([executable('lake'), 'exe', 'cache', 'get'], cwd=PROOFS)


def extract(destination: Path, rust_root: Path | None = None) -> Path:
    rust_root = ROOT / 'rust' if rust_root is None else rust_root
    run([TOOLS / 'charon', 'cargo', '--preset=aeneas', '--sysroot', 'default',
         '--', '--lib', '--locked'], cwd=rust_root / 'crates/aivm-secrets-primitives')
    destination.mkdir(parents=True, exist_ok=True)
    run([TOOLS / 'aeneas', '-backend', 'lean', '-no-progress-bar', '-abort-on-error',
         '-warnings-as-errors', '-dest', destination,
         rust_root / 'aivm_secrets_primitives.llbc'])
    generated = destination / 'AivmSecretsPrimitives.lean'
    if not generated.is_file():
        raise SystemExit('extraction did not produce the expected Lean module')
    return generated


def check_extraction() -> None:
    with tempfile.TemporaryDirectory(prefix='freshness-extract-', dir=ROOT / '.tools') as path:
        generated = extract(Path(path))
        if generated.read_bytes() != (PROOFS / 'generated' / generated.name).read_bytes():
            raise SystemExit('generated Lean is stale: regenerate and review the diff')


def check_axioms(output: str) -> None:
    found = {}
    for name, axioms in re.findall(r"'([^']+)' depends on axioms:\s*\[([^\]]*)\]", output):
        found[name] = {item.strip() for item in axioms.split(',') if item.strip()}
    for name in re.findall(r"'([^']+)' does not depend on any axioms", output):
        found[name] = set()
    expected = {f'aivm_secrets_primitives.Proofs.{name}' for name in THEOREMS}
    if set(found) != expected:
        raise SystemExit(f'named theorem/axiom inventory differs: {set(found) ^ expected}')
    for name, axioms in found.items():
        if axioms - ALLOWED_AXIOMS:
            raise SystemExit(f'{name} uses undeclared axioms: {axioms - ALLOWED_AXIOMS}')
    print(f'Checked {len(found)} named theorems and their transitive axiom dependencies.')


def prove() -> None:
    run([executable('lake'), 'build'], cwd=PROOFS)
    # Force a fresh audit even when Lake reuses compiled proof objects.
    done = run([executable('lake'), 'env', 'lean', '-DwarningAsError=true', 'Check.lean'],
               cwd=PROOFS, capture=True)
    print(done.stdout, end='')
    check_axioms(done.stdout)


def parity() -> None:
    run([executable('cargo'), '+' + RUST, 'build', '--locked', '--release',
         '-p', 'freshness-conformance'], cwd=ROOT / 'rust')
    env = dict(os.environ, AIVM_SECRETS_FRESHNESS_RUNNER=str(
        ROOT / 'rust/target/release/freshness-conformance'))
    run([sys.executable, '-m', 'pytest', '-q', 'tests/test_rust_freshness.py'], env=env)


def model_digest() -> str:
    digest = hashlib.sha256()
    backend = TOOLS / 'backends/lean'
    paths = []
    for directory, children, files in os.walk(backend):
        children[:] = [name for name in children if name != '.lake']
        paths.extend(Path(directory) / name for name in files if name.endswith('.lean'))
    paths += [backend / name for name in ['lean-toolchain', 'lake-manifest.json']]
    for path in sorted(paths):
        digest.update(str(path.relative_to(backend)).encode() + b'\0')
        digest.update(path.read_bytes())
    return digest.hexdigest()


def check_hashes(manifest: dict) -> None:
    if not (TOOLS / 'aeneas').is_file():
        raise SystemExit('verification tools are missing: run freshness.py bootstrap first')
    if set(manifest['sha256']) != set(SOURCE_FILES):
        raise SystemExit('proof manifest has incomplete source coverage')
    if set(manifest['tool_sha256']) != {'aeneas', 'charon', 'charon-driver'}:
        raise SystemExit('proof manifest has incomplete tool coverage')
    if model_digest() != manifest['aeneas_lean_sources_sha256']:
        raise SystemExit('Aeneas model/library sources differ from the proof manifest')
    for relative, expected in manifest['sha256'].items():
        if sha256(ROOT / relative) != expected:
            raise SystemExit(f'proof manifest is stale: {relative}')
    for name, expected in manifest['tool_sha256'].items():
        if sha256(TOOLS / name) != expected:
            raise SystemExit(f'verification tool checksum differs: {name}')
    if manifest['theorems'] != THEOREMS or set(manifest['allowed_axioms']) != ALLOWED_AXIOMS:
        raise SystemExit('proof obligations or axiom policy differ from the manifest')
    version = run([executable('rustc'), '+' + RUST, '-vV'], capture=True).stdout
    if f"commit-hash: {manifest['rustc_commit']}\n" not in version:
        raise SystemExit('Rust compiler identity differs from the proof manifest')


def record() -> None:
    check_extraction()
    prove()
    parity()
    manifest = {
        'schema': 1, 'primitive': 'capability freshness and bounded epoch revocation',
        'rust': RUST,
        'target': 'x86_64-unknown-linux-gnu', 'sysroot': 'default',
        'aeneas_commit': 'd95aeacab40f33e99e30c30955e36c072c5baf3a',
        'charon_commit': '08d7c9d50144bd84848212c24701253585e90d1f',
        'aeneas_release': RELEASE, 'aeneas_archive_sha256': ARCHIVE_SHA256,
        'lean': LEAN, 'mathlib_commit': '56a005855ea17e0b0958f73ec801ae140b0a1679',
        'theorems': THEOREMS, 'allowed_axioms': sorted(ALLOWED_AXIOMS),
        'external_models': ['Aeneas signed I64 arithmetic, comparison, Result and total-correctness WP'],
        'assumptions': [
            'Charon/Aeneas translation, their standard models and the Lean kernel are trusted.',
            'Rust compiler, target ABI and release build faithfully implement the checked source.',
            'JSON conversion and denial mapping are parity-tested, not formally proved.',
            'Epoch/time arguments are supplied by authenticated, appropriately synchronized adapters.',
            'Clock correctness and durable epoch rollback prevention are outside these pure functions.',
        ],
        'exclusions': ['Python formal verification', 'full primitive runner', 'TLS and cryptography',
                       'credential custody and egress', 'concurrency and durable storage', 'side channels'],
        'aeneas_lean_sources_sha256': model_digest(),
        'tool_sha256': {name: sha256(TOOLS / name) for name in ['aeneas', 'charon', 'charon-driver']},
        'sha256': {name: sha256(ROOT / name) for name in SOURCE_FILES},
    }
    # Record the actual compiler identity rather than an untested version string.
    version = run([executable('rustc'), '+' + RUST, '-vV'], capture=True).stdout
    manifest['rustc_commit'] = re.search(r'^commit-hash: (.+)$', version, re.M).group(1)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n')
    print('Recorded verified source, proof, tool and dependency coordinates in proofs/manifest.json.')


def mutate() -> None:
    """Re-extract changed Rust and require the unchanged Lean proofs to fail."""
    source = ROOT / 'rust/crates/aivm-secrets-primitives/src/lib.rs'
    changes = [
        ('epoch successor', 'Ok(current + 1)', 'Ok(current)'),
        ('epoch exhaustion', 'if current == maximum {', 'if false {'),
        ('epoch binding', 'actual < 0 || actual != expected', 'actual < 0'),
        ('exclusive expiry', 'now >= expires_at', 'now > expires_at'),
        ('composed time check', 'Ok(()) => require_active(now, not_before, expires_at),', 'Ok(()) => Ok(()),'),
    ]
    base_env = dict(os.environ)
    lean_path = run([executable('lake'), 'env', 'printenv', 'LEAN_PATH'],
                    cwd=PROOFS, capture=True).stdout.strip()
    lean_path = os.pathsep.join(str((PROOFS / entry).resolve())
                                for entry in lean_path.split(os.pathsep))
    for label, old, new in changes:
        if source.read_text().count(old) != 1:
            raise SystemExit(f'mutant no longer matches exactly once: {label}')
        with tempfile.TemporaryDirectory(prefix='freshness-mutant-', dir=ROOT / '.tools') as scratch:
            temporary = Path(scratch)
            rust = temporary / 'rust'
            shutil.copytree(ROOT / 'rust/crates/aivm-secrets-primitives',
                            rust / 'crates/aivm-secrets-primitives')
            shutil.copy2(ROOT / 'rust/rust-toolchain.toml', rust / 'rust-toolchain.toml')
            (rust / 'Cargo.toml').write_text(
                '[workspace]\nmembers=["crates/aivm-secrets-primitives"]\nresolver="2"\n'
                '[workspace.package]\nversion="0.1.0"\nedition="2021"\nlicense="Apache-2.0"\n')
            (rust / 'Cargo.lock').write_text(
                '# Automatically generated by Cargo.\nversion = 4\n\n'
                '[[package]]\nname = "aivm-secrets-primitives"\nversion = "0.1.0"\n')
            target = rust / 'crates/aivm-secrets-primitives/src/lib.rs'
            target.write_text(source.read_text().replace(old, new))
            extract(temporary, rust)
            env = dict(base_env, LEAN_PATH=str(temporary) + os.pathsep + lean_path)
            lean = [executable('elan'), 'run', LEAN, 'lean', '-DwarningAsError=true']
            run([*lean, '-o', temporary / 'AivmSecretsPrimitives.olean',
                 temporary / 'AivmSecretsPrimitives.lean'], cwd=temporary, env=env)
            shutil.copy2(PROOFS / 'Freshness.lean', temporary / 'Freshness.lean')
            done = run([*lean, temporary / 'Freshness.lean'], cwd=temporary, env=env,
                       capture=True, check=False)
            if done.returncode == 0:
                raise SystemExit(f'mutant survived the Lean proof gate: {label}')
            proof_error = re.search(r'Freshness\.lean:\d+:\d+: error:', done.stdout)
            infrastructure_error = any(text in done.stdout for text in [
                'unknown module prefix', 'does not exist', 'cannot find file',
            ])
            if not proof_error or infrastructure_error:
                raise SystemExit(f'mutant failed for an unexpected reason: {label}\n{done.stdout}\n{done.stderr}')
            print(f'Lean rejected the re-extracted mutant: {label}')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['bootstrap', 'extract', 'record', 'check', 'mutate'])
    args = parser.parse_args()
    if args.action == 'bootstrap':
        bootstrap()
    elif args.action == 'extract':
        extract(PROOFS / 'generated')
    elif args.action == 'record':
        record()
    else:
        check_hashes(json.loads(MANIFEST.read_text()))
        check_extraction()
        prove()
        if args.action == 'mutate':
            mutate()
        else:
            parity()


if __name__ == '__main__':
    main()
