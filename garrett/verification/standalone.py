"""Check that this tree stands alone: copy it, without build outputs, into an
empty directory and build, test, extract and prove it there.

    python verification/standalone.py [--keep] [--skip-proofs] [--skip-mutants] [--jobs N]

The copy gets its own virtual environment (only this project and its
dependencies), its own Cargo target and its own Lake build. The toolchain
bundle is installed from this tree's pinned archive, checked against its
SHA-256, so nothing is downloaded twice. It also fails if any source file
names the project this one was extracted from. Each step's output goes to
``logs/`` beside the copy; the mutation campaign's progress is also printed.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORED = shutil.ignore_patterns('target', '.tools', '.lake', '__pycache__', '*.egg-info', 'build', 'dist', '*.llbc')
# Allowed mentions of the origin: history notes and the README's origin line.
ORIGIN = re.compile(r'aivm', re.I)
ALLOWED = {'README.md', 'docs/history/composition.md', 'docs/history/stateless-profile.md', 'docs/status.md',
           'verification/standalone.py',
           # The frozen `other_typ` vector is a token of another profile's type.
           'verification/generate_vectors.py',
           # Provenance of the ported TPM signer.
           'crates/garrett-stateless/src/tpm.rs'}
# Wire-visible strings scheduled for a deliberate rename (docs/status.md, item 1).
PENDING_RENAME = {
    'crates/garrett-stateless-core/src/proxy_http.rs', 'src/garrett_stateless/core/proxy_http.py',
    'tests/vectors/proxy-http-refusal-v1.tsv', 'proofs/GarrettProxyResponse.lean',
}


def step(title: str, argv: list, cwd: Path, logs: Path, env: dict | None = None, timeout: int = 7200,
         echo: bool = False) -> None:
    """Run one step, writing its output to a log (and to stdout if `echo`)."""
    log = logs / (re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-') + '.log')
    print(f'== {title} (log: {log})', flush=True)
    started = time.monotonic()
    with log.open('w') as sink:
        process = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        timer = threading.Timer(timeout, process.kill)
        timer.start()
        try:
            last = ''
            for line in process.stdout:
                sink.write(line)
                sink.flush()
                if line.strip():
                    last = line.strip()
                if echo:
                    print(f'   {line.rstrip()}', flush=True)
            code = process.wait()
        finally:
            timer.cancel()
    elapsed = time.monotonic() - started
    if code != 0:
        print(''.join(log.read_text().splitlines(keepends=True)[-80:]))
        raise SystemExit(f'failed after {elapsed:.0f}s (exit {code}): {title}')
    print(f'   ok in {elapsed:.0f}s: {last[:160]}', flush=True)


def origin_mentions(tree: Path) -> list[str]:
    found = []
    for path in sorted(tree.rglob('*')):
        relative = str(path.relative_to(tree))
        if not path.is_file() or relative in ALLOWED or relative in PENDING_RENAME:
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        found += [f'{relative}:{n}' for n, line in enumerate(text.splitlines(), 1) if ORIGIN.search(line)]
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--keep', action='store_true', help='keep the copy for inspection')
    parser.add_argument('--skip-proofs', action='store_true', help='skip extraction, Lean and mutants')
    parser.add_argument('--skip-mutants', action='store_true', help='skip only the mutation campaign')
    parser.add_argument('--jobs', type=int, help='mutants checked at once (verification/mutate.py --jobs)')
    args = parser.parse_args()
    scratch = Path(tempfile.mkdtemp(prefix='garrett-standalone-'))
    tree = scratch / 'garrett'
    try:
        shutil.copytree(ROOT, tree, ignore=IGNORED)
        logs = scratch / 'logs'
        logs.mkdir()
        print(f'copied to {tree}', flush=True)
        mentions = origin_mentions(tree)
        if mentions:
            raise SystemExit('the tree still names its origin:\n  ' + '\n  '.join(mentions))
        print('== no source names the origin project')
        step('cargo build', ['cargo', 'build', '--locked', '--all-targets'], tree, logs)
        step('cargo test', ['cargo', 'test', '--locked'], tree, logs)
        step('cargo test --features tpm', ['cargo', 'test', '--locked', '--features', 'tpm',
                                           '--target-dir', 'target/tpm'], tree, logs)
        venv = scratch / 'venv'
        step('virtual environment', [sys.executable, '-m', 'venv', venv], scratch, logs)
        python = venv / 'bin' / 'python'
        step('pip install', [python, '-m', 'pip', 'install', '-q', '.[tests]'], tree, logs)
        step('python -m pytest', [python, '-m', 'pytest', '-q', '-p', 'no:cacheprovider'], tree, logs)
        step('python -m build', [python, '-m', 'build', '-q', '--outdir', scratch / 'dist'], tree, logs)
        step('shell guard', [python, 'verification/shell_guard.py', 'check'], tree, logs)
        if not args.skip_proofs:
            archive = ROOT / '.tools' / 'aeneas-linux-x86_64.tar.gz'
            boot = [python, 'verification/toolchain.py', 'bootstrap']
            if archive.is_file():
                boot += ['--archive', archive]
            step('toolchain bootstrap', boot, tree, logs)
            step('extraction matches the Rust', [python, 'verification/extract.py', 'check'], tree, logs)
            step('lake build', ['lake', 'build'], tree / 'proofs', logs, timeout=14400)
            if not args.skip_mutants:
                mutate = [python, 'verification/mutate.py']
                if args.jobs:
                    mutate += ['--jobs', args.jobs]
                step('mutation campaign', mutate, tree, logs, timeout=28800, echo=True)
        print(f'standalone check passed in {tree}')
        return 0
    finally:
        if args.keep:
            print(f'kept {scratch}')
        else:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(main())
