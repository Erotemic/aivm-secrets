"""Extract `garrett-stateless-core` to Lean with Charon and Aeneas.

    python verification/extract.py write    # regenerate proofs/generated/
    python verification/extract.py check    # fail if the committed file is stale

The generated module, ``proofs/generated/GarrettStatelessCore.lean``, is what
every theorem in ``proofs/`` is about; it is committed so a reviewer can read
it, and ``check`` shows it is exactly what the pinned tools produce from the
current Rust.
"""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import toolchain
from toolchain import PROOFS, ROOT, TOOLS, run

CRATE = 'garrett-stateless-core'
MODULE = 'GarrettStatelessCore.lean'


def extract(destination: Path, workspace: Path = ROOT, quiet: bool = False) -> Path:
    """Extract the crate in `workspace` (this tree, or a mutated copy) into `destination`."""
    if not (TOOLS / 'aeneas').is_file():
        raise SystemExit('the Aeneas tools are missing: run verification/toolchain.py bootstrap')
    run([TOOLS / 'charon', 'cargo', '--preset=aeneas', '--sysroot', 'default', '--', '--lib', '--locked'],
        cwd=workspace / 'crates' / CRATE, capture=quiet, quiet=quiet)
    destination.mkdir(parents=True, exist_ok=True)
    run([TOOLS / 'aeneas', '-backend', 'lean', '-no-progress-bar', '-loops-to-rec', '-abort-on-error',
         '-warnings-as-errors', '-dest', destination, workspace / 'garrett_stateless_core.llbc'],
        capture=quiet, quiet=quiet)
    generated = destination / MODULE
    if not generated.is_file():
        raise SystemExit(f'extraction did not produce {MODULE}')
    return generated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('action', choices=['write', 'check'])
    args = parser.parse_args()
    committed = PROOFS / 'generated' / MODULE
    if args.action == 'write':
        extract(committed.parent)
        print(f'wrote {committed.relative_to(ROOT)} ({toolchain.sha256(committed)})')
        return 0
    with tempfile.TemporaryDirectory(prefix='garrett-extract-', dir=ROOT / '.tools') as scratch:
        fresh = extract(Path(scratch))
        if fresh.read_bytes() != committed.read_bytes():
            raise SystemExit(f'{committed.relative_to(ROOT)} is stale: run extract.py write and review the diff')
    print(f'{committed.relative_to(ROOT)} matches the Rust source')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
