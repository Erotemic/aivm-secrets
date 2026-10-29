"""The pinned Rust, Charon/Aeneas and Lean toolchain for this project.

``python verification/toolchain.py bootstrap`` installs the Aeneas release
bundle into ``.tools/aeneas`` (checked against its SHA-256), the Rust nightly
Charon needs and the Lean toolchain, then fetches Mathlib's build cache.
``--archive PATH`` reuses an already-downloaded copy of the same bundle; its
SHA-256 is still checked. Requires Python 3.12+, curl, tar, rustup and elan.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOFS = ROOT / 'proofs'
TOOLS = ROOT / '.tools/aeneas'
RUST = 'nightly-2026-09-17'
LEAN = 'leanprover/lean4:v4.35.0'
RELEASE = 'nightly-2026.10.16-d95aeac'
ARCHIVE_SHA256 = '664e9ccadbeac9eb28284c1a89d1d587725596630c06f980451514a6d478d3cf'
URL = f'https://github.com/AeneasVerif/aeneas/releases/download/{RELEASE}/aeneas-linux-x86_64.tar.gz'


def executable(name: str) -> str:
    selected = shutil.which(name)
    if selected:
        return selected
    for directory in ['.cargo/bin', '.elan/bin']:
        candidate = Path.home() / directory / name
        if candidate.is_file():
            return str(candidate)
    raise SystemExit(f'{name} is required; install its toolchain manager first')


def run(argv: list[str | Path], *, cwd: Path = ROOT, capture: bool = False, check: bool = True,
        quiet: bool = False, timeout: int = 3600) -> subprocess.CompletedProcess:
    args = [str(arg) for arg in argv]
    if not quiet:
        print('+ ' + shlex.join(args), flush=True)
    env = dict(os.environ)
    env['PATH'] = os.pathsep.join([str(Path(executable('cargo')).parent),
                                   str(Path(executable('lake')).parent), env.get('PATH', '')])
    return subprocess.run(args, cwd=cwd, env=env, capture_output=capture, text=True, check=check,
                          timeout=timeout)


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def bootstrap(archive_source: Path | None) -> None:
    if sys.platform != 'linux' or os.uname().machine != 'x86_64':
        raise SystemExit('the pinned Aeneas bundle supports Linux x86_64 only')
    archive = ROOT / '.tools/aeneas-linux-x86_64.tar.gz'
    archive.parent.mkdir(exist_ok=True)
    if not archive.exists():
        partial = archive.with_suffix('.part')
        if archive_source is not None:
            shutil.copyfile(archive_source, partial)
        else:
            run([executable('curl'), '--fail', '--location', '--output', partial, URL])
        if sha256(partial) != ARCHIVE_SHA256:
            raise SystemExit('the Aeneas archive has the wrong SHA-256')
        partial.replace(archive)
    if sha256(archive) != ARCHIVE_SHA256:
        raise SystemExit('the Aeneas archive has the wrong SHA-256')
    if not TOOLS.exists():
        # Publish the installation only after extraction succeeds, so an
        # interrupted setup never leaves a directory mistaken for a full bundle.
        with tempfile.TemporaryDirectory(prefix='aeneas-install-', dir=archive.parent) as path:
            installation = Path(path)
            run(['tar', '-xzf', archive, '-C', installation])
            if not all((installation / name).is_file() for name in ['aeneas', 'charon', 'charon-driver']):
                raise SystemExit('the Aeneas bundle is incomplete')
            installation.rename(TOOLS)
    run([executable('rustup'), 'toolchain', 'install', RUST, '--profile', 'minimal',
         '--component', 'rustc-dev,rust-src,llvm-tools'])
    run([executable('elan'), 'run', '--install', LEAN, 'lean', '--version'])
    # The committed Lake manifest fixes the revisions; do not run lake update.
    run([executable('lake'), 'exe', 'cache', 'get'], cwd=PROOFS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='action', required=True)
    boot = sub.add_parser('bootstrap')
    boot.add_argument('--archive', type=Path, help='an already-downloaded copy of the pinned bundle')
    args = parser.parse_args()
    bootstrap(args.archive)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
