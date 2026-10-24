#!/usr/bin/env python3
"""Run AIVM's secrets-adapter tests against this checkout's package.

AIVM still carries its own copy of `aivm_secrets`, so its test suite tests
that copy, not this repository. This check takes AIVM at the commit pinned in
`dev/compat/aivm.json`, removes the in-tree copy *in a temporary checkout
only*, and runs the tests of AIVM's adapter modules (`aivm.secrets_*`,
`aivm vm identity_*`) against `aivm_secrets` as installed from here. Package
internals are tested in this repository, not here.

    python dev/aivm_compat.py [--aivm-repo PATH_OR_URL] [--ref REF]

The interpreter must have this package and AIVM's dependencies installed.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / 'dev/compat/aivm.json').read_text())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aivm-repo', default=PIN['repository'])
    parser.add_argument('--ref', default=PIN['ref'])
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix='aivm-compat-') as temporary:
        checkout = Path(temporary) / 'aivm'
        subprocess.run(['git', 'clone', '--quiet', '--no-checkout', args.aivm_repo,
                        str(checkout)], check=True)
        subprocess.run(['git', '-C', str(checkout), 'checkout', '--quiet', args.ref],
                       check=True)
        # Test the real package, not AIVM's stale copy.
        shutil.rmtree(checkout / 'aivm_secrets', ignore_errors=True)
        found = subprocess.run(
            [sys.executable, '-c', 'import aivm_secrets, sys; sys.stdout.write(aivm_secrets.__file__)'],
            cwd=checkout, capture_output=True, text=True, check=True).stdout
        if not Path(found).is_relative_to(ROOT) and 'site-packages' not in found:
            print(f'aivm_secrets resolves to {found}, not this package', file=sys.stderr)
            return 2
        tests = [name for name in PIN['tests'] if (checkout / name).is_file()]
        missing = sorted(set(PIN['tests']) - set(tests))
        if missing:
            print('not present at this AIVM ref: ' + ', '.join(missing), file=sys.stderr)
        result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                                 *tests], cwd=checkout)
        return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
