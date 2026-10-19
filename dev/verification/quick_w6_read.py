#!/usr/bin/env python3
"""Fast, explicitly scoped offline native-read W6 acceptance gate.

Default: Python source guards and independent release/oracle tests only.
--native: reuse already-built native executables for selected real mTLS/HTTPS
          experiments, refusing skips. Does not invoke Lean, Cargo tests, the
          full Python suite or Charon. Use --build only if binaries need rebuild.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PORTABLE = [
    'tests/test_w6_release_oracle.py',
    'tests/test_rust_w6_adapter.py::test_w6_reference_trace_oracle_rejects_bypass_and_leaks',
    'tests/test_rust_w6_adapter.py::test_w6_reference_oracle_rejects_header_smuggling_and_unselected_release',
    'tests/test_rust_w6_adapter.py::test_w6_arrival_oracle_rejects_reordered_or_postdated_dispatch_audit',
    'tests/test_rust_w6_adapter.py::test_w6_denied_error_messages_are_fixed_public_observations',
]
NATIVE = [
    'tests/test_rust_w6_adapter.py::test_w6_native_no_preflight_pagination_is_exact_selected_guest_release',
    'tests/test_rust_w6_adapter.py::test_w6_native_preflight_only_check_release_has_no_final_send',
    'tests/test_rust_w6_adapter.py::test_w6_audit_is_present_when_each_read_reaches_real_https_provider',
]
# All of these launch real independent Rust processes. No Python-only broker
# substitution can satisfy this profile.
BINARIES = {
    'AIVM_SECRETS_RUST_GARRETT_BRIDGE': 'garrett-bridge',
    'AIVM_SECRETS_RUST_GARRETT_CLIENT': 'garrett-client',
    'AIVM_SECRETS_RUST_AUTHORITY_ADMIN': 'garrett-authority',
}


def checked_run(label: str, command: list[str], env: dict[str, str]) -> None:
    print(label, flush=True)
    start = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if result.returncode:
        raise RuntimeError(f'{label} failed (exit {result.returncode})')
    print(f'{label} passed in {time.monotonic() - start:.1f}s', flush=True)


def require_native_paths(env: dict[str, str]) -> None:
    # Never count last week's Rust executable as today's source observation.
    # Cargo is authoritative for dependency/feature freshness when --build is
    # requested. This local mtime check only catches the common stale-binary
    # case; it is not a cryptographic provenance certificate.
    from w3_effect_boundary import rust_sources
    newest_source = max(
        (ROOT / name).stat().st_mtime_ns for name in rust_sources(ROOT)
    )
    for variable, binary in BINARIES.items():
        path = (ROOT / 'rust' / 'target' / 'debug' / binary).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f'Missing {path}; run with --native --build once')
        if path.stat().st_mtime_ns < newest_source:
            raise RuntimeError(f'Stale native binary: {path}; use --native --build')
        env[variable] = str(path)


def require_no_native_skips(report: Path) -> None:
    tree = ET.parse(report)
    cases = list(tree.iter('testcase'))
    if not cases:
        raise RuntimeError('No tests collected')
    skipped = [case.get('name', '?') for case in cases if case.find('skipped') is not None]
    if skipped:
        raise RuntimeError('Native W6 acceptance skipped: ' + ', '.join(skipped))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', help='Run selected mTLS/Rust process cases')
    parser.add_argument('--build', action='store_true',
                        help='Incrementally rebuild native binaries before --native')
    args = parser.parse_args()
    if args.build and not args.native:
        parser.error('--build requires --native')
    env = dict(os.environ)
    env['PYTHONPATH'] = str(ROOT)
    env['RUSTUP_TOOLCHAIN'] = tomllib.loads(
        (ROOT / 'rust/rust-toolchain.toml').read_text())['toolchain']['channel']
    start = time.monotonic()
    try:
        for name in ('w0_contract', 'w3_effect_boundary', 'w6_adapter'):
            checked_run(name, [sys.executable, f'dev/verification/{name}.py', 'check'], env)
        if args.build:
            checked_run('incremental-native-build', [
                'cargo', 'build', '--locked', '--manifest-path', 'rust/Cargo.toml',
                '--bins', '--features', 'conformance,coordinator-server',
            ], env)
        if args.native:
            require_native_paths(env)
        with tempfile.TemporaryDirectory(prefix='garrett-quick-w6-') as tmp:
            report = Path(tmp) / 'cases.xml'
            checked_run('w6-release-observations', [
                sys.executable, '-m', 'pytest', '-q', '-ra', '--junitxml', str(report),
                *PORTABLE, *(NATIVE if args.native else []),
            ], env)
            if args.native:
                require_no_native_skips(report)
        print(f'Quick W6 read gate passed in {time.monotonic() - start:.1f}s.', flush=True)
        print('Scope: finite read-profile observations, not W4/W5 formal refinement.', flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Quick W6 read gate failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
