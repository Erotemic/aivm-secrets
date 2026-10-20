#!/usr/bin/env python3
"""Fast, explicitly scoped offline native-read W6 acceptance gate.

Default: Python source guards, proof-shape review and release/oracle tests only.
--native: reuse already-built native executables for selected real mTLS/HTTPS
          experiments, refusing skips. Does not invoke Lean, Cargo tests, the
          full Python suite or Charon. --lean additionally runs only the focused
read-path Lean proof and its imports. Use --build only if binaries need rebuild.
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
    'tests/test_w6_history_oracle.py',
    'tests/test_w6_composition.py',
    'tests/test_w6_prefix_proof_scope.py',
    'tests/test_rust_w6_adapter.py::test_w6_reference_trace_oracle_rejects_bypass_and_leaks',
    'tests/test_rust_w6_adapter.py::test_w6_reference_oracle_rejects_header_smuggling_and_unselected_release',
    'tests/test_rust_w6_adapter.py::test_w6_arrival_oracle_rejects_reordered_or_postdated_dispatch_audit',
    'tests/test_rust_w6_adapter.py::test_w6_denied_error_messages_are_fixed_public_observations',
    'tests/test_rust_w6_adapter.py::test_w6_paired_trace_requires_explicit_host_release_and_metadata',
    'tests/test_rust_w6_adapter.py::test_w6_paired_trace_forwards_independent_release_expectations',
]
NATIVE = [
    'tests/test_rust_w6_adapter.py::test_w6_native_no_preflight_pagination_is_exact_selected_guest_release',
    'tests/test_rust_w6_adapter.py::test_w6_native_preflight_only_check_release_has_no_final_send',
    'tests/test_rust_w6_adapter.py::test_w6_native_two_sequential_reads_refine_one_complete_session_audit',
    'tests/test_rust_w6_adapter.py::test_w6_audit_is_present_when_each_read_reaches_real_https_provider',
    'tests/test_rust_w6_adapter.py::test_w6_two_run_no_preflight_private_provider_mutation_is_invisible',
    'tests/test_rust_w6_adapter.py::test_w6_two_run_checked_only_private_fact_mutation_is_invisible',
    'tests/test_rust_w6_adapter.py::test_w6_two_run_two_phase_private_preflight_mutation_is_invisible',
]
FAILURE_PORTABLE = [
    'tests/test_w6_failure_oracle.py',
    'tests/test_w6_error_boundary.py',
]
PENDING_PORTABLE = [
    'tests/test_w6_pending_oracle.py',
    'tests/test_w6_pending_boundary.py',
]
PENDING_NATIVE = [
    'tests/test_rust_w6_completion.py',
    'tests/test_rust_w6_pending.py',
]
FAILURE_NATIVE = [
    'tests/test_rust_w6_adapter.py::test_w6_failed_final_read_private_diagnostics_are_invisible',
    'tests/test_rust_w6_adapter.py::test_w6_failed_final_read_malformed_private_representation_is_invisible',
    'tests/test_rust_w6_adapter.py::test_w6_failed_preflight_only_diagnostics_are_invisible',
    'tests/test_rust_w6_adapter.py::test_w6_failed_two_phase_final_response_diagnostics_are_invisible',
]
# All of these launch real independent Rust processes. No Python-only broker
# substitution can satisfy this profile.
BINARIES = {
    'AIVM_SECRETS_RUST_GARRETT_BRIDGE': 'garrett-bridge',
    'AIVM_SECRETS_RUST_GARRETT_CLIENT': 'garrett-client',
    'AIVM_SECRETS_RUST_AUTHORITY_ADMIN': 'garrett-authority',
}


# The completion-prefix witness explicitly selects the optional native
# coordinator. Other native/device helpers keep their existing three binaries.
COORDINATOR_BINARIES = {
    'AIVM_SECRETS_RUST_COORDINATOR': 'garrett-coordinator',
    'AIVM_SECRETS_RUST_COORDINATOR_CTL': 'garrett-coordinatorctl',
}


def checked_run(label: str, command: list[str], env: dict[str, str]) -> None:
    print(label, flush=True)
    start = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if result.returncode:
        raise RuntimeError(f'{label} failed (exit {result.returncode})')
    print(f'{label} passed in {time.monotonic() - start:.1f}s', flush=True)


def require_native_paths(env: dict[str, str], *, binaries: dict[str, str] | None = None) -> None:
    # Never count last week's Rust executable as today's source observation.
    # Cargo is authoritative for dependency/feature freshness when --build is
    # requested. This local mtime check only catches the common stale-binary
    # case; it is not a cryptographic provenance certificate.
    from w3_effect_boundary import rust_sources
    newest_source = max(
        (ROOT / name).stat().st_mtime_ns for name in rust_sources(ROOT)
    )
    for variable, binary in (BINARIES if binaries is None else binaries).items():
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
    parser.add_argument('--failure-only', action='store_true',
                        help='Run only the new W4/W5 failed-read observations')
    parser.add_argument('--pending-only', action='store_true',
                        help='Run only audited-but-unsent read prefix witnesses')
    parser.add_argument('--composition-only', action='store_true',
                        help='Run only the generic sequential-read prefix tests')
    parser.add_argument('--lean', action='store_true',
                        help='Compile/axiom-audit only new read-path Lean proofs and imports')
    parser.add_argument('--build', action='store_true',
                        help='Incrementally rebuild native binaries before --native')
    args = parser.parse_args()
    if sum((args.failure_only, args.pending_only, args.composition_only)) > 1:
        parser.error('choose at most one --failure-only/--pending-only/--composition-only')
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
        checked_run('w6-public-error-source', [sys.executable,
                    'dev/verification/w6_error_boundary.py', 'check'], env)
        checked_run('w6-pending-source', [sys.executable,
                    'dev/verification/w6_pending_boundary.py', 'check'], env)
        checked_run('w4-w5-read-shape-source', [sys.executable,
                    'dev/verification/read_paths.py', 'check'], env)
        checked_run('w4-w5-read-prefix-source', [sys.executable,
                    'dev/verification/read_prefixes.py', 'check'], env)
        if args.lean:
            checked_run('focused-read-prefix-Lean', [sys.executable,
                        'dev/verification/read_prefixes.py', 'prove'], env)
        if args.build:
            checked_run('incremental-native-build', [
                'cargo', 'build', '--locked', '--manifest-path', 'rust/Cargo.toml',
                '--bins', '--features', 'conformance,coordinator-server',
            ], env)
        if args.native:
            selected = BINARIES
            if not (args.failure_only or args.composition_only):
                selected = selected | COORDINATOR_BINARIES
            require_native_paths(env, binaries=selected)
        portable = (['tests/test_w6_composition.py',
                     'tests/test_w6_prefix_proof_scope.py'] if args.composition_only else
                    PENDING_PORTABLE if args.pending_only else
                    FAILURE_PORTABLE if args.failure_only else
                    PORTABLE + FAILURE_PORTABLE + PENDING_PORTABLE)
        native = ([
                    'tests/test_rust_w6_adapter.py::test_w6_native_two_sequential_reads_refine_one_complete_session_audit'
                  ] if args.composition_only else
                  PENDING_NATIVE if args.pending_only else
                  FAILURE_NATIVE if args.failure_only else
                  NATIVE + FAILURE_NATIVE + PENDING_NATIVE)
        with tempfile.TemporaryDirectory(prefix='garrett-quick-w6-') as tmp:
            report = Path(tmp) / 'cases.xml'
            checked_run('w6-release-observations', [
                sys.executable, '-m', 'pytest', '-q', '-ra', '--junitxml', str(report),
                *portable, *(native if args.native else []),
            ], env)
            if args.native:
                require_no_native_skips(report)
        print(f'Quick W6 read gate passed in {time.monotonic() - start:.1f}s.', flush=True)
        print('Scope: finite native read evidence; source guards are not proof.', flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Quick W6 read gate failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
