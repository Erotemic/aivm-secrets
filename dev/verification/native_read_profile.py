#!/usr/bin/env python3
"""NR-0: pin the selected offline native-read configuration and record evidence.

This is an evidence *inventory* and acceptance runner, not a proof of guest
isolation, complete Rust I/O reachability, or native-to-Lean simulation.

Default: structural profile/fingerprint review only (no Rust/Lean required).
--portable: existing quick W6 source/oracle gate.
--native: selected real Rust + local TLS/provider witnesses; skips are fatal.
--lean: focused kernel compilation of read path/prefix proofs (no axiom dump).
--build: optional incremental native build, only with --native.
--output: write a JSON run record even when an acceptance stage fails.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path('docs/planning/aivm-secrets-native-read-nr0.json')
W0 = Path('docs/planning/aivm-secrets-w0-boundaries.json')
ASSUMPTIONS = Path('docs/planning/aivm-secrets-assumptions.json')
FIXTURE = Path('tests/test_rust_garrett_manifest.py')

# Select existing REAL Rust process cases; do not accept Python-only substitutes.
# Grouped by independent evidence obligation, not by test file.
NATIVE_WITNESSES = {
    'selected-positive-read': [
        'tests/test_rust_w6_adapter.py::test_w6_native_no_preflight_pagination_is_exact_selected_guest_release',
        'tests/test_rust_w6_adapter.py::test_w6_native_preflight_only_check_release_has_no_final_send',
    ],
    'denied-write-and-invalid-request': [
        'tests/test_rust_garrett_manifest.py::test_no_provider_call_for_denied_arguments_or_declared_write',
    ],
    'provider-error-not-disclosed': [
        'tests/test_rust_w6_adapter.py::test_w6_failed_final_read_private_diagnostics_are_invisible',
    ],
    'audited-but-unsent': [
        'tests/test_rust_w6_pending.py::test_native_untrusted_provider_ca_leaves_audited_but_unsent_read',
        'tests/test_rust_w6_pending.py::test_native_late_remote_revocation_never_emits_pending_read',
    ],
    'sequential-history': [
        'tests/test_rust_w6_adapter.py::test_w6_native_two_sequential_reads_refine_one_complete_session_audit',
    ],
    'guest-control-verbs-and-binding': [
        'tests/test_rust_garrett_manifest.py::test_manifest_keeps_actual_peer_binding_and_renunciation',
    ],
}


class ProfileError(ValueError):
    """The selected profile or its evidence failed a stated acceptance rule."""


def insist(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_file(path: Path) -> dict:
    value = json.loads(path.read_text())
    insist(type(value) is dict, f'{path}: expected JSON object')
    return value


def fixture_profile(source: str) -> dict:
    """Read the actual fixture call shape, not just a nearby reassuring comment."""
    module = ast.parse(source)
    classes = [node for node in module.body
               if isinstance(node, ast.ClassDef) and node.name == 'ManifestCase']
    insist(len(classes) == 1, 'missing or duplicate native ManifestCase fixture')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
               and node.name == '__init__']
    insist(len(methods) == 1, 'ManifestCase initializer changed')
    calls = [node for node in ast.walk(methods[0]) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == '__init__'
             and isinstance(node.func.value, ast.Call)
             and isinstance(node.func.value.func, ast.Name)
             and node.func.value.func.id == 'super']
    insist(len(calls) == 1, 'native fixture no longer has one super().__init__')
    keywords = {item.arg: item.value for item in calls[0].keywords if item.arg}
    assert_exact = {'profile': 'manifest-https-v1', 'request_limit': 'unbounded'}
    for key, expected in assert_exact.items():
        node = keywords.get(key)
        insist(isinstance(node, ast.Constant) and node.value == expected,
               f'ManifestCase {key} differs from selected native read profile')
    writes = keywords.get('writes')
    insist(isinstance(writes, ast.Call) and isinstance(writes.func, ast.Attribute)
           and writes.func.attr == 'pop'
           and isinstance(writes.func.value, ast.Name)
           and writes.func.value.id == 'changes'
           and len(writes.args) == 2
           and isinstance(writes.args[0], ast.Constant)
           and writes.args[0].value == 'writes'
           and isinstance(writes.args[1], ast.Constant)
           and writes.args[1].value == 'deny',
           'ManifestCase must default to writes=deny (caller override remains possible)')
    return {'profile': 'manifest-https-v1', 'writes_default': 'deny',
            'request_limit': 'unbounded', 'writes_override_possible': True}


def review(root: Path = ROOT, manifest: dict | None = None) -> dict:
    """Check exact reviewed sources, W0 sink coverage and witness selection."""
    manifest = manifest if manifest is not None else json_file(root / MANIFEST)
    w0 = json_file(root / W0)
    assumptions = json_file(root / ASSUMPTIONS)
    insist(manifest.get('schema') == 1, 'NR-0 profile schema changed')
    insist(manifest.get('scope') == 'native-manifest-read-sequential-nr0-v1',
           'profile scope changed without review')
    insist(manifest.get('assurance_state') == 'reproducibility-baseline-not-refinement',
           'profile source guard cannot certify whole-service refinement')
    insist(manifest.get('w0_contract') == W0.as_posix(), 'W0 reference changed')
    primary = next((p for p in w0.get('profiles', []) if p.get('id') == 'native-manifest'), None)
    insist(primary is not None and set(primary['guest_verbs']) ==
           {'request', 'describe', 'renounce'}, 'native guest entry set changed')
    fixture = fixture_profile((root / FIXTURE).read_text())
    insist(manifest.get('fixture_contract') == fixture, 'fixture selection changed')

    files = manifest.get('source_sha256')
    insist(isinstance(files, dict) and len(files) >= 16,
           'incomplete pinned Rust/Lean/harness source inventory')
    insist(all(isinstance(name, str) and name.startswith(('rust/', 'proofs/', 'tests/'))
               and '..' not in Path(name).parts for name in files),
           'unsafe or unrecognized pinned path')
    drift = []
    for filename, expected in files.items():
        candidate = (root / filename).resolve()
        insist(candidate.is_relative_to(root.resolve()) and candidate.is_file(),
               f'missing pinned source: {filename}')
        insist(isinstance(expected, str) and len(expected) == 64,
               f'invalid pinned hash: {filename}')
        if sha(candidate) != expected:
            drift.append(filename)
    insist(not drift, 'NR-0 pinned source drift (review and update manually): '
           + ', '.join(drift))
    rust_pin = tomllib.loads((root / 'rust/rust-toolchain.toml').read_text())['toolchain']['channel']
    lean_pin = (root / 'proofs/lean-toolchain').read_text().strip()
    insist(manifest.get('toolchains') == {'rust': rust_pin, 'lean': lean_pin},
           'toolchain pins changed')
    sink_rows = manifest.get('sink_dispositions', {})
    ids = {s['id'] for s in w0.get('sinks', [])}
    insist(set(sink_rows) == ids, 'W0 sink inventory changed: '
           f'missing={sorted(ids - set(sink_rows))}, stale={sorted(set(sink_rows) - ids)}')
    allowed = {'included-evidence-partial', 'included-unresolved',
               'configuration-disabled-not-proven-unreachable', 'host-only-assumption'}
    required_classes = {
        'S-GUEST-FRAME': 'included-evidence-partial',
        'S-GUEST-CLOSE': 'included-unresolved',
        'S-PROVIDER-HTTPS': 'included-evidence-partial',
        'S-HOST-AUDIT': 'included-evidence-partial',
        'S-HOST-STDOUT': 'included-unresolved',
        'S-HOST-STDERR': 'included-unresolved',
        'S-LEGACY-UNIX': 'configuration-disabled-not-proven-unreachable',
        'S-COORDINATOR-HTTPS': 'configuration-disabled-not-proven-unreachable',
        'S-WRITE-APPROVAL-CONTROL': 'configuration-disabled-not-proven-unreachable',
    }
    for key, expected_class in required_classes.items():
        insist(isinstance(sink_rows[key], dict) and
               sink_rows[key].get('class') == expected_class,
               f'{key}: critical sink was silently reclassified')
    for key, disposition in sink_rows.items():
        insist(type(disposition) is dict and disposition.get('class') in allowed
               and isinstance(disposition.get('basis'), str) and disposition['basis'].strip()
               and isinstance(disposition.get('open_obligation'), str)
               and disposition['open_obligation'].strip(),
               f'{key}: missing reviewed scope, basis or open obligation')
    listed_assumptions = {row['id'] for row in assumptions.get('assumptions', [])}
    insist(set(manifest.get('assumptions', [])) <= listed_assumptions,
           'NR-0 invented a W0 trust assumption')
    insist({'RUST-AUDIT-01', 'RUST-HTTPS-01', 'RUST-MTLS-01', 'ENV-GUEST-01'} <=
           set(manifest.get('assumptions', [])), 'missing core trust assumptions')
    insist(manifest.get('native_witnesses') == NATIVE_WITNESSES,
           'test selection changed without NR-0 review')
    selected = [node for nodes in NATIVE_WITNESSES.values() for node in nodes]
    insist(len(selected) == len(set(selected)), 'duplicate native acceptance witness')
    for node in selected:
        relative, separator, test = node.partition('::')
        insist(separator == '::' and test.startswith('test_')
               and (root / relative).is_file()
               and ('def ' + test + '(') in (root / relative).read_text(),
               f'missing native witness: {node}')
    insist(manifest.get('unproved_obligations') == [
        'NR-1-production-extraction', 'NR-2-Rust-Lean-simulation',
        'NR-3-transitive-I-O-and-dependency-effects',
        'NR-4-adaptive-guest-observation', 'NR-5-independent-review',
    ], 'an unproved assurance obligation was silently removed')
    return {'scope': manifest['scope'], 'pinned_sources': len(files),
            'w0_sinks': len(ids), 'native_witness_groups': len(NATIVE_WITNESSES),
            'native_selected_nodes': len(selected), 'fixture_contract': fixture,
            'status': 'source-and-inventory-reviewed; not a security proof'}


def git_snapshot(root: Path) -> dict:
    result: dict = {}
    for key, args in [('commit', ['rev-parse', 'HEAD']),
                      ('status', ['status', '--porcelain=v1', '--untracked-files=no'])]:
        try:
            done = subprocess.run(['git', '-c', f'safe.directory={root}', *args],
                                  cwd=root, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            result[key] = None
        else:
            result[key] = done.stdout.strip() if done.returncode == 0 else None
    return result


def native_binaries(root: Path, env: dict[str, str]) -> dict:
    """Hash the actual Rust processes and reject obviously stale executables.

    Uses W3's reviewed source list for an mtime guard. This is intentionally
    not a compiler/source equivalence theorem or a reproducible-build claim.
    """
    # Running this file as `python dev/verification/native_read_profile.py`
    # puts dev/verification, not the repository root, on sys.path. Both the
    # script and `python -m dev.verification.native_read_profile` are supported.
    if __package__:
        from . import w3_effect_boundary, quick_w6_read
    else:
        import w3_effect_boundary
        import quick_w6_read
    newest_source = max((root / name).stat().st_mtime_ns
                        for name in w3_effect_boundary.rust_sources(root))
    record = {}
    for variable, binary in quick_w6_read.BINARIES.items():
        path = (root / 'rust' / 'target' / 'debug' / binary).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ProfileError(f'missing native {path}; run --native --build once')
        if path.stat().st_mtime_ns < newest_source:
            raise ProfileError(f'stale native {path}; rerun with --native --build')
        env[variable] = str(path)
        record[variable] = {'path': str(path.relative_to(root.resolve())),
                            'sha256': sha(path), 'size_bytes': path.stat().st_size}
    return record


def execute(label: str, command: list[str], env: dict[str, str],
            cwd: Path = ROOT, *, timeout: int = 180) -> dict:
    print(f'[NR-0] {label}: ' + ' '.join(command), flush=True)
    start = time.monotonic()
    try:
        # Capture output in the evidence record, but do not save secrets or
        # process environment variables. Report only bounded diagnostic tails.
        result = subprocess.run(command, env=env, cwd=cwd, text=True,
                                capture_output=True, timeout=timeout)
        row = {'status': 'passed' if result.returncode == 0 else 'failed',
               'exit_code': result.returncode, 'elapsed_seconds': round(time.monotonic()-start, 2)}
        # Only the pytest count, not unbounded subprocess logs, is retained on
        # successful runs. Full output stays on the calling terminal only if
        # deliberately requested in an independent test execution.
        summaries = re.findall(
            r'(?m)^\d+ passed(?:, \d+ failed)?(?:, \d+ skipped)? in \d+(?:\.\d+)?s$',
            result.stdout)
        if summaries:
            row['pytest_summary'] = summaries[-1]
        if result.returncode:
            row['diagnostic_tail'] = '\n'.join((result.stdout + '\n' + result.stderr).splitlines()[-35:])[-3500:]
    except subprocess.TimeoutExpired:
        row = {'status': 'failed', 'reason': 'timeout', 'elapsed_seconds': round(time.monotonic()-start, 2)}
    except OSError as error:
        row = {'status': 'failed', 'reason': type(error).__name__ + ': ' + str(error)}
    print(f'[NR-0] {label}: {row["status"]}', flush=True)
    return row


def native_acceptance(root: Path, env: dict[str, str]) -> dict:
    with tempfile.TemporaryDirectory(prefix='garrett-nr0-') as temp:
        report = Path(temp) / 'test-results.xml'
        selected = [node for group in NATIVE_WITNESSES.values() for node in group]
        result = execute('native-local-tls-witnesses', [
            sys.executable, '-m', 'pytest', '-q', '-ra', '--junitxml', str(report), *selected,
        ], env, root, timeout=420)
        if report.is_file():
            try:
                tests = list(ET.parse(report).iter('testcase'))
            except ET.ParseError:
                result['status'] = 'failed'
                result['reason'] = 'malformed native JUnit evidence'
                return result
            result['cases'] = len(tests)
            result['skips'] = sum(case.find('skipped') is not None for case in tests)
            result['failures'] = sum(case.find('failure') is not None or case.find('error') is not None
                                     for case in tests)
            if not tests or result['skips'] or result['failures']:
                result['status'] = 'failed'
                result['reason'] = 'native acceptance requires non-skipped passing Rust cases'
        else:
            result['status'] = 'failed'
            result['reason'] = 'no native JUnit evidence was produced'
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--portable', action='store_true', help='Run existing quick W6 source/oracle suite')
    parser.add_argument('--native', action='store_true', help='Run real Rust/local HTTPS witnesses, no skips')
    parser.add_argument('--lean', action='store_true', help='Compile scoped Lean proofs without routine axiom auditing')
    parser.add_argument('--build', action='store_true', help='Incremental Cargo build before --native')
    parser.add_argument('--output', type=Path, help='Write machine-readable evidence JSON to this path')
    args = parser.parse_args()
    if args.build and not args.native:
        parser.error('--build requires --native')
    env = dict(os.environ)
    env['PYTHONPATH'] = str(ROOT)
    report = {'schema': 1, 'campaign': 'NR-0',
              'generated_at_utc': datetime.now(timezone.utc).isoformat(),
              'host': {'python': platform.python_version(), 'system': platform.system(),
                       'machine': platform.machine()},
              'git': git_snapshot(ROOT), 'stages': {}}
    verdict = 0
    try:
        summary = review(ROOT)
        report['review'] = summary
        report['manifest_sha256'] = sha(ROOT / MANIFEST)
        report['toolchains'] = json_file(ROOT / MANIFEST)['toolchains']
        report['stages']['profile'] = {'status': 'passed'}
    except (ProfileError, OSError, ValueError, SyntaxError, KeyError) as error:
        report['stages']['profile'] = {'status': 'failed', 'reason': str(error)}
        verdict = 1
    if verdict == 0 and args.portable:
        report['stages']['portable'] = execute(
            'portable-source-and-W6-oracles',
            [sys.executable, 'dev/verification/quick_w6_read.py'], env, timeout=180)
        verdict |= report['stages']['portable']['status'] != 'passed'
    if verdict == 0 and args.native:
        if args.build:
            env['RUSTUP_TOOLCHAIN'] = tomllib.loads(
                (ROOT / 'rust/rust-toolchain.toml').read_text())['toolchain']['channel']
            report['stages']['build'] = execute('incremental-Cargo-build', [
                'cargo', 'build', '--locked', '--manifest-path', 'rust/Cargo.toml',
                '--bins', '--features', 'conformance,coordinator-server',
            ], env, timeout=900)
            verdict |= report['stages']['build']['status'] != 'passed'
        if verdict == 0:
            try:
                report['native_binaries'] = native_binaries(ROOT, env)
            except (OSError, RuntimeError, ValueError) as error:
                report['stages']['native'] = {'status': 'failed', 'reason': str(error)}
                verdict = 1
        if verdict == 0:
            report['stages']['native'] = native_acceptance(ROOT, env)
            verdict |= report['stages']['native']['status'] != 'passed'
    if verdict == 0 and args.lean:
        report['stages']['lean'] = execute('read-path-and-prefix-kernel-proofs', [
            sys.executable, 'dev/verification/read_prefixes.py', 'prove',
        ], env, timeout=240)
        verdict |= report['stages']['lean']['status'] != 'passed'
    report['status'] = 'failed' if verdict else ('evidence-collected-not-whole-service-proof'
                          if (args.native and args.lean) else 'partial-evidence')
    report['unrun'] = [name for name, condition in [
        ('portable', args.portable), ('native', args.native), ('lean', args.lean),
    ] if not condition or name not in report['stages']]
    if args.output is not None:
        path = args.output.expanduser().absolute()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(f'[NR-0] evidence: {path}', flush=True)
    print(json.dumps({'status': report['status'],
                      'stages': {k:v['status'] for k,v in report['stages'].items()},
                      'unrun': report['unrun']}, sort_keys=True), flush=True)
    return int(bool(verdict))


if __name__ == '__main__':
    raise SystemExit(main())
