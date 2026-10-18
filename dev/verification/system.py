#!/usr/bin/env python3
"""Run the synthetic usable-system gate with explicit native Rust backends.

No VM, TPM, live provider credential, or AIVM installation is required. Optional
TPM tests remain separate. Passing establishes the listed checks, not complete
Python/Rust parity, adapter refinement, or a whole-service confidentiality proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_TESTS = [
    'tests/test_secrets_w1_github_workflow.py',
    'tests/test_rust_w2_github_workflow.py',
    'tests/test_rust_w5_noninterference.py',
    'tests/test_rust_w6_adapter.py',
    'tests/test_assurance_profiles.py',
    'tests/test_rust_garrett_authority.py::test_tpm_requirement_rejects_software_before_credential_custody',
]


def require_no_skips(report: Path) -> int:
    """A missing backend must fail this gate, even if pytest reports success."""
    root = ET.parse(report).getroot()
    skipped = [case.get('name', '?') for case in root.iter('testcase')
               if case.find('skipped') is not None]
    failed = [case.get('name', '?') for case in root.iter('testcase')
              if case.find('failure') is not None or case.find('error') is not None]
    if failed:
        raise RuntimeError('Required workflow tests failed: ' + ', '.join(failed))
    if skipped:
        raise RuntimeError('Required workflow tests skipped: ' + ', '.join(skipped))
    cases = list(root.iter('testcase'))
    if not cases:
        raise RuntimeError('Workflow gate collected no tests')
    return len(cases)


def source_fingerprint() -> dict[str, str]:
    """Hash Git-visible inputs, including new files, without reading ignored state."""
    paths = subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT
    ).decode().split('\0')
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in sorted(set(paths)) if name and (ROOT / name).is_file()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proofs', action='store_true',
                        help='Also compile the pinned W4/W5 Lean dependency chain.')
    parser.add_argument('--full-tests', action='store_true',
                        help='Also run the full portable suite with native conformance runners.')
    args = parser.parse_args()
    # Every invocation retains its logs; parallel checkouts cannot reuse a report.
    (ROOT / '.tools').mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='system-', dir=ROOT / '.tools'))
    manifest = dict(schema=1, status='running', steps=[],
                    source_commit=subprocess.check_output(
                        ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    source_dirty=bool(subprocess.check_output(
                        ['git', 'status', '--porcelain'], cwd=ROOT)),
                    scope='synthetic usable workflow; not full protocol parity',
                    input_sha256=source_fingerprint())
    report = output / 'report.json'
    env = dict(os.environ)
    env['PYTHONPATH'] = str(ROOT)
    env['RUSTUP_TOOLCHAIN'] = tomllib.loads(
        (ROOT / 'rust/rust-toolchain.toml').read_text())['toolchain']['channel']
    env['ELAN_TOOLCHAIN'] = (ROOT / 'proofs/lean-toolchain').read_text().strip()
    manifest['rust_toolchain'] = env['RUSTUP_TOOLCHAIN']
    manifest['lean_toolchain'] = env['ELAN_TOOLCHAIN']
    python = sys.executable

    def save():
        report.write_text(json.dumps(manifest, indent=2) + '\n')

    def run(name, command):
        print(name, flush=True)
        started = time.monotonic()
        log = output / (name + '.log')
        with log.open('w') as stream:
            result = subprocess.run(command, cwd=ROOT, env=env,
                                    stdout=stream, stderr=subprocess.STDOUT)
        manifest['steps'].append(dict(name=name, command=command,
                                      seconds=round(time.monotonic() - started, 3),
                                      exit_code=result.returncode, log=str(log)))
        save()
        if result.returncode:
            print(log.read_text()[-16000:], file=sys.stderr)
            raise RuntimeError(f'{name} failed; full log: {log}')

    save()
    try:
        run('native-build', ['cargo', 'build', '--locked', '--manifest-path',
                            'rust/Cargo.toml', '--bins', '--features', 'conformance'])
        # Import only the existing runner registry; do not substitute a Python
        # implementation when a binary is absent or an operation is refused.
        from garrett import RUNNERS
        runners = dict(RUNNERS, AIVM_SECRETS_FRESHNESS_RUNNER='freshness-conformance')
        for variable, binary in runners.items():
            path = ROOT / 'rust/target/debug' / binary
            if not path.is_file() or not os.access(path, os.X_OK):
                raise RuntimeError(f'Missing native runner: {path}')
            env[variable] = str(path)
        run('rust-unit', ['cargo', 'test', '--locked', '--manifest-path',
                          'rust/Cargo.toml', '--workspace', '--features', 'conformance'])
        for script in ['w0_contract', 'w3_effect_boundary', 'w6_adapter']:
            run(script, [python, f'dev/verification/{script}.py', 'check'])
        with tempfile.TemporaryDirectory(prefix='as-system-', dir='/tmp') as temporary:
            junit = output / 'workflows.xml'
            run('workflows', [python, '-m', 'pytest', '-q', '-ra',
                              '--basetemp', str(Path(temporary) / 'tests'),
                              '--junitxml', str(junit), *WORKFLOW_TESTS])
            manifest['required_workflow_tests'] = require_no_skips(junit)
        if args.proofs:
            run('lean-w4-w5', [python, 'dev/verification/w5_noninterference.py', 'prove'])
            run('lean-profiles', ['lake', '-d', 'proofs', 'build', '+GarrettProfiles'])
        if args.full_tests:
            with tempfile.TemporaryDirectory(prefix='as-full-', dir='/tmp') as temporary:
                run('full-python-native', [python, '-m', 'pytest', '-q', '-ra',
                                          '--basetemp', str(Path(temporary) / 'tests')])
        if source_fingerprint() != manifest['input_sha256']:
            raise RuntimeError('Source changed during validation; rerun on a stable snapshot')
        manifest['status'] = 'passed'
        save()
        print(f'Usable-system gate passed. Evidence: {report}', flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        manifest['status'] = 'failed'
        manifest['error'] = str(error)
        save()
        print(f'{error}\nEvidence: {report}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
