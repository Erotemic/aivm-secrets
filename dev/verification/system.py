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
    'tests/test_rust_http_response.py',
    'tests/test_rust_proxy.py',
    'tests/test_rust_w6_pending.py',
    'tests/test_rust_approval.py::test_existing_python_operator_cli_controls_native_approval',
    'tests/test_rust_approval.py::test_native_exact_write_approval_is_bound_and_one_shot',
    'tests/test_rust_approval.py::test_native_expired_approval_denied_and_new_explicit_approval_works',
    'tests/test_rust_approval.py::test_native_host_revocation_fences_approved_writes_and_guest_control',
    'tests/test_rust_approval.py::test_native_failed_approved_write_never_refunds_authority',
    'tests/test_rust_approval.py::test_native_concurrent_writes_spend_one_approval_once',
    'tests/test_rust_approval.py::test_native_host_revoke_is_responsive_during_provider_io_and_fences_release',
    'tests/test_rust_approval.py::test_native_semantic_write_get_needs_approval_and_reads_preserve_it',
    'tests/test_rust_approval.py::test_native_invalid_host_approval_cannot_authorize',
    'tests/test_rust_approval.py::test_native_guest_cannot_reach_operator_commands_or_create_approval',
    'tests/test_rust_approval.py::test_native_approval_precedes_preflight_and_is_spent_on_failed_preflight',
    'tests/test_rust_approval.py::test_native_approval_requires_separate_private_host_endpoint',

    'tests/test_coordinator_operator.py',
    'tests/test_rust_invoke.py::test_named_read_preserves_python_request_and_provider_effect',
    'tests/test_rust_invoke.py::test_named_read_with_no_arguments',
    'tests/test_rust_invoke.py::test_named_write_keeps_broker_permission_gate',
    'tests/test_rust_invoke.py::test_named_write_reservation_replay_and_terminal_revocation',
    'tests/test_rust_invoke.py::test_malformed_invocation_refused_before_config_or_transport',
    'tests/test_rust_invoke.py::test_argument_file_is_bounded_untrusted_data',
    'tests/test_rust_invoke.py::test_invoke_retains_public_errors_and_invalid_replies_stay_uncertain',

    'tests/test_secrets_w1_github_workflow.py',
    'tests/test_rust_w2_github_workflow.py',
    'tests/test_rust_w5_noninterference.py',
    'tests/test_rust_w6_adapter.py',
    # Offline Python HTTPS adapter regression counterparts to native W6.
    'tests/test_secrets_egress.py::test_a_partial_success_is_not_a_complete_read_or_write',
    'tests/test_secrets_egress.py::test_a_parseable_ambiguous_http_response_cannot_be_released',
    'tests/test_secrets_egress.py::test_a_well_framed_chunked_answer_still_succeeds',
    'tests/test_secrets_egress.py::test_a_parseable_response_must_have_host_selected_media_type',
    'tests/test_secrets_egress.py::test_a_declared_json_response_accepts_charset_parameter',
    'tests/test_secrets_egress.py::test_recording_provider_can_send_duplicate_raw_headers_over_tls',
    'tests/test_secrets_egress.py::test_bodyless_204_is_supported_only_for_declared_text',
    'tests/test_secrets_egress.py::test_204_with_forbidden_body_framing_is_denied',
    'tests/test_assurance_profiles.py',
    'tests/test_rust_garrett_dispatch.py',
    'tests/test_rust_oauth_current_session.py',
    'tests/test_rust_coordination.py',
    'tests/test_rust_coordinator_authority.py',
    'tests/test_rust_bound_renewal.py',
    'tests/test_secrets_primitives_parity.py',
    'tests/test_specialized_calls.py',
    'tests/test_rust_policy_normalization.py',
    'tests/test_rust_http_auth.py',
    'tests/test_rust_http_request.py',
    'tests/test_rust_http_wire.py',
    'tests/test_rust_line_framing.py',
    'tests/test_rust_json_reflection.py::test_actual_manifest_checks_selected_decoded_text_before_release',
    'tests/test_system_package_isolation.py',
    'tests/test_identity_bundle.py',
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


def require_isolated_checkout(python: str, env: dict[str, str]) -> Path:
    """Refuse workflow evidence from an outdated `python -I` installation.

    Some identity/authority tests intentionally use `-I`, which ignores the
    runner's PYTHONPATH. A stale wheel can otherwise be tested alongside the
    current checkout and cause false successes or unrelated CLI failures.
    """
    expected = (ROOT / 'aivm_secrets/identity/cli.py').resolve()
    probe = subprocess.run(
        [python, '-I', '-c',
         'from aivm_secrets.identity import cli; print(cli.__file__)'],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=15,
    )
    observed = probe.stdout.strip()
    if probe.returncode != 0 or not observed or Path(observed).resolve() != expected:
        where = observed if probe.returncode == 0 and observed else 'not importable'
        raise RuntimeError(
            'Isolated Python uses aivm_secrets.identity.cli from '
            f'{where}, not the current checkout {expected}. '
            'The -I flag ignores PYTHONPATH. Reinstall this checkout in the '
            'active environment (uv pip install --python "$(command -v python)" '
            '--no-deps -e .), then rerun '
            'the gate. Do not count mixed installed/source tests as evidence.'
        )
    return expected


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
    parser.add_argument('--call-linkage', action='store_true',
                        help='Also inspect compiler-specialized native callback links (not mediation).')
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
                    proofs_requested=args.proofs, full_tests_requested=args.full_tests,
                    call_linkage_requested=args.call_linkage,
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
        print('isolated-python-source', flush=True)
        manifest['isolated_python_cli_source'] = str(require_isolated_checkout(python, env))
        save()
        run('native-build', ['cargo', 'build', '--locked', '--manifest-path',
                            'rust/Cargo.toml', '--bins', '--features', 'conformance,coordinator-server'])
        # Import only the existing runner registry; do not substitute a Python
        # implementation when a binary is absent or an operation is refused.
        from garrett import RUNNERS
        runners = dict(RUNNERS, AIVM_SECRETS_FRESHNESS_RUNNER='freshness-conformance',
                       AIVM_SECRETS_RUST_PRIMITIVES_RUNNER='primitives-conformance')
        for variable, binary in runners.items():
            path = ROOT / 'rust/target/debug' / binary
            if not path.is_file() or not os.access(path, os.X_OK):
                raise RuntimeError(f'Missing native runner: {path}')
            env[variable] = str(path)
        run('rust-unit', ['cargo', 'test', '--locked', '--manifest-path',
                          'rust/Cargo.toml', '--workspace', '--features', 'conformance,coordinator-server'])
        for script in ['w0_contract', 'w3_effect_boundary', 'w4_trace',
                       'w5_noninterference', 'w6_adapter', 'read_paths', 'read_prefixes']:
            run(script, [python, f'dev/verification/{script}.py', 'check'])
        run('native-read-profile', [python, 'dev/verification/native_read_profile.py'])
        with tempfile.TemporaryDirectory(prefix='as-system-', dir='/tmp') as temporary:
            junit = output / 'workflows.xml'
            run('workflows', [python, '-m', 'pytest', '-q', '-ra',
                              '--basetemp', str(Path(temporary) / 'tests'),
                              '--junitxml', str(junit), *WORKFLOW_TESTS])
            manifest['required_workflow_tests'] = require_no_skips(junit)
        run('offline-native-product', [python, 'dev/offline_native_guest.py'])
        if args.proofs:
            run('lean-read-transition', [python, 'dev/verification/read_transition.py'])
            run('lean-w4-w5', [python, 'dev/verification/w5_noninterference.py', 'prove'])
            run('lean-read-prefixes', [python, 'dev/verification/read_prefixes.py', 'prove'])
            run('lean-profile-emission-oauth', ['lake', '-d', 'proofs', 'build',
                                               '+GarrettProfiles', '+GarrettEmission',
                                               '+GarrettOAuth', '+GarrettCoordination', '+GarrettRetryKey', '+GarrettRebinding', '+GarrettHttpAuth', '+GarrettHttpRequest', '+GarrettHttpWire', '+GarrettLineFrame', '+GarrettBundle', '+GarrettJsonReflection', '+GarrettCoordinatorAuthority', '+GarrettCoordinatorReply', '+GarrettApproval'])
            # The HTTPS proxy profiles, request targets, control verbs and the write gate.
            run('lean-proxy-route-control', ['lake', '-d', 'proofs', 'build',
                                            '+GarrettProxyHttp', '+GarrettProxyResponse',
                                            '+GarrettProxyController', '+GarrettProxyConnect',
                                            '+GarrettRoute', '+GarrettRouteMatch', '+GarrettControl',
                                            '+GarrettWriteGate', '+GarrettPublicFieldNameContract', '+GarrettProxyParse', '+GarrettApprovalStore', '+GarrettProxyTunnel', '+GarrettSessionAudit', '+GarrettProxyAudit', '+GarrettBase64', '+GarrettRouteUnique', '+GarrettServiceHistory', '+GarrettLoginHistory'])
        if args.full_tests:
            with tempfile.TemporaryDirectory(prefix='as-full-', dir='/tmp') as temporary:
                run('full-python-native', [python, '-m', 'pytest', '-q', '-ra',
                                          '--basetemp', str(Path(temporary) / 'tests')])
        # Do this last: Charon inspects the normal-feature target, after all
        # conformance-backed process tests have finished using their binaries.
        if args.call_linkage:
            run('compiler-callback-links', [python, 'dev/verification/specialized_calls.py'])
            run('coordinator-callback-links', [python, 'dev/verification/specialized_calls.py',
                                                '--profile', 'coordinator'])
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
