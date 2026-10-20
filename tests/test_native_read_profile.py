"""NR-0 profile drift, sink coverage, witness and evidence integrity regressions.

Portable only. These checks do not validate Rust behavior or prove I/O reachability.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from dev.verification import native_read_profile as nr0


def manifest():
    return json.loads((nr0.ROOT / nr0.MANIFEST).read_text())


def test_actual_profile_baseline_review_is_explicitly_non_proof():
    summary = nr0.review()
    assert summary['w0_sinks'] == 14
    assert summary['pinned_sources'] >= 25
    assert summary['native_witness_groups'] == 6
    assert summary['status'] == 'source-and-inventory-reviewed; not a security proof'
    assert summary['fixture_contract']['writes_override_possible'] is True


def test_fingerprint_mutation_requires_review():
    changed = manifest()
    source = 'rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs'
    changed['source_sha256'][source] = '0' * 64
    with pytest.raises(nr0.ProfileError, match='source drift'):
        nr0.review(manifest=changed)


@pytest.mark.parametrize('mutation', [
    lambda m: m['sink_dispositions'].pop('S-GUEST-CLOSE'),
    lambda m: m['sink_dispositions'].update({'S-NEW-GUEST': {
        'class': 'included-evidence-partial', 'basis': 'unknown', 'open_obligation': 'unknown'}}),
    lambda m: m['sink_dispositions']['S-PROVIDER-HTTPS'].update({'basis': ''}),
])
def test_all_w0_sinks_must_be_explained(mutation):
    changed = manifest()
    mutation(changed)
    with pytest.raises(nr0.ProfileError, match='sink inventory|missing reviewed scope'):
        nr0.review(manifest=changed)


def test_assurance_status_cannot_be_silently_promoted():
    changed = manifest()
    changed['assurance_state'] = 'fully-verified'
    with pytest.raises(nr0.ProfileError, match='whole-service'):
        nr0.review(manifest=changed)


def test_open_obligations_cannot_be_dropped():
    changed = manifest()
    changed['unproved_obligations'].remove('NR-3-transitive-I-O-and-dependency-effects')
    with pytest.raises(nr0.ProfileError, match='silently removed'):
        nr0.review(manifest=changed)


def test_positive_native_witness_cannot_disappear():
    changed = manifest()
    changed['native_witnesses']['selected-positive-read'] = []
    with pytest.raises(nr0.ProfileError, match='test selection'):
        nr0.review(manifest=changed)


def test_fixture_ast_requires_explicit_manifest_and_default_deny():
    source = (nr0.ROOT / nr0.FIXTURE).read_text()
    assert nr0.fixture_profile(source)['writes_default'] == 'deny'
    with pytest.raises(nr0.ProfileError, match='writes=deny'):
        nr0.fixture_profile(source.replace('changes.pop("writes", "deny")',
                                           'changes.pop("writes", "allow")'))
    with pytest.raises(nr0.ProfileError, match='selected native read profile'):
        nr0.fixture_profile(source.replace('profile="manifest-https-v1",',
                                           'profile="account-status-v1",'))


def test_native_acceptance_rejects_skips_and_absent_report(monkeypatch):
    def fake_execute_with_skip(label, command, env, cwd, **kwargs):
        report = Path(command[command.index('--junitxml') + 1])
        root = ET.Element('testsuite')
        case = ET.SubElement(root, 'testcase', name='fake-Rust-test')
        ET.SubElement(case, 'skipped')
        ET.ElementTree(root).write(report)
        return {'status': 'passed', 'exit_code': 0}
    monkeypatch.setattr(nr0, 'execute', fake_execute_with_skip)
    result = nr0.native_acceptance(nr0.ROOT, {})
    assert result['status'] == 'failed'
    assert result['skips'] == 1

    monkeypatch.setattr(nr0, 'execute', lambda *a, **kw: {'status': 'passed'})
    result = nr0.native_acceptance(nr0.ROOT, {})
    assert result['status'] == 'failed'
    assert result['reason'] == 'no native JUnit evidence was produced'


def test_critical_sink_cannot_be_marked_host_only():
    changed = manifest()
    changed['sink_dispositions']['S-PROVIDER-HTTPS']['class'] = 'host-only-assumption'
    with pytest.raises(nr0.ProfileError, match='silently reclassified'):
        nr0.review(manifest=changed)


def test_native_binaries_are_pinned_and_stale_builds_fail(tmp_path, monkeypatch):
    from dev.verification import w3_effect_boundary, quick_w6_read
    source = tmp_path / 'main.rs'
    source.write_text('test')
    monkeypatch.setattr(w3_effect_boundary, 'rust_sources', lambda root: ['main.rs'])
    root = tmp_path / 'rust' / 'target' / 'debug'
    root.mkdir(parents=True)
    env = {}
    for filename in quick_w6_read.BINARIES.values():
        path = root / filename
        path.write_bytes(b'fake executable')
        path.chmod(0o700)
    result = nr0.native_binaries(tmp_path, env)
    assert set(result) == set(quick_w6_read.BINARIES)
    assert all(entry['sha256'] == nr0.sha(root / quick_w6_read.BINARIES[name])
               for name, entry in result.items())
    import os
    now = source.stat().st_mtime + 20
    os.utime(source, (now, now))
    with pytest.raises(nr0.ProfileError, match='stale native'):
        nr0.native_binaries(tmp_path, {})


def test_native_binary_provenance_imports_work_from_script_and_module(tmp_path):
    """Exercise native_binaries without running Cargo, Rust, or TLS tests."""
    import subprocess
    import sys

    root = tmp_path / 'checkout'
    source = root / 'rust' / 'src' / 'entry.rs'
    source.parent.mkdir(parents=True)
    source.write_text('fn main() {}\n')
    for name in ('garrett-bridge', 'garrett-client', 'garrett-authority'):
        target = root / 'rust' / 'target' / 'debug' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('#!/bin/sh\nexit 0\n')
        target.chmod(0o755)

    # When imported by pytest it must work as a package member.
    record = nr0.native_binaries(root, {})
    assert len(record) == 3

    # When run by path, its sibling modules must also be importable.
    code = (
        'import sys; from pathlib import Path; '
        'sys.path.insert(0, sys.argv[1]); '
        'import native_read_profile as nr0; '
        'print(len(nr0.native_binaries(Path(sys.argv[2]), {})))'
    )
    runner = nr0.ROOT / 'dev' / 'verification'
    done = subprocess.run(
        [sys.executable, '-c', code, str(runner), str(root)],
        cwd=nr0.ROOT, capture_output=True, text=True, timeout=10,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == '3'
