#!/usr/bin/env python3
"""Opt-in native CSR, enrollment, TLS and provider witness on /dev/tpmrm0.

Uses synthetic credentials and two initially unused fixture handles. Refuses
occupied handles and verifies that pre-existing public objects are unchanged.
No TPM clear, hierarchy change, global flush or software fallback is used.
This dev-only harness is non-core; it does not establish physical provenance,
EK activation, VM isolation, clone resistance or provider compatibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from garrett import ROOT, RUNNERS
from quick_w6_read import require_native_paths
from system import require_no_skips


def snapshot(device: Path, directory: Path) -> dict[str, str]:
    """Read public areas only; never expose authorization values or key blobs."""
    prefix = ['-Q', '-T', f'device:{device}']
    # getcap's capability list is its ordinary stdout; -Q would erase it and
    # falsely report an empty TPM. Only readpublic uses quiet/file output.
    result = subprocess.run(['tpm2_getcap', '-T', f'device:{device}', 'handles-persistent'],
                            capture_output=True, check=True, timeout=15)
    handles = re.findall(r'0x[0-9a-fA-F]+', result.stdout.decode('ascii'))
    public = {}
    for handle in handles:
        path = directory / f'{handle}.tpmt'
        subprocess.run(['tpm2_readpublic', *prefix, '-c', handle, '-f', 'tpmt', '-o', str(path)],
                       capture_output=True, check=True, timeout=15)
        public[handle.lower()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return public


def dictionary_state(device: Path) -> dict[str, int]:
    result = subprocess.run(['tpm2_getcap', '-T', f'device:{device}', 'properties-variable'],
                            capture_output=True, check=True, timeout=15)
    output = result.stdout.decode('ascii')
    state = {}
    for field in ('inLockout', 'TPM2_PT_LOCKOUT_COUNTER'):
        match = re.search(rf'(?m)^\s*{field}:\s+(0x[0-9a-fA-F]+|[0-9]+)\s*$', output)
        if match is None:
            raise RuntimeError(f'TPM dictionary-attack property missing: {field}')
        state[field] = int(match[1], 0)
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True, type=Path)
    parser.add_argument('--output', type=Path, help='Optional public JSON validation record')
    args = parser.parse_args()
    device = args.device
    if str(device) != '/dev/tpmrm0' or not device.is_char_device():
        raise SystemExit('select the native signer\'s supported /dev/tpmrm0 character device')
    if not os.access(device, os.R_OK | os.W_OK):
        raise SystemExit('TPM resource-manager access required; run as an authorized operator')
    os.umask(0o077)
    env = dict(os.environ, AIVM_SECRETS_REQUIRE_TPM_TESTS='1',
               AIVM_SECRETS_TEST_TPM_DEVICE=str(device))
    env.update({name: str(ROOT / 'rust/target/debug' / binary)
                for name, binary in RUNNERS.items()})
    require_native_paths(env)
    with tempfile.TemporaryDirectory(prefix='garrett-device-') as scratch:
        directory = Path(scratch)
        before = snapshot(device, directory)
        counters = dictionary_state(device)
        if counters['inLockout']:
            raise SystemExit('device TPM is in dictionary-attack lockout; no tests were started')
        reserved = {'0x81010011', '0x81010012'}
        if reserved.intersection(before):
            raise SystemExit('fixture handles are occupied; refusing to replace them')
        report = directory / 'tests.xml'
        result = subprocess.run([
            sys.executable, '-m', 'pytest', '-q',
            'tests/test_rust_garrett_tpm_request.py', '-k', 'not authorization',
            '--junitxml', str(report),
        ], cwd=ROOT, env=env, check=False)
        after = snapshot(device, directory)
        if before != after:
            raise RuntimeError('persistent TPM public objects changed or fixture cleanup failed')
        if dictionary_state(device) != counters:
            raise RuntimeError('shared dictionary-attack state changed during device tests')
        if result.returncode:
            raise SystemExit(result.returncode)
        count = require_no_skips(report)
        record = dict(schema=1, scope='native-tpm-device-synthetic-workflow',
                      status='passed', device=str(device), tests=count,
                      existing_public_sha256=before,
                      dictionary_attack_state_preserved=True,
                      persistent_objects_preserved=True, fixture_handles_cleaned=True)
        if args.output:
            args.output.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    main()
