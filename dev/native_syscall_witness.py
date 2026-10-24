#!/usr/bin/env python3
"""Whole-process witness for NATIVE-SINK-01: where can the credential go?

Runs the offline operator/guest demonstration (allowed reads, a denied
write, revocation) with the real `garrett-bridge` under `strace -f`, which
records every write-family and connect syscall the broker and any child
make, with full buffers. Then it checks:

1. no buffer written or sent anywhere contains the provider credential or
   its base64 forms. The provider connection is TLS, so the plaintext
   credential has no legitimate reason to appear in any syscall;
2. every outbound network connection goes to the configured provider;
3. the provider's own record shows only the authorized requests (the
   demonstration checks this).

A positive control requires that the trace contains the plaintext audit
records the broker wrote, so an empty or broken trace cannot pass.

This is runtime evidence for one run, not a proof. It covers what source
guards cannot: std, rustls, ring and the kernel interface. It does not see
writes through shared memory mappings (the broker makes none on this path)
or bytes that leave inside TLS records to the provider; check 3 covers those.

    python dev/native_syscall_witness.py [--bin-dir DIR] [--keep]
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dev import offline_native_guest as offline  # noqa: E402

TRACED = ('write,writev,pwrite64,pwritev,pwritev2,sendto,sendmsg,sendmmsg,'
          'sendfile,splice,tee,vmsplice,connect')
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
CALL = re.compile(r'^(?:\[pid\s+)?(\d+)\]?\s*([a-z0-9_]+)\(')


def decode(escaped: str) -> bytes:
    """Decode one strace -xx string (every byte as \\xHH, plus \\-escapes)."""
    out = bytearray()
    index = 0
    simple = {'n': 10, 't': 9, 'r': 13, 'v': 11, 'f': 12, '"': 34, '\\': 92}
    while index < len(escaped):
        char = escaped[index]
        if char == '\\' and index + 1 < len(escaped):
            nxt = escaped[index + 1]
            if nxt == 'x':
                out.append(int(escaped[index + 2:index + 4], 16))
                index += 4
                continue
            if nxt in simple:
                out.append(simple[nxt])
                index += 2
                continue
            digits = re.match(r'[0-7]{1,3}', escaped[index + 1:])
            if digits:
                out.append(int(digits.group(0), 8))
                index += 1 + len(digits.group(0))
                continue
        out.extend(char.encode('utf-8'))
        index += 1
    return bytes(out)


def parse(trace: str) -> dict:
    """Return the decoded buffers of write-family calls and the connects."""
    buffers: list[tuple[str, bytes]] = []
    connects: list[str] = []
    for line in trace.splitlines():
        match = CALL.match(line.strip())
        if not match:
            continue
        name = match.group(2)
        if name == 'connect':
            connects.append(line)
            continue
        data = b''.join(decode(s) for s in QUOTED.findall(line))
        buffers.append((name, data))
    return {'buffers': buffers, 'connects': connects}


def inet_destinations(connects: list[str]) -> list[tuple[str, int]]:
    """IPv4/IPv6 connect destinations; Unix and netlink sockets are local."""
    found = []
    for line in connects:
        if 'AF_INET' not in line:
            continue
        port = re.search(r'sin6?_port=htons\((\d+)\)', line)
        address = re.search(r'inet_(?:addr|pton)\((?:AF_INET6, )?"([^"]+)"', line)
        if port and address:
            text = address.group(1)
            if text.startswith('\\x'):
                text = decode(text).decode('ascii')
            found.append((str(ipaddress.ip_address(text)), int(port.group(1))))
        else:
            found.append(('unparsed', 0))
    return found


def patterns(token: str) -> list[bytes]:
    raw = token.encode()
    return [raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw).rstrip(b'=')]


def witness(bin_dir: Path, workspace: Path) -> dict:
    real = offline.binaries(bin_dir)
    wrapped = workspace / 'bin'
    wrapped.mkdir(mode=0o700)
    for role in ('authority', 'client'):
        (wrapped / real[role].name).symlink_to(real[role])
    log = workspace / 'bridge.strace'
    script = wrapped / 'garrett-bridge'
    # strace detaches on SIGTERM instead of stopping the bridge, so the
    # wrapper forwards the demonstration's SIGTERM to the bridge itself.
    traced = shlex.join([
        shutil.which('strace') or 'strace', '-f', '-qq', '-e', 'signal=none',
        '-s', str(1 << 22), '-xx', '-e', 'trace=' + TRACED, '-o', str(log),
        str(real['bridge'])])
    script.write_text('#!/bin/sh\n' + traced + ' "$@" &\n'
                      'tracer=$!\n'
                      'trap \'pkill -TERM -P "$tracer"; wait "$tracer"\' TERM\n'
                      'wait "$tracer"\n')
    script.chmod(0o700)

    (workspace / 'demo').mkdir(mode=0o700)
    demo = offline.demonstrate(workspace / 'demo', wrapped)
    if demo.get('ok') is not True:
        raise offline.DemoError('the demonstration itself failed')
    token = offline.FAKE_TOKEN
    host = workspace / 'demo' / 'host'
    provider = json.loads((host / 'bridge.json').read_text())['provider']

    traced = parse(log.read_text(errors='replace'))
    leaks = sorted({name for name, data in traced['buffers']
                    for pattern in patterns(token) if pattern in data})
    destinations = inet_destinations(traced['connects'])
    allowed = {(provider['address'], provider['port'])}
    stray = sorted({d for d in destinations if d not in allowed})

    audit_lines = [line for line in (host / 'provider-audit.jsonl').read_bytes().splitlines() if line]
    written = b''.join(data for _, data in traced['buffers'])
    control = bool(audit_lines) and all(line in written for line in audit_lines)

    report = {
        'ok': not leaks and not stray and control,
        'scope': 'offline demonstration: allowed reads, denied write, revocation',
        'syscalls_scanned': len(traced['buffers']),
        'bytes_scanned': sum(len(data) for _, data in traced['buffers']),
        'credential_patterns': len(patterns(token)),
        'credential_in_written_buffers': leaks,
        'network_destinations': sorted(set(destinations)),
        'unexpected_destinations': stray,
        'positive_control_audit_records_seen': control,
        'provider_requests': len(demo.get('provider_requests', [])),
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, default=REPO_ROOT / 'rust/target/debug')
    parser.add_argument('--keep', action='store_true', help='keep the trace for inspection')
    args = parser.parse_args(argv)
    if shutil.which('strace') is None:
        print('strace is required', file=sys.stderr)
        return 2
    workspace = Path(tempfile.mkdtemp(prefix='garrett-strace-', dir='/tmp'))
    try:
        report = witness(args.bin_dir.absolute(), workspace)
    finally:
        if args.keep:
            print(f'kept {workspace}', file=sys.stderr)
        else:
            shutil.rmtree(workspace, ignore_errors=True)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
