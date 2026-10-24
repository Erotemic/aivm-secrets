#!/usr/bin/env python3
"""Search a guest for given byte strings, run as guest root by the host.

The patterns arrive on stdin, one hex-encoded pattern per line, so they never
appear in a guest file or command line. The search covers the root
filesystem (without crossing into virtiofs shares, which the share canary
search covers), the tmpfs mounts where sessions keep files, and every
process's environment and command line. It prints counts and the paths that
matched, never the matched bytes.

    sudo python3 -I guest_secret_hunt.py < patterns.hex

`--root DIR` searches only DIR (and still every process); tests use it.
"""
from __future__ import annotations

import json
import os
import sys

MAX_FILE = 32 << 20
EXTRA_ROOTS = ('/run', '/dev/shm', '/tmp', '/var/tmp')
SKIP = ('/proc', '/sys', '/dev')


def scan_file(path: str, patterns: list[bytes]) -> bool:
    try:
        if os.path.getsize(path) > MAX_FILE:
            return False
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return False
    return any(pattern in data for pattern in patterns)


def walk(root: str, patterns: list[bytes], report: dict) -> None:
    device = os.lstat(root).st_dev
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = [d for d in subdirs
                      if not os.path.join(directory, d).startswith(SKIP)
                      and os.lstat(os.path.join(directory, d)).st_dev == device]
        for name in files:
            path = os.path.join(directory, name)
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            report['files_scanned'] += 1
            if scan_file(path, patterns):
                report['file_hits'].append(path)


def main(argv: list[str]) -> int:
    patterns = [bytes.fromhex(line.strip()) for line in sys.stdin if line.strip()]
    if not patterns:
        print(json.dumps({'error': 'no patterns'}))
        return 2
    report: dict = {'files_scanned': 0, 'file_hits': [], 'processes_scanned': 0,
                    'process_hits': []}
    if len(argv) == 3 and argv[1] == '--root':
        walk(argv[2], patterns, report)
    else:
        walk('/', patterns, report)
        for root in EXTRA_ROOTS:
            if os.path.isdir(root) and os.lstat(root).st_dev != os.lstat('/').st_dev:
                walk(root, patterns, report)
    me = str(os.getpid())
    for pid in os.listdir('/proc'):
        if not pid.isdigit() or pid == me:
            continue
        report['processes_scanned'] += 1
        for part in ('environ', 'cmdline'):
            if scan_file(f'/proc/{pid}/{part}', patterns):
                report['process_hits'].append(f'{pid}/{part}')
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
