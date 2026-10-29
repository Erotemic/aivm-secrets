"""Compare the Aeneas-generated Garrett core between a git revision and the
working tree, declaration by declaration, grouped by Rust source file.

Several gates (NR-0, read-path, W4, W5) pin the SHA-256 of the whole
generated file ``proofs/generated/AivmSecretsGarrettCore.lean``, so any new
extracted module changes their pin. This check shows a reviewer what a re-pin
actually covers: which declarations were added, removed or changed, and from
which source files. It does not approve anything; a maintainer still accepts
or rejects each re-pin.

    python dev/verification/generated_scope.py diff BASE [--outside PATTERN]

``--outside`` (a regular expression over source paths, default ``stateless``)
names the sources the change is expected to be confined to; the command exits
non-zero if any declaration from another source was added, removed or changed.
Source line numbers are ignored, since an unrelated addition can shift them.
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATED = 'proofs/generated/AivmSecretsGarrettCore.lean'
HEADER = re.compile(r'^/-- (?:Trait declaration: |Trait implementation: )?\[(?P<name>[^\]]+)\]', re.M)
SOURCE = re.compile(r"Source: '(?P<path>[^']+)', lines [0-9:.-]+")


def declarations(text: str) -> dict[str, tuple[str, str]]:
    """Each extracted declaration: name -> (source path, text without line numbers)."""
    starts = [m.start() for m in HEADER.finditer(text)] + [len(text)]
    # The imports and options before the first declaration.
    out = {'(preamble)': ('', text[:starts[0]])}
    for begin, end in zip(starts, starts[1:]):
        block = text[begin:end]
        name = HEADER.match(block).group('name')
        source = SOURCE.search(block)
        path = source.group('path') if source else ''
        key = name if name not in out else f'{name}#{begin}'
        out[key] = (path, SOURCE.sub(f"Source: '{path}'", block))
    return out


def diff(base: str, outside: str) -> int:
    before = declarations(subprocess.run(['git', 'show', f'{base}:{GENERATED}'], cwd=ROOT, check=True,
                                         capture_output=True, text=True).stdout)
    after = declarations((ROOT / GENERATED).read_text())
    changes: dict[str, list[str]] = {}
    for name in sorted(before.keys() | after.keys()):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        kind = 'added' if old is None else 'removed' if new is None else 'changed'
        path = (new or old)[0]
        changes.setdefault(path, []).append(f'{kind} {name}')
    expected = re.compile(outside)
    stray = 0
    for path in sorted(changes):
        inside = bool(expected.search(path))
        stray += 0 if inside else len(changes[path])
        print(f"{'ok' if inside else 'OUTSIDE'} {path or '(no source)'}: {len(changes[path])} declarations")
        if not inside:
            for line in changes[path]:
                print(f'  {line}')
    unchanged = sum(1 for name in before if before[name] == after.get(name))
    print(f'{unchanged} declarations unchanged since {base}; {stray} changed outside /{outside}/')
    return 1 if stray else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('action', choices=['diff'])
    parser.add_argument('base')
    parser.add_argument('--outside', default='stateless')
    args = parser.parse_args()
    return diff(args.base, args.outside)


if __name__ == '__main__':
    raise SystemExit(main())
