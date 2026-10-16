"""Verify extraction attribution against the original AIVM repository.

Run from this repository: python3 dev/port/verify_history.py /path/to/aivm
The source may have advanced, provided it still contains the pinned Git objects.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', '-C', str(repo), *args])


def attribution(repo: Path, commit: str) -> tuple[list[bytes], bytes]:
    headers, message = git(repo, 'cat-file', 'commit', commit).split(b'\n\n', 1)
    identities = [line for line in headers.splitlines()
                  if line.startswith((b'author ', b'committer ', b'encoding '))]
    return identities, message


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    provenance = json.loads((repo / 'dev/port/source.json').read_text())
    rows = (repo / 'dev/port/aivm-commit-map.txt').read_text().splitlines()[1:]
    commits = [line.split() for line in rows if int(line.split()[1], 16)]
    if len(commits) != provenance['preserved_commits']:
        raise SystemExit('commit count does not match provenance')
    for old, new in commits:
        if attribution(args.source, old) != attribution(repo, new):
            raise SystemExit(f'authorship, dates, or message differ: {old} -> {new}')
    pinned = provenance['source_commit']
    for path in provenance['external_assurance_paths']:
        git(args.source, 'cat-file', '-e', f'{pinned}:{path}')
    print(f'Verified {len(commits)} original author/committer identities, dates, '
          'and complete messages (including co-author trailers).')
    print('All pinned external assurance paths exist in the source commit.')


if __name__ == '__main__':
    main()
