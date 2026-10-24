"""Compare the `gh --json` fields the aliases accept with the installed `gh`.

Both guest clients accept a reviewed subset of `gh pr view --json` and
`gh pr checks --json` fields. This asks the real `gh` on this machine which
fields it accepts and reports, per command and client:

* `extra`: fields we accept that this `gh` does not (a script written for
  stock `gh` never asks for them, but one written for us fails on stock `gh`);
* `missing`: fields this `gh` accepts that we refuse.

`gh` prints its field list for a bare `--json` before it needs a login, so
this runs with an empty config directory and no token. It never contacts
GitHub. Usage: `python dev/gh_json_audit.py [--gh PATH]`; prints JSON.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'rust/crates/aivm-secrets-garrett/src/client_alias.rs'


def official_fields(gh: str, command: list[str]) -> list[str] | None:
    """The installed gh's --json fields, or None when it has no --json."""
    with tempfile.TemporaryDirectory() as config:
        env = {key: value for key, value in os.environ.items()
               if key not in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN')}
        env['GH_CONFIG_DIR'] = config
        done = subprocess.run([gh, *command, '1', '-R', 'example/example', '--json'],
                              capture_output=True, text=True, env=env, timeout=30)
    text = done.stdout + done.stderr
    if 'unknown flag: --json' in text:
        return None
    if 'Specify one or more comma-separated fields' not in text:
        raise SystemExit(f'unexpected gh output for {command}: {text[:200]!r}')
    return sorted(line.strip() for line in text.splitlines()[1:] if line.strip())


def native_fields() -> dict[str, list[str]]:
    """The native client's per-command field lists, read from its source."""
    source = NATIVE.read_text()
    found = {}
    for kind, command in (('View', 'view'), ('Checks', 'checks')):
        match = re.search(rf'CommandKind::{kind} => &\[([^\]]*)\]', source)
        assert match, kind
        found[command] = sorted(re.findall(r'"([^"]+)"', match.group(1)))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gh', default='gh')
    args = parser.parse_args(argv)
    sys.path.insert(0, str(ROOT))
    from aivm_secrets.kernel.presets import GH_CHECKS_JSON, GH_VIEW_JSON

    version = subprocess.run([args.gh, '--version'], capture_output=True,
                             text=True, check=True).stdout.splitlines()[0]
    ours = {
        'view': {'python': sorted(GH_VIEW_JSON),
                 'native': native_fields()['view']},
        'checks': {'python': sorted(GH_CHECKS_JSON),
                   'native': native_fields()['checks']},
    }
    report: dict[str, object] = {'gh': version}
    for command, clients in ours.items():
        official = official_fields(args.gh, ['pr', command])
        entry: dict[str, object] = {'official': official}
        for client, fields in clients.items():
            entry[client] = {
                'accepted': fields,
                'extra': None if official is None else sorted(set(fields) - set(official)),
                'missing': None if official is None else sorted(set(official) - set(fields)),
            }
        report[f'pr {command}'] = entry
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
