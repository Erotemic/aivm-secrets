"""The `gh --json` compatibility audit runs against an installed `gh`, if any."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Reviewed extensions: fields we accept that stock `gh` does not. Older `gh`
# lacks `baseRefOid`; `status` and `conclusion` are raw check-run fields.
REVIEWED_VIEW_EXTRAS = {'baseRefOid'}
REVIEWED_CHECKS_EXTRAS = {'status', 'conclusion'}
# The stock fields an ordinary script asks for must work in both clients.
COMMON_CHECKS = {'name', 'state', 'link'}


@pytest.mark.skipif(shutil.which('gh') is None, reason='gh is not installed')
def test_view_fields_are_stock_gh_fields_or_reviewed_extensions():
    done = subprocess.run([sys.executable, str(ROOT / 'dev/gh_json_audit.py')],
                          capture_output=True, text=True, timeout=120, check=True)
    report = json.loads(done.stdout)
    view = report['pr view']
    assert view['official'], report['gh']
    assert set(view['native']['extra']) <= REVIEWED_VIEW_EXTRAS
    assert set(view['python']['extra']) <= REVIEWED_VIEW_EXTRAS
    checks = report['pr checks']
    if checks['official'] is not None:  # gh 2.45 has no `pr checks --json`
        for client in ('python', 'native'):
            assert set(checks[client]['extra']) <= REVIEWED_CHECKS_EXTRAS
            assert COMMON_CHECKS <= set(checks[client]['accepted'])
