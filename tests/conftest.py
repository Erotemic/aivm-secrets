"""Keep host state isolated without importing the VM manager's fixtures."""
import os
from pathlib import Path

import pytest


@pytest.fixture(scope='session', autouse=True)
def private_test_files():
    """Create private fixtures even when the developer uses a shared umask.

    Production ownership checks still run unchanged; tests of unsafe modes
    explicitly chmod their fixtures to exercise those refusals.
    """
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.fixture(autouse=True)
def isolated_user_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve the original suite's isolation of implicit user paths."""
    root = tmp_path / 'process-scope'
    for name, directory in {
        'HOME': 'home',
        'XDG_CONFIG_HOME': 'config',
        'XDG_DATA_HOME': 'data',
        'XDG_CACHE_HOME': 'cache',
        'XDG_STATE_HOME': 'state',
    }.items():
        path = root / directory
        path.mkdir(parents=True)
        monkeypatch.setenv(name, str(path))
