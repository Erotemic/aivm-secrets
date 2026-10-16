"""Check the independent artifacts and installed CLI from outside the checkout."""
from __future__ import annotations

from email.parser import Parser
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def test_standalone_wheel_and_sdist(tmp_path: Path) -> None:
    subprocess.run(
        [sys.executable, '-m', 'build', '--no-isolation', '--outdir',
         str(tmp_path), str(ROOT)],
        check=True, capture_output=True, text=True, timeout=120,
    )
    wheel, = tmp_path.glob('*.whl')
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert 'aivm_secrets/cli.py' in names
        assert 'aivm_secrets/identity/garrett/protocol.py' in names
        assert not any(name.startswith(('aivm/', 'tests/')) for name in names)
        metadata_path, = (name for name in names if name.endswith('/METADATA'))
        metadata = Parser().parsestr(archive.read(metadata_path).decode())
        assert metadata['Name'] == 'aivm-secrets'
        assert metadata['Version'] == '0.2.0'
        assert metadata['License-Expression'] == 'Apache-2.0'
        requirements = metadata.get_all('Requires-Dist', [])
        assert any(item.startswith('cryptography>=46') for item in requirements)
        assert not any(item.lower().startswith(('aivm;', 'aivm ', 'aivm>', 'aivm='))
                       for item in requirements)
        entry_path, = (name for name in names if name.endswith('/entry_points.txt'))
        assert 'aivm-secrets = aivm_secrets.cli:main' in archive.read(entry_path).decode()
        assert any(name.endswith('/licenses/LICENSE') for name in names)
    sdist, = tmp_path.glob('*.tar.gz')
    with tarfile.open(sdist) as archive:
        names = [name.split('/', 1)[-1] for name in archive.getnames()]
        assert 'pyproject.toml' in names
        assert 'tests/test_secrets_broker.py' in names
        assert 'docs/planning/aivm-secrets-assumptions.json' in names
        assert 'dev/port/aivm-commit-map.txt' in names
        assert not any(name.startswith(('aivm/', '.llm_resource_tally/'))
                       for name in names)


def test_installed_cli_has_no_vm_manager_dependency(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, '-I', '-c',
         'import importlib.util; '
         'assert importlib.util.find_spec("aivm") is None; '
         'from aivm_secrets.cli import main; main(["--help"])'],
        cwd=tmp_path, check=True, capture_output=True, text=True, timeout=20,
    )
    assert 'aivm-secrets' in result.stdout
