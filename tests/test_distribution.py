"""Check the independent artifacts and installed CLI from outside the checkout."""
from __future__ import annotations

from email.parser import Parser
from pathlib import Path
import subprocess
import sys
import tarfile
import textwrap
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
        assert 'rust/crates/aivm-secrets-primitives/src/lib.rs' in names
        assert 'proofs/generated/AivmSecretsPrimitives.lean' in names
        assert 'proofs/manifest.json' in names
        assert 'dev/verification/freshness.py' in names
        assert '.github/workflows/freshness.yml' in names
        assert not any('/.lake/' in name or '/.tools/' in name or '/rust/target/' in name
                       for name in names)
        assert not any(name.startswith(('aivm/', '.llm_resource_tally/'))
                       for name in names)


def test_installed_cli_has_no_vm_manager_dependency(tmp_path: Path) -> None:
    # This is a development machine: AIVM may be installed independently.
    # Its mere presence cannot mean aivm-secrets depends on it. Exercise the
    # installed distribution under -I with an import guard that rejects any
    # attempt to import AIVM, even when AIVM is importable in site-packages.
    probe = textwrap.dedent("""\
        import sys

        assert not any(n == 'aivm' or n.startswith('aivm.') for n in sys.modules)
        class ForbidAivm:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == 'aivm' or fullname.startswith('aivm.'):
                    raise RuntimeError('aivm-secrets attempted to import AIVM')
                return None

        sys.meta_path.insert(0, ForbidAivm())
        from aivm_secrets.cli import main
        try:
            main(['--help'])
        except SystemExit as error:
            assert error.code in (0, None)
        assert not any(n == 'aivm' or n.startswith('aivm.') for n in sys.modules)
    """)
    result = subprocess.run(
        [sys.executable, '-I', '-c', probe],
        cwd=tmp_path, check=True, capture_output=True, text=True, timeout=20,
    )
    assert 'aivm-secrets' in result.stdout
