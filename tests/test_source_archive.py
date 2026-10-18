"""The distributed source must contain every committed top-level proof module."""
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def test_source_archive_contains_the_reproducible_proof_and_system_gate(tmp_path):
    result = subprocess.run(
        [sys.executable, '-c',
         'from setuptools import build_meta; import sys; build_meta.build_sdist(sys.argv[1])',
         str(tmp_path)], cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    archives = list(tmp_path.glob('*.tar.gz'))
    assert len(archives) == 1
    with tarfile.open(archives[0], 'r:gz') as archive:
        names = {name.split('/', 1)[1] for name in archive.getnames() if '/' in name}
    expected = {str(p.relative_to(ROOT)) for p in (ROOT / 'proofs').glob('*.lean')}
    expected |= {'dev/verification/system.py', 'dev/verification/w5_noninterference.py',
                 'docs/planning/aivm-secrets-assurance-profiles.json',
                 'docs/assurance-profiles.html'}
    assert expected <= names, 'Missing reproducibility inputs: ' + repr(sorted(expected - names))
    assert not any(name.startswith(('.tools/', 'proofs/.lake/', 'rust/target/')) for name in names)
