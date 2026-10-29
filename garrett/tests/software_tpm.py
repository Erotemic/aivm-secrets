"""A software TPM (swtpm) holding one persistent P-256 signing key at
``0x81010011``, for the optional TPM client-identity test. Set
``GARRETT_REQUIRE_TPM_TESTS=1`` to fail instead of skip without swtpm and
tpm2-tools."""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

# The shared emulator fixture needs more than the swtpm executable. Check the
# entire set before starting an optional test so a partial apt installation
# never produces a late, misleading FileNotFoundError from subprocess.Popen.
SOFTWARE_TPM_TOOLS = (
    'swtpm',
    'tpm2_createprimary',
    'tpm2_evictcontrol',
    'tpm2_flushcontext',
    'tpm2_readpublic',
    'tpm2_sign',
)


def require_software_tpm_tools(*, emulator: bool = True) -> None:
    required = SOFTWARE_TPM_TOOLS if emulator else SOFTWARE_TPM_TOOLS[1:]
    missing = [name for name in required if shutil.which(name) is None]
    if not missing:
        return
    packages = 'swtpm tpm2-tools' if emulator else 'tpm2-tools'
    message = (f'local {"software" if emulator else "device"} TPM prerequisites missing: '
               f'{", ".join(missing)}; install {packages} '
               f'(Ubuntu: sudo apt install {packages})')
    if os.getenv('GARRETT_REQUIRE_TPM_TESTS') == '1':
        pytest.fail(message)
    pytest.skip(message)


class SoftwareTPM:
    def __init__(self, directory):
        self.directory = Path(directory)

    def tool(self, name, *args):
        return subprocess.run(
            [f"tpm2_{name}", *([] if name == 'getcap' else ['-Q']),
             "-T", self.tcti, *map(str, args)],
            capture_output=True,
            timeout=15,
            check=True,
        )

    def flush_transients(self):
        # This instance owns an isolated emulator, including all its objects.
        self.tool("flushcontext", "-t")

    def __enter__(self):
        p = self.directory
        self.tcti = f"swtpm:path={p}/tpm.sock"
        self.process = subprocess.Popen(
            [
                "swtpm",
                "socket",
                "--tpm2",
                "--tpmstate",
                f"dir={p}",
                "--server",
                f"type=unixio,path={p}/tpm.sock,mode=0600",
                "--ctrl",
                f"type=unixio,path={p}/tpm.sock.ctrl,mode=0600",
                "--flags",
                "not-need-init,startup-clear",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(100):
                if (p / "tpm.sock").exists():
                    break
                assert self.process.poll() is None
                time.sleep(0.02)
            (p / "auth").write_bytes(os.urandom(32))
            (p / "auth").chmod(0o600)
            self.tool(
                "createprimary",
                "-C",
                "o",
                "-G",
                "ecc256:ecdsa-sha256",
                "-g",
                "sha256",
                "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                "-p",
                f"file:{p}/auth",
                "-c",
                p / "key.ctx",
                "-d",
                p / "creation.hash",
                "-t",
                p / "creation.ticket",
            )
            self.tool("evictcontrol", "-C", "o", "-c", p / "key.ctx", "0x81010011")
            self.flush_transients()
            self.tool(
                "readpublic", "-c", "0x81010011", "-f", "tpmt", "-o", p / "public.tpmt"
            )
            self.tool(
                "readpublic", "-c", "0x81010011", "-f", "der", "-o", p / "public.der"
            )
            for item in p.iterdir():
                if item.is_file():
                    item.chmod(0o600)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *exc):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
