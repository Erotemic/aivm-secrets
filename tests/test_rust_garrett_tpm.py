"""Actual TPM signing through TLS, using isolated disposable swtpm state.

This demonstrates an adapter, not physical hardware provenance. No TPM private
key is exported; the emulator host can still copy its state or act as an oracle.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aivm_secrets.primitives import codec
from tests.secrets_helpers import REPO, TOKEN
from tests.test_rust_garrett import BoundBridge, executable, run


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
    'tpm2_certifycreation',
)


def require_software_tpm_tools() -> None:
    missing = [name for name in SOFTWARE_TPM_TOOLS if shutil.which(name) is None]
    if not missing:
        return
    message = (
        f'local software TPM prerequisites missing: {", ".join(missing)}; '
        'install swtpm and tpm2-tools (Ubuntu: sudo apt install swtpm tpm2-tools)'
    )
    if os.getenv('AIVM_SECRETS_REQUIRE_TPM_TESTS') == '1':
        pytest.fail(message)
    pytest.skip(message)


class SoftwareTPM:
    def __init__(self, directory):
        self.directory = Path(directory)

    def tool(self, name, *args):
        return subprocess.run(
            [f"tpm2_{name}", "-Q", "-T", self.tcti, *map(str, args)],
            capture_output=True,
            timeout=15,
            check=True,
        )

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
            self.tool("flushcontext", "-t")
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

    def certificates(self, directory):
        """Test authority knows the emulator fixture; no remote-attestation claim."""
        p = Path(directory)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)

        def name(value):
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])

        def builder(role, public):
            return (
                x509.CertificateBuilder()
                .subject_name(name(role))
                .issuer_name(name("TPM test CA"))
                .public_key(public)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=1))
            )

        ca = (
            builder("TPM test CA", ca_key.public_key())
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(ca_key, hashes.SHA256())
        )
        ca_path = p / "ca.pem"
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        result = {"ca": ca_path}
        for role in ("server", "client1", "client2"):
            key = None if role == "client1" else ec.generate_private_key(ec.SECP256R1())
            public = (
                serialization.load_der_public_key(
                    (self.directory / "public.der").read_bytes()
                )
                if key is None
                else key.public_key()
            )
            cert_builder = (
                builder(role, public)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(
                    x509.ExtendedKeyUsage(
                        [
                            ExtendedKeyUsageOID.SERVER_AUTH
                            if role == "server"
                            else ExtendedKeyUsageOID.CLIENT_AUTH
                        ]
                    ),
                    False,
                )
            )
            if role == "server":
                cert_builder = cert_builder.add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]), False
                )
            cert = cert_builder.sign(ca_key, hashes.SHA256())
            cert_path, key_path = p / f"{role}.pem", p / f"{role}.key"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            if key is not None:
                key_path.write_bytes(
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
            result[role] = (
                cert_path,
                key_path,
                cert.public_bytes(serialization.Encoding.DER),
            )
        assert not result["client1"][1].exists()
        return result


def test_tpm_tls_success_wrong_auth_and_pinned_key_rejection():
    client = executable("AIVM_SECRETS_RUST_GARRETT_CLIENT")
    runner = executable("AIVM_SECRETS_RUST_GARRETT_RUNNER")
    bridge = executable("AIVM_SECRETS_RUST_GARRETT_BRIDGE")
    require_software_tpm_tools()
    with tempfile.TemporaryDirectory(prefix="agt-") as directory:
        p = Path(directory)
        state = p / "tpm"
        state.mkdir(mode=0o700)
        work = p / "work"
        work.mkdir(mode=0o700)
        with SoftwareTPM(state) as tpm:
            with BoundBridge(directory, runner, bridge, tpm.certificates) as case:
                config = dict(
                    schema=1,
                    key_mode="tpm2",
                    socket=str(case.listen),
                    server_name="localhost",
                    certificate=str(case.certs["client1"][0]),
                    server_ca=str(case.certs["ca"]),
                    tcti=tpm.tcti,
                    persistent_handle=0x81010011,
                    authorization_file=str(state / "auth"),
                    public_area_file=str(state / "public.tpmt"),
                    work_directory=str(work),
                )
                path = p / "client.json"
                path.write_bytes(codec.dumps(config))
                path.chmod(0o600)
                frame = dict(
                    version=1,
                    capability=case.token,
                    request={
                        "operation": "pr.view",
                        "arguments": {"repository": REPO, "pr": 13861},
                    },
                )

                def call():
                    return subprocess.run(
                        [client, "--config", str(path)],
                        input=codec.dumps(frame),
                        capture_output=True,
                        timeout=20,
                    )

                good = call()
                assert good.returncode == 0, good.stderr
                assert codec.loads(good.stdout)["result"]["number"] == 13861
                assert len(case.harness.executor.calls) == 1
                assert TOKEN.encode() not in good.stdout + good.stderr
                assert not case.certs["client1"][1].exists()
                assert list(work.iterdir()) == []
                auth = (state / "auth").read_bytes()
                (state / "auth").write_bytes(b"wrong-authorization-0123456789012")
                denied = call()
                assert denied.returncode == 1 and not denied.stdout
                assert denied.stderr == b"invalid_capability\n"
                assert len(case.harness.executor.calls) == 1
                assert list(work.iterdir()) == []
                (state / "auth").write_bytes(auth)
                area = (state / "public.tpmt").read_bytes()
                # Removing fixedTPM must fail before using the key.
                altered = bytearray(area)
                altered[7] ^= 2
                (state / "public.tpmt").write_bytes(altered)
                assert call().returncode == 1
                (state / "public.tpmt").write_bytes(area)
                # A different pinned point cannot be substituted under this cert.
                altered = bytearray(area)
                altered[-1] ^= 1
                (state / "public.tpmt").write_bytes(altered)
                assert call().returncode == 1
                assert len(case.harness.executor.calls) == 1
                assert list(work.iterdir()) == []


def test_fresh_creation_evidence_under_pinned_attestation_key():
    runner = executable("AIVM_SECRETS_RUST_GARRETT_RUNNER")
    require_software_tpm_tools()
    with tempfile.TemporaryDirectory(prefix="aga-") as directory:
        p = Path(directory)
        with SoftwareTPM(p) as tpm:
            tpm.tool(
                "createprimary",
                "-C",
                "o",
                "-G",
                "ecc256:ecdsa-sha256:null",
                "-g",
                "sha256",
                "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign",
                "-c",
                p / "ak.ctx",
            )
            tpm.tool("evictcontrol", "-C", "o", "-c", p / "ak.ctx", "0x81010012")
            tpm.tool("flushcontext", "-t")
            tpm.tool(
                "readpublic",
                "-c",
                "0x81010012",
                "-f",
                "tpmt",
                "-o",
                p / "ak.tpmt",
                "-q",
                p / "ak.qname",
            )
            challenge = os.urandom(32)

            def evidence(nonce):
                tpm.tool(
                    "certifycreation",
                    "-C",
                    "0x81010012",
                    "-c",
                    "0x81010011",
                    "-d",
                    p / "creation.hash",
                    "-t",
                    p / "creation.ticket",
                    "-g",
                    "sha256",
                    "-s",
                    "ecdsa",
                    "-f",
                    "plain",
                    "-q",
                    nonce.hex(),
                    "-o",
                    p / "signature",
                    "--attestation",
                    p / "attestation",
                )
                return dict(
                    action="attestation",
                    ak_area_hex=(p / "ak.tpmt").read_bytes().hex(),
                    ak_qualified_name_hex=(p / "ak.qname").read_bytes().hex(),
                    challenge_hex=challenge.hex(),
                    public_area_hex=(p / "public.tpmt").read_bytes().hex(),
                    signature_hex=(p / "signature").read_bytes().hex(),
                    attestation_hex=(p / "attestation").read_bytes().hex(),
                )

            valid = evidence(challenge)
            (accepted,) = run(runner, [valid], crypto=True)
            assert accepted["ok"]
            assert accepted["spki_der_hex"] == (p / "public.der").read_bytes().hex()
            rows = [
                evidence(os.urandom(32))
            ]  # Valid AK signature with stale/wrong challenge
            for field in [
                "signature_hex",
                "attestation_hex",
                "public_area_hex",
                "ak_area_hex",
                "ak_qualified_name_hex",
            ]:
                altered = dict(valid)
                value = bytearray.fromhex(altered[field])
                value[-1] ^= 1
                altered[field] = value.hex()
                rows.append(altered)
            altered = dict(valid)
            value = bytearray.fromhex(altered["public_area_hex"])
            value[7] ^= 2
            altered["public_area_hex"] = value.hex()
            rows.append(altered)
            for length in [
                0,
                1,
                6,
                35,
                66,
                len(bytes.fromhex(valid["attestation_hex"])) - 1,
            ]:
                altered = dict(valid)
                altered["attestation_hex"] = altered["attestation_hex"][: length * 2]
                rows.append(altered)
            assert run(runner, rows, crypto=True) == [
                dict(ok=False, code="invalid_capability")
            ] * len(rows)
