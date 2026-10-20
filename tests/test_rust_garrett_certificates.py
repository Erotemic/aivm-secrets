"""Independent Rust CA/CSR behavior, reference parity and synthetic key evidence."""

from __future__ import annotations

import datetime as dt
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aivm_secrets.identity.certificates import create_ca, inspect_csr, _leaf_certificate
from tests.test_rust_garrett import executable, run


def request(key=None, extensions=(), algorithm=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-admin")])
    )
    for extension in extensions:
        builder = builder.add_extension(extension, True)
    csr = builder.sign(key, algorithm or hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def fixture_ca(now, **changes):
    key, cert = create_ca(now=now, days=365)
    if changes:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.fromtimestamp(now - 60, dt.timezone.utc))
            .not_valid_after(dt.datetime.fromtimestamp(now + 31536000, dt.timezone.utc))
        )
        if not changes.get("missing_constraints"):
            builder = builder.add_extension(
                x509.BasicConstraints(
                    ca=changes.get("ca", True),
                    path_length=changes.get("path_length", 0),
                ),
                changes.get("critical", True),
            )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=changes.get("key_cert_sign", True),
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
        if changes.get("restricted_eku"):
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False
            )
        cert = builder.sign(key, hashes.SHA256())
    return (
        key,
        cert,
        dict(
            ca_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            ca_key_pem=key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
        ),
    )


def call(rows):
    return run(executable("AIVM_SECRETS_RUST_GARRETT_RUNNER"), rows, crypto=True)


def enrollment(ca, csr, now, **changes):
    value = dict(
        action="client-software",
        **ca,
        csr_pem=csr,
        now=now,
        subject="host-selected-vm",
        approve_fingerprint=inspect_csr(csr.encode()),
    )
    value.update(changes)
    return value


def test_csr_possession_and_client_certificate_reference_parity():
    now = int(time.time())
    ca_key, ca, fields = fixture_ca(now)
    key, csr = request()
    reference_fp = inspect_csr(csr.encode())
    inspected, first, second = call(
        [
            dict(action="csr-inspect", csr_pem=csr),
            enrollment(fields, csr, now),
            enrollment(fields, csr, now),
        ]
    )
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert inspected == dict(ok=True, fingerprint=reference_fp, spki_der_hex=spki.hex())
    assert first["ok"] and second["ok"]
    assert first["subject"] == "host-selected-vm"
    assert first["assurance"] == "operator-approved-software"
    cert = x509.load_pem_x509_certificate(first["certificate_pem"].encode())
    renewed = x509.load_pem_x509_certificate(second["certificate_pem"].encode())
    reference = _leaf_certificate(
        ca_key, ca, key.public_key(), name="aivm-guest", now=now, days=7, server=False
    )
    assert (
        cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        == spki
    )
    assert cert.subject == reference.subject
    assert (
        cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        == "aivm-guest"
    )
    assert cert.issuer == reference.issuer
    assert cert.not_valid_before_utc == reference.not_valid_before_utc
    assert cert.not_valid_after_utc == reference.not_valid_after_utc
    for kind in (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage):
        assert cert.extensions.get_extension_for_class(
            kind
        ) == reference.extensions.get_extension_for_class(kind)
    assert cert.serial_number != renewed.serial_number
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )
    assert first["not_before"] == now - 60 and first["not_after"] == now + 604800


def test_rust_ca_generation_and_software_approval_fail_closed():
    now = int(time.time())
    (root,) = call([dict(action="ca-create", now=now)])
    assert root["ok"]
    ca = x509.load_pem_x509_certificate(root["ca_pem"].encode())
    ca.public_key().verify(
        ca.signature, ca.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )
    assert ca.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value == x509.BasicConstraints(ca=True, path_length=0)
    key = serialization.load_pem_private_key(root["key_pem"].encode(), password=None)
    assert key.public_key().public_numbers() == ca.public_key().public_numbers()
    _, csr = request()
    fields = dict(ca_pem=root["ca_pem"], ca_key_pem=root["key_pem"])
    good = enrollment(fields, csr, now)
    _, _, other = fixture_ca(now)
    altered_ca = bytearray(ca.public_bytes(serialization.Encoding.DER))
    altered_ca[-1] ^= 1
    bad_ca_pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(altered_ca).decode()
        + "\n-----END CERTIFICATE-----\n"
    )
    rows = [
        good,
        dict(good, approve_fingerprint="0" * 64),
        dict(good, ca_key_pem=other["ca_key_pem"]),
        dict(good, now=now + 31536000 - 604800),
        dict(good, tpm_backed=True),
        dict(good, ca_pem=bad_ca_pem),
    ]
    results = call(rows)
    assert results[0]["ok"]
    assert results[1:] == [
        dict(ok=False, code=code)
        for code in [
            "denied",
            "invalid_capability",
            "expired",
            "invalid_capability",
            "invalid_capability",
        ]
    ]


@pytest.mark.parametrize(
    "changes",
    [
        dict(ca=False, path_length=None),
        dict(path_length=1),
        dict(path_length=None),
        dict(critical=False),
        dict(missing_constraints=True),
        dict(key_cert_sign=False),
        dict(restricted_eku=True),
    ],
)
def test_ca_authority_constraints_are_not_assumed_by_signing_library(changes):
    now = int(time.time())
    _, _, ca = fixture_ca(now, **changes)
    _, csr = request()
    assert call([enrollment(ca, csr, now)]) == [
        dict(ok=False, code="invalid_capability")
    ]


def test_csr_capability_requests_bad_signatures_and_ambiguous_payloads_are_denied():
    _, valid = request()
    body = x509.load_pem_x509_csr(valid.encode()).public_bytes(
        serialization.Encoding.DER
    )
    altered = bytearray(body)
    altered[-1] ^= 1
    tampered = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.b64encode(altered).decode()
        + "\n-----END CERTIFICATE REQUEST-----\n"
    )
    trailing_der = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.b64encode(body + b"\x00").decode()
        + "\n-----END CERTIFICATE REQUEST-----\n"
    )
    inputs = [
        tampered,
        trailing_der,
        valid + valid,
        valid + "garbage",
        " " + valid + " " * 8192,
    ]
    for extensions in [
        [x509.BasicConstraints(ca=True, path_length=0)],
        [x509.SubjectAlternativeName([x509.DNSName("attacker.test")])],
        [x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])],
    ]:
        inputs.append(request(extensions=extensions)[1])
    inputs.append(request(key=ec.generate_private_key(ec.SECP384R1()))[1])
    inputs.append(
        request(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))[1]
    )
    inputs.append(request(algorithm=hashes.SHA384())[1])
    assert call([dict(action="csr-inspect", csr_pem=csr) for csr in inputs]) == [
        dict(ok=False, code="invalid_capability")
    ] * len(inputs)


def tpm_csr(tpm):
    """PKCS#10 fixture signed by the actual TPM key, with no exported private key."""

    def der(tag, body):
        size = len(body)
        if size < 128:
            length = bytes([size])
        else:
            raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
            length = bytes([0x80 + len(raw)]) + raw
        return bytes([tag]) + length + body

    p = tpm.directory
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-tpm-request")]
    ).public_bytes()
    info = der(
        0x30, b"\x02\x01\x00" + name + (p / "public.der").read_bytes() + b"\xa0\x00"
    )
    (p / "csr.digest").write_bytes(hashlib.sha256(info).digest())
    tpm.tool(
        "sign",
        "-c",
        "0x81010011",
        "-p",
        f"file:{p / 'auth'}",
        "-g",
        "sha256",
        "-s",
        "ecdsa",
        "-d",
        "-f",
        "plain",
        "-o",
        p / "csr.sig",
        p / "csr.digest",
    )
    signed = der(
        0x30,
        info
        + bytes.fromhex("300a06082a8648ce3d040302")
        + der(3, b"\x00" + (p / "csr.sig").read_bytes()),
    )
    result = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.b64encode(signed).decode()
        + "\n-----END CERTIFICATE REQUEST-----\n"
    )
    assert x509.load_pem_x509_csr(result.encode()).is_signature_valid
    return result


def creation_evidence(tpm):
    p = tpm.directory
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
    tpm.flush_transients()
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
        challenge.hex(),
        "-o",
        p / "evidence.sig",
        "--attestation",
        p / "evidence.attestation",
    )
    return dict(
        action="attestation",
        ak_area_hex=(p / "ak.tpmt").read_bytes().hex(),
        ak_qualified_name_hex=(p / "ak.qname").read_bytes().hex(),
        challenge_hex=challenge.hex(),
        public_area_hex=(p / "public.tpmt").read_bytes().hex(),
        signature_hex=(p / "evidence.sig").read_bytes().hex(),
        attestation_hex=(p / "evidence.attestation").read_bytes().hex(),
    )


def test_attested_csr_key_is_certified_and_performs_provider_action():
    from tests.test_rust_garrett_tpm import SoftwareTPM, require_software_tpm_tools
    from tests.test_rust_garrett_provider import ProviderCase, provider_directory
    from tests.secrets_helpers import TLSService, TOKEN

    require_software_tpm_tools()
    with tempfile.TemporaryDirectory(prefix="agcert-") as directory:
        p = Path(directory)
        state, work = p / "tpm", p / "work"
        state.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        with SoftwareTPM(state) as tpm:
            csr = tpm_csr(tpm)
            evidence = creation_evidence(tpm)
            now = int(time.time())
            (root,) = call([dict(action="ca-create", now=now)])
            assert root["ok"]
            ca = dict(ca_pem=root["ca_pem"], ca_key_pem=root["key_pem"])
            value = dict(
                action="client-tpm",
                **ca,
                csr_pem=csr,
                evidence=evidence,
                subject="vm-test",
                now=now,
            )
            _, different = request()
            valid, denied, stale, expired = call(
                [
                    value,
                    dict(value, csr_pem=different),
                    dict(
                        value,
                        evidence=dict(evidence, challenge_hex=os.urandom(32).hex()),
                    ),
                    dict(value, expire_evidence=True),
                ]
            )
            assert valid["ok"] and valid["assurance"] == "attested-tpm"
            assert denied == dict(ok=False, code="denied")
            assert stale == dict(ok=False, code="invalid_capability")
            assert expired == dict(ok=False, code="expired")
            certificate = x509.load_pem_x509_certificate(
                valid["certificate_pem"].encode()
            )
            assert (
                certificate.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                == (state / "public.der").read_bytes()
            )

            def certificates(directory):
                dest = Path(directory)
                ca_path = dest / "ca.pem"
                ca_path.write_text(ca["ca_pem"])
                (server,) = call([dict(action="server-generate", **ca, now=now)])
                assert server["ok"]
                other_key, other_csr = request()
                (other,) = call([enrollment(ca, other_csr, now)])
                assert other["ok"]
                values = {
                    "server": (server["certificate_pem"], server["key_pem"]),
                    "client1": (valid["certificate_pem"], None),
                    "client2": (
                        other["certificate_pem"],
                        other_key.private_bytes(
                            serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption(),
                        ).decode(),
                    ),
                }
                result = {"ca": ca_path}
                for name, (cert_pem, key_pem) in values.items():
                    cert_path, key_path = dest / f"{name}.pem", dest / f"{name}.key"
                    cert_path.write_text(cert_pem)
                    if key_pem is not None:
                        key_path.write_text(key_pem)
                    result[name] = (
                        cert_path,
                        key_path,
                        x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(
                            serialization.Encoding.DER
                        ),
                    )
                assert not result["client1"][1].exists()
                return result

            with TLSService(provider_directory(p)) as provider:
                provider.routes[("GET", "/v1/account")] = dict(id=42, active=True)
                with ProviderCase(
                    p, provider, certificate_factory=certificates
                ) as case:
                    key_configuration = dict(
                        key_mode="tpm2",
                        tcti=tpm.tcti,
                        persistent_handle=0x81010011,
                        authorization_file=str(state / "auth"),
                        public_area_file=str(state / "public.tpmt"),
                        work_directory=str(work),
                    )
                    assert case.invoke(key_configuration=key_configuration)[
                        "result"
                    ] == dict(id=42, active=True)
                    assert (
                        provider.requests[-1]["headers"]["authorization"]
                        == "Bearer " + TOKEN
                    )
                    assert not case.invoke(role="client2")["ok"]
                    assert len(provider.requests) == 1
