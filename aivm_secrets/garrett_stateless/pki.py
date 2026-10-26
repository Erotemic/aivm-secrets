"""A minimal development PKI (software keys only)."""
from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True, repr=False)
class Issued:
    certificate: bytes  # PEM
    key: bytes  # PEM PKCS#8

    def __repr__(self) -> str:
        return 'Issued(<certificate>, <key>)'


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _window(builder, days: int):
    now = datetime.datetime.now(datetime.timezone.utc)
    return builder.not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))


def create_ca(name: str, days: int = 30) -> Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    cert = _window(builder, days).sign(key, hashes.SHA256())
    return Issued(cert.public_bytes(serialization.Encoding.PEM), _pem_key(key))


def issue(ca: Issued, *, server_names: list[str] | None = None, client_name: str | None = None,
          uri: str | None = None, days: int = 30) -> Issued:
    """A server certificate for ``server_names`` or a client one for ``client_name``."""
    ca_cert = x509.load_pem_x509_certificate(ca.certificate)
    ca_key = serialization.load_pem_private_key(ca.key, None)
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateBuilder().issuer_name(ca_cert.subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if server_names:
        names = []
        for name in server_names:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                names.append(x509.DNSName(name))
        builder = (builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_names[0])]))
                   .add_extension(x509.SubjectAlternativeName(names), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    else:
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_name or 'agent')]))
        if uri:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]),
                                            critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    cert = _window(builder, days).sign(ca_key, hashes.SHA256())
    return Issued(cert.public_bytes(serialization.Encoding.PEM), _pem_key(key))
