"""A per-session interception CA, name-constrained to the policy's origins.

The guest trusts this CA only for the duration of one proxy session. Its key
is generated in host memory and never written to disk or sent to the guest.
X.509 ``nameConstraints`` limit it to the configured origin host names, so a
copy of the CA certificate cannot help forge a certificate for any other
name in a client that enforces constraints. Leaf certificates are minted
only for configured origins.
"""

from __future__ import annotations

import datetime
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


class SessionCA:
    def __init__(self, hosts: list[str], lifetime_seconds: int):
        self.hosts = tuple(hosts)
        now = datetime.datetime.now(datetime.timezone.utc)
        self._not_before = now - datetime.timedelta(minutes=1)
        self._not_after = now + datetime.timedelta(seconds=lifetime_seconds + 60)
        self._key = ec.generate_private_key(ec.SECP256R1())
        public = self._key.public_key()
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(_name('aivm-secrets proxy session CA'))
            .issuer_name(_name('aivm-secrets proxy session CA'))
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before)
            .not_valid_after(self._not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(digital_signature=False, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=True, crl_sign=False,
                              encipher_only=False, decipher_only=False),
                critical=True,
            )
            .add_extension(
                x509.NameConstraints(
                    permitted_subtrees=[x509.DNSName(host) for host in self.hosts],
                    excluded_subtrees=None,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        self._contexts: dict[str, ssl.SSLContext] = {}

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def _leaf(self, host: str) -> tuple[bytes, bytes]:
        if host not in self.hosts:
            raise ValueError('unknown_origin')
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(_name(host))
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self._not_before)
            .not_valid_after(self._not_after)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        return (
            certificate.public_bytes(serialization.Encoding.PEM) + self.pem,
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
        )

    def server_context(self, host: str) -> ssl.SSLContext:
        """TLS 1.2+ server context presenting the leaf for ``host`` only."""
        if host in self._contexts:
            return self._contexts[host]
        chain, key = self._leaf(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        # ``load_cert_chain`` needs files; keep them private and transient.
        with tempfile.TemporaryDirectory(prefix='aivm-proxy-leaf-') as directory:
            chain_path = Path(directory) / 'chain.pem'
            key_path = Path(directory) / 'key.pem'
            chain_path.write_bytes(chain)
            key_path.touch(mode=0o600)
            key_path.write_bytes(key)
            context.load_cert_chain(chain_path, key_path)
        self._contexts[host] = context
        return context
