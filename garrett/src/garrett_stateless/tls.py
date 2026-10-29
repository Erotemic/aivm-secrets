"""TLS contexts and the authenticated peer identity (spec section 6).

The peer thumbprint comes from the certificate the TLS stack verified in
the completed handshake (``getpeercert(binary_form=True)``)."""
from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from .core import encoding as enc


def thumbprint(der: bytes) -> str:
    """The ``x5t#S256`` of a certificate DER."""
    return enc.b64url(hashlib.sha256(der).digest())


def _harden(context: ssl.SSLContext) -> ssl.SSLContext:
    context.options |= ssl.OP_NO_COMPRESSION
    if hasattr(context, 'num_tickets'):
        context.num_tickets = 0
    return context


def mtls_server(certificate: Path, key: Path, client_ca: Path) -> ssl.SSLContext:
    """TLS 1.3; a client certificate chaining to ``client_ca`` required."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(client_ca))
    context.load_cert_chain(str(certificate), str(key))
    return _harden(context)


def server(certificate: Path, key: Path) -> ssl.SSLContext:
    """Server authentication only (the broker's browser endpoint)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(key))
    return _harden(context)


def agent_client(server_ca: Path, certificate: Path, key: Path) -> ssl.SSLContext:
    """TLS 1.3 to a broker or proxy, authenticating with a software key."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(server_ca))
    context.load_cert_chain(str(certificate), str(key))
    return context


def upstream_client(ca_file: Path | None) -> ssl.SSLContext:
    """A provider API or token endpoint: a pinned CA, or the system roots."""
    context = ssl.create_default_context(cafile=None if ca_file is None else str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


@dataclass(frozen=True)
class PeerIdentity:
    thumbprint: str
    subject: str
    not_after: int

    @classmethod
    def from_der(cls, der: bytes) -> 'PeerIdentity':
        cert = x509.load_der_x509_certificate(der)
        print_ = thumbprint(der)
        subject = f'x5t#S256:{print_}'
        try:
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            uris = names.get_values_for_type(x509.UniformResourceIdentifier)
            if uris and enc.is_text(uris[0]):
                subject = uris[0]
        except x509.ExtensionNotFound:
            pass
        return cls(print_, subject, int(cert.not_valid_after_utc.timestamp()))

    @classmethod
    def from_socket(cls, sock: ssl.SSLSocket) -> 'PeerIdentity':
        der = sock.getpeercert(binary_form=True)
        if not der:
            raise ssl.SSLError('no client certificate')
        cert = x509.load_der_x509_certificate(der)
        try:
            usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
                raise ssl.SSLError('client certificate lacks clientAuth')
        except x509.ExtensionNotFound:
            pass
        return cls.from_der(der)
