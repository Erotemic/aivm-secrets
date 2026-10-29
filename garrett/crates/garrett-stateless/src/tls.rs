//! TLS configurations and the authenticated peer identity (spec section 6).
//!
//! The peer thumbprint is computed from the certificate rustls verified in
//! the completed handshake; nothing a client sends inside the connection
//! can supply or change it.
use crate::encoding::{is_text, thumbprint};
use crate::error::{Error, Result};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
use std::sync::Arc;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls(message: &str) -> Error {
    Error::Tls(message.to_owned())
}

pub fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut &*pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| tls("bad certificate PEM"))?;
    if certs.is_empty() {
        return Err(tls("no certificate in PEM"));
    }
    Ok(certs)
}

pub fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &*pem)
        .map_err(|_| tls("bad private key PEM"))?
        .ok_or_else(|| tls("no private key in PEM"))
}

pub fn roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in certificates(pem)? {
        store.add(cert).map_err(|_| tls("bad CA certificate"))?;
    }
    Ok(store)
}

fn harden(mut config: ServerConfig) -> Arc<ServerConfig> {
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.max_early_data_size = 0;
    Arc::new(config)
}

/// TLS 1.3, a client certificate chaining to `client_ca` required.
pub fn mtls_server(certificate: &[u8], key: &[u8], client_ca: &[u8]) -> Result<Arc<ServerConfig>> {
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(client_ca)?), provider())
            .build()
            .map_err(|_| tls("client verifier"))?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| tls("protocol versions"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(certificate)?, private_key(key)?)
        .map_err(|_| tls("server certificate and key do not match"))?;
    Ok(harden(config))
}

/// Server authentication only (the broker's browser endpoint).
pub fn server(certificate: &[u8], key: &[u8]) -> Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| tls("protocol versions"))?
        .with_no_client_auth()
        .with_single_cert(certificates(certificate)?, private_key(key)?)
        .map_err(|_| tls("server certificate and key do not match"))?;
    Ok(harden(config))
}

/// How an agent proves its identity.
pub enum ClientIdentity {
    /// A PEM certificate chain and private key (software custody).
    Software { certificate: Vec<u8>, key: Vec<u8> },
    /// An external signer (TPM, HSM); the private key never enters this process.
    Resolver(Arc<dyn ResolvesClientCert>),
}

impl ClientIdentity {
    /// A TPM-backed identity (feature `tpm`, `crate::tpm`).
    #[cfg(feature = "tpm")]
    pub fn tpm(configuration: crate::tpm::Configuration, certificate: &[u8]) -> Result<Self> {
        Ok(ClientIdentity::Resolver(crate::tpm::resolver(
            configuration,
            certificate,
        )?))
    }
}

fn finish(mut config: ClientConfig) -> Arc<ClientConfig> {
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

/// TLS 1.3 to a broker or proxy, authenticating with `identity`.
pub fn agent_client(server_ca: &[u8], identity: ClientIdentity) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| tls("protocol versions"))?
        .with_root_certificates(roots(server_ca)?);
    let config = match identity {
        ClientIdentity::Software { certificate, key } => builder
            .with_client_auth_cert(certificates(&certificate)?, private_key(&key)?)
            .map_err(|_| tls("client certificate and key do not match"))?,
        ClientIdentity::Resolver(resolver) => builder.with_client_cert_resolver(resolver),
    };
    Ok(finish(config))
}

/// A server-authenticated client (a provider API or token endpoint):
/// `ca` pins a CA bundle; `None` uses the Mozilla web PKI roots.
pub fn upstream_client(ca: Option<&[u8]>) -> Result<Arc<ClientConfig>> {
    let store = match ca {
        Some(pem) => roots(pem)?,
        None => RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        },
    };
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| tls("protocol versions"))?
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(finish(config))
}

/// The identity of the authenticated client of a completed handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// `x5t#S256` of the leaf certificate DER.
    pub thumbprint: String,
    /// Spec section 6.2.
    pub subject: String,
    /// The leaf's `notAfter`, Unix seconds.
    pub not_after: i64,
}

impl PeerIdentity {
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, cert) =
            x509_parser::parse_x509_certificate(der).map_err(|_| tls("peer certificate"))?;
        let print = thumbprint(der);
        let mut subject = format!("x5t#S256:{print}");
        if let Ok(Some(names)) = cert.subject_alternative_name() {
            for name in &names.value.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if is_text(uri) {
                        subject = (*uri).to_owned();
                    }
                    break;
                }
            }
        }
        Ok(Self {
            thumbprint: print,
            subject,
            not_after: cert.validity().not_after.timestamp(),
        })
    }
    /// The verified peer of a server connection whose handshake completed.
    pub fn from_connection(connection: &ServerConnection) -> Result<Self> {
        if connection.is_handshaking() {
            return Err(tls("handshake incomplete"));
        }
        let leaf = connection
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or_else(|| tls("no client certificate"))?;
        Self::from_der(leaf.as_ref())
    }
}
