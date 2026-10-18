//! TLS 1.3 client. Software keys and externally supplied key resolvers are explicit.
use crate::{json, tls::Deadline, Error, Outcome};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use std::{io::Write, os::unix::net::UnixStream, path::Path, sync::Arc, time::Duration};

pub struct AuthenticatedClientConfig(Arc<ClientConfig>);
fn roots(pem: &[u8]) -> Outcome<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for item in rustls_pemfile::certs(&mut &*pem) {
        roots
            .add(item.map_err(|_| Error::InvalidCapability)?)
            .map_err(|_| Error::InvalidCapability)?;
    }
    if roots.is_empty() {
        return Err(Error::InvalidCapability);
    }
    Ok(roots)
}
fn finish(mut config: ClientConfig) -> AuthenticatedClientConfig {
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    AuthenticatedClientConfig(Arc::new(config))
}
/// Software-key custody matches the current Python profile, without a TPM claim.
pub fn software_identity(
    certificate: &[u8],
    private_key: &[u8],
    server_ca: &[u8],
) -> Outcome<AuthenticatedClientConfig> {
    let certificate = rustls_pemfile::certs(&mut &*certificate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidCapability)?;
    let key = rustls_pemfile::private_key(&mut &*private_key)
        .map_err(|_| Error::InvalidCapability)?
        .ok_or(Error::InvalidCapability)?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::InvalidCapability)?
            .with_root_certificates(roots(server_ca)?)
            .with_client_auth_cert(certificate, key)
            .map_err(|_| Error::InvalidCapability)?;
    Ok(finish(config))
}
/// A trusted application can supply a TPM signing resolver without exporting a
/// private key or falling back to software. Enrollment still verifies provenance.
pub fn signing_resolver(
    server_ca: &[u8],
    resolver: Arc<dyn rustls::client::ResolvesClientCert>,
) -> Outcome<AuthenticatedClientConfig> {
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::InvalidCapability)?
            .with_root_certificates(roots(server_ca)?)
            .with_client_cert_resolver(resolver);
    Ok(finish(config))
}
pub fn exchange_unix(
    config: &AuthenticatedClientConfig,
    socket: &Path,
    server_name: &str,
    request: &Value,
) -> Outcome<Value> {
    let data = json::canonical(request);
    if data.len() + 1 > 65536 {
        return Err(Error::InvalidRequest);
    }
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::InvalidCapability)?;
    let mut connection =
        ClientConnection::new(config.0.clone(), name).map_err(|_| Error::InvalidCapability)?;
    let mut socket = UnixStream::connect(socket).map_err(|_| Error::Unreachable)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(55)))
        .map_err(|_| Error::InternalError)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(55)))
        .map_err(|_| Error::InternalError)?;
    let killer = socket.try_clone().map_err(|_| Error::InternalError)?;
    let _deadline = Deadline::start(move || {
        let _ = killer.shutdown(std::net::Shutdown::Both);
    });
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|_| Error::InvalidCapability)?;
    }
    let mut stream = StreamOwned::new(connection, socket);
    stream
        .write_all(&data)
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .map_err(|_| Error::OutcomeUnknown)?;
    let limit = 2 * 1024 * 1024 + 65536;
    // A sent request with an incomplete/ambiguous reply is never a definite
    // non-dispatch. The same bounded frame admission guards bridge ingress.
    let reply = crate::tls::frame(&mut stream, limit).map_err(|_| Error::OutcomeUnknown)?;
    let result = json::parse(&reply, limit).map_err(|_| Error::OutcomeUnknown)?;
    if !result.is_object() {
        return Err(Error::OutcomeUnknown);
    }
    Ok(result)
}
