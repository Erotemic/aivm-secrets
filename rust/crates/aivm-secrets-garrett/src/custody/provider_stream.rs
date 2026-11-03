//! The bridge's provider transport: the only native code that opens a TLS
//! session to a provider and the only native code that can write to one.
//!
//! [`connect`] opens a TCP connection to the configured provider address and
//! completes a TLS handshake in which the server proves `host` under the
//! bridge's roots. It returns a [`ProviderWriter`] that owns the session.
//! The session is a private field of this module's types, so the rest of the
//! crate reaches the provider socket only through:
//!
//! * the extracted core's `provider_io::Writer` contract (`write_all`,
//!   `flush`), which, on the manifest read path, only the core's
//!   `Request::submit` calls, once per request (`NATIVE-SINK-01`);
//! * [`ProviderWriter::into_reader`], which turns the session into a
//!   [`ProviderReader`] that can only be read: the native response parser
//!   receives the session after the core's response gate, but cannot write
//!   to the provider through it.
//!
//! What the types cannot say — that `write_all` and `flush` emit only the
//! bytes they are given and that rustls verifies the name and chain — stays
//! with the TLS library and the operating system.
use super::{Deadline, Error, Outcome};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

type Session = StreamOwned<ClientConnection, TcpStream>;

/// An authenticated provider session on which the core may write. Generic
/// only so the unit tests can drive the production callbacks over a fake
/// stream; outside tests the one way to make one is [`connect`].
pub(super) struct ProviderWriter<W: Write = Session>(W);

/// The same session after the core released it: read-only.
pub(super) struct ProviderReader<W = Session>(W);

/// Connect to `address` and complete a TLS handshake in which the server
/// proves `host` under `tls`'s roots. `name_error` is the error for an
/// unusable server name, `setup_error` for an unusable TLS client.
pub(super) fn connect(
    tls: &Arc<ClientConfig>,
    address: SocketAddr,
    host: &str,
    name_error: Error,
    setup_error: Error,
) -> Outcome<(ProviderWriter, Deadline)> {
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|_| Error::Unreachable)?;
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| Error::Unreachable)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| Error::Unreachable)?;
    // The deadline's handle can only shut the socket down.
    let killer = socket.try_clone().map_err(|_| Error::Unreachable)?;
    let deadline = Deadline::start_for(Duration::from_secs(40), move || {
        let _ = killer.shutdown(std::net::Shutdown::Both);
    });
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| name_error)?;
    let mut conn = ClientConnection::new(tls.clone(), name).map_err(|_| setup_error)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut socket)
            .map_err(|_| Error::Unreachable)?;
    }
    Ok((ProviderWriter(StreamOwned::new(conn, socket)), deadline))
}

// The standard Write contract includes partial acceptance before an error.
impl<W: Write> aivm_secrets_garrett_core::provider_io::Writer for ProviderWriter<W> {
    type Error = Error;
    const INVALID_TRANSITION: Error = Error::InternalError;
    fn write_all(&mut self, bytes: &Vec<u8>) -> Outcome<()> {
        self.0.write_all(bytes).map_err(|_| Error::UpstreamResponse)
    }
    fn flush(&mut self) -> Outcome<()> {
        self.0.flush().map_err(|_| Error::UpstreamResponse)
    }
}

impl<W: Write> ProviderWriter<W> {
    /// Give up writing: what remains is the provider's answer.
    pub(super) fn into_reader(self) -> ProviderReader<W> {
        ProviderReader(self.0)
    }
}

#[cfg(test)]
impl<W: Write> ProviderWriter<W> {
    pub(super) fn wrap(stream: W) -> Self {
        Self(stream)
    }
    pub(super) fn inner(self) -> W {
        self.0
    }
}

impl<W: Read> Read for ProviderReader<W> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}
