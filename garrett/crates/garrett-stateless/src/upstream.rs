//! The proxy's provider transport: the only code that opens a TLS session to
//! a provider or writes to one.
//!
//! This module is the native half of the core's `stateless_proxy::exchange`
//! and the whole of the native code the network-level confinement theorem
//! trusts (`TransportFaithful` in `proofs/Garrett.lean`,
//! `STATELESS-NATIVE-01`). Its types carry the contract:
//!
//! * an [`Authenticated`] session exists only after [`Authenticated::open`]
//!   connected to a destination's address and port and completed a TLS
//!   handshake in which the server proved the destination's host under the
//!   destination's trust anchors; it remembers that destination;
//! * [`Authenticated::transmit`] consumes the session and one core `Egress`,
//!   refuses an egress for any other destination, and writes the egress bytes
//!   as TLS application data, once. A failed write may have emitted any
//!   prefix of them and nothing else; a success means they were all written
//!   and flushed to the socket, not that the provider received them;
//! * after the write only an [`Answering`] session is left, which can be read
//!   and never written: one authorized request per session, no retry.
//!
//! The fields are private, so nothing else in this crate can reach a provider
//! socket. What the types cannot say — that `write_all` and `flush` write
//! only the bytes they are given, that rustls verifies the name and the
//! chain, and that reading the answer emits no application data — is the
//! trusted remainder, with the TLS library and the operating system.
use crate::error::Result;
use crate::tls;
use garrett_stateless_core::stateless_proxy::{
    egress_destination, egress_wire, Destination, Egress, Received,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const UPSTREAM_DEADLINE: Duration = Duration::from_secs(45);

/// The TLS client for a destination's trust anchors (PEM), or the default
/// web roots when it names none.
pub(crate) fn client(trust: &[u8]) -> Result<Arc<ClientConfig>> {
    if trust.is_empty() {
        tls::upstream_client(None)
    } else {
        tls::upstream_client(Some(trust))
    }
}

/// A TLS session to a provider whose server authenticated as the host of
/// `destination`, on which nothing has been written yet.
pub(crate) struct Authenticated {
    destination: Destination,
    tls: StreamOwned<ClientConnection, TcpStream>,
    started: Instant,
}

/// The same session after its one write: it can only be read.
pub(crate) struct Answering {
    tls: StreamOwned<ClientConnection, TcpStream>,
    started: Instant,
}

impl Authenticated {
    /// Connect to `destination` and complete a TLS handshake in which the
    /// server proves `destination.host` under `destination.trust`.
    pub(crate) fn open(destination: &Destination) -> Option<Authenticated> {
        let address = std::str::from_utf8(&destination.address).ok()?;
        let host = std::str::from_utf8(&destination.host).ok()?;
        let socket_address = (address, destination.port).to_socket_addrs().ok()?.next()?;
        let socket = TcpStream::connect_timeout(&socket_address, IO_TIMEOUT).ok()?;
        socket.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
        socket.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
        let name = ServerName::try_from(host.to_string()).ok()?;
        let config = client(&destination.trust).ok()?;
        let connection = ClientConnection::new(config, name).ok()?;
        let mut tls = StreamOwned::new(connection, socket);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).ok()?;
        }
        Some(Authenticated {
            destination: destination.clone(),
            tls,
            started: Instant::now(),
        })
    }

    /// The one write of this session: the egress bytes, if the egress is for
    /// this session's destination. `None` if it was refused or the write
    /// failed (the provider may have received a prefix of the bytes); the
    /// session is then gone.
    pub(crate) fn transmit(self, egress: Egress) -> Option<Answering> {
        if &self.destination != egress_destination(&egress) {
            return None;
        }
        let mut tls = self.tls;
        let written = tls.write_all(egress_wire(&egress));
        drop(egress);
        written.and_then(|()| tls.flush()).ok()?;
        Some(Answering {
            tls,
            started: self.started,
        })
    }
}

impl Answering {
    /// The next read of the provider's answer into `chunk`. `End` or
    /// `Failed` ends the session.
    pub(crate) fn receive(&mut self, chunk: &mut [u8]) -> Received {
        if self.started.elapsed() > UPSTREAM_DEADLINE {
            return Received::Failed;
        }
        match self.tls.read(chunk) {
            Ok(0) => Received::End,
            Ok(n) => Received::Bytes(chunk[..n].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Received::End,
            Err(_) => Received::Failed,
        }
    }
}
