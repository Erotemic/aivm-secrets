//! Source-owned route forwarding and captured provider-byte submission.
//! Native DNS/TLS/Write/parser and storage semantics remain contracts.
// Keep the same borrowed byte-vector carrier in the extracted writer contract.
#![allow(clippy::ptr_arg)]
use crate::{credential_use::Route, dispatch, provider_exchange, read_transition::Phase};

pub trait RouteWork<C, E> {
    fn setup_route(&mut self, route: &Route) -> Result<C, E>;
    fn audit_route(&mut self, route: &Route, phase: Phase) -> Result<(), E>;
}

pub struct Routed<'a, W: dispatch::Work>
where
    W: RouteWork<W::Channel, W::Error>,
{
    route: &'a Route,
    work: W,
}
impl<'a, W: dispatch::Work> Routed<'a, W>
where
    W: RouteWork<W::Channel, W::Error>,
{
    pub fn new(route: &'a Route, work: W) -> Self {
        Self { route, work }
    }
}
impl<W: dispatch::Work> provider_exchange::Provider for Routed<'_, W>
where
    W: RouteWork<W::Channel, W::Error>,
{
    type Channel = W::Channel;
    type Output = W::Output;
    type Error = W::Error;
    const INVALID_POLICY: Self::Error = W::INVALID_POLICY;
    const OUTCOME_UNKNOWN: Self::Error = W::OUTCOME_UNKNOWN;
    fn setup(&mut self) -> Result<Self::Channel, Self::Error> {
        self.work.setup_route(self.route)
    }
    fn recheck(&mut self) -> Result<crate::manifest::AdmissionStamp, Self::Error> {
        self.work.recheck()
    }
    fn send(&mut self, channel: &mut Self::Channel) -> Result<(), Self::Error> {
        self.work.send(channel)
    }
    fn receive(&mut self, channel: Self::Channel) -> Result<Self::Output, Self::Error> {
        self.work.receive(channel)
    }
}
impl<W: dispatch::Work> dispatch::Work for Routed<'_, W>
where
    W: RouteWork<W::Channel, W::Error>,
{
    const INVALID_TRANSITION: Self::Error = W::INVALID_TRANSITION;
    fn effect_write(&self) -> bool {
        self.work.effect_write()
    }
    fn prepare(&mut self) -> Result<(), Self::Error> {
        self.work.prepare()
    }
    fn audit(&mut self, phase: Phase) -> Result<(), Self::Error> {
        self.work.audit_route(self.route, phase)
    }
    fn configure(&mut self, keyed_write: bool) -> Result<(), Self::Error> {
        self.work.configure(keyed_write)
    }
    fn check(&mut self) -> Result<(), Self::Error> {
        self.work.check()
    }
    fn reserve(&mut self) -> Result<(), Self::Error> {
        self.work.reserve()
    }
    fn finish(&mut self) -> Result<(), Self::Error> {
        self.work.finish()
    }
}

pub trait WireBytes {
    fn bytes(&self) -> &Vec<u8>;
}
pub trait Writer {
    type Error;
    const INVALID_TRANSITION: Self::Error;
    fn write_all(&mut self, bytes: &Vec<u8>) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// Own the native buffer wrapper so its zeroizing drop remains native. There
/// is no setter, reset or retry, including after zero/partial writes or flush.
pub struct Request<B: WireBytes> {
    body: B,
    attempted: bool,
}
impl<B: WireBytes> Request<B> {
    pub fn new(body: B) -> Self {
        Self {
            body,
            attempted: false,
        }
    }
    pub fn attempted(&self) -> bool {
        self.attempted
    }
    pub fn submit<W: Writer>(&mut self, writer: &mut W) -> Result<(), W::Error> {
        if self.attempted {
            return Err(W::INVALID_TRANSITION);
        }
        self.attempted = true;
        let bytes = self.body.bytes();
        match writer.write_all(bytes) {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
        writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Buffer {
        bytes: Vec<u8>,
        reads: Cell<usize>,
    }
    impl WireBytes for Buffer {
        fn bytes(&self) -> &Vec<u8> {
            self.reads.set(self.reads.get() + 1);
            &self.bytes
        }
    }
    struct Sink {
        calls: Vec<&'static str>,
        accepted: Vec<u8>,
        limit: usize,
        flush_error: bool,
    }
    impl Writer for Sink {
        type Error = &'static str;
        const INVALID_TRANSITION: Self::Error = "replay";
        fn write_all(&mut self, bytes: &Vec<u8>) -> Result<(), Self::Error> {
            self.calls.push("write");
            self.accepted
                .extend_from_slice(&bytes[..bytes.len().min(self.limit)]);
            if self.limit < bytes.len() {
                Err("write")
            } else {
                Ok(())
            }
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            self.calls.push("flush");
            if self.flush_error {
                Err("flush")
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn captured_exact_bytes_and_every_write_flush_prefix_stay_spent() {
        for (limit, flush_error) in [
            (0, false),
            (4, false),
            (usize::MAX, true),
            (usize::MAX, false),
        ] {
            let bytes = b"synthetic-request\0\xff".to_vec();
            let mut request = Request::new(Buffer {
                bytes: bytes.clone(),
                reads: Cell::new(0),
            });
            let mut sink = Sink {
                calls: vec![],
                accepted: vec![],
                limit,
                flush_error,
            };
            assert!(!request.attempted());
            assert_eq!(
                request.submit(&mut sink),
                if limit < bytes.len() {
                    Err("write")
                } else if flush_error {
                    Err("flush")
                } else {
                    Ok(())
                }
            );
            assert!(request.attempted());
            assert_eq!(sink.accepted, bytes[..bytes.len().min(limit)]);
            assert_eq!(
                sink.calls,
                if limit < bytes.len() {
                    vec!["write"]
                } else {
                    vec!["write", "flush"]
                }
            );
            assert_eq!(request.body.reads.get(), 1);
            let before = sink.accepted.clone();
            let calls = sink.calls.clone();
            // Even a different body cannot make an attempted request reusable.
            request.body.bytes = b"other".to_vec();
            assert_eq!(request.submit(&mut sink), Err("replay"));
            assert_eq!(sink.accepted, before);
            assert_eq!(sink.calls, calls);
            assert_eq!(request.body.reads.get(), 1);
        }
    }
}
