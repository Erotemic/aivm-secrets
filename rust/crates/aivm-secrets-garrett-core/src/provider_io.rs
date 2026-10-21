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

/// Keep the captured request, its concrete writer and response-lifetime state
/// together. Parsing receives their exact states only after a successful flush.
pub struct Channel<B: WireBytes, W: Writer, M> {
    request: Request<B>,
    writer: W,
    metadata: M,
    ready: bool,
}
impl<B: WireBytes, W: Writer, M> Channel<B, W, M> {
    pub fn new(body: B, writer: W, metadata: M) -> Self {
        Self {
            request: Request::new(body),
            writer,
            metadata,
            ready: false,
        }
    }
    pub fn submit(&mut self) -> Result<(), W::Error> {
        // A refused extra call also withdraws a previously successful receipt.
        self.ready = false;
        match self.request.submit(&mut self.writer) {
            Ok(()) => {
                self.ready = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    pub fn into_parts(self) -> Result<(W, Request<B>, M), W::Error> {
        if !self.ready {
            return Err(W::INVALID_TRANSITION);
        }
        Ok((self.writer, self.request, self.metadata))
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
    fn channel(limit: usize, flush_error: bool) -> Channel<Buffer, Sink, u64> {
        Channel::new(
            Buffer {
                bytes: b"captured-channel\0\xff".to_vec(),
                reads: Cell::new(0),
            },
            Sink {
                calls: vec![],
                accepted: vec![],
                limit,
                flush_error,
            },
            731,
        )
    }
    #[test]
    fn channel_captures_exact_parts_and_only_successful_flush_releases_them() {
        for (limit, flush_error) in [
            (0, false),
            (4, false),
            (usize::MAX, true),
            (usize::MAX, false),
        ] {
            let mut pending = channel(limit, flush_error);
            assert!(!pending.ready);
            assert!(!pending.request.attempted());
            let result = pending.submit();
            let success = limit == usize::MAX && !flush_error;
            assert_eq!(result.is_ok(), success);
            assert_eq!(pending.ready, success);
            assert!(pending.request.attempted());
            assert_eq!(pending.request.body.reads.get(), 1);
            assert_eq!(
                pending.writer.accepted,
                b"captured-channel\0\xff"[..b"captured-channel\0\xff".len().min(limit)]
            );
            if success {
                let (writer, request, metadata) = pending.into_parts().ok().unwrap();
                assert_eq!(writer.calls, ["write", "flush"]);
                assert_eq!(writer.accepted, request.body.bytes);
                assert!(request.attempted());
                assert_eq!(metadata, 731);
            } else {
                assert!(matches!(pending.into_parts(), Err("replay")));
            }
        }
    }
    #[test]
    fn channel_refuses_early_parse_and_extra_submission_withdraws_readiness() {
        assert!(matches!(
            channel(usize::MAX, false).into_parts(),
            Err("replay")
        ));
        let mut pending = channel(usize::MAX, false);
        assert_eq!(pending.submit(), Ok(()));
        let accepted = pending.writer.accepted.clone();
        let calls = pending.writer.calls.clone();
        assert_eq!(pending.submit(), Err("replay"));
        assert!(!pending.ready);
        assert_eq!(pending.writer.accepted, accepted);
        assert_eq!(pending.writer.calls, calls);
        assert_eq!(pending.request.body.reads.get(), 1);
        assert!(matches!(pending.into_parts(), Err("replay")));
    }
}
