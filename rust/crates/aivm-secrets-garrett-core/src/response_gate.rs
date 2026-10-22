//! Source-owned, extractable provider response handoff.
//!
//! Only a successfully submitted and flushed Channel can yield a Released
//! token. Its fields and constructor are private; the native parser accepts
//! the token by value, rather than receiving a Channel or an arbitrary tuple.
//! The token is deliberately not Clone or Copy. Native parser, TLS delivery,
//! response bytes and deadlines remain external to the extracted model.
//!
//! Aeneas cannot translate the former nested generic Parser trait (associated
//! output and a different trait's associated error). Use the same extraction-
//! friendly, owned-data gate as provider_io::Channel::into_parts instead.

use crate::provider_io::{Channel, Request, WireBytes, Writer};

/// Proof-carrying response parts. The only safe constructor is `receive`.
/// The native parser can consume the exact captured parts but cannot forge
/// permission by constructing this struct outside the core crate.
pub struct Released<B: WireBytes, W, M> {
    writer: W,
    request: Request<B>,
    metadata: M,
}

impl<B: WireBytes, W, M> Released<B, W, M> {
    /// Consume the one-shot parse eligibility token, transferring the exact
    /// writer/request/metadata state owned by the source channel.
    pub fn into_parts(self) -> (W, Request<B>, M) {
        (self.writer, self.request, self.metadata)
    }
}

/// The production ManifestProvider calls this gate before its native parser.
/// No Released value can emerge unless Channel::into_parts succeeds, which
/// itself requires the source-owned write-and-flush ready flag.
pub fn receive<B: WireBytes, W: Writer, M>(
    channel: Channel<B, W, M>,
) -> Result<Released<B, W, M>, W::Error> {
    let (writer, request, metadata) = channel.into_parts()?;
    Ok(Released {
        writer,
        request,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_io;

    #[derive(Debug, PartialEq, Eq)]
    enum Failure {
        NotReady,
        Write,
        Flush,
    }
    struct Bytes(Vec<u8>);
    impl WireBytes for Bytes {
        fn bytes(&self) -> &Vec<u8> {
            &self.0
        }
    }
    struct TestWriter {
        write_error: bool,
        flush_error: bool,
        calls: Vec<&'static str>,
    }
    impl Writer for TestWriter {
        type Error = Failure;
        const INVALID_TRANSITION: Failure = Failure::NotReady;
        fn write_all(&mut self, _: &Vec<u8>) -> Result<(), Failure> {
            self.calls.push("write");
            if self.write_error {
                Err(Failure::Write)
            } else {
                Ok(())
            }
        }
        fn flush(&mut self) -> Result<(), Failure> {
            self.calls.push("flush");
            if self.flush_error {
                Err(Failure::Flush)
            } else {
                Ok(())
            }
        }
    }
    fn new_channel(write_error: bool, flush_error: bool) -> Channel<Bytes, TestWriter, u64> {
        provider_io::Channel::new(
            Bytes(vec![1, 2, 3]),
            TestWriter { write_error, flush_error, calls: vec![] },
            731,
        )
    }
    fn consume_token(token: Released<Bytes, TestWriter, u64>, parsed: &mut usize) {
        let (writer, request, metadata) = token.into_parts();
        assert_eq!(writer.calls, ["write", "flush"]);
        assert!(request.attempted());
        assert_eq!(metadata, 731);
        *parsed += 1;
    }
    #[test]
    fn parse_token_exists_only_after_successful_submit_and_flush() {
        let mut parsed = 0;
        assert!(matches!(receive(new_channel(false, false)), Err(Failure::NotReady)));
        assert_eq!(parsed, 0);
        for (write_error, flush_error, expected) in [
            (true, false, Failure::Write),
            (false, true, Failure::Flush),
        ] {
            let mut channel = new_channel(write_error, flush_error);
            assert_eq!(channel.submit(), Err(expected));
            assert!(matches!(receive(channel), Err(Failure::NotReady)));
            assert_eq!(parsed, 0);
        }
        let mut channel = new_channel(false, false);
        assert_eq!(channel.submit(), Ok(()));
        consume_token(receive(channel).ok().unwrap(), &mut parsed);
        assert_eq!(parsed, 1);
    }
    #[test]
    fn extra_submit_withdraws_a_previously_successful_parse_token() {
        let mut channel = new_channel(false, false);
        assert_eq!(channel.submit(), Ok(()));
        assert_eq!(channel.submit(), Err(Failure::NotReady));
        assert!(matches!(receive(channel), Err(Failure::NotReady)));
    }
}
