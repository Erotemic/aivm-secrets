//! Source-owned durable audit callback order.
//!
//! Successful acknowledgement requires payload append, record delimiter,
//! and a completed sync callback in that order. The flag is set before the
//! first external callback; even partial I/O or unwinding leaves it poisoned.
//! The concrete File adapter, kernel durability and mutex remain outside the
//! extracted model. The adapter must implement `append` as an exact write of
//! its supplied byte vector, and `sync_record` as the required persistence
//! barrier; no such effects are inferred from this trait.

/// Callback boundary for one durable record. `Vec` is used deliberately to
/// carry the same captured byte vector through extraction and native I/O.
pub trait Sink {
    type Error;
    const POISONED: Self::Error;
    fn append(&mut self, bytes: &Vec<u8>) -> Result<(), Self::Error>;
    fn sync_record(&mut self) -> Result<(), Self::Error>;
}

/// Exactly one LF record separator, with its bytes exposed to extraction.
pub fn record_delimiter() -> Vec<u8> {
    vec![b'\n']
}

/// The production audit recorder calls this function directly while holding
/// its session mutex. No native code is permitted to insert callbacks between
/// the three source-owned effects.
pub fn append_durable_record<S: Sink>(
    sink: &mut S,
    poisoned: &mut bool,
    bytes: &Vec<u8>,
) -> Result<(), S::Error> {
    if *poisoned {
        return Err(S::POISONED);
    }
    *poisoned = true;
    sink.append(bytes)?;
    let delimiter = record_delimiter();
    sink.append(&delimiter)?;
    sink.sync_record()?;
    *poisoned = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Failure { Poisoned, Callback }
    struct Probe {
        calls: Vec<&'static str>,
        bytes: Vec<u8>,
        fail: Option<&'static str>,
    }
    impl Sink for Probe {
        type Error = Failure;
        const POISONED: Failure = Failure::Poisoned;
        fn append(&mut self, bytes: &Vec<u8>) -> Result<(), Failure> {
            let stage = if bytes.as_slice() == b"\n" { "delimiter" } else { "payload" };
            self.calls.push(stage);
            if self.fail == Some(stage) {
                return Err(Failure::Callback);
            }
            if self.fail == Some("partial") && stage == "payload" {
                self.bytes.extend_from_slice(&bytes[..bytes.len().min(3)]);
                return Err(Failure::Callback);
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }
        fn sync_record(&mut self) -> Result<(), Failure> {
            self.calls.push("sync");
            if self.fail == Some("sync") {
                Err(Failure::Callback)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn all_returned_error_prefixes_are_fail_stop() {
        for (fault, calls, bytes) in [
            (Some("payload"), vec!["payload"], b"".as_slice()),
            (Some("partial"), vec!["payload"], b"abc".as_slice()),
            (Some("delimiter"), vec!["payload", "delimiter"], b"abcdef".as_slice()),
            (Some("sync"), vec!["payload", "delimiter", "sync"], b"abcdef\n".as_slice()),
            (None, vec!["payload", "delimiter", "sync"], b"abcdef\n".as_slice()),
        ] {
            let mut sink = Probe { calls: Vec::new(), bytes: Vec::new(), fail: fault };
            let mut poisoned = false;
            let result = append_durable_record(&mut sink, &mut poisoned, &b"abcdef".to_vec());
            assert_eq!(result.is_ok(), fault.is_none());
            assert_eq!(poisoned, fault.is_some());
            assert_eq!(sink.calls, calls);
            assert_eq!(sink.bytes, bytes);
            let before = sink.calls.len();
            if fault.is_some() {
                assert_eq!(append_durable_record(&mut sink, &mut poisoned, &vec![42]), Err(Failure::Poisoned));
                assert_eq!(sink.calls.len(), before);
            }
        }
    }
    #[test]
    fn callback_panic_poisoned_before_first_effect() {
        struct PanicSink;
        impl Sink for PanicSink {
            type Error = Failure;
            const POISONED: Failure = Failure::Poisoned;
            fn append(&mut self, _: &Vec<u8>) -> Result<(), Failure> { panic!("synthetic panic") }
            fn sync_record(&mut self) -> Result<(), Failure> { unreachable!() }
        }
        let mut poisoned = false;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = append_durable_record(&mut PanicSink, &mut poisoned, &vec![42]);
        }));
        assert!(caught.is_err() && poisoned);
    }
}
