//! Bounded outbound guest frame and a single application-write attempt.
//! JSON/disclosure and TLS/Write semantics remain adapter contracts. A marked
//! attempt, including a zero-byte/partial/flush error, is never retried here.

pub enum FrameDenial {
    Invalid,
}

pub struct Frame {
    wire: Vec<u8>,
    attempted: bool,
}

pub fn prepare(mut payload: Vec<u8>, limit: usize) -> Result<Frame, FrameDenial> {
    // Reserve the terminal newline within the existing reply bound. This
    // also discharges the modeled push's integer/length bound.
    if payload.len() >= limit {
        return Err(FrameDenial::Invalid);
    }
    payload.push(b'\n');
    if !crate::line_frame::complete(&payload, b"", limit) {
        return Err(FrameDenial::Invalid);
    }
    Ok(Frame {
        wire: payload,
        attempted: false,
    })
}

pub trait Writer {
    type Error;
    const ALREADY_ATTEMPTED: Self::Error;
    fn write_frame(&mut self, wire: &[u8]) -> Result<(), Self::Error>;
}

impl Frame {
    pub fn attempted(&self) -> bool {
        self.attempted
    }
    pub fn send<W: Writer>(&mut self, writer: &mut W) -> Result<(), W::Error> {
        if self.attempted {
            return Err(W::ALREADY_ATTEMPTED);
        }
        self.attempted = true;
        writer.write_frame(&self.wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_exact_one_line_without_payload_rewriting() {
        for payload in [b"{}".as_slice(), b"line\nother", b"line\n", b""] {
            let size = payload.len() + 1;
            assert!(matches!(
                prepare(payload.to_vec(), size - 1),
                Err(FrameDenial::Invalid)
            ));
            let prepared = prepare(payload.to_vec(), size);
            assert_eq!(prepared.is_ok(), !payload.contains(&b'\n'));
            if let Ok(frame) = prepared {
                let mut expected = payload.to_vec();
                expected.push(b'\n');
                assert_eq!(frame.wire, expected);
                assert!(!frame.attempted());
            }
        }
        assert!(prepare(Vec::new(), 0).is_err());
    }
}
