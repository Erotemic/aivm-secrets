//! Admission of one bounded newline-delimited frame. JSON and stream reads
//! remain adapters; already buffered trailing bytes cannot be ignored.
#[allow(clippy::len_zero)]
pub fn complete(data: &[u8], buffered: &[u8], limit: usize) -> bool {
    if data.len() > limit || buffered.len() != 0 {
        return false;
    }
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\n' {
            return i + 1 == data.len();
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_terminal_newline_within_the_bound() {
        for body in [b"".as_slice(), b"{}", b"\0\xff"] {
            let mut frame = body.to_vec();
            frame.push(b'\n');
            assert!(complete(&frame, b"", frame.len()));
            assert!(!complete(&frame, b"", frame.len() - 1));
            assert!(!complete(&frame, b"pending", frame.len()));
            assert!(!complete(body, b"", usize::MAX));
            frame.push(b'\n');
            assert!(!complete(&frame, b"", usize::MAX));
        }
        assert!(!complete(b"", b"", usize::MAX));
        assert!(!complete(b"{}\ntrailing", b"", usize::MAX));
    }
}
