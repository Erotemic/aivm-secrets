//! ASCII case folding and decimal formatting for the HTTP encoder.

pub fn ascii_lower(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' {
        byte + 32
    } else {
        byte
    }
}
pub fn ascii_prefix(name: &[u8], prefix: &[u8]) -> bool {
    if name.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if ascii_lower(name[i]) != ascii_lower(prefix[i]) {
            return false;
        }
        i += 1;
    }
    true
}
pub fn ascii_equal(name: &[u8], other: &[u8]) -> bool {
    name.len() == other.len() && ascii_prefix(name, other)
}
pub fn alphanumeric(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'0' && byte <= b'9')
}

// At most twenty recursive calls on the supported 64-bit target. Decimal
// formatting stays concrete in the extracted encoder, including body length.
pub fn append_decimal(output: &mut Vec<u8>, value: usize) {
    if value >= 10 {
        append_decimal(output, value / 10);
    }
    output.push(b'0' + (value % 10) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_matches_standard_formatting() {
        for value in [0, 1, 9, 10, 99, 100, 65535, usize::MAX] {
            let mut output = b"prefix".to_vec();
            append_decimal(&mut output, value);
            assert_eq!(output, format!("prefix{value}").into_bytes());
        }
    }

    #[test]
    fn folded_comparison_agrees_with_standard_ascii_rules() {
        for a in 0..=255u8 {
            assert_eq!(ascii_lower(a), a.to_ascii_lowercase());
            for b in 0..=255u8 {
                assert_eq!(ascii_equal(&[a], &[b]), [a].eq_ignore_ascii_case(&[b]));
            }
        }
    }
}
