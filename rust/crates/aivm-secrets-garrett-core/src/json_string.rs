//! Canonical ASCII JSON quoting of Unicode scalars. Native UTF-8 decoding and
//! byte/String conversion remain adapters; invalid scalar lists never append.
#![allow(clippy::ptr_arg)]

pub fn valid_scalar(value: u32) -> bool {
    value <= 0x10ffff && (value < 0xd800 || value > 0xdfff)
}
pub fn valid_text(values: &Vec<u32>) -> bool {
    let mut index = 0;
    while index < values.len() {
        if !valid_scalar(values[index]) {
            return false;
        }
        index += 1;
    }
    true
}
fn hex_digit(value: u32) -> u8 {
    if value < 10 {
        b'0' + value as u8
    } else {
        b'a' + (value - 10) as u8
    }
}
fn append_hex(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(b"\\u");
    output.push(hex_digit(value / 4096 % 16));
    output.push(hex_digit(value / 256 % 16));
    output.push(hex_digit(value / 16 % 16));
    output.push(hex_digit(value % 16));
}
fn append_wide(output: &mut Vec<u8>, value: u32) {
    if value <= 65535 {
        append_hex(output, value);
    } else {
        let remaining = value - 65536;
        append_hex(output, 55296 + remaining / 1024);
        append_hex(output, 56320 + remaining % 1024);
    }
}
fn append_scalar(output: &mut Vec<u8>, value: u32) {
    if value == 34 {
        output.extend_from_slice(b"\\\"");
    } else if value == 92 {
        output.extend_from_slice(b"\\\\");
    } else if value == 8 {
        output.extend_from_slice(b"\\b");
    } else if value == 12 {
        output.extend_from_slice(b"\\f");
    } else if value == 10 {
        output.extend_from_slice(b"\\n");
    } else if value == 13 {
        output.extend_from_slice(b"\\r");
    } else if value == 9 {
        output.extend_from_slice(b"\\t");
    } else if value >= 32 && value <= 126 {
        output.push(value as u8);
    } else {
        append_wide(output, value);
    }
}

/// Validate the entire scalar list before touching the caller's buffer.
/// Successful output is quoted ASCII, including UTF-16 pairs for non-BMP text.
pub fn append(output: &mut Vec<u8>, values: &Vec<u32>) -> bool {
    if !valid_text(values) {
        return false;
    }
    output.push(b'"');
    let mut index = 0;
    while index < values.len() {
        append_scalar(output, values[index]);
        index += 1;
    }
    output.push(b'"');
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(value: char) -> Vec<u8> {
        use std::fmt::Write;
        let mut output = String::from("\"");
        match value {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ' '..='~' => output.push(value),
            _ => {
                for unit in value.encode_utf16(&mut [0; 2]) {
                    write!(output, "\\u{unit:04x}").unwrap();
                }
            }
        }
        output.push('"');
        output.into_bytes()
    }
    #[test]
    fn every_unicode_scalar_matches_independent_utf16_formatting() {
        for code in 0..=0x10ffff {
            if let Some(value) = char::from_u32(code) {
                let mut output = Vec::new();
                assert!(append(&mut output, &vec![code]));
                assert_eq!(output, reference(value), "U+{code:X}");
            }
        }
    }
    #[test]
    fn invalid_scalar_anywhere_leaves_existing_buffer_untouched() {
        for value in [0xd800, 0xdbff, 0xdc00, 0xdfff, 0x110000, u32::MAX] {
            for values in [
                vec![value],
                vec![65, value],
                vec![value, 65],
                vec![65, value, 66],
            ] {
                let mut output = b"preserved\0\xff".to_vec();
                assert!(!append(&mut output, &values));
                assert_eq!(output, b"preserved\0\xff");
            }
        }
    }
    #[test]
    fn mixed_text_has_exact_ascii_quotes_escapes_and_surrogate_pairs() {
        let mut output = b"prefix".to_vec();
        assert!(append(
            &mut output,
            &vec![34, 92, 8, 12, 10, 13, 9, 0, 32, 126, 127, 0xe9, 0x1f600]
        ));
        assert_eq!(
            output,
            b"prefix\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000 ~\\u007f\\u00e9\\ud83d\\ude00\""
        );
        assert!(output.iter().all(|byte| byte.is_ascii()));
    }
}
