//! Strict url-safe base64 without padding (spec section 2).
// Explicit indices, matches and loops keep to what Aeneas models.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_range_contains,
    clippy::len_zero,
    clippy::single_match,
    clippy::match_like_matches_macro,
    clippy::comparison_chain,
    clippy::manual_map
)]

use super::*;

pub fn b64url(bytes: &[u8]) -> Vec<u8> {
    encode_unpadded(bytes, true)
}

/// The value of one url-alphabet symbol, or 64.
pub fn symbol_value(symbol: u8) -> u32 {
    if symbol >= b'A' && symbol <= b'Z' {
        (symbol - b'A') as u32
    } else if symbol >= b'a' && symbol <= b'z' {
        (symbol - b'a') as u32 + 26
    } else if symbol >= b'0' && symbol <= b'9' {
        (symbol - b'0') as u32 + 52
    } else if symbol == b'-' {
        62
    } else if symbol == b'_' {
        63
    } else {
        64
    }
}

/// The group of up to four symbols at `index`, as a 24-bit value (missing
/// symbols count as zero), and how many symbols it has.
pub fn group(text: &[u8], index: usize) -> Option<(u32, usize)> {
    let count = if text.len() - index < 4 {
        text.len() - index
    } else {
        4
    };
    let mut value: u32 = 0;
    let mut valid = true;
    let mut position = 0;
    while position < 4 {
        let symbol = if position < count {
            symbol_value(text[index + position])
        } else {
            0
        };
        if symbol >= 64 {
            valid = false;
        } else {
            value = value * 64 + symbol;
        }
        position += 1;
    }
    if !valid {
        return None;
    }
    Some((value, count))
}

/// Strict decoding: unpadded url alphabet, and the text must be exactly the
/// encoding of the bytes it decodes to (canonical trailing bits).
pub fn from_b64url(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::new();
    let mut valid = true;
    let mut index = 0;
    while valid && index < text.len() {
        match group(text, index) {
            Some((value, count)) => {
                out.push((value / 65536) as u8);
                if count > 2 {
                    out.push((value / 256 % 256) as u8);
                }
                if count > 3 {
                    out.push((value % 256) as u8);
                }
                index += count;
            }
            None => valid = false,
        }
    }
    if !valid {
        return None;
    }
    let encoded = encode_unpadded(&out, true);
    let same: &[u8] = &encoded;
    if same != text {
        return None;
    }
    Some(out)
}
