//! The grammars of the claim and key names (spec section 2).
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

/// 0x21-0x7e except `"` and `\`.
pub fn plain(byte: u8) -> bool {
    byte >= 0x21 && byte <= 0x7e && byte != b'"' && byte != b'\\'
}

pub fn lower_or_digit(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z') || (byte >= b'0' && byte <= b'9')
}

pub fn alphanumeric(byte: u8) -> bool {
    (byte >= b'A' && byte <= b'Z') || lower_or_digit(byte)
}

/// 1-256 plain bytes.
pub fn is_text(value: &[u8]) -> bool {
    if value.len() < 1 || value.len() > 256 {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        if !plain(value[index]) {
            return false;
        }
        index += 1;
    }
    true
}

/// `[a-z0-9][a-z0-9._-]{0,63}`.
pub fn is_provider(value: &[u8]) -> bool {
    if value.len() < 1 || value.len() > 64 || !lower_or_digit(value[0]) {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if !lower_or_digit(byte) && byte != b'.' && byte != b'_' && byte != b'-' {
            return false;
        }
        index += 1;
    }
    true
}

/// `[A-Za-z0-9][A-Za-z0-9_-]{0,31}`.
pub fn is_kid(value: &[u8]) -> bool {
    if value.len() < 1 || value.len() > 32 || !alphanumeric(value[0]) {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if !alphanumeric(byte) && byte != b'_' && byte != b'-' {
            return false;
        }
        index += 1;
    }
    true
}

/// 32 lowercase hex digits.
pub fn is_id(value: &[u8]) -> bool {
    if value.len() != 32 {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if !((byte >= b'0' && byte <= b'9') || (byte >= b'a' && byte <= b'f')) {
            return false;
        }
        index += 1;
    }
    true
}

/// 43 b64url symbols decoding to 32 bytes.
pub fn is_thumbprint(value: &[u8]) -> bool {
    if value.len() != 43 {
        return false;
    }
    match from_b64url(value) {
        Some(bytes) => bytes.len() == 32,
        None => false,
    }
}

/// 0-1024 bytes: plain tokens separated by single spaces.
pub fn is_scope(value: &[u8]) -> bool {
    if value.len() > 1024 {
        return false;
    }
    let mut valid = true;
    let mut after_space = true;
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if byte == b' ' {
            if after_space {
                valid = false;
            }
            after_space = true;
        } else {
            if !plain(byte) {
                valid = false;
            }
            after_space = false;
        }
        index += 1;
    }
    valid && (value.len() == 0 || !after_space)
}

/// A PKCE verifier: 43-128 of `[A-Za-z0-9-._~]`.
pub fn is_verifier(value: &[u8]) -> bool {
    if value.len() < 43 || value.len() > 128 {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if !alphanumeric(byte) && byte != b'-' && byte != b'.' && byte != b'_' && byte != b'~' {
            return false;
        }
        index += 1;
    }
    true
}
