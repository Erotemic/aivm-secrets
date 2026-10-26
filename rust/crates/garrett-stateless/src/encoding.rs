//! b64url and the grammars of spec section 2.
use crate::error::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let count = chunk.len() + 1;
        for i in 0..count {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn sextet(byte: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == byte).map(|p| p as u32)
}

/// Strict decoding: no padding, alphabet only, canonical trailing bits.
pub fn from_b64url(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            n |= sextet(byte)? << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..chunk.len() - 1]);
    }
    if b64url(&out) != text {
        return None;
    }
    Some(out)
}

/// 1-256 bytes of 0x21-0x7e excluding `"` and `\`.
pub fn is_text(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

/// `[a-z0-9][a-z0-9._-]{0,63}`.
pub fn is_provider(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|&b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// `[A-Za-z0-9][A-Za-z0-9_-]{0,31}`.
pub fn is_kid(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// 32 lowercase hex digits.
pub fn is_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 43 b64url characters decoding to 32 bytes.
pub fn is_thumbprint(value: &str) -> bool {
    value.len() == 43 && from_b64url(value).is_some_and(|b| b.len() == 32)
}

/// 1-4096 bytes of 0x21-0x7e.
pub fn is_credential(value: &[u8]) -> bool {
    (1..=4096).contains(&value.len()) && value.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// 0-1024 bytes: space-separated tokens of 0x21-0x7e excluding `"` and `\`.
pub fn is_scope(value: &str) -> bool {
    value.len() <= 1024
        && (value.is_empty()
            || value.split(' ').all(|t| {
                !t.is_empty()
                    && t.bytes()
                        .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
            }))
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    use ring::rand::SecureRandom;
    let mut out = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| Error::Io("random".into()))?;
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh 128-bit identifier (`jti`, `login`).
pub fn random_id() -> Result<String> {
    Ok(hex(&random::<16>()?))
}

/// The `x5t#S256` thumbprint of a certificate DER.
pub fn thumbprint(der: &[u8]) -> String {
    b64url(ring::digest::digest(&ring::digest::SHA256, der).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_round_trip_and_strictness() {
        for len in 0..10 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(from_b64url(&b64url(&bytes)).unwrap(), bytes);
        }
        assert!(from_b64url("AB==").is_none());
        assert!(from_b64url("AB").is_none() || b64url(&from_b64url("AB").unwrap()) == "AB");
        assert!(from_b64url("AF").is_none(), "non-canonical trailing bits");
        assert!(from_b64url("A+").is_none());
        assert_eq!(b64url(b"\xff\xfe"), "__4");
    }
}
