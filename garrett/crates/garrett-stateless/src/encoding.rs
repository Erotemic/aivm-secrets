//! b64url and the grammars of spec section 2, as `&str` views of the core's
//! extracted and proved functions (`stateless_token::{b64url, from_b64url,
//! is_*}` and `http_auth::valid_credential`), so the application and the
//! core cannot disagree about a grammar.
use crate::error::{Error, Result};
use garrett_stateless_core::{http_auth, stateless_token};

/// Unpadded url-safe base64.
pub fn b64url(bytes: &[u8]) -> String {
    stateless_token::b64url(bytes).into_iter().map(char::from).collect()
}

/// Strict decoding: no padding, alphabet only, canonical trailing bits.
pub fn from_b64url(text: &str) -> Option<Vec<u8>> {
    stateless_token::from_b64url(text.as_bytes())
}

/// 1-256 bytes of 0x21-0x7e excluding `"` and `\`.
pub fn is_text(value: &str) -> bool {
    stateless_token::is_text(value.as_bytes())
}

/// `[a-z0-9][a-z0-9._-]{0,63}`.
pub fn is_provider(value: &str) -> bool {
    stateless_token::is_provider(value.as_bytes())
}

/// `[A-Za-z0-9][A-Za-z0-9_-]{0,31}`.
pub fn is_kid(value: &str) -> bool {
    stateless_token::is_kid(value.as_bytes())
}

/// 32 lowercase hex digits.
pub fn is_id(value: &str) -> bool {
    stateless_token::is_id(value.as_bytes())
}

/// 43 b64url characters decoding to 32 bytes.
pub fn is_thumbprint(value: &str) -> bool {
    stateless_token::is_thumbprint(value.as_bytes())
}

/// 1-4096 bytes of 0x21-0x7e.
pub fn is_credential(value: &[u8]) -> bool {
    http_auth::valid_credential(value)
}

/// 0-1024 bytes: space-separated tokens of 0x21-0x7e excluding `"` and `\`.
pub fn is_scope(value: &str) -> bool {
    stateless_token::is_scope(value.as_bytes())
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
