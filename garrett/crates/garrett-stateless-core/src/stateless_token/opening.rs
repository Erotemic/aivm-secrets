//! Opening a surrogate: segments, signature, then the credential (spec section 5).
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

/// Whether every byte is ASCII.
pub fn ascii(token: &[u8]) -> bool {
    let mut index = 0;
    while index < token.len() {
        if token[index] > 0x7f {
            return false;
        }
        index += 1;
    }
    true
}

/// The index of the first `.` at or after `from` (or `token.len()`).
pub fn dot_from(token: &[u8], from: usize) -> usize {
    let mut index = from;
    while index < token.len() && token[index] != b'.' {
        index += 1;
    }
    index
}

/// The positions of the two `.` of a three-segment ASCII token.
pub fn segments(token: &[u8]) -> Option<(usize, usize)> {
    if token.len() > MAX_TOKEN || !ascii(token) {
        return None;
    }
    let first = dot_from(token, 0);
    if first >= token.len() {
        return None;
    }
    let second = dot_from(token, first + 1);
    if second >= token.len() || dot_from(token, second + 1) < token.len() {
        return None;
    }
    Some((first, second))
}

/// Verify a surrogate's header and signature under `entries` and decode its
/// authoritative claims, the associated data and the sealed credential.
pub fn verify_token<M: KeyMaterial>(
    entries: &[KeyEntry<M>],
    token: &[u8],
) -> Result<Verified, Rejection> {
    let (first, second) = match segments(token) {
        Some(found) => found,
        None => return Err(Rejection::Malformed),
    };
    let header = match from_b64url(&token[..first]) {
        Some(header) => header,
        None => return Err(Rejection::Malformed),
    };
    let kid = match header_kid(&header) {
        Some(kid) => kid,
        None => return Err(Rejection::Malformed),
    };
    let key = select(entries, &kid);
    if key >= entries.len() {
        return Err(Rejection::UnknownKey);
    }
    let entry = &entries[key];
    let signature = match from_b64url(&token[second + 1..]) {
        Some(signature) => signature,
        None => return Err(Rejection::Malformed),
    };
    if signature.len() != SIGNATURE {
        return Err(Rejection::Malformed);
    }
    if !entry.material.verify(&token[..second], &signature) {
        return Err(Rejection::BadSignature);
    }
    // Authenticated from here on; still accepted only in canonical form.
    let payload_bytes_seen = match from_b64url(&token[first + 1..second]) {
        Some(bytes) => bytes,
        None => return Err(Rejection::Malformed),
    };
    let payload = match parse_payload(&payload_bytes_seen) {
        Some(payload) => payload,
        None => return Err(Rejection::Malformed),
    };
    let sealed = match from_b64url(&payload.enc) {
        Some(sealed) => sealed,
        None => return Err(Rejection::Malformed),
    };
    if sealed.len() < NONCE + TAG + 1 {
        return Err(Rejection::Malformed);
    }
    let public = payload_bytes(&payload, false);
    let aad = associated(&header, &public);
    let issuer: &[u8] = &entry.issuer;
    Ok(Verified {
        key,
        key_issuer: issuer.to_vec(),
        claims: payload.claims,
        aad,
        sealed,
    })
}

/// Open `enc` with the key that verified the token.
pub fn unseal_token<M: KeyMaterial>(
    entries: &[KeyEntry<M>],
    verified: &Verified,
) -> Result<Vec<u8>, Rejection> {
    if verified.key >= entries.len() || verified.sealed.len() < NONCE + TAG + 1 {
        return Err(Rejection::UnknownKey);
    }
    let nonce: &[u8] = &verified.sealed[..NONCE];
    let sealed: &[u8] = &verified.sealed[NONCE..];
    match entries[verified.key]
        .material
        .open(nonce, &verified.aad, sealed)
    {
        Some(plain) => Ok(plain),
        None => Err(Rejection::Undecryptable),
    }
}

impl<M: KeyMaterial> SurrogateOpener for KeySet<M> {
    fn verify(&self, token: &[u8]) -> Result<Verified, Rejection> {
        verify_token(&self.entries, token)
    }
    fn unseal(&self, verified: &Verified) -> Result<Vec<u8>, Rejection> {
        unseal_token(&self.entries, verified)
    }
}
