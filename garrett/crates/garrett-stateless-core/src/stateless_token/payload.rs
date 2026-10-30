//! The exact header and payload layout, and its one canonical parse (spec sections 4.1-4.2).
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

pub fn append(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}

/// The canonical header for `kid`.
pub fn header_bytes(kid: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    append(&mut out, HEADER_START);
    append(&mut out, kid);
    append(&mut out, HEADER_END);
    out
}

/// The `kid` of exactly the version-1 header.
pub fn header_kid(bytes: &[u8]) -> Option<Vec<u8>> {
    let fixed = HEADER_START.len() + HEADER_END.len();
    if bytes.len() < fixed {
        return None;
    }
    let tail = bytes.len() - HEADER_END.len();
    let start: &[u8] = &bytes[..HEADER_START.len()];
    let ending: &[u8] = &bytes[tail..];
    if start != HEADER_START || ending != HEADER_END {
        return None;
    }
    let kid: &[u8] = &bytes[HEADER_START.len()..tail];
    if !is_kid(kid) {
        return None;
    }
    Some(kid.to_vec())
}

/// Decimal digits of a non-negative integer.
pub fn append_natural(out: &mut Vec<u8>, value: i64) {
    if value >= 10 {
        append_natural(out, value / 10);
    }
    out.push(b'0' + (value % 10) as u8);
}

/// A canonical non-negative integer at `at`, at most `2^53 - 1`.
pub fn natural(bytes: &[u8], at: usize) -> Option<(i64, usize)> {
    if at >= bytes.len() || !digit(bytes[at]) {
        return None;
    }
    if bytes[at] == b'0' {
        return Some((0, at + 1));
    }
    let (value, stop, valid) = digits(bytes, at);
    if !valid {
        return None;
    }
    Some((value, stop))
}

/// A string field of a grammar without escapes at `at` (its opening quote):
/// its bytes and the index after its closing quote.
pub fn plain_string(bytes: &[u8], at: usize) -> Option<(Vec<u8>, usize)> {
    if at >= bytes.len() || bytes[at] != b'"' {
        return None;
    }
    let mut index = at + 1;
    while index < bytes.len() && bytes[index] != b'"' && bytes[index] != b'\\' {
        index += 1;
    }
    if index >= bytes.len() || bytes[index] != b'"' {
        return None;
    }
    let found: &[u8] = &bytes[at + 1..index];
    Some((found.to_vec(), index + 1))
}

/// The informational claims, carried but never decision inputs.
#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub struct Informational {
    pub has_scope: bool,
    pub scope: Vec<u8>,
    pub has_upstream: bool,
    /// The canonical JSON object of the copied claims.
    pub upstream: Vec<u8>,
}

/// Every member of a payload.
pub struct Payload {
    pub claims: SurrogateClaims,
    /// The b64url text of the sealed credential.
    pub enc: Vec<u8>,
    pub info: Informational,
}

pub fn append_quoted(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'"');
    append(out, bytes);
    out.push(b'"');
}

/// The canonical payload; without `enc` when `with_enc` is false (the bytes
/// the credential's associated data authenticates).
pub fn payload_bytes(payload: &Payload, with_enc: bool) -> Vec<u8> {
    let claims = &payload.claims;
    let mut out = Vec::new();
    append(&mut out, b"{\"aud\":");
    append_quoted(&mut out, &claims.audience);
    append(&mut out, b",\"cnf\":{\"x5t#S256\":");
    append_quoted(&mut out, &claims.certificate);
    out.push(b'}');
    if with_enc {
        append(&mut out, b",\"enc\":");
        append_quoted(&mut out, &payload.enc);
    }
    append(&mut out, b",\"exp\":");
    append_natural(&mut out, claims.expires_at);
    append(&mut out, b",\"iat\":");
    append_natural(&mut out, claims.issued_at);
    append(&mut out, b",\"iss\":");
    append_quoted(&mut out, &claims.issuer);
    append(&mut out, b",\"jti\":");
    append_quoted(&mut out, &claims.token_id);
    append(&mut out, b",\"prv\":");
    append_quoted(&mut out, &claims.provider);
    append(&mut out, b",\"ren\":");
    append_natural(&mut out, claims.renew_until);
    if payload.info.has_scope {
        append(&mut out, b",\"scope\":");
        append_quoted(&mut out, &payload.info.scope);
    }
    append(&mut out, b",\"sub\":");
    append_quoted(&mut out, &claims.subject);
    if payload.info.has_upstream {
        append(&mut out, b",\"upstream\":");
        append(&mut out, &payload.info.upstream);
    }
    out.push(b'}');
    out
}

/// Every grammar a payload's members must satisfy.
pub fn payload_valid(payload: &Payload) -> bool {
    let claims = &payload.claims;
    is_text(&claims.issuer)
        && is_text(&claims.audience)
        && is_text(&claims.subject)
        && is_id(&claims.token_id)
        && is_provider(&claims.provider)
        && is_thumbprint(&claims.certificate)
        && claims.issued_at >= 0
        && claims.issued_at <= MAX_INTEGER
        && claims.expires_at >= 0
        && claims.expires_at <= MAX_INTEGER
        && claims.renew_until >= 0
        && claims.renew_until <= MAX_INTEGER
        && (!payload.info.has_scope || is_scope(&payload.info.scope))
        && (!payload.info.has_upstream || upstream_object(&payload.info.upstream))
}

/// The string field after `key` at `at`.
pub fn field(bytes: &[u8], at: usize, key: &[u8]) -> Option<(Vec<u8>, usize)> {
    match word(bytes, at, key) {
        Some(next) => plain_string(bytes, next),
        None => None,
    }
}

/// The integer field after `key` at `at`.
pub fn number(bytes: &[u8], at: usize, key: &[u8]) -> Option<(i64, usize)> {
    match word(bytes, at, key) {
        Some(next) => natural(bytes, next),
        None => None,
    }
}

/// The one payload whose canonical encoding is `bytes`, if any.
pub fn parse_payload(bytes: &[u8]) -> Option<Payload> {
    let (audience, i) = match field(bytes, 0, b"{\"aud\":") {
        Some(found) => found,
        None => return None,
    };
    let (certificate, i) = match field(bytes, i, b",\"cnf\":{\"x5t#S256\":") {
        Some(found) => found,
        None => return None,
    };
    let i = match word(bytes, i, b"}") {
        Some(next) => next,
        None => return None,
    };
    let (enc, i) = match field(bytes, i, b",\"enc\":") {
        Some(found) => found,
        None => return None,
    };
    let (expires_at, i) = match number(bytes, i, b",\"exp\":") {
        Some(found) => found,
        None => return None,
    };
    let (issued_at, i) = match number(bytes, i, b",\"iat\":") {
        Some(found) => found,
        None => return None,
    };
    let (issuer, i) = match field(bytes, i, b",\"iss\":") {
        Some(found) => found,
        None => return None,
    };
    let (token_id, i) = match field(bytes, i, b",\"jti\":") {
        Some(found) => found,
        None => return None,
    };
    let (provider, i) = match field(bytes, i, b",\"prv\":") {
        Some(found) => found,
        None => return None,
    };
    let (renew_until, i) = match number(bytes, i, b",\"ren\":") {
        Some(found) => found,
        None => return None,
    };
    let (has_scope, scope, i) = match field(bytes, i, b",\"scope\":") {
        Some((scope, next)) => (true, scope, next),
        None => (false, Vec::new(), i),
    };
    let (subject, i) = match field(bytes, i, b",\"sub\":") {
        Some(found) => found,
        None => return None,
    };
    let (has_upstream, upstream) = match word(bytes, i, b",\"upstream\":") {
        Some(next) => {
            if next >= bytes.len() {
                return None;
            }
            let found: &[u8] = &bytes[next..bytes.len() - 1];
            (true, found.to_vec())
        }
        None => {
            if i + 1 != bytes.len() {
                return None;
            }
            (false, Vec::new())
        }
    };
    if bytes[bytes.len() - 1] != b'}' {
        return None;
    }
    let payload = Payload {
        claims: SurrogateClaims {
            issuer,
            audience,
            subject,
            token_id,
            provider,
            certificate,
            issued_at,
            expires_at,
            renew_until,
        },
        enc,
        info: Informational {
            has_scope,
            scope,
            has_upstream,
            upstream,
        },
    };
    if !payload_valid(&payload) {
        return None;
    }
    Some(payload)
}

/// The authenticated data of `enc`: the label, the header, a zero byte, and
/// the payload without `enc`.
pub fn associated(header: &[u8], public: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    append(&mut aad, CREDENTIAL_LABEL);
    append(&mut aad, header);
    aad.push(0);
    append(&mut aad, public);
    aad
}
