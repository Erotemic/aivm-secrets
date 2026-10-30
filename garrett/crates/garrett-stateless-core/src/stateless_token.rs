//! The `garrett-stateless-v1` surrogate codec (`docs/garrett-stateless-v1.md`
//! sections 2-5): strict b64url, the grammars, the exact header and payload
//! layout, key selection, and the key-set opener and sealer that
//! `stateless::open` and `stateless::issue` call.
//!
//! Ed25519 and AES-256-GCM are the only adapters ([`KeyMaterial`]). This module
//! fixes every byte they are given and every check made on what they return:
//! which key a token selects, which bytes are signed, which bytes are
//! authenticated with the credential, and which claims authorize. A payload is
//! accepted only in its one canonical form, so the signed bytes are the claims.
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

use crate::http_auth;
use crate::proxy_http::encode_unpadded;
use crate::stateless::{Rejection, SurrogateClaims, SurrogateOpener, SurrogateSealer, Verified};
use crate::stateless_login::LoginState;

pub const MAX_TOKEN: usize = 16384;
/// Largest integer this profile treats as an integer (`2^53 - 1`).
pub const MAX_INTEGER: i64 = 9007199254740991;
pub const MAX_KEYS: usize = 8;
/// The payload nests at most this deep (the payload object is level 0).
pub const MAX_DEPTH: usize = 16;
pub const NONCE: usize = 12;
pub const TAG: usize = 16;
pub const SIGNATURE: usize = 64;

pub const CREDENTIAL_LABEL: &[u8] = b"garrett-stateless-v1/credential\0";
pub const HEADER_START: &[u8] = b"{\"alg\":\"EdDSA\",\"kid\":\"";
pub const HEADER_END: &[u8] = b"\",\"typ\":\"garrett-stateless-v1+jwt\"}";

/// One key's primitives, implemented by the native shell with `ring`.
pub trait KeyMaterial {
    /// Ed25519: whether `signature` is valid for `message` under this key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    /// AES-256-GCM: the plaintext, or `None` if authentication fails.
    fn open(&self, nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>>;
    /// Ed25519 signature of `message`, or `None` without a signing key.
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>>;
    /// AES-256-GCM: the ciphertext with its tag appended.
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>>;
}

/// One configured `kid`: the issuer it signs for and its key material.
pub struct KeyEntry<M> {
    pub kid: Vec<u8>,
    pub issuer: Vec<u8>,
    pub material: M,
}

/// A validated key set: 1 to 8 entries, valid names, no `kid` twice.
pub struct KeySet<M> {
    entries: Vec<KeyEntry<M>>,
}

/* ---- b64url (spec section 2) ------------------------------------------- */

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

/* ---- grammars (spec section 2) ----------------------------------------- */

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

/* ---- canonical JSON values (the `upstream` claim) ---------------------- */

pub fn hex_value(byte: u8) -> u32 {
    if byte >= b'0' && byte <= b'9' {
        (byte - b'0') as u32
    } else if byte >= b'a' && byte <= b'f' {
        (byte - b'a') as u32 + 10
    } else {
        16
    }
}

/// Four lowercase hex digits at `at`.
pub fn hex4(bytes: &[u8], at: usize) -> Option<u32> {
    if at + 4 > bytes.len() {
        return None;
    }
    let mut value = 0;
    let mut valid = true;
    let mut index = 0;
    while index < 4 {
        let digit = hex_value(bytes[at + index]);
        if digit >= 16 {
            valid = false;
        } else {
            value = value * 16 + digit;
        }
        index += 1;
    }
    if !valid {
        return None;
    }
    Some(value)
}

/// One escape `\X` or `\uXXXX[\uXXXX]` at `at` (the backslash), in exactly
/// the form the canonical encoder writes it: the scalar and the next index.
pub fn escape(bytes: &[u8], at: usize) -> Option<(u32, usize)> {
    if at + 1 >= bytes.len() {
        return None;
    }
    let kind = bytes[at + 1];
    if kind == b'"' {
        return Some((34, at + 2));
    }
    if kind == b'\\' {
        return Some((92, at + 2));
    }
    if kind == b'b' {
        return Some((8, at + 2));
    }
    if kind == b'f' {
        return Some((12, at + 2));
    }
    if kind == b'n' {
        return Some((10, at + 2));
    }
    if kind == b'r' {
        return Some((13, at + 2));
    }
    if kind == b't' {
        return Some((9, at + 2));
    }
    if kind != b'u' {
        return None;
    }
    let high = match hex4(bytes, at + 2) {
        Some(value) => value,
        None => return None,
    };
    if high >= 0xdc00 && high <= 0xdfff {
        return None;
    }
    if high >= 0xd800 && high <= 0xdbff {
        if at + 12 > bytes.len() || bytes[at + 6] != b'\\' || bytes[at + 7] != b'u' {
            return None;
        }
        let low = match hex4(bytes, at + 8) {
            Some(value) => value,
            None => return None,
        };
        if low < 0xdc00 || low > 0xdfff {
            return None;
        }
        return Some((0x10000 + (high - 0xd800) * 1024 + (low - 0xdc00), at + 12));
    }
    // A short escape or a plain byte is the only canonical form of these.
    if high == 8 || high == 9 || high == 10 || high == 12 || high == 13 {
        return None;
    }
    if high >= 0x20 && high <= 0x7e {
        return None;
    }
    Some((high, at + 6))
}

/// The scalars of a canonical string body from `index` to its closing quote,
/// appended to `scalars`, and the index after the quote.
pub fn characters(bytes: &[u8], index: usize, scalars: Vec<u32>) -> Option<(Vec<u32>, usize)> {
    if index >= bytes.len() {
        return None;
    }
    let byte = bytes[index];
    if byte == b'"' {
        return Some((scalars, index + 1));
    }
    let mut more = scalars;
    if byte == b'\\' {
        match escape(bytes, index) {
            Some((scalar, next)) => {
                more.push(scalar);
                characters(bytes, next, more)
            }
            None => None,
        }
    } else {
        if byte < 0x20 || byte > 0x7e {
            return None;
        }
        more.push(byte as u32);
        characters(bytes, index + 1, more)
    }
}

/// A canonical string at `at` (its opening quote): its scalars and the index
/// after its closing quote.
pub fn string(bytes: &[u8], at: usize) -> Option<(Vec<u32>, usize)> {
    if at >= bytes.len() || bytes[at] != b'"' {
        return None;
    }
    characters(bytes, at + 1, Vec::new())
}

pub fn digit(byte: u8) -> bool {
    byte >= b'0' && byte <= b'9'
}

/// The value of the decimal digits from `index`, the index after them, and
/// whether every prefix stayed at most `2^53 - 1`.
pub fn digits(bytes: &[u8], index: usize) -> (i64, usize, bool) {
    let mut value: i64 = 0;
    let mut valid = true;
    let mut at = index;
    while valid && at < bytes.len() && digit(bytes[at]) {
        let next = (bytes[at] - b'0') as i64;
        if value > (MAX_INTEGER - next) / 10 {
            valid = false;
        } else {
            value = value * 10 + next;
            at += 1;
        }
    }
    (value, at, valid)
}

/// Whether the byte at `index` would continue a number as a fraction or
/// exponent.
pub fn fraction_at(bytes: &[u8], index: usize) -> bool {
    index < bytes.len() && (bytes[index] == b'.' || bytes[index] == b'e' || bytes[index] == b'E')
}

/// A canonical integer at `at`: `0` or `-?[1-9][0-9]*` of magnitude at most
/// `2^53 - 1`, never `-0`. The index after it.
pub fn integer(bytes: &[u8], at: usize) -> Option<usize> {
    let mut index = at;
    if index < bytes.len() && bytes[index] == b'-' {
        index += 1;
    }
    if index >= bytes.len() || !digit(bytes[index]) {
        return None;
    }
    if bytes[index] == b'0' {
        if index > at {
            return None;
        }
        if (index + 1 < bytes.len() && digit(bytes[index + 1])) || fraction_at(bytes, index + 1) {
            return None;
        }
        return Some(index + 1);
    }
    let (_, stop, valid) = digits(bytes, index);
    if !valid || fraction_at(bytes, stop) {
        return None;
    }
    Some(stop)
}

/// Whether `a` sorts strictly before `b` (code point order).
pub fn before(a: &[u32], b: &[u32]) -> bool {
    let mut index = 0;
    while index < a.len() && index < b.len() && a[index] == b[index] {
        index += 1;
    }
    if index < a.len() && index < b.len() {
        return a[index] < b[index];
    }
    a.len() < b.len()
}

/// A canonical value at `at`, nested at `level`: the index after it.
pub fn value(bytes: &[u8], at: usize, level: usize) -> Option<usize> {
    if at >= bytes.len() {
        return None;
    }
    let first = bytes[at];
    if first == b'{' {
        return object(bytes, at, level);
    }
    if first == b'[' {
        return array(bytes, at, level);
    }
    if first == b'"' {
        return match string(bytes, at) {
            Some((_, next)) => Some(next),
            None => None,
        };
    }
    if first == b't' {
        return word(bytes, at, b"true");
    }
    if first == b'f' {
        return word(bytes, at, b"false");
    }
    if first == b'n' {
        return word(bytes, at, b"null");
    }
    integer(bytes, at)
}

/// `literal` at `at`: the index after it.
pub fn word(bytes: &[u8], at: usize, literal: &[u8]) -> Option<usize> {
    if at + literal.len() > bytes.len() {
        return None;
    }
    let found: &[u8] = &bytes[at..at + literal.len()];
    if found != literal {
        return None;
    }
    Some(at + literal.len())
}

/// The elements of a canonical array from `index` (just after `[` or a
/// `,`), up to and including `]`: the index after it.
pub fn elements(bytes: &[u8], index: usize, level: usize) -> Option<usize> {
    let next = match value(bytes, index, level + 1) {
        Some(next) => next,
        None => return None,
    };
    if next >= bytes.len() {
        return None;
    }
    if bytes[next] == b']' {
        return Some(next + 1);
    }
    if bytes[next] != b',' {
        return None;
    }
    elements(bytes, next + 1, level)
}

/// A canonical array at `at`: `[]` or values separated by `,`.
pub fn array(bytes: &[u8], at: usize, level: usize) -> Option<usize> {
    if level >= MAX_DEPTH {
        return None;
    }
    if at + 1 < bytes.len() && bytes[at + 1] == b']' {
        return Some(at + 2);
    }
    elements(bytes, at + 1, level)
}

/// The members of a canonical object from `index` (just after `{` or a
/// `,`), each key after `previous` (if any), up to and including `}`.
pub fn members(
    bytes: &[u8],
    index: usize,
    level: usize,
    first: bool,
    previous: &[u32],
) -> Option<usize> {
    let (key, next) = match string(bytes, index) {
        Some(found) => found,
        None => return None,
    };
    if !first && !before(previous, &key) {
        return None;
    }
    if next >= bytes.len() || bytes[next] != b':' {
        return None;
    }
    let after = match value(bytes, next + 1, level + 1) {
        Some(after) => after,
        None => return None,
    };
    if after >= bytes.len() {
        return None;
    }
    if bytes[after] == b'}' {
        return Some(after + 1);
    }
    if bytes[after] != b',' {
        return None;
    }
    members(bytes, after + 1, level, false, &key)
}

/// A canonical object at `at`: members with strictly increasing keys.
pub fn object(bytes: &[u8], at: usize, level: usize) -> Option<usize> {
    if level >= MAX_DEPTH {
        return None;
    }
    if at + 1 < bytes.len() && bytes[at + 1] == b'}' {
        return Some(at + 2);
    }
    members(bytes, at + 1, level, true, &[])
}

/// Whether `bytes` is exactly one canonical JSON object (the `upstream` claim,
/// nested at level 1 of the payload).
pub fn upstream_object(bytes: &[u8]) -> bool {
    if bytes.len() == 0 || bytes[0] != b'{' {
        return false;
    }
    match object(bytes, 0, 1) {
        Some(stop) => stop == bytes.len(),
        None => false,
    }
}

/* ---- the exact header and payload layout (spec sections 4.1-4.2) ------- */

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

/* ---- keys (spec section 3) --------------------------------------------- */

/// The first entry for `kid` (or `entries.len()`).
pub fn select<M>(entries: &[KeyEntry<M>], kid: &[u8]) -> usize {
    let mut index = 0;
    while index < entries.len() && !named(&entries[index], kid) {
        index += 1;
    }
    index
}

pub fn named<M>(entry: &KeyEntry<M>, kid: &[u8]) -> bool {
    let own: &[u8] = &entry.kid;
    own == kid
}

/// 1 to 8 entries, valid `kid` and issuer grammars, and no `kid` twice, so
/// every `kid` selects at most one entry.
pub fn keys_valid<M>(entries: &[KeyEntry<M>]) -> bool {
    if entries.len() < 1 || entries.len() > MAX_KEYS {
        return false;
    }
    let mut valid = true;
    let mut index = 0;
    while index < entries.len() {
        if !entry_valid(entries, index) {
            valid = false;
        }
        index += 1;
    }
    valid
}

/// Entry `index` has valid names and is the first for its `kid`.
pub fn entry_valid<M>(entries: &[KeyEntry<M>], index: usize) -> bool {
    let entry = &entries[index];
    is_kid(&entry.kid) && is_text(&entry.issuer) && select(entries, &entry.kid) == index
}

#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub enum KeyError {
    Invalid,
}

impl<M> KeySet<M> {
    /// The key set, if the entries are a valid one.
    pub fn new(entries: Vec<KeyEntry<M>>) -> Result<KeySet<M>, KeyError> {
        if !keys_valid(&entries) {
            return Err(KeyError::Invalid);
        }
        Ok(KeySet { entries })
    }

    pub fn entries(&self) -> &[KeyEntry<M>] {
        &self.entries
    }
}

/* ---- opening (spec section 5) ------------------------------------------ */

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

/* ---- sealing (spec section 4) ------------------------------------------ */

/// Whether `needle` occurs in `haystack`.
pub fn occurs(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() == 0 {
        return true;
    }
    let mut found = false;
    let mut start = 0;
    while !found && start + needle.len() <= haystack.len() {
        let window: &[u8] = &haystack[start..start + needle.len()];
        if window == needle {
            found = true;
        }
        start += 1;
    }
    found
}

/// Sign and seal exactly `claims` around `credential` with `entry`, under the
/// fresh `nonce`. The credential never occurs in the public part.
pub fn seal_token<M: KeyMaterial>(
    entry: &KeyEntry<M>,
    info: &Informational,
    claims: &SurrogateClaims,
    credential: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Rejection> {
    if !http_auth::valid_credential(credential) || !is_kid(&entry.kid) || nonce.len() != NONCE {
        return Err(Rejection::InvalidCredential);
    }
    let header = header_bytes(&entry.kid);
    let mut payload = Payload {
        claims: copy_claims(claims),
        enc: Vec::new(),
        info: copy_info(info),
    };
    if !payload_valid(&payload) {
        return Err(Rejection::Malformed);
    }
    let public = payload_bytes(&payload, false);
    if occurs(&header, credential) || occurs(&public, credential) {
        return Err(Rejection::Malformed);
    }
    let aad = associated(&header, &public);
    let ciphertext = match entry.material.seal(nonce, &aad, credential) {
        Some(ciphertext) => ciphertext,
        None => return Err(Rejection::Undecryptable),
    };
    let mut sealed = Vec::new();
    append(&mut sealed, nonce);
    append(&mut sealed, &ciphertext);
    payload.enc = b64url(&sealed);
    let mut body = b64url(&header);
    body.push(b'.');
    append(&mut body, &b64url(&payload_bytes(&payload, true)));
    let signature = match entry.material.sign(&body) {
        Some(signature) => signature,
        None => return Err(Rejection::UnknownKey),
    };
    if signature.len() != SIGNATURE {
        return Err(Rejection::UnknownKey);
    }
    let mut token = body;
    token.push(b'.');
    append(&mut token, &b64url(&signature));
    if token.len() > MAX_TOKEN {
        return Err(Rejection::Malformed);
    }
    Ok(token)
}

pub fn copy_claims(claims: &SurrogateClaims) -> SurrogateClaims {
    let issuer: &[u8] = &claims.issuer;
    let audience: &[u8] = &claims.audience;
    let subject: &[u8] = &claims.subject;
    let token_id: &[u8] = &claims.token_id;
    let provider: &[u8] = &claims.provider;
    let certificate: &[u8] = &claims.certificate;
    SurrogateClaims {
        issuer: issuer.to_vec(),
        audience: audience.to_vec(),
        subject: subject.to_vec(),
        token_id: token_id.to_vec(),
        provider: provider.to_vec(),
        certificate: certificate.to_vec(),
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
        renew_until: claims.renew_until,
    }
}

pub fn copy_info(info: &Informational) -> Informational {
    let scope: &[u8] = &info.scope;
    let upstream: &[u8] = &info.upstream;
    Informational {
        has_scope: info.has_scope,
        scope: scope.to_vec(),
        has_upstream: info.has_upstream,
        upstream: upstream.to_vec(),
    }
}

/// The broker's sealer for one issuance: the signing entry, the informational
/// claims, and the AES-GCM nonce for that one seal.
///
/// The core has no randomness, so the caller supplies the nonce, and it must
/// never have been used with the entry's sealing key before (reusing an
/// AES-GCM nonce under one key breaks confidentiality and integrity). The
/// proofs do not establish this; it is the runtime obligation
/// `STATELESS-CRYPTO-01`. `seal` consumes the sealer, so one nonce seals at
/// most one surrogate.
pub struct TokenSealer<M> {
    entry: KeyEntry<M>,
    info: Informational,
    nonce: Vec<u8>,
}

impl<M> TokenSealer<M> {
    /// A sealer for one issuance; `nonce` must be fresh (see above).
    pub fn new(entry: KeyEntry<M>, info: Informational, nonce: Vec<u8>) -> TokenSealer<M> {
        TokenSealer { entry, info, nonce }
    }
}

impl<M: KeyMaterial> SurrogateSealer for TokenSealer<M> {
    fn seal(self, claims: &SurrogateClaims, credential: &[u8]) -> Result<Vec<u8>, Rejection> {
        seal_token(&self.entry, &self.info, claims, credential, &self.nonce)
    }
}

/// The informational claims of a token whose payload parses (for renewal,
/// after `stateless::open` accepted the same bytes).
pub fn informational(token: &[u8]) -> Option<Informational> {
    let (first, second) = match segments(token) {
        Some(found) => found,
        None => return None,
    };
    let bytes = match from_b64url(&token[first + 1..second]) {
        Some(bytes) => bytes,
        None => return None,
    };
    match parse_payload(&bytes) {
        Some(payload) => Some(payload.info),
        None => None,
    }
}

/* ---- the sealed login state (spec section 8.2) ------------------------- */

pub const STATE_PREFIX: &[u8] = b"gs1.";
pub const MAX_STATE: usize = 4096;
pub const LOGIN_LABEL: &[u8] = b"garrett-stateless-v1/login\0";

/// The broker's login-state key (AES-256-GCM), implemented with `ring`.
pub trait StateKey {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>>;
    fn open(&self, nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>>;
}

/// Every grammar of a login state.
pub fn state_valid(state: &LoginState) -> bool {
    is_thumbprint(&state.certificate)
        && is_id(&state.login)
        && is_provider(&state.provider)
        && is_kid(&state.replica)
        && is_scope(&state.scope)
        && is_text(&state.subject)
        && is_verifier(&state.verifier)
        && state.certificate_expires >= 0
        && state.certificate_expires <= MAX_INTEGER
        && state.issued_at >= 0
        && state.issued_at <= MAX_INTEGER
        && state.expires_at >= 0
        && state.expires_at <= MAX_INTEGER
}

/// The canonical plaintext of a login state.
pub fn state_bytes(state: &LoginState) -> Vec<u8> {
    let mut out = Vec::new();
    append(&mut out, b"{\"cert_exp\":");
    append_natural(&mut out, state.certificate_expires);
    append(&mut out, b",\"cnf\":");
    append_quoted(&mut out, &state.certificate);
    append(&mut out, b",\"exp\":");
    append_natural(&mut out, state.expires_at);
    append(&mut out, b",\"iat\":");
    append_natural(&mut out, state.issued_at);
    append(&mut out, b",\"login\":");
    append_quoted(&mut out, &state.login);
    append(&mut out, b",\"prv\":");
    append_quoted(&mut out, &state.provider);
    append(&mut out, b",\"rep\":");
    append_quoted(&mut out, &state.replica);
    append(&mut out, b",\"scope\":");
    append_quoted(&mut out, &state.scope);
    append(&mut out, b",\"sub\":");
    append_quoted(&mut out, &state.subject);
    append(&mut out, b",\"verifier\":");
    append_quoted(&mut out, &state.verifier);
    out.push(b'}');
    out
}

/// The one login state whose canonical plaintext is `bytes`, if any.
pub fn parse_state(bytes: &[u8]) -> Option<LoginState> {
    let (certificate_expires, i) = match number(bytes, 0, b"{\"cert_exp\":") {
        Some(found) => found,
        None => return None,
    };
    let (certificate, i) = match field(bytes, i, b",\"cnf\":") {
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
    let (login, i) = match field(bytes, i, b",\"login\":") {
        Some(found) => found,
        None => return None,
    };
    let (provider, i) = match field(bytes, i, b",\"prv\":") {
        Some(found) => found,
        None => return None,
    };
    let (replica, i) = match field(bytes, i, b",\"rep\":") {
        Some(found) => found,
        None => return None,
    };
    let (scope, i) = match field(bytes, i, b",\"scope\":") {
        Some(found) => found,
        None => return None,
    };
    let (subject, i) = match field(bytes, i, b",\"sub\":") {
        Some(found) => found,
        None => return None,
    };
    let (verifier, i) = match field(bytes, i, b",\"verifier\":") {
        Some(found) => found,
        None => return None,
    };
    if i + 1 != bytes.len() || bytes[i] != b'}' {
        return None;
    }
    let state = LoginState {
        login,
        provider,
        certificate,
        subject,
        certificate_expires,
        replica,
        scope,
        verifier,
        issued_at,
        expires_at,
    };
    if !state_valid(&state) {
        return None;
    }
    Some(state)
}

/// Seal a login state under the broker's state key with a fresh `nonce`.
pub fn seal_state<K: StateKey>(key: &K, state: &LoginState, nonce: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != NONCE || !state_valid(state) {
        return None;
    }
    let ciphertext = match key.seal(nonce, LOGIN_LABEL, &state_bytes(state)) {
        Some(ciphertext) => ciphertext,
        None => return None,
    };
    let mut sealed = Vec::new();
    append(&mut sealed, nonce);
    append(&mut sealed, &ciphertext);
    let mut out = Vec::new();
    append(&mut out, STATE_PREFIX);
    append(&mut out, &b64url(&sealed));
    if out.len() > MAX_STATE {
        return None;
    }
    Some(out)
}

/// Open a `state` parameter. Any forgery, truncation or foreign key fails.
pub fn open_state<K: StateKey>(key: &K, text: &[u8]) -> Result<LoginState, Rejection> {
    if text.len() > MAX_STATE || text.len() < STATE_PREFIX.len() {
        return Err(Rejection::Malformed);
    }
    let prefix: &[u8] = &text[..STATE_PREFIX.len()];
    if prefix != STATE_PREFIX {
        return Err(Rejection::Malformed);
    }
    let sealed = match from_b64url(&text[STATE_PREFIX.len()..]) {
        Some(sealed) => sealed,
        None => return Err(Rejection::Malformed),
    };
    if sealed.len() < NONCE + TAG + 1 {
        return Err(Rejection::Malformed);
    }
    let plain = match key.open(&sealed[..NONCE], LOGIN_LABEL, &sealed[NONCE..]) {
        Some(plain) => plain,
        None => return Err(Rejection::Undecryptable),
    };
    match parse_state(&plain) {
        Some(state) => Ok(state),
        None => Err(Rejection::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_round_trip_and_strictness() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(from_b64url(&b64url(&bytes)).unwrap(), bytes);
        }
        for bad in [&b"AB=="[..], b"A", b"AF", b"A+", b"A/", b"A.B"] {
            assert!(from_b64url(bad).is_none(), "{bad:?}");
        }
        assert_eq!(b64url(b"\xff\xfe"), b"__4");
    }

    #[test]
    fn grammars() {
        assert!(is_scope(b"") && is_scope(b"read write") && !is_scope(b" read"));
        assert!(!is_scope(b"read  write") && !is_scope(b"read ") && !is_scope(b"a\"b"));
        assert!(is_kid(b"k-1_x") && !is_kid(b"-k") && !is_kid(b""));
        assert!(is_provider(b"api.v2") && !is_provider(b"Api"));
        assert!(is_thumbprint(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!is_thumbprint(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
        ));
    }

    #[test]
    fn header_is_exact() {
        let h = header_bytes(b"k1");
        assert_eq!(
            h,
            br#"{"alg":"EdDSA","kid":"k1","typ":"garrett-stateless-v1+jwt"}"#
        );
        assert_eq!(header_kid(&h).unwrap(), b"k1");
        assert!(
            header_kid(br#"{"alg":"none","kid":"k1","typ":"garrett-stateless-v1+jwt"}"#).is_none()
        );
        assert!(
            header_kid(br#"{"alg":"EdDSA","kid":"k\"1","typ":"garrett-stateless-v1+jwt"}"#)
                .is_none()
        );
    }

    fn payload(scope: Option<&[u8]>, upstream: Option<&[u8]>) -> Payload {
        Payload {
            claims: SurrogateClaims {
                issuer: b"https://broker".to_vec(),
                audience: b"https://proxy".to_vec(),
                subject: b"spiffe://test/agent".to_vec(),
                token_id: b"0123456789abcdef0123456789abcdef".to_vec(),
                provider: b"api".to_vec(),
                certificate: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
                issued_at: 0,
                expires_at: 3600,
                renew_until: 9007199254740991,
            },
            enc: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
            info: Informational {
                has_scope: scope.is_some(),
                scope: scope.unwrap_or_default().to_vec(),
                has_upstream: upstream.is_some(),
                upstream: upstream.unwrap_or_default().to_vec(),
            },
        }
    }

    #[test]
    fn payload_round_trip() {
        for (scope, upstream) in [
            (None, None),
            (Some(&b"read"[..]), None),
            (
                Some(&b""[..]),
                Some(&br#"{"aud":"x","exp":-5,"roles":["a","b\"c"],"z":null}"#[..]),
            ),
            (
                None,
                Some(&br#"{"\u00e9":{"\ud83d\ude00":[true,false,0]}}"#[..]),
            ),
        ] {
            let p = payload(scope, upstream);
            let bytes = payload_bytes(&p, true);
            let back = parse_payload(&bytes).unwrap();
            assert_eq!(payload_bytes(&back, true), bytes);
            assert_eq!(back.claims.renew_until, 9007199254740991);
        }
    }

    #[test]
    fn noncanonical_upstream_is_refused() {
        for bad in [
            &br#"{"b":1,"a":2}"#[..],
            br#"{"a":1,"a":2}"#,
            br#"{"a":01}"#,
            br#"{"a":-0}"#,
            br#"{"a":1.5}"#,
            br#"{"a":9007199254740992}"#,
            br#"{"a":"\u0041"}"#,
            br#"{"a":"\/"}"#,
            br#"{"a":"\u00E9"}"#,
            br#"{"a":"\ud800"}"#,
            b"{\"a\":\"\n\"}",
            br#"{ "a":1}"#,
            br#"{"a":[1,]}"#,
            br#"{"a":1}x"#,
        ] {
            assert!(!upstream_object(bad), "{}", String::from_utf8_lossy(bad));
        }
        let mut deep = Vec::new();
        for _ in 0..15 {
            deep.extend_from_slice(b"{\"a\":");
        }
        deep.extend_from_slice(b"1");
        deep.resize(deep.len() + 15, b'}');
        assert!(upstream_object(&deep));
        let mut deeper = b"{\"a\":".to_vec();
        deeper.extend_from_slice(&deep);
        deeper.push(b'}');
        assert!(!upstream_object(&deeper));
    }

    #[test]
    fn duplicate_and_unknown_members_are_refused() {
        let bytes = payload_bytes(&payload(None, None), true);
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            text.replacen("{\"aud\"", "{\"aud\":\"x\",\"aud\"", 1),
            text.replacen(",\"sub\"", ",\"extra\":1,\"sub\"", 1),
            text.replacen("\"exp\":3600", "\"exp\":\"3600\"", 1),
            text.replacen(
                ",\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
                "",
                1,
            ),
            text.replacen("}", "} ", 1),
        ] {
            assert!(parse_payload(bad.as_bytes()).is_none(), "{bad}");
        }
    }
}
