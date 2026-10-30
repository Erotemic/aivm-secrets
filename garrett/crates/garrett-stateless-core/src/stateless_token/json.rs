//! Canonical JSON values, for the `upstream` claim.
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
