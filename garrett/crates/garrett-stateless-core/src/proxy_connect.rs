//! Authorization-scheme matching and strict standard base64, used to find
//! the surrogate in a `Bearer` or `Basic` field (`stateless_proxy`).

use crate::http_wire::ascii_lower;

/// The value of one standard base64 character, or 64 if it is not one.
pub fn sextet(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' {
        byte - b'A'
    } else if byte >= b'a' && byte <= b'z' {
        byte - b'a' + 26
    } else if byte >= b'0' && byte <= b'9' {
        byte - b'0' + 52
    } else if byte == b'+' {
        62
    } else if byte == b'/' {
        63
    } else {
        64
    }
}

/// Strict standard base64 with canonical padding and zero trailing bits.
pub fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut index = 0;
    while index < input.len() {
        let last = input.len() - index == 4;
        let a = sextet(input[index]);
        let b = sextet(input[index + 1]);
        let c_byte = input[index + 2];
        let d_byte = input[index + 3];
        if a == 64 || b == 64 {
            return None;
        }
        if last && c_byte == b'=' {
            // "xx==": one byte, the low four bits of b must be zero.
            if d_byte != b'=' || b & 15 != 0 {
                return None;
            }
            out.push((a << 2) | (b >> 4));
            return Some(out);
        }
        let c = sextet(c_byte);
        if c == 64 {
            return None;
        }
        if last && d_byte == b'=' {
            // "xxx=": two bytes, the low two bits of c must be zero.
            if c & 3 != 0 {
                return None;
            }
            out.push((a << 2) | (b >> 4));
            out.push(((b & 15) << 4) | (c >> 2));
            return Some(out);
        }
        let d = sextet(d_byte);
        if d == 64 {
            return None;
        }
        out.push((a << 2) | (b >> 4));
        out.push(((b & 15) << 4) | (c >> 2));
        out.push(((c & 3) << 6) | d);
        index += 4;
    }
    Some(out)
}

/// `value` starts with `prefix`, ignoring ASCII case, and has more after it.
pub fn scheme_is(value: &[u8], prefix: &[u8]) -> bool {
    if value.len() <= prefix.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if ascii_lower(value[index]) != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// The token a `Proxy-Authorization` value presents: `Bearer TOKEN`, or
/// `Basic base64(USER:TOKEN)` with any user.
pub fn presented(value: &[u8]) -> Option<Vec<u8>> {
    let basic: &[u8] = b"basic ";
    let bearer: &[u8] = b"bearer ";
    if scheme_is(value, basic) {
        let decoded = match decode_base64(&value[6..]) {
            Some(decoded) => decoded,
            None => return None,
        };
        let mut colon = 0;
        while colon < decoded.len() {
            if decoded[colon] == b':' {
                return Some(decoded[colon + 1..].to_vec());
            }
            colon += 1;
        }
        return None;
    }
    if scheme_is(value, bearer) {
        return Some(value[7..].to_vec());
    }
    None
}
