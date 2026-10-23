//! Whether a guest may open a tunnel (`CONNECT`) to the proxy: the request
//! line, the one `Proxy-Authorization` field carrying the session token, a
//! configured origin on port 443, and a current session. `garrett-proxy`
//! calls [`admit`] with the head it read and acts only on its answer.

use crate::http_wire::ascii_lower;
use crate::proxy_http::{
    clean_head, count_named, first_named, line_end, parse_fields, Code, Field,
};

/// The answer for one `CONNECT` head.
pub enum Admission {
    /// Open a tunnel to the origin at this index.
    Open(usize),
    /// Refuse with this fixed response.
    Refuse(Code),
}

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

/// Equal length and bytes, without an early exit on the first difference.
pub fn same_secret(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference: u8 = 0;
    let mut index = 0;
    while index < a.len() {
        difference |= a[index] ^ b[index];
        index += 1;
    }
    difference == 0
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

/// Exactly one `Proxy-Authorization` field, presenting the session token.
pub fn authenticated(fields: &[Field], token: &[u8]) -> bool {
    let name: &[u8] = b"proxy-authorization";
    if count_named(fields, name) != 1 {
        return false;
    }
    let index = first_named(fields, name);
    if index >= fields.len() {
        return false;
    }
    match presented(&fields[index].value) {
        Some(candidate) => same_secret(&candidate, token),
        None => false,
    }
}

/// The index of the last `:` in `authority`, or its length.
pub fn last_colon(authority: &[u8]) -> usize {
    let mut index = authority.len();
    while index > 0 {
        if authority[index - 1] == b':' {
            return index - 1;
        }
        index -= 1;
    }
    authority.len()
}

/// The index of the origin named `host`, or `hosts.len()`.
pub fn origin_index(hosts: &[Vec<u8>], host: &[u8]) -> usize {
    let mut index = 0;
    while index < hosts.len() {
        let candidate: &[u8] = &hosts[index];
        if candidate == host {
            return index;
        }
        index += 1;
    }
    hosts.len()
}

/// The positions of the two spaces of a three-part request line, if any.
pub fn spaces(line: &[u8]) -> Option<(usize, usize)> {
    let mut first = line.len();
    let mut second = line.len();
    let mut index = 0;
    while index < line.len() {
        if line[index] == b' ' {
            if first == line.len() {
                first = index;
            } else if second == line.len() {
                second = index;
            } else {
                return None;
            }
        }
        index += 1;
    }
    if second == line.len() {
        return None;
    }
    Some((first, second))
}

/// The decision for one `CONNECT` head (without its final empty line).
pub fn admit(head: &[u8], token: &[u8], hosts: &[Vec<u8>], current: bool) -> Admission {
    let first = line_end(head, 0);
    let line = &head[..first];
    let found = match spaces(line) {
        Some(found) => found,
        None => return Admission::Refuse(Code::InvalidRequest),
    };
    let one = found.0;
    let two = found.1;
    let method: &[u8] = &line[..one];
    let version: &[u8] = &line[two + 1..];
    let connect: &[u8] = b"CONNECT";
    let http: &[u8] = b"HTTP/1.1";
    if !clean_head(head) || !(method == connect) || !(version == http) {
        return Admission::Refuse(Code::InvalidRequest);
    }
    let fields = if first >= head.len() {
        Vec::new()
    } else {
        match parse_fields(head, first + 2) {
            Some(fields) => fields,
            None => return Admission::Refuse(Code::InvalidRequest),
        }
    };
    if !authenticated(&fields, token) {
        return Admission::Refuse(Code::Unauthenticated);
    }
    let authority = &line[one + 1..two];
    let colon = last_colon(authority);
    let host = &authority[..colon];
    let port: &[u8] = if colon < authority.len() {
        &authority[colon + 1..]
    } else {
        &authority[colon..]
    };
    let https: &[u8] = b"443";
    let index = origin_index(hosts, host);
    if index >= hosts.len() || !(port == https) {
        return Admission::Refuse(Code::UnknownOrigin);
    }
    if !current {
        return Admission::Refuse(Code::Revoked);
    }
    Admission::Open(index)
}
