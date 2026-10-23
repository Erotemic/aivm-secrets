//! The provider request target of a named operation: the policy's path
//! template and query template filled with the request's arguments.
//!
//! The native manifest parses the policy and converts each argument to its
//! scalar text; this module owns every byte of the target. Each path value
//! is split on `/` and every piece must be an unreserved segment, as must
//! every query name and value, so a target contains no `?`, `#`, `%`, space,
//! CR or LF beyond the single `?` and the `=`/`&` separators written here.

use crate::http_wire::{alphanumeric, append_decimal};
use crate::manifest::Scalar;

/// One template part: a literal segment or a named parameter.
pub enum Piece {
    Literal(Vec<u8>),
    Parameter(Vec<u8>),
}

/// One query entry, `name=piece`, in policy order.
pub struct QueryPiece {
    pub name: Vec<u8>,
    pub piece: Piece,
}

/// A request argument already converted to its scalar text.
pub struct Binding {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

pub const MAX_SEGMENT: usize = 128;
pub const MAX_PATH: usize = 1024;
pub const MAX_TARGET: usize = 8192;

pub fn unreserved(byte: u8) -> bool {
    alphanumeric(byte) || byte == b'-' || byte == b'.' || byte == b'_' || byte == b'~'
}

/// A non-empty, bounded segment of unreserved bytes other than `.` and `..`.
pub fn segment_ok(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_SEGMENT {
        return false;
    }
    let dot: &[u8] = b".";
    let dots: &[u8] = b"..";
    if value == dot || value == dots {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        if !unreserved(value[index]) {
            return false;
        }
        index += 1;
    }
    true
}

/// Every `/`-separated piece of `value` is a segment.
pub fn segments_ok(value: &[u8]) -> bool {
    let mut start = 0;
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'/' {
            if !segment_ok(&value[start..index]) {
                return false;
            }
            start = index + 1;
        }
        index += 1;
    }
    segment_ok(&value[start..])
}

/// A parameter name: 1..=32 bytes, a lowercase letter first, then
/// lowercase letters, digits or `_`.
pub fn parameter_name(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > 32 || !(value[0] >= b'a' && value[0] <= b'z') {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if !((byte >= b'a' && byte <= b'z') || (byte >= b'0' && byte <= b'9') || byte == b'_') {
            return false;
        }
        index += 1;
    }
    true
}

/// One template part: `{name}` is a parameter, anything else must be a
/// segment literal.
pub fn parse_piece(text: &[u8]) -> Option<Piece> {
    if text.len() >= 2 && text[0] == b'{' && text[text.len() - 1] == b'}' {
        let inner = &text[1..text.len() - 1];
        if parameter_name(inner) {
            return Some(Piece::Parameter(inner.to_vec()));
        }
        return None;
    }
    if segment_ok(text) {
        Some(Piece::Literal(text.to_vec()))
    } else {
        None
    }
}

/// The first `/` at or after `from`, or the length of `text`.
pub fn next_slash(text: &[u8], from: usize) -> usize {
    let mut index = from;
    while index < text.len() {
        if text[index] == b'/' {
            return index;
        }
        index += 1;
    }
    text.len()
}

/// Parse the `/`-separated parts from `start` on, appending them to `pieces`.
pub fn parse_parts(text: &[u8], start: usize, pieces: &mut Vec<Piece>) -> bool {
    let mut begin = start;
    let mut ok = true;
    while ok && begin <= text.len() {
        let stop = next_slash(text, begin);
        match parse_piece(&text[begin..stop]) {
            Some(piece) => pieces.push(piece),
            None => ok = false,
        }
        begin = stop + 1;
    }
    ok
}

/// A path template `/part/part...` as pieces, or `None` if any part is not
/// a segment or a `{name}`.
pub fn parse_template(text: &[u8]) -> Option<Vec<Piece>> {
    if text.is_empty() || text[0] != b'/' {
        return None;
    }
    let mut pieces = Vec::new();
    if parse_parts(text, 1, &mut pieces) {
        Some(pieces)
    } else {
        None
    }
}

/// The text of a scalar argument: a string as is, an integer in decimal
/// (with `-` when negative).
pub fn scalar_text(value: &Scalar) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        Scalar::Text(bytes) => out.extend_from_slice(bytes),
        Scalar::Integer(number) => {
            if *number < 0 {
                out.push(b'-');
                // |number| without overflow, also for i64::MIN.
                append_decimal(&mut out, (-(*number + 1)) as usize + 1);
            } else {
                append_decimal(&mut out, *number as usize);
            }
        }
    }
    out
}

/// A binding from a name and a scalar argument.
pub fn scalar_binding(name: &[u8], value: &Scalar) -> Binding {
    Binding {
        name: name.to_vec(),
        value: scalar_text(value),
    }
}

/// The index of the binding named `name`, if any.
pub fn lookup(bindings: &[Binding], name: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index < bindings.len() {
        let candidate: &[u8] = &bindings[index].name;
        if candidate == name {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// A referenced argument is missing, a value is not a valid segment, or the
/// path or target is out of bounds.
pub enum RouteDenial {
    Denied,
}

/// Append one filled part, with `/`-separated pieces each a segment.
pub fn fill_piece(
    output: &mut Vec<u8>,
    piece: &Piece,
    bindings: &[Binding],
) -> Result<(), RouteDenial> {
    match piece {
        Piece::Literal(text) => {
            if !segments_ok(text) {
                return Err(RouteDenial::Denied);
            }
            output.extend_from_slice(text);
            Ok(())
        }
        Piece::Parameter(name) => match lookup(bindings, name) {
            Some(index) => {
                let value: &[u8] = &bindings[index].value;
                if !segments_ok(value) {
                    return Err(RouteDenial::Denied);
                }
                output.extend_from_slice(value);
                Ok(())
            }
            None => Err(RouteDenial::Denied),
        },
    }
}

/// `/part/part...`, at most `MAX_PATH` bytes.
pub fn fill_path(
    output: &mut Vec<u8>,
    path: &[Piece],
    bindings: &[Binding],
) -> Result<(), RouteDenial> {
    let mut ok = true;
    let mut index = 0;
    while ok && index < path.len() {
        output.push(b'/');
        match fill_piece(output, &path[index], bindings) {
            Ok(()) => index += 1,
            Err(_) => ok = false,
        }
    }
    if !ok || output.len() < 2 || output.len() > MAX_PATH {
        return Err(RouteDenial::Denied);
    }
    Ok(())
}

/// `?name=value` (first) or `&name=value`, the value one segment.
pub fn fill_query_entry(
    output: &mut Vec<u8>,
    entry: &QueryPiece,
    first: bool,
    bindings: &[Binding],
) -> Result<(), RouteDenial> {
    if !segment_ok(&entry.name) {
        return Err(RouteDenial::Denied);
    }
    if first {
        output.push(b'?');
    } else {
        output.push(b'&');
    }
    output.extend_from_slice(&entry.name);
    output.push(b'=');
    let start = output.len();
    match fill_piece(output, &entry.piece, bindings) {
        Ok(()) => (),
        Err(denial) => return Err(denial),
    }
    if !segment_ok(&output[start..]) {
        return Err(RouteDenial::Denied);
    }
    Ok(())
}

/// The complete target: the filled path, then `?name=value&...` when the
/// operation has a query, at most `MAX_TARGET` bytes.
pub fn fill_target(
    path: &[Piece],
    query: &[QueryPiece],
    bindings: &[Binding],
) -> Result<Vec<u8>, RouteDenial> {
    let mut output = Vec::new();
    match fill_path(&mut output, path, bindings) {
        Ok(()) => (),
        Err(denial) => return Err(denial),
    }
    let mut ok = true;
    let mut index = 0;
    while ok && index < query.len() {
        match fill_query_entry(&mut output, &query[index], index == 0, bindings) {
            Ok(()) => index += 1,
            Err(_) => ok = false,
        }
    }
    if !ok || output.len() > MAX_TARGET {
        return Err(RouteDenial::Denied);
    }
    Ok(output)
}
