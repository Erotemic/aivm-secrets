//! The provider request target of a named operation: the policy's path
//! template and query template filled with the request's arguments.
//!
//! The native manifest parses the policy and converts each argument to its
//! scalar text; this module owns every byte of the target. Each path value
//! is split on `/` and every piece must be an unreserved segment, as must
//! every query name and value, so a target contains no `?`, `#`, `%`, space,
//! CR or LF beyond the single `?` and the `=`/`&` separators written here.

use crate::http_wire::alphanumeric;

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
