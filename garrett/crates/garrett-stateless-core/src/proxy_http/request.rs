//! Parsing the agent's request: the strict HTTP/1.1 request subset.
use super::*;

#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub enum Refusal {
    InvalidRequest,
    TooLarge,
    Denied,
    InvalidCredential,
    /// The upstream answer was not a usable response.
    UpstreamResponse,
    /// The response would have shown the guest a form of the credential.
    Reflected,
}

pub struct Field {
    /// Lowercased token.
    pub name: Vec<u8>,
    /// Exactly as received, without surrounding SP/HTAB.
    pub value: Vec<u8>,
}

pub struct Request {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub fields: Vec<Field>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

/// A complete request and how many input bytes it used.
pub struct Parsed {
    pub request: Request,
    pub used: usize,
}

pub fn visible(byte: u8) -> bool {
    byte >= b'!' && byte <= b'~'
}

pub fn token_byte(byte: u8) -> bool {
    http_wire::alphanumeric(byte)
        || byte == b'!'
        || byte == b'#'
        || byte == b'$'
        || byte == b'%'
        || byte == b'&'
        || byte == b'\''
        || byte == b'*'
        || byte == b'+'
        || byte == b'-'
        || byte == b'.'
        || byte == b'^'
        || byte == b'_'
        || byte == b'`'
        || byte == b'|'
        || byte == b'~'
}

pub fn valid_method(method: &[u8]) -> bool {
    let get: &[u8] = b"GET";
    let head: &[u8] = b"HEAD";
    let post: &[u8] = b"POST";
    let put: &[u8] = b"PUT";
    let patch: &[u8] = b"PATCH";
    let delete: &[u8] = b"DELETE";
    let options: &[u8] = b"OPTIONS";
    method == get
        || method == head
        || method == post
        || method == put
        || method == patch
        || method == delete
        || method == options
}

/// A percent-escape the strict subset refuses: malformed (not two hex
/// digits), or one that encodes an unreserved character (an alternate
/// spelling of a plain path), `/`, `\\`, NUL or `;`. Refusing these keeps
/// every accepted target in one canonical spelling, so deny rules cannot be
/// bypassed with an equivalent encoding.
pub fn bad_escape_at(value: &[u8], start: usize) -> bool {
    if start >= value.len() || value[start] != b'%' {
        return false;
    }
    if value.len() - start < 3 {
        return true;
    }
    let high = match hex_digit(value[start + 1]) {
        Some(digit) => digit,
        None => return true,
    };
    let low = match hex_digit(value[start + 2]) {
        Some(digit) => digit,
        None => return true,
    };
    let byte = (high * 16 + low) as u8;
    unreserved(byte) || byte == b'/' || byte == b'\\' || byte == 0 || byte == b';'
}

/// Visible ASCII without `#`, backslash, `;` or a refused escape.
pub fn plain_target_bytes(target: &[u8]) -> bool {
    let mut index = 0;
    while index < target.len() {
        let byte = target[index];
        if !visible(byte)
            || byte == b'#'
            || byte == b'\\'
            || byte == b';'
            || bad_escape_at(target, index)
        {
            return false;
        }
        index += 1;
    }
    true
}

pub fn path_end(target: &[u8]) -> usize {
    let mut index = 0;
    while index < target.len() && target[index] != b'?' {
        index += 1;
    }
    index
}

/// Whether the segment `path[start..end]` is acceptable at its position.
pub fn segment_ok(path: &[u8], start: usize, end: usize, last: bool) -> bool {
    let length = end - start;
    if length == 0 {
        return last;
    }
    if length == 1 {
        return path[start] != b'.';
    }
    if length == 2 {
        return !(path[start] == b'.' && path[start + 1] == b'.');
    }
    true
}

/// No empty segment (except a trailing slash) and no dot segment.
pub fn segments_ok(path: &[u8]) -> bool {
    // `path[0]` is `/`; segments follow each `/`.
    let mut start = 1;
    let mut index = 1;
    while index < path.len() {
        if path[index] == b'/' {
            if !segment_ok(path, start, index, false) {
                return false;
            }
            start = index + 1;
        }
        index += 1;
    }
    segment_ok(path, start, path.len(), true)
}

#[allow(clippy::len_zero)]
pub fn check_target(target: &[u8]) -> bool {
    if target.len() == 0 || target.len() > MAX_TARGET || target[0] != b'/' {
        return false;
    }
    if !plain_target_bytes(target) {
        return false;
    }
    let end = path_end(target);
    segments_ok(&target[..end])
}

/// Index of the first `\r\n\r\n`, if any.
pub fn head_end(data: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index + 4 <= data.len() {
        if data[index] == b'\r'
            && data[index + 1] == b'\n'
            && data[index + 2] == b'\r'
            && data[index + 3] == b'\n'
        {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Every CR in the head starts a CRLF, every LF ends one, and there is no NUL.
pub fn clean_head(head: &[u8]) -> bool {
    let mut index = 0;
    while index < head.len() {
        let byte = head[index];
        if byte == 0 {
            return false;
        }
        if byte == b'\r' && (index + 1 >= head.len() || head[index + 1] != b'\n') {
            return false;
        }
        if byte == b'\n' && (index == 0 || head[index - 1] != b'\r') {
            return false;
        }
        index += 1;
    }
    true
}

/// The end of the line starting at `start` (the index of its CR, or the end).
pub fn line_end(head: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < head.len() && head[index] != b'\r' {
        index += 1;
    }
    index
}

pub fn lowered(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in bytes {
        out.push(http_wire::ascii_lower(*byte));
    }
    out
}

pub fn colon_at(line: &[u8]) -> usize {
    let mut index = 0;
    while index < line.len() && line[index] != b':' {
        index += 1;
    }
    index
}

pub fn blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

pub fn all_token(line: &[u8], end: usize) -> bool {
    let mut index = 0;
    while index < end {
        // Every token byte is visible; checking both keeps the proof local.
        if !visible(line[index]) || !token_byte(line[index]) {
            return false;
        }
        index += 1;
    }
    true
}

pub fn skip_blank(line: &[u8], start: usize) -> usize {
    let mut first = start;
    while first < line.len() && blank(line[first]) {
        first += 1;
    }
    first
}

pub fn trim_blank_end(line: &[u8], first: usize) -> usize {
    let mut last = line.len();
    while last > first && blank(line[last - 1]) {
        last -= 1;
    }
    last
}

pub fn all_value(line: &[u8], first: usize, last: usize) -> bool {
    let mut check = first;
    while check < last {
        if !(visible(line[check]) || blank(line[check])) {
            return false;
        }
        check += 1;
    }
    true
}

/// One header field, `token ":" OWS value OWS`.
#[allow(clippy::len_zero)]
pub fn parse_field(line: &[u8]) -> Option<Field> {
    if line.len() == 0 || blank(line[0]) {
        return None;
    }
    let colon = colon_at(line);
    if colon == 0 || colon >= line.len() || !all_token(line, colon) {
        return None;
    }
    let first = skip_blank(line, colon + 1);
    let last = trim_blank_end(line, first);
    if !all_value(line, first, last) {
        return None;
    }
    Some(Field {
        name: lowered(&line[..colon]),
        value: line[first..last].to_vec(),
    })
}

/// Fields from the lines after the request line, or `None` if any is bad.
pub fn parse_fields(head: &[u8], start: usize) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    let mut position = start;
    while position < head.len() {
        let end = line_end(head, position);
        if fields.len() >= MAX_FIELDS {
            return None;
        }
        match parse_field(&head[position..end]) {
            Some(field) => fields.push(field),
            None => return None,
        }
        position = end + 2;
    }
    Some(fields)
}

/// ASCII-case-insensitive, so the filter does not depend on the parser
/// having lowercased names.
pub fn name_is(field: &Field, name: &[u8]) -> bool {
    http_wire::ascii_equal(&field.name, name)
}

pub fn count_named(fields: &[Field], name: &[u8]) -> usize {
    let mut count = 0;
    for field in fields {
        if name_is(field, name) {
            count += 1;
        }
    }
    count
}

/// Index of the first field named `name` (or `fields.len()`).
pub fn first_named(fields: &[Field], name: &[u8]) -> usize {
    let mut index = 0;
    while index < fields.len() && !name_is(&fields[index], name) {
        index += 1;
    }
    index
}

pub fn refused_field(field: &Field) -> bool {
    name_is(field, b"upgrade")
        || name_is(field, b"expect")
        || name_is(field, b"te")
        || name_is(field, b"trailer")
}

pub fn any_refused_field(fields: &[Field]) -> bool {
    for field in fields {
        if refused_field(field) {
            return true;
        }
    }
    false
}

/// `value` lowercased equals `host` or `host:443`.
pub fn host_matches(value: &[u8], host: &[u8]) -> bool {
    let lower = lowered(value);
    let mut with_port = host.to_vec();
    with_port.extend_from_slice(b":443");
    let lowered_value: &[u8] = &lower;
    let host_port: &[u8] = &with_port;
    lowered_value == host || lowered_value == host_port
}

/// One comma-separated `Connection` token, trimmed; `None` if not allowed.
/// Returns `Some(true)` for `close`.
pub fn connection_token(value: &[u8], start: usize, end: usize) -> Option<bool> {
    let mut first = start;
    while first < end && blank(value[first]) {
        first += 1;
    }
    let mut last = end;
    while last > first && blank(value[last - 1]) {
        last -= 1;
    }
    let token = lowered(&value[first..last]);
    let bytes: &[u8] = &token;
    let close: &[u8] = b"close";
    let keep: &[u8] = b"keep-alive";
    if bytes == close {
        Some(true)
    } else if bytes == keep {
        Some(false)
    } else {
        None
    }
}

/// Whether one `Connection` value is allowed, and whether it says `close`.
pub fn connection_value(value: &[u8]) -> Option<bool> {
    let mut close = false;
    let mut start = 0;
    let mut index = 0;
    while index <= value.len() {
        if index == value.len() || value[index] == b',' {
            match connection_token(value, start, index) {
                Some(token) => close = close || token,
                None => return None,
            }
            start = index + 1;
        }
        index += 1;
    }
    Some(close)
}

/// `Some(keep_alive)` if every `Connection` value is allowed.
pub fn keep_alive(fields: &[Field]) -> Option<bool> {
    let mut close = false;
    for field in fields {
        if name_is(field, b"connection") {
            match connection_value(&field.value) {
                Some(token) => close = close || token,
                None => return None,
            }
        }
    }
    Some(!close)
}

pub fn decimal(value: &[u8]) -> Option<usize> {
    if value.len() == 0 || value.len() > 12 {
        return None;
    }
    let mut total: usize = 0;
    for byte in value {
        if *byte < b'0' || *byte > b'9' {
            return None;
        }
        total = total * 10 + (*byte - b'0') as usize;
    }
    Some(total)
}

pub fn hex_digit(byte: u8) -> Option<usize> {
    if byte >= b'0' && byte <= b'9' {
        Some((byte - b'0') as usize)
    } else if byte >= b'a' && byte <= b'f' {
        Some((byte - b'a') as usize + 10)
    } else if byte >= b'A' && byte <= b'F' {
        Some((byte - b'A') as usize + 10)
    } else {
        None
    }
}

/// A chunk-size line `data[start..end]`: 1..=8 hex digits, no extensions.
pub fn chunk_size(data: &[u8], start: usize, end: usize) -> Option<usize> {
    if end <= start || end - start > 8 {
        return None;
    }
    let mut total: usize = 0;
    let mut index = start;
    while index < end {
        match hex_digit(data[index]) {
            Some(digit) => total = total * 16 + digit,
            None => return None,
        }
        index += 1;
    }
    Some(total)
}

pub fn crlf_from(data: &[u8], start: usize) -> usize {
    let mut index = start;
    while index + 1 < data.len() && !(data[index] == b'\r' && data[index + 1] == b'\n') {
        index += 1;
    }
    if index + 1 < data.len() {
        index
    } else {
        data.len()
    }
}

/// The outcome of decoding a chunked body from `data[start..]`.
pub enum Chunked {
    Done(Vec<u8>, usize),
    More,
    Bad(Refusal),
}

/// Decode chunks without extensions or trailers.
pub fn decode_chunked(data: &[u8], start: usize, limit: usize) -> Chunked {
    let mut body = Vec::new();
    let mut position = start;
    loop {
        let end = crlf_from(data, position);
        if end >= data.len() {
            if data.len() - position > 16 {
                return Chunked::Bad(Refusal::InvalidRequest);
            }
            return Chunked::More;
        }
        let size = match chunk_size(data, position, end) {
            Some(size) => size,
            None => return Chunked::Bad(Refusal::InvalidRequest),
        };
        position = end + 2;
        if size == 0 {
            if position + 2 <= data.len() {
                if data[position] == b'\r' && data[position + 1] == b'\n' {
                    return Chunked::Done(body, position + 2);
                }
                return Chunked::Bad(Refusal::InvalidRequest);
            }
            return Chunked::More;
        }
        if body.len() + size > limit {
            return Chunked::Bad(Refusal::TooLarge);
        }
        if data.len() < position + size + 2 {
            return Chunked::More;
        }
        if data[position + size] != b'\r' || data[position + size + 1] != b'\n' {
            return Chunked::Bad(Refusal::InvalidRequest);
        }
        body.extend_from_slice(&data[position..position + size]);
        position += size + 2;
    }
}

/// The request line `head[..end]`: method, target and the start of the target.
pub fn request_line(head: &[u8], end: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut first = 0;
    while first < end && head[first] != b' ' {
        first += 1;
    }
    let mut second = first + 1;
    while second < end && head[second] != b' ' {
        second += 1;
    }
    if first >= end || second >= end {
        return None;
    }
    let method = head[..first].to_vec();
    let target = head[first + 1..second].to_vec();
    let version: &[u8] = &head[second + 1..end];
    let expected: &[u8] = b"HTTP/1.1";
    if !(version == expected) || !valid_method(&method) || !check_target(&target) {
        return None;
    }
    Some((method, target))
}

/// Framing of the body that follows the head: `Ok(None)` for no body.
pub enum Framing {
    Empty,
    Length(usize),
    Chunked,
}

pub fn framing(fields: &[Field], limit: usize) -> Result<Framing, Refusal> {
    let encodings = count_named(fields, b"transfer-encoding");
    let lengths = count_named(fields, b"content-length");
    if encodings > 0 {
        let first = first_named(fields, b"transfer-encoding");
        let coding: &[u8] = &fields[first].value;
        let chunked: &[u8] = b"chunked";
        if lengths > 0 || encodings != 1 || !(coding == chunked) {
            return Err(Refusal::InvalidRequest);
        }
        return Ok(Framing::Chunked);
    }
    if lengths > 0 {
        if lengths != 1 {
            return Err(Refusal::InvalidRequest);
        }
        let first = first_named(fields, b"content-length");
        return match decimal(&fields[first].value) {
            Some(length) if length > limit => Err(Refusal::TooLarge),
            Some(length) => Ok(Framing::Length(length)),
            None => Err(Refusal::InvalidRequest),
        };
    }
    Ok(Framing::Empty)
}

/// Parse one request. `Ok(None)` means more bytes are needed.
/// The fields after the request line (none if the head is one line).
pub fn request_fields(head: &[u8], first: usize) -> Option<Vec<Field>> {
    if first >= head.len() {
        Some(Vec::new())
    } else {
        parse_fields(head, first + 2)
    }
}

/// The body starting at `start` and the bytes used, `None` if incomplete.
pub fn body_of(
    data: &[u8],
    start: usize,
    framed: &Framing,
    limit: usize,
) -> Result<Option<(Vec<u8>, usize)>, Refusal> {
    match framed {
        Framing::Empty => Ok(Some((Vec::new(), start))),
        Framing::Length(length) => {
            if data.len() - start < *length {
                return Ok(None);
            }
            Ok(Some((
                data[start..start + *length].to_vec(),
                start + *length,
            )))
        }
        Framing::Chunked => match decode_chunked(data, start, limit) {
            Chunked::Done(body, used) => Ok(Some((body, used))),
            Chunked::More => Ok(None),
            Chunked::Bad(refusal) => Err(refusal),
        },
    }
}

pub fn parse_request(data: &[u8], host: &[u8], limit: usize) -> Result<Option<Parsed>, Refusal> {
    let end = match head_end(data) {
        Some(end) => end,
        None => {
            if data.len() > MAX_HEAD {
                return Err(Refusal::InvalidRequest);
            }
            return Ok(None);
        }
    };
    if end > MAX_HEAD {
        return Err(Refusal::InvalidRequest);
    }
    let head = &data[..end];
    if !clean_head(head) {
        return Err(Refusal::InvalidRequest);
    }
    let first = line_end(head, 0);
    let (method, target) = match request_line(head, first) {
        Some(line) => line,
        None => return Err(Refusal::InvalidRequest),
    };
    let fields = match request_fields(head, first) {
        Some(fields) => fields,
        None => return Err(Refusal::InvalidRequest),
    };
    if any_refused_field(&fields) || count_named(&fields, b"host") != 1 {
        return Err(Refusal::InvalidRequest);
    }
    if !host_matches(&fields[first_named(&fields, b"host")].value, host) {
        return Err(Refusal::InvalidRequest);
    }
    let keep = match keep_alive(&fields) {
        Some(keep) => keep,
        None => return Err(Refusal::InvalidRequest),
    };
    let framed = match framing(&fields, limit) {
        Ok(framed) => framed,
        Err(refusal) => return Err(refusal),
    };
    let (body, used) = match body_of(data, end + 4, &framed, limit) {
        Ok(Some(found)) => found,
        Ok(None) => return Ok(None),
        Err(refusal) => return Err(refusal),
    };
    Ok(Some(Parsed {
        request: Request {
            method,
            target,
            fields,
            body,
            keep_alive: keep,
        },
        used,
    }))
}
