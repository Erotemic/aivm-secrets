//! The proxy's strict HTTP/1.1 subset: request and response parsing, the
//! field filter, the exact upstream encoder, response re-framing with
//! reflected-credential refusal, and the fixed refusal responses
//! (`docs/garrett-stateless-v1.md` section 11).
//!
//! The Python counterpart is `garrett_stateless.core.http`. Every function is
//! pure over bytes. The encoder injects the credential only through
//! `http_auth::append_header`; every agent field that could carry a
//! credential or change framing is removed first. ("Guest" below is the
//! agent's side of the proxy.)
use crate::credential_use::Authentication;
use crate::{http_auth, http_wire, reflection};

pub const MAX_HEAD: usize = 32 * 1024;
pub const MAX_FIELDS: usize = 100;
pub const MAX_TARGET: usize = 8192;

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

pub struct DenyRule {
    /// Empty means any method.
    pub method: Vec<u8>,
    pub path: Vec<u8>,
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

/// Guest fields never forwarded: credentials of any scheme, proxy and
/// hop-by-hop fields, framing, negotiation the proxy owns, method overrides
/// (which could route around method-specific deny rules) and ranges (which
/// could fetch an echoed credential in pieces).
pub fn dropped(field: &Field) -> bool {
    name_is(field, b"authorization")
        || name_is(field, b"x-api-key")
        || name_is(field, b"proxy-authorization")
        || name_is(field, b"proxy-connection")
        || name_is(field, b"connection")
        || name_is(field, b"keep-alive")
        || name_is(field, b"transfer-encoding")
        || name_is(field, b"content-length")
        || name_is(field, b"te")
        || name_is(field, b"trailer")
        || name_is(field, b"upgrade")
        || name_is(field, b"host")
        || name_is(field, b"accept-encoding")
        || name_is(field, b"cookie")
        || name_is(field, b"x-http-method-override")
        || name_is(field, b"x-method-override")
        || name_is(field, b"x-http-method")
        || name_is(field, b"range")
        || name_is(field, b"if-range")
}

pub fn forwarded(fields: &[Field]) -> Vec<Field> {
    let mut out = Vec::new();
    for field in fields {
        if !dropped(field) {
            out.push(Field {
                name: field.name.clone(),
                value: field.value.clone(),
            });
        }
    }
    out
}

/// A rule matches its exact path, the same path with a trailing slash, or,
/// for a `/`-ending prefix, the prefix without its slash and everything
/// under it.
#[allow(clippy::len_zero)]
/// An empty rule method matches any method.
#[allow(clippy::len_zero)]
pub fn method_ok(rule_method: &[u8], method: &[u8]) -> bool {
    rule_method.len() == 0 || rule_method == method
}

/// `path` is `prefix` followed by exactly one `/`.
pub fn plus_slash(prefix: &[u8], path: &[u8]) -> bool {
    path.len() > prefix.len()
        && path.len() - prefix.len() == 1
        && path[prefix.len()] == b'/'
        && &path[..prefix.len()] == prefix
}

/// `rule_path` ends with `/`.
pub fn ends_with_slash(rule_path: &[u8]) -> bool {
    rule_path.len() > 0 && rule_path[rule_path.len() - 1] == b'/'
}

/// The rule path matches exactly, with one added trailing `/`, and, for a
/// rule path ending in `/`, without that `/` or as a prefix.
pub fn path_matches(rule_path: &[u8], path: &[u8]) -> bool {
    path == rule_path
        || plus_slash(rule_path, path)
        || (ends_with_slash(rule_path)
            && (plus_slash(path, rule_path)
                || (path.len() >= rule_path.len() && &path[..rule_path.len()] == rule_path)))
}

pub fn rule_matches(rule: &DenyRule, method: &[u8], path: &[u8]) -> bool {
    method_ok(&rule.method, method) && path_matches(&rule.path, path)
}

pub fn denied(rules: &[DenyRule], method: &[u8], path: &[u8]) -> bool {
    for rule in rules {
        if rule_matches(rule, method, path) {
            return true;
        }
    }
    false
}

/// A field that is one header line: a non-empty token name and a value of
/// visible ASCII, SP and HTAB (so no CR, LF or NUL).
#[allow(clippy::len_zero)]
pub fn clean_field(field: &Field) -> bool {
    field.name.len() != 0
        && all_token(&field.name, field.name.len())
        && all_value(&field.value, 0, field.value.len())
}

pub fn clean_fields(fields: &[Field]) -> bool {
    for field in fields {
        if !clean_field(field) {
            return false;
        }
    }
    true
}

pub fn append_fields(output: &mut Vec<u8>, fields: &[Field]) {
    for field in fields {
        output.extend_from_slice(&field.name);
        output.extend_from_slice(b": ");
        output.extend_from_slice(&field.value);
        output.extend_from_slice(b"\r\n");
    }
}

pub fn needs_length(request: &Request) -> bool {
    let post: &[u8] = b"POST";
    let put: &[u8] = b"PUT";
    let patch: &[u8] = b"PATCH";
    let method: &[u8] = &request.method;
    request.body.len() > 0 || method == post || method == put || method == patch
}

/// The canonical upstream request for an accepted guest request.
///
/// Refuses a deny-listed request or an invalid credential before touching
/// `output`. The credential enters `output` only through
/// `http_auth::append_header`, after the filtered guest fields.
pub fn encode_upstream(
    output: &mut Vec<u8>,
    request: &Request,
    host: &[u8],
    rules: &[DenyRule],
    secret: &[u8],
    authentication: &Authentication,
) -> Result<(), Refusal> {
    // Re-validate everything the parser should already have ensured, so the
    // framing of the upstream request does not depend on the parser.
    if !valid_method(&request.method) || !check_target(&request.target) {
        return Err(Refusal::InvalidRequest);
    }
    let fields = forwarded(&request.fields);
    if !clean_fields(&fields) {
        return Err(Refusal::InvalidRequest);
    }
    let end = path_end(&request.target);
    if denied(rules, &request.method, &request.target[..end]) {
        return Err(Refusal::Denied);
    }
    if !http_auth::valid_credential(secret) {
        return Err(Refusal::InvalidCredential);
    }
    output.extend_from_slice(&request.method);
    output.extend_from_slice(b" ");
    output.extend_from_slice(&request.target);
    output.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    output.extend_from_slice(host);
    output.extend_from_slice(b"\r\n");
    append_fields(output, &fields);
    match http_auth::append_header(output, secret, authentication) {
        Ok(()) => (),
        Err(_) => return Err(Refusal::InvalidCredential),
    }
    output.extend_from_slice(b"Accept-Encoding: identity\r\nConnection: close\r\n");
    if needs_length(request) {
        output.extend_from_slice(b"Content-Length: ");
        http_wire::append_decimal(output, request.body.len());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&request.body);
    Ok(())
}

// ---------------------------------------------------------------------------
// Response side: parse the upstream answer, re-frame it for the guest, and
// refuse it when it reflects the credential.
// ---------------------------------------------------------------------------

pub struct Response {
    pub status: u16,
    pub reason: Vec<u8>,
    pub fields: Vec<Field>,
    pub body: Vec<u8>,
}

/// An encoding of the credential the guest must never receive. `folded`
/// forms are compared without regard to ASCII case.
pub struct Form {
    pub bytes: Vec<u8>,
    pub folded: bool,
}

pub fn digit3(line: &[u8], start: usize) -> Option<u16> {
    if start + 3 > line.len() {
        return None;
    }
    let mut total: u16 = 0;
    let mut index = start;
    while index < start + 3 {
        let byte = line[index];
        if byte < b'0' || byte > b'9' {
            return None;
        }
        total = total * 10 + (byte - b'0') as u16;
        index += 1;
    }
    Some(total)
}

/// `HTTP/1.1 NNN reason`; three digits, at least 200.
pub fn status_line(head: &[u8], end: usize) -> Option<(u16, Vec<u8>)> {
    let prefix: &[u8] = b"HTTP/1.1 ";
    if end < 12 || !(&head[..9] == prefix) {
        return None;
    }
    let status = match digit3(head, 9) {
        Some(status) => status,
        None => return None,
    };
    if status < 200 {
        return None;
    }
    if end > 12 && head[12] != b' ' {
        return None;
    }
    let reason_start = if end > 12 { 13 } else { 12 };
    if !all_value(head, reason_start, end) {
        return None;
    }
    Some((status, head[reason_start..end].to_vec()))
}

pub fn identity_only(fields: &[Field]) -> bool {
    for field in fields {
        if name_is(field, b"content-encoding") && !http_wire::ascii_equal(&field.value, b"identity")
        {
            return false;
        }
    }
    true
}

/// Parse one complete upstream response (the upstream connection is closed
/// after it, so `data` is everything the provider sent).
pub fn parse_response(data: &[u8], head_request: bool, limit: usize) -> Result<Response, Refusal> {
    let end = match head_end(data) {
        Some(end) => end,
        None => return Err(Refusal::UpstreamResponse),
    };
    if end > MAX_HEAD {
        return Err(Refusal::UpstreamResponse);
    }
    let head = &data[..end];
    if !clean_head(head) {
        return Err(Refusal::UpstreamResponse);
    }
    let first = line_end(head, 0);
    let (status, reason) = match status_line(head, first) {
        Some(line) => line,
        None => return Err(Refusal::UpstreamResponse),
    };
    let fields = if first >= head.len() {
        Vec::new()
    } else {
        match parse_fields(head, first + 2) {
            Some(fields) => fields,
            None => return Err(Refusal::UpstreamResponse),
        }
    };
    if !identity_only(&fields) {
        return Err(Refusal::UpstreamResponse);
    }
    let start = end + 4;
    let body = if head_request || status == 204 || status == 304 {
        Vec::new()
    } else {
        match framing(&fields, limit) {
            Err(Refusal::TooLarge) => return Err(Refusal::TooLarge),
            Err(_) => return Err(Refusal::UpstreamResponse),
            Ok(Framing::Length(length)) => {
                if data.len() - start < length {
                    return Err(Refusal::UpstreamResponse);
                }
                data[start..start + length].to_vec()
            }
            Ok(Framing::Chunked) => match decode_chunked(data, start, limit) {
                Chunked::Done(body, _) => body,
                Chunked::More => return Err(Refusal::UpstreamResponse),
                Chunked::Bad(Refusal::TooLarge) => return Err(Refusal::TooLarge),
                Chunked::Bad(_) => return Err(Refusal::UpstreamResponse),
            },
            Ok(Framing::Empty) => {
                if data.len() - start > limit {
                    return Err(Refusal::TooLarge);
                }
                data[start..].to_vec()
            }
        }
    };
    Ok(Response {
        status,
        reason,
        fields,
        body,
    })
}

/// Upstream fields never returned to the guest.
pub fn dropped_response(field: &Field) -> bool {
    name_is(field, b"connection")
        || name_is(field, b"keep-alive")
        || name_is(field, b"transfer-encoding")
        || name_is(field, b"content-length")
        || name_is(field, b"proxy-authenticate")
        || name_is(field, b"proxy-connection")
        || name_is(field, b"trailer")
        || name_is(field, b"upgrade")
        || name_is(field, b"set-cookie")
}

pub fn returned_fields(fields: &[Field]) -> Vec<Field> {
    let mut out = Vec::new();
    for field in fields {
        if !dropped_response(field) {
            out.push(Field {
                name: field.name.clone(),
                value: field.value.clone(),
            });
        }
    }
    out
}

/// Re-frame a response for the guest with an exact `Content-Length`.
pub fn encode_response(
    output: &mut Vec<u8>,
    response: &Response,
    fields: &[Field],
    keep_alive: bool,
    head: bool,
) {
    output.extend_from_slice(b"HTTP/1.1 ");
    http_wire::append_decimal(output, response.status as usize);
    output.extend_from_slice(b" ");
    output.extend_from_slice(&response.reason);
    output.extend_from_slice(b"\r\n");
    append_fields(output, fields);
    output.extend_from_slice(b"Content-Length: ");
    http_wire::append_decimal(output, response.body.len());
    if keep_alive {
        output.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");
    } else {
        output.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    }
    if !head {
        output.extend_from_slice(&response.body);
    }
}

pub fn hex_lower(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

pub fn unreserved(byte: u8) -> bool {
    http_wire::alphanumeric(byte) || byte == b'_' || byte == b'.' || byte == b'-' || byte == b'~'
}

/// Percent-encoding of every byte but `A-Za-z0-9_.-~`, lowercased throughout.
pub fn percent_lower(secret: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in secret {
        if unreserved(*byte) {
            out.push(http_wire::ascii_lower(*byte));
        } else {
            out.push(b'%');
            out.push(hex_lower(*byte >> 4));
            out.push(hex_lower(*byte & 15));
        }
    }
    out
}

pub fn hex_bytes(secret: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in secret {
        out.push(hex_lower(*byte >> 4));
        out.push(hex_lower(*byte & 15));
    }
    out
}

pub fn base64_symbol(value: u8, url: bool) -> u8 {
    if value < 26 {
        b'A' + value
    } else if value < 52 {
        b'a' + (value - 26)
    } else if value < 62 {
        b'0' + (value - 52)
    } else if value == 62 {
        if url {
            b'-'
        } else {
            b'+'
        }
    } else if url {
        b'_'
    } else {
        b'/'
    }
}

/// The 6-bit group `index` of `bytes` (zero bits past the end).
pub fn sextet(bytes: &[u8], index: usize) -> u8 {
    let bit = index * 6;
    let byte = bit / 8;
    let offset = bit % 8;
    let high = bytes[byte] as u16;
    let low = if byte + 1 < bytes.len() {
        bytes[byte + 1] as u16
    } else {
        0
    };
    let pair = (high << 8) | low;
    ((pair >> (10 - offset)) & 63) as u8
}

/// Unpadded base64 of `bytes`: groups `0 .. ceil(8n/6)`. The native broker
/// encodes with this, so `encode(decode(text)) == text` pins the decoded bytes.
pub fn encode_unpadded(bytes: &[u8], url: bool) -> Vec<u8> {
    let end = (8 * bytes.len() + 5) / 6;
    let mut out = Vec::new();
    let mut index = 0;
    while index < end {
        out.push(base64_symbol(sextet(bytes, index), url));
        index += 1;
    }
    out
}

/// Base64 symbols that occur whenever `secret` is encoded after `shift`
/// leading bytes: groups `ceil(8*shift/6) .. floor(8*(shift+n)/6)`.
pub fn aligned_base64(secret: &[u8], shift: usize, url: bool) -> Vec<u8> {
    let mut padded = Vec::new();
    let mut zero = 0;
    while zero < shift {
        padded.push(0);
        zero += 1;
    }
    padded.extend_from_slice(secret);
    let start = (8 * shift + 5) / 6;
    let end = (8 * padded.len()) / 6;
    let mut out = Vec::new();
    let mut index = start;
    while index < end {
        out.push(base64_symbol(sextet(&padded, index), url));
        index += 1;
    }
    out
}

/// Every encoding of the credential the guest must never receive.
/// The credential as a JSON string body escapes it (`/` as `\\/`).
pub fn json_slashes(secret: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in secret {
        if *byte == b'/' {
            out.push(b'\\');
        }
        out.push(*byte);
    }
    out
}

pub fn reflection_forms(secret: &[u8]) -> Vec<Form> {
    let mut forms = Vec::new();
    forms.push(Form {
        bytes: secret.to_vec(),
        folded: false,
    });
    let escaped = json_slashes(secret);
    if escaped.len() != secret.len() {
        forms.push(Form {
            bytes: escaped,
            folded: false,
        });
    }
    forms.push(Form {
        bytes: percent_lower(secret),
        folded: true,
    });
    forms.push(Form {
        bytes: hex_bytes(secret),
        folded: true,
    });
    let mut shift = 0;
    while shift < 3 {
        let standard = aligned_base64(secret, shift, false);
        if standard.len() >= 8 {
            forms.push(Form {
                bytes: standard,
                folded: false,
            });
        }
        let url = aligned_base64(secret, shift, true);
        if url.len() >= 8 {
            forms.push(Form {
                bytes: url,
                folded: false,
            });
        }
        shift += 1;
    }
    forms
}

/// `data` without CR and LF, so line-wrapped (MIME-style) base64 is found.
pub fn unwrapped(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in data {
        if *byte != b'\r' && *byte != b'\n' {
            out.push(*byte);
        }
    }
    out
}

/// Whether one form occurs: folded forms are searched in the lowercased
/// data; the others in the data and in the data without line breaks.
pub fn form_present(data: &[u8], folded_data: &[u8], unwrapped_data: &[u8], form: &Form) -> bool {
    if form.folded {
        reflection::contains(folded_data, &form.bytes)
    } else {
        reflection::contains(data, &form.bytes) || reflection::contains(unwrapped_data, &form.bytes)
    }
}

pub fn reflects(data: &[u8], forms: &[Form]) -> bool {
    let folded_data = lowered(data);
    let unwrapped_data = unwrapped(data);
    for form in forms {
        if form_present(data, &folded_data, &unwrapped_data, form) {
            return true;
        }
    }
    false
}

/// The guest's bytes for an upstream response, or `Reflected` if the full
/// re-framed response contains any form of the credential.
pub fn guest_response(
    output: &mut Vec<u8>,
    response: &Response,
    forms: &[Form],
    keep_alive: bool,
    head: bool,
) -> Result<(), Refusal> {
    let fields = returned_fields(&response.fields);
    let mut full = Vec::new();
    encode_response(&mut full, response, &fields, keep_alive, false);
    if reflects(&full, forms) {
        return Err(Refusal::Reflected);
    }
    encode_response(output, response, &fields, keep_alive, head);
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixed refusals: the only guest-visible answer when a request is refused.
// ---------------------------------------------------------------------------

/// Every public refusal reason of the proxy.
pub enum Code {
    InvalidRequest,
    TooLarge,
    Denied,
    UnknownOrigin,
    Unauthenticated,
    Revoked,
    Reflected,
    Unreachable,
    OutcomeUnknown,
    CredentialSource,
    UnsupportedRequest,
    /// The admission audit could not be recorded; nothing was sent.
    InternalError,
}

pub fn append_code(output: &mut Vec<u8>, code: &Code) {
    match code {
        Code::InvalidRequest => output.extend_from_slice(b"invalid_request"),
        Code::TooLarge => output.extend_from_slice(b"too_large"),
        Code::Denied => output.extend_from_slice(b"denied"),
        Code::UnknownOrigin => output.extend_from_slice(b"unknown_origin"),
        Code::Unauthenticated => output.extend_from_slice(b"unauthenticated"),
        Code::Revoked => output.extend_from_slice(b"revoked"),
        Code::Reflected => output.extend_from_slice(b"reflected"),
        Code::Unreachable => output.extend_from_slice(b"unreachable"),
        Code::OutcomeUnknown => output.extend_from_slice(b"outcome_unknown"),
        Code::CredentialSource => output.extend_from_slice(b"credential_source"),
        Code::UnsupportedRequest => output.extend_from_slice(b"unsupported_request"),
        Code::InternalError => output.extend_from_slice(b"internal_error"),
    }
}

pub fn append_status(output: &mut Vec<u8>, code: &Code) {
    match code {
        Code::InvalidRequest => output.extend_from_slice(b"400 Bad Request"),
        Code::TooLarge => output.extend_from_slice(b"413 Content Too Large"),
        Code::Unauthenticated => output.extend_from_slice(b"407 Proxy Authentication Required"),
        Code::Denied | Code::UnknownOrigin | Code::Revoked | Code::UnsupportedRequest => {
            output.extend_from_slice(b"403 Forbidden")
        }
        Code::Reflected
        | Code::Unreachable
        | Code::OutcomeUnknown
        | Code::CredentialSource
        | Code::InternalError => output.extend_from_slice(b"502 Bad Gateway"),
    }
}

/// The fixed guest response for a refusal: status, code and nothing else.
pub fn refusal(code: &Code) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"{\"error\":{\"code\":\"");
    append_code(&mut body, code);
    body.extend_from_slice(b"\"},\"ok\":false,\"proxy\":\"aivm-secrets\"}\n");
    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 ");
    append_status(&mut out, code);
    out.extend_from_slice(b"\r\n");
    if let Code::Unauthenticated = code {
        out.extend_from_slice(b"Proxy-Authenticate: Basic realm=\"aivm-secrets\"\r\n");
    }
    out.extend_from_slice(b"Content-Type: application/json\r\nContent-Length: ");
    http_wire::append_decimal(&mut out, body.len());
    out.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    /// The deny-rule matcher before it was split into helpers.
    fn legacy_rule_matches(rule: &DenyRule, method: &[u8], path: &[u8]) -> bool {
        let rule_method: &[u8] = &rule.method;
        let rule_path: &[u8] = &rule.path;
        if rule_method.len() != 0 && !(rule_method == method) {
            return false;
        }
        if path == rule_path {
            return true;
        }
        if path.len() > rule_path.len()
            && path.len() - rule_path.len() == 1
            && path[rule_path.len()] == b'/'
            && &path[..rule_path.len()] == rule_path
        {
            return true;
        }
        if rule_path.len() == 0 || rule_path[rule_path.len() - 1] != b'/' {
            return false;
        }
        if rule_path.len() > path.len()
            && rule_path.len() - path.len() == 1
            && path == &rule_path[..path.len()]
        {
            return true;
        }
        path.len() >= rule_path.len() && &path[..rule_path.len()] == rule_path
    }

    #[test]
    fn deny_rule_matcher_agrees_with_the_legacy_matcher_on_all_short_paths() {
        // Every path and rule path of up to four bytes over {a, /}, every
        // method pair: exhaustive, not sampled.
        let mut words: Vec<Vec<u8>> = vec![Vec::new()];
        let mut frontier = words.clone();
        for _ in 0..4 {
            frontier = frontier
                .iter()
                .flat_map(|w| [b'a', b'/'].map(|b| [w.clone(), vec![b]].concat()))
                .collect();
            words.extend(frontier.clone());
        }
        let methods: [&[u8]; 3] = [b"", b"GET", b"POST"];
        for rule_path in &words {
            for rule_method in methods {
                let rule = DenyRule {
                    method: rule_method.to_vec(),
                    path: rule_path.clone(),
                };
                for path in &words {
                    for method in &methods[1..] {
                        assert_eq!(
                            rule_matches(&rule, method, path),
                            legacy_rule_matches(&rule, method, path),
                            "{rule_method:?} {rule_path:?} {method:?} {path:?}"
                        );
                    }
                }
            }
        }
    }

    use super::*;

    fn parse(bytes: &[u8]) -> Result<Option<Parsed>, Refusal> {
        parse_request(bytes, b"api.example.org", 1024)
    }

    #[test]
    fn a_request_is_reencoded_with_one_credential_line() {
        let raw = b"POST /v1/issues HTTP/1.1\r\nHost: api.example.org\r\nAuthorization: token guest\r\nX-Trace:  t  \r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
        let parsed = match parse(raw) {
            Ok(Some(parsed)) => parsed,
            _ => panic!("refused"),
        };
        assert_eq!(parsed.used, raw.len());
        let mut out = Vec::new();
        assert!(encode_upstream(
            &mut out,
            &parsed.request,
            b"api.example.org",
            &[],
            b"SECRET",
            &Authentication::Bearer
        )
        .is_ok());
        assert_eq!(out, b"POST /v1/issues HTTP/1.1\r\nHost: api.example.org\r\nx-trace: t\r\nAuthorization: Bearer SECRET\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi".to_vec());
    }

    #[test]
    fn ambiguous_requests_are_refused() {
        for raw in [
            b"GET / HTTP/1.1\r\nHost: api.example.org\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: api.example.org\r\nX: a\r\n b\r\n\r\n",
            b"GET / HTTP/1.1\nHost: api.example.org\r\n\r\n",
            b"GET /a/../b HTTP/1.1\r\nHost: api.example.org\r\n\r\n",
            b"GET /a%2Fb HTTP/1.1\r\nHost: api.example.org\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: evil.example.org\r\n\r\n",
            b"GET / HTTP/1.0\r\nHost: api.example.org\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: api.example.org\r\nUpgrade: h2c\r\n\r\n",
        ] {
            assert!(matches!(parse(raw), Err(Refusal::InvalidRequest)));
        }
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn code(refusal: &Refusal) -> &'static str {
        match refusal {
            Refusal::InvalidRequest => "invalid",
            Refusal::TooLarge => "large",
            Refusal::Denied => "denied",
            Refusal::InvalidCredential => "credential",
            Refusal::UpstreamResponse => "upstream",
            Refusal::Reflected => "reflected",
        }
    }

    /// Byte parity with the Python reference (`tests/test_proxy_rust_parity.py`).
    #[test]
    fn python_reference_vectors() {
        let vectors = include_str!("../../../tests/vectors/proxy-http-v1.tsv");
        let rules = [
            DenyRule {
                method: b"POST".to_vec(),
                path: b"/v1/tokens".to_vec(),
            },
            DenyRule {
                method: Vec::new(),
                path: b"/v1/admin/".to_vec(),
            },
        ];
        let mut checked = 0;
        for line in vectors.lines().skip(1) {
            let columns: Vec<&str> = line.split('\t').collect();
            let raw = unhex(columns[0]);
            let secret = unhex(columns[1]);
            let authentication = match columns[2] {
                "bearer" => Authentication::Bearer,
                _ => Authentication::ApiKey,
            };
            let actual = match parse_request(&raw, b"api.example.org", 64) {
                Ok(None) => "more".to_string(),
                Err(refusal) => format!("refused:{}", code(&refusal)),
                Ok(Some(parsed)) => {
                    let mut out = Vec::new();
                    match encode_upstream(
                        &mut out,
                        &parsed.request,
                        b"api.example.org",
                        &rules,
                        &secret,
                        &authentication,
                    ) {
                        Ok(()) => format!("ok:{}:{}", parsed.used, hex(&out)),
                        Err(refusal) => format!("refused:{}", code(&refusal)),
                    }
                }
            };
            assert_eq!(actual, columns[3], "vector {}", checked);
            checked += 1;
        }
        assert!(checked >= 60);
    }

    /// Response-side parity with the Python reference.
    #[test]
    fn python_reference_response_vectors() {
        let vectors = include_str!("../../../tests/vectors/proxy-http-response-v1.tsv");
        let mut checked = 0;
        for line in vectors.lines().skip(1) {
            let columns: Vec<&str> = line.split('\t').collect();
            let raw = unhex(columns[0]);
            let head = columns[1] == "1";
            let keep = columns[2] == "1";
            let secret = unhex(columns[3]);
            let forms = reflection_forms(&secret);
            let actual = match parse_response(&raw, head, 64) {
                Err(refusal) => format!("refused:{}", code(&refusal)),
                Ok(response) => {
                    let mut out = Vec::new();
                    match guest_response(&mut out, &response, &forms, keep, head) {
                        Ok(()) => format!("ok:{}", hex(&out)),
                        Err(refusal) => format!("refused:{}", code(&refusal)),
                    }
                }
            };
            assert_eq!(actual, columns[4], "response vector {}", checked);
            checked += 1;
        }
        assert!(checked >= 35);
    }

    /// Refusal parity with the Python reference.
    #[test]
    fn python_reference_refusals() {
        let vectors = include_str!("../../../tests/vectors/proxy-http-refusal-v1.tsv");
        let codes = [
            ("invalid_request", Code::InvalidRequest),
            ("too_large", Code::TooLarge),
            ("denied", Code::Denied),
            ("unknown_origin", Code::UnknownOrigin),
            ("unauthenticated", Code::Unauthenticated),
            ("revoked", Code::Revoked),
            ("reflected", Code::Reflected),
            ("unreachable", Code::Unreachable),
            ("outcome_unknown", Code::OutcomeUnknown),
            ("credential_source", Code::CredentialSource),
            ("unsupported_request", Code::UnsupportedRequest),
        ];
        let mut checked = 0;
        for line in vectors.lines().skip(1) {
            let columns: Vec<&str> = line.split('\t').collect();
            let code = &codes
                .iter()
                .find(|(name, _)| *name == columns[0])
                .unwrap()
                .1;
            assert_eq!(hex(&refusal(code)), columns[1], "refusal {}", columns[0]);
            checked += 1;
        }
        assert_eq!(checked, codes.len());
    }

    #[test]
    fn deny_rules_refuse_before_writing() {
        let raw = b"GET /v1/admin/x HTTP/1.1\r\nHost: api.example.org\r\n\r\n";
        let parsed = match parse(raw) {
            Ok(Some(parsed)) => parsed,
            _ => panic!("refused"),
        };
        let rules = [DenyRule {
            method: Vec::new(),
            path: b"/v1/admin/".to_vec(),
        }];
        let mut out = b"keep".to_vec();
        assert!(matches!(
            encode_upstream(
                &mut out,
                &parsed.request,
                b"api.example.org",
                &rules,
                b"S",
                &Authentication::ApiKey
            ),
            Err(Refusal::Denied)
        ));
        assert_eq!(out, b"keep".to_vec());
    }
}
