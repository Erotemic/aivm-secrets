//! The provider's response: parse it, re-frame it for the agent, and refuse it when it reflects the credential.
use super::*;

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
