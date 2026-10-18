//! Complete provider HTTP framing; route/TLS selection and JSON serialization
//! remain adapters. Credentials are borrowed and copied only into the chosen
//! authentication line in the caller's zeroizing buffer.
use crate::{credential_use::Authentication, http_auth, http_request};

pub const MAX_BODY: usize = 2 * 1024 * 1024;

pub struct Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}
pub struct Head {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub host: Vec<u8>,
    pub port: u16,
    pub accept: Vec<u8>,
    pub headers: Vec<Header>,
}
pub enum EncodingDenial {
    InvalidRequest,
    InvalidCredential,
}

pub fn ascii_lower(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' {
        byte + 32
    } else {
        byte
    }
}
pub fn ascii_prefix(name: &[u8], prefix: &[u8]) -> bool {
    if name.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if ascii_lower(name[i]) != ascii_lower(prefix[i]) {
            return false;
        }
        i += 1;
    }
    true
}
pub fn ascii_equal(name: &[u8], other: &[u8]) -> bool {
    name.len() == other.len() && ascii_prefix(name, other)
}
pub fn reserved_name(name: &[u8]) -> bool {
    ascii_equal(name, b"accept")
        || ascii_equal(name, b"accept-encoding")
        || ascii_equal(name, b"authorization")
        || ascii_equal(name, b"connection")
        || ascii_equal(name, b"content-encoding")
        || ascii_equal(name, b"content-length")
        || ascii_equal(name, b"content-type")
        || ascii_equal(name, b"cookie")
        || ascii_equal(name, b"expect")
        || ascii_equal(name, b"forwarded")
        || ascii_equal(name, b"host")
        || ascii_equal(name, b"keep-alive")
        || ascii_equal(name, b"proxy-authorization")
        || ascii_equal(name, b"proxy-connection")
        || ascii_equal(name, b"te")
        || ascii_equal(name, b"trailer")
        || ascii_equal(name, b"transfer-encoding")
        || ascii_equal(name, b"upgrade")
        || ascii_equal(name, b"user-agent")
        || ascii_equal(name, b"via")
        || ascii_equal(name, b"x-api-key")
        || ascii_prefix(name, b"proxy-")
        || ascii_prefix(name, b"sec-")
        || ascii_prefix(name, b"x-forwarded-")
}
pub fn alphanumeric(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'0' && byte <= b'9')
}
#[allow(clippy::len_zero)]
pub fn valid_name(name: &[u8]) -> bool {
    if name.len() == 0 || name.len() > 64 {
        return false;
    }
    let mut i = 0;
    while i < name.len() {
        if !alphanumeric(name[i]) && (i == 0 || name[i] != b'-') {
            return false;
        }
        i += 1;
    }
    !reserved_name(name)
}
#[allow(clippy::len_zero)]
pub fn valid_value(value: &[u8]) -> bool {
    if value.len() == 0 || value.len() > 256 {
        return false;
    }
    if value[0] == b' ' || value[value.len() - 1] == b' ' {
        return false;
    }
    for byte in value {
        if *byte < b' ' || *byte > b'~' {
            return false;
        }
    }
    true
}
pub fn valid_header(header: &Header) -> bool {
    valid_name(&header.name) && valid_value(&header.value)
}
pub fn unique_before(headers: &[Header], end: usize, name: &[u8]) -> bool {
    if end > headers.len() {
        return false;
    }
    let mut j = 0;
    while j < end {
        if ascii_equal(&headers[j].name, name) {
            return false;
        }
        j += 1;
    }
    true
}
pub fn valid_headers(headers: &[Header]) -> bool {
    if headers.len() > 9 {
        return false;
    }
    let mut i = 0;
    while i < headers.len() {
        if !valid_header(&headers[i]) || !unique_before(headers, i, &headers[i].name) {
            return false;
        }
        i += 1;
    }
    true
}
#[allow(clippy::len_zero)]
pub fn valid_host(host: &[u8]) -> bool {
    if host.len() == 0 || host.len() > 253 {
        return false;
    }
    for byte in host {
        if !alphanumeric(*byte) && *byte != b'.' && *byte != b'-' {
            return false;
        }
    }
    true
}
#[allow(clippy::len_zero)]
pub fn valid_accept(accept: &[u8]) -> bool {
    if accept.len() == 0 || accept.len() > 96 {
        return false;
    }
    for byte in accept {
        if *byte < b'!' || *byte > b'~' {
            return false;
        }
    }
    true
}
pub fn valid_start(head: &Head) -> bool {
    valid_host(&head.host)
        && head.port != 0
        && valid_accept(&head.accept)
        && http_request::valid_method(&head.method)
        && http_request::valid_target(&head.target)
}

// At most twenty recursive calls on the supported 64-bit target. Decimal
// formatting stays concrete in the extracted encoder, including body length.
pub fn append_decimal(output: &mut Vec<u8>, value: usize) {
    if value >= 10 {
        append_decimal(output, value / 10);
    }
    output.push(b'0' + (value % 10) as u8);
}

pub fn valid_body(body: Option<&[u8]>) -> bool {
    match body {
        None => true,
        Some(bytes) => bytes.len() <= MAX_BODY,
    }
}
pub fn append_headers(output: &mut Vec<u8>, headers: &[Header]) {
    for header in headers {
        output.extend_from_slice(&header.name);
        output.extend_from_slice(b": ");
        output.extend_from_slice(&header.value);
        output.extend_from_slice(b"\r\n");
    }
}

pub fn append_request(
    output: &mut Vec<u8>,
    head: &Head,
    secret: &[u8],
    authentication: &Authentication,
    body: Option<&[u8]>,
) -> Result<(), EncodingDenial> {
    // Validate the entire message before touching the caller's buffer.
    if !valid_start(head) {
        return Err(EncodingDenial::InvalidRequest);
    }
    if !http_auth::valid_credential(secret) {
        return Err(EncodingDenial::InvalidCredential);
    }
    if !valid_body(body) {
        return Err(EncodingDenial::InvalidRequest);
    }
    if !valid_headers(&head.headers) {
        return Err(EncodingDenial::InvalidRequest);
    }
    http_request::append_line(output, &head.method, &head.target)
        .map_err(|_| EncodingDenial::InvalidRequest)?;
    output.extend_from_slice(b"Host: ");
    output.extend_from_slice(&head.host);
    output.extend_from_slice(b":");
    append_decimal(output, head.port as usize);
    output.extend_from_slice(b"\r\nAccept: ");
    output.extend_from_slice(&head.accept);
    output.extend_from_slice(
        b"\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\n",
    );
    append_headers(output, &head.headers);
    http_auth::append_header(output, secret, authentication)
        .map_err(|_| EncodingDenial::InvalidCredential)?;
    if let Some(bytes) = body {
        output.extend_from_slice(b"Content-Type: application/json\r\nContent-Length: ");
        append_decimal(output, bytes.len());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    if let Some(bytes) = body {
        output.extend_from_slice(bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn head() -> Head {
        Head {
            method: b"POST".to_vec(),
            target: b"/v1/items?state=open".to_vec(),
            host: b"api.example.org".to_vec(),
            port: 9443,
            accept: b"application/json".to_vec(),
            headers: vec![Header {
                name: b"X-Request-ID".to_vec(),
                value: b"job-7".to_vec(),
            }],
        }
    }
    #[test]
    fn entire_request_has_exact_framing_and_binary_body_length() {
        for (authentication, auth) in [
            (
                Authentication::Bearer,
                b"Authorization: Bearer TOKEN\r\n".as_slice(),
            ),
            (Authentication::ApiKey, b"X-API-Key: TOKEN\r\n".as_slice()),
        ] {
            let mut output = b"existing".to_vec();
            let body = b"{}\r\nGET /in-body HTTP/1.1\r\n\0";
            assert!(
                append_request(&mut output, &head(), b"TOKEN", &authentication, Some(body)).is_ok()
            );
            let expected = [
                b"existingPOST /v1/items?state=open HTTP/1.1\r\nHost: api.example.org:9443\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\nX-Request-ID: job-7\r\n".as_slice(),
                auth, format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(), body,
            ].concat();
            assert_eq!(output, expected);
        }
        let mut request = head();
        request.method = b"GET".to_vec();
        request.headers.clear();
        let mut output = Vec::new();
        assert!(append_request(
            &mut output,
            &request,
            b"TOKEN",
            &Authentication::Bearer,
            None
        )
        .is_ok());
        assert_eq!(output, b"GET /v1/items?state=open HTTP/1.1\r\nHost: api.example.org:9443\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: aivm-secrets/1\r\nConnection: close\r\nAuthorization: Bearer TOKEN\r\n\r\n");
    }
    fn refused(head: Head, secret: &[u8], body: Option<&[u8]>) {
        let mut output = vec![0, 255, 13, 10, 65];
        let before = output.clone();
        assert!(append_request(&mut output, &head, secret, &Authentication::Bearer, body).is_err());
        assert_eq!(output, before);
    }
    #[test]
    fn header_overrides_and_injections_cannot_modify_the_buffer() {
        for name in [
            "Host",
            "HOST",
            "hOsT",
            "AUTHORIZATION",
            "X-API-Key",
            "Content-Length",
            "Transfer-Encoding",
            "Accept",
            "Content-Type",
            "Connection",
            "Cookie",
            "Expect",
            "TE",
            "Trailer",
            "Upgrade",
            "Via",
            "User-Agent",
            "Sec-Fetch-Site",
            "PrOxY-Anything",
            "X-FoRwArDeD-For",
            "-bad",
            "X: bad",
            "X\r\nEvil",
            "",
        ] {
            let mut h = head();
            h.headers[0].name = name.as_bytes().to_vec();
            refused(h, b"TOKEN", None);
        }
        for value in [
            b"".as_slice(),
            b" leading",
            b"trailing ",
            b"ok\r\nHost: evil",
            b"\t",
            &[255],
        ] {
            let mut h = head();
            h.headers[0].value = value.to_vec();
            refused(h, b"TOKEN", None);
        }
        let mut h = head();
        h.headers.push(Header {
            name: b"x-request-id".to_vec(),
            value: b"different".to_vec(),
        });
        refused(h, b"TOKEN", None);
        for host in [
            b"".as_slice(),
            b"api.example.org\r\nHost: evil",
            b"evil:443",
            &[255],
        ] {
            let mut h = head();
            h.host = host.to_vec();
            refused(h, b"TOKEN", None);
        }
        let mut h = head();
        h.port = 0;
        refused(h, b"TOKEN", None);
        let mut h = head();
        h.accept = b"application/json\r\nX: y".to_vec();
        refused(h, b"TOKEN", None);
        let mut h = head();
        h.target = b"//evil/".to_vec();
        refused(h, b"TOKEN", None);
        refused(head(), b"TOKEN\r\nX: y", None);
        refused(head(), b"", None);
    }
    #[test]
    fn decimal_and_message_boundaries_match_standard_formatting() {
        for value in [0, 1, 9, 10, 99, 100, 65535, MAX_BODY, usize::MAX] {
            let mut output = b"prefix".to_vec();
            append_decimal(&mut output, value);
            assert_eq!(output, format!("prefix{value}").into_bytes());
        }
        let body = vec![0; MAX_BODY];
        let mut output = Vec::new();
        assert!(append_request(
            &mut output,
            &head(),
            b"TOKEN",
            &Authentication::Bearer,
            Some(&body)
        )
        .is_ok());
        assert_eq!(&output[output.len() - body.len()..], &body);
        refused(head(), b"TOKEN", Some(&vec![0; MAX_BODY + 1]));
        let mut h = head();
        h.headers = (0..9)
            .map(|i| Header {
                name: format!("X-{i}").into_bytes(),
                value: b"v".to_vec(),
            })
            .collect();
        assert!(valid_headers(&h.headers));
        h.headers.push(Header {
            name: b"X-9".to_vec(),
            value: b"v".to_vec(),
        });
        refused(h, b"TOKEN", None);
    }
    #[test]
    fn folded_comparison_agrees_with_standard_ascii_rules() {
        for a in 0..=255u8 {
            assert_eq!(ascii_lower(a), a.to_ascii_lowercase());
            for b in 0..=255u8 {
                assert_eq!(ascii_equal(&[a], &[b]), [a].eq_ignore_ascii_case(&[b]));
            }
        }
    }
}
