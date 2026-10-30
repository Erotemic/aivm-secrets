//! The fixed refusals: the only answer the agent sees when a request is refused.
use super::*;

/// Every public refusal reason of the proxy.
#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
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
