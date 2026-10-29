//! Request framing on a proxy connection and the release of an upstream
//! answer to the agent; `stateless_proxy` sequences them.

use crate::proxy_http::{
    guest_response, parse_request, parse_response, refusal, Code, Form, Parsed, Refusal, Request,
    MAX_HEAD,
};

/// Where a request stopped, for the audit.
pub enum Stage {
    /// Refused before anything was sent upstream.
    Refused,
    /// Sent upstream; the exchange or the release failed.
    Failed,
    /// Released to the guest.
    Completed,
}

pub struct Served {
    /// The exact bytes for the guest.
    pub reply: Vec<u8>,
    /// Whether the tunnel stays open for another request.
    pub keep: bool,
    pub stage: Stage,
    /// The refusal code, when the request did not complete.
    pub code: Code,
    /// The provider status of a completed request (0 otherwise).
    pub status: u16,
}

/// What to do with the bytes a guest has sent on a tunnel so far.
pub enum Framed {
    /// Read more bytes.
    More,
    /// Refuse with this fixed response and close the tunnel.
    Refuse(Code),
    /// One complete request, and how many buffered bytes it used.
    Request(Parsed),
}

/// The raw bytes one request may occupy before it is complete: the body
/// limit with room for chunk framing, plus the head. This also bounds how
/// often an incomplete body is re-parsed.
pub fn raw_limit(request_limit: usize) -> usize {
    2 * request_limit + MAX_HEAD + 65536
}

/// The next step for `buffer`: refuse if it is past `raw_limit`, otherwise
/// what the strict parser says.
pub fn frame(buffer: &[u8], host: &[u8], request_limit: usize) -> Framed {
    if buffer.len() > raw_limit(request_limit) {
        return Framed::Refuse(Code::TooLarge);
    }
    match parse_request(buffer, host, request_limit) {
        Err(refused) => Framed::Refuse(code_of(&refused)),
        Ok(None) => Framed::More,
        Ok(Some(parsed)) => Framed::Request(parsed),
    }
}

/// The buffered bytes a tunnel holds after one step, and whether it goes on.
pub struct Tunnel {
    pub buffer: Vec<u8>,
    pub open: bool,
}

/// The bytes of `buffer` from `used` on.
pub fn remainder(buffer: &[u8], used: usize) -> Vec<u8> {
    let mut rest = Vec::new();
    if used < buffer.len() {
        rest.extend_from_slice(&buffer[used..]);
    }
    rest
}

pub fn code_of(refused: &Refusal) -> Code {
    match refused {
        Refusal::InvalidRequest => Code::InvalidRequest,
        Refusal::TooLarge => Code::TooLarge,
        Refusal::Denied => Code::Denied,
        Refusal::InvalidCredential => Code::CredentialSource,
        Refusal::UpstreamResponse => Code::OutcomeUnknown,
        Refusal::Reflected => Code::Reflected,
    }
}

pub fn stopped(code: Code, stage: Stage) -> Served {
    let reply = refusal(&code);
    Served {
        reply,
        keep: false,
        stage,
        code,
        status: 0,
    }
}

pub fn is_head(method: &[u8]) -> bool {
    let head: &[u8] = b"HEAD";
    method == head
}

/// Release a raw upstream answer to the guest, or refuse it.
pub fn release(raw: &[u8], request: &Request, forms: &[Form], limit: usize) -> Served {
    let head = is_head(&request.method);
    let response = match parse_response(raw, head, limit) {
        Ok(response) => response,
        Err(Refusal::TooLarge) => return stopped(Code::TooLarge, Stage::Failed),
        Err(_) => return stopped(Code::OutcomeUnknown, Stage::Failed),
    };
    let mut out = Vec::new();
    match guest_response(&mut out, &response, forms, request.keep_alive, head) {
        Ok(()) => Served {
            reply: out,
            keep: request.keep_alive,
            stage: Stage::Completed,
            code: Code::OutcomeUnknown,
            status: response.status,
        },
        Err(_) => stopped(Code::Reflected, Stage::Failed),
    }
}
