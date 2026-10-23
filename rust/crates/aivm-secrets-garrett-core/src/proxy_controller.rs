//! The per-request controller of the credential-substitution proxy
//! (PROXY-NATIVE-01): every decision `garrett-proxy` used to sequence
//! itself. The native shell supplies only the session clock, the audit
//! write and the socket exchange, through [`Upstream`].

use crate::credential_use::Authentication;
use crate::proxy_http::{
    encode_upstream, guest_response, parse_request, parse_response, refusal, Code, DenyRule, Form,
    Parsed, Refusal, Request, MAX_HEAD,
};

/// What the native shell provides for one guest request.
pub trait Upstream {
    /// Whether the session is still current (not revoked, not expired).
    fn current(&mut self) -> bool;
    /// Record that a request was admitted, before anything is sent.
    fn admitted(&mut self);
    /// Send `wire` to the origin's pinned destination and return everything
    /// the origin answered before closing, or the refusal that applies.
    fn exchange(&mut self, wire: &[u8]) -> Result<Vec<u8>, Code>;
}

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

/// What the native shell provides for one guest tunnel.
pub trait Guest {
    /// True once a partly received request has taken too long.
    fn overdue(&mut self) -> bool;
    /// The next bytes from the guest; `None` at end of stream or on error.
    fn read(&mut self) -> Option<Vec<u8>>;
    /// Write `bytes` to the guest; false on error.
    fn send(&mut self, bytes: &[u8]) -> bool;
    /// Audit a refusal before it is sent.
    fn refused(&mut self, code: &Code);
    /// Serve one parsed request (through [`serve`]) and restart the deadline.
    fn serve(&mut self, request: &Request) -> Answer;
}

/// The guest reply for one request, and whether the tunnel stays open.
pub struct Answer {
    pub reply: Vec<u8>,
    pub keep: bool,
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

/// One step of a guest tunnel: give up on an overdue partial request, refuse
/// what [`frame`] refuses, read more, or serve exactly the parsed request and
/// keep only the bytes after it.
// `len` rather than `is_empty`: Aeneas models only the former.
#[allow(clippy::len_zero)]
pub fn step<G: Guest>(guest: &mut G, buffer: Vec<u8>, host: &[u8], request_limit: usize) -> Tunnel {
    if buffer.len() != 0 && guest.overdue() {
        return Tunnel {
            buffer,
            open: false,
        };
    }
    match frame(&buffer, host, request_limit) {
        Framed::Refuse(code) => {
            guest.refused(&code);
            let _ = guest.send(&refusal(&code));
            Tunnel {
                buffer,
                open: false,
            }
        }
        Framed::More => match guest.read() {
            None => Tunnel {
                buffer,
                open: false,
            },
            Some(bytes) => {
                if bytes.len() == 0 {
                    return Tunnel {
                        buffer,
                        open: false,
                    };
                }
                let mut grown = buffer;
                grown.extend_from_slice(&bytes);
                Tunnel {
                    buffer: grown,
                    open: true,
                }
            }
        },
        Framed::Request(parsed) => {
            let rest = remainder(&buffer, parsed.used);
            let answer = guest.serve(&parsed.request);
            let sent = guest.send(&answer.reply);
            Tunnel {
                buffer: rest,
                open: sent && answer.keep,
            }
        }
    }
}

/// A whole guest tunnel: steps until one closes it.
pub fn tunnel<G: Guest>(guest: &mut G, host: &[u8], request_limit: usize) {
    let mut state = Tunnel {
        buffer: Vec::new(),
        open: true,
    };
    while state.open {
        state = step(guest, state.buffer, host, request_limit);
    }
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

/// One accepted guest request, end to end.
#[allow(clippy::too_many_arguments)]
pub fn serve<U: Upstream>(
    io: &mut U,
    request: &Request,
    host: &[u8],
    rules: &[DenyRule],
    secret: &[u8],
    authentication: &Authentication,
    forms: &[Form],
    limit: usize,
) -> Served {
    if !io.current() {
        return stopped(Code::Revoked, Stage::Refused);
    }
    let mut wire = Vec::new();
    match encode_upstream(&mut wire, request, host, rules, secret, authentication) {
        Ok(()) => (),
        Err(refused) => return stopped(code_of(&refused), Stage::Refused),
    }
    io.admitted();
    let sent: &[u8] = &wire;
    match io.exchange(sent) {
        Ok(raw) => release(&raw, request, forms, limit),
        Err(code) => stopped(code, Stage::Failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_http::{parse_request, reflection_forms};

    /// Records every callback; answers with a fixed provider response.
    struct Mock {
        current: bool,
        calls: Vec<&'static str>,
        sent: Vec<Vec<u8>>,
        answer: fn() -> Result<Vec<u8>, Code>,
    }

    impl Upstream for Mock {
        fn current(&mut self) -> bool {
            self.calls.push("current");
            self.current
        }
        fn admitted(&mut self) {
            self.calls.push("admitted");
        }
        fn exchange(&mut self, wire: &[u8]) -> Result<Vec<u8>, Code> {
            self.calls.push("exchange");
            self.sent.push(wire.to_vec());
            (self.answer)()
        }
    }

    const HOST: &[u8] = b"api.example.org";
    const SECRET: &[u8] = b"SECRET-value";

    fn request(raw: &[u8]) -> Request {
        match parse_request(raw, HOST, 1024) {
            Ok(Some(parsed)) => parsed.request,
            _ => panic!("refused"),
        }
    }

    fn mock(current: bool, answer: fn() -> Result<Vec<u8>, Code>) -> Mock {
        Mock {
            current,
            calls: Vec::new(),
            sent: Vec::new(),
            answer,
        }
    }

    fn run(io: &mut Mock, request: &Request, rules: &[DenyRule]) -> Served {
        let forms = reflection_forms(SECRET);
        serve(
            io,
            request,
            HOST,
            rules,
            SECRET,
            &Authentication::Bearer,
            &forms,
            4096,
        )
    }

    /// Oracle: the composition `garrett-proxy` used before the controller
    /// was extracted (encode, exchange, parse, release).
    fn old_composition(request: &Request, answer: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut wire = Vec::new();
        assert!(encode_upstream(
            &mut wire,
            request,
            HOST,
            &[],
            SECRET,
            &Authentication::Bearer
        )
        .is_ok());
        let head = request.method == b"HEAD";
        let response = parse_response(answer, head, 4096).ok().expect("parsed");
        let mut out = Vec::new();
        let forms = reflection_forms(SECRET);
        assert!(guest_response(&mut out, &response, &forms, request.keep_alive, head).is_ok());
        (wire, out)
    }

    #[test]
    fn a_completed_request_matches_the_old_composition_byte_for_byte() {
        fn ok() -> Result<Vec<u8>, Code> {
            Ok(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
                    .to_vec(),
            )
        }
        let answer = ok().ok().expect("answer");
        for raw in [
            b"GET /v1/account HTTP/1.1\r\nHost: api.example.org\r\nAuthorization: token guest\r\n\r\n".as_slice(),
            b"HEAD /v1/account HTTP/1.1\r\nHost: api.example.org\r\nConnection: close\r\n\r\n",
            b"POST /v1/issues HTTP/1.1\r\nHost: api.example.org\r\nContent-Length: 2\r\n\r\nhi",
        ] {
            let request = request(raw);
            let mut io = mock(true, ok);
            let served = run(&mut io, &request, &[]);
            let (wire, out) = old_composition(&request, &answer);
            assert_eq!(io.calls, ["current", "admitted", "exchange"]);
            assert_eq!(io.sent, [wire]);
            assert_eq!(served.reply, out);
            assert!(matches!(served.stage, Stage::Completed));
            assert_eq!(served.keep, request.keep_alive);
            assert_eq!(served.status, 200);
        }
    }

    #[test]
    fn nothing_is_sent_when_not_current_or_refused() {
        let get = request(b"GET /v1/admin/x HTTP/1.1\r\nHost: api.example.org\r\n\r\n");
        let mut io = mock(false, || Ok(Vec::new()));
        let served = run(&mut io, &get, &[]);
        assert_eq!(io.calls, ["current"]);
        assert_eq!(served.reply, refusal(&Code::Revoked));
        assert!(matches!(served.stage, Stage::Refused) && !served.keep);

        let rules = [DenyRule {
            method: Vec::new(),
            path: b"/v1/admin/".to_vec(),
        }];
        let mut io = mock(true, || Ok(Vec::new()));
        let served = run(&mut io, &get, &rules);
        assert_eq!(io.calls, ["current"]);
        assert_eq!(served.reply, refusal(&Code::Denied));
        assert!(matches!(served.stage, Stage::Refused));
    }

    #[test]
    fn failed_exchanges_and_reflections_are_fixed_refusals() {
        let get = request(b"GET /v1/account HTTP/1.1\r\nHost: api.example.org\r\n\r\n");
        let cases: [(fn() -> Result<Vec<u8>, Code>, Code); 4] = [
            (|| Err(Code::Unreachable), Code::Unreachable),
            (|| Ok(b"garbage".to_vec()), Code::OutcomeUnknown),
            (
                || Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nSECRET-value".to_vec()),
                Code::Reflected,
            ),
            (
                || Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n".to_vec()),
                Code::TooLarge,
            ),
        ];
        for (answer, code) in cases {
            let mut io = mock(true, answer);
            let served = run(&mut io, &get, &[]);
            assert_eq!(io.calls, ["current", "admitted", "exchange"]);
            assert_eq!(served.reply, refusal(&code));
            assert!(matches!(served.stage, Stage::Failed) && !served.keep);
        }
    }

    /// A scripted guest: input chunks, a step budget for the deadline, and a
    /// log of every effect in order.
    struct Script {
        chunks: Vec<Vec<u8>>,
        overdue_after: usize,
        polls: usize,
        fail_send: bool,
        log: Vec<String>,
    }

    impl Guest for Script {
        fn overdue(&mut self) -> bool {
            self.polls += 1;
            self.polls > self.overdue_after
        }
        fn read(&mut self) -> Option<Vec<u8>> {
            if self.chunks.is_empty() {
                return None;
            }
            Some(self.chunks.remove(0))
        }
        fn send(&mut self, bytes: &[u8]) -> bool {
            self.log
                .push(format!("send {}", String::from_utf8_lossy(bytes)));
            !self.fail_send
        }
        fn refused(&mut self, code: &Code) {
            self.log.push(format!("refused {}", code_number(code)));
        }
        fn serve(&mut self, request: &Request) -> Answer {
            self.log.push(format!(
                "serve {} {} {}",
                String::from_utf8_lossy(&request.method),
                String::from_utf8_lossy(&request.target),
                request.body.len()
            ));
            self.polls = 0;
            Answer {
                reply: b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
                keep: request.keep_alive,
            }
        }
    }

    fn code_number(code: &Code) -> u8 {
        match code {
            Code::InvalidRequest => 0,
            Code::TooLarge => 1,
            Code::Denied => 2,
            Code::CredentialSource => 3,
            Code::OutcomeUnknown => 4,
            Code::Reflected => 5,
            _ => 9,
        }
    }

    /// The loop `garrett-proxy` ran natively before `tunnel` was extracted,
    /// over the same callbacks.
    fn legacy(guest: &mut Script, host: &[u8], limit: usize) {
        let mut buffer = Vec::new();
        loop {
            if buffer.len() != 0 && guest.overdue() {
                break;
            }
            match frame(&buffer, host, limit) {
                Framed::Refuse(code) => {
                    guest.refused(&code);
                    guest.send(&refusal(&code));
                    break;
                }
                Framed::More => match guest.read() {
                    Some(bytes) if !bytes.is_empty() => buffer.extend_from_slice(&bytes),
                    _ => break,
                },
                Framed::Request(parsed) => {
                    buffer.drain(..parsed.used);
                    let answer = guest.serve(&parsed.request);
                    if !guest.send(&answer.reply) || !answer.keep {
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn extracted_tunnel_matches_the_native_loop() {
        let get = b"GET /a HTTP/1.1\r\nHost: api.example.org\r\n\r\n".to_vec();
        let post =
            b"POST /b HTTP/1.1\r\nHost: api.example.org\r\nContent-Length: 3\r\n\r\nabc".to_vec();
        let chunked =
            b"POST /c HTTP/1.1\r\nHost: api.example.org\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"
                .to_vec();
        let close =
            b"GET /d HTTP/1.1\r\nHost: api.example.org\r\nConnection: close\r\n\r\n".to_vec();
        let other_host = b"GET /e HTTP/1.1\r\nHost: evil.example\r\n\r\n".to_vec();
        let garbage = b"NOT HTTP\r\n\r\n".to_vec();
        let pieces = [get, post, chunked, close, other_host, garbage];
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        let mut served = 0;
        for _ in 0..400 {
            let mut stream = Vec::new();
            for _ in 0..(1 + next(5)) {
                stream.extend_from_slice(&pieces[next(pieces.len() as u64) as usize]);
            }
            if next(4) == 0 {
                stream.truncate(next(stream.len() as u64) as usize);
            }
            let mut chunks = Vec::new();
            let mut at = 0;
            while at < stream.len() {
                let take = (1 + next(40) as usize).min(stream.len() - at);
                chunks.push(stream[at..at + take].to_vec());
                at += take;
            }
            if next(6) == 0 {
                chunks.push(Vec::new());
            }
            let overdue_after = 1 + next(200) as usize;
            let fail_send = next(10) == 0;
            let limit = [2usize, 64, 4096][next(3) as usize];
            let script = || Script {
                chunks: chunks.clone(),
                overdue_after,
                polls: 0,
                fail_send,
                log: Vec::new(),
            };
            let (mut old, mut new) = (script(), script());
            legacy(&mut old, HOST, limit);
            tunnel(&mut new, HOST, limit);
            assert_eq!(old.log, new.log);
            assert_eq!(old.chunks.len(), new.chunks.len());
            served += new
                .log
                .iter()
                .filter(|line| line.starts_with("serve"))
                .count();
        }
        assert!(served > 100);
    }
}
