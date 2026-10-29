//! The connection loop and per-request controller of the
//! `garrett-stateless-v1` mTLS reverse proxy (`docs/garrett-stateless-v1.md`
//! section 11).
//!
//! The native shell completes the TLS handshake, then calls [`connection`]
//! with the peer thumbprint of that handshake and supplies only socket reads
//! and writes, the clock, diagnostics and the upstream exchange
//! ([`Channel`], [`Origin`]). Everything else is decided here: how the
//! guest's bytes are framed, which surrogate a request presents, whether it
//! opens for this connection's peer, which configured route its
//! authenticated `prv` selects, whether the static operation policy
//! (`stateless_policy`) permits the request's operation, the exact upstream bytes
//! (`proxy_http::encode_upstream`) and the released reply
//! (`proxy_controller::release`).
//!
//! Credential-bearing egress is closed: the upstream bytes reach the native
//! shell only inside an [`Egress`], which only [`serve`] can build (its fields
//! are private) and only after an acknowledged admission, and which
//! [`Origin::exchange`] consumes.

use crate::credential_use::Authentication;
use crate::proxy_connect;
use crate::proxy_controller::{
    code_of, frame, release, remainder, stopped, Framed, Served, Stage, Tunnel,
};
use crate::proxy_http::{
    count_named, encode_upstream, first_named, reflection_forms, refusal, Code, DenyRule, Field,
    Request,
};
use crate::stateless::{self, Acceptance, Rejection, SurrogateClaims, SurrogateOpener};
use crate::stateless_policy::{operation_of, OperationPolicy};

/// One configured provider destination.
pub struct Route {
    pub provider: Vec<u8>,
    /// The upstream `Host` (also the name its TLS certificate must carry).
    pub host: Vec<u8>,
    pub rules: Vec<DenyRule>,
    pub authentication: Authentication,
}

/// One credential-bearing upstream request: the route and the exact bytes.
/// Only [`serve`] makes one, after an acknowledged admission.
pub struct Egress {
    route: usize,
    wire: Vec<u8>,
}

/// The route an egress is for.
pub fn egress_route(egress: &Egress) -> usize {
    egress.route
}

/// The exact bytes an egress sends.
pub fn egress_wire(egress: &Egress) -> &[u8] {
    &egress.wire
}

/// What the native shell provides for one request.
pub trait Origin {
    /// A surrogate was refused, for diagnostics; the reason only.
    fn rejected(&mut self, rejection: &Rejection);
    /// Record an admitted request before anything is sent; false refuses.
    fn admitted(&mut self, claims: &SurrogateClaims, route: usize) -> bool;
    /// Send the egress bytes, once, to the pinned destination of its route
    /// and return everything it answered before closing, or the refusal
    /// that applies.
    fn exchange(&mut self, egress: Egress) -> Result<Vec<u8>, Code>;
    /// Record a completed request before its reply is released; false
    /// withholds the reply.
    fn completed(&mut self, status: u16) -> bool;
}

/// What the native shell provides for one authenticated connection.
pub trait Channel: Origin {
    /// True once a partly received request has taken too long.
    fn overdue(&mut self) -> bool;
    /// The next bytes from the guest; `None` at end of stream or on error.
    fn read(&mut self) -> Option<Vec<u8>>;
    /// Write `bytes` to the guest; false on error.
    fn send(&mut self, bytes: &[u8]) -> bool;
    /// Audit a framing refusal before it is sent.
    fn refused(&mut self, code: &Code);
    /// Audit a request that did not complete.
    fn stopped(&mut self, code: &Code);
    /// A request is about to be served (its method, for diagnostics); the
    /// clock, read once per request.
    fn begin(&mut self, request: &Request) -> i64;
    /// Restart the request deadline after a served request.
    fn restart(&mut self);
}

/// The surrogate one `Authorization` value presents: `Bearer T`, `token T`
/// or `Basic base64(USER:T)`.
pub fn surrogate_value(value: &[u8]) -> Option<Vec<u8>> {
    let token: &[u8] = b"token ";
    if proxy_connect::scheme_is(value, token) {
        return Some(value[6..].to_vec());
    }
    proxy_connect::presented(value)
}

/// The surrogate of exactly one `Authorization` field.
pub fn surrogate_of(fields: &[Field]) -> Option<Vec<u8>> {
    if count_named(fields, b"authorization") != 1 {
        return None;
    }
    let index = first_named(fields, b"authorization");
    if index >= fields.len() {
        return None;
    }
    surrogate_value(&fields[index].value)
}

pub fn provides(route: &Route, provider: &[u8]) -> bool {
    let own: &[u8] = &route.provider;
    own == provider
}

/// Index of the first route for `provider` (or `routes.len()`).
pub fn route_of(routes: &[Route], provider: &[u8]) -> usize {
    let mut index = 0;
    while index < routes.len() && !provides(&routes[index], provider) {
        index += 1;
    }
    index
}

/// The fixed answer to a request whose surrogate is missing or refused.
pub fn unauthorized() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 401 Unauthorized\r\n");
    out.extend_from_slice(
        b"WWW-Authenticate: Bearer realm=\"garrett-stateless\", error=\"invalid_token\"\r\n",
    );
    out.extend_from_slice(b"Content-Type: application/json\r\nContent-Length: 26\r\n");
    out.extend_from_slice(b"Connection: close\r\n\r\n{\"error\":\"invalid_token\"}\n");
    out
}

/// The refused request: the fixed `401`, nothing admitted or sent.
pub fn unauthorized_served() -> Served {
    Served {
        reply: unauthorized(),
        keep: false,
        stage: Stage::Refused,
        code: Code::Unauthenticated,
        status: 0,
    }
}

/// A decided dispatch: the route, the exact credential-bearing bytes and the
/// opened surrogate. Its fields are private, so only this module reads them.
pub struct Dispatch {
    route: usize,
    wire: Vec<u8>,
    opened: stateless::Opened,
}

/// What one request is authorized to do.
// Unboxed: Aeneas models `Box` as the identity, so it would buy nothing.
#[allow(clippy::large_enum_variant)]
pub enum Decision {
    /// No usable surrogate (`None`), or why the opener refused it.
    Unauthorized(Option<Rejection>),
    /// A fixed refusal before any egress.
    Refused(Code),
    /// Send these exact bytes to this route, for this opened surrogate.
    Dispatch(Dispatch),
}

/// The authorization decision for one request, from the keys (through
/// `opener`), the authenticated peer, the request, the clock and the
/// static routes, operation policy and acceptance policy alone. It reads no
/// other state and performs no effect, so every replica with the same keys
/// and configuration decides alike.
#[allow(clippy::too_many_arguments)]
pub fn decide<V: SurrogateOpener, P: OperationPolicy>(
    opener: &V,
    policy: &P,
    request: &Request,
    routes: &[Route],
    acceptance: &Acceptance,
    peer: &[u8],
    now: i64,
) -> Decision {
    let token = match surrogate_of(&request.fields) {
        Some(token) => token,
        None => return Decision::Unauthorized(None),
    };
    let verified = match stateless::authenticate(opener, &token, acceptance, peer, now) {
        Ok(verified) => verified,
        Err(rejection) => return Decision::Unauthorized(Some(rejection)),
    };
    // The destination is the authenticated provider's route, never a
    // request value.
    let index = route_of(routes, &verified.claims.provider);
    if index >= routes.len() {
        return Decision::Refused(Code::UnknownOrigin);
    }
    // The operation policy sees the claims and the operation, never the
    // credential, which is not decrypted for a refused operation.
    if !policy.permits(&verified.claims, &operation_of(request)) {
        return Decision::Refused(Code::Denied);
    }
    let opened = match stateless::decrypt(opener, verified) {
        Ok(opened) => opened,
        Err(rejection) => return Decision::Unauthorized(Some(rejection)),
    };
    let route = &routes[index];
    let mut wire = Vec::new();
    match encode_upstream(
        &mut wire,
        request,
        &route.host,
        &route.rules,
        &opened.credential,
        &route.authentication,
    ) {
        Ok(()) => Decision::Dispatch(Dispatch {
            route: index,
            wire,
            opened,
        }),
        Err(refusal) => Decision::Refused(code_of(&refusal)),
    }
}

/// One request on an authenticated connection, end to end: [`decide`], then,
/// only for a dispatch, the admission record, the one exchange and the
/// release.
#[allow(clippy::too_many_arguments)]
pub fn serve<V: SurrogateOpener, P: OperationPolicy, O: Origin>(
    opener: &V,
    policy: &P,
    origin: &mut O,
    request: &Request,
    routes: &[Route],
    acceptance: &Acceptance,
    peer: &[u8],
    now: i64,
    limit: usize,
) -> Served {
    let (index, wire, opened) = match decide(opener, policy, request, routes, acceptance, peer, now)
    {
        Decision::Unauthorized(rejection) => {
            match rejection {
                Some(rejection) => origin.rejected(&rejection),
                None => origin.rejected(&Rejection::Malformed),
            }
            return unauthorized_served();
        }
        Decision::Refused(code) => return stopped(code, Stage::Refused),
        Decision::Dispatch(dispatch) => (dispatch.route, dispatch.wire, dispatch.opened),
    };
    // Fail closed: no acknowledged admission record, no egress.
    if !origin.admitted(&opened.claims, index) {
        return stopped(Code::InternalError, Stage::Refused);
    }
    let forms = reflection_forms(&opened.credential);
    match origin.exchange(Egress { route: index, wire }) {
        Ok(raw) => {
            let served = release(&raw, request, &forms, limit);
            match served.stage {
                Stage::Completed => {
                    if origin.completed(served.status) {
                        served
                    } else {
                        stopped(Code::OutcomeUnknown, Stage::Failed)
                    }
                }
                _ => served,
            }
        }
        Err(code) => stopped(code, Stage::Failed),
    }
}

/// One step of an authenticated connection: give up on an overdue partial
/// request, refuse what the strict framing refuses, read more, or serve
/// exactly the parsed request for this connection's `peer` and keep only the
/// bytes after it.
// `len` rather than `is_empty`: Aeneas models only the former.
#[allow(clippy::too_many_arguments, clippy::len_zero)]
pub fn connection_step<V: SurrogateOpener, P: OperationPolicy, C: Channel>(
    opener: &V,
    policy: &P,
    channel: &mut C,
    buffer: Vec<u8>,
    routes: &[Route],
    acceptance: &Acceptance,
    authority: &[u8],
    peer: &[u8],
    limit: usize,
) -> Tunnel {
    if buffer.len() != 0 && channel.overdue() {
        return Tunnel {
            buffer,
            open: false,
        };
    }
    match frame(&buffer, authority, limit) {
        Framed::Refuse(code) => {
            channel.refused(&code);
            let _ = channel.send(&refusal(&code));
            Tunnel {
                buffer,
                open: false,
            }
        }
        Framed::More => match channel.read() {
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
            let now = channel.begin(&parsed.request);
            let served = serve(
                opener,
                policy,
                channel,
                &parsed.request,
                routes,
                acceptance,
                peer,
                now,
                limit,
            );
            match served.stage {
                Stage::Completed => (),
                _ => channel.stopped(&served.code),
            }
            channel.restart();
            let sent = channel.send(&served.reply);
            Tunnel {
                buffer: rest,
                open: sent && served.keep,
            }
        }
    }
}

/// A whole authenticated connection, for the `peer` its handshake verified:
/// steps until one closes it.
#[allow(clippy::too_many_arguments)]
pub fn connection<V: SurrogateOpener, P: OperationPolicy, C: Channel>(
    opener: &V,
    policy: &P,
    channel: &mut C,
    routes: &[Route],
    acceptance: &Acceptance,
    authority: &[u8],
    peer: &[u8],
    limit: usize,
) {
    let mut state = Tunnel {
        buffer: Vec::new(),
        open: true,
    };
    while state.open {
        state = connection_step(
            opener,
            policy,
            channel,
            state.buffer,
            routes,
            acceptance,
            authority,
            peer,
            limit,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_http::parse_request;
    use crate::stateless::Verified;
    use crate::stateless_policy::{ReadOnly, Resource, Unrestricted};

    const AUTHORITY: &[u8] = b"proxy.test:8443";

    struct Keys;
    impl SurrogateOpener for Keys {
        fn verify(&self, token: &[u8]) -> Result<Verified, Rejection> {
            if token != b"GOOD" {
                return Err(Rejection::BadSignature);
            }
            Ok(Verified {
                key: 0,
                key_issuer: b"iss".to_vec(),
                claims: SurrogateClaims {
                    issuer: b"iss".to_vec(),
                    audience: b"aud".to_vec(),
                    subject: b"agent".to_vec(),
                    token_id: b"j".to_vec(),
                    provider: b"api".to_vec(),
                    certificate: b"PEER".to_vec(),
                    issued_at: 100,
                    expires_at: 200,
                    renew_until: 300,
                },
                aad: Vec::new(),
                sealed: Vec::new(),
            })
        }
        fn unseal(&self, _verified: &Verified) -> Result<Vec<u8>, Rejection> {
            Ok(b"REAL-SECRET".to_vec())
        }
    }

    #[derive(Default)]
    struct Recorder {
        sent: Vec<(usize, Vec<u8>)>,
        rejected: usize,
        answer: Vec<u8>,
    }
    impl Origin for Recorder {
        fn rejected(&mut self, _rejection: &Rejection) {
            self.rejected += 1;
        }
        fn admitted(&mut self, _claims: &SurrogateClaims, _route: usize) -> bool {
            true
        }
        fn exchange(&mut self, egress: Egress) -> Result<Vec<u8>, Code> {
            self.sent
                .push((egress_route(&egress), egress_wire(&egress).to_vec()));
            Ok(self.answer.clone())
        }
        fn completed(&mut self, _status: u16) -> bool {
            true
        }
    }

    fn routes() -> Vec<Route> {
        vec![
            Route {
                provider: b"other".to_vec(),
                host: b"other.test".to_vec(),
                rules: Vec::new(),
                authentication: Authentication::ApiKey,
            },
            Route {
                provider: b"api".to_vec(),
                host: b"api.test".to_vec(),
                rules: Vec::new(),
                authentication: Authentication::Bearer,
            },
        ]
    }

    fn acceptance() -> Acceptance {
        Acceptance {
            audiences: vec![b"aud".to_vec()],
            providers: vec![b"api".to_vec(), b"other".to_vec()],
            max_lifetime: 3600,
            skew: 0,
        }
    }

    fn run(raw: &[u8], peer: &[u8], answer: &[u8]) -> (Served, Recorder) {
        run_with(&Unrestricted, raw, peer, answer)
    }

    fn run_with<P: OperationPolicy>(
        policy: &P,
        raw: &[u8],
        peer: &[u8],
        answer: &[u8],
    ) -> (Served, Recorder) {
        let request = match parse_request(raw, AUTHORITY, 4096) {
            Ok(Some(parsed)) => parsed.request,
            _ => panic!("parse"),
        };
        let mut origin = Recorder {
            answer: answer.to_vec(),
            ..Default::default()
        };
        let served = serve(
            &Keys,
            policy,
            &mut origin,
            &request,
            &routes(),
            &acceptance(),
            peer,
            150,
            4096,
        );
        (served, origin)
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

    #[test]
    fn substitutes_on_the_authenticated_route() {
        let raw = b"GET /user?x=1 HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let (served, origin) = run(raw, b"PEER", OK);
        assert!(matches!(served.stage, Stage::Completed));
        assert_eq!(origin.sent.len(), 1);
        let (route, wire) = &origin.sent[0];
        assert_eq!(*route, 1);
        let text = String::from_utf8(wire.clone()).unwrap();
        assert!(text.starts_with("GET /user?x=1 HTTP/1.1\r\nHost: api.test\r\n"));
        assert!(text.contains("Authorization: Bearer REAL-SECRET\r\n"));
        assert!(!text.contains("GOOD"));
    }

    #[test]
    fn stock_token_and_basic_schemes() {
        for header in ["token GOOD", "Basic eC1hY2Nlc3MtdG9rZW46R09PRA=="] {
            let raw = format!(
                "GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: {header}\r\n\r\n"
            );
            let (served, origin) = run(raw.as_bytes(), b"PEER", OK);
            assert!(matches!(served.stage, Stage::Completed), "{header}");
            assert_eq!(origin.sent.len(), 1);
        }
    }

    #[test]
    fn refusals_send_nothing() {
        let wrong_peer =
            b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let (served, origin) = run(wrong_peer, b"OTHER", OK);
        assert_eq!(served.reply, unauthorized());
        assert!(origin.sent.is_empty());
        assert_eq!(origin.rejected, 1);
        let forged =
            b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer BAD\r\n\r\n";
        let (served, origin) = run(forged, b"PEER", OK);
        assert_eq!(served.reply, unauthorized());
        assert!(origin.sent.is_empty());
        let missing = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\n\r\n";
        let (_, origin) = run(missing, b"PEER", OK);
        assert!(origin.sent.is_empty());
        let twice = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let (_, origin) = run(twice, b"PEER", OK);
        assert!(origin.sent.is_empty());
    }

    /// A guest that sends `input` in two reads, over one authenticated connection.
    struct Guest {
        reads: Vec<Vec<u8>>,
        written: Vec<u8>,
        origin: Recorder,
        stopped: usize,
    }
    impl Origin for Guest {
        fn rejected(&mut self, rejection: &Rejection) {
            self.origin.rejected(rejection)
        }
        fn admitted(&mut self, claims: &SurrogateClaims, route: usize) -> bool {
            self.origin.admitted(claims, route)
        }
        fn exchange(&mut self, egress: Egress) -> Result<Vec<u8>, Code> {
            self.origin.exchange(egress)
        }
        fn completed(&mut self, status: u16) -> bool {
            self.origin.completed(status)
        }
    }
    impl Channel for Guest {
        fn overdue(&mut self) -> bool {
            false
        }
        fn read(&mut self) -> Option<Vec<u8>> {
            if self.reads.is_empty() {
                None
            } else {
                Some(self.reads.remove(0))
            }
        }
        fn send(&mut self, bytes: &[u8]) -> bool {
            self.written.extend_from_slice(bytes);
            true
        }
        fn refused(&mut self, _code: &Code) {}
        fn stopped(&mut self, _code: &Code) {
            self.stopped += 1;
        }
        fn begin(&mut self, _request: &Request) -> i64 {
            150
        }
        fn restart(&mut self) {}
    }

    #[test]
    fn a_connection_serves_each_request_for_its_peer() {
        let one = b"GET /a HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let two = b"GET /b HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer BAD\r\n\r\n";
        let mut input = one.to_vec();
        input.extend_from_slice(two);
        let mut guest = Guest {
            reads: vec![input[..20].to_vec(), input[20..].to_vec()],
            written: Vec::new(),
            origin: Recorder {
                answer: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec(),
                ..Default::default()
            },
            stopped: 0,
        };
        connection(
            &Keys,
            &Unrestricted,
            &mut guest,
            &routes(),
            &acceptance(),
            AUTHORITY,
            b"PEER",
            4096,
        );
        assert_eq!(
            guest.origin.sent.len(),
            1,
            "only the admitted request goes upstream"
        );
        assert_eq!(guest.origin.rejected, 1);
        assert_eq!(guest.stopped, 1);
        let written = String::from_utf8(guest.written).unwrap();
        assert!(written.starts_with("HTTP/1.1 200 OK"));
        assert!(written.contains("invalid_token"));
    }

    #[test]
    fn reflected_credential_is_withheld() {
        let raw = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let echo = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nREAL-SECRET";
        let (served, _) = run(raw, b"PEER", echo);
        assert!(matches!(served.stage, Stage::Failed));
        assert!(!String::from_utf8_lossy(&served.reply).contains("REAL-SECRET"));
    }

    /// One surrogate through the two policies: the read-only proxy refuses,
    /// before any admission or egress, what Garrett's proxy forwards.
    #[test]
    fn the_read_only_policy_refuses_before_egress() {
        let read_only = ReadOnly {
            resources: vec![Resource {
                provider: b"api".to_vec(),
                method: Vec::new(),
                path: b"/user".to_vec(),
            }],
        };
        let allowed =
            b"GET /user HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        for policy_run in [
            run_with(&Unrestricted, allowed, b"PEER", OK),
            run_with(&read_only, allowed, b"PEER", OK),
        ] {
            assert!(matches!(policy_run.0.stage, Stage::Completed));
            assert_eq!(policy_run.1.sent.len(), 1);
        }
        let changed: [&[u8]; 4] = [
            b"DELETE /user HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n",
            b"GET /admin HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n",
            b"POST /user HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\nContent-Length: 2\r\n\r\n{}",
            b"GET /user/x HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n",
        ];
        for raw in changed {
            let (served, origin) = run_with(&Unrestricted, raw, b"PEER", OK);
            assert!(matches!(served.stage, Stage::Completed));
            assert_eq!(origin.sent.len(), 1);
            let (served, origin) = run_with(&read_only, raw, b"PEER", OK);
            assert!(matches!(served.stage, Stage::Refused));
            assert!(matches!(served.code, Code::Denied));
            assert!(origin.sent.is_empty());
        }
    }
}
