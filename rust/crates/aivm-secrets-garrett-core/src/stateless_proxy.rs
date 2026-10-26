//! The per-request controller of the `garrett-stateless-v1` mTLS reverse
//! proxy (`docs/garrett-stateless-v1.md` section 11).
//!
//! The native shell supplies the parsed request, the peer thumbprint from
//! the completed handshake, the clock, the key-set adapter and the socket
//! exchange ([`Origin`]). Everything else is decided here, from those
//! inputs only: which surrogate the request presents, whether it opens for
//! this peer, which configured route its authenticated `prv` selects, the
//! exact upstream bytes (`proxy_http::encode_upstream`) and the released
//! reply (`proxy_controller::release`).

use crate::credential_use::Authentication;
use crate::proxy_connect;
use crate::proxy_controller::{code_of, release, stopped, Served, Stage};
use crate::proxy_http::{
    count_named, encode_upstream, first_named, reflection_forms, Code, DenyRule, Field, Request,
};
use crate::stateless::{self, Acceptance, Rejection, SurrogateClaims, SurrogateOpener};

/// One configured provider destination.
pub struct Route {
    pub provider: Vec<u8>,
    /// The upstream `Host` (also the name its TLS certificate must carry).
    pub host: Vec<u8>,
    pub rules: Vec<DenyRule>,
    pub authentication: Authentication,
}

/// What the native shell provides for one request.
pub trait Origin {
    /// A surrogate was refused, for diagnostics; the reason only.
    fn rejected(&mut self, rejection: &Rejection);
    /// Record an admitted request before anything is sent; false refuses.
    fn admitted(&mut self, claims: &SurrogateClaims, route: usize) -> bool;
    /// Send `wire` to the pinned destination of route `route` and return
    /// everything it answered before closing, or the refusal that applies.
    fn exchange(&mut self, route: usize, wire: &[u8]) -> Result<Vec<u8>, Code>;
    /// Record a completed request before its reply is released; false
    /// withholds the reply.
    fn completed(&mut self, status: u16) -> bool;
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

/// One request on an authenticated connection, end to end.
#[allow(clippy::too_many_arguments)]
pub fn serve<V: SurrogateOpener, O: Origin>(
    opener: &V,
    origin: &mut O,
    request: &Request,
    routes: &[Route],
    acceptance: &Acceptance,
    peer: &[u8],
    now: i64,
    limit: usize,
) -> Served {
    let token = match surrogate_of(&request.fields) {
        Some(token) => token,
        None => {
            origin.rejected(&Rejection::Malformed);
            return unauthorized_served();
        }
    };
    let opened = match stateless::open(opener, &token, acceptance, peer, now) {
        Ok(opened) => opened,
        Err(rejection) => {
            origin.rejected(&rejection);
            return unauthorized_served();
        }
    };
    // The destination is the authenticated provider's route, never a
    // request value.
    let index = route_of(routes, &opened.claims.provider);
    if index >= routes.len() {
        return stopped(Code::UnknownOrigin, Stage::Refused);
    }
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
        Ok(()) => (),
        Err(refusal) => return stopped(code_of(&refusal), Stage::Refused),
    }
    // Fail closed: no acknowledged admission record, no egress.
    if !origin.admitted(&opened.claims, index) {
        return stopped(Code::InternalError, Stage::Refused);
    }
    let forms = reflection_forms(&opened.credential);
    let sent: &[u8] = &wire;
    match origin.exchange(index, sent) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_http::parse_request;
    use crate::stateless::Verified;

    const AUTHORITY: &[u8] = b"proxy.test:8443";

    struct Keys;
    impl SurrogateOpener for Keys {
        fn verify(&self, token: &[u8]) -> Result<Verified, Rejection> {
            if token != b"GOOD" {
                return Err(Rejection::BadSignature);
            }
            Ok(Verified {
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
        fn exchange(&mut self, route: usize, wire: &[u8]) -> Result<Vec<u8>, Code> {
            self.sent.push((route, wire.to_vec()));
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

    #[test]
    fn reflected_credential_is_withheld() {
        let raw = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let echo = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nREAL-SECRET";
        let (served, _) = run(raw, b"PEER", echo);
        assert!(matches!(served.stage, Stage::Failed));
        assert!(!String::from_utf8_lossy(&served.reply).contains("REAL-SECRET"));
    }
}
