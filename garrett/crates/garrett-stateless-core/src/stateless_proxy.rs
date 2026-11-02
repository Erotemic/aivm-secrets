//! The connection loop and per-request controller of the
//! `garrett-stateless-v1` mTLS reverse proxy (`docs/garrett-stateless-v1.md`
//! section 11).
//!
//! The native shell completes the TLS handshake, then calls [`connection`]
//! with the peer thumbprint of that handshake and supplies only socket reads
//! and writes, the clock, diagnostics and the three steps of a provider
//! exchange ([`Channel`], [`Origin`]). Everything else is decided here: how
//! the guest's bytes are framed, which surrogate a request presents, whether
//! it opens for this connection's peer, which configured route its
//! authenticated `prv` selects, whether the static operation policy
//! (`stateless_policy`) permits the request's operation, the exact upstream
//! bytes (`proxy_http::encode_upstream`), the destination they go to (the
//! route's own [`Destination`]), the order of the exchange ([`exchange`]) and
//! the released reply (`proxy_controller::release`).
//!
//! Credential-bearing egress is closed: the upstream bytes reach the native
//! shell only inside an [`Egress`], which only [`serve`] can build (its fields
//! are private) and only after an acknowledged admission. [`exchange`] shows
//! the shell the egress's destination to connect to, and hands it the egress
//! itself, which [`Origin::transmit`] consumes, only if that connection was
//! authenticated.

use crate::credential_use::Authentication;
use crate::proxy_connect;
use crate::proxy_controller::{
    code_of, frame, release, remainder, stopped, Framed, Served, Stage, Tunnel,
};
use crate::proxy_http::{
    count_named, encode_upstream, first_named, reflection_forms, refusal, Code, DenyRule, Field,
    Request, MAX_HEAD,
};
use crate::stateless::{self, Acceptance, Rejection, SurrogateClaims, SurrogateOpener};
use crate::stateless_policy::{operation_of, OperationPolicy};

/// Where a route's requests go, and who must answer there.
#[cfg_attr(feature = "derive", derive(Debug, Clone, PartialEq, Eq))]
pub struct Destination {
    /// The provider's server name: the upstream `Host`, and the name the
    /// server's TLS certificate must carry.
    pub host: Vec<u8>,
    /// The transport address to connect to (a name or an IP literal).
    pub address: Vec<u8>,
    pub port: u16,
    /// The PEM trust anchors the server's certificate must chain to; empty
    /// for the default web roots.
    pub trust: Vec<u8>,
}

/// One configured provider route: the provider, its destination, its deny
/// rules and how the credential is presented. The destination is part of the
/// route, so whatever selects the route selects where the credential goes.
pub struct Route {
    pub provider: Vec<u8>,
    pub destination: Destination,
    pub rules: Vec<DenyRule>,
    pub authentication: Authentication,
}

/// Whether no two routes serve the same provider, so a provider names one
/// destination. The proxy refuses a configuration that fails this.
pub fn routes_valid(routes: &[Route]) -> bool {
    let mut index = 0;
    while index < routes.len() {
        if route_of(routes, &routes[index].provider) != index {
            return false;
        }
        index += 1;
    }
    true
}

/// A copy of a destination.
pub fn copy_destination(destination: &Destination) -> Destination {
    Destination {
        host: destination.host.to_vec(),
        address: destination.address.to_vec(),
        port: destination.port,
        trust: destination.trust.to_vec(),
    }
}

/// One credential-bearing upstream request: the destination of the route
/// and the exact bytes. Only [`serve`] makes one, after an acknowledged
/// admission.
pub struct Egress {
    destination: Destination,
    wire: Vec<u8>,
}

/// Where an egress goes.
pub fn egress_destination(egress: &Egress) -> &Destination {
    &egress.destination
}

/// The exact bytes an egress sends.
pub fn egress_wire(egress: &Egress) -> &[u8] {
    &egress.wire
}

/// One read of the provider's answer.
pub enum Received {
    /// More bytes of the answer.
    Bytes(Vec<u8>),
    /// The provider closed the connection: the answer is complete.
    End,
    /// The read failed or the deadline passed.
    Failed,
}

/// What the native shell provides for one request.
pub trait Origin {
    /// A surrogate was refused, for diagnostics; the reason only.
    fn rejected(&mut self, rejection: &Rejection);
    /// Record an admitted request before anything is sent; false refuses.
    fn admitted(&mut self, claims: &SurrogateClaims, route: usize) -> bool;
    /// Open a connection to `destination`'s address and port and complete a
    /// TLS handshake in which the server proves the name `host` under the
    /// trust anchors `trust`. False if any of that failed, and then nothing
    /// was sent.
    fn connect(&mut self, destination: &Destination) -> bool;
    /// Write the egress's bytes, once, on the connection `connect` just
    /// opened. True if all of them were written; false if the write failed,
    /// in which case any prefix of them may have been sent and the provider
    /// may or may not have acted.
    fn transmit(&mut self, egress: Egress) -> bool;
    /// The next read of the provider's answer on that connection.
    fn receive(&mut self) -> Received;
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
/// other state and performs no effect of its own, so every replica with the same keys
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
    let admitted = match stateless::authenticate(opener, &token, acceptance, peer, now) {
        Ok(admitted) => admitted,
        Err(rejection) => return Decision::Unauthorized(Some(rejection)),
    };
    // The destination is the authenticated provider's route, never a
    // request value.
    let index = route_of(routes, &admitted.verified.claims.provider);
    if index >= routes.len() {
        return Decision::Refused(Code::UnknownOrigin);
    }
    // The operation policy sees the claims and the operation, never the
    // credential, which is not decrypted for a refused operation.
    if !policy.permits(&admitted.verified.claims, &operation_of(request)) {
        return Decision::Refused(Code::Denied);
    }
    let opened = match stateless::decrypt(opener, admitted) {
        Ok(opened) => opened,
        Err(rejection) => return Decision::Unauthorized(Some(rejection)),
    };
    let route = &routes[index];
    let mut wire = Vec::new();
    match encode_upstream(
        &mut wire,
        request,
        &route.destination.host,
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

/// The most answer bytes [`exchange`] collects for a request limit.
pub fn answer_limit(limit: usize) -> usize {
    limit + MAX_HEAD + 64
}

/// Collect the provider's answer until it closes, within `bound` bytes.
pub fn collect<O: Origin>(origin: &mut O, bound: usize) -> Result<Vec<u8>, Code> {
    let mut answer = Vec::new();
    loop {
        match origin.receive() {
            Received::End => return Ok(answer),
            Received::Failed => return Err(Code::OutcomeUnknown),
            Received::Bytes(bytes) => {
                answer.extend_from_slice(&bytes);
                if answer.len() > bound {
                    return Err(Code::TooLarge);
                }
            }
        }
    }
}

/// The provider exchange of one egress: connect to its destination, and only
/// if the server authenticated as that destination, send its bytes once and
/// collect the answer. No retry.
pub fn exchange<O: Origin>(origin: &mut O, egress: Egress, limit: usize) -> Result<Vec<u8>, Code> {
    if !origin.connect(egress_destination(&egress)) {
        return Err(Code::Unreachable);
    }
    if !origin.transmit(egress) {
        return Err(Code::OutcomeUnknown);
    }
    collect(origin, answer_limit(limit))
}

/// One request on an authenticated connection, end to end: [`decide`], then,
/// only for a dispatch, the admission record, the one exchange with the
/// route's destination and the release.
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
    let egress = Egress {
        destination: copy_destination(&routes[index].destination),
        wire,
    };
    match exchange(origin, egress, limit) {
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
    use crate::stateless::{Admitted, Verified};
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
        fn unseal(&self, _admitted: &Admitted) -> Result<Vec<u8>, Rejection> {
            Ok(b"REAL-SECRET".to_vec())
        }
    }

    /// A simulated provider connection: what happened, in order.
    #[derive(Debug, PartialEq)]
    enum Effect {
        Connected(Vec<u8>),
        Sent(Vec<u8>, Vec<u8>),
    }

    struct Recorder {
        effects: Vec<Effect>,
        sent: Vec<(Vec<u8>, Vec<u8>)>,
        rejected: usize,
        admit: bool,
        authenticated: bool,
        written: bool,
        reads: Vec<Received>,
        connected: Option<Vec<u8>>,
        completions: usize,
    }
    impl Default for Recorder {
        fn default() -> Self {
            Recorder {
                effects: Vec::new(),
                sent: Vec::new(),
                rejected: 0,
                admit: true,
                authenticated: true,
                written: true,
                reads: Vec::new(),
                connected: None,
                completions: 0,
            }
        }
    }
    impl Recorder {
        fn answering(answer: &[u8]) -> Self {
            Recorder {
                reads: vec![Received::Bytes(answer.to_vec()), Received::End],
                ..Default::default()
            }
        }
    }
    impl Origin for Recorder {
        fn rejected(&mut self, _rejection: &Rejection) {
            self.rejected += 1;
        }
        fn admitted(&mut self, _claims: &SurrogateClaims, _route: usize) -> bool {
            self.admit
        }
        fn connect(&mut self, destination: &Destination) -> bool {
            self.effects
                .push(Effect::Connected(destination.address.clone()));
            if self.authenticated {
                self.connected = Some(destination.host.clone());
            }
            self.authenticated
        }
        fn transmit(&mut self, egress: Egress) -> bool {
            let host = egress_destination(&egress).host.clone();
            assert_eq!(
                self.connected.as_ref(),
                Some(&host),
                "sent before connecting"
            );
            self.effects
                .push(Effect::Sent(host.clone(), egress_wire(&egress).to_vec()));
            self.sent.push((host, egress_wire(&egress).to_vec()));
            self.written
        }
        fn receive(&mut self) -> Received {
            if self.reads.is_empty() {
                Received::End
            } else {
                self.reads.remove(0)
            }
        }
        fn completed(&mut self, _status: u16) -> bool {
            self.completions += 1;
            true
        }
    }

    fn destination(host: &[u8], address: &[u8]) -> Destination {
        Destination {
            host: host.to_vec(),
            address: address.to_vec(),
            port: 443,
            trust: Vec::new(),
        }
    }

    fn routes() -> Vec<Route> {
        vec![
            Route {
                provider: b"other".to_vec(),
                destination: destination(b"other.test", b"10.0.0.1"),
                rules: Vec::new(),
                authentication: Authentication::ApiKey,
            },
            Route {
                provider: b"api".to_vec(),
                destination: destination(b"api.test", b"10.0.0.2"),
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
        run_origin(policy, raw, peer, Recorder::answering(answer))
    }

    fn run_origin<P: OperationPolicy>(
        policy: &P,
        raw: &[u8],
        peer: &[u8],
        mut origin: Recorder,
    ) -> (Served, Recorder) {
        let request = match parse_request(raw, AUTHORITY, 4096) {
            Ok(Some(parsed)) => parsed.request,
            _ => panic!("parse"),
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
        let (host, wire) = &origin.sent[0];
        assert_eq!(host, b"api.test");
        let text = String::from_utf8(wire.clone()).unwrap();
        assert!(text.starts_with("GET /user?x=1 HTTP/1.1\r\nHost: api.test\r\n"));
        assert!(text.contains("Authorization: Bearer REAL-SECRET\r\n"));
        assert!(!text.contains("GOOD"));
        // The connection went to the authenticated provider's destination,
        // before the one write, and nowhere else.
        assert_eq!(
            origin.effects,
            vec![
                Effect::Connected(b"10.0.0.2".to_vec()),
                Effect::Sent(b"api.test".to_vec(), wire.clone()),
            ]
        );
    }

    /// A destination belongs to its route: reordering the configuration
    /// moves the destination with the provider, never to another provider.
    #[test]
    fn the_destination_moves_with_its_route() {
        let raw = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let mut reordered = routes();
        reordered.reverse();
        let request = match parse_request(raw, AUTHORITY, 4096) {
            Ok(Some(parsed)) => parsed.request,
            _ => panic!("parse"),
        };
        let mut origin = Recorder::answering(OK);
        serve(
            &Keys,
            &Unrestricted,
            &mut origin,
            &request,
            &reordered,
            &acceptance(),
            b"PEER",
            150,
            4096,
        );
        assert_eq!(origin.effects[0], Effect::Connected(b"10.0.0.2".to_vec()));
        assert_eq!(origin.sent[0].0, b"api.test");
    }

    /// A surrogate the proxy accepts, for a provider it has no route for, is
    /// refused before anything is decrypted, admitted or connected.
    #[test]
    fn a_provider_without_a_route_is_refused() {
        let raw = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let request = match parse_request(raw, AUTHORITY, 4096) {
            Ok(Some(parsed)) => parsed.request,
            _ => panic!("parse"),
        };
        let mut only_other = routes();
        only_other.truncate(1);
        let mut origin = Recorder::answering(OK);
        let served = serve(
            &Keys,
            &Unrestricted,
            &mut origin,
            &request,
            &only_other,
            &acceptance(),
            b"PEER",
            150,
            4096,
        );
        assert!(matches!(served.code, Code::UnknownOrigin));
        assert!(origin.effects.is_empty());
    }

    #[test]
    fn duplicate_providers_are_not_a_valid_catalogue() {
        assert!(routes_valid(&routes()));
        assert!(routes_valid(&[]));
        let mut twice = routes();
        twice.push(Route {
            provider: b"api".to_vec(),
            destination: destination(b"evil.test", b"10.6.6.6"),
            rules: Vec::new(),
            authentication: Authentication::Bearer,
        });
        assert!(!routes_valid(&twice));
    }

    /// A server that fails to authenticate as the destination is never sent
    /// the credential; a failed write is never retried.
    #[test]
    fn the_credential_is_written_only_after_authentication_and_once() {
        let raw = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let impostor = Recorder {
            authenticated: false,
            ..Recorder::answering(OK)
        };
        let (served, origin) = run_origin(&Unrestricted, raw, b"PEER", impostor);
        assert!(matches!(served.stage, Stage::Failed));
        assert!(matches!(served.code, Code::Unreachable));
        assert!(origin.sent.is_empty());
        assert!(!String::from_utf8_lossy(&served.reply).contains("REAL-SECRET"));

        // A write that failed part-way: the provider may hold any prefix of
        // the request, so its answer is not read and nothing is completed.
        let broken = Recorder {
            written: false,
            ..Recorder::answering(OK)
        };
        let (served, origin) = run_origin(&Unrestricted, raw, b"PEER", broken);
        assert!(matches!(served.stage, Stage::Failed));
        assert!(matches!(served.code, Code::OutcomeUnknown));
        assert_eq!(origin.sent.len(), 1, "no retry after a failed write");
        assert_eq!(
            origin.reads.len(),
            2,
            "no answer is read after a failed write"
        );
        assert_eq!(origin.completions, 0, "a failed write is never completed");
        assert!(!String::from_utf8_lossy(&served.reply).contains("REAL-SECRET"));
    }

    /// An unacknowledged admission record stops the request before it
    /// connects anywhere.
    #[test]
    fn unadmitted_requests_never_connect() {
        let raw = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let refusing = Recorder {
            admit: false,
            ..Recorder::answering(OK)
        };
        let (served, origin) = run_origin(&Unrestricted, raw, b"PEER", refusing);
        assert!(matches!(served.stage, Stage::Refused));
        assert!(origin.effects.is_empty());
    }

    /// The answer is collected across reads, within the bound, and a failed
    /// read is an unknown outcome.
    #[test]
    fn the_answer_is_bounded_and_failures_are_unknown() {
        let raw = b"GET / HTTP/1.1\r\nHost: proxy.test:8443\r\nAuthorization: Bearer GOOD\r\n\r\n";
        let split = Recorder {
            reads: vec![
                Received::Bytes(OK[..10].to_vec()),
                Received::Bytes(OK[10..].to_vec()),
                Received::End,
            ],
            ..Default::default()
        };
        let (served, _) = run_origin(&Unrestricted, raw, b"PEER", split);
        assert!(matches!(served.stage, Stage::Completed));
        let failing = Recorder {
            reads: vec![Received::Bytes(OK[..10].to_vec()), Received::Failed],
            ..Default::default()
        };
        let (served, _) = run_origin(&Unrestricted, raw, b"PEER", failing);
        assert!(matches!(served.code, Code::OutcomeUnknown));
        let flood = Recorder {
            reads: vec![
                Received::Bytes(vec![b'x'; answer_limit(4096)]),
                Received::Bytes(vec![b'x']),
            ],
            ..Default::default()
        };
        let (served, _) = run_origin(&Unrestricted, raw, b"PEER", flood);
        assert!(matches!(served.code, Code::TooLarge));
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
        fn connect(&mut self, destination: &Destination) -> bool {
            self.origin.connect(destination)
        }
        fn transmit(&mut self, egress: Egress) -> bool {
            self.origin.transmit(egress)
        }
        fn receive(&mut self) -> Received {
            self.origin.receive()
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
                reads: vec![
                    Received::Bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec()),
                    Received::End,
                ],
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
