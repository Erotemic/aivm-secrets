//! The library in one page, as a test so it cannot drift: an operator mints
//! a surrogate for an agent's certificate, then the proxy's core decides
//! requests that present it. No network and no files; `tests/workflow.rs`
//! runs the same protocol over real TLS, with an OAuth login.
use garrett_stateless::broker::{mint_with, now_seconds};
use garrett_stateless::keys::BrokerKeys;
use garrett_stateless::pki::{self, Leaf};
use garrett_stateless::tls::PeerIdentity;
use garrett_stateless::token::ClaimCopy;
use garrett_stateless::{Acceptance, IssuePolicy, Rejection};
use garrett_stateless_core::credential_use::Authentication;
use garrett_stateless_core::proxy_http::{parse_request, Request};
use garrett_stateless_core::stateless_policy::Unrestricted;
use garrett_stateless_core::stateless_proxy::{decide, Decision, Route};

const ISSUER: &str = "https://broker.example";
const AUDIENCE: &str = "https://proxy.example";
/// A synthetic provider token; never a real one.
const CREDENTIAL: &str = "synthetic_PROVIDER_token_0123456789";

/// A client certificate from a throwaway development CA, as DER.
fn certificate(ca: &pki::Issued, name: &str) -> Vec<u8> {
    let leaf = pki::issue(
        &ca.certificate,
        &ca.key,
        Leaf::Client { name, uri: None },
        1,
    )
    .unwrap();
    let mut pem = leaf.certificate.as_bytes();
    let der = rustls_pemfile::certs(&mut pem).next().unwrap().unwrap();
    der.to_vec()
}

/// The agent's request as the proxy parses it off the connection.
fn request(surrogate: &str) -> Request {
    let raw = format!(
        "GET /user HTTP/1.1\r\nHost: proxy.example\r\nAuthorization: Bearer {surrogate}\r\n\r\n"
    );
    parse_request(raw.as_bytes(), b"proxy.example", 1 << 16)
        .ok()
        .flatten()
        .unwrap()
        .request
}

#[test]
fn mint_then_decide() {
    // The broker's keys. The proxy gets only the verification and opening
    // half (`export_proxy`), as a validated key set.
    let keys = BrokerKeys::generate(ISSUER, "k1").unwrap();
    let opener = keys.export_proxy().key_set().unwrap();

    let ca = pki::create_ca("example CA", 1).unwrap();
    let agent = certificate(&ca, "agent");
    let other = certificate(&ca, "other");
    let now = now_seconds();

    // 1. Issuance: a surrogate bound to the agent's certificate, carrying the
    //    credential encrypted. `mint_with` runs the extracted `stateless::issue`.
    let policy = IssuePolicy {
        issuer: ISSUER.as_bytes().to_vec(),
        audience: AUDIENCE.as_bytes().to_vec(),
        providers: vec![b"api".to_vec()],
        max_lifetime: 3600,
        max_renew: 86400,
    };
    let issued = mint_with(
        &keys,
        &policy,
        "api",
        CREDENTIAL.as_bytes(),
        &agent,
        &ClaimCopy::default(),
        600,
        now,
    )
    .unwrap();
    assert!(
        !issued.token.contains(CREDENTIAL),
        "the surrogate does not show the credential"
    );

    // 2. The proxy's static configuration: one route per provider, and what
    //    it accepts.
    let routes = [Route {
        provider: b"api".to_vec(),
        host: b"api.example".to_vec(),
        rules: Vec::new(),
        authentication: Authentication::Bearer,
    }];
    let acceptance = Acceptance {
        audiences: vec![AUDIENCE.as_bytes().to_vec()],
        providers: vec![b"api".to_vec()],
        max_lifetime: 3600,
        skew: 60,
    };

    // 3. The decision for a request on a connection whose TLS peer is the
    //    agent: authenticate, choose the signed provider's route, authorize
    //    (Garrett's proxy: `Unrestricted`), decrypt, encode.
    let peer = PeerIdentity::from_der(&agent).unwrap().thumbprint;
    let presented = request(&issued.token);
    match decide(
        &opener,
        &Unrestricted,
        &presented,
        &routes,
        &acceptance,
        peer.as_bytes(),
        now,
    ) {
        Decision::Dispatch(dispatch) => {
            let _ = dispatch; // its route and bytes are private to `serve`
        }
        _ => panic!("the agent's own surrogate is dispatched"),
    }

    // 4. The same surrogate on another certificate's connection is refused
    //    before anything is decrypted.
    let thief = PeerIdentity::from_der(&other).unwrap().thumbprint;
    assert!(matches!(
        decide(
            &opener,
            &Unrestricted,
            &presented,
            &routes,
            &acceptance,
            thief.as_bytes(),
            now
        ),
        Decision::Unauthorized(Some(Rejection::WrongCertificate))
    ));

    // 5. A request with no surrogate is refused too.
    let bare = parse_request(
        b"GET /user HTTP/1.1\r\nHost: proxy.example\r\n\r\n",
        b"proxy.example",
        1 << 16,
    )
    .ok()
    .flatten()
    .unwrap()
    .request;
    assert!(matches!(
        decide(
            &opener,
            &Unrestricted,
            &bare,
            &routes,
            &acceptance,
            peer.as_bytes(),
            now
        ),
        Decision::Unauthorized(None)
    ));
}
