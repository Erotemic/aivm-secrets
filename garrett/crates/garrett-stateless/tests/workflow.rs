//! End-to-end `garrett-stateless-v1` over real TLS, in one process:
//! development PKI, an OAuth login with PKCE (a synthetic token endpoint),
//! surrogate delivery, substitution through the proxy to a synthetic HTTPS
//! API, an independent proxy replica, renewal, and the refusals.
use garrett_stateless::agent::{Agent, Endpoint};
use garrett_stateless::broker::{Broker, TokenEndpoint, TokenResponse};
use garrett_stateless::config::{BrokerConfig, OAuthClient};
use garrett_stateless::error::{Error, Result};
use garrett_stateless::http;
use garrett_stateless::keys::BrokerKeys;
use garrett_stateless::login::pkce_challenge;
use garrett_stateless::pki::{self, Leaf};
use garrett_stateless::proxy::Proxy;
use garrett_stateless::tls::{self, ClientIdentity};
use rustls::{ServerConnection, StreamOwned};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CREDENTIAL: &str = "gho_SYNTHETIC0123456789abcdefREAL";

struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "garrett-stateless-{}",
            garrett_stateless::encoding::random_id().unwrap()
        ));
        std::fs::create_dir(&path).unwrap();
        Dir(path)
    }
    fn write(&self, name: &str, bytes: &[u8], private: bool) -> PathBuf {
        let path = self.0.join(name);
        if private {
            garrett_stateless::files::write_private(&path, bytes).unwrap();
        } else {
            std::fs::write(&path, bytes).unwrap();
        }
        path
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A synthetic OAuth provider: `/authorize` records the PKCE challenge and
/// redirects with a code; the token endpoint checks code and verifier.
#[derive(Default)]
struct SyntheticOAuth {
    issued: Mutex<Vec<(String, String, String)>>, // (code, challenge, redirect)
}
impl SyntheticOAuth {
    fn authorize(&self, url: &str) -> String {
        let query = url.split_once('?').unwrap().1;
        let params = http::parse_query(query).unwrap();
        let get = |k: &str| params.iter().find(|(n, _)| n == k).unwrap().1.clone();
        assert_eq!(get("code_challenge_method"), "S256");
        let code = garrett_stateless::encoding::random_id().unwrap();
        self.issued.lock().unwrap().push((
            code.clone(),
            get("code_challenge"),
            get("redirect_uri"),
        ));
        format!(
            "{}?{}",
            get("redirect_uri"),
            http::form(&[("code", &code), ("state", &get("state"))])
        )
    }
}
struct TokenStub(Arc<SyntheticOAuth>);
impl TokenEndpoint for TokenStub {
    fn exchange(&self, _provider: &OAuthClient, form: &str) -> Result<TokenResponse> {
        let params = http::parse_query(form).unwrap();
        let get = |k: &str| {
            params
                .iter()
                .find(|(n, _)| n == k)
                .map(|p| p.1.clone())
                .unwrap_or_default()
        };
        let mut issued = self.0.issued.lock().unwrap();
        let index = issued
            .iter()
            .position(|(code, _, _)| *code == get("code"))
            .ok_or(Error::Protocol("token_rejected"))?;
        let (_, challenge, redirect) = issued.remove(index);
        if pkce_challenge(&get("code_verifier")) != challenge || get("redirect_uri") != redirect {
            return Err(Error::Protocol("token_rejected"));
        }
        garrett_stateless::broker::token_response(
            200,
            format!(r#"{{"access_token":"{CREDENTIAL}","token_type":"bearer","scope":"read","refresh_token":"r-SECRET"}}"#).as_bytes(),
        )
    }
}

/// The synthetic protected API: records the Authorization it received and
/// answers with JSON (or, at `/echo`, reflects the credential).
fn api(certificate: &str, key: &str) -> (String, Arc<Mutex<Vec<String>>>) {
    let config = tls::server(certificate.as_bytes(), key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let mut stream = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), tcp);
            let Ok(request) = http::read_request(&mut stream) else {
                continue;
            };
            let auth = request.header("authorization").unwrap_or("").to_owned();
            log.lock()
                .unwrap()
                .push(format!("{} {} {}", request.method, request.path, auth));
            let body = if request.path == "/echo" {
                auth.clone()
            } else {
                format!(r#"{{"login":"octocat","path":"{}"}}"#, request.path)
            };
            let _ = stream.write_all(&http::response(
                200,
                "application/json",
                &[],
                body.as_bytes(),
            ));
            stream.conn.send_close_notify();
            let _ = stream.conn.complete_io(&mut stream.sock);
        }
    });
    (address, seen)
}

fn browser_get(ca: &[u8], url: &str, connect: &str) -> http::Response {
    let parsed =
        garrett_stateless::config::HttpsUrl::parse(url.split('?').next().unwrap()).unwrap();
    let target = format!(
        "{}{}",
        parsed.path,
        url.find('?').map(|i| &url[i..]).unwrap_or("")
    );
    let request = http::request_bytes("GET", &target, &parsed.authority(), &[], b"");
    let raw = http::exchange(
        tls::upstream_client(Some(ca)).unwrap(),
        connect,
        &parsed.host,
        &request,
        1 << 20,
    )
    .unwrap();
    http::parse_response(&raw, false, 1 << 20).unwrap()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_json(dir: &Dir, name: &str, text: String) -> PathBuf {
    dir.write(name, text.as_bytes(), false)
}

fn proxy_config(dir: &Dir, name: &str, api: &str, api_port: &str) -> PathBuf {
    write_json(
        dir,
        name,
        format!(
            r#"{{"schema":"garrett-stateless-v1/proxy","listen":"127.0.0.1:0","authority":"proxy.test:8443",
            "certificate":"server.pem","private_key":"server.key","client_ca":"ca.pem","keys":"proxy-keys.json",
            "audiences":["https://proxy.test"],"skew":0,
            "routes":[{{"provider":"api","host":"api.test","address":"{api}","port":{api_port},"ca_file":"ca.pem",
                       "authentication":"bearer","deny":[{{"method":"DELETE","path":"/"}}]}}]}}"#
        ),
    )
}

#[test]
fn stateless_workflow_end_to_end() {
    let dir = Dir::new();
    let ca = pki::create_ca("test CA", 2).unwrap();
    let names = vec![
        "broker.test".to_owned(),
        "proxy.test".to_owned(),
        "api.test".to_owned(),
    ];
    let server = pki::issue(&ca.certificate, &ca.key, Leaf::Server(&names), 2).unwrap();
    let agent_c = pki::issue(
        &ca.certificate,
        &ca.key,
        Leaf::Client {
            name: "agent",
            uri: Some("spiffe://test/agent"),
        },
        2,
    )
    .unwrap();
    let agent_d = pki::issue(
        &ca.certificate,
        &ca.key,
        Leaf::Client {
            name: "other",
            uri: None,
        },
        2,
    )
    .unwrap();
    dir.write("ca.pem", ca.certificate.as_bytes(), false);
    dir.write("server.pem", server.certificate.as_bytes(), false);
    dir.write("server.key", server.key.as_bytes(), true);
    let keys = BrokerKeys::generate("https://broker.test", "k1").unwrap();
    dir.write("broker-keys.json", &keys.to_json(), true);
    dir.write("proxy-keys.json", &keys.export_proxy().to_json(), true);
    write_json(
        &dir,
        "provider.json",
        r#"{"schema":"garrett-stateless-v1/provider","name":"api","authorization_url":"https://idp.test/authorize",
            "token_url":"https://idp.test/token","client_id":"client-1","scopes":["read","write"],"default_scope":"read"}"#
            .to_owned(),
    );
    let browser_port = free_port();
    let broker_path = write_json(
        &dir,
        "broker.json",
        format!(
            r#"{{"schema":"garrett-stateless-v1/broker","issuer":"https://broker.test","audience":"https://proxy.test",
            "replica":"a","agent_listen":"127.0.0.1:0","browser_listen":"127.0.0.1:{browser_port}",
            "public_url":"https://broker.test:{browser_port}/","certificate":"server.pem","private_key":"server.key",
            "agent_ca":"ca.pem","keys":"broker-keys.json","providers":["provider.json"]}}"#
        ),
    );
    let (api_address, seen) = api(&server.certificate, &server.key);
    let (api_host, api_port) = api_address.rsplit_once(':').unwrap();
    let proxy_path = proxy_config(&dir, "proxy.json", api_host, api_port);

    let oauth = Arc::new(SyntheticOAuth::default());
    let config = BrokerConfig::load(&broker_path).unwrap();
    let broker = Arc::new(
        Broker::new(
            config,
            BrokerKeys::load(&dir.0.join("broker-keys.json")).unwrap(),
            Box::new(TokenStub(oauth.clone())),
        )
        .unwrap(),
    );
    let running = broker.clone().serve().unwrap();
    let broker_endpoint = Endpoint::parse(
        "https://broker.test:9443",
        Some(&running.agent_address.to_string()),
    )
    .unwrap();
    let browser = running.browser_address.unwrap().to_string();

    let ca_pem = ca.certificate.as_bytes();
    let agent = |c: &pki::Issued| {
        Agent::new(
            ca_pem,
            ClientIdentity::Software {
                certificate: c.certificate.clone().into_bytes(),
                key: c.key.as_bytes().to_vec(),
            },
        )
        .unwrap()
    };
    let (agent_c_client, agent_d_client) = (agent(&agent_c), agent(&agent_d));

    // 1. The agent begins a login; the human opens the URL and approves.
    let started = agent_c_client
        .begin_login(&broker_endpoint, "api", None)
        .unwrap();
    assert!(agent_c_client
        .poll(&broker_endpoint, &started.login, 0)
        .unwrap()
        .is_none());
    let page = browser_get(ca_pem, &started.authorization_url, &browser);
    let html = String::from_utf8(page.body).unwrap();
    assert!(html.contains(&started.confirmation) && html.contains("spiffe://test/agent"));
    let href = html
        .split("href=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .replace("&amp;", "&");
    let callback = oauth.authorize(&href);
    // Another certificate cannot collect the login.
    let done = browser_get(ca_pem, &callback, &browser);
    assert_eq!(done.status, 200);
    assert!(matches!(
        agent_d_client.poll(&broker_endpoint, &started.login, 0),
        Err(Error::Protocol("wrong_certificate"))
    ));
    // A replayed callback is refused.
    assert_eq!(browser_get(ca_pem, &callback, &browser).status, 400);
    let issued = agent_c_client
        .wait_for_token(&broker_endpoint, &started.login, Duration::from_secs(5))
        .unwrap();
    assert!(!issued.token.contains(CREDENTIAL) && !issued.token.contains("r-SECRET"));
    // Collected once.
    assert!(agent_c_client
        .poll(&broker_endpoint, &started.login, 0)
        .is_err());

    // 2. Broker A goes away; proxy B has only keys and configuration.
    running.stop();
    drop(broker);
    let proxy_b = Arc::new(Proxy::from_file(&proxy_path).unwrap())
        .serve()
        .unwrap();
    let proxy_endpoint = |p: &garrett_stateless::proxy::RunningProxy| {
        Endpoint::parse("https://proxy.test:8443", Some(&p.address.to_string())).unwrap()
    };
    let response = agent_c_client
        .request(
            &proxy_endpoint(&proxy_b),
            &issued.token,
            "GET",
            "/user?x=1",
            &[],
            b"",
        )
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        seen.lock().unwrap().last().unwrap(),
        &format!("GET /user Bearer {CREDENTIAL}")
    );
    let body = agent_c_client
        .request(
            &proxy_endpoint(&proxy_b),
            &issued.token,
            "POST",
            "/repos",
            &[("Content-Type", "application/json")],
            b"{}",
        )
        .unwrap();
    assert_eq!(body.status, 200);

    // 3. A copied surrogate on another certificate: 401, nothing sent upstream.
    let before = seen.lock().unwrap().len();
    let stolen = agent_d_client
        .request(
            &proxy_endpoint(&proxy_b),
            &issued.token,
            "GET",
            "/user",
            &[],
            b"",
        )
        .unwrap();
    assert_eq!(stolen.status, 401);
    // A deny rule, a reflected credential, a forged token.
    assert_eq!(
        agent_c_client
            .request(
                &proxy_endpoint(&proxy_b),
                &issued.token,
                "DELETE",
                "/repo",
                &[],
                b""
            )
            .unwrap()
            .status,
        403
    );
    let mut forged = issued.token.clone().into_bytes();
    let n = forged.len() - 3;
    forged[n] = if forged[n] == b'A' { b'B' } else { b'A' };
    let forged = String::from_utf8(forged).unwrap();
    assert_eq!(
        agent_c_client
            .request(&proxy_endpoint(&proxy_b), &forged, "GET", "/user", &[], b"")
            .unwrap()
            .status,
        401
    );
    assert_eq!(seen.lock().unwrap().len(), before);
    let echo = agent_c_client
        .request(
            &proxy_endpoint(&proxy_b),
            &issued.token,
            "GET",
            "/echo",
            &[],
            b"",
        )
        .unwrap();
    assert_eq!(echo.status, 502);
    assert!(!String::from_utf8_lossy(&echo.body).contains(CREDENTIAL));

    // 4. An independent replica C accepts the same surrogate.
    let proxy_c = Arc::new(
        Proxy::from_file(&proxy_config(&dir, "proxy-c.json", api_host, api_port)).unwrap(),
    )
    .serve()
    .unwrap();
    assert_eq!(
        agent_c_client
            .request(
                &proxy_endpoint(&proxy_c),
                &issued.token,
                "GET",
                "/user",
                &[],
                b""
            )
            .unwrap()
            .status,
        200
    );
    proxy_b.stop();
    proxy_c.stop();

    // 5. Renewal on a fresh broker process keeps binding and credential.
    let broker2 = Arc::new(Broker::from_file(&broker_path).unwrap());
    let peer_c = tls::PeerIdentity::from_der(
        tls::certificates(agent_c.certificate.as_bytes()).unwrap()[0].as_ref(),
    )
    .unwrap();
    let peer_d = tls::PeerIdentity::from_der(
        tls::certificates(agent_d.certificate.as_bytes()).unwrap()[0].as_ref(),
    )
    .unwrap();
    let renewed = broker2.renew(&peer_c, &issued.token).unwrap();
    assert!(renewed.renew_until <= issued.renew_until);
    assert!(broker2.renew(&peer_d, &issued.token).is_err());
}

/// Direct provisioning in the strict profile: an API key minted by the
/// operator, with no OAuth client, browser listener, token endpoint or login
/// mailbox, and a proxy with no audit file. Renewal still works.
#[test]
fn strict_provisioned_workflow() {
    let dir = Dir::new();
    let ca = pki::create_ca("test CA", 2).unwrap();
    let names = vec![
        "broker.test".to_owned(),
        "proxy.test".to_owned(),
        "api.test".to_owned(),
    ];
    let server = pki::issue(&ca.certificate, &ca.key, Leaf::Server(&names), 2).unwrap();
    let agent_c = pki::issue(
        &ca.certificate,
        &ca.key,
        Leaf::Client {
            name: "agent",
            uri: None,
        },
        2,
    )
    .unwrap();
    dir.write("ca.pem", ca.certificate.as_bytes(), false);
    dir.write("server.pem", server.certificate.as_bytes(), false);
    dir.write("server.key", server.key.as_bytes(), true);
    let keys = BrokerKeys::generate("https://broker.test", "k1").unwrap();
    dir.write("broker-keys.json", &keys.to_json(), true);
    dir.write("proxy-keys.json", &keys.export_proxy().to_json(), true);
    write_json(
        &dir,
        "api-key.json",
        r#"{"schema":"garrett-stateless-v1/provider","name":"api","acquisition":"provisioned"}"#
            .to_owned(),
    );
    write_json(
        &dir,
        "oauth.json",
        r#"{"schema":"garrett-stateless-v1/provider","name":"idp","authorization_url":"https://idp.test/authorize",
            "token_url":"https://idp.test/token","client_id":"client-1","scopes":["read"],"default_scope":"read"}"#
            .to_owned(),
    );
    // A provisioned provider has no OAuth members.
    let with_oauth_member = write_json(
        &dir,
        "bad-provider.json",
        r#"{"schema":"garrett-stateless-v1/provider","name":"api","acquisition":"provisioned","client_id":"x"}"#
            .to_owned(),
    );
    assert!(garrett_stateless::config::ProviderConfig::load(&with_oauth_member).is_err());
    let broker_json = |providers: &str, extra: &str| {
        format!(
            r#"{{"schema":"garrett-stateless-v1/broker","issuer":"https://broker.test","audience":"https://proxy.test",
            "replica":"a","agent_listen":"127.0.0.1:0","certificate":"server.pem","private_key":"server.key",
            "agent_ca":"ca.pem","keys":"broker-keys.json","providers":[{providers}]{extra}}}"#
        )
    };
    let broker_path = write_json(
        &dir,
        "broker.json",
        broker_json(r#""api-key.json""#, r#","stateless":"strict""#),
    );
    // A strict broker refuses an OAuth provider; a browser endpoint needs one.
    for (name, providers, extra) in [
        (
            "strict-oauth.json",
            r#""api-key.json","oauth.json""#,
            r#","stateless":"strict","browser_listen":"127.0.0.1:0","public_url":"https://broker.test/""#,
        ),
        ("no-browser.json", r#""oauth.json""#, ""),
        (
            "stray-browser.json",
            r#""api-key.json""#,
            r#","browser_listen":"127.0.0.1:0","public_url":"https://broker.test/""#,
        ),
    ] {
        let path = write_json(&dir, name, broker_json(providers, extra));
        assert!(BrokerConfig::load(&path).is_err(), "{name}");
    }
    let (api_address, seen) = api(&server.certificate, &server.key);
    let (api_host, api_port) = api_address.rsplit_once(':').unwrap();
    let proxy_json = |extra: &str| {
        format!(
            r#"{{"schema":"garrett-stateless-v1/proxy","listen":"127.0.0.1:0","authority":"proxy.test:8443",
            "certificate":"server.pem","private_key":"server.key","client_ca":"ca.pem","keys":"proxy-keys.json",
            "audiences":["https://proxy.test"],"skew":0,"stateless":"strict"{extra},
            "routes":[{{"provider":"api","host":"api.test","address":"{api_host}","port":{api_port},"ca_file":"ca.pem",
                       "authentication":"api-key"}}]}}"#
        )
    };
    let audited = write_json(&dir, "audited.json", proxy_json(r#","audit":"audit.log""#));
    assert!(garrett_stateless::config::ProxyConfig::load(&audited).is_err());
    let proxy_path = write_json(&dir, "proxy.json", proxy_json(""));

    // The operator mints from the keys and the issuance policy alone: the
    // broker's TLS files are named but never read.
    let issue_only = write_json(
        &dir,
        "issue-only.json",
        broker_json(r#""api-key.json""#, r#","stateless":"strict""#)
            .replace("server.pem", "absent.pem")
            .replace("server.key", "absent.key")
            .replace("\"ca.pem\"", "\"absent-ca.pem\""),
    );
    assert!(BrokerConfig::load(&issue_only).is_ok());
    let config = BrokerConfig::load(&broker_path).unwrap();
    assert!(config.browser.is_none());
    let der = tls::certificates(agent_c.certificate.as_bytes())
        .unwrap()
        .remove(0);
    let provider = config.provider("api").unwrap();
    let issued = garrett_stateless::broker::mint_with(
        &BrokerKeys::load(&config.keys).unwrap(),
        &config.issue_policy(),
        &provider.name,
        b"sk_SYNTHETIC_API_KEY_0123456789",
        der.as_ref(),
        &provider.copy_claims,
        600,
        garrett_stateless::broker::now_seconds(),
    )
    .unwrap();
    assert!(!issued.token.contains("sk_SYNTHETIC"));

    let ca_pem = ca.certificate.as_bytes();
    let agent = Agent::new(
        ca_pem,
        ClientIdentity::Software {
            certificate: agent_c.certificate.clone().into_bytes(),
            key: agent_c.key.as_bytes().to_vec(),
        },
    )
    .unwrap();
    let proxy = Arc::new(Proxy::from_file(&proxy_path).unwrap())
        .serve()
        .unwrap();
    let proxy_endpoint =
        Endpoint::parse("https://proxy.test:8443", Some(&proxy.address.to_string())).unwrap();
    let response = agent
        .request(
            &proxy_endpoint,
            &issued.token,
            "GET",
            "/v1/things",
            &[],
            b"",
        )
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(seen.lock().unwrap().len(), 1);

    // The strict broker serves only the agent API: renewal, and no logins.
    let broker = Arc::new(Broker::from_file(&broker_path).unwrap());
    // The native side of `strict_no_login_state`'s hypothesis.
    assert!(broker.login_policy().providers.is_empty());
    let running = broker.serve().unwrap();
    assert!(running.browser_address.is_none());
    let broker_endpoint = Endpoint::parse(
        "https://broker.test:9443",
        Some(&running.agent_address.to_string()),
    )
    .unwrap();
    assert!(agent.begin_login(&broker_endpoint, "api", None).is_err());
    let renewed = agent.renew(&broker_endpoint, &issued.token).unwrap();
    assert!(renewed.renew_until <= issued.renew_until);
    let again = agent
        .request(
            &proxy_endpoint,
            &renewed.token,
            "GET",
            "/v1/things",
            &[],
            b"",
        )
        .unwrap();
    assert_eq!(again.status, 200);
    running.stop();
    proxy.stop();

    // The same surrogate through a read-only proxy: the authorized read
    // succeeds; a changed method, path or body is refused before egress.
    let read_only_path = write_json(
        &dir,
        "read-only.json",
        proxy_json(r#","read_only":[{"provider":"api","path":"/v1/things"}]"#),
    );
    let read_only = Arc::new(Proxy::from_file(&read_only_path).unwrap());
    assert_eq!(read_only.config().operations.name(), "read-only");
    let read_only = read_only.serve().unwrap();
    let read_only_endpoint = Endpoint::parse(
        "https://proxy.test:8443",
        Some(&read_only.address.to_string()),
    )
    .unwrap();
    let before = seen.lock().unwrap().len();
    let read = agent
        .request(
            &read_only_endpoint,
            &issued.token,
            "GET",
            "/v1/things",
            &[],
            b"",
        )
        .unwrap();
    assert_eq!(read.status, 200);
    assert_eq!(seen.lock().unwrap().len(), before + 1);
    for (method, target, body) in [
        ("POST", "/v1/things", &b"{}"[..]),
        ("DELETE", "/v1/things", &b""[..]),
        ("GET", "/v1/other", &b""[..]),
        ("GET", "/v1/things/1", &b""[..]),
        ("GET", "/v1/things", &b"x"[..]),
    ] {
        let refused = agent
            .request(
                &read_only_endpoint,
                &issued.token,
                method,
                target,
                &[],
                body,
            )
            .unwrap();
        assert_eq!(refused.status, 403, "{method} {target}");
        assert_eq!(seen.lock().unwrap().len(), before + 1, "{method} {target}");
    }
    read_only.stop();
}
