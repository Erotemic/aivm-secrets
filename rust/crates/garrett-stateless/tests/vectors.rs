//! The Rust implementation, including the extracted core controllers,
//! against the frozen vectors in `tests/secrets_vectors/garrett-stateless-v1.jsonl`
//! (the Python implementation checks the same file).
use aivm_secrets_garrett_core::oauth_login::{IssuerRule, Stage};
use aivm_secrets_garrett_core::stateless::{self, Acceptance, Grant, IssuePolicy, SurrogateClaims};
use aivm_secrets_garrett_core::stateless_login::{self, Delivery, Entry, LoginPolicy, LoginState};
use garrett_stateless::error::rejection_name;
use garrett_stateless::json::{self, Value};
use garrett_stateless::keys::BrokerKeys;
use garrett_stateless::login;
use garrett_stateless::tls::PeerIdentity;
use garrett_stateless::token::{copy_upstream, fixture_seal, ClaimCopy, Informational};

fn rows() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/secrets_vectors/garrett-stateless-v1.jsonl"
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| json::parse(line.as_bytes(), 1 << 20, 32).unwrap())
        .collect()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key}"))
}
fn i(v: &Value, key: &str) -> i64 {
    v.get(key)
        .and_then(Value::as_int)
        .unwrap_or_else(|| panic!("{key}"))
}
fn b(v: &Value, key: &str) -> Vec<u8> {
    s(v, key).as_bytes().to_vec()
}
fn texts(v: &Value, key: &str) -> Vec<Vec<u8>> {
    match v.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|x| x.as_str().unwrap().as_bytes().to_vec())
            .collect(),
        _ => panic!("{key}"),
    }
}
fn unhex(text: &str) -> [u8; 12] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&text[k..k + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}
fn claims(v: &Value) -> SurrogateClaims {
    SurrogateClaims {
        issuer: b(v, "issuer"),
        audience: b(v, "audience"),
        subject: b(v, "subject"),
        token_id: b(v, "token_id"),
        provider: b(v, "provider"),
        certificate: b(v, "certificate"),
        issued_at: i(v, "issued_at"),
        expires_at: i(v, "expires_at"),
        renew_until: i(v, "renew_until"),
    }
}
fn state(v: &Value) -> LoginState {
    LoginState {
        login: b(v, "login"),
        provider: b(v, "provider"),
        certificate: b(v, "certificate"),
        subject: b(v, "subject"),
        certificate_expires: i(v, "certificate_expires"),
        replica: b(v, "replica"),
        scope: b(v, "scope"),
        verifier: b(v, "verifier"),
        issued_at: i(v, "issued_at"),
        expires_at: i(v, "expires_at"),
    }
}
fn stage(name: &str) -> Stage {
    match name {
        "pending" => Stage::Pending,
        "accepted" => Stage::Accepted,
        "denied" => Stage::Denied,
        "exchanging" => Stage::Exchanging,
        "complete" => Stage::Complete,
        "failed" => Stage::Uncertain,
        other => panic!("{other}"),
    }
}
fn entry(v: &Value, stage_name: &str) -> Entry {
    let mut e = stateless_login::entry_of(&state(v));
    e.stage = stage(stage_name);
    e
}
fn policy_of(value: &Value) -> ClaimCopy {
    match value {
        Value::Str(text) if text == "access" => ClaimCopy::Access,
        Value::Str(text) if text == "all" => ClaimCopy::All,
        Value::Array(items) => ClaimCopy::Only(
            items
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect(),
        ),
        _ => panic!("policy"),
    }
}

#[test]
fn every_vector() {
    let rows = rows();
    let keys =
        BrokerKeys::parse(&json::canonical(rows[0].get("broker_keys").unwrap()).unwrap()).unwrap();
    let proxy = keys.export_proxy();
    let exported = json::parse(&proxy.to_json(), 1 << 16, 8).unwrap();
    assert_eq!(&exported, rows[0].get("proxy_keys").unwrap());
    let mut checked = 0;
    for row in &rows {
        let label = row.get("label").and_then(Value::as_str).unwrap_or("");
        match s(row, "kind") {
            "keys" => (),
            "certificate" => {
                let der = base64_decode(s(row, "der"));
                let peer = PeerIdentity::from_der(&der).unwrap();
                assert_eq!(peer.thumbprint, s(row, "thumbprint"));
                assert_eq!(peer.subject, s(row, "subject"));
                assert_eq!(peer.not_after, i(row, "not_after"));
            }
            "seal" => {
                let entry = keys
                    .entries
                    .iter()
                    .find(|e| e.kid == s(row, "kid"))
                    .unwrap();
                let info_value = row.get("info").unwrap();
                let info = Informational {
                    scope: info_value
                        .get("scope")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    upstream: info_value
                        .get("upstream")
                        .and_then(Value::as_object)
                        .cloned(),
                };
                let token = fixture_seal(
                    entry,
                    &info,
                    &claims(row.get("claims").unwrap()),
                    s(row, "credential").as_bytes(),
                    unhex(s(row, "nonce")),
                )
                .ok()
                .unwrap();
                assert_eq!(
                    String::from_utf8(token).unwrap(),
                    s(row, "token"),
                    "{label}"
                );
            }
            "open" => {
                let a = row.get("acceptance").unwrap();
                let acceptance = Acceptance {
                    audiences: texts(a, "audiences"),
                    providers: texts(a, "providers"),
                    max_lifetime: i(a, "max_lifetime"),
                    skew: i(a, "skew"),
                };
                let opener = proxy.key_set().unwrap();
                let result = stateless::open(
                    &opener,
                    s(row, "token").as_bytes(),
                    &acceptance,
                    s(row, "peer").as_bytes(),
                    i(row, "now"),
                );
                let expect = row.get("expect").unwrap();
                match (result, expect.get("rejection").and_then(Value::as_str)) {
                    (Err(rejection), Some(code)) => {
                        assert_eq!(rejection_name(&rejection), code, "{label}")
                    }
                    (Ok(opened), None) => {
                        assert_eq!(opened.credential, b(expect, "credential"), "{label}");
                        if let Some(c) = expect.get("claims") {
                            let want = claims(c);
                            assert_eq!(opened.claims.certificate, want.certificate);
                            assert_eq!(opened.claims.subject, want.subject);
                            assert_eq!(
                                (
                                    opened.claims.issued_at,
                                    opened.claims.expires_at,
                                    opened.claims.renew_until
                                ),
                                (want.issued_at, want.expires_at, want.renew_until)
                            );
                        }
                    }
                    (Ok(_), Some(code)) => panic!("{label}: accepted, expected {code}"),
                    (Err(rejection), None) => {
                        panic!("{label}: refused {}", rejection_name(&rejection))
                    }
                }
            }
            "upstream" => {
                let copied = copy_upstream(
                    s(row, "access_token"),
                    &policy_of(row.get("policy").unwrap()),
                );
                let want = row.get("expect").unwrap();
                match (copied, want) {
                    (None, Value::Null) => (),
                    (Some(map), Value::Object(expect)) => assert_eq!(&map, expect, "{label}"),
                    (got, _) => panic!("{label}: {got:?}"),
                }
            }
            "login_state" => {
                let want = state(row.get("state").unwrap());
                let sealed = login::seal_plaintext(
                    keys.state_key(),
                    &login::state_plaintext(&want).unwrap(),
                    unhex(s(row, "nonce")),
                )
                .unwrap();
                assert_eq!(sealed, s(row, "sealed"));
                let opened = login::open_state(keys.state_key(), &sealed).ok().unwrap();
                assert_eq!(
                    (opened.login, opened.verifier, opened.expires_at),
                    (want.login, want.verifier, want.expires_at)
                );
            }
            "login_state_open" => {
                let refused = login::open_state(keys.state_key(), s(row, "sealed"))
                    .err()
                    .unwrap();
                assert_eq!(rejection_name(&refused), s(row, "expect"), "{label}");
            }
            "pkce" => assert_eq!(
                login::pkce_challenge(s(row, "verifier")),
                s(row, "challenge")
            ),
            "issue_window" => {
                let p = row.get("policy").unwrap();
                let policy = IssuePolicy {
                    issuer: b(p, "issuer"),
                    audience: b(p, "audience"),
                    providers: texts(p, "providers"),
                    max_lifetime: i(p, "max_lifetime"),
                    max_renew: i(p, "max_renew"),
                };
                let grant = Grant {
                    provider: b"api".to_vec(),
                    subject: b"agent".to_vec(),
                    certificate: b"c".to_vec(),
                    certificate_expires: i(row, "certificate_expires"),
                    credential_expires: i(row, "credential_expires"),
                };
                let expect = row.get("expect").unwrap();
                match (
                    stateless::issue_window(&policy, &grant, i(row, "now"), i(row, "lifetime")),
                    expect.get("window"),
                ) {
                    (Ok(w), Some(Value::Array(want))) => {
                        assert_eq!(
                            vec![
                                Value::Int(w.issued_at),
                                Value::Int(w.expires_at),
                                Value::Int(w.renew_until)
                            ],
                            *want,
                            "{label}"
                        )
                    }
                    (Err(r), None) => {
                        assert_eq!(rejection_name(&r), s(expect, "rejection"), "{label}")
                    }
                    _ => panic!("{label}"),
                }
            }
            "accept_callback" => {
                let policy = LoginPolicy {
                    replica: b"a".to_vec(),
                    providers: vec![b"api".to_vec()],
                    ttl: 600,
                };
                let e = entry(row.get("entry").unwrap(), s(row, "entry_stage"));
                let rule = match row.get("issuer_rule") {
                    Some(Value::Str(issuer)) => IssuerRule::Exact(issuer.as_bytes().to_vec()),
                    _ => IssuerRule::Absent,
                };
                let issuer = row.get("issuer").and_then(Value::as_str);
                let denied = matches!(row.get("denied"), Some(Value::Bool(true)));
                let result = stateless_login::accept_callback(
                    &policy,
                    &e,
                    &state(row.get("state").unwrap()),
                    &rule,
                    issuer.unwrap_or("").as_bytes(),
                    issuer.is_some(),
                    denied,
                    i(row, "now"),
                );
                let expect = row.get("expect").unwrap();
                match (
                    result,
                    expect.get("stage").and_then(Value::as_str),
                    expect.get("denial").and_then(Value::as_str),
                ) {
                    (Ok(got), Some(want), None) => {
                        assert_eq!(login::stage_name(&got), want, "{label}")
                    }
                    (Err(denial), None, Some(want)) => {
                        let name = match denial {
                            aivm_secrets_garrett_core::oauth_login::LoginDenial::Invalid => {
                                "invalid"
                            }
                            aivm_secrets_garrett_core::oauth_login::LoginDenial::Expired => {
                                "expired"
                            }
                            aivm_secrets_garrett_core::oauth_login::LoginDenial::Consumed => {
                                "consumed"
                            }
                        };
                        assert_eq!(name, want, "{label}");
                    }
                    _ => panic!("{label}"),
                }
            }
            "deliver" => {
                let e = entry(row.get("entry").unwrap(), s(row, "stage"));
                let got =
                    match stateless_login::deliver(&e, s(row, "peer").as_bytes(), i(row, "now")) {
                        Delivery::Pending => "pending",
                        Delivery::Deliver => "deliver",
                        Delivery::WrongCertificate => "wrong_certificate",
                        Delivery::Denied => "denied",
                        Delivery::Failed => "failed",
                        Delivery::Expired => "expired",
                    };
                assert_eq!(got, s(row, "expect"), "{label}");
            }
            other => panic!("unknown vector kind {other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, rows.len());
}

fn base64_decode(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in text.bytes().filter(|b| *b != b'=') {
        buffer = (buffer << 6) | alphabet.iter().position(|a| *a == byte).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}
