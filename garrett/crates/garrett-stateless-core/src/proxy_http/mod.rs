//! The proxy's strict HTTP/1.1 subset: request and response parsing, the
//! field filter, the exact upstream encoder, response re-framing with
//! reflected-credential refusal, and the fixed refusal responses
//! (`docs/garrett-stateless-v1.md` section 11).
//!
//! The Python counterpart is `garrett_stateless.core.proxy_http`. Every function is
//! pure over bytes. The encoder injects the credential only through
//! `http_auth::append_header`; every agent field that could carry a
//! credential or change framing is removed first. ("Guest" below is the
//! agent's side of the proxy.)
//!
//! The module is split by direction; everything is re-exported here, so
//! `proxy_http::X` names every item:
//!
//! | file | what |
//! | --- | --- |
//! | `request.rs` | parsing the agent's request |
//! | `upstream.rs` | the field filter, deny rules and exact upstream encoder |
//! | `response.rs` | the provider's response, re-framed, with reflected-credential refusal |
//! | `refusal.rs` | the fixed refusal responses |
use crate::credential_use::Authentication;
use crate::{http_auth, http_wire, reflection};

mod request;
mod upstream;
mod response;
mod refusal;

pub use request::*;
pub use upstream::*;
pub use response::*;
pub use refusal::*;

pub const MAX_HEAD: usize = 32 * 1024;
pub const MAX_FIELDS: usize = 100;
pub const MAX_TARGET: usize = 8192;

#[cfg(test)]
mod tests {
    /// The deny-rule matcher before it was split into helpers.
    fn legacy_rule_matches(rule: &DenyRule, method: &[u8], path: &[u8]) -> bool {
        let rule_method: &[u8] = &rule.method;
        let rule_path: &[u8] = &rule.path;
        if rule_method.len() != 0 && !(rule_method == method) {
            return false;
        }
        if path == rule_path {
            return true;
        }
        if path.len() > rule_path.len()
            && path.len() - rule_path.len() == 1
            && path[rule_path.len()] == b'/'
            && &path[..rule_path.len()] == rule_path
        {
            return true;
        }
        if rule_path.len() == 0 || rule_path[rule_path.len() - 1] != b'/' {
            return false;
        }
        if rule_path.len() > path.len()
            && rule_path.len() - path.len() == 1
            && path == &rule_path[..path.len()]
        {
            return true;
        }
        path.len() >= rule_path.len() && &path[..rule_path.len()] == rule_path
    }

    #[test]
    fn deny_rule_matcher_agrees_with_the_legacy_matcher_on_all_short_paths() {
        // Every path and rule path of up to four bytes over {a, /}, every
        // method pair: exhaustive, not sampled.
        let mut words: Vec<Vec<u8>> = vec![Vec::new()];
        let mut frontier = words.clone();
        for _ in 0..4 {
            frontier = frontier
                .iter()
                .flat_map(|w| [b'a', b'/'].map(|b| [w.clone(), vec![b]].concat()))
                .collect();
            words.extend(frontier.clone());
        }
        let methods: [&[u8]; 3] = [b"", b"GET", b"POST"];
        for rule_path in &words {
            for rule_method in methods {
                let rule = DenyRule {
                    method: rule_method.to_vec(),
                    path: rule_path.clone(),
                };
                for path in &words {
                    for method in &methods[1..] {
                        assert_eq!(
                            rule_matches(&rule, method, path),
                            legacy_rule_matches(&rule, method, path),
                            "{rule_method:?} {rule_path:?} {method:?} {path:?}"
                        );
                    }
                }
            }
        }
    }

    use super::*;

    fn parse(bytes: &[u8]) -> Result<Option<Parsed>, Refusal> {
        parse_request(bytes, b"api.example.org", 1024)
    }

    #[test]
    fn a_request_is_reencoded_with_one_credential_line() {
        let raw = b"POST /v1/issues HTTP/1.1\r\nHost: api.example.org\r\nAuthorization: token guest\r\nX-Trace:  t  \r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
        let parsed = match parse(raw) {
            Ok(Some(parsed)) => parsed,
            _ => panic!("refused"),
        };
        assert_eq!(parsed.used, raw.len());
        let mut out = Vec::new();
        assert!(encode_upstream(
            &mut out,
            &parsed.request,
            b"api.example.org",
            &[],
            b"SECRET",
            &Authentication::Bearer
        )
        .is_ok());
        assert_eq!(out, b"POST /v1/issues HTTP/1.1\r\nHost: api.example.org\r\nx-trace: t\r\nAuthorization: Bearer SECRET\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi".to_vec());
    }

    #[test]
    fn ambiguous_requests_are_refused() {
        for raw in [
            b"GET / HTTP/1.1\r\nHost: api.example.org\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: api.example.org\r\nX: a\r\n b\r\n\r\n",
            b"GET / HTTP/1.1\nHost: api.example.org\r\n\r\n",
            b"GET /a/../b HTTP/1.1\r\nHost: api.example.org\r\n\r\n",
            b"GET /a%2Fb HTTP/1.1\r\nHost: api.example.org\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: evil.example.org\r\n\r\n",
            b"GET / HTTP/1.0\r\nHost: api.example.org\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: api.example.org\r\nUpgrade: h2c\r\n\r\n",
        ] {
            assert!(matches!(parse(raw), Err(Refusal::InvalidRequest)));
        }
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn code(refusal: &Refusal) -> &'static str {
        match refusal {
            Refusal::InvalidRequest => "invalid",
            Refusal::TooLarge => "large",
            Refusal::Denied => "denied",
            Refusal::InvalidCredential => "credential",
            Refusal::UpstreamResponse => "upstream",
            Refusal::Reflected => "reflected",
        }
    }

    /// Byte parity with the Python reference (`tests/test_proxy_rust_parity.py`).
    #[test]
    fn python_reference_vectors() {
        let vectors = include_str!("../../../../tests/vectors/proxy-http-v1.tsv");
        let rules = [
            DenyRule {
                method: b"POST".to_vec(),
                path: b"/v1/tokens".to_vec(),
            },
            DenyRule {
                method: Vec::new(),
                path: b"/v1/admin/".to_vec(),
            },
        ];
        let mut checked = 0;
        for line in vectors.lines().skip(1) {
            let columns: Vec<&str> = line.split('\t').collect();
            let raw = unhex(columns[0]);
            let secret = unhex(columns[1]);
            let authentication = match columns[2] {
                "bearer" => Authentication::Bearer,
                _ => Authentication::ApiKey,
            };
            let actual = match parse_request(&raw, b"api.example.org", 64) {
                Ok(None) => "more".to_string(),
                Err(refusal) => format!("refused:{}", code(&refusal)),
                Ok(Some(parsed)) => {
                    let mut out = Vec::new();
                    match encode_upstream(
                        &mut out,
                        &parsed.request,
                        b"api.example.org",
                        &rules,
                        &secret,
                        &authentication,
                    ) {
                        Ok(()) => format!("ok:{}:{}", parsed.used, hex(&out)),
                        Err(refusal) => format!("refused:{}", code(&refusal)),
                    }
                }
            };
            assert_eq!(actual, columns[3], "vector {}", checked);
            checked += 1;
        }
        assert!(checked >= 60);
    }

    /// Response-side parity with the Python reference.
    #[test]
    fn python_reference_response_vectors() {
        let vectors = include_str!("../../../../tests/vectors/proxy-http-response-v1.tsv");
        let mut checked = 0;
        for line in vectors.lines().skip(1) {
            let columns: Vec<&str> = line.split('\t').collect();
            let raw = unhex(columns[0]);
            let head = columns[1] == "1";
            let keep = columns[2] == "1";
            let secret = unhex(columns[3]);
            let forms = reflection_forms(&secret);
            let actual = match parse_response(&raw, head, 64) {
                Err(refusal) => format!("refused:{}", code(&refusal)),
                Ok(response) => {
                    let mut out = Vec::new();
                    match guest_response(&mut out, &response, &forms, keep, head) {
                        Ok(()) => format!("ok:{}", hex(&out)),
                        Err(refusal) => format!("refused:{}", code(&refusal)),
                    }
                }
            };
            assert_eq!(actual, columns[4], "response vector {}", checked);
            checked += 1;
        }
        assert!(checked >= 35);
    }

    /// Refusal parity with the Python reference.
    #[test]
    fn python_reference_refusals() {
        let vectors = include_str!("../../../../tests/vectors/proxy-http-refusal-v1.tsv");
        let codes = [
            ("invalid_request", Code::InvalidRequest),
            ("too_large", Code::TooLarge),
            ("denied", Code::Denied),
            ("unknown_origin", Code::UnknownOrigin),
            ("unauthenticated", Code::Unauthenticated),
            ("revoked", Code::Revoked),
            ("reflected", Code::Reflected),
            ("unreachable", Code::Unreachable),
            ("outcome_unknown", Code::OutcomeUnknown),
            ("credential_source", Code::CredentialSource),
            ("unsupported_request", Code::UnsupportedRequest),
        ];
        let mut checked = 0;
        for line in vectors.lines().skip(1) {
            let columns: Vec<&str> = line.split('\t').collect();
            let code = &codes
                .iter()
                .find(|(name, _)| *name == columns[0])
                .unwrap()
                .1;
            assert_eq!(hex(&refusal(code)), columns[1], "refusal {}", columns[0]);
            checked += 1;
        }
        assert_eq!(checked, codes.len());
    }

    #[test]
    fn deny_rules_refuse_before_writing() {
        let raw = b"GET /v1/admin/x HTTP/1.1\r\nHost: api.example.org\r\n\r\n";
        let parsed = match parse(raw) {
            Ok(Some(parsed)) => parsed,
            _ => panic!("refused"),
        };
        let rules = [DenyRule {
            method: Vec::new(),
            path: b"/v1/admin/".to_vec(),
        }];
        let mut out = b"keep".to_vec();
        assert!(matches!(
            encode_upstream(
                &mut out,
                &parsed.request,
                b"api.example.org",
                &rules,
                b"S",
                &Authentication::ApiKey
            ),
            Err(Refusal::Denied)
        ));
        assert_eq!(out, b"keep".to_vec());
    }
}
