//! The `garrett-stateless-v1` surrogate codec (`docs/garrett-stateless-v1.md`
//! sections 2-5): strict b64url, the grammars, the exact header and payload
//! layout, key selection, and the key-set opener and sealer that
//! `stateless::open` and `stateless::issue` call.
//!
//! Ed25519 and AES-256-GCM are the only adapters ([`KeyMaterial`]). This module
//! fixes every byte they are given and every check made on what they return:
//! which key a token selects, which bytes are signed, which bytes are
//! authenticated with the credential, and which claims authorize. A payload is
//! accepted only in its one canonical form, so the signed bytes are the claims.
//!
//! The module is split by responsibility; everything is re-exported here, so
//! `stateless_token::X` names every item:
//!
//! | file | what |
//! | --- | --- |
//! | `base64.rs` | strict b64url |
//! | `grammar.rs` | the name and claim grammars |
//! | `json.rs` | canonical JSON values (`upstream`) |
//! | `payload.rs` | the exact header and payload bytes and their parse |
//! | `keys.rs` | `KeyMaterial`, key entries, validated key sets |
//! | `opening.rs` | `verify_token`, `unseal_token`, the `SurrogateOpener` |
//! | `sealing.rs` | `seal_token`, the one-shot `TokenSealer` |
//! | `login_state.rs` | the sealed login state |
// Explicit indices, matches and loops keep to what Aeneas models.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_range_contains,
    clippy::len_zero,
    clippy::single_match,
    clippy::match_like_matches_macro,
    clippy::comparison_chain,
    clippy::manual_map
)]

use crate::http_auth;
use crate::proxy_http::encode_unpadded;
use crate::stateless::{Rejection, SurrogateClaims, SurrogateOpener, SurrogateSealer, Verified};
use crate::stateless_login::LoginState;

mod base64;
mod grammar;
mod json;
mod payload;
mod keys;
mod opening;
mod sealing;
mod login_state;

pub use base64::*;
pub use grammar::*;
pub use json::*;
pub use payload::*;
pub use keys::*;
pub use opening::*;
pub use sealing::*;
pub use login_state::*;

pub const MAX_TOKEN: usize = 16384;
/// Largest integer this profile treats as an integer (`2^53 - 1`).
pub const MAX_INTEGER: i64 = 9007199254740991;
pub const MAX_KEYS: usize = 8;
/// The payload nests at most this deep (the payload object is level 0).
pub const MAX_DEPTH: usize = 16;
pub const NONCE: usize = 12;
pub const TAG: usize = 16;
pub const SIGNATURE: usize = 64;

pub const CREDENTIAL_LABEL: &[u8] = b"garrett-stateless-v1/credential\0";
pub const HEADER_START: &[u8] = b"{\"alg\":\"EdDSA\",\"kid\":\"";
pub const HEADER_END: &[u8] = b"\",\"typ\":\"garrett-stateless-v1+jwt\"}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_round_trip_and_strictness() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(from_b64url(&b64url(&bytes)).unwrap(), bytes);
        }
        for bad in [&b"AB=="[..], b"A", b"AF", b"A+", b"A/", b"A.B"] {
            assert!(from_b64url(bad).is_none(), "{bad:?}");
        }
        assert_eq!(b64url(b"\xff\xfe"), b"__4");
    }

    #[test]
    fn grammars() {
        assert!(is_scope(b"") && is_scope(b"read write") && !is_scope(b" read"));
        assert!(!is_scope(b"read  write") && !is_scope(b"read ") && !is_scope(b"a\"b"));
        assert!(is_kid(b"k-1_x") && !is_kid(b"-k") && !is_kid(b""));
        assert!(is_provider(b"api.v2") && !is_provider(b"Api"));
        assert!(is_thumbprint(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!is_thumbprint(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
        ));
    }

    #[test]
    fn header_is_exact() {
        let h = header_bytes(b"k1");
        assert_eq!(
            h,
            br#"{"alg":"EdDSA","kid":"k1","typ":"garrett-stateless-v1+jwt"}"#
        );
        assert_eq!(header_kid(&h).unwrap(), b"k1");
        assert!(
            header_kid(br#"{"alg":"none","kid":"k1","typ":"garrett-stateless-v1+jwt"}"#).is_none()
        );
        assert!(
            header_kid(br#"{"alg":"EdDSA","kid":"k\"1","typ":"garrett-stateless-v1+jwt"}"#)
                .is_none()
        );
    }

    fn payload(scope: Option<&[u8]>, upstream: Option<&[u8]>) -> Payload {
        Payload {
            claims: SurrogateClaims {
                issuer: b"https://broker".to_vec(),
                audience: b"https://proxy".to_vec(),
                subject: b"spiffe://test/agent".to_vec(),
                token_id: b"0123456789abcdef0123456789abcdef".to_vec(),
                provider: b"api".to_vec(),
                certificate: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
                issued_at: 0,
                expires_at: 3600,
                renew_until: 9007199254740991,
            },
            enc: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
            info: Informational {
                has_scope: scope.is_some(),
                scope: scope.unwrap_or_default().to_vec(),
                has_upstream: upstream.is_some(),
                upstream: upstream.unwrap_or_default().to_vec(),
            },
        }
    }

    #[test]
    fn payload_round_trip() {
        for (scope, upstream) in [
            (None, None),
            (Some(&b"read"[..]), None),
            (
                Some(&b""[..]),
                Some(&br#"{"aud":"x","exp":-5,"roles":["a","b\"c"],"z":null}"#[..]),
            ),
            (
                None,
                Some(&br#"{"\u00e9":{"\ud83d\ude00":[true,false,0]}}"#[..]),
            ),
        ] {
            let p = payload(scope, upstream);
            let bytes = payload_bytes(&p, true);
            let back = parse_payload(&bytes).unwrap();
            assert_eq!(payload_bytes(&back, true), bytes);
            assert_eq!(back.claims.renew_until, 9007199254740991);
        }
    }

    #[test]
    fn noncanonical_upstream_is_refused() {
        for bad in [
            &br#"{"b":1,"a":2}"#[..],
            br#"{"a":1,"a":2}"#,
            br#"{"a":01}"#,
            br#"{"a":-0}"#,
            br#"{"a":1.5}"#,
            br#"{"a":9007199254740992}"#,
            br#"{"a":"\u0041"}"#,
            br#"{"a":"\/"}"#,
            br#"{"a":"\u00E9"}"#,
            br#"{"a":"\ud800"}"#,
            b"{\"a\":\"\n\"}",
            br#"{ "a":1}"#,
            br#"{"a":[1,]}"#,
            br#"{"a":1}x"#,
        ] {
            assert!(!upstream_object(bad), "{}", String::from_utf8_lossy(bad));
        }
        let mut deep = Vec::new();
        for _ in 0..15 {
            deep.extend_from_slice(b"{\"a\":");
        }
        deep.extend_from_slice(b"1");
        deep.resize(deep.len() + 15, b'}');
        assert!(upstream_object(&deep));
        let mut deeper = b"{\"a\":".to_vec();
        deeper.extend_from_slice(&deep);
        deeper.push(b'}');
        assert!(!upstream_object(&deeper));
    }

    #[test]
    fn duplicate_and_unknown_members_are_refused() {
        let bytes = payload_bytes(&payload(None, None), true);
        let text = String::from_utf8(bytes).unwrap();
        for bad in [
            text.replacen("{\"aud\"", "{\"aud\":\"x\",\"aud\"", 1),
            text.replacen(",\"sub\"", ",\"extra\":1,\"sub\"", 1),
            text.replacen("\"exp\":3600", "\"exp\":\"3600\"", 1),
            text.replacen(
                ",\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
                "",
                1,
            ),
            text.replacen("}", "} ", 1),
        ] {
            assert!(parse_payload(bad.as_bytes()).is_none(), "{bad}");
        }
    }
}
