//! The sealed login state (spec section 8.2) and PKCE. The transient login
//! mailbox (section 9) is the extracted `stateless_mailbox`.
use crate::encoding::{b64url, random};
use crate::error::{Error, Result};
use crate::token::RingStateKey;
use aivm_secrets_garrett_core::oauth_login::Stage;
use aivm_secrets_garrett_core::stateless::Rejection;
use aivm_secrets_garrett_core::stateless_login::LoginState;
use aivm_secrets_garrett_core::stateless_token::{self, StateKey};
use zeroize::Zeroizing;

pub const STATE_PREFIX: &str = "gs1.";
pub const MAX_STATE: usize = 4096;

/// Seal a login state under the broker's login-state key (the extracted
/// `stateless_token::seal_state`, with a fresh nonce).
pub fn seal_state(state_key: &[u8; 32], state: &LoginState) -> Result<String> {
    let sealed = stateless_token::seal_state(&RingStateKey(state_key), state, &random::<12>()?)
        .ok_or(Error::Protocol("invalid_request"))?;
    String::from_utf8(sealed).map_err(|_| Error::Protocol("internal_error"))
}

/// The canonical plaintext of a login state.
pub fn state_plaintext(state: &LoginState) -> Result<Vec<u8>> {
    if !stateless_token::state_valid(state) {
        return Err(Error::Protocol("invalid_request"));
    }
    Ok(stateless_token::state_bytes(state))
}

/// Deterministic sealing of a plaintext, for conformance vectors.
pub fn seal_plaintext(state_key: &[u8; 32], plaintext: &[u8], nonce: [u8; 12]) -> Result<String> {
    let ciphertext = RingStateKey(state_key)
        .seal(&nonce, stateless_token::LOGIN_LABEL, plaintext)
        .ok_or(Error::Protocol("internal_error"))?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ciphertext);
    let out = format!("{STATE_PREFIX}{}", b64url(&sealed));
    if out.len() > MAX_STATE {
        return Err(Error::Protocol("invalid_request"));
    }
    Ok(out)
}

/// Open a `state` parameter (the extracted `stateless_token::open_state`).
pub fn open_state(state_key: &[u8; 32], text: &str) -> std::result::Result<LoginState, Rejection> {
    stateless_token::open_state(&RingStateKey(state_key), text.as_bytes())
}

/// A fresh PKCE verifier (32 random bytes, b64url).
pub fn pkce_verifier() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(b64url(&random::<32>()?)))
}

/// The S256 challenge of a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    b64url(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

/// `XXXX-XXXX`: the first 8 hex digits of the login, upper case.
pub fn confirmation(login: &str) -> String {
    let upper = login.to_ascii_uppercase();
    format!("{}-{}", &upper[..4], &upper[4..8])
}

/// The stable name of a login stage, for diagnostics.
pub fn stage_name(stage: &Stage) -> &'static str {
    match stage {
        Stage::Pending => "pending",
        Stage::Accepted => "accepted",
        Stage::Denied => "denied",
        Stage::Exchanging => "exchanging",
        Stage::Complete => "complete",
        Stage::Uncertain => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> LoginState {
        LoginState {
            login: b"0123456789abcdef0123456789abcdef".to_vec(),
            provider: b"api".to_vec(),
            certificate: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
            subject: b"spiffe://test/agent".to_vec(),
            certificate_expires: 99999,
            replica: b"a".to_vec(),
            scope: b"read".to_vec(),
            verifier: b"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv".to_vec(),
            issued_at: 100,
            expires_at: 700,
        }
    }

    #[test]
    fn state_round_trip_and_forgery() {
        let k = [7u8; 32];
        let sealed = seal_state(&k, &state()).unwrap();
        let opened = open_state(&k, &sealed).ok().unwrap();
        assert_eq!(opened.verifier, state().verifier);
        assert!(!sealed.contains("vvvv"));
        assert!(open_state(&[8u8; 32], &sealed).is_err());
        let mut forged = sealed.clone().into_bytes();
        let last = forged.len() - 1;
        forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
        assert!(open_state(&k, std::str::from_utf8(&forged).unwrap()).is_err());
    }

    #[test]
    fn pkce_matches_rfc7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
