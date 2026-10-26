//! The sealed login state (spec section 8.2), PKCE, and the transient
//! login mailbox (section 9).
use crate::encoding::{
    b64url, from_b64url, is_id, is_kid, is_provider, is_scope, is_text, is_thumbprint, random,
};
use crate::error::{Error, Result};
use crate::json::{self, Value, MAX_INTEGER};
use aivm_secrets_garrett_core::oauth_login::Stage;
use aivm_secrets_garrett_core::stateless::Rejection;
use aivm_secrets_garrett_core::stateless_login::{Entry, LoginState};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const STATE_PREFIX: &str = "gs1.";
pub const MAX_STATE: usize = 4096;
pub const MAX_PENDING: usize = 1024;
const LOGIN_LABEL: &[u8] = b"garrett-stateless-v1/login\0";

fn key(state_key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, state_key).expect("32-byte AES key"))
}

fn text(bytes: &[u8]) -> Result<Value> {
    Ok(json::text(
        std::str::from_utf8(bytes).map_err(|_| Error::Protocol("invalid_request"))?,
    ))
}

/// Seal a login state under the broker's login-state key.
pub fn seal_state(state_key: &[u8; 32], state: &LoginState) -> Result<String> {
    let plain = json::object([
        (
            "cert_exp",
            Value::Int(state.certificate_expires.min(MAX_INTEGER)),
        ),
        ("cnf", text(&state.certificate)?),
        ("exp", Value::Int(state.expires_at)),
        ("iat", Value::Int(state.issued_at)),
        ("login", text(&state.login)?),
        ("prv", text(&state.provider)?),
        ("rep", text(&state.replica)?),
        ("scope", text(&state.scope)?),
        ("sub", text(&state.subject)?),
        ("verifier", text(&state.verifier)?),
    ]);
    seal_plaintext(
        state_key,
        &json::canonical(&plain).map_err(|_| Error::Protocol("invalid_request"))?,
        random::<12>()?,
    )
}

/// Deterministic sealing for conformance vectors.
pub fn seal_plaintext(state_key: &[u8; 32], plaintext: &[u8], nonce: [u8; 12]) -> Result<String> {
    let mut data = Zeroizing::new(plaintext.to_vec());
    key(state_key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(LOGIN_LABEL),
            &mut *data,
        )
        .map_err(|_| Error::Protocol("internal_error"))?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&data);
    let out = format!("{STATE_PREFIX}{}", b64url(&sealed));
    if out.len() > MAX_STATE {
        return Err(Error::Protocol("invalid_request"));
    }
    Ok(out)
}

fn field(
    map: &std::collections::BTreeMap<String, Value>,
    name: &str,
    valid: fn(&str) -> bool,
) -> std::result::Result<Vec<u8>, Rejection> {
    let value = map
        .get(name)
        .and_then(Value::as_str)
        .ok_or(Rejection::Malformed)?;
    if !valid(value) {
        return Err(Rejection::Malformed);
    }
    Ok(value.as_bytes().to_vec())
}

fn number(
    map: &std::collections::BTreeMap<String, Value>,
    name: &str,
) -> std::result::Result<i64, Rejection> {
    map.get(name)
        .and_then(Value::as_int)
        .filter(|v| *v >= 0)
        .ok_or(Rejection::Malformed)
}

fn is_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Open a `state` parameter. Any forgery, truncation or foreign key fails.
pub fn open_state(state_key: &[u8; 32], text: &str) -> std::result::Result<LoginState, Rejection> {
    if text.len() > MAX_STATE {
        return Err(Rejection::Malformed);
    }
    let encoded = text
        .strip_prefix(STATE_PREFIX)
        .ok_or(Rejection::Malformed)?;
    let sealed = from_b64url(encoded).ok_or(Rejection::Malformed)?;
    if sealed.len() < 12 + 16 + 1 {
        return Err(Rejection::Malformed);
    }
    let nonce: [u8; 12] = sealed[..12].try_into().map_err(|_| Rejection::Malformed)?;
    let mut data = Zeroizing::new(sealed[12..].to_vec());
    let plain = key(state_key)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(LOGIN_LABEL),
            &mut *data,
        )
        .map_err(|_| Rejection::Undecryptable)?;
    let value = json::parse(plain, MAX_STATE, 2).map_err(|_| Rejection::Malformed)?;
    let map = value.as_object().ok_or(Rejection::Malformed)?;
    if map.len() != 10 {
        return Err(Rejection::Malformed);
    }
    Ok(LoginState {
        login: field(map, "login", is_id)?,
        provider: field(map, "prv", is_provider)?,
        certificate: field(map, "cnf", is_thumbprint)?,
        subject: field(map, "sub", is_text)?,
        certificate_expires: number(map, "cert_exp")?,
        replica: field(map, "rep", is_kid)?,
        scope: field(map, "scope", is_scope)?,
        verifier: field(map, "verifier", is_verifier)?,
        issued_at: number(map, "iat")?,
        expires_at: number(map, "exp")?,
    })
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

/// One mailbox slot: the transient entry and, once issued, its surrogate.
pub struct Slot {
    pub entry: Entry,
    pub token: Option<(String, i64)>,
}

/// The broker's only mutable state: logins in progress, in memory.
#[derive(Default)]
pub struct Mailbox {
    slots: HashMap<String, Slot>,
}

impl Mailbox {
    pub fn prune(&mut self, now: i64) {
        self.slots.retain(|_, slot| {
            now < slot.entry.expires_at + aivm_secrets_garrett_core::stateless_login::DELIVERY_GRACE
        });
    }
    pub fn insert(&mut self, login: String, entry: Entry, now: i64) -> Result<()> {
        self.prune(now);
        if self.slots.len() >= MAX_PENDING {
            return Err(Error::Protocol("too_many_logins"));
        }
        if self.slots.contains_key(&login) {
            return Err(Error::Protocol("internal_error"));
        }
        self.slots.insert(login, Slot { entry, token: None });
        Ok(())
    }
    pub fn get_mut(&mut self, login: &str) -> Option<&mut Slot> {
        self.slots.get_mut(login)
    }
    pub fn remove(&mut self, login: &str) -> Option<Slot> {
        self.slots.remove(login)
    }
    pub fn len(&self) -> usize {
        self.slots.len()
    }
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
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
