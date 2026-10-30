//! The sealed OAuth login state (spec section 8.2).
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

use super::*;

pub const STATE_PREFIX: &[u8] = b"gs1.";
pub const MAX_STATE: usize = 4096;
pub const LOGIN_LABEL: &[u8] = b"garrett-stateless-v1/login\0";

/// The broker's login-state key (AES-256-GCM), implemented with `ring`.
pub trait StateKey {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>>;
    fn open(&self, nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>>;
}

/// Every grammar of a login state.
pub fn state_valid(state: &LoginState) -> bool {
    is_thumbprint(&state.certificate)
        && is_id(&state.login)
        && is_provider(&state.provider)
        && is_kid(&state.replica)
        && is_scope(&state.scope)
        && is_text(&state.subject)
        && is_verifier(&state.verifier)
        && state.certificate_expires >= 0
        && state.certificate_expires <= MAX_INTEGER
        && state.issued_at >= 0
        && state.issued_at <= MAX_INTEGER
        && state.expires_at >= 0
        && state.expires_at <= MAX_INTEGER
}

/// The canonical plaintext of a login state.
pub fn state_bytes(state: &LoginState) -> Vec<u8> {
    let mut out = Vec::new();
    append(&mut out, b"{\"cert_exp\":");
    append_natural(&mut out, state.certificate_expires);
    append(&mut out, b",\"cnf\":");
    append_quoted(&mut out, &state.certificate);
    append(&mut out, b",\"exp\":");
    append_natural(&mut out, state.expires_at);
    append(&mut out, b",\"iat\":");
    append_natural(&mut out, state.issued_at);
    append(&mut out, b",\"login\":");
    append_quoted(&mut out, &state.login);
    append(&mut out, b",\"prv\":");
    append_quoted(&mut out, &state.provider);
    append(&mut out, b",\"rep\":");
    append_quoted(&mut out, &state.replica);
    append(&mut out, b",\"scope\":");
    append_quoted(&mut out, &state.scope);
    append(&mut out, b",\"sub\":");
    append_quoted(&mut out, &state.subject);
    append(&mut out, b",\"verifier\":");
    append_quoted(&mut out, &state.verifier);
    out.push(b'}');
    out
}

/// The one login state whose canonical plaintext is `bytes`, if any.
pub fn parse_state(bytes: &[u8]) -> Option<LoginState> {
    let (certificate_expires, i) = match number(bytes, 0, b"{\"cert_exp\":") {
        Some(found) => found,
        None => return None,
    };
    let (certificate, i) = match field(bytes, i, b",\"cnf\":") {
        Some(found) => found,
        None => return None,
    };
    let (expires_at, i) = match number(bytes, i, b",\"exp\":") {
        Some(found) => found,
        None => return None,
    };
    let (issued_at, i) = match number(bytes, i, b",\"iat\":") {
        Some(found) => found,
        None => return None,
    };
    let (login, i) = match field(bytes, i, b",\"login\":") {
        Some(found) => found,
        None => return None,
    };
    let (provider, i) = match field(bytes, i, b",\"prv\":") {
        Some(found) => found,
        None => return None,
    };
    let (replica, i) = match field(bytes, i, b",\"rep\":") {
        Some(found) => found,
        None => return None,
    };
    let (scope, i) = match field(bytes, i, b",\"scope\":") {
        Some(found) => found,
        None => return None,
    };
    let (subject, i) = match field(bytes, i, b",\"sub\":") {
        Some(found) => found,
        None => return None,
    };
    let (verifier, i) = match field(bytes, i, b",\"verifier\":") {
        Some(found) => found,
        None => return None,
    };
    if i + 1 != bytes.len() || bytes[i] != b'}' {
        return None;
    }
    let state = LoginState {
        login,
        provider,
        certificate,
        subject,
        certificate_expires,
        replica,
        scope,
        verifier,
        issued_at,
        expires_at,
    };
    if !state_valid(&state) {
        return None;
    }
    Some(state)
}

/// Seal a login state under the broker's state key with a fresh `nonce`.
pub fn seal_state<K: StateKey>(key: &K, state: &LoginState, nonce: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != NONCE || !state_valid(state) {
        return None;
    }
    let ciphertext = match key.seal(nonce, LOGIN_LABEL, &state_bytes(state)) {
        Some(ciphertext) => ciphertext,
        None => return None,
    };
    let mut sealed = Vec::new();
    append(&mut sealed, nonce);
    append(&mut sealed, &ciphertext);
    let mut out = Vec::new();
    append(&mut out, STATE_PREFIX);
    append(&mut out, &b64url(&sealed));
    if out.len() > MAX_STATE {
        return None;
    }
    Some(out)
}

/// Open a `state` parameter. Any forgery, truncation or foreign key fails.
pub fn open_state<K: StateKey>(key: &K, text: &[u8]) -> Result<LoginState, Rejection> {
    if text.len() > MAX_STATE || text.len() < STATE_PREFIX.len() {
        return Err(Rejection::Malformed);
    }
    let prefix: &[u8] = &text[..STATE_PREFIX.len()];
    if prefix != STATE_PREFIX {
        return Err(Rejection::Malformed);
    }
    let sealed = match from_b64url(&text[STATE_PREFIX.len()..]) {
        Some(sealed) => sealed,
        None => return Err(Rejection::Malformed),
    };
    if sealed.len() < NONCE + TAG + 1 {
        return Err(Rejection::Malformed);
    }
    let plain = match key.open(&sealed[..NONCE], LOGIN_LABEL, &sealed[NONCE..]) {
        Some(plain) => plain,
        None => return Err(Rejection::Undecryptable),
    };
    match parse_state(&plain) {
        Some(state) => Ok(state),
        None => Err(Rejection::Malformed),
    }
}
