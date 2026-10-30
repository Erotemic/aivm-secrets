//! Sealing a surrogate, and the one-shot `TokenSealer` (spec section 4).
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

/// Whether `needle` occurs in `haystack`.
pub fn occurs(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() == 0 {
        return true;
    }
    let mut found = false;
    let mut start = 0;
    while !found && start + needle.len() <= haystack.len() {
        let window: &[u8] = &haystack[start..start + needle.len()];
        if window == needle {
            found = true;
        }
        start += 1;
    }
    found
}

/// Sign and seal exactly `claims` around `credential` with `entry`, under the
/// fresh `nonce`. The credential never occurs in the public part.
pub fn seal_token<M: KeyMaterial>(
    entry: &KeyEntry<M>,
    info: &Informational,
    claims: &SurrogateClaims,
    credential: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Rejection> {
    if !http_auth::valid_credential(credential) || !is_kid(&entry.kid) || nonce.len() != NONCE {
        return Err(Rejection::InvalidCredential);
    }
    let header = header_bytes(&entry.kid);
    let mut payload = Payload {
        claims: copy_claims(claims),
        enc: Vec::new(),
        info: copy_info(info),
    };
    if !payload_valid(&payload) {
        return Err(Rejection::Malformed);
    }
    let public = payload_bytes(&payload, false);
    if occurs(&header, credential) || occurs(&public, credential) {
        return Err(Rejection::Malformed);
    }
    let aad = associated(&header, &public);
    let ciphertext = match entry.material.seal(nonce, &aad, credential) {
        Some(ciphertext) => ciphertext,
        None => return Err(Rejection::Undecryptable),
    };
    let mut sealed = Vec::new();
    append(&mut sealed, nonce);
    append(&mut sealed, &ciphertext);
    payload.enc = b64url(&sealed);
    let mut body = b64url(&header);
    body.push(b'.');
    append(&mut body, &b64url(&payload_bytes(&payload, true)));
    let signature = match entry.material.sign(&body) {
        Some(signature) => signature,
        None => return Err(Rejection::UnknownKey),
    };
    if signature.len() != SIGNATURE {
        return Err(Rejection::UnknownKey);
    }
    let mut token = body;
    token.push(b'.');
    append(&mut token, &b64url(&signature));
    if token.len() > MAX_TOKEN {
        return Err(Rejection::Malformed);
    }
    Ok(token)
}

pub fn copy_claims(claims: &SurrogateClaims) -> SurrogateClaims {
    let issuer: &[u8] = &claims.issuer;
    let audience: &[u8] = &claims.audience;
    let subject: &[u8] = &claims.subject;
    let token_id: &[u8] = &claims.token_id;
    let provider: &[u8] = &claims.provider;
    let certificate: &[u8] = &claims.certificate;
    SurrogateClaims {
        issuer: issuer.to_vec(),
        audience: audience.to_vec(),
        subject: subject.to_vec(),
        token_id: token_id.to_vec(),
        provider: provider.to_vec(),
        certificate: certificate.to_vec(),
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
        renew_until: claims.renew_until,
    }
}

pub fn copy_info(info: &Informational) -> Informational {
    let scope: &[u8] = &info.scope;
    let upstream: &[u8] = &info.upstream;
    Informational {
        has_scope: info.has_scope,
        scope: scope.to_vec(),
        has_upstream: info.has_upstream,
        upstream: upstream.to_vec(),
    }
}

/// The broker's sealer for one issuance: the signing entry, the informational
/// claims, and the AES-GCM nonce for that one seal.
///
/// The core has no randomness, so the caller supplies the nonce, and it must
/// never have been used with the entry's sealing key before (reusing an
/// AES-GCM nonce under one key breaks confidentiality and integrity). The
/// proofs do not establish this; it is the runtime obligation
/// `STATELESS-CRYPTO-01`. `seal` consumes the sealer, so one nonce seals at
/// most one surrogate.
pub struct TokenSealer<M> {
    entry: KeyEntry<M>,
    info: Informational,
    nonce: Vec<u8>,
}

impl<M> TokenSealer<M> {
    /// A sealer for one issuance; `nonce` must be fresh (see above).
    pub fn new(entry: KeyEntry<M>, info: Informational, nonce: Vec<u8>) -> TokenSealer<M> {
        TokenSealer { entry, info, nonce }
    }
}

impl<M: KeyMaterial> SurrogateSealer for TokenSealer<M> {
    fn seal(self, claims: &SurrogateClaims, credential: &[u8]) -> Result<Vec<u8>, Rejection> {
        seal_token(&self.entry, &self.info, claims, credential, &self.nonce)
    }
}

/// The informational claims of a token whose payload parses (for renewal,
/// after `stateless::open` accepted the same bytes).
pub fn informational(token: &[u8]) -> Option<Informational> {
    let (first, second) = match segments(token) {
        Some(found) => found,
        None => return None,
    };
    let bytes = match from_b64url(&token[first + 1..second]) {
        Some(bytes) => bytes,
        None => return None,
    };
    match parse_payload(&bytes) {
        Some(payload) => Some(payload.info),
        None => None,
    }
}
