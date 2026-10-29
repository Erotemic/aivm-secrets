//! The surrogate token's primitives and the broker's claim copying (spec
//! section 4). The codec itself, every byte signed, sealed and accepted, key
//! selection, and the opener and sealer the controllers use, is the
//! extracted `stateless_token`. This module supplies `ring`'s Ed25519 and
//! AES-256-GCM behind its `KeyMaterial`, and builds the informational claims.
use crate::encoding::{from_b64url, random};
use crate::json::{self, Value};
use garrett_stateless_core::stateless::{Rejection, SurrogateClaims};
use garrett_stateless_core::stateless_token::{
    self, KeyMaterial, StateKey, TokenSealer, MAX_TOKEN,
};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const TYP: &str = "garrett-stateless-v1+jwt";
pub const MAX_UPSTREAM: usize = 4096;

/// One key's material: the Ed25519 public key, the AES-256-GCM sealing key
/// and, for a broker key, the Ed25519 seed.
#[derive(Clone)]
pub struct RingKey {
    pub verify: [u8; 32],
    pub seal: Zeroizing<[u8; 32]>,
    pub sign: Option<Zeroizing<[u8; 32]>>,
}

fn aes(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("32-byte AES key"))
}

fn aes_seal(key: &[u8; 32], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    let mut data = plaintext.to_vec();
    aes(key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut data,
        )
        .ok()?;
    Some(data)
}

fn aes_open(key: &[u8; 32], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    let mut data = Zeroizing::new(sealed.to_vec());
    let plain = aes(key)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut data,
        )
        .ok()?;
    Some(plain.to_vec())
}

impl KeyMaterial for RingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, &self.verify)
            .verify(message, signature)
            .is_ok()
    }
    fn open(&self, nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        aes_open(&self.seal, nonce, aad, sealed)
    }
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let seed = self.sign.as_ref()?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed[..]).ok()?;
        Some(pair.sign(message).as_ref().to_vec())
    }
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        aes_seal(&self.seal, nonce, aad, plaintext)
    }
}

/// The broker's login-state key.
pub struct RingStateKey<'a>(pub &'a [u8; 32]);

impl StateKey for RingStateKey<'_> {
    fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        aes_seal(self.0, nonce, aad, plaintext)
    }
    fn open(&self, nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        aes_open(self.0, nonce, aad, sealed)
    }
}

/// Claims that inform the agent but never authorize anything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Informational {
    pub scope: Option<String>,
    pub upstream: Option<BTreeMap<String, Value>>,
}

impl Informational {
    /// The codec's form: the scope bytes and the canonical upstream object.
    pub fn encoded(&self) -> Result<stateless_token::Informational, Rejection> {
        let upstream = match &self.upstream {
            Some(map) => {
                json::canonical(&Value::Object(map.clone())).map_err(|_| Rejection::Malformed)?
            }
            None => Vec::new(),
        };
        Ok(stateless_token::Informational {
            has_scope: self.scope.is_some(),
            scope: self.scope.clone().unwrap_or_default().into_bytes(),
            has_upstream: self.upstream.is_some(),
            upstream,
        })
    }
}

/// The extracted sealer for one issuance by `entry`, with a fresh nonce.
pub fn sealer(
    entry: &crate::keys::KeyEntry,
    info: &Informational,
) -> Result<TokenSealer<RingKey>, Rejection> {
    sealer_with_nonce(
        entry,
        info,
        random::<12>().map_err(|_| Rejection::Undecryptable)?,
    )
}

/// The same sealer with a given nonce (conformance vectors only).
pub fn sealer_with_nonce(
    entry: &crate::keys::KeyEntry,
    info: &Informational,
    nonce: [u8; 12],
) -> Result<TokenSealer<RingKey>, Rejection> {
    Ok(TokenSealer {
        entry: entry.core(),
        info: info.encoded()?,
        nonce: nonce.to_vec(),
    })
}

/// Deterministic sealing for conformance vectors.
pub fn fixture_seal(
    entry: &crate::keys::KeyEntry,
    info: &Informational,
    claims: &SurrogateClaims,
    credential: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, Rejection> {
    let sealer = sealer_with_nonce(entry, info, nonce)?;
    stateless_token::seal_token(
        &sealer.entry,
        &sealer.info,
        claims,
        credential,
        &sealer.nonce,
    )
}

/// Decode a surrogate's header and payload **without verifying** it, for an
/// agent to inspect what it holds. Never use the result for a decision.
pub fn inspect(token: &str) -> Result<(Value, Value), Rejection> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Rejection::Malformed);
    };
    let header = json::parse(&from_b64url(h).ok_or(Rejection::Malformed)?, 1024, 2)
        .map_err(|_| Rejection::Malformed)?;
    let payload = json::parse(&from_b64url(p).ok_or(Rejection::Malformed)?, MAX_TOKEN, 16)
        .map_err(|_| Rejection::Malformed)?;
    Ok((header, payload))
}

fn copyable_scalar(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Int(_) => true,
        Value::Str(text) => text.len() <= 1024 && text.bytes().all(|b| (0x20..=0x7e).contains(&b)),
        _ => false,
    }
}

fn copyable(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.len() <= 32 && items.iter().all(copyable_scalar),
        other => copyable_scalar(other),
    }
}

fn copyable_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

/// Which provider claims a surrogate copies (spec section 4.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ClaimCopy {
    /// Only claims describing the access itself ([`DEFAULT_COPIED`]).
    #[default]
    Access,
    /// Every copyable claim, as Garrett proposes; may include personal data.
    All,
    /// Exactly these claim names.
    Only(Vec<String>),
}

/// The default copied claims: what the token grants, not who the user is.
pub const DEFAULT_COPIED: [&str; 10] = [
    "aud",
    "azp",
    "client_id",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "scope",
    "scp",
];

impl ClaimCopy {
    pub fn allows(&self, name: &str) -> bool {
        match self {
            ClaimCopy::Access => DEFAULT_COPIED.contains(&name),
            ClaimCopy::All => true,
            ClaimCopy::Only(names) => names.iter().any(|n| n == name),
        }
    }
}

/// Spec section 4.4: the copied claims of a provider JWT, or `None` for an
/// opaque token (or when the copy would exceed 4096 bytes).
pub fn copy_upstream(access_token: &str, policy: &ClaimCopy) -> Option<BTreeMap<String, Value>> {
    let mut parts = access_token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    from_b64url(h)?;
    from_b64url(s)?;
    let payload = json::parse(&from_b64url(p)?, MAX_TOKEN, 16).ok()?;
    let copied: BTreeMap<String, Value> = payload
        .as_object()?
        .iter()
        .filter(|(name, value)| copyable_name(name) && copyable(value) && policy.allows(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let size = json::canonical(&Value::Object(copied.clone())).ok()?.len();
    if size > MAX_UPSTREAM {
        return None;
    }
    Some(copied)
}

/// The informational claims of an authenticated token, to carry across a
/// renewal. Only call after `stateless::open` accepted the same bytes.
pub fn informational(token: &[u8]) -> Result<stateless_token::Informational, Rejection> {
    stateless_token::informational(token).ok_or(Rejection::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::b64url;
    use crate::keys::BrokerKeys;
    use garrett_stateless_core::stateless::{self, Acceptance, SurrogateOpener, SurrogateSealer};

    fn claims(peer: &str) -> SurrogateClaims {
        SurrogateClaims {
            issuer: b"https://broker.test".to_vec(),
            audience: b"https://proxy.test".to_vec(),
            subject: b"spiffe://test/agent".to_vec(),
            token_id: b"0123456789abcdef0123456789abcdef".to_vec(),
            provider: b"api".to_vec(),
            certificate: peer.as_bytes().to_vec(),
            issued_at: 1000,
            expires_at: 2000,
            renew_until: 5000,
        }
    }

    fn acceptance() -> Acceptance {
        Acceptance {
            audiences: vec![b"https://proxy.test".to_vec()],
            providers: vec![b"api".to_vec()],
            max_lifetime: 3600,
            skew: 0,
        }
    }

    const PEER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn seal_then_open() {
        let keys = BrokerKeys::generate("https://broker.test", "k1").unwrap();
        let sealer = sealer(keys.active_entry(), &Informational::default())
            .ok()
            .unwrap();
        let token = sealer.seal(&claims(PEER), b"real-token").ok().unwrap();
        let opener = keys.export_proxy().key_set().unwrap();
        let opened = stateless::open(&opener, &token, &acceptance(), PEER.as_bytes(), 1500)
            .ok()
            .unwrap();
        assert_eq!(opened.credential, b"real-token");
        assert!(!String::from_utf8_lossy(&token).contains("real-token"));
        let other = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(stateless::open(&opener, &token, &acceptance(), other.as_bytes(), 1500).is_err());
    }

    #[test]
    fn tampering_is_rejected() {
        let keys = BrokerKeys::generate("https://broker.test", "k1").unwrap();
        let sealer = sealer(keys.active_entry(), &Informational::default())
            .ok()
            .unwrap();
        let token =
            String::from_utf8(sealer.seal(&claims(PEER), b"real-token").ok().unwrap()).unwrap();
        let opener = keys.export_proxy().key_set().unwrap();
        let mut bytes = token.clone().into_bytes();
        let middle = token.find('.').unwrap() + 5;
        bytes[middle] = if bytes[middle] == b'A' { b'B' } else { b'A' };
        assert!(matches!(
            opener.verify(&bytes),
            Err(Rejection::BadSignature) | Err(Rejection::Malformed)
        ));
        let unknown = BrokerKeys::generate("https://broker.test", "k9")
            .unwrap()
            .export_proxy()
            .key_set()
            .unwrap();
        assert!(matches!(
            unknown.verify(token.as_bytes()),
            Err(Rejection::UnknownKey)
        ));
    }

    #[test]
    fn a_credential_in_the_public_claims_is_never_sealed() {
        let keys = BrokerKeys::generate("https://broker.test", "k1").unwrap();
        let info = Informational {
            scope: Some("read the-real-token".into()),
            upstream: None,
        };
        let sealer = sealer(keys.active_entry(), &info).ok().unwrap();
        assert!(sealer.seal(&claims(PEER), b"the-real-token").is_err());
    }

    #[test]
    fn upstream_claims_are_namespaced_and_filtered() {
        let payload =
            br#"{"aud":"api","exp":99,"nested":{"x":1},"roles":["a","b"],"f":1.5,"name":"\u00e9"}"#;
        let jwt = format!("{}.{}.{}", b64url(b"{}"), b64url(payload), b64url(b"sig"));
        let copied = copy_upstream(&jwt, &ClaimCopy::All).unwrap();
        assert_eq!(
            copied.keys().cloned().collect::<Vec<_>>(),
            vec!["aud", "exp", "roles"]
        );
        let access = copy_upstream(&jwt, &ClaimCopy::Access).unwrap();
        assert_eq!(
            access.keys().cloned().collect::<Vec<_>>(),
            vec!["aud", "exp"]
        );
        let only = copy_upstream(&jwt, &ClaimCopy::Only(vec!["roles".into()])).unwrap();
        assert_eq!(only.keys().cloned().collect::<Vec<_>>(), vec!["roles"]);
        assert!(copy_upstream("opaque-token", &ClaimCopy::All).is_none());
    }
}
