//! The surrogate token codec (spec section 4): the signing and sealing
//! adapter behind the extracted `stateless::SurrogateSealer`, and the
//! verifying and unsealing adapter behind `stateless::SurrogateOpener`.
use crate::encoding::{
    b64url, from_b64url, is_id, is_kid, is_provider, is_scope, is_text, is_thumbprint, random,
};
use crate::json::{self, Value, MAX_INTEGER};
use crate::keys::KeyEntry;
use aivm_secrets_garrett_core::stateless::{
    Rejection, SurrogateClaims, SurrogateOpener, SurrogateSealer, Verified,
};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::signature::{UnparsedPublicKey, ED25519};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const TYP: &str = "garrett-stateless-v1+jwt";
pub const MAX_TOKEN: usize = 16384;
pub const MAX_UPSTREAM: usize = 4096;
const CREDENTIAL_LABEL: &[u8] = b"garrett-stateless-v1/credential\0";
const REQUIRED: [&str; 10] = [
    "aud", "cnf", "enc", "exp", "iat", "iss", "jti", "prv", "ren", "sub",
];
const OPTIONAL: [&str; 2] = ["scope", "upstream"];

/// Claims that inform the agent but never authorize anything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Informational {
    pub scope: Option<String>,
    pub upstream: Option<BTreeMap<String, Value>>,
}

fn header(kid: &str) -> Value {
    json::object([
        ("alg", json::text("EdDSA")),
        ("kid", json::text(kid)),
        ("typ", json::text(TYP)),
    ])
}

fn utf8(bytes: &[u8]) -> Result<&str, Rejection> {
    std::str::from_utf8(bytes).map_err(|_| Rejection::Malformed)
}

fn int(value: i64) -> Result<Value, Rejection> {
    if !(0..=MAX_INTEGER).contains(&value) {
        return Err(Rejection::Malformed);
    }
    Ok(Value::Int(value))
}

/// The payload without `enc`, after checking every grammar.
fn public_payload(
    claims: &SurrogateClaims,
    info: &Informational,
) -> Result<BTreeMap<String, Value>, Rejection> {
    let issuer = utf8(&claims.issuer)?;
    let audience = utf8(&claims.audience)?;
    let subject = utf8(&claims.subject)?;
    let token_id = utf8(&claims.token_id)?;
    let provider = utf8(&claims.provider)?;
    let certificate = utf8(&claims.certificate)?;
    if !is_text(issuer)
        || !is_text(audience)
        || !is_text(subject)
        || !is_id(token_id)
        || !is_provider(provider)
        || !is_thumbprint(certificate)
    {
        return Err(Rejection::Malformed);
    }
    let mut map = BTreeMap::new();
    map.insert("iss".into(), json::text(issuer));
    map.insert("aud".into(), json::text(audience));
    map.insert("sub".into(), json::text(subject));
    map.insert("jti".into(), json::text(token_id));
    map.insert("prv".into(), json::text(provider));
    map.insert(
        "cnf".into(),
        json::object([("x5t#S256", json::text(certificate))]),
    );
    map.insert("iat".into(), int(claims.issued_at)?);
    map.insert("exp".into(), int(claims.expires_at)?);
    map.insert("ren".into(), int(claims.renew_until)?);
    if let Some(scope) = &info.scope {
        if !is_scope(scope) {
            return Err(Rejection::Malformed);
        }
        map.insert("scope".into(), json::text(scope));
    }
    if let Some(upstream) = &info.upstream {
        map.insert("upstream".into(), Value::Object(upstream.clone()));
    }
    Ok(map)
}

fn associated(header: &[u8], public: &[u8]) -> Vec<u8> {
    let mut aad = CREDENTIAL_LABEL.to_vec();
    aad.extend_from_slice(header);
    aad.push(0);
    aad.extend_from_slice(public);
    aad
}

fn sealing_key(entry: &KeyEntry) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM, entry.seal_key()).expect("32-byte AES key"))
}

/// Signs with one broker key entry. The informational claims are carried
/// by the adapter; the extracted controller chooses every other claim.
pub struct Sealer<'a> {
    pub entry: &'a KeyEntry,
    pub info: Informational,
}

impl Sealer<'_> {
    fn seal_with_nonce(
        &self,
        claims: &SurrogateClaims,
        credential: &[u8],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>, Rejection> {
        if !crate::encoding::is_credential(credential) || !is_kid(&self.entry.kid) {
            return Err(Rejection::InvalidCredential);
        }
        let header = json::canonical(&header(&self.entry.kid)).map_err(|_| Rejection::Malformed)?;
        let mut payload = public_payload(claims, &self.info)?;
        let public =
            json::canonical(&Value::Object(payload.clone())).map_err(|_| Rejection::Malformed)?;
        let mut sealed = Zeroizing::new(credential.to_vec());
        sealing_key(self.entry)
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(associated(&header, &public)),
                &mut *sealed,
            )
            .map_err(|_| Rejection::Undecryptable)?;
        let mut enc = nonce.to_vec();
        enc.extend_from_slice(&sealed);
        payload.insert("enc".into(), json::text(&b64url(&enc)));
        let payload = json::canonical(&Value::Object(payload)).map_err(|_| Rejection::Malformed)?;
        let body = format!("{}.{}", b64url(&header), b64url(&payload));
        let signature = self
            .entry
            .signer()
            .map_err(|_| Rejection::UnknownKey)?
            .sign(body.as_bytes());
        let token = format!("{}.{}", body, b64url(signature.as_ref()));
        if token.len() > MAX_TOKEN {
            return Err(Rejection::Malformed);
        }
        Ok(token.into_bytes())
    }

    /// Deterministic sealing for conformance vectors only.
    pub fn fixture_seal(
        &self,
        claims: &SurrogateClaims,
        credential: &[u8],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>, Rejection> {
        self.seal_with_nonce(claims, credential, nonce)
    }
}

impl SurrogateSealer for Sealer<'_> {
    fn seal(&self, claims: &SurrogateClaims, credential: &[u8]) -> Result<Vec<u8>, Rejection> {
        let nonce = random::<12>().map_err(|_| Rejection::Undecryptable)?;
        self.seal_with_nonce(claims, credential, nonce)
    }
}

/// Verifies against a set of configured key entries (any `kid` listed).
pub struct Opener<'a> {
    pub keys: &'a [KeyEntry],
}

fn string_claim(
    map: &BTreeMap<String, Value>,
    name: &str,
    valid: fn(&str) -> bool,
) -> Result<Vec<u8>, Rejection> {
    let text = map
        .get(name)
        .and_then(Value::as_str)
        .ok_or(Rejection::Malformed)?;
    if !valid(text) {
        return Err(Rejection::Malformed);
    }
    Ok(text.as_bytes().to_vec())
}

fn time_claim(map: &BTreeMap<String, Value>, name: &str) -> Result<i64, Rejection> {
    let value = map
        .get(name)
        .and_then(Value::as_int)
        .ok_or(Rejection::Malformed)?;
    if value < 0 {
        return Err(Rejection::Malformed);
    }
    Ok(value)
}

/// The three segments of a token, each strictly decoded.
fn segments(token: &[u8]) -> Result<(&str, &str, &str), Rejection> {
    if token.len() > MAX_TOKEN || !token.is_ascii() {
        return Err(Rejection::Malformed);
    }
    let text = utf8(token)?;
    let mut parts = text.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Rejection::Malformed);
    };
    Ok((h, p, s))
}

/// The header's `kid`, if the header is exactly the version-1 header.
fn header_kid(encoded: &str) -> Result<(String, Vec<u8>), Rejection> {
    let bytes = from_b64url(encoded).ok_or(Rejection::Malformed)?;
    let value = json::parse(&bytes, 1024, 2).map_err(|_| Rejection::Malformed)?;
    let kid = value
        .get("kid")
        .and_then(Value::as_str)
        .filter(|k| is_kid(k))
        .ok_or(Rejection::Malformed)?;
    if value != header(kid) || json::canonical(&value).map_err(|_| Rejection::Malformed)? != bytes {
        return Err(Rejection::Malformed);
    }
    Ok((kid.to_owned(), bytes))
}

impl SurrogateOpener for Opener<'_> {
    fn verify(&self, token: &[u8]) -> Result<Verified, Rejection> {
        let (h, p, s) = segments(token)?;
        let (kid, header_bytes) = header_kid(h)?;
        let key = self
            .keys
            .iter()
            .position(|e| e.kid == kid)
            .ok_or(Rejection::UnknownKey)?;
        let entry = &self.keys[key];
        let signature = from_b64url(s)
            .filter(|sig| sig.len() == 64)
            .ok_or(Rejection::Malformed)?;
        let signed = &token[..h.len() + 1 + p.len()];
        UnparsedPublicKey::new(&ED25519, &entry.verify)
            .verify(signed, &signature)
            .map_err(|_| Rejection::BadSignature)?;
        // Authenticated from here on; still strictly parsed.
        let payload_bytes = from_b64url(p).ok_or(Rejection::Malformed)?;
        let payload =
            json::parse(&payload_bytes, MAX_TOKEN, 16).map_err(|_| Rejection::Malformed)?;
        if json::canonical(&payload).map_err(|_| Rejection::Malformed)? != payload_bytes {
            return Err(Rejection::Malformed);
        }
        let mut map = payload.as_object().ok_or(Rejection::Malformed)?.clone();
        if !REQUIRED.iter().all(|k| map.contains_key(*k))
            || !map
                .keys()
                .all(|k| REQUIRED.contains(&k.as_str()) || OPTIONAL.contains(&k.as_str()))
        {
            return Err(Rejection::Malformed);
        }
        if let Some(scope) = map.get("scope") {
            if !scope.as_str().is_some_and(is_scope) {
                return Err(Rejection::Malformed);
            }
        }
        if let Some(upstream) = map.get("upstream") {
            upstream.as_object().ok_or(Rejection::Malformed)?;
        }
        let cnf = map
            .get("cnf")
            .and_then(Value::as_object)
            .ok_or(Rejection::Malformed)?;
        if cnf.len() != 1 {
            return Err(Rejection::Malformed);
        }
        let certificate = string_claim(cnf, "x5t#S256", is_thumbprint)?;
        let claims = SurrogateClaims {
            issuer: string_claim(&map, "iss", is_text)?,
            audience: string_claim(&map, "aud", is_text)?,
            subject: string_claim(&map, "sub", is_text)?,
            token_id: string_claim(&map, "jti", is_id)?,
            provider: string_claim(&map, "prv", is_provider)?,
            certificate,
            issued_at: time_claim(&map, "iat")?,
            expires_at: time_claim(&map, "exp")?,
            renew_until: time_claim(&map, "ren")?,
        };
        let enc = map.remove("enc").ok_or(Rejection::Malformed)?;
        let sealed = enc
            .as_str()
            .and_then(from_b64url)
            .ok_or(Rejection::Malformed)?;
        if sealed.len() < 12 + 16 + 1 {
            return Err(Rejection::Malformed);
        }
        let public = json::canonical(&Value::Object(map)).map_err(|_| Rejection::Malformed)?;
        Ok(Verified {
            key,
            key_issuer: entry.issuer.as_bytes().to_vec(),
            claims,
            aad: associated(&header_bytes, &public),
            sealed,
        })
    }

    fn unseal(&self, verified: &Verified) -> Result<Vec<u8>, Rejection> {
        let entry = self.keys.get(verified.key).ok_or(Rejection::UnknownKey)?;
        let nonce: [u8; 12] = verified.sealed[..12]
            .try_into()
            .map_err(|_| Rejection::Malformed)?;
        let mut data = Zeroizing::new(verified.sealed[12..].to_vec());
        let plain = sealing_key(entry)
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(verified.aad.clone()),
                &mut data,
            )
            .map_err(|_| Rejection::Undecryptable)?;
        Ok(plain.to_vec())
    }
}

/// The informational claims of an authenticated token, to carry across a
/// renewal. Only call after `stateless::open` accepted the same bytes.
pub fn informational(token: &[u8]) -> Result<Informational, Rejection> {
    let (_, p, _) = segments(token)?;
    let payload = json::parse(&from_b64url(p).ok_or(Rejection::Malformed)?, MAX_TOKEN, 16)
        .map_err(|_| Rejection::Malformed)?;
    Ok(Informational {
        scope: payload
            .get("scope")
            .and_then(Value::as_str)
            .map(str::to_owned),
        upstream: payload.get("upstream").and_then(Value::as_object).cloned(),
    })
}

/// Decode a surrogate's header and payload **without verifying** it, for an
/// agent to inspect what it holds. Never use the result for a decision.
pub fn inspect(token: &str) -> Result<(Value, Value), Rejection> {
    let (h, p, _) = segments(token.as_bytes())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::BrokerKeys;
    use aivm_secrets_garrett_core::stateless::{self, Acceptance};

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
        let sealer = Sealer {
            entry: keys.active_entry(),
            info: Informational::default(),
        };
        let token = sealer.seal(&claims(PEER), b"real-token").ok().unwrap();
        let proxy = keys.export_proxy();
        let opener = Opener {
            keys: &proxy.entries,
        };
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
        let sealer = Sealer {
            entry: keys.active_entry(),
            info: Informational::default(),
        };
        let token =
            String::from_utf8(sealer.seal(&claims(PEER), b"real-token").ok().unwrap()).unwrap();
        let proxy = keys.export_proxy();
        let opener = Opener {
            keys: &proxy.entries,
        };
        let mut bytes = token.clone().into_bytes();
        let middle = token.find('.').unwrap() + 5;
        bytes[middle] = if bytes[middle] == b'A' { b'B' } else { b'A' };
        assert!(matches!(
            opener.verify(&bytes),
            Err(Rejection::BadSignature) | Err(Rejection::Malformed)
        ));
        let unknown = BrokerKeys::generate("https://broker.test", "k9")
            .unwrap()
            .export_proxy();
        assert!(matches!(
            Opener {
                keys: &unknown.entries
            }
            .verify(token.as_bytes()),
            Err(Rejection::UnknownKey)
        ));
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
