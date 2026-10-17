//! Exact Ed25519/AES-256-GCM nested surrogate profile. Crypto primitives are trusted.
use crate::{json, model, Error, Outcome};
use aivm_secrets_garrett_core::{self as core, Claims, Expectation};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};
use serde_json::json;
#[cfg(feature = "conformance")]
use serde_json::Value;
use zeroize::Zeroizing;

const AAD: &[u8] = b"aivm-secrets/identity/aes-gcm/v1\0";
pub const MAX_TOKEN: usize = 65536;
pub const MAX_INNER: usize = 16384;

/// No Debug, Display, Serialize, Clone or public plaintext accessor.
pub struct InnerCapability(Zeroizing<Vec<u8>>);
impl InnerCapability {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}
pub(crate) struct Opened {
    #[cfg(feature = "conformance")]
    pub(crate) claims: Claims,
    pub(crate) inner: InnerCapability,
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn decode(text: &str, limit: usize) -> Outcome<Vec<u8>> {
    if text.is_empty() || text.len() > limit {
        return Err(Error::InvalidCapability);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::InvalidCapability)?;
    if b64(&bytes) != text {
        return Err(Error::InvalidCapability);
    }
    Ok(bytes)
}
pub fn certificate_thumbprint(der: &[u8]) -> Outcome<String> {
    if der.is_empty() || der.len() > 65536 {
        return Err(Error::InvalidCapability);
    }
    Ok(b64(digest::digest(&digest::SHA256, der).as_ref()))
}
fn key(key: &[u8]) -> Outcome<aead::LessSafeKey> {
    Ok(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::InvalidCapability)?,
    ))
}
fn kid(value: &str) -> Outcome<String> {
    if value.is_empty()
        || value.len() > 32
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::InvalidCapability);
    }
    Ok(value.to_owned())
}
fn associated(claims: &Claims) -> Outcome<Vec<u8>> {
    let mut aad = AAD.to_vec();
    aad.extend(json::canonical(&model::claims_json(claims)?));
    Ok(aad)
}
fn inner_valid(inner: &[u8]) -> bool {
    inner.len() <= MAX_INNER && inner.starts_with(b"aivs1.") && inner.is_ascii()
}

pub struct Issuer {
    signer: signature::Ed25519KeyPair,
    sealer: aead::LessSafeKey,
    kid: String,
}
const ED25519_PKCS8: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const ED25519_SPKI: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
pub(crate) fn issuer_material() -> Outcome<(Zeroizing<String>, String, Zeroizing<Vec<u8>>)> {
    let mut seed = Zeroizing::new([0u8; 32]);
    let mut aes = Zeroizing::new(vec![0u8; 32]);
    SystemRandom::new()
        .fill(&mut *seed)
        .map_err(|_| Error::InternalError)?;
    SystemRandom::new()
        .fill(&mut aes)
        .map_err(|_| Error::InternalError)?;
    let pair =
        signature::Ed25519KeyPair::from_seed_unchecked(&*seed).map_err(|_| Error::InternalError)?;
    // RFC 8410 PKCS#8 v1 / SPKI, matching the Python authority's immutable files.
    let mut private = Zeroizing::new(ED25519_PKCS8.to_vec());
    private.extend_from_slice(&*seed);
    let mut public = ED25519_SPKI.to_vec();
    public.extend_from_slice(pair.public_key().as_ref());
    Ok((
        Zeroizing::new(crate::certificates::pem(&private, "PRIVATE KEY")),
        crate::certificates::pem(&public, "PUBLIC KEY"),
        aes,
    ))
}
pub(crate) fn issuer_public(pem: &[u8]) -> Outcome<Vec<u8>> {
    let der = crate::certificates::decode_pem(pem, "PUBLIC KEY", 4096)?;
    if der.len() != 44 || !der.starts_with(ED25519_SPKI) {
        return Err(Error::InvalidCapability);
    }
    Ok(der[12..].to_vec())
}
/// An unverified header only selects from the trusted enabled keyring. The
/// selected verifier still authenticates the complete token before unsealing.
pub(crate) fn token_key_id(token: &str) -> Outcome<String> {
    if token.len() > MAX_TOKEN {
        return Err(Error::InvalidCapability);
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidCapability);
    }
    let header = json::parse(&decode(parts[0], 1024)?, 1024)?;
    let map = json::keys(&header, &["alg", "typ", "kid"], &[])?;
    if map["alg"] != "EdDSA" || map["typ"] != "aivm-bound+jwt" {
        return Err(Error::InvalidCapability);
    }
    kid(map["kid"].as_str().ok_or(Error::InvalidCapability)?)
}
impl Issuer {
    pub(crate) fn from_pem(
        private: &[u8],
        public: &[u8],
        aes: &[u8],
        key_id: &str,
    ) -> Outcome<Self> {
        let der = crate::certificates::decode_pem(private, "PRIVATE KEY", 4096)?;
        if der.len() != 48 || !der.starts_with(ED25519_PKCS8) {
            return Err(Error::InvalidCapability);
        }
        let issuer = Self::new(&der[16..], aes, key_id)?;
        if issuer.public_key() != issuer_public(public)? {
            return Err(Error::InvalidCapability);
        }
        Ok(issuer)
    }
    pub fn new(seed: &[u8], encryption_key: &[u8], key_id: &str) -> Outcome<Self> {
        Ok(Self {
            signer: signature::Ed25519KeyPair::from_seed_unchecked(seed)
                .map_err(|_| Error::InvalidCapability)?,
            sealer: key(encryption_key)?,
            kid: kid(key_id)?,
        })
    }
    pub fn public_key(&self) -> &[u8] {
        self.signer.public_key().as_ref()
    }
    /// Trusted issuer input only. Enrollment-based issuance is the service API.
    pub fn issue(&self, claims: &Claims, inner: &[u8]) -> Outcome<String> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::InternalError)?;
        self.seal(claims, inner, nonce)
    }
    /// Enrollment-selected issuance uses the extracted controller before signing.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_for_enrollment(
        &self,
        registry: &model::Registry,
        issuer: &str,
        audience: &str,
        subject: &str,
        inner: &[u8],
        now: i64,
        lifetime: i64,
    ) -> Outcome<core::IssuedSurrogate> {
        let (input, secret) =
            Self::enrollment_material(registry, issuer, audience, subject, inner)?;
        core::issue_surrogate(self, input, now, lifetime, &secret)
            .map_err(|_| Error::InvalidCapability)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_observed<A: core::protocol::IssuanceObserver>(
        &self,
        observer: &A,
        registry: &model::Registry,
        issuer: &str,
        audience: &str,
        subject: &str,
        inner: &[u8],
        now: i64,
        lifetime: i64,
    ) -> Outcome<core::IssuedSurrogate> {
        let (input, secret) =
            Self::enrollment_material(registry, issuer, audience, subject, inner)?;
        core::protocol::issue_recorded(self, observer, input, now, lifetime, &secret)
            .map_err(|_| Error::InvalidCapability)
    }
    fn enrollment_material(
        registry: &model::Registry,
        issuer: &str,
        audience: &str,
        subject: &str,
        inner: &[u8],
    ) -> Outcome<(core::IssueInputs, InnerCapability)> {
        let mut id = [0; 16];
        SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| Error::InternalError)?;
        let token_id: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let input = registry.issue_inputs(issuer, audience, subject, &token_id)?;
        let secret = InnerCapability(Zeroizing::new(inner.to_vec()));
        Ok((input, secret))
    }
    fn seal(&self, claims: &Claims, inner: &[u8], nonce: [u8; 12]) -> Outcome<String> {
        let public = model::claims_json(claims)?;
        model::claims(&public)?;
        if !inner_valid(inner) {
            return Err(Error::InvalidCapability);
        }
        let mut ciphertext = Zeroizing::new(inner.to_vec());
        self.sealer
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(associated(claims)?),
                &mut *ciphertext,
            )
            .map_err(|_| Error::InvalidCapability)?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        let mut payload = public;
        payload
            .as_object_mut()
            .ok_or(Error::InvalidCapability)?
            .insert("enc".into(), json!(b64(&sealed)));
        let header = json!({"alg":"EdDSA","typ":"aivm-bound+jwt","kid":self.kid});
        let body = format!(
            "{}.{}",
            b64(&json::canonical(&header)),
            b64(&json::canonical(&payload))
        );
        let token = format!(
            "{}.{}",
            body,
            b64(self.signer.sign(body.as_bytes()).as_ref())
        );
        if token.len() > MAX_TOKEN {
            return Err(Error::InvalidCapability);
        }
        Ok(token)
    }
    #[cfg(feature = "conformance")]
    pub fn fixture_issue(&self, claims: &Claims, inner: &[u8], nonce: [u8; 12]) -> Outcome<String> {
        self.seal(claims, inner, nonce)
    }
}

pub struct Verifier {
    public_key: Vec<u8>,
    sealer: aead::LessSafeKey,
    kid: String,
}
impl Verifier {
    pub fn new(public_key: &[u8], encryption_key: &[u8], key_id: &str) -> Outcome<Self> {
        if public_key.len() != 32 {
            return Err(Error::InvalidCapability);
        }
        Ok(Self {
            public_key: public_key.to_vec(),
            sealer: key(encryption_key)?,
            kid: kid(key_id)?,
        })
    }
    pub(crate) fn open(
        &self,
        token: &str,
        peer: &crate::tls::VerifiedPeer,
        expected: &Expectation,
        now: i64,
    ) -> Outcome<Opened> {
        self.open_bound(token, peer.thumbprint(), expected, now)
    }
    fn open_bound(
        &self,
        token: &str,
        peer: &str,
        expected: &Expectation,
        now: i64,
    ) -> Outcome<Opened> {
        let peer = json::thumbprint(&json!(peer))?.into_bytes();
        let opened = core::open_surrogate(self, &token.as_bytes().to_vec(), expected, &peer, now)
            .map_err(|_| Error::InvalidCapability)?;
        Ok(Opened {
            #[cfg(feature = "conformance")]
            claims: opened.claims,
            inner: opened.secret,
        })
    }
    fn verify_token(&self, token: &str) -> Outcome<core::AuthenticatedEnvelope> {
        if token.len() > MAX_TOKEN {
            return Err(Error::InvalidCapability);
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidCapability);
        }
        let (h, p, sig) = (
            decode(parts[0], MAX_TOKEN)?,
            decode(parts[1], MAX_TOKEN)?,
            decode(parts[2], MAX_TOKEN)?,
        );
        let header = json::parse(&h, MAX_TOKEN)?;
        json::keys(&header, &["alg", "typ", "kid"], &[])?;
        if header != json!({"alg":"EdDSA","typ":"aivm-bound+jwt","kid":self.kid})
            || json::canonical(&header) != h
        {
            return Err(Error::InvalidCapability);
        }
        let body = format!("{}.{}", parts[0], parts[1]);
        signature::UnparsedPublicKey::new(&signature::ED25519, &self.public_key)
            .verify(body.as_bytes(), &sig)
            .map_err(|_| Error::InvalidCapability)?;
        let mut payload = json::parse(&p, MAX_TOKEN)?;
        json::keys(
            &payload,
            &[
                "iss", "aud", "sub", "jti", "iat", "exp", "epoch", "cnf", "enc",
            ],
            &[],
        )?;
        if json::canonical(&payload) != p {
            return Err(Error::InvalidCapability);
        }
        let enc = payload
            .as_object_mut()
            .ok_or(Error::InvalidCapability)?
            .remove("enc")
            .ok_or(Error::InvalidCapability)?;
        let claims = model::claims(&payload)?;
        Ok(core::AuthenticatedEnvelope {
            claims,
            encrypted: enc
                .as_str()
                .ok_or(Error::InvalidCapability)?
                .as_bytes()
                .to_vec(),
        })
    }
    fn unseal_token(&self, envelope: &core::AuthenticatedEnvelope) -> Outcome<InnerCapability> {
        let mut ciphertext = Zeroizing::new(decode(
            std::str::from_utf8(&envelope.encrypted).map_err(|_| Error::InvalidCapability)?,
            MAX_TOKEN,
        )?);
        if ciphertext.len() < 29 {
            return Err(Error::InvalidCapability);
        }
        let nonce: [u8; 12] = ciphertext[..12]
            .try_into()
            .map_err(|_| Error::InvalidCapability)?;
        let plain = self
            .sealer
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(associated(&envelope.claims)?),
                &mut ciphertext[12..],
            )
            .map_err(|_| Error::InvalidCapability)?;
        if !inner_valid(plain) {
            return Err(Error::InvalidCapability);
        }
        Ok(InnerCapability(Zeroizing::new(plain.to_vec())))
    }
    #[cfg(feature = "conformance")]
    pub fn fixture_open(
        &self,
        token: &str,
        der: &[u8],
        expected: &Expectation,
        now: i64,
    ) -> Outcome<Value> {
        let opened = self.open_bound(token, &certificate_thumbprint(der)?, expected, now)?;
        Ok(
            json!({"ok":true,"claims":model::claims_json(&opened.claims)?,
            "inner_capability":std::str::from_utf8(opened.inner.bytes()).map_err(|_|Error::InvalidCapability)?}),
        )
    }
}

impl core::EnvelopeVerifier for Verifier {
    type Secret = InnerCapability;
    fn verify(&self, token: &Vec<u8>) -> Result<core::AuthenticatedEnvelope, core::Denial> {
        let text = std::str::from_utf8(token).map_err(|_| core::Denial::InvalidCapability)?;
        self.verify_token(text)
            .map_err(|_| core::Denial::InvalidCapability)
    }
    fn unseal(&self, envelope: &core::AuthenticatedEnvelope) -> Result<Self::Secret, core::Denial> {
        self.unseal_token(envelope)
            .map_err(|_| core::Denial::InvalidCapability)
    }
}

impl core::EnvelopeIssuer for Issuer {
    type Secret = InnerCapability;
    fn seal(&self, claims: &Claims, secret: &Self::Secret) -> Result<Vec<u8>, core::Denial> {
        self.issue(claims, secret.bytes())
            .map(String::into_bytes)
            .map_err(|_| core::Denial::InvalidCapability)
    }
}
