//! `garrett-stateless-v1` surrogate admission and issuance
//! (`docs/garrett-stateless-v1.md` sections 5 and 7).
//!
//! Signature verification, authenticated decryption and JSON decoding are
//! adapters behind [`SurrogateOpener`] and [`SurrogateSealer`]. This module
//! fixes their order and every comparison of an authoritative claim. No
//! function here reads stored state: each decision is a function of its
//! arguments (token, key-set adapter, policy, authenticated peer, clock),
//! which is what lets independent proxy replicas accept the same surrogate.

use crate::http_auth;

/// Largest time value (`2^53 - 1`), so every sum below stays far from overflow.
pub const MAX_TIME: i64 = 9007199254740991;
/// Hard cap on `exp - iat` for any acceptance or issuance policy.
pub const MAX_LIFETIME: i64 = 86400;
/// Hard cap on `ren - iat`.
pub const MAX_RENEW: i64 = 2592000;
/// Hard cap on the accepted clock skew.
pub const MAX_SKEW: i64 = 300;

/// Why a surrogate was not accepted or not issued. Only diagnostics see
/// the distinction; clients get one fixed refusal.
pub enum Rejection {
    Malformed,
    UnknownKey,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    UnknownProvider,
    BadLifetime,
    NotYetValid,
    Expired,
    WrongCertificate,
    Undecryptable,
    InvalidCredential,
    BadPolicy,
}

/// The authoritative claims of a surrogate (`iss`, `aud`, `sub`, `jti`,
/// `prv`, `cnf`, `iat`, `exp`, `ren`). Informational claims (`scope`,
/// `upstream`) are never decision inputs and are not represented here.
pub struct SurrogateClaims {
    pub issuer: Vec<u8>,
    pub audience: Vec<u8>,
    pub subject: Vec<u8>,
    pub token_id: Vec<u8>,
    pub provider: Vec<u8>,
    /// The `cnf.x5t#S256` certificate thumbprint.
    pub certificate: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub renew_until: i64,
}

/// A token whose header and signature the opener has verified under one
/// configured key. `key_issuer` is the issuer configured for that key;
/// `key`, `aad` and `sealed` are opaque to this module and returned to
/// `unseal`.
pub struct Verified {
    pub key: usize,
    pub key_issuer: Vec<u8>,
    pub claims: SurrogateClaims,
    pub aad: Vec<u8>,
    pub sealed: Vec<u8>,
}

/// What a proxy (or the broker, for renewal) accepts.
pub struct Acceptance {
    pub audiences: Vec<Vec<u8>>,
    pub providers: Vec<Vec<u8>>,
    pub max_lifetime: i64,
    pub skew: i64,
}

pub fn member(set: &[Vec<u8>], value: &[u8]) -> bool {
    for item in set {
        let item: &[u8] = item;
        if item == value {
            return true;
        }
    }
    false
}

pub fn acceptance_valid(acceptance: &Acceptance) -> bool {
    acceptance.max_lifetime >= 1
        && acceptance.max_lifetime <= MAX_LIFETIME
        && acceptance.skew >= 0
        && acceptance.skew <= MAX_SKEW
}

/// `iat < exp <= iat + max_lifetime` and `exp <= ren <= iat + MAX_RENEW`.
pub fn lifetime_valid(claims: &SurrogateClaims, max_lifetime: i64) -> bool {
    claims.issued_at >= 0
        && claims.issued_at <= MAX_TIME
        && claims.expires_at > claims.issued_at
        && claims.expires_at - claims.issued_at <= max_lifetime
        && claims.renew_until >= claims.expires_at
        && claims.renew_until - claims.issued_at <= MAX_RENEW
}

/// Every authoritative claim against the acceptance policy, the issuer
/// configured for the verifying key, the authenticated peer and the clock.
pub fn admit(
    claims: &SurrogateClaims,
    key_issuer: &[u8],
    acceptance: &Acceptance,
    peer: &[u8],
    now: i64,
) -> Result<(), Rejection> {
    if !acceptance_valid(acceptance) || now < 0 || now > MAX_TIME {
        return Err(Rejection::BadPolicy);
    }
    let issuer: &[u8] = &claims.issuer;
    if !(issuer == key_issuer) {
        return Err(Rejection::WrongIssuer);
    }
    if !member(&acceptance.audiences, &claims.audience) {
        return Err(Rejection::WrongAudience);
    }
    if !member(&acceptance.providers, &claims.provider) {
        return Err(Rejection::UnknownProvider);
    }
    if !lifetime_valid(claims, acceptance.max_lifetime) {
        return Err(Rejection::BadLifetime);
    }
    if now + acceptance.skew < claims.issued_at {
        return Err(Rejection::NotYetValid);
    }
    if now >= claims.expires_at {
        return Err(Rejection::Expired);
    }
    let certificate: &[u8] = &claims.certificate;
    if !(certificate == peer) {
        return Err(Rejection::WrongCertificate);
    }
    Ok(())
}

/// The key-set adapter: `verify` authenticates the header and signature
/// and decodes the claims; `unseal` opens `enc` with the same key.
pub trait SurrogateOpener {
    fn verify(&self, token: &[u8]) -> Result<Verified, Rejection>;
    fn unseal(&self, verified: &Verified) -> Result<Vec<u8>, Rejection>;
}

pub struct Opened {
    pub claims: SurrogateClaims,
    pub credential: Vec<u8>,
}

/// Verify, then admit, then (only then) decrypt. The production proxy and
/// the broker's renewal both open surrogates through this function.
pub fn open<V: SurrogateOpener>(
    opener: &V,
    token: &[u8],
    acceptance: &Acceptance,
    peer: &[u8],
    now: i64,
) -> Result<Opened, Rejection> {
    let verified = match opener.verify(token) {
        Ok(verified) => verified,
        Err(error) => return Err(error),
    };
    match admit(
        &verified.claims,
        &verified.key_issuer,
        acceptance,
        peer,
        now,
    ) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    let credential = match opener.unseal(&verified) {
        Ok(credential) => credential,
        Err(error) => return Err(error),
    };
    if !http_auth::valid_credential(&credential) {
        return Err(Rejection::InvalidCredential);
    }
    Ok(Opened {
        claims: verified.claims,
        credential,
    })
}

/// The first half of [`open`]: verify, then admit for this peer, and stop
/// before decrypting. The proxy authorizes the operation between this and
/// [`decrypt`], so a refused operation never has its credential unsealed.
pub fn authenticate<V: SurrogateOpener>(
    opener: &V,
    token: &[u8],
    acceptance: &Acceptance,
    peer: &[u8],
    now: i64,
) -> Result<Verified, Rejection> {
    let verified = match opener.verify(token) {
        Ok(verified) => verified,
        Err(error) => return Err(error),
    };
    match admit(
        &verified.claims,
        &verified.key_issuer,
        acceptance,
        peer,
        now,
    ) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    Ok(verified)
}

/// The second half of [`open`]: unseal an authenticated surrogate and
/// check the credential.
pub fn decrypt<V: SurrogateOpener>(opener: &V, verified: Verified) -> Result<Opened, Rejection> {
    let credential = match opener.unseal(&verified) {
        Ok(credential) => credential,
        Err(error) => return Err(error),
    };
    if !http_auth::valid_credential(&credential) {
        return Err(Rejection::InvalidCredential);
    }
    Ok(Opened {
        claims: verified.claims,
        credential,
    })
}

/// What the broker issues for.
pub struct IssuePolicy {
    pub issuer: Vec<u8>,
    pub audience: Vec<u8>,
    pub providers: Vec<Vec<u8>>,
    pub max_lifetime: i64,
    pub max_renew: i64,
}

/// One credential to wrap and the agent to bind it to. `certificate` and
/// `subject` come from the certificate the agent authenticated with;
/// `credential_expires` is `MAX_TIME` when the provider gave no expiry.
pub struct Grant {
    pub provider: Vec<u8>,
    pub subject: Vec<u8>,
    pub certificate: Vec<u8>,
    pub certificate_expires: i64,
    pub credential_expires: i64,
}

pub struct Window {
    pub issued_at: i64,
    pub expires_at: i64,
    pub renew_until: i64,
}

pub fn earlier(a: i64, b: i64) -> i64 {
    if a <= b {
        a
    } else {
        b
    }
}

/// `ren = min(now + max_renew, certificate expiry, credential expiry)` and
/// `exp = min(now + lifetime, ren)`, refusing an empty window.
pub fn issue_window(
    policy: &IssuePolicy,
    grant: &Grant,
    now: i64,
    lifetime: i64,
) -> Result<Window, Rejection> {
    if policy.max_lifetime < 1
        || policy.max_lifetime > MAX_LIFETIME
        || policy.max_renew < 0
        || policy.max_renew > MAX_RENEW
    {
        return Err(Rejection::BadPolicy);
    }
    if now < 0 || now > MAX_TIME - MAX_RENEW {
        return Err(Rejection::BadPolicy);
    }
    if lifetime < 1 || lifetime > policy.max_lifetime {
        return Err(Rejection::BadLifetime);
    }
    let cap = earlier(grant.certificate_expires, grant.credential_expires);
    let renew_until = earlier(now + policy.max_renew, cap);
    let expires_at = earlier(now + lifetime, renew_until);
    if expires_at <= now {
        return Err(Rejection::Expired);
    }
    Ok(Window {
        issued_at: now,
        expires_at,
        renew_until,
    })
}

/// The credential expiry from an optional `expires_in`.
pub fn credential_expiry(
    now: i64,
    has_expires_in: bool,
    expires_in: i64,
) -> Result<i64, Rejection> {
    if now < 0 || now > MAX_TIME {
        return Err(Rejection::BadPolicy);
    }
    if !has_expires_in {
        return Ok(MAX_TIME);
    }
    if expires_in < 1 || expires_in > MAX_TIME - now {
        return Err(Rejection::Malformed);
    }
    Ok(now + expires_in)
}

/// The claims for one issuance: issuer and audience from the policy, the
/// binding from the grant, a window from [`issue_window`].
pub fn claims_for(
    policy: &IssuePolicy,
    grant: Grant,
    token_id: &[u8],
    now: i64,
    lifetime: i64,
) -> Result<SurrogateClaims, Rejection> {
    if !member(&policy.providers, &grant.provider) {
        return Err(Rejection::UnknownProvider);
    }
    let window = match issue_window(policy, &grant, now, lifetime) {
        Ok(window) => window,
        Err(error) => return Err(error),
    };
    let issuer: &[u8] = &policy.issuer;
    let audience: &[u8] = &policy.audience;
    Ok(SurrogateClaims {
        issuer: issuer.to_vec(),
        audience: audience.to_vec(),
        subject: grant.subject,
        token_id: token_id.to_vec(),
        provider: grant.provider,
        certificate: grant.certificate,
        issued_at: window.issued_at,
        expires_at: window.expires_at,
        renew_until: window.renew_until,
    })
}

/// Signs and seals exactly the given claims around the credential.
pub trait SurrogateSealer {
    fn seal(&self, claims: &SurrogateClaims, credential: &[u8]) -> Result<Vec<u8>, Rejection>;
}

pub struct Issued {
    pub claims: SurrogateClaims,
    pub token: Vec<u8>,
}

/// One issuance: a valid credential, the claims of [`claims_for`], then
/// sealing. Nothing is sealed if any check fails.
pub fn issue<S: SurrogateSealer>(
    sealer: &S,
    policy: &IssuePolicy,
    grant: Grant,
    credential: &[u8],
    token_id: &[u8],
    now: i64,
    lifetime: i64,
) -> Result<Issued, Rejection> {
    if !http_auth::valid_credential(credential) {
        return Err(Rejection::InvalidCredential);
    }
    let claims = match claims_for(policy, grant, token_id, now, lifetime) {
        Ok(claims) => claims,
        Err(error) => return Err(error),
    };
    let token = match sealer.seal(&claims, credential) {
        Ok(token) => token,
        Err(error) => return Err(error),
    };
    Ok(Issued { claims, token })
}

/// The grant a renewal re-issues: the opened token's provider, subject and
/// binding, with its `ren` as the credential expiry so `ren` never grows.
pub fn renewal_grant(claims: &SurrogateClaims, certificate_expires: i64) -> Grant {
    let provider: &[u8] = &claims.provider;
    let subject: &[u8] = &claims.subject;
    let certificate: &[u8] = &claims.certificate;
    Grant {
        provider: provider.to_vec(),
        subject: subject.to_vec(),
        certificate: certificate.to_vec(),
        certificate_expires,
        credential_expires: claims.renew_until,
    }
}

/// Stateless renewal: open the presented surrogate for this peer, then
/// issue a new one for the same binding and credential.
#[allow(clippy::too_many_arguments)]
pub fn renew<V: SurrogateOpener, S: SurrogateSealer>(
    opener: &V,
    sealer: &S,
    acceptance: &Acceptance,
    policy: &IssuePolicy,
    token: &[u8],
    peer: &[u8],
    certificate_expires: i64,
    token_id: &[u8],
    now: i64,
    lifetime: i64,
) -> Result<Issued, Rejection> {
    let opened = match open(opener, token, acceptance, peer, now) {
        Ok(opened) => opened,
        Err(error) => return Err(error),
    };
    let grant = renewal_grant(&opened.claims, certificate_expires);
    issue(
        sealer,
        policy,
        grant,
        &opened.credential,
        token_id,
        now,
        lifetime,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> SurrogateClaims {
        SurrogateClaims {
            issuer: b"https://broker".to_vec(),
            audience: b"https://proxy".to_vec(),
            subject: b"agent".to_vec(),
            token_id: b"00".to_vec(),
            provider: b"github".to_vec(),
            certificate: b"PEER".to_vec(),
            issued_at: 1000,
            expires_at: 4600,
            renew_until: 10000,
        }
    }

    fn acceptance() -> Acceptance {
        Acceptance {
            audiences: vec![b"https://proxy".to_vec()],
            providers: vec![b"github".to_vec()],
            max_lifetime: 3600,
            skew: 60,
        }
    }

    struct Fixed {
        claims: fn() -> SurrogateClaims,
        unsealed: std::cell::Cell<bool>,
    }
    impl SurrogateOpener for Fixed {
        fn verify(&self, _token: &[u8]) -> Result<Verified, Rejection> {
            Ok(Verified {
                key: 0,
                key_issuer: b"https://broker".to_vec(),
                claims: (self.claims)(),
                aad: Vec::new(),
                sealed: Vec::new(),
            })
        }
        fn unseal(&self, _verified: &Verified) -> Result<Vec<u8>, Rejection> {
            self.unsealed.set(true);
            Ok(b"real-credential".to_vec())
        }
    }

    #[test]
    fn admits_bound_current_token() {
        assert!(admit(&claims(), b"https://broker", &acceptance(), b"PEER", 2000).is_ok());
        assert!(admit(&claims(), b"https://broker", &acceptance(), b"PEER", 940).is_ok());
    }

    #[test]
    fn rejects_each_authoritative_mismatch() {
        let a = acceptance();
        let check = |c: SurrogateClaims, issuer: &[u8], peer: &[u8], now: i64| {
            admit(&c, issuer, &a, peer, now).is_err()
        };
        assert!(check(claims(), b"https://other", b"PEER", 2000));
        assert!(check(claims(), b"https://broker", b"OTHER", 2000));
        assert!(check(claims(), b"https://broker", b"PEER", 4600));
        assert!(check(claims(), b"https://broker", b"PEER", 939));
        let mut c = claims();
        c.audience = b"x".to_vec();
        assert!(check(c, b"https://broker", b"PEER", 2000));
        let mut c = claims();
        c.provider = b"x".to_vec();
        assert!(check(c, b"https://broker", b"PEER", 2000));
        let mut c = claims();
        c.expires_at = 4601;
        assert!(check(c, b"https://broker", b"PEER", 2000));
        let mut c = claims();
        c.renew_until = 4599;
        assert!(check(c, b"https://broker", b"PEER", 2000));
    }

    #[test]
    fn wrong_peer_is_never_unsealed() {
        let opener = Fixed {
            claims,
            unsealed: std::cell::Cell::new(false),
        };
        assert!(open(&opener, b"t", &acceptance(), b"OTHER", 2000).is_err());
        assert!(!opener.unsealed.get());
        let opened = open(&opener, b"t", &acceptance(), b"PEER", 2000)
            .ok()
            .unwrap();
        assert!(opener.unsealed.get());
        assert_eq!(opened.credential, b"real-credential");
    }

    #[test]
    fn window_respects_every_cap() {
        let policy = IssuePolicy {
            issuer: b"i".to_vec(),
            audience: b"a".to_vec(),
            providers: vec![b"github".to_vec()],
            max_lifetime: 3600,
            max_renew: 86400,
        };
        let grant = |cert: i64, cred: i64| Grant {
            provider: b"github".to_vec(),
            subject: b"s".to_vec(),
            certificate: b"c".to_vec(),
            certificate_expires: cert,
            credential_expires: cred,
        };
        let w = issue_window(&policy, &grant(MAX_TIME, MAX_TIME), 100, 3600)
            .ok()
            .unwrap();
        assert_eq!(
            (w.issued_at, w.expires_at, w.renew_until),
            (100, 3700, 86500)
        );
        let w = issue_window(&policy, &grant(1000, MAX_TIME), 100, 3600)
            .ok()
            .unwrap();
        assert_eq!((w.expires_at, w.renew_until), (1000, 1000));
        let w = issue_window(&policy, &grant(MAX_TIME, 500), 100, 3600)
            .ok()
            .unwrap();
        assert_eq!((w.expires_at, w.renew_until), (500, 500));
        assert!(issue_window(&policy, &grant(100, MAX_TIME), 100, 3600).is_err());
        assert!(issue_window(&policy, &grant(MAX_TIME, MAX_TIME), 100, 3601).is_err());
    }
}
