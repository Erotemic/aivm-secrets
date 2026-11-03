//! Typed identifiers at the public boundary.
//!
//! The extracted core carries the issuer, audience, subject, token ID,
//! provider and certificate thumbprint as plain byte vectors, so its proofs
//! keep simple types. Here each one is its own type, made only by checking
//! the spec's grammar (section 2) with the core's own extracted predicates
//! (`stateless_token::grammar`, proved in `GarrettStatelessGrammar`), so a
//! subject cannot be passed where a thumbprint is expected and an unchecked
//! string cannot reach the core as either. [`Claims`] is the typed view of a
//! surrogate's claims; it converts to and from the core's `SurrogateClaims`
//! without changing a byte.
//!
//! ```
//! use garrett_stateless::ids::{Subject, Thumbprint};
//! assert!(Subject::parse("spiffe://example.org/agent").is_ok());
//! assert!(Thumbprint::parse("spiffe://example.org/agent").is_err());
//! ```
//!
//! A subject is not a thumbprint:
//!
//! ```compile_fail
//! use garrett_stateless::ids::{Subject, Thumbprint};
//! fn bind(_peer: &Thumbprint) {}
//! let subject = Subject::parse("spiffe://example.org/agent").unwrap();
//! bind(&subject);
//! ```
//!
//! and an unchecked string is neither:
//!
//! ```compile_fail
//! use garrett_stateless::ids::Thumbprint;
//! let forged = Thumbprint(String::from("anything"));
//! ```
use crate::error::{Error, Result};
use garrett_stateless_core::stateless::SurrogateClaims;
use garrett_stateless_core::stateless_token as grammar;
use std::fmt;
use std::str::FromStr;

macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident, $check:path) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Accept `text` only if it matches the grammar; otherwise the
            /// rejection is `malformed`, as for a malformed surrogate claim.
            pub fn parse(text: &str) -> Result<Self> {
                if $check(text.as_bytes()) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(Error::Rejected("malformed"))
                }
            }
            /// The same, from bytes (which the grammar keeps ASCII).
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                match std::str::from_utf8(bytes) {
                    Ok(text) => Self::parse(text),
                    Err(_) => Err(Error::Rejected("malformed")),
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
            pub fn into_bytes(self) -> Vec<u8> {
                self.0.into_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(text: &str) -> Result<Self> {
                Self::parse(text)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

identifier!(
    /// The broker that issued a surrogate (`iss`): a spec `text`.
    Issuer,
    grammar::is_text
);
identifier!(
    /// The proxies a surrogate is for (`aud`): a spec `text`.
    Audience,
    grammar::is_text
);
identifier!(
    /// The agent a surrogate names (`sub`, spec section 6.2): a spec `text`.
    /// Informational; the binding is the [`Thumbprint`].
    Subject,
    grammar::is_text
);
identifier!(
    /// A provider name (`prv`): `[a-z0-9][a-z0-9._-]{0,63}`.
    ProviderName,
    grammar::is_provider
);
identifier!(
    /// A surrogate's token ID (`jti`): 32 lowercase hex digits.
    TokenId,
    grammar::is_id
);
identifier!(
    /// The `x5t#S256` thumbprint of an agent certificate: 43 b64url symbols
    /// of a SHA-256 digest. This, not the subject, binds a surrogate.
    Thumbprint,
    grammar::is_thumbprint
);

impl TokenId {
    /// A fresh token ID: 128 random bits as 32 lowercase hex digits.
    pub fn random() -> Result<Self> {
        Self::parse(&crate::encoding::random_id()?)
    }
}

/// The typed claims of a surrogate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub issuer: Issuer,
    pub audience: Audience,
    pub subject: Subject,
    pub token_id: TokenId,
    pub provider: ProviderName,
    pub certificate: Thumbprint,
    pub issued_at: i64,
    pub expires_at: i64,
    pub renew_until: i64,
}

impl TryFrom<&SurrogateClaims> for Claims {
    type Error = Error;
    fn try_from(claims: &SurrogateClaims) -> Result<Self> {
        Ok(Self {
            issuer: Issuer::from_bytes(&claims.issuer)?,
            audience: Audience::from_bytes(&claims.audience)?,
            subject: Subject::from_bytes(&claims.subject)?,
            token_id: TokenId::from_bytes(&claims.token_id)?,
            provider: ProviderName::from_bytes(&claims.provider)?,
            certificate: Thumbprint::from_bytes(&claims.certificate)?,
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            renew_until: claims.renew_until,
        })
    }
}

impl From<Claims> for SurrogateClaims {
    fn from(claims: Claims) -> Self {
        SurrogateClaims {
            issuer: claims.issuer.into_bytes(),
            audience: claims.audience.into_bytes(),
            subject: claims.subject.into_bytes(),
            token_id: claims.token_id.into_bytes(),
            provider: claims.provider.into_bytes(),
            certificate: claims.certificate.into_bytes(),
            issued_at: claims.issued_at,
            expires_at: claims.expires_at,
            renew_until: claims.renew_until,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINT: &str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    #[test]
    fn each_identifier_takes_exactly_its_grammar() {
        assert!(Issuer::parse("https://broker.example").is_ok());
        assert!(Issuer::parse("").is_err());
        assert!(Issuer::parse("has space").is_err());
        assert!(Audience::parse("with\"quote").is_err());
        assert!(Subject::parse(&"x".repeat(256)).is_ok());
        assert!(Subject::parse(&"x".repeat(257)).is_err());
        assert!(ProviderName::parse("github").is_ok());
        assert!(ProviderName::parse("GitHub").is_err());
        assert!(ProviderName::parse("-github").is_err());
        assert!(TokenId::parse("0123456789abcdef0123456789abcdef").is_ok());
        assert!(TokenId::parse("0123456789ABCDEF0123456789ABCDEF").is_err());
        assert!(TokenId::parse("0123").is_err());
        assert!(Thumbprint::parse(PRINT).is_ok());
        assert!(Thumbprint::parse(&PRINT[..42]).is_err());
        assert!(Thumbprint::parse(&format!("{PRINT}=")).is_err());
        assert_eq!(Thumbprint::parse("x"), Err(Error::Rejected("malformed")));
        assert!(Thumbprint::from_bytes(&[0xff; 43]).is_err());
    }

    #[test]
    fn random_token_ids_are_token_ids() {
        let id = TokenId::random().unwrap();
        assert_eq!(id.as_str().len(), 32);
        assert_ne!(id, TokenId::random().unwrap());
    }

    fn core_claims() -> SurrogateClaims {
        SurrogateClaims {
            issuer: b"https://broker.example".to_vec(),
            audience: b"proxy.example".to_vec(),
            subject: b"spiffe://example.org/agent".to_vec(),
            token_id: b"0123456789abcdef0123456789abcdef".to_vec(),
            provider: b"github".to_vec(),
            certificate: PRINT.as_bytes().to_vec(),
            issued_at: 10,
            expires_at: 20,
            renew_until: 30,
        }
    }

    #[test]
    fn typed_claims_round_trip_byte_for_byte() {
        let core = core_claims();
        let typed = Claims::try_from(&core).unwrap();
        assert_eq!(typed.certificate.as_str(), PRINT);
        let back: SurrogateClaims = typed.into();
        assert_eq!(back.issuer, core.issuer);
        assert_eq!(back.audience, core.audience);
        assert_eq!(back.subject, core.subject);
        assert_eq!(back.token_id, core.token_id);
        assert_eq!(back.provider, core.provider);
        assert_eq!(back.certificate, core.certificate);
        assert_eq!(
            (back.issued_at, back.expires_at, back.renew_until),
            (10, 20, 30)
        );
    }

    #[test]
    fn claims_outside_the_grammar_have_no_typed_view() {
        let mut swapped = core_claims();
        // A subject in the thumbprint slot is refused, not silently carried.
        swapped.certificate = swapped.subject.clone();
        assert!(Claims::try_from(&swapped).is_err());
        let mut bad = core_claims();
        bad.provider = b"Bad Provider".to_vec();
        assert!(Claims::try_from(&bad).is_err());
    }
}
