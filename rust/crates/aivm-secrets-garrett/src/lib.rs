//! Independent Garrett protocol implementation. Experimental and unaudited.
#![forbid(unsafe_code)]
pub mod attestation;
pub mod authority;
pub mod certificates;
pub mod client;
pub mod crypto;
mod custody;
pub use custody::ProviderSession;
pub mod files;
pub mod json;
pub mod lifecycle;
pub mod model;
pub mod oauth;
pub mod oauth_vault;
pub mod registry;
pub mod tls;
pub mod tpm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidCapability,
    InvalidRequest,
    Denied,
    Unreachable,
    UpstreamResponse,
    InternalError,
    UnsafeFile,
    OutcomeUnknown,
    Exhausted,
    Revoked,
    CredentialSource,
    Expired,
    AuthorizationDenied,
}
pub type Outcome<T> = Result<T, Error>;
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidCapability => "invalid_capability",
            Self::InvalidRequest => "invalid_request",
            Self::Denied => "denied",
            Self::Unreachable => "unreachable",
            Self::UpstreamResponse => "upstream_response",
            Self::InternalError => "internal_error",
            Self::UnsafeFile => "unsafe_file",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::CredentialSource | Self::AuthorizationDenied => "credential_source",
            Self::Expired => "expired",
        }
    }
}

#[cfg(feature = "conformance")]
pub mod conformance;
