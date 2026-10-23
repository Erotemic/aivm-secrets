//! Independent Garrett protocol implementation. Experimental and unaudited.
#![forbid(unsafe_code)]
pub mod attestation;
pub mod authority;
pub mod certificates;
pub mod client;
pub mod client_material;
mod coordination;
pub mod coordinator_admin;
#[cfg(feature = "coordinator-server")]
pub mod coordinator_authority;
pub mod crypto;
mod custody;
pub mod identity_bundle;
pub use custody::ProviderSession;
pub mod files;
pub mod host_control;
pub mod json;
pub mod lifecycle;
pub mod manifest;
pub mod model;
pub mod oauth;
pub mod oauth_vault;
pub mod registry;
pub mod tls;
pub mod tpm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidCapability,
    InvalidPolicy,
    ResourceMismatch,
    InvalidRequest,
    Denied,
    Unreachable,
    UpstreamResponse,
    UpstreamRejected,
    UpstreamError,
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
    /// Host-side spelling; equality with the extracted guest-frame table
    /// `public_error::code` is pinned by `public_error_tests`.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidCapability => "invalid_capability",
            Self::InvalidPolicy => "invalid_policy",
            Self::ResourceMismatch => "resource_mismatch",
            Self::InvalidRequest => "invalid_request",
            Self::Denied => "denied",
            Self::Unreachable => "unreachable",
            Self::UpstreamResponse => "upstream_response",
            Self::UpstreamRejected => "upstream_rejected",
            Self::UpstreamError => "upstream_error",
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
// One-to-one and exhaustive: adding a native variant must extend PublicError.
impl From<Error> for aivm_secrets_garrett_core::public_error::PublicError {
    fn from(error: Error) -> Self {
        use aivm_secrets_garrett_core::public_error::PublicError as P;
        match error {
            Error::InvalidCapability => P::InvalidCapability,
            Error::InvalidPolicy => P::InvalidPolicy,
            Error::ResourceMismatch => P::ResourceMismatch,
            Error::InvalidRequest => P::InvalidRequest,
            Error::Denied => P::Denied,
            Error::Unreachable => P::Unreachable,
            Error::UpstreamResponse => P::UpstreamResponse,
            Error::UpstreamRejected => P::UpstreamRejected,
            Error::UpstreamError => P::UpstreamError,
            Error::InternalError => P::InternalError,
            Error::UnsafeFile => P::UnsafeFile,
            Error::OutcomeUnknown => P::OutcomeUnknown,
            Error::Exhausted => P::Exhausted,
            Error::Revoked => P::Revoked,
            Error::CredentialSource => P::CredentialSource,
            Error::Expired => P::Expired,
            Error::AuthorizationDenied => P::AuthorizationDenied,
        }
    }
}

#[cfg(feature = "conformance")]
pub mod conformance;

#[cfg(test)]
mod public_error_tests {
    use super::Error;
    // The public codes predate the extracted table; they must not change.
    #[test]
    fn extracted_codes_equal_previous_native_codes() {
        for (error, code) in [
            (Error::InvalidCapability, "invalid_capability"),
            (Error::InvalidPolicy, "invalid_policy"),
            (Error::ResourceMismatch, "resource_mismatch"),
            (Error::InvalidRequest, "invalid_request"),
            (Error::Denied, "denied"),
            (Error::Unreachable, "unreachable"),
            (Error::UpstreamResponse, "upstream_response"),
            (Error::UpstreamRejected, "upstream_rejected"),
            (Error::UpstreamError, "upstream_error"),
            (Error::InternalError, "internal_error"),
            (Error::UnsafeFile, "unsafe_file"),
            (Error::OutcomeUnknown, "outcome_unknown"),
            (Error::Exhausted, "exhausted"),
            (Error::Revoked, "revoked"),
            (Error::CredentialSource, "credential_source"),
            (Error::AuthorizationDenied, "credential_source"),
            (Error::Expired, "expired"),
        ] {
            assert_eq!(error.code(), code);
            let public = aivm_secrets_garrett_core::public_error::code(error.into());
            assert_eq!(public, code.as_bytes());
        }
    }
}
