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
pub mod profile;
pub mod registry;
pub mod tls;
pub mod tpm;

/// The native error type is the extracted public error table itself
/// (`public_error::PublicError`): there is no native-to-public mapping to trust.
pub use aivm_secrets_garrett_core::public_error::PublicError as Error;
pub type Outcome<T> = Result<T, Error>;
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
            assert_eq!(error.name(), code);
            let public = aivm_secrets_garrett_core::public_error::code(error.into());
            assert_eq!(public, code.as_bytes());
        }
    }
}
