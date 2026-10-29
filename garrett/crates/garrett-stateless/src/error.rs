//! Structured errors. Messages never contain credentials, surrogates,
//! authorization codes, verifiers or keys.
use garrett_stateless_core::stateless::Rejection;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A configuration or key file is invalid; the message names the field.
    Config(String),
    /// A file or socket operation failed.
    Io(String),
    /// A surrogate was refused or could not be issued; the reason code.
    Rejected(&'static str),
    /// A protocol exchange failed; a closed error code (spec section 13).
    Protocol(&'static str),
    /// TLS setup or the handshake failed.
    Tls(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(message) => write!(f, "invalid configuration: {message}"),
            Error::Io(message) => write!(f, "I/O error: {message}"),
            Error::Rejected(code) => write!(f, "rejected: {code}"),
            Error::Protocol(code) => write!(f, "protocol error: {code}"),
            Error::Tls(message) => write!(f, "TLS error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error.kind().to_string())
    }
}

/// The stable name of a rejection reason, as used in diagnostics and the
/// conformance vectors.
pub fn rejection_name(rejection: &Rejection) -> &'static str {
    match rejection {
        Rejection::Malformed => "malformed",
        Rejection::UnknownKey => "unknown_key",
        Rejection::BadSignature => "bad_signature",
        Rejection::WrongIssuer => "wrong_issuer",
        Rejection::WrongAudience => "wrong_audience",
        Rejection::UnknownProvider => "unknown_provider",
        Rejection::BadLifetime => "bad_lifetime",
        Rejection::NotYetValid => "not_yet_valid",
        Rejection::Expired => "expired",
        Rejection::WrongCertificate => "wrong_certificate",
        Rejection::Undecryptable => "undecryptable",
        Rejection::InvalidCredential => "invalid_credential",
        Rejection::BadPolicy => "bad_policy",
    }
}

impl From<Rejection> for Error {
    fn from(rejection: Rejection) -> Self {
        Error::Rejected(rejection_name(&rejection))
    }
}

pub(crate) fn config(message: impl Into<String>) -> Error {
    Error::Config(message.into())
}
