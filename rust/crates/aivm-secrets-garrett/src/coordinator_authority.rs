//! Optional single-host SQLite authority. Never replicate its database file.
//! Peer authentication, storage durability and rollback remain trust boundaries.
mod ledger;
mod server;
use crate::Error;
use aivm_secrets_garrett_core::coordinator_authority as core;
pub use ledger::Ledger;
pub use server::Server;

#[derive(Debug)]
pub enum AuthorityError {
    Public(Error),
    Storage,
}
pub type Result<T> = std::result::Result<T, AuthorityError>;
impl AuthorityError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Public(error) => error.code(),
            Self::Storage => "audit_failed",
        }
    }
}
impl From<Error> for AuthorityError {
    fn from(error: Error) -> Self {
        Self::Public(error)
    }
}
impl From<rusqlite::Error> for AuthorityError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<core::Denial> for AuthorityError {
    fn from(error: core::Denial) -> Self {
        match error {
            core::Denial::Denied => Error::Denied.into(),
            core::Denial::Revoked => Error::Revoked.into(),
            core::Denial::OutcomeUnknown => Error::OutcomeUnknown.into(),
            core::Denial::Storage => Self::Storage,
        }
    }
}
