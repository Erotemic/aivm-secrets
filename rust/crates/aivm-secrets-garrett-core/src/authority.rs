//! Current authority admission and ordered durable publication decisions.
#![allow(clippy::ptr_arg)]
pub enum AuthorityDenial {
    Invalid,
    Revoked,
    Assurance,
}
pub enum Assurance {
    Unrecorded,
    Software,
    Tpm,
}
pub enum Requirement {
    Enrolled,
    AttestedTpm,
}
pub fn require_peer(
    active: bool,
    certificate: &Vec<u8>,
    peer: &Vec<u8>,
    not_after: i64,
    now: i64,
    assurance: &Assurance,
    required: &Requirement,
) -> Result<(), AuthorityDenial> {
    if !active || now < 0 || now >= not_after || *certificate != *peer {
        return Err(AuthorityDenial::Revoked);
    }
    match required {
        Requirement::Enrolled => (),
        Requirement::AttestedTpm => match assurance {
            Assurance::Tpm => (),
            _ => return Err(AuthorityDenial::Assurance),
        },
    }
    Ok(())
}
pub struct Revoked {
    pub active: bool,
    pub epoch: i64,
}
pub fn revoke(active: bool, epoch: i64) -> Result<Revoked, AuthorityDenial> {
    if epoch < 0 || epoch > 2147483647 {
        return Err(AuthorityDenial::Invalid);
    }
    let next = if active && epoch < 2147483647 {
        epoch + 1
    } else {
        epoch
    };
    Ok(Revoked {
        active: false,
        epoch: next,
    })
}
pub enum StorageFailure {
    Failed,
}
pub enum CommitDenial {
    Unpublished,
    OutcomeUnknown,
}
pub trait ChangeStore {
    fn intent(&self) -> Result<(), StorageFailure>;
    fn stage(&self) -> Result<(), StorageFailure>;
    fn publish(&self) -> Result<(), StorageFailure>;
    fn complete(&self) -> Result<(), StorageFailure>;
}
/// Staged material must be durable before a state pointer can name it. Once
/// publication begins, an error cannot promise that authority stayed unchanged.
#[allow(clippy::redundant_pattern_matching)] // Keep the extracted error branches explicit.
pub fn commit_change<S: ChangeStore>(store: &S) -> Result<(), CommitDenial> {
    if let Err(_) = store.intent() {
        return Err(CommitDenial::Unpublished);
    }
    if let Err(_) = store.stage() {
        return Err(CommitDenial::Unpublished);
    }
    if let Err(_) = store.publish() {
        return Err(CommitDenial::OutcomeUnknown);
    }
    if let Err(_) = store.complete() {
        return Err(CommitDenial::OutcomeUnknown);
    }
    Ok(())
}
