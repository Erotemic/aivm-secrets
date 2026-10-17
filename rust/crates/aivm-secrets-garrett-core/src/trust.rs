//! Trust fencing, safe recovery prefixes and root-cutover publication order.
#![allow(clippy::ptr_arg)]
use crate::authority::StorageFailure;

pub enum TrustDenial {
    Stale,
    Unpublished,
    OutcomeUnknown,
}
pub fn require_root(current: &Vec<u8>, expected: &Vec<u8>) -> Result<(), TrustDenial> {
    if *current != *expected {
        return Err(TrustDenial::Stale);
    }
    Ok(())
}
pub enum RecoveryPhase {
    Unchanged,
    Retired,
    Activated,
}
/// The anchor includes the complete selected CA/server and issuer keyring.
/// A changed enrollment set or a selector published before retirement is a
/// conflict, never permission to restore an old registry or trust snapshot.
pub fn recovery_phase(
    anchor: &Vec<u8>,
    before_anchor: &Vec<u8>,
    after_anchor: &Vec<u8>,
    registry: &Vec<u8>,
    before_registry: &Vec<u8>,
    after_registry: &Vec<u8>,
) -> Result<RecoveryPhase, TrustDenial> {
    if *anchor == *before_anchor {
        if *registry == *before_registry {
            return Ok(RecoveryPhase::Unchanged);
        }
        if *registry == *after_registry {
            return Ok(RecoveryPhase::Retired);
        }
    }
    if *anchor == *after_anchor && *registry == *after_registry {
        return Ok(RecoveryPhase::Activated);
    }
    Err(TrustDenial::Stale)
}
pub trait TrustStore {
    fn intent(&self) -> Result<(), StorageFailure>;
    fn stage(&self) -> Result<(), StorageFailure>;
    fn retire(&self) -> Result<(), StorageFailure>;
    fn activate(&self) -> Result<(), StorageFailure>;
    fn complete(&self) -> Result<(), StorageFailure>;
}
/// Invalidate old enrollments durably before installing a new trust root.
/// Retirement itself changes authority; any failure from that point is uncertain.
#[allow(clippy::redundant_pattern_matching)]
pub fn commit_trust<S: TrustStore>(
    store: &S,
    current: &Vec<u8>,
    expected: &Vec<u8>,
) -> Result<(), TrustDenial> {
    if let Err(error) = require_root(current, expected) {
        return Err(error);
    }
    if let Err(_) = store.intent() {
        return Err(TrustDenial::Unpublished);
    }
    if let Err(_) = store.stage() {
        return Err(TrustDenial::Unpublished);
    }
    if let Err(_) = store.retire() {
        return Err(TrustDenial::OutcomeUnknown);
    }
    if let Err(_) = store.activate() {
        return Err(TrustDenial::OutcomeUnknown);
    }
    if let Err(_) = store.complete() {
        return Err(TrustDenial::OutcomeUnknown);
    }
    Ok(())
}
