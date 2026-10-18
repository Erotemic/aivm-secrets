//! CAS before staging, then conservative single-pointer publication. Storage
//! callbacks own hashing, locking, serialization, rename and durability.
pub enum InstallFailure {
    Changed,
    Unpublished,
    OutcomeUnknown,
}
pub trait BundleStore {
    fn current(&self) -> Result<Option<Vec<u8>>, InstallFailure>;
    fn stage(&self) -> Result<(), InstallFailure>;
    fn publish(&self) -> Result<(), InstallFailure>;
}
pub fn install<S: BundleStore>(store: &S, expected: Option<Vec<u8>>) -> Result<(), InstallFailure> {
    let current = match store.current() {
        Ok(current) => current,
        Err(error) => return Err(error),
    };
    let changed = match (&current, &expected) {
        (None, None) => false,
        (Some(a), Some(b)) => a != b,
        _ => true,
    };
    if changed {
        return Err(InstallFailure::Changed);
    }
    match store.stage() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    match store.publish() {
        Ok(()) => Ok(()),
        Err(_) => Err(InstallFailure::OutcomeUnknown),
    }
}
