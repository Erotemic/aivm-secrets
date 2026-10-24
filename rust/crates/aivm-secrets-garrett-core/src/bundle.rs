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

/// A guest bundle's local consistency: the JWT header and payload are in
/// canonical form, the signature is 64 bytes, the encrypted claim is at least
/// 29 bytes (nonce and tag), and the token's `cnf` thumbprint is the bundled
/// certificate's. Parsing is native; the broker still authenticates both on
/// every call.
#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
pub fn consistent(
    header_canonical: bool,
    payload_canonical: bool,
    signature_length: usize,
    encrypted_length: usize,
    cnf: &Vec<u8>,
    thumbprint: &Vec<u8>,
) -> bool {
    header_canonical
        && payload_canonical
        && signature_length == 64
        && encrypted_length >= 29
        && *cnf == *thumbprint
}
