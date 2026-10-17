//! Publish a private client key before its public possession request. A later
//! failure retains the key and cannot be reported as an unchanged operation.

pub enum PublishFailure {
    Unpublished,
    OutcomeUnknown,
}
pub trait RequestStore {
    fn write_key(&self) -> Result<(), PublishFailure>;
    fn write_csr(&self) -> Result<(), PublishFailure>;
}
pub fn publish_request<S: RequestStore>(store: &S) -> Result<(), PublishFailure> {
    match store.write_key() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    match store.write_csr() {
        Ok(()) => Ok(()),
        Err(_) => Err(PublishFailure::OutcomeUnknown),
    }
}
