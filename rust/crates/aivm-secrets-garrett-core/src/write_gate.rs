//! The exact-write gate around the production controller (OUT-4).
//!
//! The native session computes the approval decision with the extracted
//! `approval::consume` (single-use, digest- and expiry-bound). This gate is
//! the only place the production controller `read_transition::run_current`
//! is invoked: it runs only when that decision is `Allowed`, so a write
//! that was denied or still needs host approval never reaches dispatch.
use crate::approval::Decision;
use crate::read_transition::{self, Request};

pub enum Gated<T> {
    Ran(T),
    Denied,
    Required,
}

pub fn run_approved<R: Request>(
    decision: Decision,
    adapter: R,
) -> Gated<Result<R::Output, R::Error>> {
    match decision {
        Decision::Allowed => Gated::Ran(read_transition::run_current(adapter)),
        Decision::Denied => Gated::Denied,
        Decision::Required => Gated::Required,
    }
}

/// The session's approval admission for one request digest.
pub trait Admission {
    type Error;
    /// Decide (and, in approve mode, consume) for exactly `digest`.
    fn admit(&mut self, digest: &Vec<u8>, write: bool) -> Result<Decision, Self::Error>;
}

/// Admit exactly `digest`, then gate the controller on that decision: the
/// decision that gates the controller is the one returned for this digest.
#[allow(clippy::ptr_arg)]
pub fn run_admitted<A: Admission, R: Request>(
    admission: &mut A,
    digest: &Vec<u8>,
    write: bool,
    adapter: R,
) -> Result<Gated<Result<R::Output, R::Error>>, A::Error> {
    match admission.admit(digest, write) {
        Ok(decision) => Ok(run_approved(decision, adapter)),
        Err(error) => Err(error),
    }
}
