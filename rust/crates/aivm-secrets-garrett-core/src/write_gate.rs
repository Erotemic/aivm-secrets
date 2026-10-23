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
