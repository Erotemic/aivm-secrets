//! Production-called phase-to-audit transition for native manifest dispatch.
//!
//! This module is intentionally pure and small enough for Aeneas extraction.
//! A successful adapter `write_record` is represented by the explicit `ack`
//! input to `acknowledge`.  The filesystem's durability contract, subsequent
//! freshness validation, socket emission, and guest release remain external
//! obligations.  The structs' fields are private, so the native executor must
//! carry the selected phase and permission through these checked transitions.

use crate::Denial;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Preflight,
    Final,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Final => "final",
        }
    }
}

pub struct Prepared {
    phase: Phase,
    write: bool,
}

pub struct Audited {
    phase: Phase,
    write: bool,
}

/// Admit a policy-compiled effect for the selected phase.  A preflight may
/// never write; a final write must belong to an admitted write operation.
/// Neither guest arguments nor unchecked provider facts are authority here.
pub fn prepare(
    phase: Phase,
    admitted_operation_write: bool,
    effect_write: bool,
) -> Result<Prepared, Denial> {
    if effect_write && (matches!(phase, Phase::Preflight) || !admitted_operation_write) {
        return Err(Denial::InvalidCapability);
    }
    Ok(Prepared {
        phase,
        write: effect_write,
    })
}

impl Prepared {
    pub fn phase(&self) -> Phase {
        self.phase
    }
}

/// Convert a prepared effect to a dispatch permit only after the private host
/// audit adapter has acknowledged its exact record. An `ack` supplied by a
/// dishonest or incorrect adapter is not ruled out by this pure function.
pub fn acknowledge(prepared: Prepared, ack: bool) -> Result<Audited, Denial> {
    if !ack {
        return Err(Denial::InvalidCapability);
    }
    Ok(Audited {
        phase: prepared.phase,
        write: prepared.write,
    })
}

impl Audited {
    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn is_write(&self) -> bool {
        self.write
    }
}

/// Completion audit and current authority are external adapter outcomes.
/// The selected reply remains private until both have succeeded. Rechecking
/// after the audit prevents a blocking append from extending its authority.
pub enum CompletionPhase {
    BeforeAudit,
    BeforeRelease,
}

pub trait Completion {
    type Output;
    type Error;
    fn recheck(&self, phase: CompletionPhase) -> Result<(), Self::Error>;
    fn audit(&self) -> Result<(), Self::Error>;
    fn release(self) -> Result<Self::Output, Self::Error>;
}

pub fn complete_current<C: Completion>(pending: C) -> Result<C::Output, C::Error> {
    match pending.recheck(CompletionPhase::BeforeAudit) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    match pending.audit() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    match pending.recheck(CompletionPhase::BeforeRelease) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    pending.release()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_preflight_and_final_carry_their_actual_phase() {
        for phase in [Phase::Preflight, Phase::Final] {
            let prepared = prepare(phase, false, false)
                .ok()
                .expect("checked transition");
            assert_eq!(prepared.phase(), phase);
            let audited = acknowledge(prepared, true)
                .ok()
                .expect("checked transition");
            assert_eq!(audited.phase(), phase);
            assert!(!audited.is_write());
        }
    }

    #[test]
    fn preflight_cannot_write_even_for_admitted_write_operation() {
        assert!(prepare(Phase::Preflight, true, true).is_err());
        assert!(prepare(Phase::Preflight, false, true).is_err());
    }

    #[test]
    fn final_write_requires_original_write_admission() {
        assert!(prepare(Phase::Final, false, true).is_err());
        let admitted = prepare(Phase::Final, true, true)
            .ok()
            .expect("checked transition");
        let audited = acknowledge(admitted, true)
            .ok()
            .expect("checked transition");
        assert_eq!(audited.phase(), Phase::Final);
        assert!(audited.is_write());
    }

    #[test]
    fn failed_audit_does_not_make_an_executable_permit() {
        let prepared = prepare(Phase::Final, false, false)
            .ok()
            .expect("checked transition");
        assert!(acknowledge(prepared, false).is_err());
    }

    struct TestCompletion<'a> {
        trace: &'a std::cell::RefCell<Vec<&'static str>>,
        fault: Option<&'static str>,
    }

    impl TestCompletion<'_> {
        fn step(&self, name: &'static str) -> Result<(), &'static str> {
            self.trace.borrow_mut().push(name);
            if self.fault == Some(name) {
                Err(name)
            } else {
                Ok(())
            }
        }
    }

    impl Completion for TestCompletion<'_> {
        type Output = &'static str;
        type Error = &'static str;

        fn recheck(&self, phase: CompletionPhase) -> Result<(), Self::Error> {
            self.step(match phase {
                CompletionPhase::BeforeAudit => "before-audit",
                CompletionPhase::BeforeRelease => "before-release",
            })
        }

        fn audit(&self) -> Result<(), Self::Error> {
            self.step("audit")
        }

        fn release(self) -> Result<Self::Output, Self::Error> {
            self.step("release")?;
            Ok("selected-reply")
        }
    }

    #[test]
    fn completion_checks_surround_audit_and_each_failure_stops_its_continuation() {
        let stages = ["before-audit", "audit", "before-release", "release"];
        for (index, stage) in stages.iter().enumerate() {
            let trace = std::cell::RefCell::new(Vec::new());
            let pending = TestCompletion {
                trace: &trace,
                fault: Some(stage),
            };
            assert_eq!(complete_current(pending), Err(*stage));
            assert_eq!(*trace.borrow(), stages[..=index]);
        }
        let trace = std::cell::RefCell::new(Vec::new());
        assert_eq!(
            complete_current(TestCompletion {
                trace: &trace,
                fault: None
            }),
            Ok("selected-reply")
        );
        assert_eq!(*trace.borrow(), stages);
    }
}
