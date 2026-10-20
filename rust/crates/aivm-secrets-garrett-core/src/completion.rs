//! Source-owned selected-value completion around external native primitives.
//! Work cannot mutate the private receipt through this interface. Primitive
//! correctness and absence of other I/O remain separate adapter contracts.

use crate::{read_transition, request_effects::RequestEffects};

pub trait Work {
    type Output;
    type Error;
    const INVALID_TRANSITION: Self::Error;
    fn select(&mut self) -> Result<Self::Output, Self::Error>;
    fn recheck(&mut self, phase: read_transition::CompletionPhase) -> Result<(), Self::Error>;
    fn audit(&mut self) -> Result<(), Self::Error>;
}

pub struct Completed<T> {
    value: T,
}
impl<T> Completed<T> {
    pub fn into_value(self) -> T {
        self.value
    }
}

pub struct Report<W: Work> {
    pub outcome: Result<Completed<W::Output>, W::Error>,
    pub work: W,
    pub effects: RequestEffects,
}

struct Pending<W: Work> {
    work: W,
    effects: RequestEffects,
    value: Option<W::Output>,
}
impl<W: Work> read_transition::Completion for Pending<W> {
    type Output = Completed<W::Output>;
    type Error = W::Error;

    fn recheck(&mut self, phase: read_transition::CompletionPhase) -> Result<(), Self::Error> {
        if !self.effects.begin_completion_check(phase) {
            return Err(W::INVALID_TRANSITION);
        }
        match self.work.recheck(phase) {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
        if !self.effects.finish_completion_check(phase) {
            return Err(W::INVALID_TRANSITION);
        }
        Ok(())
    }
    fn audit(&mut self) -> Result<(), Self::Error> {
        if !self.effects.begin_completion_audit() {
            return Err(W::INVALID_TRANSITION);
        }
        match self.work.audit() {
            Ok(()) => (),
            Err(error) => return Err(error),
        }
        if !self.effects.acknowledge_completion_audit() {
            return Err(W::INVALID_TRANSITION);
        }
        Ok(())
    }
    fn release(&mut self) -> Result<Self::Output, Self::Error> {
        if !self.effects.value_ready() {
            return Err(W::INVALID_TRANSITION);
        }
        match self.value.take() {
            Some(value) => Ok(Completed { value }),
            None => Err(W::INVALID_TRANSITION),
        }
    }
}

fn select_and_complete<W: Work>(
    pending: &mut Pending<W>,
) -> Result<Completed<W::Output>, W::Error> {
    if !pending.effects.begin_completion() {
        return Err(W::INVALID_TRANSITION);
    }
    let value = match pending.work.select() {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if !pending.effects.selected() {
        return Err(W::INVALID_TRANSITION);
    }
    pending.value = Some(value);
    read_transition::complete_current(pending)
}

/// Return the real receipt and primitive post-state even after a failed
/// selection/check/audit. No native receipt borrow is held across these calls.
pub fn complete<W: Work>(work: W, effects: RequestEffects) -> Report<W> {
    let mut pending = Pending {
        work,
        effects,
        value: None,
    };
    let outcome = select_and_complete(&mut pending);
    Report {
        outcome,
        work: pending.work,
        effects: pending.effects,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Primitives {
        trace: Vec<&'static str>,
        fail: Option<&'static str>,
    }
    impl Primitives {
        fn step(&mut self, name: &'static str) -> Result<(), &'static str> {
            self.trace.push(name);
            if self.fail == Some(name) {
                Err(name)
            } else {
                Ok(())
            }
        }
    }
    impl Work for Primitives {
        type Output = Vec<u8>;
        type Error = &'static str;
        const INVALID_TRANSITION: Self::Error = "invalid";
        fn select(&mut self) -> Result<Vec<u8>, Self::Error> {
            self.step("select")?;
            Ok(b"exact-selected-value".to_vec())
        }
        fn recheck(&mut self, phase: read_transition::CompletionPhase) -> Result<(), Self::Error> {
            self.step(match phase {
                read_transition::CompletionPhase::BeforeAudit => "before",
                read_transition::CompletionPhase::BeforeRelease => "after",
            })
        }
        fn audit(&mut self) -> Result<(), Self::Error> {
            self.step("audit")
        }
    }

    #[test]
    fn each_primitive_error_retains_its_exact_prefix_and_receipt() {
        let steps = ["select", "before", "audit", "after"];
        for (index, fault) in steps.into_iter().enumerate() {
            let report = complete(
                Primitives {
                    trace: vec![],
                    fail: Some(fault),
                },
                RequestEffects::new(),
            );
            assert!(matches!(report.outcome, Err(error) if error == fault));
            assert_eq!(report.work.trace, steps[..=index]);
            let receipt = report.effects.completion();
            assert_eq!(receipt.selected(), index >= 1);
            assert_eq!(receipt.before_checked(), index >= 2);
            assert_eq!(receipt.audit_attempted(), index >= 2);
            assert_eq!(receipt.audit_acknowledged(), index >= 3);
            assert!(!receipt.after_checked());
            assert!(!report.effects.can_return_value());
        }
    }

    #[test]
    fn successful_value_is_exact_and_cannot_reopen_completion() {
        let report = complete(
            Primitives {
                trace: vec![],
                fail: None,
            },
            RequestEffects::new(),
        );
        assert_eq!(report.work.trace, ["select", "before", "audit", "after"]);
        assert!(report.effects.can_return_value());
        assert_eq!(
            report.outcome.ok().unwrap().into_value(),
            b"exact-selected-value"
        );
        let repeated = complete(report.work, report.effects);
        assert!(matches!(repeated.outcome, Err("invalid")));
        assert_eq!(repeated.work.trace, ["select", "before", "audit", "after"]);
        assert!(!repeated.effects.can_return_value());
        assert!(repeated.effects.completion().audit_acknowledged());
    }
}
