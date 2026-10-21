//! Production request adapter owns one receipt across both extracted effect
//! controllers. Native factories and primitives cannot borrow that receipt;
//! their context, I/O and conversion semantics remain separate contracts.
use crate::{completion, dispatch, read_transition, request_effects::RequestEffects};

pub struct DispatchPlan<D: dispatch::Work> {
    pub work: D,
    pub keyed_write: bool,
}

pub trait Work {
    type Facts;
    type Effect;
    type Output;
    type Error;
    type Dispatch: dispatch::Work<Output = Self::Facts, Error = Self::Error>;
    type Completion: completion::Work<Output = Self::Output, Error = Self::Error>;
    const INVALID_TRANSITION: Self::Error;
    const INVALID_POLICY: Self::Error;

    fn preflight(&self) -> Result<Option<Self::Effect>, Self::Error>;
    fn empty_facts(&self) -> Self::Facts;
    fn final_effect(&self, facts: &Self::Facts) -> Result<Option<Self::Effect>, Self::Error>;
    fn effect_write(&self, effect: &Self::Effect) -> bool;
    fn operation_write(&self) -> bool;
    fn dispatch(
        &mut self,
        phase: read_transition::Phase,
        effect: Self::Effect,
    ) -> DispatchPlan<Self::Dispatch>;
    fn complete(&mut self, raw: Self::Facts) -> Self::Completion;
    fn recheck(&mut self) -> Result<(), Self::Error>;
    fn outcome_unknown(&self) -> Self::Error;
}

pub struct Pending<W: Work> {
    work: W,
    effects: RequestEffects,
}
impl<W: Work> Pending<W> {
    pub fn new(work: W) -> Self {
        Self {
            work,
            effects: RequestEffects::new(),
        }
    }
    pub fn effects(&self) -> RequestEffects {
        self.effects
    }
}
impl<W: Work> read_transition::Request for Pending<W> {
    type Facts = W::Facts;
    type Effect = W::Effect;
    type Output = completion::Completed<W::Output>;
    type Error = W::Error;
    const INVALID_TRANSITION: Self::Error = W::INVALID_TRANSITION;

    fn preflight(&self) -> Result<Option<Self::Effect>, Self::Error> {
        self.work.preflight()
    }
    fn empty_facts(&self) -> Self::Facts {
        self.work.empty_facts()
    }
    fn final_effect(&self, facts: &Self::Facts) -> Result<Option<Self::Effect>, Self::Error> {
        self.work.final_effect(facts)
    }
    fn effect_write(&self, effect: &Self::Effect) -> bool {
        self.work.effect_write(effect)
    }
    fn dispatch(
        &mut self,
        phase: read_transition::Phase,
        effect: Self::Effect,
    ) -> Result<Self::Facts, Self::Error> {
        let prepared = match read_transition::prepare(
            phase,
            self.work.operation_write(),
            self.work.effect_write(&effect),
        ) {
            Ok(prepared) => prepared,
            Err(_) => return Err(W::INVALID_POLICY),
        };
        let plan = self.work.dispatch(phase, effect);
        let report = dispatch::dispatch(plan.work, Ok(prepared), self.effects, plan.keyed_write);
        self.effects = report.effects;
        report.outcome
    }
    fn recheck(&mut self) -> Result<(), Self::Error> {
        self.work.recheck()
    }
    fn complete(&mut self, raw: Self::Facts) -> Result<Self::Output, Self::Error> {
        let pending = self.work.complete(raw);
        let report = completion::complete(pending, self.effects);
        self.effects = report.effects;
        report.outcome
    }
    fn outcome_unknown(&self) -> Self::Error {
        self.work.outcome_unknown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_use::{Authentication, Route, UseClaims, UseGrant},
        manifest,
        provider_exchange::Provider,
        read_transition::{Phase, Request},
    };
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone)]
    struct Source {
        calls: Rc<RefCell<Vec<&'static str>>>,
        fault: Option<usize>,
        preflight: bool,
        final_effect: bool,
        write: bool,
    }
    impl Source {
        fn step(&self, name: &'static str) -> Result<(), &'static str> {
            let index = self.calls.borrow().len();
            self.calls.borrow_mut().push(name);
            if self.fault == Some(index) {
                Err("failure")
            } else {
                Ok(())
            }
        }
        fn factory(&self, name: &'static str) {
            self.calls.borrow_mut().push(name);
        }
    }
    struct Effect {
        value: u8,
        write: bool,
    }
    struct ProviderWork {
        source: Source,
        effect: Effect,
    }
    fn stamp(write: bool) -> manifest::AdmissionStamp {
        let claims = || UseClaims {
            binding: b"peer".to_vec(),
            policy: b"policy".to_vec(),
            grant: b"grant".to_vec(),
            issued_at: 1,
            expires_at: 100,
        };
        let grant = UseGrant {
            claims: claims(),
            operation: b"op".to_vec(),
            active: true,
            route: Route {
                host: b"api.example.org".to_vec(),
                port: 443,
                path: b"/".to_vec(),
                authentication: Authentication::Bearer,
            },
        };
        manifest::current(
            &claims(),
            &grant,
            &b"op".to_vec(),
            &b"op".to_vec(),
            write,
            true,
            2,
            1,
        )
        .ok()
        .unwrap()
    }
    impl Provider for ProviderWork {
        type Channel = u8;
        type Output = u8;
        type Error = &'static str;
        const INVALID_POLICY: Self::Error = "policy";
        const OUTCOME_UNKNOWN: Self::Error = "unknown";
        fn setup(&mut self) -> Result<u8, Self::Error> {
            self.source.step("setup")?;
            Ok(0)
        }
        fn recheck(&mut self) -> Result<manifest::AdmissionStamp, Self::Error> {
            self.source.step("current")?;
            Ok(stamp(self.effect.write))
        }
        fn send(&mut self, channel: &mut u8) -> Result<(), Self::Error> {
            self.source.step("send")?;
            *channel = self.effect.value * 2;
            Ok(())
        }
        fn receive(&mut self, channel: u8) -> Result<u8, Self::Error> {
            self.source.step("receive")?;
            Ok(channel)
        }
    }
    impl dispatch::Work for ProviderWork {
        const INVALID_TRANSITION: Self::Error = "invalid";
        fn effect_write(&self) -> bool {
            self.effect.write
        }
        fn prepare(&mut self) -> Result<(), Self::Error> {
            self.source.step("prepare")
        }
        fn audit(&mut self, _: Phase) -> Result<(), Self::Error> {
            self.source.step("audit")
        }
        fn configure(&mut self, _: bool) -> Result<(), Self::Error> {
            self.source.step("configure")
        }
        fn check(&mut self) -> Result<(), Self::Error> {
            self.source.step("dispatch.check")
        }
        fn reserve(&mut self) -> Result<(), Self::Error> {
            self.source.step("reserve")
        }
        fn finish(&mut self) -> Result<(), Self::Error> {
            self.source.step("finish")
        }
    }
    struct CompletionWork {
        source: Source,
        raw: u8,
    }
    impl completion::Work for CompletionWork {
        type Output = u8;
        type Error = &'static str;
        const INVALID_TRANSITION: Self::Error = "invalid";
        fn select(&mut self) -> Result<u8, Self::Error> {
            self.source.step("select")?;
            Ok(self.raw + 1)
        }
        fn recheck(&mut self, phase: read_transition::CompletionPhase) -> Result<(), Self::Error> {
            self.source.step(match phase {
                read_transition::CompletionPhase::BeforeAudit => "before",
                read_transition::CompletionPhase::BeforeRelease => "after",
            })
        }
        fn audit(&mut self) -> Result<(), Self::Error> {
            self.source.step("completed")
        }
    }
    impl Work for Source {
        type Facts = u8;
        type Effect = Effect;
        type Output = u8;
        type Error = &'static str;
        type Dispatch = ProviderWork;
        type Completion = CompletionWork;
        const INVALID_TRANSITION: Self::Error = "invalid";
        const INVALID_POLICY: Self::Error = "policy";
        fn preflight(&self) -> Result<Option<Effect>, Self::Error> {
            self.step("plan.preflight")?;
            Ok(self.preflight.then_some(Effect {
                value: 10,
                write: false,
            }))
        }
        fn empty_facts(&self) -> u8 {
            0
        }
        fn final_effect(&self, facts: &u8) -> Result<Option<Effect>, Self::Error> {
            self.step("plan.final")?;
            Ok(self.final_effect.then_some(Effect {
                value: facts + 1,
                write: self.write,
            }))
        }
        fn effect_write(&self, effect: &Effect) -> bool {
            effect.write
        }
        fn operation_write(&self) -> bool {
            self.write
        }
        fn dispatch(&mut self, phase: Phase, effect: Effect) -> DispatchPlan<ProviderWork> {
            self.factory("factory.dispatch");
            let keyed_write = matches!(phase, Phase::Final) && effect.write;
            DispatchPlan {
                work: ProviderWork {
                    source: self.clone(),
                    effect,
                },
                keyed_write,
            }
        }
        fn complete(&mut self, raw: u8) -> CompletionWork {
            self.factory("factory.complete");
            CompletionWork {
                source: self.clone(),
                raw,
            }
        }
        fn recheck(&mut self) -> Result<(), Self::Error> {
            self.step("request.check")
        }
        fn outcome_unknown(&self) -> Self::Error {
            "unknown"
        }
    }
    fn source(preflight: bool, final_effect: bool, write: bool) -> Source {
        Source {
            calls: Rc::new(RefCell::new(Vec::new())),
            fault: None,
            preflight,
            final_effect,
            write,
        }
    }

    #[test]
    fn whole_request_has_exact_selected_value_and_terminal_failure_prefixes() {
        for (preflight, final_effect, write, selected) in [
            (false, true, false, 3),
            (true, false, false, 21),
            (true, true, false, 43),
            (false, true, true, 3),
        ] {
            let original = source(preflight, final_effect, write);
            let out = read_transition::run_current(Pending::new(original.clone())).unwrap();
            assert_eq!(out.into_value(), selected);
            let expected = original.calls.borrow().clone();
            for (index, name) in expected.iter().enumerate() {
                if name.starts_with("factory.") {
                    continue;
                }
                let mut failed = source(preflight, final_effect, write);
                failed.fault = Some(index);
                let calls = failed.calls.clone();
                let out = read_transition::run_current(Pending::new(failed));
                assert_eq!(*calls.borrow(), expected[..=index]);
                let uncertain = write
                    && [
                        "send",
                        "receive",
                        "finish",
                        "select",
                        "before",
                        "completed",
                        "after",
                    ]
                    .contains(name);
                assert!(
                    matches!(out, Err(error) if error == if uncertain { "unknown" } else { "failure" })
                );
            }
        }
    }

    #[test]
    fn invalid_phase_or_write_cannot_construct_any_native_adapter() {
        for (phase, operation_write) in [(Phase::Preflight, true), (Phase::Final, false)] {
            let original = source(false, true, operation_write);
            let calls = original.calls.clone();
            let mut pending = Pending::new(original);
            assert_eq!(
                Request::dispatch(
                    &mut pending,
                    phase,
                    Effect {
                        value: 1,
                        write: true
                    }
                ),
                Err("policy")
            );
            assert!(calls.borrow().is_empty());
            assert!(!pending.effects().phase(phase).audit_attempted());
        }
    }

    #[test]
    fn both_owned_reports_keep_failure_receipts_and_prevent_replay() {
        let mut original = source(false, true, false);
        original.fault = Some(7); // raw send, after audit and current stamp
        let calls = original.calls.clone();
        let mut pending = Pending::new(original);
        assert_eq!(
            Request::dispatch(
                &mut pending,
                Phase::Final,
                Effect {
                    value: 1,
                    write: false
                }
            ),
            Err("failure")
        );
        assert_eq!(calls.borrow().last(), Some(&"send"));
        let receipt = pending.effects().phase(Phase::Final);
        assert!(receipt.audit_acknowledged() && receipt.provider_attempted());
        assert!(!receipt.provider_completed());
        let before = calls.borrow().len();
        assert_eq!(
            Request::dispatch(
                &mut pending,
                Phase::Final,
                Effect {
                    value: 1,
                    write: false
                }
            ),
            Err("invalid")
        );
        assert_eq!(&calls.borrow()[before..], &["factory.dispatch", "prepare"]);

        let mut original = source(false, true, false);
        original.fault = Some(1); // selection, with every receipt flag still false
        let calls = original.calls.clone();
        let mut pending = Pending::new(original);
        assert!(matches!(Request::complete(&mut pending, 8), Err("failure")));
        assert!(!pending.effects().completion().selected());
        assert!(matches!(Request::complete(&mut pending, 8), Err("invalid")));
        assert_eq!(
            *calls.borrow(),
            ["factory.complete", "select", "factory.complete"]
        );
        assert!(!pending.effects().can_return_value());
    }
}
