//! Production-owned manifest dispatch around explicit native primitives.
//! Receipt and local send state are private to this controller. Primitive
//! authority, audit durability, TLS/Write/parser semantics and other I/O remain
//! separate contracts; a returned error retains the actual attempted prefix.
use crate::{
    manifest::AdmissionStamp,
    provider_exchange::{self, Provider, SendState, Stage},
    read_transition::{self, Phase, Prepared},
    request_effects::RequestEffects,
};

pub trait Work: Provider {
    const INVALID_TRANSITION: Self::Error;
    fn effect_write(&self) -> bool;
    fn prepare(&mut self) -> Result<(), Self::Error>;
    fn audit(&mut self, phase: Phase) -> Result<(), Self::Error>;
    fn configure(&mut self, keyed_write: bool) -> Result<(), Self::Error>;
    fn check(&mut self) -> Result<(), Self::Error>;
    fn reserve(&mut self) -> Result<(), Self::Error>;
    fn finish(&mut self) -> Result<(), Self::Error>;
}

pub struct Report<W: Work> {
    pub outcome: Result<W::Output, W::Error>,
    pub work: W,
    pub effects: RequestEffects,
    pub local: SendState,
    pub provider_stage: Option<Stage>,
    pub current: Option<AdmissionStamp>,
}

struct Pending<W: Work> {
    work: W,
    effects: RequestEffects,
    local: SendState,
    phase: Phase,
    write: bool,
    provider_stage: Option<Stage>,
    current: Option<AdmissionStamp>,
}
impl<W: Work> Provider for Pending<W> {
    type Channel = W::Channel;
    type Output = W::Output;
    type Error = W::Error;
    const INVALID_POLICY: Self::Error = W::INVALID_POLICY;
    const OUTCOME_UNKNOWN: Self::Error = W::OUTCOME_UNKNOWN;

    fn setup(&mut self) -> Result<Self::Channel, Self::Error> {
        self.work.setup()
    }
    fn recheck(&mut self) -> Result<AdmissionStamp, Self::Error> {
        if !self.local.begin_check() {
            return Err(W::INVALID_TRANSITION);
        }
        let stamp = match self.work.recheck() {
            Ok(stamp) => stamp,
            Err(error) => return Err(error),
        };
        if !self.local.finish_check(stamp) {
            return Err(W::INVALID_TRANSITION);
        }
        Ok(stamp)
    }
    fn send(&mut self, channel: &mut Self::Channel) -> Result<(), Self::Error> {
        if !self
            .effects
            .begin_send(self.phase, &mut self.local, self.write)
        {
            return Err(W::INVALID_TRANSITION);
        }
        self.work.send(channel)
    }
    fn receive(&mut self, channel: Self::Channel) -> Result<Self::Output, Self::Error> {
        self.work.receive(channel)
    }
}

fn audit<W: Work>(
    pending: &mut Pending<W>,
    prepared: Prepared,
) -> Result<read_transition::Audited, W::Error> {
    match pending.work.prepare() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    if !pending.effects.begin_dispatch_audit(&prepared) {
        return Err(W::INVALID_TRANSITION);
    }
    match pending.work.audit(prepared.phase()) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    let audited = match read_transition::acknowledge(prepared, true) {
        Ok(audited) => audited,
        Err(_) => return Err(W::INVALID_TRANSITION),
    };
    if !pending.effects.acknowledge_dispatch(&audited) {
        return Err(W::INVALID_TRANSITION);
    }
    Ok(audited)
}
fn exchange<W: Work>(
    pending: &mut Pending<W>,
    audited: &read_transition::Audited,
) -> Result<W::Output, W::Error> {
    if audited.is_write() != pending.work.effect_write() {
        return Err(W::INVALID_POLICY);
    }
    if !pending.effects.begin_provider(audited) {
        return Err(W::INVALID_TRANSITION);
    }
    pending.phase = audited.phase();
    pending.write = audited.is_write();
    let report = provider_exchange::exchange(pending, audited);
    pending.provider_stage = Some(report.stage());
    pending.current = report.current();
    let value = match report.into_result() {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if !pending.effects.provider_completed(pending.phase) {
        return Err(W::INVALID_TRANSITION);
    }
    Ok(value)
}
fn finish<W: Work>(pending: &mut Pending<W>, keyed_write: bool) -> Result<(), W::Error> {
    let finished = if keyed_write {
        pending.work.finish()
    } else {
        Ok(())
    };
    match finished {
        Ok(()) => (),
        Err(_) => return Err(W::OUTCOME_UNKNOWN),
    }
    if !pending.effects.finish_dispatch(pending.phase) {
        return Err(W::INVALID_TRANSITION);
    }
    Ok(())
}
fn run<W: Work>(
    pending: &mut Pending<W>,
    prepared: Prepared,
    keyed_write: bool,
) -> Result<W::Output, W::Error> {
    let audited = match audit(pending, prepared) {
        Ok(audited) => audited,
        Err(error) => return Err(error),
    };
    match pending.work.configure(keyed_write) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    match pending.work.check() {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    let reserved = if keyed_write {
        pending.work.reserve()
    } else {
        Ok(())
    };
    match reserved {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    let value = match exchange(pending, &audited) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    match finish(pending, keyed_write) {
        Ok(()) => (),
        Err(error) => return Err(error),
    }
    Ok(value)
}

pub fn dispatch<W: Work>(
    work: W,
    prepared: Result<Prepared, W::Error>,
    effects: RequestEffects,
    keyed_write: bool,
) -> Report<W> {
    let phase = match &prepared {
        Ok(prepared) => prepared.phase(),
        Err(_) => Phase::Final,
    };
    let mut pending = Pending {
        work,
        effects,
        local: SendState::new(),
        phase,
        write: false,
        provider_stage: None,
        current: None,
    };
    let outcome = match prepared {
        Ok(prepared) => run(&mut pending, prepared, keyed_write),
        Err(error) => Err(error),
    };
    Report {
        outcome,
        work: pending.work,
        effects: pending.effects,
        local: pending.local,
        provider_stage: pending.provider_stage,
        current: pending.current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_use::{Authentication, Route, UseClaims, UseGrant};

    struct Primitives {
        calls: Vec<&'static str>,
        fault: Option<&'static str>,
        write: bool,
    }
    impl Primitives {
        fn call(&mut self, name: &'static str) -> Result<(), &'static str> {
            self.calls.push(name);
            if self.fault == Some(name) {
                Err(name)
            } else {
                Ok(())
            }
        }
    }
    fn stamp(write: bool) -> AdmissionStamp {
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
        crate::manifest::current(
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
    impl Provider for Primitives {
        type Channel = u8;
        type Output = u8;
        type Error = &'static str;
        const INVALID_POLICY: Self::Error = "policy";
        const OUTCOME_UNKNOWN: Self::Error = "uncertain";
        fn setup(&mut self) -> Result<u8, Self::Error> {
            self.call("setup")?;
            Ok(10)
        }
        fn recheck(&mut self) -> Result<AdmissionStamp, Self::Error> {
            self.call("current")?;
            Ok(stamp(self.write))
        }
        fn send(&mut self, channel: &mut u8) -> Result<(), Self::Error> {
            assert_eq!(*channel, 10);
            *channel = 20;
            self.call("send")
        }
        fn receive(&mut self, channel: u8) -> Result<u8, Self::Error> {
            assert_eq!(channel, 20);
            self.call("receive")?;
            Ok(channel)
        }
    }
    impl Work for Primitives {
        const INVALID_TRANSITION: Self::Error = "invalid";
        fn effect_write(&self) -> bool {
            self.write
        }
        fn prepare(&mut self) -> Result<(), Self::Error> {
            self.call("prepare")
        }
        fn audit(&mut self, _: Phase) -> Result<(), Self::Error> {
            self.call("audit")
        }
        fn configure(&mut self, _: bool) -> Result<(), Self::Error> {
            self.call("configure")
        }
        fn check(&mut self) -> Result<(), Self::Error> {
            self.call("check")
        }
        fn reserve(&mut self) -> Result<(), Self::Error> {
            self.call("reserve")
        }
        fn finish(&mut self) -> Result<(), Self::Error> {
            self.call("finish")
        }
    }
    fn prepared(phase: Phase, write: bool) -> Result<Prepared, &'static str> {
        read_transition::prepare(phase, write, write).map_err(|_| "policy")
    }
    #[test]
    fn exact_primitive_failure_prefixes_preserve_receipts_and_write_uncertainty() {
        for keyed in [false, true] {
            let calls: &[&str] = if keyed {
                &[
                    "prepare",
                    "audit",
                    "configure",
                    "check",
                    "reserve",
                    "setup",
                    "current",
                    "send",
                    "receive",
                    "finish",
                ]
            } else {
                &[
                    "prepare",
                    "audit",
                    "configure",
                    "check",
                    "setup",
                    "current",
                    "send",
                    "receive",
                ]
            };
            for (index, fault) in calls.iter().enumerate() {
                let report = dispatch(
                    Primitives {
                        calls: vec![],
                        fault: Some(fault),
                        write: keyed,
                    },
                    prepared(Phase::Final, keyed),
                    RequestEffects::new(),
                    keyed,
                );
                assert_eq!(report.work.calls, calls[..=index]);
                let expected = if keyed && ["send", "receive", "finish"].contains(fault) {
                    "uncertain"
                } else {
                    fault
                };
                assert_eq!(report.outcome, Err(expected));
                let receipt = report.effects.phase(Phase::Final);
                assert_eq!(receipt.audit_attempted(), index >= 1);
                assert_eq!(receipt.audit_acknowledged(), index >= 2);
                assert_eq!(
                    receipt.provider_ready(),
                    ["setup", "current", "send", "receive", "finish"].contains(fault)
                );
                assert_eq!(
                    receipt.provider_attempted(),
                    ["send", "receive", "finish"].contains(fault)
                );
                assert_eq!(receipt.provider_completed(), *fault == "finish");
                assert!(!receipt.dispatch_succeeded());
                assert!(!report.effects.can_return_value());
            }
        }
    }
    #[test]
    fn rejected_preparation_invokes_no_primitive() {
        let mut report = dispatch(
            Primitives {
                calls: vec![],
                fault: None,
                write: false,
            },
            Err("policy"),
            RequestEffects::new(),
            false,
        );
        assert_eq!(report.outcome, Err("policy"));
        assert!(report.work.calls.is_empty());
        assert!(report.provider_stage.is_none() && report.current.is_none());
        assert!(!report.effects.phase(Phase::Final).audit_attempted());
        assert!(report.effects.begin_completion());
    }
    #[test]
    fn both_read_phases_and_keyed_write_complete_exactly_once() {
        for (phase, write) in [
            (Phase::Preflight, false),
            (Phase::Final, false),
            (Phase::Final, true),
        ] {
            let report = dispatch(
                Primitives {
                    calls: vec![],
                    fault: None,
                    write,
                },
                prepared(phase, write),
                RequestEffects::new(),
                write,
            );
            assert_eq!(report.outcome, Ok(20));
            let receipt = report.effects.phase(phase);
            assert!(
                receipt.audit_acknowledged()
                    && receipt.provider_attempted()
                    && receipt.provider_completed()
                    && receipt.dispatch_succeeded()
            );
            assert!(report.local.attempted());
            let before = report.work.calls.clone();
            let repeat = dispatch(report.work, prepared(phase, write), report.effects, write);
            assert_eq!(repeat.outcome, Err("invalid"));
            assert_eq!(repeat.work.calls, [before, vec!["prepare"]].concat());
            assert!(repeat.effects.phase(phase).provider_attempted());
        }
    }
}
