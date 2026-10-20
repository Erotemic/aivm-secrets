//! The production manifest provider continuation after an acknowledged audit.
//! TLS and I/O are explicit mutable adapters. A failed send is still an attempt;
//! it is never inferred from provider arrival or successful response parsing.
use crate::{
    manifest::AdmissionStamp,
    read_transition::{Audited, Phase},
};

pub trait Provider {
    type Channel;
    type Output;
    type Error;
    const INVALID_POLICY: Self::Error;
    const OUTCOME_UNKNOWN: Self::Error;

    fn setup(&mut self) -> Result<Self::Channel, Self::Error>;
    fn recheck(&mut self) -> Result<AdmissionStamp, Self::Error>;
    fn send(&mut self, channel: &mut Self::Channel) -> Result<(), Self::Error>;
    fn receive(&mut self, channel: Self::Channel) -> Result<Self::Output, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Setup,
    Admission,
    Send,
    Response,
    Complete,
}
impl Stage {
    pub fn attempted(self) -> bool {
        matches!(self, Self::Send | Self::Response | Self::Complete)
    }
}

pub struct Report<T, E> {
    phase: Phase,
    stage: Stage,
    current: Option<AdmissionStamp>,
    result: Result<T, E>,
}
impl<T, E> Report<T, E> {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn current(&self) -> Option<AdmissionStamp> {
        self.current
    }
    pub fn into_result(self) -> Result<T, E> {
        self.result
    }
}

pub fn exchange<P: Provider>(ops: &mut P, audited: &Audited) -> Report<P::Output, P::Error> {
    let phase = audited.phase();
    let write = audited.is_write();
    let mut channel = match ops.setup() {
        Ok(channel) => channel,
        Err(error) => {
            return Report {
                phase,
                stage: Stage::Setup,
                current: None,
                result: Err(error),
            }
        }
    };
    let current = match ops.recheck() {
        Ok(current) => current,
        Err(error) => {
            return Report {
                phase,
                stage: Stage::Admission,
                current: None,
                result: Err(error),
            }
        }
    };
    // A writing effect cannot reuse a current check of a nonwriting operation.
    if write && !current.write() {
        return Report {
            phase,
            stage: Stage::Admission,
            current: Some(current),
            result: Err(P::INVALID_POLICY),
        };
    }
    match ops.send(&mut channel) {
        Ok(()) => (),
        Err(error) => {
            return Report {
                phase,
                stage: Stage::Send,
                current: Some(current),
                result: Err(if write { P::OUTCOME_UNKNOWN } else { error }),
            }
        }
    }
    match ops.receive(channel) {
        Ok(value) => Report {
            phase,
            stage: Stage::Complete,
            current: Some(current),
            result: Ok(value),
        },
        Err(error) => Report {
            phase,
            stage: Stage::Response,
            current: Some(current),
            result: Err(if write { P::OUTCOME_UNKNOWN } else { error }),
        },
    }
}

// The native raw writer owns this state in addition to the outer request
// receipt. No retry or reset operation exists on a live provider continuation.
enum SendProgress {
    Empty,
    Checking,
    Halted,
    Checked(AdmissionStamp),
    Attempted(AdmissionStamp),
}
pub struct SendState {
    progress: SendProgress,
}
impl SendState {
    pub fn new() -> Self {
        Self {
            progress: SendProgress::Empty,
        }
    }
    pub fn begin_check(&mut self) -> bool {
        match self.progress {
            SendProgress::Empty => {
                self.progress = SendProgress::Checking;
                true
            }
            SendProgress::Attempted(_) => false,
            _ => {
                self.progress = SendProgress::Halted;
                false
            }
        }
    }
    pub fn finish_check(&mut self, stamp: AdmissionStamp) -> bool {
        match self.progress {
            SendProgress::Checking => {
                self.progress = SendProgress::Checked(stamp);
                true
            }
            SendProgress::Attempted(_) => false,
            _ => {
                self.progress = SendProgress::Halted;
                false
            }
        }
    }
    pub fn begin_send(&mut self, write: bool) -> bool {
        match self.progress {
            SendProgress::Checked(stamp) => {
                if write && !stamp.write() {
                    self.progress = SendProgress::Halted;
                    return false;
                }
                self.progress = SendProgress::Attempted(stamp);
                true
            }
            SendProgress::Attempted(_) => false,
            _ => {
                self.progress = SendProgress::Halted;
                false
            }
        }
    }
    pub fn stamp(&self) -> Option<AdmissionStamp> {
        match self.progress {
            SendProgress::Checked(stamp) | SendProgress::Attempted(stamp) => Some(stamp),
            _ => None,
        }
    }
    pub fn attempted(&self) -> bool {
        matches!(self.progress, SendProgress::Attempted(_))
    }
}
impl Default for SendState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_use::{Authentication, Route, UseClaims, UseGrant},
        manifest,
    };

    fn claims() -> UseClaims {
        UseClaims {
            binding: b"client".to_vec(),
            policy: b"policy".to_vec(),
            grant: b"grant".to_vec(),
            issued_at: 1,
            expires_at: 100,
        }
    }
    fn current(write: bool) -> AdmissionStamp {
        let grant = UseGrant {
            claims: claims(),
            operation: b"read".to_vec(),
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
            &b"read".to_vec(),
            &b"read".to_vec(),
            write,
            true,
            2,
            1,
        )
        .ok()
        .unwrap()
    }
    fn audited(phase: Phase, write: bool) -> Audited {
        crate::read_transition::acknowledge(
            crate::read_transition::prepare(phase, write, write)
                .ok()
                .unwrap(),
            true,
        )
        .ok()
        .unwrap()
    }
    struct Probe {
        calls: Vec<&'static str>,
        fault: Option<&'static str>,
        current_write: bool,
    }
    impl Probe {
        fn step(&mut self, stage: &'static str) -> Result<(), &'static str> {
            self.calls.push(stage);
            if self.fault == Some(stage) {
                Err(stage)
            } else {
                Ok(())
            }
        }
    }
    impl Provider for Probe {
        type Channel = u8;
        type Output = u8;
        type Error = &'static str;
        const INVALID_POLICY: Self::Error = "invalid-policy";
        const OUTCOME_UNKNOWN: Self::Error = "uncertain";
        fn setup(&mut self) -> Result<u8, Self::Error> {
            self.step("setup")?;
            Ok(10)
        }
        fn recheck(&mut self) -> Result<AdmissionStamp, Self::Error> {
            self.step("current")?;
            Ok(current(self.current_write))
        }
        fn send(&mut self, channel: &mut u8) -> Result<(), Self::Error> {
            assert_eq!(*channel, 10);
            *channel = 20; // Updated channel must be passed to the parser.
            self.step("send")
        }
        fn receive(&mut self, channel: u8) -> Result<u8, Self::Error> {
            assert_eq!(channel, 20);
            self.step("receive")?;
            Ok(channel)
        }
    }
    #[test]
    fn all_provider_failure_prefixes_preserve_order_state_and_uncertainty() {
        let stages = [Stage::Setup, Stage::Admission, Stage::Send, Stage::Response];
        let calls = ["setup", "current", "send", "receive"];
        for (index, stage) in stages.iter().enumerate() {
            for write in [false, true] {
                let mut probe = Probe {
                    calls: Vec::new(),
                    fault: Some(calls[index]),
                    current_write: write,
                };
                let report = exchange(&mut probe, &audited(Phase::Final, write));
                assert_eq!(report.stage(), *stage);
                assert_eq!(report.stage().attempted(), index >= 2);
                assert_eq!(report.current().is_some(), index >= 2);
                assert_eq!(
                    report.into_result(),
                    Err(if write && index >= 2 {
                        "uncertain"
                    } else {
                        calls[index]
                    })
                );
                assert_eq!(probe.calls, calls[..=index]);
            }
        }
    }
    #[test]
    fn native_send_state_rejects_unchecked_repeated_and_rebound_attempts() {
        let mut unchecked = SendState::new();
        assert!(!unchecked.begin_send(false));
        assert!(!unchecked.begin_check());
        let mut state = SendState::new();
        assert!(state.begin_check());
        assert!(state.finish_check(current(false)));
        assert!(state.begin_send(false));
        assert!(state.attempted());
        assert!(!state.begin_send(false));
        assert!(!state.begin_check());
        assert!(!state.finish_check(current(true)));
        assert!(!state.begin_send(true));
        assert!(state.attempted());
        assert!(!state.stamp().unwrap().write());
        let mut mismatch = SendState::new();
        assert!(mismatch.begin_check());
        assert!(mismatch.finish_check(current(false)));
        assert!(!mismatch.begin_send(true));
        assert!(!mismatch.begin_send(false));
        assert!(!mismatch.begin_check());
    }
    #[test]
    fn successful_reads_keep_phase_current_stamp_and_updated_channel() {
        for phase in [Phase::Preflight, Phase::Final] {
            let mut probe = Probe {
                calls: Vec::new(),
                fault: None,
                current_write: false,
            };
            let report = exchange(&mut probe, &audited(phase, false));
            assert_eq!(report.phase(), phase);
            assert_eq!(report.stage(), Stage::Complete);
            let stamp = report.current().unwrap();
            assert_eq!((stamp.now(), stamp.elapsed(), stamp.write()), (2, 1, false));
            assert_eq!(report.into_result(), Ok(20));
            assert_eq!(probe.calls, ["setup", "current", "send", "receive"]);
        }
    }
    #[test]
    fn writing_effect_cannot_use_a_read_only_current_stamp() {
        let mut probe = Probe {
            calls: Vec::new(),
            fault: None,
            current_write: false,
        };
        let report = exchange(&mut probe, &audited(Phase::Final, true));
        assert_eq!(report.stage(), Stage::Admission);
        assert!(!report.stage().attempted());
        assert_eq!(report.into_result(), Err("invalid-policy"));
        assert_eq!(probe.calls, ["setup", "current"]);
    }
}
