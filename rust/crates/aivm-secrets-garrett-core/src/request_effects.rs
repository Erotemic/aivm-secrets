//! Production request-wide receipt and ordering gate. The native audit,
//! provider submission and completed-value adapters all borrow this same state.
//! Markers contain no credential, provider value or serialized guest data.
use crate::{
    manifest::AdmissionStamp,
    provider_exchange::SendState,
    read_transition::{Audited, CompletionPhase, Phase, Prepared},
};

#[derive(Clone, Copy)]
pub struct DispatchRecord {
    audit_attempted: bool,
    audit_acknowledged: bool,
    provider_ready: bool,
    current: Option<AdmissionStamp>,
    provider_attempted: bool,
    provider_completed: bool,
    dispatch_succeeded: bool,
}
impl DispatchRecord {
    fn empty() -> Self {
        Self {
            audit_attempted: false,
            audit_acknowledged: false,
            provider_ready: false,
            current: None,
            provider_attempted: false,
            provider_completed: false,
            dispatch_succeeded: false,
        }
    }
    pub fn audit_attempted(&self) -> bool {
        self.audit_attempted
    }
    pub fn audit_acknowledged(&self) -> bool {
        self.audit_acknowledged
    }
    pub fn provider_ready(&self) -> bool {
        self.provider_ready
    }
    pub fn current(&self) -> Option<AdmissionStamp> {
        self.current
    }
    pub fn provider_attempted(&self) -> bool {
        self.provider_attempted
    }
    pub fn provider_completed(&self) -> bool {
        self.provider_completed
    }
    pub fn dispatch_succeeded(&self) -> bool {
        self.dispatch_succeeded
    }
}
#[derive(Clone, Copy)]
pub struct CompletionRecord {
    selected: bool,
    before_checked: bool,
    audit_attempted: bool,
    audit_acknowledged: bool,
    after_checked: bool,
    value_ready: bool,
}
impl CompletionRecord {
    fn empty() -> Self {
        Self {
            selected: false,
            before_checked: false,
            audit_attempted: false,
            audit_acknowledged: false,
            after_checked: false,
            value_ready: false,
        }
    }
    pub fn selected(&self) -> bool {
        self.selected
    }
    pub fn before_checked(&self) -> bool {
        self.before_checked
    }
    pub fn audit_attempted(&self) -> bool {
        self.audit_attempted
    }
    pub fn audit_acknowledged(&self) -> bool {
        self.audit_acknowledged
    }
    pub fn after_checked(&self) -> bool {
        self.after_checked
    }
    pub fn value_ready(&self) -> bool {
        self.value_ready
    }
}
#[derive(Clone, Copy)]
enum Progress {
    Entry,
    DispatchAudit(Phase),
    Audited(Phase),
    ProviderReady(Phase),
    ProviderAttempted(Phase),
    ProviderCompleted(Phase),
    DispatchReturned(Phase),
    Selecting,
    Selected,
    CheckingBefore,
    BeforeAudit,
    CompletionAudit,
    CompletionAudited,
    CheckingAfter,
    AfterAudit,
    ValueReady,
    Halted,
}
#[derive(Clone, Copy)]
pub struct RequestEffects {
    preflight: DispatchRecord,
    final_effect: DispatchRecord,
    completion: CompletionRecord,
    progress: Progress,
}
impl RequestEffects {
    pub fn new() -> Self {
        Self {
            preflight: DispatchRecord::empty(),
            final_effect: DispatchRecord::empty(),
            completion: CompletionRecord::empty(),
            progress: Progress::Entry,
        }
    }
    fn reject(&mut self) -> bool {
        self.progress = Progress::Halted;
        false
    }
    pub fn phase(&self, phase: Phase) -> DispatchRecord {
        match phase {
            Phase::Preflight => self.preflight,
            Phase::Final => self.final_effect,
        }
    }
    fn set_phase(&mut self, phase: Phase, record: DispatchRecord) {
        match phase {
            Phase::Preflight => self.preflight = record,
            Phase::Final => self.final_effect = record,
        }
    }
    pub fn completion(&self) -> CompletionRecord {
        self.completion
    }
    pub fn can_return_value(&self) -> bool {
        matches!(self.progress, Progress::ValueReady)
    }
    pub fn begin_dispatch_audit(&mut self, prepared: &Prepared) -> bool {
        let phase = prepared.phase();
        let allowed = matches!(
            (phase, self.progress),
            (Phase::Preflight, Progress::Entry)
                | (
                    Phase::Final,
                    Progress::Entry | Progress::DispatchReturned(Phase::Preflight)
                )
        );
        if !allowed {
            return self.reject();
        }
        let mut record = self.phase(phase);
        record.audit_attempted = true;
        self.set_phase(phase, record);
        self.progress = Progress::DispatchAudit(phase);
        true
    }
    pub fn acknowledge_dispatch(&mut self, audited: &Audited) -> bool {
        let phase = audited.phase();
        match self.progress {
            Progress::DispatchAudit(recorded) if recorded == phase => (),
            _ => return self.reject(),
        }
        let mut record = self.phase(phase);
        record.audit_acknowledged = true;
        self.set_phase(phase, record);
        self.progress = Progress::Audited(phase);
        true
    }
    pub fn begin_provider(&mut self, audited: &Audited) -> bool {
        let phase = audited.phase();
        match self.progress {
            Progress::Audited(recorded) if recorded == phase => (),
            _ => return self.reject(),
        }
        let mut record = self.phase(phase);
        record.provider_ready = true;
        self.set_phase(phase, record);
        self.progress = Progress::ProviderReady(phase);
        true
    }
    /// Validate the request phase before arming the native writer. Both
    /// receipts are marked together only when the local current gate succeeds.
    pub fn begin_send(&mut self, phase: Phase, local: &mut SendState, write: bool) -> bool {
        match self.progress {
            Progress::ProviderReady(recorded) if recorded == phase => (),
            _ => return self.reject(),
        }
        if !local.begin_send(write) {
            return self.reject();
        }
        let mut record = self.phase(phase);
        record.current = local.stamp();
        record.provider_attempted = true;
        self.set_phase(phase, record);
        self.progress = Progress::ProviderAttempted(phase);
        true
    }
    pub fn provider_completed(&mut self, phase: Phase) -> bool {
        match self.progress {
            Progress::ProviderAttempted(recorded) if recorded == phase => (),
            _ => return self.reject(),
        }
        let mut record = self.phase(phase);
        record.provider_completed = true;
        self.set_phase(phase, record);
        self.progress = Progress::ProviderCompleted(phase);
        true
    }
    pub fn finish_dispatch(&mut self, phase: Phase) -> bool {
        match self.progress {
            Progress::ProviderCompleted(recorded) if recorded == phase => (),
            _ => return self.reject(),
        }
        let mut record = self.phase(phase);
        record.dispatch_succeeded = true;
        self.set_phase(phase, record);
        self.progress = Progress::DispatchReturned(phase);
        true
    }
    pub fn begin_completion(&mut self) -> bool {
        match self.progress {
            Progress::Entry | Progress::DispatchReturned(_) => (),
            _ => return self.reject(),
        }
        self.progress = Progress::Selecting;
        true
    }
    pub fn selected(&mut self) -> bool {
        if !matches!(self.progress, Progress::Selecting) {
            return self.reject();
        }
        self.completion.selected = true;
        self.progress = Progress::Selected;
        true
    }
    pub fn begin_completion_check(&mut self, phase: CompletionPhase) -> bool {
        match (phase, self.progress) {
            (CompletionPhase::BeforeAudit, Progress::Selected) => {
                self.progress = Progress::CheckingBefore
            }
            (CompletionPhase::BeforeRelease, Progress::CompletionAudited) => {
                self.progress = Progress::CheckingAfter
            }
            _ => return self.reject(),
        };
        true
    }
    pub fn finish_completion_check(&mut self, phase: CompletionPhase) -> bool {
        match (phase, self.progress) {
            (CompletionPhase::BeforeAudit, Progress::CheckingBefore) => {
                self.completion.before_checked = true;
                self.progress = Progress::BeforeAudit;
            }
            (CompletionPhase::BeforeRelease, Progress::CheckingAfter) => {
                self.completion.after_checked = true;
                self.progress = Progress::AfterAudit;
            }
            _ => return self.reject(),
        };
        true
    }
    pub fn begin_completion_audit(&mut self) -> bool {
        if !matches!(self.progress, Progress::BeforeAudit) {
            return self.reject();
        }
        self.completion.audit_attempted = true;
        self.progress = Progress::CompletionAudit;
        true
    }
    pub fn acknowledge_completion_audit(&mut self) -> bool {
        if !matches!(self.progress, Progress::CompletionAudit) {
            return self.reject();
        }
        self.completion.audit_acknowledged = true;
        self.progress = Progress::CompletionAudited;
        true
    }
    /// Authorize the completed native value; this is not a guest frame write.
    pub fn value_ready(&mut self) -> bool {
        if !matches!(self.progress, Progress::AfterAudit) {
            return self.reject();
        }
        self.completion.value_ready = true;
        self.progress = Progress::ValueReady;
        true
    }
}
impl Default for RequestEffects {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_use::{Authentication, Route, UseClaims, UseGrant};
    fn stamp() -> AdmissionStamp {
        let claims = || UseClaims {
            binding: b"client".to_vec(),
            policy: b"policy".to_vec(),
            grant: b"grant".to_vec(),
            issued_at: 1,
            expires_at: 100,
        };
        let grant = UseGrant {
            claims: claims(),
            operation: b"read".to_vec(),
            route: Route {
                host: b"api.example.org".to_vec(),
                port: 443,
                path: b"/".to_vec(),
                authentication: Authentication::Bearer,
            },
            active: true,
        };
        crate::manifest::current(
            &claims(),
            &grant,
            &b"read".to_vec(),
            &b"read".to_vec(),
            false,
            false,
            2,
            1,
        )
        .ok()
        .unwrap()
    }
    fn dispatch(state: &mut RequestEffects, phase: Phase) {
        let prepared = crate::read_transition::prepare(phase, false, false)
            .ok()
            .unwrap();
        assert!(state.begin_dispatch_audit(&prepared));
        let audited = crate::read_transition::acknowledge(prepared, true)
            .ok()
            .unwrap();
        assert!(state.acknowledge_dispatch(&audited));
        assert!(state.begin_provider(&audited));
        let mut local = SendState::new();
        assert!(local.begin_check());
        assert!(local.finish_check(stamp()));
        assert!(state.begin_send(phase, &mut local, false));
        assert!(state.provider_completed(phase));
        assert!(state.finish_dispatch(phase));
    }
    fn selected(state: &mut RequestEffects) {
        assert!(state.begin_completion());
        assert!(state.selected());
        assert!(state.begin_completion_check(CompletionPhase::BeforeAudit));
        assert!(state.finish_completion_check(CompletionPhase::BeforeAudit));
        assert!(state.begin_completion_audit());
        assert!(state.acknowledge_completion_audit());
    }
    #[test]
    fn successful_optional_phases_require_acknowledged_completion_and_both_checks() {
        for preflight in [false, true] {
            for final_effect in [false, true] {
                let mut state = RequestEffects::new();
                if preflight {
                    dispatch(&mut state, Phase::Preflight);
                }
                if final_effect {
                    dispatch(&mut state, Phase::Final);
                }
                selected(&mut state);
                assert!(!state.can_return_value());
                assert!(state.begin_completion_check(CompletionPhase::BeforeRelease));
                assert!(state.finish_completion_check(CompletionPhase::BeforeRelease));
                assert!(state.value_ready());
                assert!(state.can_return_value());
                assert_eq!(
                    state.phase(Phase::Preflight).provider_attempted(),
                    preflight
                );
                assert_eq!(state.phase(Phase::Final).provider_attempted(), final_effect);
                let completion = state.completion();
                assert!(
                    completion.selected()
                        && completion.before_checked()
                        && completion.audit_acknowledged()
                        && completion.after_checked()
                        && completion.value_ready()
                );
                // An ignored extra effect invalidates the saved completed result.
                assert!(!state.begin_completion_audit());
                assert!(!state.can_return_value());
                assert!(state.completion().audit_acknowledged());
            }
        }
    }
    #[test]
    fn completion_acknowledgement_survives_late_denial_without_a_value() {
        let mut state = RequestEffects::new();
        dispatch(&mut state, Phase::Final);
        selected(&mut state);
        assert!(state.begin_completion_check(CompletionPhase::BeforeRelease));
        // The actual fresh adapter returns Err: no finish call occurs.
        assert!(state.completion().audit_acknowledged());
        assert!(!state.completion().after_checked());
        assert!(!state.completion().value_ready());
        assert!(!state.value_ready());
        assert!(!state.can_return_value());
        assert!(state.phase(Phase::Final).provider_attempted());
        assert!(state.completion().audit_acknowledged());
    }
    #[test]
    fn audit_refusal_and_unsent_provider_cannot_complete_or_retry() {
        for stage in [0, 1, 2] {
            let mut state = RequestEffects::new();
            let prepared = crate::read_transition::prepare(Phase::Final, false, false)
                .ok()
                .unwrap();
            assert!(state.begin_dispatch_audit(&prepared));
            if stage > 0 {
                let audited = crate::read_transition::acknowledge(prepared, true)
                    .ok()
                    .unwrap();
                assert!(state.acknowledge_dispatch(&audited));
                if stage > 1 {
                    assert!(state.begin_provider(&audited));
                }
            }
            assert!(!state.phase(Phase::Final).provider_attempted());
            assert!(!state.begin_completion());
            assert!(!state.can_return_value());
            assert!(state.phase(Phase::Final).audit_attempted());
            assert_eq!(state.phase(Phase::Final).audit_acknowledged(), stage > 0);
        }
    }
}
