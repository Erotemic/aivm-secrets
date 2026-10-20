import GarrettProviderExchange

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-!
Invariants of the production request-wide gate, extracted from Rust. `Step`
uses equalities of the actual extracted functions; it is not a second decision
procedure. Primitive audit/Write/freshness correspondence remains external.
`value_ready` authorizes a native completed value, not a guest frame write.
-/
namespace aivm_secrets_garrett_core.request_effects.Proofs
open read_transition

def DispatchSound (r : DispatchRecord) : Prop :=
  (r.audit_acknowledged = true → r.audit_attempted = true) ∧
  (r.provider_ready = true → r.audit_acknowledged = true) ∧
  (r.provider_attempted = true → r.provider_ready = true ∧ r.current.isSome = true) ∧
  (r.provider_completed = true → r.provider_attempted = true) ∧
  (r.dispatch_succeeded = true → r.provider_completed = true)

def CompletionSound (r : CompletionRecord) : Prop :=
  (r.before_checked = true → r.selected = true) ∧
  (r.audit_attempted = true → r.before_checked = true) ∧
  (r.audit_acknowledged = true → r.audit_attempted = true) ∧
  (r.after_checked = true → r.audit_acknowledged = true) ∧
  (r.value_ready = true → r.after_checked = true)

def record (s : RequestEffects) (phase : Phase) : DispatchRecord :=
  match phase with | .Preflight => s.preflight | .Final => s.final_effect

def ControlSound (s : RequestEffects) : Prop :=
  match s.progress with
  | .Entry | .Selecting | .Halted => True
  | .DispatchAudit p => (record s p).audit_attempted = true
  | .Audited p => (record s p).audit_acknowledged = true
  | .ProviderReady p => (record s p).provider_ready = true
  | .ProviderAttempted p => (record s p).provider_attempted = true
  | .ProviderCompleted p => (record s p).provider_completed = true
  | .DispatchReturned p => (record s p).dispatch_succeeded = true
  | .Selected | .CheckingBefore => s.completion.selected = true
  | .BeforeAudit => s.completion.before_checked = true
  | .CompletionAudit => s.completion.audit_attempted = true
  | .CompletionAudited | .CheckingAfter => s.completion.audit_acknowledged = true
  | .AfterAudit => s.completion.after_checked = true
  | .ValueReady => s.completion.value_ready = true

def Sound (s : RequestEffects) : Prop :=
  DispatchSound s.preflight ∧ DispatchSound s.final_effect ∧
  CompletionSound s.completion ∧ ControlSound s

theorem initial_is_sound :
    ∃ s, RequestEffects.new = Result.ok s ∧ Sound s := by
  simp [RequestEffects.new, DispatchRecord.empty, CompletionRecord.empty,
    Sound, DispatchSound, CompletionSound, ControlSound]

@[simp] private theorem phase_Preflight_Preflight :
    Phase.Insts.CoreCmpPartialEqPhase.eq .Preflight .Preflight = Result.ok true := by
  simp [Phase.Insts.CoreCmpPartialEqPhase.eq, read_discriminant, Phase.read_discriminant]

@[simp] private theorem phase_Preflight_Final :
    Phase.Insts.CoreCmpPartialEqPhase.eq .Preflight .Final = Result.ok false := by
  simp [Phase.Insts.CoreCmpPartialEqPhase.eq, read_discriminant, Phase.read_discriminant]

@[simp] private theorem phase_Final_Preflight :
    Phase.Insts.CoreCmpPartialEqPhase.eq .Final .Preflight = Result.ok false := by
  simp [Phase.Insts.CoreCmpPartialEqPhase.eq, read_discriminant, Phase.read_discriminant]

@[simp] private theorem phase_Final_Final :
    Phase.Insts.CoreCmpPartialEqPhase.eq .Final .Final = Result.ok true := by
  simp [Phase.Insts.CoreCmpPartialEqPhase.eq, read_discriminant, Phase.read_discriminant]

-- Share the exhaustive progress split; no proof branch is omitted.
macro "receipt_cases " progress:Lean.Parser.Tactic.elimTarget " at " step:Lean.Parser.Tactic.elimTarget " using " fn:Lean.Parser.Tactic.simpLemma : tactic =>
  `(tactic| cases $progress with
    | DispatchAudit recorded =>
      cases recorded <;>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Audited recorded =>
      cases recorded <;>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderReady recorded =>
      cases recorded <;>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderAttempted recorded =>
      cases recorded <;>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderCompleted recorded =>
      cases recorded <;>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | DispatchReturned recorded =>
      cases recorded <;>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Entry =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Selecting =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Selected =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CheckingBefore =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | BeforeAudit =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CompletionAudit =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CompletionAudited =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CheckingAfter =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | AfterAudit =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ValueReady =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Halted =>
      try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, Sound, DispatchSound, CompletionSound, ControlSound, record, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop)

theorem begin_dispatch_audit_preserves (s after : RequestEffects) (accepted : Bool) (p : Prepared)
    (safe : Sound s)
    (step : RequestEffects.begin_dispatch_audit s p = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases p with | mk phase write => cases phase <;>
    receipt_cases progress at step using RequestEffects.begin_dispatch_audit

theorem acknowledge_dispatch_preserves (s after : RequestEffects) (accepted : Bool) (p : Audited)
    (safe : Sound s)
    (step : RequestEffects.acknowledge_dispatch s p = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases p with | mk phase write => cases phase <;>
    receipt_cases progress at step using RequestEffects.acknowledge_dispatch

theorem begin_provider_preserves (s after : RequestEffects) (accepted : Bool) (p : Audited)
    (safe : Sound s)
    (step : RequestEffects.begin_provider s p = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases p with | mk phase write => cases phase <;>
    receipt_cases progress at step using RequestEffects.begin_provider

theorem provider_completed_preserves (s after : RequestEffects) (accepted : Bool) (phase : Phase)
    (safe : Sound s)
    (step : RequestEffects.provider_completed s phase = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    receipt_cases progress at step using RequestEffects.provider_completed

theorem finish_dispatch_preserves (s after : RequestEffects) (accepted : Bool) (phase : Phase)
    (safe : Sound s)
    (step : RequestEffects.finish_dispatch s phase = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    receipt_cases progress at step using RequestEffects.finish_dispatch

theorem begin_completion_preserves (s after : RequestEffects) (accepted : Bool)
    (safe : Sound s)
    (step : RequestEffects.begin_completion s  = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>

    receipt_cases progress at step using RequestEffects.begin_completion

theorem selected_preserves (s after : RequestEffects) (accepted : Bool)
    (safe : Sound s)
    (step : RequestEffects.selected s  = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>

    receipt_cases progress at step using RequestEffects.selected

theorem begin_completion_check_preserves (s after : RequestEffects) (accepted : Bool) (phase : CompletionPhase)
    (safe : Sound s)
    (step : RequestEffects.begin_completion_check s phase = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    receipt_cases progress at step using RequestEffects.begin_completion_check

theorem finish_completion_check_preserves (s after : RequestEffects) (accepted : Bool) (phase : CompletionPhase)
    (safe : Sound s)
    (step : RequestEffects.finish_completion_check s phase = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    receipt_cases progress at step using RequestEffects.finish_completion_check

theorem begin_completion_audit_preserves (s after : RequestEffects) (accepted : Bool)
    (safe : Sound s)
    (step : RequestEffects.begin_completion_audit s  = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>

    receipt_cases progress at step using RequestEffects.begin_completion_audit

theorem acknowledge_completion_audit_preserves (s after : RequestEffects) (accepted : Bool)
    (safe : Sound s)
    (step : RequestEffects.acknowledge_completion_audit s  = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>

    receipt_cases progress at step using RequestEffects.acknowledge_completion_audit

theorem value_ready_preserves (s after : RequestEffects) (accepted : Bool)
    (safe : Sound s)
    (step : RequestEffects.value_ready s  = Result.ok (accepted, after)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>

    receipt_cases progress at step using RequestEffects.value_ready

private theorem rejected_is_sound (s : RequestEffects) (safe : Sound s) :
    Sound {s with progress := .Halted} :=
  ⟨safe.1, safe.2.1, safe.2.2.1, trivial⟩

/-- Both native gates must agree on the exact phase and current stamp before
    the request-wide record can mark an attempt. -/
theorem begin_send_preserves (s after : RequestEffects) (localState localAfter : provider_exchange.SendState)
    (phase : Phase) (write accepted : Bool) (safe : Sound s)
    (step : RequestEffects.begin_send s phase localState write = Result.ok (accepted, after, localAfter)) :
    Sound after := by
  cases s with
  | mk pre final completion progress =>
    cases progress <;>
      try (simp only [RequestEffects.begin_send, RequestEffects.reject, bind_tc_ok] at step
           obtain ⟨rfl, rfl, rfl⟩ := (by simpa using step)
           exact rejected_is_sound _ safe)
    case ProviderReady recorded =>
      cases recorded <;> cases phase <;>
        cases localState with
        | mk status =>
          cases status with
          | Checked stamp =>
            cases stamp with
            | mk now elapsed approved =>
              cases approved <;> cases write <;>
                simp_all [RequestEffects.begin_send, RequestEffects.reject, RequestEffects.phase,
                  RequestEffects.set_phase, provider_exchange.SendState.begin_send,
                  provider_exchange.SendState.stamp, manifest.AdmissionStamp.impl.write] <;>
                rcases step with ⟨rfl, rfl, rfl⟩ <;>
                simp_all [Sound, DispatchSound, CompletionSound, ControlSound, record]
          | Empty | Checking | Halted | Attempted _ =>
            simp_all [RequestEffects.begin_send, RequestEffects.reject,
              provider_exchange.SendState.begin_send]
            rcases step with ⟨rfl, rfl, rfl⟩
            exact rejected_is_sound _ safe

/-- Actual returned transitions, including rejected calls. Native I/O is not
    reimplemented here; its markers remain conditional on primitive contracts. -/
inductive Step (s after : RequestEffects) : Prop where
  | begin_dispatch_audit (accepted : Bool) (p : Prepared)
      (returned : RequestEffects.begin_dispatch_audit s p = Result.ok (accepted, after)) : Step s after
  | acknowledge_dispatch (accepted : Bool) (p : Audited)
      (returned : RequestEffects.acknowledge_dispatch s p = Result.ok (accepted, after)) : Step s after
  | begin_provider (accepted : Bool) (p : Audited)
      (returned : RequestEffects.begin_provider s p = Result.ok (accepted, after)) : Step s after
  | provider_completed (accepted : Bool) (phase : Phase)
      (returned : RequestEffects.provider_completed s phase = Result.ok (accepted, after)) : Step s after
  | finish_dispatch (accepted : Bool) (phase : Phase)
      (returned : RequestEffects.finish_dispatch s phase = Result.ok (accepted, after)) : Step s after
  | begin_completion (accepted : Bool)
      (returned : RequestEffects.begin_completion s  = Result.ok (accepted, after)) : Step s after
  | selected (accepted : Bool)
      (returned : RequestEffects.selected s  = Result.ok (accepted, after)) : Step s after
  | begin_completion_check (accepted : Bool) (phase : CompletionPhase)
      (returned : RequestEffects.begin_completion_check s phase = Result.ok (accepted, after)) : Step s after
  | finish_completion_check (accepted : Bool) (phase : CompletionPhase)
      (returned : RequestEffects.finish_completion_check s phase = Result.ok (accepted, after)) : Step s after
  | begin_completion_audit (accepted : Bool)
      (returned : RequestEffects.begin_completion_audit s  = Result.ok (accepted, after)) : Step s after
  | acknowledge_completion_audit (accepted : Bool)
      (returned : RequestEffects.acknowledge_completion_audit s  = Result.ok (accepted, after)) : Step s after
  | value_ready (accepted : Bool)
      (returned : RequestEffects.value_ready s  = Result.ok (accepted, after)) : Step s after
  | begin_send (accepted : Bool) (phase : Phase) (localState localAfter : provider_exchange.SendState)
      (write : Bool)
      (returned : RequestEffects.begin_send s phase localState write =
        Result.ok (accepted, after, localAfter)) : Step s after

inductive Steps (s : RequestEffects) : RequestEffects → Prop where
  | refl : Steps s s
  | next {middle after : RequestEffects} (prior : Steps s middle)
      (last : Step middle after) : Steps s after

def Reachable (s : RequestEffects) : Prop :=
  ∃ initial, RequestEffects.new = Result.ok initial ∧ Steps initial s

theorem step_preserves (s after : RequestEffects) (safe : Sound s) (step : Step s after) :
    Sound after := by
  cases step with
  | begin_dispatch_audit accepted p returned => exact begin_dispatch_audit_preserves s after accepted p safe returned
  | acknowledge_dispatch accepted p returned => exact acknowledge_dispatch_preserves s after accepted p safe returned
  | begin_provider accepted p returned => exact begin_provider_preserves s after accepted p safe returned
  | provider_completed accepted phase returned => exact provider_completed_preserves s after accepted phase safe returned
  | finish_dispatch accepted phase returned => exact finish_dispatch_preserves s after accepted phase safe returned
  | begin_completion accepted  returned => exact begin_completion_preserves s after accepted  safe returned
  | selected accepted  returned => exact selected_preserves s after accepted  safe returned
  | begin_completion_check accepted phase returned => exact begin_completion_check_preserves s after accepted phase safe returned
  | finish_completion_check accepted phase returned => exact finish_completion_check_preserves s after accepted phase safe returned
  | begin_completion_audit accepted  returned => exact begin_completion_audit_preserves s after accepted  safe returned
  | acknowledge_completion_audit accepted  returned => exact acknowledge_completion_audit_preserves s after accepted  safe returned
  | value_ready accepted  returned => exact value_ready_preserves s after accepted  safe returned
  | begin_send accepted phase localState localAfter write returned =>
    exact begin_send_preserves s after localState localAfter phase write accepted safe returned

theorem steps_preserve (s after : RequestEffects) (safe : Sound s) (steps : Steps s after) :
    Sound after := by
  induction steps with
  | refl => exact safe
  | next prior last preserved => exact step_preserves _ _ preserved last

theorem reachable_is_sound (s : RequestEffects) (reachable : Reachable s) : Sound s := by
  obtain ⟨initial, made, steps⟩ := reachable
  obtain ⟨canonical, actual, safe⟩ := initial_is_sound
  have same : initial = canonical := by simpa [made] using actual
  exact steps_preserve initial s (same.symm ▸ safe) steps

theorem provider_attempt_requires_audit_and_stamp (s : RequestEffects) (phase : Phase)
    (reachable : Reachable s) (attempted : (record s phase).provider_attempted = true) :
    (record s phase).audit_attempted = true ∧
    (record s phase).audit_acknowledged = true ∧
    (record s phase).provider_ready = true ∧ (record s phase).current.isSome = true := by
  have safe := reachable_is_sound s reachable
  have dispatched : DispatchSound (record s phase) := by cases phase <;> simp_all [record, Sound]
  obtain ⟨ready, stamp⟩ := dispatched.2.2.1 attempted
  have ack := dispatched.2.1 ready
  exact ⟨dispatched.1 ack, ack, ready, stamp⟩

theorem can_return_value_iff (s : RequestEffects) :
    RequestEffects.can_return_value s = Result.ok true ↔ s.progress = .ValueReady := by
  cases progress : s.progress <;> simp [RequestEffects.can_return_value, progress]

theorem completed_value_requires_selection_checks_and_audit (s : RequestEffects)
    (reachable : Reachable s) (ready : RequestEffects.can_return_value s = Result.ok true) :
    s.completion.selected = true ∧ s.completion.before_checked = true ∧
    s.completion.audit_attempted = true ∧ s.completion.audit_acknowledged = true ∧
    s.completion.after_checked = true ∧ s.completion.value_ready = true := by
  have safe := reachable_is_sound s reachable
  have terminal := (can_return_value_iff s).mp ready
  have value : s.completion.value_ready = true := by simpa [ControlSound, terminal] using safe.2.2.2
  have after := safe.2.2.1.2.2.2.2 value
  have ack := safe.2.2.1.2.2.2.1 after
  have audit := safe.2.2.1.2.2.1 ack
  have before := safe.2.2.1.2.1 audit
  exact ⟨safe.2.2.1.1 before, before, audit, ack, after, value⟩

/-- A denied post-audit freshness callback never calls `finish_completion_check`.
    Its already acknowledged audit is retained, with the return gate closed. -/
theorem late_denial_retains_ack_with_no_return (s : RequestEffects)
    (atAudit : s.progress = .CompletionAudited) :
    RequestEffects.begin_completion_check s .BeforeRelease =
      Result.ok (true, {s with progress := .CheckingAfter}) ∧
    ({s with progress := .CheckingAfter} : RequestEffects).completion = s.completion ∧
    RequestEffects.can_return_value {s with progress := .CheckingAfter} = Result.ok false := by
  simp [RequestEffects.begin_completion_check, RequestEffects.can_return_value, atAudit]

/-- Once a bad extra call poisons progress, sticky receipt flags do not restore
    a previously saved completed value. -/
theorem rejected_call_closes_return_gate (s : RequestEffects) :
    RequestEffects.reject s = Result.ok (false, {s with progress := .Halted}) ∧
    RequestEffects.can_return_value {s with progress := .Halted} = Result.ok false ∧
    ({s with progress := .Halted} : RequestEffects).completion = s.completion := by
  simp [RequestEffects.reject, RequestEffects.can_return_value]

theorem audited_unsent_cannot_complete (s : RequestEffects) (phase : Phase)
    (audited : s.progress = .Audited phase) :
    RequestEffects.begin_completion s = Result.ok (false, {s with progress := .Halted}) := by
  simp [RequestEffects.begin_completion, RequestEffects.reject, audited]

theorem attempted_cannot_submit_again (s : RequestEffects) (recorded phase : Phase)
    (localState : provider_exchange.SendState) (write : Bool)
    (attempted : s.progress = .ProviderAttempted recorded) :
    RequestEffects.begin_send s phase localState write =
      Result.ok (false, {s with progress := .Halted}, localState) := by
  simp [RequestEffects.begin_send, RequestEffects.reject, attempted]

theorem completion_ack_is_not_return_permission (s : RequestEffects)
    (audited : s.progress = .CompletionAudited) :
    RequestEffects.can_return_value s = Result.ok false := by
  simp [RequestEffects.can_return_value, audited]

end aivm_secrets_garrett_core.request_effects.Proofs
