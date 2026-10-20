import GarrettRequestEffects

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-!
Exact progress prefixes for the actual production request-wide gate.
The progress-prefix invariant rules out counting a sticky flag as two effects.
Stamp origin and native primitive correspondence remain local contracts; guest
frame serialization, public-value rendering and complete I/O mediation remain
separate obligations. No independently supplied provider-reached bit is used.
-/
namespace aivm_secrets_garrett_core.request_effects.TraceRefinement
open read_transition
open request_effects.Proofs

/-- Exact occupied prefix, not just implications between already true flags. -/
def DispatchPrefix (level : Nat) (r : DispatchRecord) : Prop :=
  r.audit_attempted = decide (1 ≤ level) ∧
  r.audit_acknowledged = decide (2 ≤ level) ∧
  r.provider_ready = decide (3 ≤ level) ∧
  r.current.isSome = decide (4 ≤ level) ∧
  r.provider_attempted = decide (4 ≤ level) ∧
  r.provider_completed = decide (5 ≤ level) ∧
  r.dispatch_succeeded = decide (6 ≤ level)

def CompletionPrefix (level : Nat) (r : CompletionRecord) : Prop :=
  r.selected = decide (1 ≤ level) ∧ r.before_checked = decide (2 ≤ level) ∧
  r.audit_attempted = decide (3 ≤ level) ∧ r.audit_acknowledged = decide (4 ≤ level) ∧
  r.after_checked = decide (5 ≤ level) ∧ r.value_ready = decide (6 ≤ level)

def EmptyOrDone (r : DispatchRecord) : Prop := DispatchPrefix 0 r ∨ DispatchPrefix 6 r

def PhasePrefix (s : RequestEffects) (phase : read_transition.Phase) (level : Nat) : Prop :=
  match phase with
  | .Preflight => DispatchPrefix level s.preflight ∧ DispatchPrefix 0 s.final_effect ∧ CompletionPrefix 0 s.completion
  | .Final => EmptyOrDone s.preflight ∧ DispatchPrefix level s.final_effect ∧ CompletionPrefix 0 s.completion

def ReleasedPrefix (s : RequestEffects) (level : Nat) : Prop :=
  EmptyOrDone s.preflight ∧ EmptyOrDone s.final_effect ∧ CompletionPrefix level s.completion

/-- Invalid calls halt without clearing records. No halted operation can
    subsequently succeed; the ordinary Sound invariant still covers its flags. -/
def ControlPrefix (s : RequestEffects) : Prop :=
  match s.progress with
  | .Entry => DispatchPrefix 0 s.preflight ∧ DispatchPrefix 0 s.final_effect ∧ CompletionPrefix 0 s.completion
  | .DispatchAudit p => PhasePrefix s p 1
  | .Audited p => PhasePrefix s p 2
  | .ProviderReady p => PhasePrefix s p 3
  | .ProviderAttempted p => PhasePrefix s p 4
  | .ProviderCompleted p => PhasePrefix s p 5
  | .DispatchReturned p => PhasePrefix s p 6
  | .Selecting => ReleasedPrefix s 0
  | .Selected | .CheckingBefore => ReleasedPrefix s 1
  | .BeforeAudit => ReleasedPrefix s 2
  | .CompletionAudit => ReleasedPrefix s 3
  | .CompletionAudited | .CheckingAfter => ReleasedPrefix s 4
  | .AfterAudit => ReleasedPrefix s 5
  | .ValueReady => ReleasedPrefix s 6
  | .Halted => True

theorem initial_has_empty_prefix :
    ∃ s, RequestEffects.new = Result.ok s ∧ ControlPrefix s := by
  simp [RequestEffects.new, DispatchRecord.empty, CompletionRecord.empty,
    ControlPrefix, DispatchPrefix, CompletionPrefix]

macro "prefix_cases " progress:Lean.Parser.Tactic.elimTarget " at " step:Lean.Parser.Tactic.elimTarget " using " fn:Lean.Parser.Tactic.simpLemma : tactic =>
  `(tactic| cases $progress with
    | DispatchAudit recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Audited recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderReady recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderAttempted recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderCompleted recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | DispatchReturned recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Entry =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Selecting =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Selected =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CheckingBefore =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | BeforeAudit =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CompletionAudit =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CompletionAudited =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CheckingAfter =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | AfterAudit =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ValueReady =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Halted =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        rcases $step with ⟨rfl, rfl⟩ <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop)

private theorem begin_dispatch_audit_prefix (s after : RequestEffects) (accepted : Bool) (p : Prepared)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.begin_dispatch_audit s p = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases p with | mk phase write => cases phase <;>
    prefix_cases progress at step using RequestEffects.begin_dispatch_audit

private theorem acknowledge_dispatch_prefix (s after : RequestEffects) (accepted : Bool) (p : Audited)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.acknowledge_dispatch s p = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases p with | mk phase write => cases phase <;>
    prefix_cases progress at step using RequestEffects.acknowledge_dispatch

private theorem begin_provider_prefix (s after : RequestEffects) (accepted : Bool) (p : Audited)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.begin_provider s p = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases p with | mk phase write => cases phase <;>
    prefix_cases progress at step using RequestEffects.begin_provider

private theorem provider_completed_prefix (s after : RequestEffects) (accepted : Bool) (phase : read_transition.Phase)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.provider_completed s phase = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    prefix_cases progress at step using RequestEffects.provider_completed

private theorem finish_dispatch_prefix (s after : RequestEffects) (accepted : Bool) (phase : read_transition.Phase)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.finish_dispatch s phase = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    prefix_cases progress at step using RequestEffects.finish_dispatch

private theorem begin_completion_prefix (s after : RequestEffects) (accepted : Bool)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.begin_completion s  = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>

    prefix_cases progress at step using RequestEffects.begin_completion

private theorem selected_prefix (s after : RequestEffects) (accepted : Bool)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.selected s  = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>

    prefix_cases progress at step using RequestEffects.selected

private theorem begin_completion_check_prefix (s after : RequestEffects) (accepted : Bool) (phase : CompletionPhase)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.begin_completion_check s phase = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    prefix_cases progress at step using RequestEffects.begin_completion_check

private theorem finish_completion_check_prefix (s after : RequestEffects) (accepted : Bool) (phase : CompletionPhase)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.finish_completion_check s phase = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases phase <;>
    prefix_cases progress at step using RequestEffects.finish_completion_check

private theorem begin_completion_audit_prefix (s after : RequestEffects) (accepted : Bool)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.begin_completion_audit s  = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>

    prefix_cases progress at step using RequestEffects.begin_completion_audit

private theorem acknowledge_completion_audit_prefix (s after : RequestEffects) (accepted : Bool)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.acknowledge_completion_audit s  = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>

    prefix_cases progress at step using RequestEffects.acknowledge_completion_audit

private theorem value_ready_prefix (s after : RequestEffects) (accepted : Bool)
    (prefixOK : ControlPrefix s)
    (step : RequestEffects.value_ready s  = Result.ok (accepted, after)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>

    prefix_cases progress at step using RequestEffects.value_ready

private theorem begin_send_prefix (s after : RequestEffects) (localState localAfter : provider_exchange.SendState)
    (phase : read_transition.Phase) (write accepted : Bool) (safe : ControlPrefix s)
    (step : RequestEffects.begin_send s phase localState write = Result.ok (accepted, after, localAfter)) :
    ControlPrefix after := by
  cases s with
  | mk pre final completion progress =>
    cases progress <;>
      try (simp only [RequestEffects.begin_send, RequestEffects.reject, bind_tc_ok] at step
           obtain ⟨rfl, rfl, rfl⟩ := (by simpa using step)
           trivial)
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
                simp_all [ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix]
          | Empty | Checking | Halted | Attempted _ =>
            simp_all [RequestEffects.begin_send, RequestEffects.reject,
              provider_exchange.SendState.begin_send]
            rcases step with ⟨rfl, rfl, rfl⟩
            trivial


theorem step_preserves_prefix (s after : RequestEffects) (prefixOK : ControlPrefix s)
    (step : Step s after) : ControlPrefix after := by
  cases step with
  | begin_dispatch_audit accepted p returned => exact begin_dispatch_audit_prefix s after accepted p prefixOK returned
  | acknowledge_dispatch accepted p returned => exact acknowledge_dispatch_prefix s after accepted p prefixOK returned
  | begin_provider accepted p returned => exact begin_provider_prefix s after accepted p prefixOK returned
  | provider_completed accepted phase returned => exact provider_completed_prefix s after accepted phase prefixOK returned
  | finish_dispatch accepted phase returned => exact finish_dispatch_prefix s after accepted phase prefixOK returned
  | begin_completion accepted  returned => exact begin_completion_prefix s after accepted  prefixOK returned
  | selected accepted  returned => exact selected_prefix s after accepted  prefixOK returned
  | begin_completion_check accepted phase returned => exact begin_completion_check_prefix s after accepted phase prefixOK returned
  | finish_completion_check accepted phase returned => exact finish_completion_check_prefix s after accepted phase prefixOK returned
  | begin_completion_audit accepted  returned => exact begin_completion_audit_prefix s after accepted  prefixOK returned
  | acknowledge_completion_audit accepted  returned => exact acknowledge_completion_audit_prefix s after accepted  prefixOK returned
  | value_ready accepted  returned => exact value_ready_prefix s after accepted  prefixOK returned
  | begin_send accepted phase localState localAfter write returned =>
    exact begin_send_prefix s after localState localAfter phase write accepted prefixOK returned

theorem steps_preserve_prefix (s after : RequestEffects) (prefixOK : ControlPrefix s)
    (steps : Steps s after) : ControlPrefix after := by
  induction steps with
  | refl => exact prefixOK
  | next prior last preserved => exact step_preserves_prefix _ _ preserved last

theorem reachable_has_control_prefix (s : RequestEffects) (reachable : Reachable s) : ControlPrefix s := by
  obtain ⟨initial, made, steps⟩ := reachable
  obtain ⟨canonical, actual, prefixOK⟩ := initial_has_empty_prefix
  have same : initial = canonical := by simpa [made] using actual
  exact steps_preserve_prefix initial s (same.symm ▸ prefixOK) steps

end aivm_secrets_garrett_core.request_effects.TraceRefinement
