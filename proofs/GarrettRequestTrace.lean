import GarrettRequestPrefix
import GarrettRequestSimulation
import GarrettProviderSimulation

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-!
Audit/provider-attempt/denial projection of actual receipt transitions and all
returned controller outcomes. Current-stamp origin and native callback/primitive
correspondence are local contracts. Guest value/framing and whole-service I/O
refinement remain separate obligations.
-/
namespace aivm_secrets_garrett_core.request_effects.TraceRefinement
open read_transition request_effects.Proofs
open provider_exchange.Simulation confinement.Proofs

/-- A raised bit denotes an actual change between two receipt states. Exact
    source-gate counting below requires the reachable control-prefix invariant. -/
def raised (before after : Bool) : Bool := !before && after

def auditDelta (phase : confinement.Proofs.Phase) (before after : Bool) : List Event :=
  if raised before after then [.auditAttempt phase] else []

def providerDelta (phase : read_transition.Phase) (ctx : Context)
    (before after : DispatchRecord) : List Event :=
  if raised before.provider_attempted after.provider_attempted then
    match after.current with
    | none => []
    | some stamp => [.providerSend (eventPhase phase) (snapshot ctx stamp) after.audit_acknowledged]
  else []

def phaseDelta (phase : read_transition.Phase) (ctx : Context)
    (before after : DispatchRecord) : List Event :=
  auditDelta (eventPhase phase) before.audit_attempted after.audit_attempted ++
    providerDelta phase ctx before after

def delta (contexts : read_transition.Phase → Context) (before after : RequestEffects) : List Event :=
  phaseDelta .Preflight (contexts .Preflight) before.preflight after.preflight ++
  phaseDelta .Final (contexts .Final) before.final_effect after.final_effect ++
  auditDelta .completed before.completion.audit_attempted after.completion.audit_attempted

/-- Local current-constructor origin only at a newly marked provider attempt.
    Native instantiation must tie the captured context and exact checked stamp
    to the real current callback. This is not a whole-trace soundness premise. -/
def FreshOrigin (contexts : read_transition.Phase → Context)
    (before after : RequestEffects) : Prop :=
  ∀ phase stamp,
    raised (record before phase).provider_attempted (record after phase).provider_attempted = true →
    (record after phase).current = some stamp → Issued (contexts phase) stamp

private theorem append_sound (left right : List Event)
    (a : SoundTrace left) (b : SoundTrace right) : SoundTrace (left ++ right) := by
  intro event member
  rcases List.mem_append.mp member with first | last
  · exact a event first
  · exact b event last

private theorem audit_delta_sound (phase : confinement.Proofs.Phase) (before after : Bool) :
    SoundTrace (auditDelta phase before after) := by
  intro event member
  cases before <;> cases after <;> simp [auditDelta, raised] at member
  subst event
  trivial

private theorem provider_delta_sound (phase : read_transition.Phase) (ctx : Context)
    (before after : DispatchRecord) (safe : DispatchSound after)
    (origin : ∀ stamp, raised before.provider_attempted after.provider_attempted = true →
      after.current = some stamp → Issued ctx stamp) :
    SoundTrace (providerDelta phase ctx before after) := by
  intro event member
  by_cases mark : raised before.provider_attempted after.provider_attempted = true
  · cases current : after.current with
    | none => simp [providerDelta, mark, current] at member
    | some stamp =>
      have attempted : after.provider_attempted = true := by
        cases before.provider_attempted <;> cases value : after.provider_attempted <;> simp_all [raised]
      have ack : after.audit_acknowledged = true := safe.2.1 (safe.2.2.1 attempted).1
      have issued := origin stamp mark current
      simp only [providerDelta, mark, ↓reduceIte, current, List.mem_singleton] at member
      subst event
      exact ⟨issued_snapshot_is_accepted ctx stamp issued, ack⟩
  · simp [providerDelta, mark] at member

/-- Every emitted event is derived from changed native receipt fields. A
    failed send is still an attempt; a stored audit alone is never a send. -/
theorem delta_is_sound (contexts : read_transition.Phase → Context) (before after : RequestEffects)
    (reachable : Reachable after) (origin : FreshOrigin contexts before after) :
    SoundTrace (delta contexts before after) := by
  have safe := reachable_is_sound after reachable
  unfold delta phaseDelta
  apply append_sound
  · apply append_sound
    · apply append_sound
      · exact audit_delta_sound _ _ _
      · exact provider_delta_sound .Preflight _ _ _ safe.1 (origin .Preflight)
    · apply append_sound
      · exact audit_delta_sound _ _ _
      · exact provider_delta_sound .Final _ _ _ safe.2.1 (origin .Final)
  · exact audit_delta_sound _ _ _

/-- The chronological projection of actual extracted receipt transitions.
    No alternative execution function, fake arrival bit or guest frame is
    supplied. The origin premise is local to newly marked current stamps. -/
inductive TraceSteps (contexts : read_transition.Phase → Context) (start : RequestEffects) :
    RequestEffects → List Event → Prop where
  | refl : TraceSteps contexts start start []
  | next {before after : RequestEffects} {events : List Event}
      (prior : TraceSteps contexts start before events)
      (step : Step before after) (origin : FreshOrigin contexts before after) :
      TraceSteps contexts start after (events ++ delta contexts before after)

theorem trace_steps_are_actual_steps (contexts : read_transition.Phase → Context)
    (start after : RequestEffects) (events : List Event) (trace : TraceSteps contexts start after events) :
    Steps start after := by
  induction trace with
  | refl => exact .refl
  | next prior step origin actual => exact .next actual step

theorem trace_steps_preserve_soundness (contexts : read_transition.Phase → Context)
    (start after : RequestEffects) (events : List Event) (reachable : Reachable start)
    (trace : TraceSteps contexts start after events) : Reachable after ∧ SoundTrace events := by
  induction trace with
  | refl => exact ⟨reachable, by intro event member; simp at member⟩
  | @next before after events prior step origin preserved =>
    obtain ⟨reached, sound⟩ := preserved
    obtain ⟨initial, made, steps⟩ := reached
    have next : Reachable after := ⟨initial, made, .next steps step⟩
    exact ⟨next, append_sound _ _ sound (delta_is_sound contexts before after next origin)⟩

@[simp] private theorem raised_self (value : Bool) : raised value value = false := by
  cases value <;> rfl

@[simp] private theorem raised_false_true : raised false true = true := rfl

@[simp] private theorem audit_delta_self (phase : confinement.Proofs.Phase) (value : Bool) :
    auditDelta phase value value = [] := by simp [auditDelta]

@[simp] private theorem provider_delta_self (phase : read_transition.Phase) (ctx : Context) (r : DispatchRecord) :
    providerDelta phase ctx r r = [] := by simp [providerDelta]

macro "mark_cases " progress:Lean.Parser.Tactic.elimTarget " at " step:Lean.Parser.Tactic.elimTarget " using " fn:Lean.Parser.Tactic.simpLemma : tactic =>
  `(tactic| cases $progress with
    | DispatchAudit recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Audited recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderReady recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderAttempted recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ProviderCompleted recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | DispatchReturned recorded =>
      cases recorded <;>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Entry =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Selecting =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Selected =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CheckingBefore =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | BeforeAudit =>
      simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CompletionAudit =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CompletionAudited =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | CheckingAfter =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | AfterAudit =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | ValueReady =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop
    | Halted =>
      try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase] <;>
        (try rcases $step with ⟨rfl, rfl⟩) <;> (try simp_all [$fn, ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, eventPhase, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase, Prepared.impl.phase, Audited.impl.phase]) <;> aesop)

/-- An accepted production dispatch-audit gate creates one audit marker;
    rejected calls create none. The control prefix rules out a sticky re-audit. -/
theorem dispatch_audit_counts_exactly (contexts : read_transition.Phase → Context)
    (s after : RequestEffects) (accepted : Bool) (prepared : Prepared)
    (reachable : Reachable s)
    (step : RequestEffects.begin_dispatch_audit s prepared = Result.ok (accepted, after)) :
    delta contexts s after = (if accepted then [.auditAttempt (eventPhase prepared.phase)] else []) := by
  have prefixOK := reachable_has_control_prefix s reachable
  cases s with
  | mk pre final completion progress =>
    cases prepared with
    | mk phase write =>
      cases phase <;> mark_cases progress at step using RequestEffects.begin_dispatch_audit

/-- Acknowledgement is distinct from the audit attempt already recorded; it
    does not create another W4 audit/provider event. -/
theorem dispatch_ack_is_silent (contexts : read_transition.Phase → Context)
    (s after : RequestEffects) (accepted : Bool) (audited : Audited)
    (reachable : Reachable s)
    (step : RequestEffects.acknowledge_dispatch s audited = Result.ok (accepted, after)) :
    delta contexts s after = [] := by
  have prefixOK := reachable_has_control_prefix s reachable
  cases s with
  | mk pre final completion progress =>
    cases audited with
    | mk phase write =>
      cases phase <;> mark_cases progress at step using RequestEffects.acknowledge_dispatch

/-- Completion acknowledgement is not itself a guest reply. -/
theorem completion_audit_counts_exactly (contexts : read_transition.Phase → Context)
    (s after : RequestEffects) (accepted : Bool) (reachable : Reachable s)
    (step : RequestEffects.begin_completion_audit s = Result.ok (accepted, after)) :
    delta contexts s after = (if accepted then [.auditAttempt .completed] else []) := by
  have prefixOK := reachable_has_control_prefix s reachable
  cases s with
  | mk pre final completion progress =>
    cases progress <;>
      try (simp [RequestEffects.begin_completion_audit, RequestEffects.reject] at step
           rcases step with ⟨rfl, rfl⟩
           simp [delta, phaseDelta, auditDelta, providerDelta])
    case BeforeAudit =>
      have noAudit : completion.audit_attempted = false := prefixOK.2.2.2.2.1
      simp [delta, phaseDelta, auditDelta, providerDelta, noAudit]

/-- Every accepted native submission gate contributes exactly one attempted
    provider event with the exact SendState stamp. A rejected duplicate does
    not replay the first state's already recorded attempt. -/
theorem send_counts_exactly (contexts : read_transition.Phase → Context)
    (s after : RequestEffects) (localState localAfter : provider_exchange.SendState)
    (phase : read_transition.Phase) (write accepted : Bool) (reachable : Reachable s)
    (step : RequestEffects.begin_send s phase localState write = Result.ok (accepted, after, localAfter)) :
    delta contexts s after = (if accepted then recordedEvents phase (contexts phase) localAfter else []) := by
  have safe := reachable_has_control_prefix s reachable
  cases s with
  | mk pre final completion progress =>
    cases progress <;>
      try (simp only [RequestEffects.begin_send, RequestEffects.reject, bind_tc_ok] at step
           obtain ⟨rfl, rfl, rfl⟩ := (by simpa using step)
           simp [delta, phaseDelta, auditDelta, providerDelta])
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
                simp_all [ControlPrefix, PhasePrefix, ReleasedPrefix, EmptyOrDone, DispatchPrefix, CompletionPrefix, delta, phaseDelta, auditDelta, providerDelta, recordedEvents, attemptedEvent, eventPhase]
          | Empty | Checking | Halted | Attempted _ =>
            simp_all [RequestEffects.begin_send, RequestEffects.reject,
              provider_exchange.SendState.begin_send]
            rcases step with ⟨rfl, rfl, rfl⟩
            simp [delta, phaseDelta, auditDelta, providerDelta]


private theorem progress_change_has_no_new_origin (contexts : read_transition.Phase → Context)
    (s : RequestEffects) (progress : Progress) : FreshOrigin contexts s {s with progress} := by
  intro phase stamp mark current
  cases phase <;> simp [record] at mark

/-- A primitive checked-stamp contract is sufficient to instantiate the local
    origin premise at the ACTUAL composite native send gate. The context and
    stamp must come from the source-owned current constructor; no gate-admitted
    or provider-reached Boolean is supplied independently. -/
theorem checked_send_establishes_origin (contexts : read_transition.Phase → Context)
    (s after : RequestEffects) (localState localAfter : provider_exchange.SendState)
    (phase : read_transition.Phase) (write accepted : Bool)
    (checkedOrigin : ∀ stamp, localState.progress = .Checked stamp → Issued (contexts phase) stamp)
    (step : RequestEffects.begin_send s phase localState write = Result.ok (accepted, after, localAfter)) :
    FreshOrigin contexts s after := by
  cases s with
  | mk pre final completion progress =>
    cases progress <;>
      try (simp only [RequestEffects.begin_send, RequestEffects.reject, bind_tc_ok] at step
           obtain ⟨rfl, rfl, rfl⟩ := (by simpa using step)
           exact progress_change_has_no_new_origin contexts _ _)
    case ProviderReady recorded =>
      cases recorded <;> cases phase <;>
        cases localState with
        | mk status =>
          cases status with
          | Checked actualStamp =>
            cases actualStamp with
            | mk now elapsed approved =>
              cases approved <;> cases write <;>
                simp_all [RequestEffects.begin_send, RequestEffects.reject, RequestEffects.phase,
                  RequestEffects.set_phase, provider_exchange.SendState.begin_send,
                  provider_exchange.SendState.stamp, manifest.AdmissionStamp.impl.write] <;>
                rcases step with ⟨rfl, rfl, rfl⟩ <;>
                intro target stamp mark current <;> cases target <;>
                simp_all [record]
          | Empty | Checking | Halted | Attempted _ =>
            simp_all [RequestEffects.begin_send, RequestEffects.reject,
              provider_exchange.SendState.begin_send]
            rcases step with ⟨rfl, rfl, rfl⟩
            exact progress_change_has_no_new_origin contexts _ _

/-- Local native callback histories over the actual receipt gate. These do
    not assert that all native I/O is captured. New stamp origin is witnessed
    by the actual current constructor at the primitive send boundary. -/
structure CallbackContracts {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context) : Prop where
  dispatch : ∀ pending phase effect out after,
    ops.dispatch pending phase effect = Result.ok (out, after) →
      ∃ events, TraceSteps contexts (observe pending) (observe after) events
  recheck : ∀ pending out after,
    ops.recheck pending = Result.ok (out, after) →
      ∃ events, TraceSteps contexts (observe pending) (observe after) events
  complete : ∀ pending facts out after,
    ops.complete pending facts = Result.ok (out, after) →
      ∃ events, TraceSteps contexts (observe pending) (observe after) events
  completed : ∀ pending facts reply after,
    ops.complete pending facts = Result.ok (.Ok reply, after) →
      RequestEffects.can_return_value (observe after) = Result.ok true

/-- Erasure recovers the earlier reachable-receipt contract without weakening
    either the mutable states or the completed-value gate. -/
theorem callback_contracts_preserve_receipts {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context)
    (world : CallbackContracts ops observe contexts) : Simulation.Contracts ops observe where
  dispatch := by
    intro pending phase effect out after returned
    obtain ⟨events, trace⟩ := world.dispatch pending phase effect out after returned
    exact trace_steps_are_actual_steps contexts _ _ events trace
  recheck := by
    intro pending out after returned
    obtain ⟨events, trace⟩ := world.recheck pending out after returned
    exact trace_steps_are_actual_steps contexts _ _ events trace
  complete := by
    intro pending facts out after returned
    obtain ⟨events, trace⟩ := world.complete pending facts out after returned
    exact trace_steps_are_actual_steps contexts _ _ events trace
  completed := world.completed

private theorem trace_trans {contexts : read_transition.Phase → Context}
    {first middle last : RequestEffects} {left right : List Event}
    (before : TraceSteps contexts first middle left) (after : TraceSteps contexts middle last right) :
    TraceSteps contexts first last (left ++ right) := by
  induction after with
  | refl => simpa using before
  | next prior step origin continued =>
    simpa [List.append_assoc] using TraceSteps.next continued step origin

private theorem origin_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context)
    (world : CallbackContracts ops observe contexts) (pending state : P) (preflight : Bool) (facts : F)
    (origin : read_transition.Proofs.FactsFrom ops pending preflight facts state) :
    ∃ events, TraceSteps contexts (observe pending) (observe state) events := by
  cases preflight with
  | false => obtain ⟨_, _, rfl⟩ := origin; exact ⟨[], .refl⟩
  | true => obtain ⟨effect, _, sent⟩ := origin; exact world.dispatch _ _ _ _ _ sent

private theorem facts_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context)
    (world : CallbackContracts ops observe contexts) (pending : P) (out : core.result.Result F X)
    (after : invocation.Invocation P) (run : read_transition.Proofs.FactsRun ops pending out after) :
    ∃ events, TraceSteps contexts (observe pending) (observe after.adapter) events := by
  cases run with
  | planDenied error planned => exact ⟨[], .refl⟩
  | providerDenied effect error state planned sent => exact world.dispatch _ _ _ _ _ sent
  | produced facts state preflight origin => exact origin_trace ops observe contexts world pending state preflight facts origin

private theorem completion_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context)
    (world : CallbackContracts ops observe contexts) (pending : P) (preflight write : Bool) (raw : F)
    (out : core.result.Result O X) (after : invocation.Invocation P)
    (run : read_transition.Proofs.FinalCompletionRun ops pending preflight raw write out after) :
    ∃ events, TraceSteps contexts (observe pending) (observe after.adapter) events := by
  cases run with
  | read result completed callback => exact world.complete _ _ _ _ callback
  | writeValue reply completed callback => exact world.complete _ _ _ _ callback
  | writeUncertain error unknown completed callback code => exact world.complete _ _ _ _ callback

private theorem finishing_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context)
    (world : CallbackContracts ops observe contexts) (pending : P) (preflight : Bool) (facts : F)
    (out : core.result.Result O X) (after : invocation.Invocation P)
    (run : read_transition.Proofs.FinishRun ops pending preflight facts out after) :
    ∃ events, TraceSteps contexts (observe pending) (observe after.adapter) events := by
  cases run with
  | planDenied error planned => exact ⟨[], .refl⟩
  | currentDenied selected error state planned current => exact world.recheck _ _ _ current
  | checkedOnly result checked completed planned current callback =>
    obtain ⟨a, first⟩ := world.recheck _ _ _ current
    obtain ⟨b, last⟩ := world.complete _ _ _ _ callback
    exact ⟨a ++ b, trace_trans first last⟩
  | providerDenied effect write checked completed error planned current classified sent =>
    obtain ⟨a, first⟩ := world.recheck _ _ _ current
    obtain ⟨b, last⟩ := world.dispatch _ _ _ _ _ sent
    exact ⟨a ++ b, trace_trans first last⟩
  | completed effect write checked dispatched raw result state planned current classified sent last =>
    obtain ⟨a, first⟩ := world.recheck _ _ _ current
    obtain ⟨b, middle⟩ := world.dispatch _ _ _ _ _ sent
    obtain ⟨c, final⟩ := completion_trace ops observe contexts world dispatched preflight write raw out after last
    exact ⟨a ++ b ++ c, trace_trans (trace_trans first middle) final⟩

/-- Composition covers EVERY returned result of the actual mutable controller,
    including failed and audited-but-unsent prefixes. Unused callbacks need
    neither return nor succeed. Native primitive contracts remain explicit. -/
theorem actual_request_has_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context)
    (world : CallbackContracts ops observe contexts) (pending : P) (out : core.result.Result O X)
    (after : invocation.Invocation P) (run : read_transition.Proofs.RequestRun ops pending out after) :
    ∃ events, TraceSteps contexts (observe pending) (observe after.adapter) events := by
  cases run with
  | factsDenied error state facts => exact facts_trace ops observe contexts world pending (.Err error) after facts
  | finish facts state preflight result last origin finished =>
    obtain ⟨a, first⟩ := origin_trace ops observe contexts world pending state preflight facts origin
    obtain ⟨b, last⟩ := finishing_trace ops observe contexts world state preflight facts out after finished
    exact ⟨a ++ b, trace_trans first last⟩

/-- Returned errors add a denial to this projection; successful values await
    separate selected-value and guest-frame refinement, so no fake reply event
    is invented from the completed-audit marker. -/
def withOutcome {O X : Type} (events : List Event) (out : core.result.Result O X) : List Event :=
  match out with | .Ok _ => events | .Err _ => events ++ [.guestDenied]

private theorem outcome_preserves_sound {O X : Type} (events : List Event)
    (out : core.result.Result O X) (sound : SoundTrace events) : SoundTrace (withOutcome events out) := by
  cases out with
  | Ok reply => exact sound
  | Err error =>
    apply append_sound _ _ sound
    intro event member
    simp only [List.mem_singleton] at member
    subst event
    trivial

/-- The actual production constructor/controller/consuming gate has a sound
    audit/provider/denial projection for all returned outcomes, conditional on
    local native callback histories and current-constructor origin. -/
theorem returned_entry_has_sound_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (contexts : read_transition.Phase → Context)
    (world : CallbackContracts ops observe contexts) (pending : P) (out : core.result.Result O X)
    (start : RequestEffects.new = Result.ok (observe pending))
    (returned : run_current ops pending = Result.ok out) :
    ∃ after events, read_transition.Proofs.RequestRun ops pending out after ∧
      TraceSteps contexts (observe pending) (observe after.adapter) events ∧
      Reachable (observe after.adapter) ∧ SoundTrace (withOutcome events out) := by
  obtain ⟨after, run⟩ := (read_transition.Proofs.run_current_returned_iff ops pending out).mp returned
  obtain ⟨events, trace⟩ := actual_request_has_trace ops observe contexts world pending out after run
  have reached : Reachable (observe pending) := ⟨observe pending, start, .refl⟩
  obtain ⟨reachable, sound⟩ := trace_steps_preserve_soundness contexts _ _ events reached trace
  exact ⟨after, events, run, trace, reachable, outcome_preserves_sound events out sound⟩

/-- Time/activity may change at a check. Identity, operation and route belong
    to the immutable context captured by the native request adapter. -/
def gateBinding (gate : Gate) : Binding :=
  ⟨gate.claims, gate.grant.claims, gate.grant.operation, gate.grant.route,
    gate.requested, gate.selected, gate.write, gate.writesAllowed⟩

def BoundTrace (binding : Binding) (events : List Event) : Prop :=
  ∀ phase gate ack, Event.providerSend phase gate ack ∈ events → gateBinding gate = binding

private theorem bound_append (binding : Binding) (a b : List Event)
    (first : BoundTrace binding a) (last : BoundTrace binding b) : BoundTrace binding (a ++ b) := by
  intro phase gate ack member
  rcases List.mem_append.mp member with left | right
  · exact first phase gate ack left
  · exact last phase gate ack right

private theorem bound_audit (binding : Binding) (phase : confinement.Proofs.Phase) (a b : Bool) :
    BoundTrace binding (auditDelta phase a b) := by
  intro p gate ack member
  cases a <;> cases b <;> simp [auditDelta, raised] at member

private theorem bound_provider (phase : read_transition.Phase) (ctx : Context) (a b : DispatchRecord) :
    BoundTrace ctx.binding (providerDelta phase ctx a b) := by
  intro p gate ack member
  by_cases mark : raised a.provider_attempted b.provider_attempted = true
  · cases current : b.current with
    | none => simp [providerDelta, mark, current] at member
    | some stamp =>
      simp [providerDelta, mark, current] at member
      obtain ⟨rfl, rfl, rfl⟩ := member
      rfl
  · simp [providerDelta, mark] at member

theorem delta_keeps_binding (contexts : read_transition.Phase → Context) (binding : Binding)
    (fixed : ∀ phase, (contexts phase).binding = binding) (before after : RequestEffects) :
    BoundTrace binding (delta contexts before after) := by
  unfold delta phaseDelta
  apply bound_append
  · apply bound_append
    · exact bound_append _ _ _ (bound_audit _ _ _ _)
        (by simpa [fixed .Preflight] using bound_provider .Preflight (contexts .Preflight) before.preflight after.preflight)
    · exact bound_append _ _ _ (bound_audit _ _ _ _)
        (by simpa [fixed .Final] using bound_provider .Final (contexts .Final) before.final_effect after.final_effect)
  · exact bound_audit _ _ _ _

theorem trace_steps_keep_binding (contexts : read_transition.Phase → Context) (binding : Binding)
    (fixed : ∀ phase, (contexts phase).binding = binding) (start after : RequestEffects)
    (events : List Event) (trace : TraceSteps contexts start after events) : BoundTrace binding events := by
  induction trace with
  | refl => intro phase gate ack member; simp at member
  | next prior step origin kept => exact bound_append _ _ _ kept (delta_keeps_binding contexts binding fixed _ _)

private theorem outcome_keeps_binding {O X : Type} (binding : Binding) (events : List Event)
    (out : core.result.Result O X) (bound : BoundTrace binding events) : BoundTrace binding (withOutcome events out) := by
  cases out with
  | Ok reply => exact bound
  | Err error =>
    apply bound_append _ _ _ bound
    intro phase gate ack member
    simp at member

/-- Both phases use the same captured identity/operation/route context. Native
    context conversion and its relation to authenticated startup remain a
    separate adapter obligation; this theorem does not invent that relation. -/
theorem returned_entry_keeps_captured_binding {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (context : Context)
    (world : CallbackContracts ops observe (fun _ => context)) (pending : P) (out : core.result.Result O X)
    (start : RequestEffects.new = Result.ok (observe pending))
    (returned : run_current ops pending = Result.ok out) :
    ∃ after events, read_transition.Proofs.RequestRun ops pending out after ∧
      TraceSteps (fun _ => context) (observe pending) (observe after.adapter) events ∧
      SoundTrace (withOutcome events out) ∧ BoundTrace context.binding (withOutcome events out) := by
  obtain ⟨after, events, run, trace, _, sound⟩ :=
    returned_entry_has_sound_trace ops observe (fun _ => context) world pending out start returned
  have bound := trace_steps_keep_binding (fun _ => context) context.binding (by intro phase; rfl) _ _ events trace
  exact ⟨after, events, run, trace, sound, outcome_keeps_binding _ _ _ bound⟩

/-- The audit acknowledgement is retained through the actual post-audit check
    entry. If its primitive returns denial, no finish/value-ready gate runs. -/
theorem late_check_keeps_audit_without_reply (contexts : read_transition.Phase → Context)
    (before after : RequestEffects) (reachable : Reachable before)
    (atAudit : before.progress = .CompletionAudited)
    (entered : RequestEffects.begin_completion_check before .BeforeRelease = Result.ok (true, after)) :
    delta contexts before after = [] ∧ after.completion.audit_acknowledged = true ∧
      RequestEffects.can_return_value after = Result.ok false := by
  have safe := reachable_is_sound before reachable
  have ack : before.completion.audit_acknowledged = true := by simpa [ControlSound, atAudit] using safe.2.2.2
  have same : after = {before with progress := .CheckingAfter} := by
    simpa [RequestEffects.begin_completion_check, atAudit, eq_comm] using entered
  subst after
  simp [delta, phaseDelta, ack, RequestEffects.can_return_value]

end aivm_secrets_garrett_core.request_effects.TraceRefinement
