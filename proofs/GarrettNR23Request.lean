import GarrettOwnedRequestTrace
import GarrettNativeReadBoundary

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-2: returned, production-extracted `request_adapter` invocation and the
*same* request-wide receipt. The main result quantifies over all returned
success/error prefixes, not a preselected trace or a fabricated audited flag.

`NativeContext` is a precisely named native factory/callback correspondence
obligation. This module does not turn its fields into axioms, and does not
identify source-level events with OS socket/file effects. See NR-3 for the
separately visible I/O boundary.
-/
namespace aivm_secrets_garrett_core.nr23.Request

open aivm_secrets_garrett_core.request_adapter.TraceRefinement
open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.read_transition

private abbrev adapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

private abbrev NativePending {W F E O X D C V H : Type} :=
  request_adapter.Pending W F E O X (current_admission.Bound D C H F X) V H

/-- One combined returned-run result for the actual core entry. It says that
    every *modeled* send event is authorized, acknowledged and bound to the
    initial capture. The event history is derived from `run_current`, not an
    independent guest-provided or oracle-provided list. -/
theorem all_returned_request_events_are_authorized_and_bound
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (factory : NativeContext ops primitive checks capture)
    (native : W) (pending : NativePending (W := W) (F := F) (E := E)
      (O := O) (X := X) (D := D) (C := C) (V := V) (H := H))
    (out : core.result.Result (completion.Completed O) X)
    (created : request_adapter.Pending.new ops native = Result.ok pending)
    (returned : run_current (adapter ops) pending = Result.ok out) :
    ∃ after events,
      read_transition.Proofs.RequestRun (adapter ops) pending out after ∧
      capture after.adapter.work = capture pending.work ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture pending.work))
        pending.effects after.adapter.effects events ∧
      Reachable after.adapter.effects ∧
      SoundTrace (withOutcome events out) ∧
      BoundTrace (current_admission.Proofs.view (capture pending.work)).binding
        (withOutcome events out) ∧
      (∀ phase gate audit,
        Event.providerSend phase gate audit ∈ withOutcome events out →
          gate.accepted ∧ audit = true ∧
          gateBinding gate =
            (current_admission.Proofs.view (capture pending.work)).binding) := by
  obtain ⟨after, events, ran, fixed, trace, reachable, sound⟩ :=
    returned_entry_sound_trace ops primitive checks capture factory native
      pending out created returned
  have binding : BoundTrace
      (current_admission.Proofs.view (capture pending.work)).binding
      (withOutcome events out) := by
    have exactBinding := trace_steps_keep_binding
      (fun _ => current_admission.Proofs.view (capture pending.work))
      (current_admission.Proofs.view (capture pending.work)).binding
      (by intro _; rfl) pending.effects after.adapter.effects events trace
    cases out with
    | Ok value => exact exactBinding
    | Err error =>
      intro phase gate audit membership
      have inTrace : Event.providerSend phase gate audit ∈ events := by
        simpa [withOutcome] using membership
      exact exactBinding phase gate audit inTrace
  refine ⟨after, events, ran, fixed, trace, reachable, sound, binding, ?_⟩
  intro phase gate audit belongs
  have approved : gate.accepted ∧ audit = true := sound _ belongs
  exact ⟨approved.1, approved.2, binding phase gate audit belongs⟩

/-- Source success entails all five observed completion barriers, including a
    successful completion audit and a second freshness check *after* audit.
    `value_ready` is not permission to write bytes through arbitrary sinks. -/
theorem returned_success_has_selected_audited_current_value
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (native : W) (pending : NativePending (W := W) (F := F) (E := E)
      (O := O) (X := X) (D := D) (C := C) (V := V) (H := H))
    (reply : completion.Completed O)
    (created : request_adapter.Pending.new ops native = Result.ok pending)
    (returned : run_current (adapter ops) pending = Result.ok (.Ok reply)) :
    ∃ finished : NativePending (W := W) (F := F) (E := E)
        (O := O) (X := X) (D := D) (C := C) (V := V) (H := H),
      Reachable finished.effects ∧
      finished.effects.completion.selected = true ∧
      finished.effects.completion.before_checked = true ∧
      finished.effects.completion.audit_attempted = true ∧
      finished.effects.completion.audit_acknowledged = true ∧
      finished.effects.completion.after_checked = true ∧
      finished.effects.completion.value_ready = true := by
  exact request_adapter.Proofs.successful_entry_completion ops native
    pending reply created returned

/-- The projection is internal: it contains audit/send/denial events, never a
    claim that a successful JSON reply was transmitted. Proving this prevents
    accidentally counting `value_ready` as a real guest frame in NR-3. -/
def InternalOnly : Event → Prop
  | .auditAttempt _ => True
  | .providerSend _ _ _ => True
  | .guestDenied => True
  | .guestReply _ _ _ _ _ => False

private theorem internal_append (left right : List Event)
    (first : ∀ e, e ∈ left → InternalOnly e)
    (second : ∀ e, e ∈ right → InternalOnly e) :
    ∀ e, e ∈ left ++ right → InternalOnly e := by
  intro e member
  rcases List.mem_append.mp member with a | b
  · exact first e a
  · exact second e b

private theorem audit_internal (phase : confinement.Proofs.Phase)
    (before after : Bool) :
    ∀ e, e ∈ auditDelta phase before after → InternalOnly e := by
  intro e member
  by_cases raisedBit : raised before after = true
  · simp [auditDelta, raisedBit] at member
    subst e
    trivial
  · simp [auditDelta, raisedBit] at member

private theorem provider_internal (phase : read_transition.Phase)
    (ctx : Context) (before after : request_effects.DispatchRecord) :
    ∀ e, e ∈ providerDelta phase ctx before after → InternalOnly e := by
  intro e member
  by_cases mark : raised before.provider_attempted after.provider_attempted = true
  · cases checked : after.current with
    | none => simp [providerDelta, mark, checked] at member
    | some stamp =>
      simp [providerDelta, mark, checked] at member
      subst e
      trivial
  · simp [providerDelta, mark] at member

private theorem phase_internal (phase : read_transition.Phase)
    (ctx : Context) (before after : request_effects.DispatchRecord) :
    ∀ e, e ∈ phaseDelta phase ctx before after → InternalOnly e := by
  apply internal_append
  · exact audit_internal _ _ _
  · exact provider_internal _ _ _ _

private theorem delta_internal (contexts : read_transition.Phase → Context)
    (before after : request_effects.RequestEffects) :
    ∀ e, e ∈ delta contexts before after → InternalOnly e := by
  unfold delta
  apply internal_append
  · apply internal_append
    · exact phase_internal _ _ _ _
    · exact phase_internal _ _ _ _
  · exact audit_internal _ _ _

/-- All source-derived returned paths, including every error prefix, remain
    purely internal until the *separate* bridge guest-frame operation. -/
theorem trace_steps_do_not_fabricate_public_replies
    (contexts : read_transition.Phase → Context)
    (initial final : request_effects.RequestEffects) (events : List Event)
    (trace : TraceSteps contexts initial final events) :
    ∀ e, e ∈ events → InternalOnly e := by
  induction trace with
  | refl =>
      intro e member
      simp at member
  | next prior step origin ih =>
      exact internal_append _ _ ih (delta_internal _ _ _)

theorem returned_error_projects_denial_not_public_success
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (factory : NativeContext ops primitive checks capture)
    (native : W) (pending : NativePending (W := W) (F := F) (E := E)
      (O := O) (X := X) (D := D) (C := C) (V := V) (H := H))
    (error : X)
    (created : request_adapter.Pending.new ops native = Result.ok pending)
    (returned : run_current (adapter ops) pending = Result.ok (.Err error)) :
    ∃ after events,
      read_transition.Proofs.RequestRun (adapter ops) pending (.Err error) after ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture pending.work))
        pending.effects after.adapter.effects events ∧
      withOutcome events
        (.Err error : core.result.Result (completion.Completed O) X) =
        events ++ [.guestDenied] ∧
      (∀ e, e ∈ withOutcome events
        (.Err error : core.result.Result (completion.Completed O) X) →
          InternalOnly e) := by
  obtain ⟨after, events, ran, _, trace, _, _⟩ :=
    returned_entry_sound_trace ops primitive checks capture factory
      native pending (.Err error) created returned
  have internal := trace_steps_do_not_fabricate_public_replies
    (fun _ => current_admission.Proofs.view (capture pending.work))
    pending.effects after.adapter.effects events trace
  refine ⟨after, events, ran, trace, rfl, ?_⟩
  exact internal_append _ _ internal (by
    intro e member
    simp at member
    subst e
    trivial)

end aivm_secrets_garrett_core.nr23.Request
