import GarrettDispatchTrace
import GarrettCompletionTrace
import GarrettRequestAdapter

open Aeneas Aeneas.Std
set_option maxHeartbeats 3000000

/-! Actual request-adapter histories. Per-state context capture/frame and the
canonical bound instance remain native input obligations. Whole-dispatch/
completion histories and current origin are derived. -/
namespace aivm_secrets_garrett_core.request_adapter.TraceRefinement
open read_transition request_effects request_effects.Proofs
open request_effects.TraceRefinement provider_exchange.Simulation

private abbrev adapter {W F E O X D V H : Type} (ops : Work W F E O X D V H) :=
  Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private theorem returned_state {A P : Type} (value out : A) (state after : P)
    (returned : Result.ok (value, state) = Result.ok (out, after)) : after = state :=
  (congrArg Prod.snd ((Result.ok.injEq).mp returned)).symm

/-- Native input obligations are per-state: canonical bound instance, the
    factory's captured constructor argument, and immutable context fields across
    the three mutable primitive returns. No callback trace/origin is assumed. -/
structure NativeContext {W F E O X D C V H : Type}
    (ops : Work W F E O X (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X) (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context) : Prop where
  dispatch_binding : ops.dispatchWorkInst = current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork primitive checks
  dispatched : ∀ pending phase effect plan after,
    ops.dispatch pending phase effect = Result.ok (plan, after) →
      plan.work.context = capture pending ∧ capture after = capture pending
  rechecked : ∀ pending out after, ops.recheck pending = Result.ok (out, after) → capture after = capture pending
  completed : ∀ pending facts value after, ops.complete pending facts = Result.ok (value, after) → capture after = capture pending

/-- A state-indexed context frame and chronological receipt history. -/
def Related {P : Type} (observe : P → RequestEffects) (capture : P → current_admission.Context)
    (before after : P) : Prop :=
  capture after = capture before ∧
    ∃ events, TraceSteps (fun _ => current_admission.Proofs.view (capture before)) (observe before) (observe after) events

private theorem related_refl {P : Type} (observe : P → RequestEffects) (capture : P → current_admission.Context)
    (state : P) : Related observe capture state state := ⟨rfl, [], .refl⟩

private theorem traces_trans {contexts : Phase → Context} {first middle last : RequestEffects}
    {a b : List confinement.Proofs.Event} (initial : TraceSteps contexts first middle a)
    (remaining : TraceSteps contexts middle last b) : TraceSteps contexts first last (a ++ b) := by
  induction remaining with
  | refl => simpa using initial
  | next prior step origin ih => simpa [List.append_assoc] using TraceSteps.next ih step origin

private theorem related_trans {P : Type} {observe : P → RequestEffects} {capture : P → current_admission.Context}
    {first middle last : P} (left : Related observe capture first middle) (right : Related observe capture middle last) :
    Related observe capture first last := by
  obtain ⟨same, a, initial⟩ := left
  obtain ⟨final, b, remaining⟩ := right
  rw [same] at remaining
  refine ⟨final.trans same, a ++ b, ?_⟩
  exact traces_trans initial remaining

private structure Callbacks {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (capture : P → current_admission.Context) : Prop where
  dispatch : ∀ pending phase effect out after,
    ops.dispatch pending phase effect = Result.ok (out, after) → Related observe capture pending after
  recheck : ∀ pending out after, ops.recheck pending = Result.ok (out, after) → Related observe capture pending after
  complete : ∀ pending facts out after, ops.complete pending facts = Result.ok (out, after) → Related observe capture pending after

/-- Refused preparation invokes no primitive factory. Every other returned
    dispatch copies the actual source-owned report and its derived history. -/
theorem dispatch_callback_trace {W F E O X D C V H : Type}
    (ops : Work W F E O X (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X) (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context) (factory : NativeContext ops primitive checks capture)
    (pending after : Pending W F E O X (current_admission.Bound D C H F X) V H)
    (phase : Phase) (effect : E) (out : core.result.Result F X)
    (returned : (adapter ops).dispatch pending phase effect = Result.ok (out, after)) :
    Related (fun pending => pending.effects) (fun pending => capture pending.work) pending after := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.dispatch at returned
  obtain ⟨operationWrite, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨effectWrite, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
  obtain ⟨prepared, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
  cases prepared with
  | Err denied =>
    obtain ⟨error, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have same := returned_state (.Err error : core.result.Result F X) out pending after (by simpa using rest)
    subst after
    exact related_refl _ _ _
  | Ok prepared =>
    obtain ⟨⟨plan, native⟩, made, rest⟩ := (bind_returns_iff _ _ _).mp rest
    obtain ⟨report, ran, rest⟩ := (bind_returns_iff _ _ _).mp rest
    rw [factory.dispatch_binding] at ran
    have traced := (dispatch.TraceRefinement.dispatch_trace primitive checks plan.work (.Ok prepared) pending.effects plan.keyed_write report ran).2
    have captured := factory.dispatched pending.work phase effect plan native made
    rw [captured.1] at traced
    have same := returned_state report.outcome out ⟨native, report.effects⟩ after (by simpa using rest)
    subst after
    exact ⟨captured.2, traced⟩

/-- Completion histories follow the extracted selection/check/audit/check/
    release gates. No new provider attempt or origin assumption is supplied. -/
theorem completion_callback_trace {W F E O X D V H : Type}
    (ops : Work W F E O X D V H) (contexts : Phase → Context)
    (pending after : Pending W F E O X D V H) (raw : F)
    (out : core.result.Result (completion.Completed O) X)
    (returned : (adapter ops).complete pending raw = Result.ok (out, after)) :
    ∃ events, TraceSteps contexts pending.effects after.effects events := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.complete at returned
  obtain ⟨⟨primitive, native⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨report, ran, rest⟩ := (bind_returns_iff _ _ _).mp rest
  have traced := (completion.TraceRefinement.complete_trace (contexts := contexts) ops.completionWorkInst primitive pending.effects report ran).1
  have pair : (report.outcome, (⟨native, report.effects⟩ : Pending W F E O X D V H)) = (out, after) := by simpa using rest
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
  exact traced

/-- Actual mutable primitive post-states preserve the per-request context;
    histories are supplied by the extracted controllers, never assumed. -/
private theorem callback_contracts {W F E O X D C V H : Type}
    (ops : Work W F E O X (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X) (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context) (factory : NativeContext ops primitive checks capture) :
    Callbacks (adapter ops) (fun pending => pending.effects) (fun pending => capture pending.work) := by
  refine ⟨?_, ?_, ?_⟩
  · intro pending phase effect out after returned
    exact dispatch_callback_trace ops primitive checks capture factory pending after phase effect out returned
  · intro pending out after returned
    have effects := Proofs.recheck_frame ops pending after out returned
    dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
    unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.recheck at returned
    obtain ⟨⟨result, native⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have same := returned_state result out {pending with work := native} after (by simpa using rest)
    subst after
    exact ⟨factory.rechecked pending.work result native called, [], .refl⟩
  · intro pending facts out after returned
    have traced := completion_callback_trace ops (fun _ => current_admission.Proofs.view (capture pending.work)) pending after facts out returned
    dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
    unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.complete at returned
    obtain ⟨⟨value, native⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp returned
    obtain ⟨report, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have same := returned_state report.outcome out ⟨native, report.effects⟩ after (by simpa using rest)
    subst after
    exact ⟨factory.completed pending.work facts value native called, traced⟩

private theorem origin_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (capture : P → current_admission.Context)
    (world : Callbacks ops observe capture) (pending state : P) (preflight : Bool) (facts : F)
    (origin : read_transition.Proofs.FactsFrom ops pending preflight facts state) :
    Related observe capture pending state := by
  cases preflight with
  | false => obtain ⟨_, _, rfl⟩ := origin; exact related_refl _ _ _
  | true => obtain ⟨effect, _, sent⟩ := origin; exact world.dispatch _ _ _ _ _ sent

private theorem facts_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (capture : P → current_admission.Context)
    (world : Callbacks ops observe capture) (pending : P) (out : core.result.Result F X)
    (after : invocation.Invocation P) (run : read_transition.Proofs.FactsRun ops pending out after) :
    Related observe capture pending after.adapter := by
  cases run with
  | planDenied error planned => exact related_refl _ _ _
  | providerDenied effect error state planned sent => exact world.dispatch _ _ _ _ _ sent
  | produced facts state preflight origin => exact origin_trace ops observe capture world pending state preflight facts origin

private theorem completion_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (capture : P → current_admission.Context)
    (world : Callbacks ops observe capture) (pending : P) (preflight write : Bool) (raw : F)
    (out : core.result.Result O X) (after : invocation.Invocation P)
    (run : read_transition.Proofs.FinalCompletionRun ops pending preflight raw write out after) :
    Related observe capture pending after.adapter := by
  cases run with
  | read result completed callback => exact world.complete _ _ _ _ callback
  | writeValue reply completed callback => exact world.complete _ _ _ _ callback
  | writeUncertain error unknown completed callback code => exact world.complete _ _ _ _ callback

private theorem finishing_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (capture : P → current_admission.Context)
    (world : Callbacks ops observe capture) (pending : P) (preflight : Bool) (facts : F)
    (out : core.result.Result O X) (after : invocation.Invocation P)
    (run : read_transition.Proofs.FinishRun ops pending preflight facts out after) :
    Related observe capture pending after.adapter := by
  cases run with
  | planDenied error planned => exact related_refl _ _ _
  | currentDenied selected error state planned current => exact world.recheck _ _ _ current
  | checkedOnly result checked completed planned current callback =>
    exact related_trans (world.recheck _ _ _ current) (world.complete _ _ _ _ callback)
  | providerDenied effect write checked completed error planned current classified sent =>
    exact related_trans (world.recheck _ _ _ current) (world.dispatch _ _ _ _ _ sent)
  | completed effect write checked dispatched raw result state planned current classified sent last =>
    exact related_trans (related_trans (world.recheck _ _ _ current) (world.dispatch _ _ _ _ _ sent))
      (completion_trace ops observe capture world dispatched preflight write raw out after last)

/-- Composition covers EVERY returned result of the actual mutable controller,
    including failed and audited-but-unsent prefixes. Unused callbacks need
    neither return nor succeed. Native primitive contracts remain explicit. -/
private theorem actual_request_has_trace {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (capture : P → current_admission.Context)
    (world : Callbacks ops observe capture) (pending : P) (out : core.result.Result O X)
    (after : invocation.Invocation P) (run : read_transition.Proofs.RequestRun ops pending out after) :
    Related observe capture pending after.adapter := by
  cases run with
  | factsDenied error state facts => exact facts_trace ops observe capture world pending (.Err error) after facts
  | finish facts state preflight result last origin finished =>
    exact related_trans (origin_trace ops observe capture world pending state preflight facts origin)
      (finishing_trace ops observe capture world state preflight facts out after finished)

private theorem outcome_sound {O X : Type} (events : List confinement.Proofs.Event)
    (out : core.result.Result O X) (sound : confinement.Proofs.SoundTrace events) :
    confinement.Proofs.SoundTrace (withOutcome events out) := by
  cases out with
  | Ok value => exact sound
  | Err error =>
    intro event member
    rcases List.mem_append.mp member with first | last
    · exact sound event first
    · simp only [List.mem_singleton] at last
      subst event
      trivial

/-- All returned outcomes of the actual constructor/controller/consuming gate
    have a source-derived audit/provider-attempt/denial projection and preserve
    their initial context. Native input/primitive and I/O semantics remain
    explicit; no whole-callback history or current-origin premise remains. -/
theorem returned_entry_sound_trace {W F E O X D C V H : Type}
    (ops : Work W F E O X (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X) (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context) (nativeContext : NativeContext ops primitive checks capture)
    (native : W) (pending : Pending W F E O X (current_admission.Bound D C H F X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (created : Pending.new ops native = Result.ok pending)
    (returned : run_current (adapter ops) pending = Result.ok out) :
    ∃ after events, read_transition.Proofs.RequestRun (adapter ops) pending out after ∧
      capture after.adapter.work = capture pending.work ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture pending.work)) pending.effects after.adapter.effects events ∧
      Reachable after.adapter.effects ∧ confinement.Proofs.SoundTrace (withOutcome events out) := by
  obtain ⟨after, ran⟩ := (read_transition.Proofs.run_current_returned_iff (adapter ops) pending out).mp returned
  obtain ⟨same, events, traced⟩ := actual_request_has_trace (adapter ops) (fun pending => pending.effects)
    (fun pending => capture pending.work) (callback_contracts ops primitive checks capture nativeContext) pending out after ran
  have reachable : Reachable pending.effects := ⟨pending.effects, (Proofs.initial_receipt ops native pending created).1, .refl⟩
  obtain ⟨reached, sound⟩ := trace_steps_preserve_soundness _ _ _ events reachable traced
  exact ⟨after, events, ran, same, traced, reached, outcome_sound events out sound⟩

/-- Both actual request phases keep the initial identity/operation/route
    binding, even on failed and audited-but-unsent returned prefixes. The
    projection includes no invented selected-value or guest-frame event. -/
theorem returned_entry_bound_trace {W F E O X D C V H : Type}
    (ops : Work W F E O X (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X) (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context) (nativeContext : NativeContext ops primitive checks capture)
    (native : W) (pending : Pending W F E O X (current_admission.Bound D C H F X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (created : Pending.new ops native = Result.ok pending)
    (returned : run_current (adapter ops) pending = Result.ok out) :
    ∃ after events, read_transition.Proofs.RequestRun (adapter ops) pending out after ∧
      capture after.adapter.work = capture pending.work ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture pending.work)) pending.effects after.adapter.effects events ∧
      confinement.Proofs.SoundTrace (withOutcome events out) ∧
      BoundTrace (current_admission.Proofs.view (capture pending.work)).binding (withOutcome events out) := by
  obtain ⟨after, events, ran, same, traced, _, sound⟩ :=
    returned_entry_sound_trace ops primitive checks capture nativeContext native pending out created returned
  have kept := trace_steps_keep_binding _ _ (fun _ => rfl) _ _ events traced
  refine ⟨after, events, ran, same, traced, sound, ?_⟩
  cases out with
  | Ok value => exact kept
  | Err error =>
    intro phase gate ack member
    have actual : confinement.Proofs.Event.providerSend phase gate ack ∈ events := by simpa [withOutcome] using member
    exact kept phase gate ack actual

end aivm_secrets_garrett_core.request_adapter.TraceRefinement
