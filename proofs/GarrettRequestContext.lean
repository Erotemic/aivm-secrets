import GarrettOwnedRequestTrace

open Aeneas Aeneas.Std
set_option maxHeartbeats 3000000

/-! Actual production context/factory wrapper: private captured context and
canonical bound dispatch are derived, not native frame/link assumptions. -/
namespace aivm_secrets_garrett_core.request_context.Proofs
open read_transition request_effects request_effects.Proofs
open request_effects.TraceRefinement provider_exchange.Simulation

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private abbrev scoped_ops {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X) :=
  ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel work factory routes

private abbrev adapter {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error (scoped_ops work factory routes)

theorem scoped_constructor {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F) :
    ScopedRequest.new work factory routes context native state = Result.ok ⟨context, native, state⟩ := rfl

/-- Exact native factory/check-factory order and returned states. Neither
    factory can supply or replace the context in the bound provider plan. -/
theorem dispatch_return_iff {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (pending after : ScopedRequest W F A E O X D V H C) (phase : Phase) (effect : E)
    (plan : request_adapter.DispatchPlan (current_admission.Bound (provider_io.Routed D H A X) C H A X) H A X) :
    (scoped_ops work factory routes).dispatch pending phase effect = Result.ok (plan, after) ↔
      ∃ raw native checks state,
        work.dispatch pending.work phase effect = Result.ok (raw, native) ∧
        factory.checks pending.factory = Result.ok (checks, state) ∧
        plan = ⟨⟨pending.context, ⟨pending.context.grant.route, raw.work⟩, checks⟩, raw.keyed_write⟩ ∧
        after = {pending with work := native, factory := state} := by
  constructor
  · intro returned
    dsimp only [scoped_ops, ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel] at returned
    unfold ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.dispatch at returned
    obtain ⟨⟨raw, native⟩, dispatched, rest⟩ := (bind_returns_iff _ _ _).mp returned
    obtain ⟨⟨checks, state⟩, sampled, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have pair : ((⟨⟨pending.context, ⟨pending.context.grant.route, raw.work⟩, checks⟩, raw.keyed_write⟩ : request_adapter.DispatchPlan (current_admission.Bound (provider_io.Routed D H A X) C H A X) H A X),
        {pending with work := native, factory := state}) = (plan, after) := by
      simpa [current_admission.Context.route, provider_io.Routed.new, current_admission.Bound.new] using rest
    exact ⟨raw, native, checks, state, dispatched, sampled, (congrArg Prod.fst pair).symm, (congrArg Prod.snd pair).symm⟩
  · rintro ⟨raw, native, checks, state, dispatched, sampled, rfl, rfl⟩
    simp [ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.dispatch, dispatched, sampled, current_admission.Context.route, provider_io.Routed.new, current_admission.Bound.new]

theorem dispatch_context {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (pending after : ScopedRequest W F A E O X D V H C) (phase : Phase) (effect : E)
    (plan : request_adapter.DispatchPlan (current_admission.Bound (provider_io.Routed D H A X) C H A X) H A X)
    (returned : (scoped_ops work factory routes).dispatch pending phase effect = Result.ok (plan, after)) :
    plan.work.context = pending.context ∧ after.context = pending.context := by
  obtain ⟨raw, native, checks, state, _, _, rfl, rfl⟩ := (dispatch_return_iff work factory routes pending after phase effect plan).mp returned
  exact ⟨rfl, rfl⟩

theorem dispatch_route {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (pending after : ScopedRequest W F A E O X D V H C) (phase : Phase) (effect : E)
    (plan : request_adapter.DispatchPlan (current_admission.Bound (provider_io.Routed D H A X) C H A X) H A X)
    (returned : (scoped_ops work factory routes).dispatch pending phase effect = Result.ok (plan, after)) :
    plan.work.work.route = pending.context.grant.route ∧
      plan.work.work.route = plan.work.context.grant.route := by
  obtain ⟨raw, native, checks, state, _, _, rfl, rfl⟩ := (dispatch_return_iff work factory routes pending after phase effect plan).mp returned
  exact ⟨rfl, rfl⟩

theorem recheck_return_iff {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (pending after : ScopedRequest W F A E O X D V H C) (out : core.result.Result Unit X) :
    (scoped_ops work factory routes).recheck pending = Result.ok (out, after) ↔
      ∃ native, work.recheck pending.work = Result.ok (out, native) ∧ after = {pending with work := native} := by
  constructor
  · intro returned
    dsimp only [scoped_ops, ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel] at returned
    unfold ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.recheck at returned
    obtain ⟨⟨result, native⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have pair : (result, {pending with work := native}) = (out, after) := by simpa using rest
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
    exact ⟨native, called, rfl⟩
  · rintro ⟨native, called, rfl⟩
    simp [ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.recheck, called]

theorem complete_return_iff {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (pending after : ScopedRequest W F A E O X D V H C) (raw : A) (out : V) :
    (scoped_ops work factory routes).complete pending raw = Result.ok (out, after) ↔
      ∃ native, work.complete pending.work raw = Result.ok (out, native) ∧ after = {pending with work := native} := by
  constructor
  · intro returned
    dsimp only [scoped_ops, ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel] at returned
    unfold ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.complete at returned
    obtain ⟨⟨result, native⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have pair : (result, {pending with work := native}) = (out, after) := by simpa using rest
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
    exact ⟨native, called, rfl⟩
  · rintro ⟨native, called, rfl⟩
    simp [ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.complete, called]

/-- All four formerly native context-input clauses now follow from the
    actual wrapper for arbitrary primitive factories and returned states. -/
theorem native_context_contract {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X) :
    request_adapter.TraceRefinement.NativeContext (scoped_ops work factory routes)
      (provider_io.Routed.Insts.Aivm_secrets_garrett_coreDispatchWork work.dispatchWorkInst routes) factory.current_admissionChecksInst (fun pending => pending.context) := by
  refine ⟨rfl, ?_, ?_, ?_⟩
  · intro pending phase effect plan after returned
    exact dispatch_context work factory routes pending after phase effect plan returned
  · intro pending out after returned
    obtain ⟨native, _, rfl⟩ := (recheck_return_iff work factory routes pending after out).mp returned
    rfl
  · intro pending raw value after returned
    obtain ⟨native, _, rfl⟩ := (complete_return_iff work factory routes pending after raw value).mp returned
    rfl


/-- The two actual constructors establish the request's initial context. -/
theorem initial_context {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (owned : ScopedRequest W F A E O X D V H C)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (wrapped : ScopedRequest.new work factory routes context native state = Result.ok owned)
    (created : request_adapter.Pending.new (scoped_ops work factory routes) owned = Result.ok pending) :
    pending.work.context = context := by
  have same : owned = ⟨context, native, state⟩ := by simpa [ScopedRequest.new] using wrapped.symm
  rw [(request_adapter.Proofs.initial_receipt (scoped_ops work factory routes) owned pending created).2, same]

/-- The exact production sequence of owned constructor, receipt constructor
    and consuming request entry has a sound, initially bound gate trace on
    every returned outcome. No native context/frame/factory-link premise is
    assumed. Input conversions and primitive/I/O semantics remain separate. -/
theorem production_entry_trace {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (out : core.result.Result (completion.Completed O) X)
    (returned : (do
      let owned ← ScopedRequest.new work factory routes context native state
      let pending ← request_adapter.Pending.new (scoped_ops work factory routes) owned
      run_current (adapter work factory routes) pending) = Result.ok out) :
    ∃ owned pending after events,
      ScopedRequest.new work factory routes context native state = Result.ok owned ∧
      request_adapter.Pending.new (scoped_ops work factory routes) owned = Result.ok pending ∧
      read_transition.Proofs.RequestRun (adapter work factory routes) pending out after ∧
      after.adapter.work.context = context ∧
      TraceSteps (fun _ => current_admission.Proofs.view context) pending.effects after.adapter.effects events ∧
      Reachable after.adapter.effects ∧ confinement.Proofs.SoundTrace (withOutcome events out) ∧
      BoundTrace (current_admission.Proofs.view context).binding (withOutcome events out) := by
  obtain ⟨owned, wrapped, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨pending, created, ran⟩ := (bind_returns_iff _ _ _).mp rest
  have initial := initial_context work factory routes context native state owned pending wrapped created
  obtain ⟨after, events, actual, frame, traced, sound, kept⟩ :=
    request_adapter.TraceRefinement.returned_entry_bound_trace (scoped_ops work factory routes)
      (provider_io.Routed.Insts.Aivm_secrets_garrett_coreDispatchWork work.dispatchWorkInst routes) factory.current_admissionChecksInst (fun pending => pending.context)
      (native_context_contract work factory routes) owned pending out created ran
  rw [initial] at frame traced kept
  have reachable : Reachable pending.effects :=
    ⟨pending.effects, (request_adapter.Proofs.initial_receipt (scoped_ops work factory routes) owned pending created).1, .refl⟩
  have reached := (trace_steps_preserve_soundness _ _ _ events reachable traced).1
  exact ⟨owned, pending, after, events, wrapped, created, actual, frame, traced, reached, sound, kept⟩

/-- Successful production entry still originates in the actual raw native
    completion factory and selector, with their exact returned states. -/
theorem production_selection_origin {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (value : completion.Completed O)
    (returned : (do
      let owned ← ScopedRequest.new work factory routes context native state
      let pending ← request_adapter.Pending.new (scoped_ops work factory routes) owned
      run_current (adapter work factory routes) pending) = Result.ok (.Ok value)) :
    ∃ callbackState : ScopedRequest W F A E O X D V H C, ∃ raw primitive after selected,
      work.complete callbackState.work raw = Result.ok (primitive, after) ∧
      work.completionWorkInst.select primitive = Result.ok (.Ok value.value, selected) := by
  obtain ⟨owned, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨pending, _, ran⟩ := (bind_returns_iff _ _ _).mp rest
  obtain ⟨callbackState, raw, primitive, after, selected, made, selection⟩ :=
    request_adapter.Proofs.successful_entry_selection_origin (scoped_ops work factory routes) pending value ran
  obtain ⟨nativeAfter, called, _⟩ := (complete_return_iff work factory routes callbackState.work after raw primitive).mp made
  exact ⟨callbackState.work, raw, primitive, nativeAfter, selected, called, selection⟩

/-- Pure planning, data and denial classifications are exact forwards; the
    wrapper introduces no authorization or output-policy conversion. -/
theorem planning_forwarded {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C) (routes : provider_io.RouteWork D H X)
    (pending : ScopedRequest W F A E O X D V H C) (facts : A) (effect : E) :
    (scoped_ops work factory routes).preflight pending = work.preflight pending.work ∧
    (scoped_ops work factory routes).empty_facts pending = work.empty_facts pending.work ∧
    (scoped_ops work factory routes).final_effect pending facts = work.final_effect pending.work facts ∧
    (scoped_ops work factory routes).effect_write pending effect = work.effect_write pending.work effect ∧
    (scoped_ops work factory routes).operation_write pending = work.operation_write pending.work ∧
    (scoped_ops work factory routes).outcome_unknown pending = work.outcome_unknown pending.work ∧
    (scoped_ops work factory routes).INVALID_POLICY = work.INVALID_POLICY ∧
    (scoped_ops work factory routes).INVALID_TRANSITION = work.INVALID_TRANSITION := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_⟩
  · unfold scoped_ops ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.INVALID_POLICY
    rfl
  · unfold scoped_ops ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel.INVALID_TRANSITION
    rfl

end aivm_secrets_garrett_core.request_context.Proofs
