import GarrettDispatch
import GarrettCompletion
import GarrettRequestSimulation

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-! Returning properties of the actual production request adapter. Shared
receipt ownership and report updates are extracted code, rather than native
callback-link hypotheses. Primitive I/O, context and conversion stay separate. -/
namespace aivm_secrets_garrett_core.request_adapter.Proofs
open read_transition request_effects request_effects.Proofs

private abbrev adapter {W F E O X D C H : Type} (ops : Work W F E O X D C H) :=
  Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private theorem returned_state {A P : Type} (value out : A) (state after : P)
    (returned : Result.ok (value, state) = Result.ok (out, after)) : after = state :=
  (congrArg Prod.snd ((Result.ok.injEq).mp returned)).symm

/-- The outer freshness callback cannot edit the controller-owned receipt,
    even when it returns denial with a changed native primitive state. -/
theorem recheck_frame {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending after : Pending W F E O X D C H) (out : core.result.Result Unit X)
    (returned : (adapter ops).recheck pending = Result.ok (out, after)) :
    after.effects = pending.effects := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.recheck at returned
  obtain ⟨⟨result, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have same := returned_state result out {pending with work} after (by simpa using rest)
  subst after
  rfl

theorem dispatch_receipts {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending after : Pending W F E O X D C H) (phase : Phase) (effect : E) (out : core.result.Result F X)
    (returned : (adapter ops).dispatch pending phase effect = Result.ok (out, after)) :
    Steps pending.effects after.effects := by
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
    exact .refl
  | Ok prepared =>
    obtain ⟨⟨plan, work⟩, factory, rest⟩ := (bind_returns_iff _ _ _).mp rest
    obtain ⟨report, ran, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have receipts := dispatch.Proofs.dispatch_receipts ops.dispatchWorkInst plan.work (.Ok prepared) pending.effects plan.keyed_write report ran
    have same := returned_state report.outcome out ⟨work, report.effects⟩ after (by simpa using rest)
    subst after
    exact receipts

theorem completion_receipts {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending after : Pending W F E O X D C H) (raw : F) (out : core.result.Result (completion.Completed O) X)
    (returned : (adapter ops).complete pending raw = Result.ok (out, after)) :
    Steps pending.effects after.effects ∧
      ∀ value, out = .Ok value → RequestEffects.can_return_value after.effects = Result.ok true := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.complete at returned
  obtain ⟨⟨primitive, work⟩, factory, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨report, ran, rest⟩ := (bind_returns_iff _ _ _).mp rest
  have receipts := completion.Proofs.complete_receipts ops.completionWorkInst primitive pending.effects report ran
  have pair : (report.outcome, (⟨work, report.effects⟩ : Pending W F E O X D C H)) = (out, after) := by simpa using rest
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
  exact ⟨receipts.1, fun value success => (receipts.2 value success).2⟩

/-- All former whole-callback receipt and completed-value premises now follow
    from the actual source-owned adapter, with no native Link assumptions. -/
theorem request_contracts {W F E O X D C H : Type} (ops : Work W F E O X D C H) :
    request_effects.Simulation.Contracts (adapter ops) (fun pending => pending.effects) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro pending phase effect out after returned
    exact dispatch_receipts ops pending after phase effect out returned
  · intro pending out after returned
    rw [recheck_frame ops pending after out returned]
    exact .refl
  · intro pending facts out after returned
    exact (completion_receipts ops pending after facts out returned).1
  · intro pending facts reply after returned
    exact (completion_receipts ops pending after facts (.Ok reply) returned).2 reply rfl

/-- Native factory post-state and the exact owned completion report determine
    every returned callback, including selection or post-audit denial. -/
theorem completion_report_iff {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending after : Pending W F E O X D C H) (raw : F) (out : core.result.Result (completion.Completed O) X) :
    (adapter ops).complete pending raw = Result.ok (out, after) ↔
      ∃ primitive work report,
        ops.complete pending.work raw = Result.ok (primitive, work) ∧
        completion.complete ops.completionWorkInst primitive pending.effects = Result.ok report ∧
        out = report.outcome ∧ after = ⟨work, report.effects⟩ := by
  constructor
  · intro returned
    dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
    unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.complete at returned
    obtain ⟨⟨primitive, work⟩, factory, rest⟩ := (bind_returns_iff _ _ _).mp returned
    obtain ⟨report, ran, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have pair : (report.outcome, (⟨work, report.effects⟩ : Pending W F E O X D C H)) = (out, after) := by simpa using rest
    exact ⟨primitive, work, report, factory, ran, (congrArg Prod.fst pair).symm, (congrArg Prod.snd pair).symm⟩
  · rintro ⟨primitive, work, report, factory, ran, rfl, rfl⟩
    simp [Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.complete, factory, ran]

theorem recheck_primitive_prefix {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending : Pending W F E O X D C H) (work : W) (out : core.result.Result Unit X)
    (callback : ops.recheck pending.work = Result.ok (out, work)) :
    (adapter ops).recheck pending = Result.ok (out, {pending with work}) := by
  simp [Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.recheck, callback]

/-- Refused preparation invokes neither adapter factory nor primitive. -/
theorem preparation_refusal {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending : Pending W F E O X D C H) (phase : Phase) (effect : E) (operationWrite effectWrite : Bool)
    (denial : Denial) (error : X)
    (operation : ops.operation_write pending.work = Result.ok operationWrite)
    (classified : ops.effect_write pending.work effect = Result.ok effectWrite)
    (refused : read_transition.prepare phase operationWrite effectWrite = Result.ok (.Err denial))
    (invalid : ops.INVALID_POLICY = Result.ok error) :
    (adapter ops).dispatch pending phase effect = Result.ok (.Err error, pending) := by
  simp [Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.dispatch,
    operation, classified, refused, invalid]

/-- A returned provider value originates in the source-owned dispatcher with
    the exact phase/write preparation, factory state and receipt. -/
theorem dispatch_success_origin {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending after : Pending W F E O X D C H) (phase : Phase) (effect : E) (value : F)
    (returned : (adapter ops).dispatch pending phase effect = Result.ok (.Ok value, after)) :
    ∃ operationWrite effectWrite prepared plan work report,
      ops.operation_write pending.work = Result.ok operationWrite ∧
      ops.effect_write pending.work effect = Result.ok effectWrite ∧
      read_transition.prepare phase operationWrite effectWrite = Result.ok (.Ok prepared) ∧
      prepared.phase = phase ∧ prepared.write = effectWrite ∧
      read_transition.Proofs.Admitted phase operationWrite effectWrite ∧
      ops.dispatch pending.work phase effect = Result.ok (plan, work) ∧
      dispatch.dispatch ops.dispatchWorkInst plan.work (.Ok prepared) pending.effects plan.keyed_write = Result.ok report ∧
      report.outcome = .Ok value ∧ after = ⟨work, report.effects⟩ := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.dispatch at returned
  obtain ⟨operationWrite, operation, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨effectWrite, classified, rest⟩ := (bind_returns_iff _ _ _).mp rest
  obtain ⟨prepared, preparation, rest⟩ := (bind_returns_iff _ _ _).mp rest
  cases prepared with
  | Err denial =>
    obtain ⟨error, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
    simp at rest
  | Ok prepared =>
    obtain ⟨⟨plan, work⟩, factory, rest⟩ := (bind_returns_iff _ _ _).mp rest
    obtain ⟨report, ran, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have pair : (report.outcome, (⟨work, report.effects⟩ : Pending W F E O X D C H)) = (.Ok value, after) := by simpa using rest
    obtain ⟨phaseEq, writeEq, admitted⟩ := (read_transition.Proofs.prepare_success_iff phase operationWrite effectWrite prepared).mp preparation
    exact ⟨operationWrite, effectWrite, prepared, plan, work, report, operation, classified,
      preparation, phaseEq, writeEq, admitted, factory, ran, congrArg Prod.fst pair, (congrArg Prod.snd pair).symm⟩

theorem initial_receipt {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (work : W) (pending : Pending W F E O X D C H)
    (created : Pending.new ops work = Result.ok pending) :
    RequestEffects.new = Result.ok pending.effects ∧ pending.work = work := by
  unfold Pending.new at created
  obtain ⟨effects, initial, rest⟩ := (bind_returns_iff _ _ _).mp created
  have same : pending = ⟨work, effects⟩ := by simpa using rest.symm
  subst pending
  exact ⟨initial, rfl⟩

/-- The real consuming request entry has a reachable receipt for every
    returned outcome. No native report/copy or whole-callback premise remains. -/
theorem returned_entry_receipt {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (work : W) (pending : Pending W F E O X D C H) (out : core.result.Result (completion.Completed O) X)
    (created : Pending.new ops work = Result.ok pending)
    (returned : run_current (adapter ops) pending = Result.ok out) :
    ∃ after, read_transition.Proofs.RequestRun (adapter ops) pending out after ∧ Reachable after.adapter.effects := by
  exact request_effects.Simulation.returned_entry_has_reachable_receipt (adapter ops) (fun pending => pending.effects)
    (request_contracts ops) pending out (initial_receipt ops work pending created).1 returned

theorem successful_entry_completion {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (work : W) (pending : Pending W F E O X D C H) (reply : completion.Completed O)
    (created : Pending.new ops work = Result.ok pending)
    (returned : run_current (adapter ops) pending = Result.ok (.Ok reply)) :
    ∃ completed : Pending W F E O X D C H, Reachable completed.effects ∧
      completed.effects.completion.selected = true ∧ completed.effects.completion.before_checked = true ∧
      completed.effects.completion.audit_attempted = true ∧ completed.effects.completion.audit_acknowledged = true ∧
      completed.effects.completion.after_checked = true ∧ completed.effects.completion.value_ready = true := by
  exact request_effects.Simulation.successful_entry_has_completed_receipt (adapter ops) (fun pending => pending.effects)
    (request_contracts ops) pending reply (initial_receipt ops work pending created).1 returned

private def positiveWork (stamp : manifest.AdmissionStamp) : Work Unit Unit Unit Unit Unit Unit Unit Unit := {
  INVALID_TRANSITION := Result.ok ()
  INVALID_POLICY := Result.ok ()
  dispatchWorkInst := {
    INVALID_TRANSITION := Result.ok ()
    provider_exchangeProviderInst := {
      INVALID_POLICY := Result.ok ()
      OUTCOME_UNKNOWN := Result.ok ()
      setup := fun _ => Result.ok (.Ok (), ())
      recheck := fun _ => Result.ok (.Ok stamp, ())
      send := fun _ _ => Result.ok (.Ok (), (), ())
      receive := fun _ _ => Result.ok (.Ok (), ())
    }
    effect_write := fun _ => Result.ok false
    prepare := fun _ => Result.ok (.Ok (), ())
    audit := fun _ _ => Result.ok (.Ok (), ())
    configure := fun _ _ => Result.ok (.Ok (), ())
    check := fun _ => Result.ok (.Ok (), ())
    reserve := fun _ => Result.ok (.Ok (), ())
    finish := fun _ => Result.ok (.Ok (), ())
  }
  completionWorkInst := {
    INVALID_TRANSITION := Result.ok ()
    select := fun _ => Result.ok (.Ok (), ())
    recheck := fun _ _ => Result.ok (.Ok (), ())
    audit := fun _ => Result.ok (.Ok (), ())
  }
  preflight := fun _ => Result.ok (.Ok none)
  empty_facts := fun _ => Result.ok ()
  final_effect := fun _ _ => Result.ok (.Ok (some ()))
  effect_write := fun _ _ => Result.ok false
  operation_write := fun _ => Result.ok false
  dispatch := fun _ _ _ => Result.ok (⟨(), false⟩, ())
  complete := fun _ _ => Result.ok ((), ())
  recheck := fun _ => Result.ok (.Ok (), ())
  outcome_unknown := fun _ => Result.ok ()
}

set_option linter.unusedSimpArgs false in
/-- The actual consuming entry can perform a final provider read, select its
    returned value, finish audit/check gates and return that exact value. -/
theorem positive_read_witness (stamp : manifest.AdmissionStamp) :
    ∃ pending,
      Pending.new (positiveWork stamp) () = Result.ok pending ∧
      run_current (adapter (positiveWork stamp)) pending = Result.ok (.Ok (completion.Completed.mk ())) := by
  let emptyDispatch : DispatchRecord := ⟨false, false, false, none, false, false, false⟩
  let emptyCompletion : CompletionRecord := ⟨false, false, false, false, false, false⟩
  let initial : RequestEffects := ⟨emptyDispatch, emptyDispatch, emptyCompletion, .Entry⟩
  refine ⟨⟨(), initial⟩, ?_, ?_⟩
  · simp [Pending.new, RequestEffects.new, DispatchRecord.empty, CompletionRecord.empty, initial, emptyDispatch, emptyCompletion]
  · simp [run_current, request_current, request_facts, finish_request,
      invocation.Invocation.new, invocation.Invocation.into_result,
      invocation.Invocation.preflight, invocation.Invocation.empty_facts,
      invocation.Invocation.final_effect, invocation.Invocation.recheck,
      invocation.Invocation.effect_write, invocation.Invocation.dispatch, invocation.Invocation.complete,
      adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.preflight,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.empty_facts,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.final_effect,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.recheck,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.effect_write,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.dispatch,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error.complete,
      positiveWork, read_transition.prepare, dispatch.dispatch, dispatch.run, dispatch.audit, dispatch.exchange, dispatch.finish,
      provider_exchange.exchange, provider_exchange.Report.impl.stage, provider_exchange.Report.impl.current,
      provider_exchange.Report.into_result, provider_exchange.SendState.new,
      dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup,
      dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck,
      dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send,
      dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive,
      Prepared.impl.phase, Audited.impl.phase, Audited.is_write, read_transition.acknowledge,
      RequestEffects.begin_dispatch_audit, RequestEffects.acknowledge_dispatch, RequestEffects.begin_provider,
      RequestEffects.begin_send, RequestEffects.provider_completed, RequestEffects.finish_dispatch,
      RequestEffects.phase, RequestEffects.set_phase, provider_exchange.SendState.begin_check,
      provider_exchange.SendState.finish_check, provider_exchange.SendState.begin_send, provider_exchange.SendState.stamp,
      Phase.Insts.CoreCmpPartialEqPhase.eq, Phase.read_discriminant,
      completion.complete, completion.select_and_complete, read_transition.complete_current,
      completion.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.recheck,
      completion.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.audit,
      completion.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.release,
      RequestEffects.begin_completion, RequestEffects.selected, RequestEffects.begin_completion_check,
      RequestEffects.finish_completion_check, RequestEffects.begin_completion_audit,
      RequestEffects.acknowledge_completion_audit, RequestEffects.value_ready, core.option.Option.take,
      initial, emptyDispatch, emptyCompletion]

/-- A successful callback releases the exact value produced by its selected
    primitive, rather than a value supplied by a native report-link premise. -/
theorem completion_selection_origin {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending after : Pending W F E O X D C H) (raw : F) (value : completion.Completed O)
    (returned : (adapter ops).complete pending raw = Result.ok (.Ok value, after)) :
    ∃ primitive work selected,
      ops.complete pending.work raw = Result.ok (primitive, work) ∧
      ops.completionWorkInst.select primitive = Result.ok (.Ok value.value, selected) := by
  obtain ⟨primitive, work, report, factory, ran, same, _⟩ := (completion_report_iff ops pending after raw (.Ok value)).mp returned
  obtain ⟨selected, origin⟩ := ((completion.Proofs.complete_receipts ops.completionWorkInst primitive pending.effects report ran).2 value same.symm).1
  exact ⟨primitive, work, selected, factory, origin⟩

/-- The actual consuming request's selected-value origin also needs no native
    whole-callback link. Raw facts, JSON projection and observations still need
    their own primitive/context correspondence. -/
theorem successful_entry_selection_origin {W F E O X D C H : Type} (ops : Work W F E O X D C H)
    (pending : Pending W F E O X D C H) (value : completion.Completed O)
    (returned : run_current (adapter ops) pending = Result.ok (.Ok value)) :
    ∃ callbackState : Pending W F E O X D C H, ∃ raw primitive work selected,
      ops.complete callbackState.work raw = Result.ok (primitive, work) ∧
      ops.completionWorkInst.select primitive = Result.ok (.Ok value.value, selected) := by
  obtain ⟨facts, state, preflight, after, origin, finished⟩ :=
    (read_transition.Proofs.run_current_success_iff (adapter ops) pending value).mp returned
  obtain ⟨checked, current, finish⟩ := finished
  rcases finish with ⟨_, completed, completionCall, rfl⟩ |
    ⟨effect, write, raw, dispatched, completed, _, _, sent, completionCall, rfl⟩
  · obtain ⟨primitive, work, selected, factory, selection⟩ := completion_selection_origin ops checked completed facts value completionCall
    exact ⟨checked, facts, primitive, work, selected, factory, selection⟩
  · obtain ⟨primitive, work, selected, factory, selection⟩ := completion_selection_origin ops dispatched completed raw value completionCall
    exact ⟨dispatched, raw, primitive, work, selected, factory, selection⟩

end aivm_secrets_garrett_core.request_adapter.Proofs
