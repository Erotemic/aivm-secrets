import GarrettCompletion
import GarrettRequestTrace

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! Chronological source-owned completion gate histories for all returned
prefixes. Selected JSON/frame observations and primitive semantics remain open. -/
namespace aivm_secrets_garrett_core.completion.TraceRefinement
open request_effects request_effects.Proofs request_effects.TraceRefinement read_transition
open provider_exchange.Simulation

def HasTrace (contexts : Phase → Context) (before after : RequestEffects) : Prop :=
  ∃ events, TraceSteps contexts before after events

private theorem trace_refl (contexts : Phase → Context) (state : RequestEffects) : HasTrace contexts state state := ⟨[], .refl⟩

private theorem trace_next {contexts : Phase → Context} {first middle last : RequestEffects}
    (prior : HasTrace contexts first middle) (step : Step middle last) (origin : FreshOrigin contexts middle last) :
    HasTrace contexts first last := by
  obtain ⟨events, prior⟩ := prior
  exact ⟨_, .next prior step origin⟩

private theorem steps_trans {contexts : Phase → Context} {first middle last : RequestEffects}
    (initial : HasTrace contexts first middle) (remaining : HasTrace contexts middle last) : HasTrace contexts first last := by
  obtain ⟨a, initial⟩ := initial
  obtain ⟨b, remaining⟩ := remaining
  refine ⟨a ++ b, ?_⟩
  induction remaining with
  | refl => simpa using initial
  | next prior step origin ih => simpa [List.append_assoc] using TraceSteps.next ih step origin

private theorem begin_completion_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool)
    (step : RequestEffects.begin_completion s = Result.ok (accepted, after)) : FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.begin_completion

private theorem selected_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool)
    (step : RequestEffects.selected s = Result.ok (accepted, after)) : FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.selected

private theorem begin_completion_check_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool) (phase : CompletionPhase)
    (step : RequestEffects.begin_completion_check s phase = Result.ok (accepted, after)) : FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases phase <;> cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.begin_completion_check

private theorem finish_completion_check_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool) (phase : CompletionPhase)
    (step : RequestEffects.finish_completion_check s phase = Result.ok (accepted, after)) : FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases phase <;> cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.finish_completion_check

private theorem begin_completion_audit_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool)
    (step : RequestEffects.begin_completion_audit s = Result.ok (accepted, after)) : FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.begin_completion_audit

private theorem acknowledge_completion_audit_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool)
    (step : RequestEffects.acknowledge_completion_audit s = Result.ok (accepted, after)) : FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.acknowledge_completion_audit

private theorem value_ready_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool)
    (step : RequestEffects.value_ready s = Result.ok (accepted, after)) : FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.value_ready

private abbrev adapter {W O X : Type} (ops : Work W O X) :=
  Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error ops

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private theorem constant_state {X A P : Type} (constant : Result X) (state after : P)
    (out : core.result.Result A X)
    (returned : (do let error ← constant; Result.ok (.Err error, state)) = Result.ok (out, after)) :
    after = state := by
  obtain ⟨error, _, same⟩ := (bind_returns_iff _ _ _).mp returned
  exact (congrArg Prod.snd ((Result.ok.injEq).mp same)).symm

private theorem returned_state {A P : Type} (value out : A) (state after : P)
    (returned : Result.ok (value, state) = Result.ok (out, after)) : after = state :=
  (congrArg Prod.snd ((Result.ok.injEq).mp returned)).symm

/-- Both successful and denied primitive checks retain their actual returned
    work state; only the source-owned gate changes the receipt. -/
theorem recheck_trace {contexts : Phase → Context} {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (phase : CompletionPhase) (out : core.result.Result Unit X)
    (returned : (adapter ops).recheck pending phase = Result.ok (out, after)) :
    HasTrace contexts pending.effects after.effects ∧ after.value = pending.value := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.recheck at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have priorSteps : HasTrace contexts pending.effects first := trace_next (trace_refl contexts _) (.begin_completion_check accepted phase began) (begin_completion_check_origin contexts _ _ accepted phase began)
  cases accepted with
  | false =>
    have same := constant_state ops.INVALID_TRANSITION {pending with effects := first} after out (by simpa using rest)
    subst after
    exact ⟨priorSteps, rfl⟩
  | true =>
    obtain ⟨⟨checked, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    cases checked with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result Unit X) out
        {pending with work, effects := first} after (by simpa using rest)
      subst after
      exact ⟨priorSteps, rfl⟩
    | Ok u =>
      cases u
      obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have suffix : HasTrace contexts pending.effects last := trace_next priorSteps (.finish_completion_check accepted phase finished) (finish_completion_check_origin contexts _ _ accepted phase finished)
      have same : after = {pending with work, effects := last} := by
        cases accepted with
        | false => exact constant_state _ _ _ _ (by simpa using rest)
        | true => exact returned_state (.Ok () : core.result.Result Unit X) out _ _ (by simpa using rest)
      subst after
      exact ⟨suffix, rfl⟩

theorem audit_trace {contexts : Phase → Context} {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result Unit X)
    (returned : (adapter ops).audit pending = Result.ok (out, after)) :
    HasTrace contexts pending.effects after.effects ∧ after.value = pending.value := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.audit at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have priorSteps : HasTrace contexts pending.effects first := trace_next (trace_refl contexts _) (.begin_completion_audit accepted began) (begin_completion_audit_origin contexts _ _ accepted began)
  cases accepted with
  | false =>
    have same := constant_state ops.INVALID_TRANSITION {pending with effects := first} after out (by simpa using rest)
    subst after
    exact ⟨priorSteps, rfl⟩
  | true =>
    obtain ⟨⟨written, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    cases written with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result Unit X) out
        {pending with work, effects := first} after (by simpa using rest)
      subst after
      exact ⟨priorSteps, rfl⟩
    | Ok u =>
      cases u
      obtain ⟨⟨accepted, last⟩, acknowledged, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have suffix : HasTrace contexts pending.effects last := trace_next priorSteps (.acknowledge_completion_audit accepted acknowledged) (acknowledge_completion_audit_origin contexts _ _ accepted acknowledged)
      have same : after = {pending with work, effects := last} := by
        cases accepted with
        | false => exact constant_state _ _ _ _ (by simpa using rest)
        | true => exact returned_state (.Ok () : core.result.Result Unit X) out _ _ (by simpa using rest)
      subst after
      exact ⟨suffix, rfl⟩

private theorem ready_gate (before after : RequestEffects)
    (returned : RequestEffects.value_ready before = Result.ok (true, after)) :
    RequestEffects.can_return_value after = Result.ok true := by
  cases before with
  | mk pre final completion progress =>
    cases progress <;>
      simp [RequestEffects.value_ready, RequestEffects.reject] at returned
    case AfterAudit =>
      subst after
      rfl

theorem release_trace {contexts : Phase → Context} {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result (Completed O) X)
    (returned : (adapter ops).release pending = Result.ok (out, after)) :
    HasTrace contexts pending.effects after.effects ∧
      ∀ completed, out = .Ok completed → pending.value = some completed.value ∧
        after.value = none ∧ RequestEffects.can_return_value after.effects = Result.ok true := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.release at returned
  obtain ⟨⟨accepted, first⟩, ready, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have priorSteps : HasTrace contexts pending.effects first := trace_next (trace_refl contexts _) (.value_ready accepted ready) (value_ready_origin contexts _ _ accepted ready)
  cases accepted with
  | false =>
    have same := constant_state ops.INVALID_TRANSITION {pending with effects := first} after out (by simpa using rest)
    subst after
    refine ⟨priorSteps, ?_⟩
    intro completed success
    subst out
    obtain ⟨error, _, impossible⟩ := (bind_returns_iff _ _ _).mp rest
    simp at impossible
  | true =>
    dsimp only [core.option.Option.take] at rest
    cases chosen : pending.value with
    | none =>
      simp only [chosen] at rest
      have same := constant_state ops.INVALID_TRANSITION {pending with effects := first, value := none} after out (by simpa using rest)
      subst after
      refine ⟨priorSteps, ?_⟩
      intro completed success
      subst out
      obtain ⟨error, _, impossible⟩ := (bind_returns_iff _ _ _).mp rest
      simp at impossible
    | some value =>
      simp only [chosen] at rest
      have same := returned_state (.Ok (Completed.mk value) : core.result.Result (Completed O) X)
        out {pending with effects := first, value := none} after (by simpa using rest)
      subst after
      refine ⟨priorSteps, ?_⟩
      intro completed success
      have equal : Completed.mk value = completed := by simpa [success] using rest
      subst completed
      exact ⟨rfl, rfl, ready_gate _ _ ready⟩

/-- Every returned completion prefix, including primitive refusals, follows
    the actual receipt steps; success consumes exactly the prepared value. -/
theorem current_trace {contexts : Phase → Context} {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result (Completed O) X)
    (returned : read_transition.complete_current (adapter ops) pending = Result.ok (out, after)) :
    HasTrace contexts pending.effects after.effects ∧
      ∀ completed, out = .Ok completed → pending.value = some completed.value ∧
        after.value = none ∧ RequestEffects.can_return_value after.effects = Result.ok true := by
  unfold read_transition.complete_current at returned
  obtain ⟨⟨checked, first⟩, before, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have firstSteps := recheck_trace (contexts := contexts) ops pending first .BeforeAudit checked before
  cases checked with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result (Completed O) X) out first after rest
    subst after
    refine ⟨firstSteps.1, ?_⟩
    intro completed success
    simp [success] at rest
  | Ok u =>
    cases u
    obtain ⟨⟨written, second⟩, audit, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have secondSteps := audit_trace (contexts := contexts) ops first second written audit
    have prior := steps_trans firstSteps.1 secondSteps.1
    cases written with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result (Completed O) X) out second after rest
      subst after
      refine ⟨prior, ?_⟩
      intro completed success
      simp [success] at rest
    | Ok u =>
      cases u
      obtain ⟨⟨checked, third⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have thirdSteps := recheck_trace (contexts := contexts) ops second third .BeforeRelease checked current
      have prior := steps_trans prior thirdSteps.1
      cases checked with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result (Completed O) X) out third after rest
        subst after
        refine ⟨prior, ?_⟩
        intro completed success
        simp [success] at rest
      | Ok u =>
        cases u
        have released := release_trace (contexts := contexts) ops third after out (by simpa using rest)
        refine ⟨steps_trans prior released.1, ?_⟩
        intro completed success
        obtain ⟨origin, consumed, ready⟩ := released.2 completed success
        exact ⟨by simpa only [thirdSteps.2, secondSteps.2, firstSteps.2] using origin, consumed, ready⟩

private theorem constant_not_success {X A P : Type} (constant : Result X) (state after : P) (value : A)
    (returned : (do let error ← constant; Result.ok ((.Err error : core.result.Result A X), state)) = Result.ok (.Ok value, after)) : False := by
  obtain ⟨error, _, impossible⟩ := (bind_returns_iff _ _ _).mp returned
  simp at impossible

theorem selection_and_completion_trace {contexts : Phase → Context} {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result (Completed O) X)
    (returned : select_and_complete ops pending = Result.ok (out, after)) :
    HasTrace contexts pending.effects after.effects ∧
      ∀ completed, out = .Ok completed →
        (∃ selected, ops.select pending.work = Result.ok (.Ok completed.value, selected)) ∧
          RequestEffects.can_return_value after.effects = Result.ok true := by
  unfold select_and_complete at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have prior : HasTrace contexts pending.effects first := trace_next (trace_refl contexts _) (.begin_completion accepted began) (begin_completion_origin contexts _ _ accepted began)
  cases accepted with
  | false =>
    have same := constant_state ops.INVALID_TRANSITION {pending with effects := first} after out (by simpa using rest)
    subst after
    refine ⟨prior, ?_⟩
    intro completed success
    subst out
    exact False.elim (constant_not_success _ _ _ _ rest)
  | true =>
    obtain ⟨⟨selected, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    cases selected with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result (Completed O) X) out
        {pending with work, effects := first} after (by simpa using rest)
      subst after
      refine ⟨prior, ?_⟩
      intro completed success
      simp [success] at rest
    | Ok value =>
      obtain ⟨⟨accepted, second⟩, selected, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have prior : HasTrace contexts pending.effects second := trace_next prior (.selected accepted selected) (selected_origin contexts _ _ accepted selected)
      cases accepted with
      | false =>
        have same := constant_state ops.INVALID_TRANSITION {pending with work, effects := second} after out (by simpa using rest)
        subst after
        refine ⟨prior, ?_⟩
        intro completed success
        subst out
        exact False.elim (constant_not_success _ _ _ _ rest)
      | true =>
        have completed := current_trace (contexts := contexts) ops ⟨work, second, some value⟩ after out (by simpa using rest)
        refine ⟨steps_trans prior completed.1, ?_⟩
        intro result success
        obtain ⟨origin, _, ready⟩ := completed.2 result success
        have equal : value = result.value := Option.some.inj origin
        exact ⟨⟨work, by simpa only [equal] using callback⟩, ready⟩

/-- No whole-callback history or return-gate hypothesis is assumed here. The
    actual production controller supplies both from its primitive returns. -/
theorem complete_trace {contexts : Phase → Context} {W O X : Type} (ops : Work W O X)
    (work : W) (effects : RequestEffects) (report : Report W O X)
    (returned : complete ops work effects = Result.ok report) :
    HasTrace contexts effects report.effects ∧
      ∀ completed, report.outcome = .Ok completed →
        (∃ selected, ops.select work = Result.ok (.Ok completed.value, selected)) ∧
          RequestEffects.can_return_value report.effects = Result.ok true := by
  unfold complete at returned
  obtain ⟨⟨out, after⟩, ran, same⟩ := (bind_returns_iff _ _ _).mp returned
  have equal : {outcome := out, work := after.work, effects := after.effects : Report W O X} = report := by
    simpa using same
  subst report
  exact selection_and_completion_trace (contexts := contexts) ops ⟨work, effects, none⟩ after out ran

end aivm_secrets_garrett_core.completion.TraceRefinement
