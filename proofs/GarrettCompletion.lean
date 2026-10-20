import GarrettRequestEffects

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-! The actual owned native-completion adapter. Receipt transitions are proved
from its extracted code, not assumed for an entire callback. Native selection,
authority and durable audit primitive semantics remain separate contracts. -/
namespace aivm_secrets_garrett_core.completion.Proofs
open request_effects request_effects.Proofs read_transition

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

private theorem steps_trans {first middle last : RequestEffects}
    (left : Steps first middle) (right : Steps middle last) : Steps first last := by
  induction right with
  | refl => exact left
  | next prior last ih => exact .next ih last

/-- Both successful and denied primitive checks retain their actual returned
    work state; only the source-owned gate changes the receipt. -/
theorem recheck_receipts {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (phase : CompletionPhase) (out : core.result.Result Unit X)
    (returned : (adapter ops).recheck pending phase = Result.ok (out, after)) :
    Steps pending.effects after.effects ∧ after.value = pending.value := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.recheck at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have priorSteps : Steps pending.effects first := .next .refl (.begin_completion_check accepted phase began)
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
      have suffix : Steps pending.effects last := .next priorSteps (.finish_completion_check accepted phase finished)
      have same : after = {pending with work, effects := last} := by
        cases accepted with
        | false => exact constant_state _ _ _ _ (by simpa using rest)
        | true => exact returned_state (.Ok () : core.result.Result Unit X) out _ _ (by simpa using rest)
      subst after
      exact ⟨suffix, rfl⟩

theorem audit_receipts {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result Unit X)
    (returned : (adapter ops).audit pending = Result.ok (out, after)) :
    Steps pending.effects after.effects ∧ after.value = pending.value := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.audit at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have priorSteps : Steps pending.effects first := .next .refl (.begin_completion_audit accepted began)
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
      have suffix : Steps pending.effects last := .next priorSteps (.acknowledge_completion_audit accepted acknowledged)
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

theorem release_receipts {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result (Completed O) X)
    (returned : (adapter ops).release pending = Result.ok (out, after)) :
    Steps pending.effects after.effects ∧
      ∀ completed, out = .Ok completed → pending.value = some completed.value ∧
        after.value = none ∧ RequestEffects.can_return_value after.effects = Result.ok true := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.release at returned
  obtain ⟨⟨accepted, first⟩, ready, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have priorSteps : Steps pending.effects first := .next .refl (.value_ready accepted ready)
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
theorem current_receipts {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result (Completed O) X)
    (returned : read_transition.complete_current (adapter ops) pending = Result.ok (out, after)) :
    Steps pending.effects after.effects ∧
      ∀ completed, out = .Ok completed → pending.value = some completed.value ∧
        after.value = none ∧ RequestEffects.can_return_value after.effects = Result.ok true := by
  unfold read_transition.complete_current at returned
  obtain ⟨⟨checked, first⟩, before, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have firstSteps := recheck_receipts ops pending first .BeforeAudit checked before
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
    have secondSteps := audit_receipts ops first second written audit
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
      have thirdSteps := recheck_receipts ops second third .BeforeRelease checked current
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
        have released := release_receipts ops third after out (by simpa using rest)
        refine ⟨steps_trans prior released.1, ?_⟩
        intro completed success
        obtain ⟨origin, consumed, ready⟩ := released.2 completed success
        exact ⟨by simpa only [thirdSteps.2, secondSteps.2, firstSteps.2] using origin, consumed, ready⟩

private theorem constant_not_success {X A P : Type} (constant : Result X) (state after : P) (value : A)
    (returned : (do let error ← constant; Result.ok ((.Err error : core.result.Result A X), state)) = Result.ok (.Ok value, after)) : False := by
  obtain ⟨error, _, impossible⟩ := (bind_returns_iff _ _ _).mp returned
  simp at impossible

theorem selection_and_completion_receipts {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (out : core.result.Result (Completed O) X)
    (returned : select_and_complete ops pending = Result.ok (out, after)) :
    Steps pending.effects after.effects ∧
      ∀ completed, out = .Ok completed →
        (∃ selected, ops.select pending.work = Result.ok (.Ok completed.value, selected)) ∧
          RequestEffects.can_return_value after.effects = Result.ok true := by
  unfold select_and_complete at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have prior : Steps pending.effects first := .next .refl (.begin_completion accepted began)
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
      have prior : Steps pending.effects second := .next prior (.selected accepted selected)
      cases accepted with
      | false =>
        have same := constant_state ops.INVALID_TRANSITION {pending with work, effects := second} after out (by simpa using rest)
        subst after
        refine ⟨prior, ?_⟩
        intro completed success
        subst out
        exact False.elim (constant_not_success _ _ _ _ rest)
      | true =>
        have completed := current_receipts ops ⟨work, second, some value⟩ after out (by simpa using rest)
        refine ⟨steps_trans prior completed.1, ?_⟩
        intro result success
        obtain ⟨origin, _, ready⟩ := completed.2 result success
        have equal : value = result.value := Option.some.inj origin
        exact ⟨⟨work, by simpa only [equal] using callback⟩, ready⟩

/-- No whole-callback Steps or return-gate hypothesis is assumed here. The
    actual production controller supplies both from its primitive returns. -/
theorem complete_receipts {W O X : Type} (ops : Work W O X)
    (work : W) (effects : RequestEffects) (report : Report W O X)
    (returned : complete ops work effects = Result.ok report) :
    Steps effects report.effects ∧
      ∀ completed, report.outcome = .Ok completed →
        (∃ selected, ops.select work = Result.ok (.Ok completed.value, selected)) ∧
          RequestEffects.can_return_value report.effects = Result.ok true := by
  unfold complete at returned
  obtain ⟨⟨out, after⟩, ran, same⟩ := (bind_returns_iff _ _ _).mp returned
  have equal : {outcome := out, work := after.work, effects := after.effects : Report W O X} = report := by
    simpa using same
  subst report
  exact selection_and_completion_receipts ops ⟨work, effects, none⟩ after out ran

theorem recheck_success_iff {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) (phase : CompletionPhase) :
    (adapter ops).recheck pending phase = Result.ok (.Ok (), after) ↔
      ∃ first last work,
        RequestEffects.begin_completion_check pending.effects phase = Result.ok (true, first) ∧
        ops.recheck pending.work phase = Result.ok (.Ok (), work) ∧
        RequestEffects.finish_completion_check first phase = Result.ok (true, last) ∧
        after = {pending with work, effects := last} := by
  constructor
  · intro returned
    dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
    unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.recheck at returned
    obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
    cases accepted with
    | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
    | true =>
      obtain ⟨⟨checked, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases checked with
      | Err error => simp at rest
      | Ok u =>
        cases u
        obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
        cases accepted with
        | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
        | true =>
          exact ⟨first, last, work, began, callback, finished,
            returned_state (.Ok () : core.result.Result Unit X) (.Ok ()) _ _ (by simpa using rest)⟩
  · rintro ⟨first, last, work, began, callback, finished, rfl⟩
    simp [
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.recheck, began, callback, finished]

theorem recheck_refusal_prefix {W O X : Type} (ops : Work W O X)
    (pending : Pending W O X) (phase : CompletionPhase) (first : RequestEffects) (work : W) (error : X)
    (began : RequestEffects.begin_completion_check pending.effects phase = Result.ok (true, first))
    (refused : ops.recheck pending.work phase = Result.ok (.Err error, work)) :
    (adapter ops).recheck pending phase = Result.ok (.Err error, {pending with work, effects := first}) := by
  simp [
    Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.recheck, began, refused]

theorem audit_success_iff {W O X : Type} (ops : Work W O X)
    (pending after : Pending W O X) :
    (adapter ops).audit pending = Result.ok (.Ok (), after) ↔
      ∃ first last work,
        RequestEffects.begin_completion_audit pending.effects = Result.ok (true, first) ∧
        ops.audit pending.work = Result.ok (.Ok (), work) ∧
        RequestEffects.acknowledge_completion_audit first = Result.ok (true, last) ∧
        after = {pending with work, effects := last} := by
  constructor
  · intro returned
    dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error] at returned
    unfold Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.audit at returned
    obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
    cases accepted with
    | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
    | true =>
      obtain ⟨⟨checked, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases checked with
      | Err error => simp at rest
      | Ok u =>
        cases u
        obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
        cases accepted with
        | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
        | true =>
          exact ⟨first, last, work, began, callback, finished,
            returned_state (.Ok () : core.result.Result Unit X) (.Ok ()) _ _ (by simpa using rest)⟩
  · rintro ⟨first, last, work, began, callback, finished, rfl⟩
    simp [
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.audit, began, callback, finished]

theorem audit_refusal_prefix {W O X : Type} (ops : Work W O X)
    (pending : Pending W O X) (first : RequestEffects) (work : W) (error : X)
    (began : RequestEffects.begin_completion_audit pending.effects = Result.ok (true, first))
    (refused : ops.audit pending.work = Result.ok (.Err error, work)) :
    (adapter ops).audit pending = Result.ok (.Err error, {pending with work, effects := first}) := by
  simp [
    Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.audit, began, refused]

private theorem current_success_iff {P O X : Type} (ops : Completion P O X)
    (pending after : P) (value : O) :
    read_transition.complete_current ops pending = Result.ok (.Ok value, after) ↔
      ∃ first second third,
        ops.recheck pending .BeforeAudit = Result.ok (.Ok (), first) ∧
        ops.audit first = Result.ok (.Ok (), second) ∧
        ops.recheck second .BeforeRelease = Result.ok (.Ok (), third) ∧
        ops.release third = Result.ok (.Ok value, after) := by
  constructor
  · intro returned
    unfold read_transition.complete_current at returned
    obtain ⟨⟨checked, first⟩, before, rest⟩ := (bind_returns_iff _ _ _).mp returned
    cases checked with
    | Err error => simp at rest
    | Ok u =>
      cases u
      obtain ⟨⟨written, second⟩, audit, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases written with
      | Err error => simp at rest
      | Ok u =>
        cases u
        obtain ⟨⟨checked, third⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
        cases checked with
        | Err error => simp at rest
        | Ok u =>
          cases u
          exact ⟨first, second, third, before, audit, current, rest⟩
  · rintro ⟨first, second, third, before, audit, current, released⟩
    simp [read_transition.complete_current, before, audit, current, released]

/-- The successful native callback has the same selection/check/audit/check
    primitive states in order. No audit-success Boolean is postulated. -/
theorem complete_success_primitives {W O X : Type} (ops : Work W O X)
    (work : W) (effects : RequestEffects) (report : Report W O X) (value : Completed O)
    (returned : complete ops work effects = Result.ok report) (success : report.outcome = .Ok value) :
    ∃ selected checked audited current,
      ops.select work = Result.ok (.Ok value.value, selected) ∧
      ops.recheck selected .BeforeAudit = Result.ok (.Ok (), checked) ∧
      ops.audit checked = Result.ok (.Ok (), audited) ∧
      ops.recheck audited .BeforeRelease = Result.ok (.Ok (), current) := by
  unfold complete at returned
  obtain ⟨⟨out, after⟩, ran, same⟩ := (bind_returns_iff _ _ _).mp returned
  have equal : {outcome := out, work := after.work, effects := after.effects : Report W O X} = report := by
    simpa using same
  subst report
  dsimp only at success
  subst out
  unfold select_and_complete at ran
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp ran
  cases accepted with
  | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
  | true =>
    obtain ⟨⟨selected, selectedWork⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    cases selected with
    | Err error => simp at rest
    | Ok selectedValue =>
      obtain ⟨⟨accepted, second⟩, selected, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases accepted with
      | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
      | true =>
        obtain ⟨p1, p2, p3, before, audit, current, released⟩ :=
          (current_success_iff (adapter ops) ⟨selectedWork, second, some selectedValue⟩ after value).mp rest
        obtain ⟨s1, s2, checkedWork, _, checked, _, firstState⟩ :=
          (recheck_success_iff ops _ p1 .BeforeAudit).mp before
        subst p1
        obtain ⟨s3, s4, auditedWork, _, written, _, secondState⟩ := (audit_success_iff ops _ p2).mp audit
        subst p2
        obtain ⟨s5, s6, currentWork, _, checkedAgain, _, thirdState⟩ :=
          (recheck_success_iff ops _ p3 .BeforeRelease).mp current
        subst p3
        have origin := (release_receipts ops _ after (.Ok value) released).2 value rfl |>.1
        have sameValue : selectedValue = value.value := Option.some.inj origin
        exact ⟨selectedWork, checkedWork, auditedWork, currentWork,
          by simpa only [sameValue] using callback, checked, written, checkedAgain⟩

theorem complete_preserves_reachability {W O X : Type} (ops : Work W O X)
    (work : W) (effects : RequestEffects) (report : Report W O X)
    (reachable : Reachable effects) (returned : complete ops work effects = Result.ok report) :
    Reachable report.effects := by
  obtain ⟨initial, created, prior⟩ := reachable
  exact ⟨initial, created, steps_trans prior (complete_receipts ops work effects report returned).1⟩

theorem successful_completion_requires_actual_checks_and_audit {W O X : Type} (ops : Work W O X)
    (work : W) (effects : RequestEffects) (report : Report W O X) (value : Completed O)
    (reachable : Reachable effects) (returned : complete ops work effects = Result.ok report)
    (success : report.outcome = .Ok value) :
    report.effects.completion.selected = true ∧ report.effects.completion.before_checked = true ∧
    report.effects.completion.audit_attempted = true ∧ report.effects.completion.audit_acknowledged = true ∧
    report.effects.completion.after_checked = true ∧ report.effects.completion.value_ready = true := by
  exact completed_value_requires_selection_checks_and_audit _
    (complete_preserves_reachability ops work effects report reachable returned)
    ((complete_receipts ops work effects report returned).2 value success).2

theorem repeated_completion_calls_no_primitive {W O X : Type} (ops : Work W O X)
    (work : W) (effects : RequestEffects) (code : X)
    (ready : RequestEffects.can_return_value effects = Result.ok true)
    (constant : ops.INVALID_TRANSITION = Result.ok code) :
    complete ops work effects = Result.ok (Report.mk (.Err code) work {effects with progress := .Halted}) := by
  have progress := (can_return_value_iff effects).mp ready
  simp [complete, select_and_complete, RequestEffects.begin_completion, RequestEffects.reject, progress, constant]

private def positiveOps : Work Unit Unit Unit := {
  INVALID_TRANSITION := Result.ok ()
  select := fun _ => Result.ok (.Ok (), ())
  recheck := fun _ _ => Result.ok (.Ok (), ())
  audit := fun _ => Result.ok (.Ok (), ())
}

/-- A successful extracted witness rules out blanket refusal of completion.
    Real native successful provider/read witnesses remain separate tests. -/
theorem completion_positive_witness :
    ∃ initial report,
      RequestEffects.new = Result.ok initial ∧
      complete positiveOps () initial = Result.ok report ∧ report.outcome = .Ok (Completed.mk ()) := by
  let emptyDispatch : DispatchRecord := ⟨false, false, false, none, false, false, false⟩
  let initial : RequestEffects := ⟨emptyDispatch, emptyDispatch,
    ⟨false, false, false, false, false, false⟩, .Entry⟩
  let finished : RequestEffects := ⟨emptyDispatch, emptyDispatch,
    ⟨true, true, true, true, true, true⟩, .ValueReady⟩
  refine ⟨initial, ⟨.Ok ⟨()⟩, (), finished⟩, ?_, ?_, rfl⟩
  · simp [RequestEffects.new, DispatchRecord.empty, CompletionRecord.empty, initial, emptyDispatch]
  · simp [complete, select_and_complete, read_transition.complete_current,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.recheck,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.audit,
      Pending.Insts.Aivm_secrets_garrett_coreRead_transitionCompletionCompletedClause0_Error.release,
      RequestEffects.begin_completion, RequestEffects.selected, RequestEffects.begin_completion_check,
      RequestEffects.finish_completion_check, RequestEffects.begin_completion_audit,
      RequestEffects.acknowledge_completion_audit, RequestEffects.value_ready,
      core.option.Option.take, positiveOps, initial, finished]

/-- The public report retains the exact internal post-state on every return,
    rather than rolling a failed callback back to an earlier sound receipt. -/
theorem returned_report_iff {W O X : Type} (ops : Work W O X)
    (work : W) (effects : RequestEffects) (report : Report W O X) :
    complete ops work effects = Result.ok report ↔
      ∃ after, select_and_complete ops ⟨work, effects, none⟩ = Result.ok (report.outcome, after) ∧
        report.work = after.work ∧ report.effects = after.effects := by
  constructor
  · intro returned
    unfold complete at returned
    obtain ⟨⟨out, after⟩, ran, same⟩ := (bind_returns_iff _ _ _).mp returned
    have equal : {outcome := out, work := after.work, effects := after.effects : Report W O X} = report := by
      simpa using same
    subst report
    exact ⟨after, ran, rfl, rfl⟩
  · rintro ⟨after, ran, workEq, effectsEq⟩
    simp [complete, ran, ←workEq, ←effectsEq]

end aivm_secrets_garrett_core.completion.Proofs
