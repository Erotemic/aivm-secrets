import GarrettCurrentAdmission
import GarrettRequestTrace

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

/-! Actual owned-dispatch receipt histories with source-derived current origin.
Native primitive semantics and complete I/O correspondence remain separate. -/
namespace aivm_secrets_garrett_core.dispatch.TraceRefinement
open read_transition request_effects request_effects.Proofs
open request_effects.TraceRefinement provider_exchange.Simulation

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private theorem returned_state {A P : Type} (value out : A) (state after : P)
    (returned : Result.ok (value, state) = Result.ok (out, after)) : after = state :=
  (congrArg Prod.snd ((Result.ok.injEq).mp returned)).symm

private theorem fixed_state {A B P : Type} (first : Result A) (build : A → B) (state after : P) (out : B)
    (returned : (do let value ← first; Result.ok (build value, state)) = Result.ok (out, after)) : after = state := by
  obtain ⟨value, _, same⟩ := (bind_returns_iff _ _ _).mp returned
  exact returned_state _ _ _ _ same

private abbrev bound {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X) :=
  current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks

private abbrev adapter {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X) :=
  Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider (bound work checks)

/-- Exact chronological source-gate history plus the context frame. -/
def Related {W C H O X : Type}
    (before after : Pending (current_admission.Bound W C H O X) H O X) : Prop :=
  after.work.context = before.work.context ∧
  ∃ events, TraceSteps (fun _ => current_admission.Proofs.view before.work.context)
    before.effects after.effects events

private theorem related_frame {W C H O X : Type}
    (before after : Pending (current_admission.Bound W C H O X) H O X)
    (ctx : after.work.context = before.work.context) (effects : after.effects = before.effects) :
    Related before after := by
  refine ⟨ctx, [], ?_⟩
  rw [effects]
  exact .refl

private theorem traces_trans {contexts : Phase → Context} {first middle last : RequestEffects}
    {a b : List confinement.Proofs.Event} (initial : TraceSteps contexts first middle a)
    (remaining : TraceSteps contexts middle last b) : TraceSteps contexts first last (a ++ b) := by
  induction remaining with
  | refl => simpa using initial
  | next prior step origin ih => simpa [List.append_assoc] using TraceSteps.next ih step origin

private theorem related_trans {W C H O X : Type}
    {first middle last : Pending (current_admission.Bound W C H O X) H O X}
    (left : Related first middle) (right : Related middle last) : Related first last := by
  obtain ⟨same, a, initial⟩ := left
  obtain ⟨final, b, remaining⟩ := right
  refine ⟨final.trans same, a ++ b, ?_⟩
  rw [same] at remaining
  exact traces_trans initial remaining

private theorem gate_related {W C H O X : Type}
    (before after : Pending (current_admission.Bound W C H O X) H O X)
    (ctx : after.work.context = before.work.context) (step : Step before.effects after.effects)
    (origin : FreshOrigin (fun _ => current_admission.Proofs.view before.work.context) before.effects after.effects) :
    Related before after := ⟨ctx, _, .next .refl step origin⟩

private theorem begin_audit_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool) (prepared : Prepared)
    (step : RequestEffects.begin_dispatch_audit s prepared = Result.ok (accepted, after)) :
    FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases prepared with
    | mk phase write =>
      cases phase <;> cases target <;>
      simp only [record] at mark current <;>
      mark_cases progress at step using RequestEffects.begin_dispatch_audit

private theorem acknowledge_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool) (audited : Audited)
    (step : RequestEffects.acknowledge_dispatch s audited = Result.ok (accepted, after)) :
    FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases audited with
    | mk phase write =>
      cases phase <;> cases target <;>
      simp only [record] at mark current <;>
      mark_cases progress at step using RequestEffects.acknowledge_dispatch

private theorem begin_provider_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool) (audited : Audited)
    (step : RequestEffects.begin_provider s audited = Result.ok (accepted, after)) :
    FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases audited with
    | mk phase write =>
      cases phase <;> cases target <;>
      simp only [record] at mark current <;>
      mark_cases progress at step using RequestEffects.begin_provider

private theorem completed_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool) (phase : Phase)
    (step : RequestEffects.provider_completed s phase = Result.ok (accepted, after)) :
    FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases phase <;> cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.provider_completed

private theorem finished_origin (contexts : Phase → Context) (s after : RequestEffects)
    (accepted : Bool) (phase : Phase)
    (step : RequestEffects.finish_dispatch s phase = Result.ok (accepted, after)) :
    FreshOrigin contexts s after := by
  intro target stamp mark current
  cases s with
  | mk pre final completion progress =>
    cases phase <;> cases target <;>
    simp only [record] at mark current <;>
    mark_cases progress at step using RequestEffects.finish_dispatch


private theorem constant_not_success {X O P : Type} (constant : Result X) (state after : P) (value : O)
    (returned : (do let error ← constant; Result.ok ((.Err error : core.result.Result O X), state)) = Result.ok (.Ok value, after)) : False := by
  obtain ⟨error, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  simp at rest

theorem setup_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (out : core.result.Result H X)
    (returned : (adapter work checks).setup pending = Result.ok (out, after)) : Related pending after :=
  related_frame pending after (current_admission.Proofs.dispatch_setup_context work checks pending after out returned)
    (Proofs.setup_frame (bound work checks) pending after out returned).1

theorem receive_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (channel : H) (out : core.result.Result O X)
    (returned : (adapter work checks).receive pending channel = Result.ok (out, after)) : Related pending after :=
  related_frame pending after (current_admission.Proofs.dispatch_receive_context work checks pending after channel out returned)
    (Proofs.receive_frame (bound work checks) pending after channel out returned).1

theorem current_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (out : core.result.Result manifest.AdmissionStamp X)
    (returned : (adapter work checks).recheck pending = Result.ok (out, after)) : Related pending after :=
  related_frame pending after (current_admission.Proofs.dispatch_current_origin work checks pending after out returned).1
    (Proofs.current_frame (bound work checks) pending after out returned).1

/-- Actual successful recheck leaves exactly the checked stamp in the private
    send state. This is derived from the source gate, not a ready premise. -/
theorem successful_current_records_stamp {W H O X : Type} (ops : Work W H O X)
    (pending after : Pending W H O X) (stamp : manifest.AdmissionStamp)
    (returned : (Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider ops).recheck pending = Result.ok (.Ok stamp, after)) :
    after.«local».progress = .Checked stamp := by
  dsimp only [Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  cases accepted with
  | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
  | true =>
    obtain ⟨⟨result, primitive⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    cases result with
    | Err error => simp at rest
    | Ok actual =>
      obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases accepted with
      | false => exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
      | true =>
        have pair : ((.Ok actual : core.result.Result manifest.AdmissionStamp X), {pending with work := primitive, «local» := last}) = (.Ok stamp, after) := by simpa using rest
        have same : actual = stamp := by simpa using congrArg Prod.fst pair
        subst actual
        have state : after = {pending with work := primitive, «local» := last} := (congrArg Prod.snd pair).symm
        subst after
        have checked := (provider_exchange.Proofs.checking_is_required_to_record_stamp first last stamp).mp finished |>.2
        rw [checked]

/-- The local proof obligation at the composite send gate is discharged by
    the actual bound current check and the actual successful local-state gate. -/
theorem checked_origin {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (stamp : manifest.AdmissionStamp)
    (returned : (adapter work checks).recheck pending = Result.ok (.Ok stamp, after)) :
    ∀ actual, after.«local».progress = .Checked actual → Issued (current_admission.Proofs.view after.work.context) actual := by
  have origin := current_admission.Proofs.dispatch_current_origin work checks pending after (.Ok stamp) returned
  have localStamp := successful_current_records_stamp (bound work checks) pending after stamp returned
  intro actual same
  have equal : stamp = actual := by simpa [localStamp] using same
  subst actual
  rw [origin.1]
  exact origin.2 stamp rfl

theorem send_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (channel next : H) (out : core.result.Result Unit X)
    (origin : ∀ stamp, pending.«local».progress = .Checked stamp → Issued (current_admission.Proofs.view pending.work.context) stamp)
    (returned : (adapter work checks).send pending channel = Result.ok (out, after, next)) : Related pending after := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at returned
  obtain ⟨⟨accepted, effects, localState⟩, gate, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have issued := checked_send_establishes_origin (fun _ => current_admission.Proofs.view pending.work.context)
    pending.effects effects pending.«local» localState pending.phase pending.write accepted origin gate
  cases accepted with
  | false =>
    obtain ⟨error, _, same⟩ := (bind_returns_iff _ _ _).mp rest
    have pair : (.Err error, {pending with effects, «local» := localState}, channel) = (out, after, next) := by simpa using same
    obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
    exact gate_related _ _ rfl (.begin_send false pending.phase pending.«local» localState pending.write gate) issued
  | true =>
    obtain ⟨⟨result, native, sent⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have frame := (current_admission.Proofs.bound_send_frame work checks pending.work native channel sent result callback).1
    have pair : (result, {pending with work := native, effects, «local» := localState}, sent) = (out, after, next) := by simpa using rest
    obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
    exact gate_related _ _ frame (.begin_send true pending.phase pending.«local» localState pending.write gate) issued


/-- Source-derived chronological gate history of the actual provider driver,
    for all returned read/write outcomes and failed submission prefixes. -/
theorem driver_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (audited : Audited)
    (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (adapter work checks) pending audited = Result.ok (report, after)) :
    Related pending after := by
  unfold provider_exchange.exchange at returned
  simp [Audited.impl.phase, Audited.is_write] at returned
  obtain ⟨⟨initial, state1⟩, planned, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have firstFrame := setup_trace work checks pending state1 initial planned
  cases initial with
  | Err error =>
    have same := returned_state (provider_exchange.Report.mk audited.phase .Setup none (.Err error)) report state1 after rest
    subst after
    exact firstFrame
  | Ok channel =>
    obtain ⟨⟨checked, second⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have secondFrame := current_trace work checks state1 second checked current
    have prior := related_trans firstFrame secondFrame
    cases checked with
    | Err error =>
      have same := returned_state (provider_exchange.Report.mk audited.phase .Admission none (.Err error)) report second after rest
      subst after
      exact prior
    | Ok stamp =>
      cases writing : audited.write with
      | false =>
        simp [writing] at rest
        obtain ⟨⟨sent, third, next⟩, sending, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have sentSteps := send_trace work checks second third channel next sent (checked_origin work checks state1 second stamp current) sending
        have prefixSteps := related_trans prior sentSteps
        cases sent with
        | Err error =>
          have same := returned_state (provider_exchange.Report.mk audited.phase .Send (some stamp) (.Err error)) report third after (by simpa using rest)
          subst after
          exact prefixSteps
        | Ok u =>
          cases u
          obtain ⟨⟨received, last⟩, receiving, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have framed := receive_trace work checks third last next received receiving
          have same : after = last := by
            cases received with
            | Err error => exact returned_state (provider_exchange.Report.mk audited.phase .Response (some stamp) (.Err error)) report last after (by simpa using rest)
            | Ok value => exact returned_state (provider_exchange.Report.mk audited.phase .Complete (some stamp) (.Ok value)) report _ _ (by simpa using rest)
          subst after
          exact related_trans prefixSteps framed
      | true =>
        simp [writing, manifest.AdmissionStamp.impl.write] at rest
        cases allowed : stamp.write with
        | false =>
          have same := fixed_state (adapter work checks).INVALID_POLICY
            (fun error => provider_exchange.Report.mk audited.phase .Admission (some stamp) (.Err error)) second after report (by simpa [allowed] using rest)
          subst after
          exact prior
        | true =>
          simp [allowed] at rest
          obtain ⟨⟨sent, third, next⟩, sending, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have sentSteps := send_trace work checks second third channel next sent (checked_origin work checks state1 second stamp current) sending
          have prefixSteps := related_trans prior sentSteps
          cases sent with
          | Err error =>
            have same := fixed_state (adapter work checks).OUTCOME_UNKNOWN (fun error => provider_exchange.Report.mk audited.phase .Send (some stamp) (.Err error)) third after report (by simpa using rest)
            subst after
            exact prefixSteps
          | Ok u =>
            cases u
            obtain ⟨⟨received, last⟩, receiving, rest⟩ := (bind_returns_iff _ _ _).mp rest
            have framed := receive_trace work checks third last next received receiving
            have same : after = last := by
              cases received with
              | Err error => exact fixed_state (adapter work checks).OUTCOME_UNKNOWN (fun error => provider_exchange.Report.mk audited.phase .Response (some stamp) (.Err error)) last after report (by simpa using rest)
              | Ok value => exact returned_state (provider_exchange.Report.mk audited.phase .Complete (some stamp) (.Ok value)) report _ _ (by simpa using rest)
            subst after
            exact related_trans prefixSteps framed


/-- Preparation and audit primitives preserve the private context; the actual
    receipt gates contribute ordered audit history on success and failure. -/
theorem audit_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (prepared : Prepared)
    (out : core.result.Result Audited X)
    (returned : dispatch.audit (bound work checks) pending prepared = Result.ok (out, after)) : Related pending after := by
  unfold dispatch.audit at returned
  obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have frame := (current_admission.Proofs.bound_prepare_frame work checks pending.work native result callback).1
  have preparedTrace : Related pending {pending with work := native} := related_frame _ _ frame rfl
  cases result with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result Audited X) out {pending with work := native} after (by simpa using rest)
    subst after
    exact preparedTrace
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have marked : Related {pending with work := native} {pending with work := native, effects := firstReceipt} :=
      gate_related _ _ rfl (.begin_dispatch_audit accepted prepared began) (begin_audit_origin _ _ _ _ _ began)
    have prior := related_trans preparedTrace marked
    cases accepted with
    | false =>
      have same := fixed_state (bound work checks).INVALID_TRANSITION (fun error => (.Err error : core.result.Result Audited X))
        {pending with work := native, effects := firstReceipt} after out (by simpa using rest)
      subst after
      exact prior
    | true =>
      simp [Prepared.impl.phase] at rest
      obtain ⟨⟨written, native2⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have auditFrame := (current_admission.Proofs.bound_audit_frame work checks native native2 prepared.phase written auditCall).1
      have auditedTrace : Related {pending with work := native, effects := firstReceipt}
          {pending with work := native2, effects := firstReceipt} := related_frame _ _ auditFrame rfl
      have prior := related_trans prior auditedTrace
      cases written with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result Audited X) out
          {pending with work := native2, effects := firstReceipt} after (by simpa using rest)
        subst after
        exact prior
      | Ok u =>
        cases u
        simp [read_transition.acknowledge] at rest
        obtain ⟨⟨accepted, last⟩, ack, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Related {pending with work := native2, effects := firstReceipt} {pending with work := native2, effects := last} :=
          gate_related _ _ rfl (.acknowledge_dispatch accepted ⟨prepared.phase, prepared.write⟩ ack)
            (acknowledge_origin _ _ _ _ _ ack)
        have same : after = {pending with work := native2, effects := last} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result Audited X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok ⟨prepared.phase, prepared.write⟩ : core.result.Result Audited X) out _ _ (by simpa using rest)
        subst after
        exact related_trans prior suffix


theorem exchange_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (audited : Audited)
    (out : core.result.Result O X)
    (returned : dispatch.exchange (bound work checks) pending audited = Result.ok (out, after)) : Related pending after := by
  unfold dispatch.exchange at returned
  simp [Audited.is_write] at returned
  obtain ⟨effectWrite, policy, rest⟩ := (bind_returns_iff _ _ _).mp returned
  split at rest
  · obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have priorSteps : Related pending {pending with effects := firstReceipt, phase := audited.phase, write := audited.write} :=
      gate_related _ _ rfl (.begin_provider accepted audited began) (begin_provider_origin _ _ _ _ _ began)
    cases accepted with
    | false =>
      have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) {pending with effects := firstReceipt} after out (by simpa using rest)
      subst after
      simpa [Related] using priorSteps
    | true =>
      simp [Audited.impl.phase] at rest
      obtain ⟨⟨report, driverState⟩, driver, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have driven := driver_trace work checks {pending with effects := firstReceipt, phase := audited.phase, write := audited.write} driverState audited report driver
      have prefixSteps := related_trans priorSteps driven
      simp [provider_exchange.Report.impl.stage, provider_exchange.Report.impl.current, provider_exchange.Report.into_result] at rest
      cases result : report.result with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {driverState with provider_stage := some report.stage, current := report.current} after (by simpa [result] using rest)
        subst after
        simpa [Related] using prefixSteps
      | Ok value =>
        simp only [result] at rest
        obtain ⟨⟨accepted, last⟩, completed, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Related driverState {driverState with effects := last} :=
          gate_related _ _ rfl (.provider_completed accepted driverState.phase completed) (completed_origin _ _ _ _ _ completed)
        have same : after = {driverState with effects := last, provider_stage := some report.stage, current := report.current} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result O X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
        subst after
        simpa [Related] using related_trans prefixSteps suffix
  · have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) pending after out rest
    subst after
    exact related_frame _ _ rfl rfl


theorem finish_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (keyed : Bool)
    (out : core.result.Result Unit X)
    (returned : dispatch.finish (bound work checks) pending keyed = Result.ok (out, after)) : Related pending after := by
  unfold dispatch.finish at returned
  obtain ⟨⟨nextState, finished⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have framed : Related pending nextState := by
    cases keyed with
    | false =>
      have pair := (Result.ok.injEq).mp finishCall
      have same : pending = nextState := congrArg Prod.fst pair
      rw [← same]
      exact related_frame _ _ rfl rfl
    | true =>
      obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp finishCall
      have same : nextState = {pending with work := native} := by
        exact (by simpa using rest : {pending with work := native} = nextState ∧ result = finished).1.symm
      subst nextState
      exact related_frame _ _ (current_admission.Proofs.bound_finish_frame work checks pending.work native result callback).1 rfl
  cases finished with
  | Err error =>
    have same := fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) nextState after out rest
    subst after
    exact framed
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have suffix : Related nextState {nextState with effects := last} :=
      gate_related _ _ rfl (.finish_dispatch accepted nextState.phase finished) (finished_origin _ _ _ _ _ finished)
    have same : after = {nextState with effects := last} := by
      cases accepted with
      | false => exact fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) _ _ _ (by simpa using rest)
      | true => exact returned_state (.Ok () : core.result.Result Unit X) out _ _ (by simpa using rest)
    subst after
    exact related_trans framed suffix


/-- All actual audit/configuration/check/reservation/provider/finish prefixes
    compose without a whole-dispatch freshness or receipt-history premise. -/
theorem run_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (pending after : Pending (current_admission.Bound W C H O X) H O X) (prepared : Prepared)
    (keyed : Bool) (out : core.result.Result O X)
    (returned : dispatch.run (bound work checks) pending prepared keyed = Result.ok (out, after)) : Related pending after := by
  unfold dispatch.run at returned
  obtain ⟨⟨audited, firstState⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have prefixSteps := audit_trace work checks pending firstState prepared audited auditCall
  cases audited with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result O X) out firstState after (by simpa using rest)
    subst after
    exact prefixSteps
  | Ok permit =>
    obtain ⟨⟨configured, native1⟩, configuredCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have configuredTrace : Related firstState {firstState with work := native1} :=
      related_frame _ _ (current_admission.Proofs.bound_configure_frame work checks firstState.work native1 keyed configured configuredCall).1 rfl
    have prefixSteps := related_trans prefixSteps configuredTrace
    cases configured with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := native1} after (by simpa using rest)
      subst after
      exact prefixSteps
    | Ok u =>
      cases u
      obtain ⟨⟨checked, work2⟩, checkCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have checkedTrace : Related {firstState with work := native1} {firstState with work := work2} :=
        related_frame _ _ (current_admission.Proofs.bound_check_frame work checks native1 work2 checked checkCall).1 rfl
      have prefixSteps := related_trans prefixSteps checkedTrace
      cases checked with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work2} after (by simpa using rest)
        subst after
        exact prefixSteps
      | Ok u =>
        cases u
        obtain ⟨⟨work3, reserved⟩, reserveCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have reserveFrame : work3.context = work2.context := by
          cases keyed with
          | false =>
            have pair : work2 = work3 ∧ (.Ok () : core.result.Result Unit X) = reserved := by simpa using reserveCall
            rw [← pair.1]
          | true =>
            obtain ⟨⟨result, native⟩, call, same⟩ := (bind_returns_iff _ _ _).mp reserveCall
            have pair : native = work3 ∧ result = reserved := by simpa using same
            rw [← pair.1]
            exact (current_admission.Proofs.bound_reserve_frame work checks work2 native result call).1
        have reservedTrace : Related {firstState with work := work2} {firstState with work := work3} :=
          related_frame _ _ reserveFrame rfl
        have prefixSteps := related_trans prefixSteps reservedTrace
        cases reserved with
        | Err error =>
          have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work3} after (by simpa using rest)
          subst after
          exact prefixSteps
        | Ok u =>
          cases u
          obtain ⟨⟨exchanged, secondState⟩, exchangeCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have prefixSteps := related_trans prefixSteps (exchange_trace work checks {firstState with work := work3} secondState permit exchanged exchangeCall)
          cases exchanged with
          | Err error =>
            have same := returned_state (.Err error : core.result.Result O X) out secondState after (by simpa using rest)
            subst after
            exact prefixSteps
          | Ok value =>
            obtain ⟨⟨finished, lastState⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
            have prefixSteps := related_trans prefixSteps (finish_trace work checks secondState lastState keyed finished finishCall)
            have same : after = lastState := by
              cases finished with
              | Err error => exact returned_state (.Err error : core.result.Result O X) out _ _ (by simpa using rest)
              | Ok u => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
            subst after
            exact prefixSteps


/-- Every returned actual owned dispatch has a chronological receipt trace
    with derived stamp origin, including invalid preparation and all errors. -/
theorem dispatch_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (primitive : current_admission.Bound W C H O X) (prepared : core.result.Result Prepared X)
    (before : RequestEffects) (keyed : Bool) (report : Report (current_admission.Bound W C H O X) H O X)
    (returned : dispatch.dispatch (bound work checks) primitive prepared before keyed = Result.ok report) :
    report.work.context = primitive.context ∧
      ∃ events, TraceSteps (fun _ => current_admission.Proofs.view primitive.context) before report.effects events := by
  cases prepared with
  | Err error =>
    have same : report = ⟨.Err error, primitive, before, ⟨.Empty⟩, none, none⟩ := by
      simpa [dispatch.dispatch, provider_exchange.SendState.new] using returned.symm
    subst report
    exact ⟨rfl, [], .refl⟩
  | Ok prepared =>
    simp [dispatch.dispatch, Prepared.impl.phase, provider_exchange.SendState.new] at returned
    obtain ⟨⟨result, after⟩, ran, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have traced := run_trace work checks ⟨primitive, before, ⟨.Empty⟩, prepared.phase, false, none, none⟩ after prepared keyed result ran
    have same : report = ⟨result, after.work, after.effects, after.«local», after.provider_stage, after.current⟩ := by simpa using rest.symm
    subst report
    exact traced

/-- The existing W4 gate-soundness invariant now follows for every returned
    owned dispatch from actual source gates and current validation. -/
theorem dispatch_sound_trace {W C H O X : Type} (work : Work W H O X) (checks : current_admission.Checks C X)
    (primitive : current_admission.Bound W C H O X) (prepared : core.result.Result Prepared X)
    (before : RequestEffects) (keyed : Bool) (report : Report (current_admission.Bound W C H O X) H O X)
    (reachable : Reachable before)
    (returned : dispatch.dispatch (bound work checks) primitive prepared before keyed = Result.ok report) :
    ∃ events, TraceSteps (fun _ => current_admission.Proofs.view primitive.context) before report.effects events ∧
      Reachable report.effects ∧ confinement.Proofs.SoundTrace events ∧
      BoundTrace (current_admission.Proofs.view primitive.context).binding events := by
  obtain ⟨_, events, traced⟩ := dispatch_trace work checks primitive prepared before keyed report returned
  obtain ⟨reached, sound⟩ := trace_steps_preserve_soundness _ _ _ events reachable traced
  exact ⟨events, traced, reached, sound, trace_steps_keep_binding _ _ (fun _ => rfl) _ _ events traced⟩

end aivm_secrets_garrett_core.dispatch.TraceRefinement
