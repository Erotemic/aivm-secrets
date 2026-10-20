import GarrettRequestEffects

open Aeneas Aeneas.Std
set_option maxHeartbeats 3000000

/-! Returning properties of the actual owned dispatch, with native primitive
semantics and report-copy correspondence retained as separate obligations. -/
namespace aivm_secrets_garrett_core.dispatch.Proofs
open request_effects request_effects.Proofs read_transition provider_exchange

private abbrev adapter {W C O X : Type} (ops : Work W C O X) :=
  Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider ops

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

private theorem steps_trans {first middle last : RequestEffects}
    (left : Steps first middle) (right : Steps middle last) : Steps first last := by
  induction right with
  | refl => exact left
  | next prior last ih => exact .next ih last

def Stable {W C O X : Type} (before after : Pending W C O X) : Prop :=
  after.phase = before.phase ∧ after.write = before.write

private theorem stable_trans {W C O X : Type} {a b c : Pending W C O X}
    (ab : Stable a b) (bc : Stable b c) : Stable a c := ⟨bc.1.trans ab.1, bc.2.trans ab.2⟩

theorem setup_frame {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (out : core.result.Result C X)
    (returned : (adapter ops).setup pending = Result.ok (out, after)) :
    after.effects = pending.effects ∧ Stable pending after := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup at returned
  obtain ⟨⟨result, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have same := returned_state result out {pending with work} after (by simpa using rest)
  subst after
  exact ⟨rfl, rfl, rfl⟩

theorem receive_frame {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (channel : C) (out : core.result.Result O X)
    (returned : (adapter ops).receive pending channel = Result.ok (out, after)) :
    after.effects = pending.effects ∧ Stable pending after := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive at returned
  obtain ⟨⟨result, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have same := returned_state result out {pending with work} after (by simpa using rest)
  subst after
  exact ⟨rfl, rfl, rfl⟩

theorem current_frame {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (out : core.result.Result manifest.AdmissionStamp X)
    (returned : (adapter ops).recheck pending = Result.ok (out, after)) :
    after.effects = pending.effects ∧ Stable pending after := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  cases accepted with
  | false =>
    have same := fixed_state ops.INVALID_TRANSITION (fun error => (.Err error : core.result.Result manifest.AdmissionStamp X))
      {pending with «local» := first} after out (by simpa using rest)
    subst after
    exact ⟨rfl, rfl, rfl⟩
  | true =>
    obtain ⟨⟨result, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    cases result with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result manifest.AdmissionStamp X) out
        {pending with work, «local» := first} after (by simpa using rest)
      subst after
      exact ⟨rfl, rfl, rfl⟩
    | Ok stamp =>
      obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have same : after = {pending with work, «local» := last} := by
        cases accepted with
        | false => exact fixed_state _ (fun error => (.Err error : core.result.Result manifest.AdmissionStamp X)) _ _ _ (by simpa using rest)
        | true => exact returned_state (.Ok stamp : core.result.Result manifest.AdmissionStamp X) out _ _ (by simpa using rest)
      subst after
      exact ⟨rfl, rfl, rfl⟩

/-- Failed/partial raw sends retain the same source-owned composite attempt. -/
theorem send_receipts {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (channel next : C) (out : core.result.Result Unit X)
    (returned : (adapter ops).send pending channel = Result.ok (out, after, next)) :
    Steps pending.effects after.effects ∧ Stable pending after := by
  dsimp only [adapter, Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at returned
  obtain ⟨⟨accepted, effects, sendState⟩, gate, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have marked : Steps pending.effects effects := .next .refl (.begin_send accepted pending.phase pending.«local» sendState pending.write gate)
  cases accepted with
  | false =>
    obtain ⟨error, constant, same⟩ := (bind_returns_iff _ _ _).mp rest
    have equal : (.Err error, {pending with effects, «local» := sendState}, channel) = (out, after, next) := by simpa using same
    obtain ⟨rfl, rfl, rfl⟩ := (by simpa using equal)
    exact ⟨marked, rfl, rfl⟩
  | true =>
    obtain ⟨⟨result, work, sentChannel⟩, callback, same⟩ := (bind_returns_iff _ _ _).mp rest
    have equal : (result, {pending with work := work, effects := effects, «local» := sendState}, sentChannel) = (out, after, next) := by simpa using same
    obtain ⟨rfl, rfl, rfl⟩ := (by simpa using equal)
    exact ⟨marked, rfl, rfl⟩

/-- All returned provider prefixes, including writing uncertainty, use the
    actual receipt transition in the source-owned writer callback. -/
theorem driver_receipts {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (audited : Audited) (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (adapter ops) pending audited = Result.ok (report, after)) :
    Steps pending.effects after.effects ∧ Stable pending after := by
  unfold provider_exchange.exchange at returned
  simp [Audited.impl.phase, Audited.is_write] at returned
  obtain ⟨⟨initial, state1⟩, planned, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have firstFrame := setup_frame ops pending state1 initial planned
  cases initial with
  | Err error =>
    have same := returned_state (provider_exchange.Report.mk audited.phase .Setup none (.Err error)) report state1 after rest
    subst after
    exact ⟨by rw [firstFrame.1]; exact .refl, firstFrame.2⟩
  | Ok channel =>
    obtain ⟨⟨checked, second⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have secondFrame := current_frame ops state1 second checked current
    have sameEffects : second.effects = pending.effects := secondFrame.1.trans firstFrame.1
    have sameBinding := stable_trans firstFrame.2 secondFrame.2
    cases checked with
    | Err error =>
      have same := returned_state (provider_exchange.Report.mk audited.phase .Admission none (.Err error)) report second after rest
      subst after
      exact ⟨by rw [sameEffects]; exact .refl, sameBinding⟩
    | Ok stamp =>
      cases writing : audited.write with
      | false =>
        simp [writing] at rest
        obtain ⟨⟨sent, third, next⟩, sending, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have sentSteps := send_receipts ops second third channel next sent sending
        have prefixSteps : Steps pending.effects third.effects := by simpa only [sameEffects] using sentSteps.1
        have binding := stable_trans sameBinding sentSteps.2
        cases sent with
        | Err error =>
          have same := returned_state (provider_exchange.Report.mk audited.phase .Send (some stamp) (.Err error)) report third after (by simpa using rest)
          subst after
          exact ⟨prefixSteps, binding⟩
        | Ok u =>
          cases u
          obtain ⟨⟨received, last⟩, receiving, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have framed := receive_frame ops third last next received receiving
          have same : after = last := by
            cases received with
            | Err error => exact returned_state (provider_exchange.Report.mk audited.phase .Response (some stamp) (.Err error)) report last after (by simpa using rest)
            | Ok value => exact returned_state (provider_exchange.Report.mk audited.phase .Complete (some stamp) (.Ok value)) report _ _ (by simpa using rest)
          subst after
          exact ⟨by simpa only [framed.1] using prefixSteps, stable_trans binding framed.2⟩
      | true =>
        simp [writing, manifest.AdmissionStamp.impl.write] at rest
        cases allowed : stamp.write with
        | false =>
          have same := fixed_state (adapter ops).INVALID_POLICY
            (fun error => provider_exchange.Report.mk audited.phase .Admission (some stamp) (.Err error)) second after report (by simpa [allowed] using rest)
          subst after
          exact ⟨by rw [sameEffects]; exact .refl, sameBinding⟩
        | true =>
          simp [allowed] at rest
          obtain ⟨⟨sent, third, next⟩, sending, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have sentSteps := send_receipts ops second third channel next sent sending
          have prefixSteps : Steps pending.effects third.effects := by simpa only [sameEffects] using sentSteps.1
          have binding := stable_trans sameBinding sentSteps.2
          cases sent with
          | Err error =>
            have same := fixed_state (adapter ops).OUTCOME_UNKNOWN (fun error => provider_exchange.Report.mk audited.phase .Send (some stamp) (.Err error)) third after report (by simpa using rest)
            subst after
            exact ⟨prefixSteps, binding⟩
          | Ok u =>
            cases u
            obtain ⟨⟨received, last⟩, receiving, rest⟩ := (bind_returns_iff _ _ _).mp rest
            have framed := receive_frame ops third last next received receiving
            have same : after = last := by
              cases received with
              | Err error => exact fixed_state (adapter ops).OUTCOME_UNKNOWN (fun error => provider_exchange.Report.mk audited.phase .Response (some stamp) (.Err error)) last after report (by simpa using rest)
              | Ok value => exact returned_state (provider_exchange.Report.mk audited.phase .Complete (some stamp) (.Ok value)) report _ _ (by simpa using rest)
            subst after
            exact ⟨by simpa only [framed.1] using prefixSteps, stable_trans binding framed.2⟩

/-- Every audit error retains the attempt; acknowledgment follows the actual
    primitive success, rather than a caller-supplied Boolean. -/
theorem audit_receipts {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (prepared : Prepared) (out : core.result.Result Audited X)
    (returned : dispatch.audit ops pending prepared = Result.ok (out, after)) :
    Steps pending.effects after.effects := by
  unfold dispatch.audit at returned
  obtain ⟨⟨result, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  cases result with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result Audited X) out {pending with work} after (by simpa using rest)
    subst after
    exact .refl
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have priorSteps : Steps pending.effects firstReceipt := .next .refl (.begin_dispatch_audit accepted prepared began)
    cases accepted with
    | false =>
      have same := fixed_state ops.INVALID_TRANSITION (fun error => (.Err error : core.result.Result Audited X))
        {pending with work, effects := firstReceipt} after out (by simpa using rest)
      subst after
      exact priorSteps
    | true =>
      simp [Prepared.impl.phase] at rest
      obtain ⟨⟨written, work2⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases written with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result Audited X) out
          {pending with work := work2, effects := firstReceipt} after (by simpa using rest)
        subst after
        exact priorSteps
      | Ok u =>
        cases u
        simp [read_transition.acknowledge] at rest
        obtain ⟨⟨accepted, last⟩, ack, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Steps pending.effects last := .next priorSteps (.acknowledge_dispatch accepted ⟨prepared.phase, prepared.write⟩ ack)
        have same : after = {pending with work := work2, effects := last} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result Audited X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok ⟨prepared.phase, prepared.write⟩ : core.result.Result Audited X) out _ _ (by simpa using rest)
        subst after
        exact suffix

theorem exchange_receipts {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (audited : Audited) (out : core.result.Result O X)
    (returned : dispatch.exchange ops pending audited = Result.ok (out, after)) :
    Steps pending.effects after.effects := by
  unfold dispatch.exchange at returned
  simp [Audited.is_write] at returned
  obtain ⟨effectWrite, policy, rest⟩ := (bind_returns_iff _ _ _).mp returned
  split at rest
  · obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have priorSteps : Steps pending.effects firstReceipt := .next .refl (.begin_provider accepted audited began)
    cases accepted with
    | false =>
      have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) {pending with effects := firstReceipt} after out (by simpa using rest)
      subst after
      exact priorSteps
    | true =>
      simp [Audited.impl.phase] at rest
      obtain ⟨⟨report, driverState⟩, driver, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have driven := driver_receipts ops {pending with effects := firstReceipt, phase := audited.phase, write := audited.write} driverState audited report driver
      have prefixSteps := steps_trans priorSteps driven.1
      simp [provider_exchange.Report.impl.stage, provider_exchange.Report.impl.current, provider_exchange.Report.into_result] at rest
      cases result : report.result with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {driverState with provider_stage := some report.stage, current := report.current} after (by simpa [result] using rest)
        subst after
        exact prefixSteps
      | Ok value =>
        simp only [result] at rest
        obtain ⟨⟨accepted, last⟩, completed, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Steps pending.effects last := .next prefixSteps (.provider_completed accepted driverState.phase completed)
        have same : after = {driverState with effects := last, provider_stage := some report.stage, current := report.current} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result O X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
        subst after
        exact suffix
  · have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) pending after out rest
    subst after
    exact .refl

theorem finish_receipts {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (keyed : Bool) (out : core.result.Result Unit X)
    (returned : dispatch.finish ops pending keyed = Result.ok (out, after)) :
    Steps pending.effects after.effects := by
  unfold dispatch.finish at returned
  obtain ⟨⟨nextState, finished⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have framed : nextState.effects = pending.effects := by
    cases keyed with
    | false =>
      have pair := (Result.ok.injEq).mp finishCall
      have same : pending = nextState := congrArg Prod.fst pair
      rw [← same]
    | true =>
      obtain ⟨⟨result, work⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp finishCall
      have same : nextState = {pending with work} := by
        exact (by simpa using rest : {pending with work} = nextState ∧ result = finished).1.symm
      subst nextState
      rfl
  cases finished with
  | Err error =>
    have same := fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) nextState after out rest
    subst after
    rw [framed]
    exact .refl
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have suffix : Steps pending.effects last := by
      rw [← framed]
      exact .next .refl (.finish_dispatch accepted nextState.phase finished)
    have same : after = {nextState with effects := last} := by
      cases accepted with
      | false => exact fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) _ _ _ (by simpa using rest)
      | true => exact returned_state (.Ok () : core.result.Result Unit X) out _ _ (by simpa using rest)
    subst after
    exact suffix

theorem run_receipts {W C O X : Type} (ops : Work W C O X)
    (pending after : Pending W C O X) (prepared : Prepared) (keyed : Bool) (out : core.result.Result O X)
    (returned : dispatch.run ops pending prepared keyed = Result.ok (out, after)) :
    Steps pending.effects after.effects := by
  unfold dispatch.run at returned
  obtain ⟨⟨audited, firstState⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have prefixSteps := audit_receipts ops pending firstState prepared audited auditCall
  cases audited with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result O X) out firstState after (by simpa using rest)
    subst after
    exact prefixSteps
  | Ok permit =>
    obtain ⟨⟨configured, work⟩, configuredCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
    cases configured with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result O X) out {firstState with work} after (by simpa using rest)
      subst after
      exact prefixSteps
    | Ok u =>
      cases u
      obtain ⟨⟨checked, work2⟩, checkCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases checked with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work2} after (by simpa using rest)
        subst after
        exact prefixSteps
      | Ok u =>
        cases u
        obtain ⟨⟨work3, reserved⟩, reserveCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
        cases reserved with
        | Err error =>
          have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work3} after (by simpa using rest)
          subst after
          exact prefixSteps
        | Ok u =>
          cases u
          obtain ⟨⟨exchanged, secondState⟩, exchangeCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have prefixSteps := steps_trans prefixSteps (exchange_receipts ops {firstState with work := work3} secondState permit exchanged exchangeCall)
          cases exchanged with
          | Err error =>
            have same := returned_state (.Err error : core.result.Result O X) out secondState after (by simpa using rest)
            subst after
            exact prefixSteps
          | Ok value =>
            obtain ⟨⟨finished, lastState⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
            have prefixSteps := steps_trans prefixSteps (finish_receipts ops secondState lastState keyed finished finishCall)
            have same : after = lastState := by
              cases finished with
              | Err error => exact returned_state (.Err error : core.result.Result O X) out _ _ (by simpa using rest)
              | Ok u => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
            subst after
            exact prefixSteps

/-- All returned dispatches retain source-derived receipt transitions; this
    includes invalid preparation and every primitive failure prefix. -/
theorem dispatch_receipts {W C O X : Type} (ops : Work W C O X)
    (work : W) (prepared : core.result.Result Prepared X) (before : RequestEffects) (keyed : Bool)
    (report : Report W C O X)
    (returned : dispatch.dispatch ops work prepared before keyed = Result.ok report) :
    Steps before report.effects := by
  cases prepared with
  | Err error =>
    have same : report = ⟨.Err error, work, before, ⟨.Empty⟩, none, none⟩ := by
      simpa [dispatch.dispatch, provider_exchange.SendState.new] using returned.symm
    subst report
    exact .refl
  | Ok prepared =>
    simp [dispatch.dispatch, Prepared.impl.phase, provider_exchange.SendState.new] at returned
    obtain ⟨⟨result, after⟩, ran, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have receipts := run_receipts ops ⟨work, before, ⟨.Empty⟩, prepared.phase, false, none, none⟩ after prepared keyed result ran
    have same : report = ⟨result, after.work, after.effects, after.«local», after.provider_stage, after.current⟩ := by simpa using rest.symm
    subst report
    exact receipts

/-- Audit denial cannot manufacture an acknowledgment or start provider I/O. -/
theorem audit_refusal_prefix {W C O X : Type} (ops : Work W C O X)
    (pending : Pending W C O X) (prepared : Prepared) (first : RequestEffects) (work1 work2 : W) (error : X)
    (prepareCall : ops.prepare pending.work = Result.ok (.Ok (), work1))
    (began : RequestEffects.begin_dispatch_audit pending.effects prepared = Result.ok (true, first))
    (refused : ops.audit work1 prepared.phase = Result.ok (.Err error, work2)) :
    dispatch.audit ops pending prepared = Result.ok (.Err error, {pending with work := work2, effects := first}) := by
  simp [dispatch.audit, prepareCall, began, Prepared.impl.phase, refused]

theorem audit_success_prefix {W C O X : Type} (ops : Work W C O X)
    (pending : Pending W C O X) (prepared : Prepared) (first last : RequestEffects) (work1 work2 : W)
    (prepareCall : ops.prepare pending.work = Result.ok (.Ok (), work1))
    (began : RequestEffects.begin_dispatch_audit pending.effects prepared = Result.ok (true, first))
    (written : ops.audit work1 prepared.phase = Result.ok (.Ok (), work2))
    (acked : RequestEffects.acknowledge_dispatch first ⟨prepared.phase, prepared.write⟩ = Result.ok (true, last)) :
    dispatch.audit ops pending prepared = Result.ok (.Ok ⟨prepared.phase, prepared.write⟩, {pending with work := work2, effects := last}) := by
  simp [dispatch.audit, prepareCall, began, Prepared.impl.phase, written, read_transition.acknowledge, acked]

/-- Both local and request-wide attempt state precede the raw send callback;
    even partial/error returns retain the callback's actual post-state. -/
theorem send_primitive_prefix {W C O X : Type} (ops : Work W C O X)
    (pending : Pending W C O X) (channel next : C) (first : RequestEffects) (localState : SendState)
    (work : W) (out : core.result.Result Unit X)
    (gate : RequestEffects.begin_send pending.effects pending.phase pending.«local» pending.write = Result.ok (true, first, localState))
    (sent : ops.provider_exchangeProviderInst.send pending.work channel = Result.ok (out, work, next)) :
    (adapter ops).send pending channel = Result.ok (out, {pending with work, effects := first, «local» := localState}, next) := by
  simp [Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send, gate, sent]

theorem send_gate_refusal {W C O X : Type} (ops : Work W C O X)
    (pending : Pending W C O X) (channel : C) (first : RequestEffects) (localState : SendState) (error : X)
    (gate : RequestEffects.begin_send pending.effects pending.phase pending.«local» pending.write = Result.ok (false, first, localState))
    (invalid : ops.INVALID_TRANSITION = Result.ok error) :
    (adapter ops).send pending channel = Result.ok (.Err error, {pending with effects := first, «local» := localState}, channel) := by
  simp [Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send, gate, invalid]

theorem coordinator_finish_refusal {W C O X : Type} (ops : Work W C O X)
    (pending : Pending W C O X) (work : W) (error unknown : X)
    (refused : ops.finish pending.work = Result.ok (.Err error, work))
    (uncertain : ops.provider_exchangeProviderInst.OUTCOME_UNKNOWN = Result.ok unknown) :
    dispatch.finish ops pending true = Result.ok (.Err unknown, {pending with work}) := by
  simp [dispatch.finish, refused, uncertain]

theorem rejected_preparation_no_primitive {W C O X : Type} (ops : Work W C O X)
    (work : W) (before : RequestEffects) (keyed : Bool) (error : X) :
    dispatch.dispatch ops work (.Err error) before keyed =
      Result.ok ⟨.Err error, work, before, ⟨.Empty⟩, none, none⟩ := by
  simp [dispatch.dispatch, provider_exchange.SendState.new]

theorem dispatch_preserves_reachability {W C O X : Type} (ops : Work W C O X)
    (work : W) (prepared : core.result.Result Prepared X) (before : RequestEffects) (keyed : Bool)
    (report : Report W C O X) (reachable : Reachable before)
    (returned : dispatch.dispatch ops work prepared before keyed = Result.ok report) :
    Reachable report.effects := by
  obtain ⟨initial, created, prior⟩ := reachable
  exact ⟨initial, created, steps_trans prior (dispatch_receipts ops work prepared before keyed report returned)⟩

/-- Exact returned work, receipt, local attempt, stage and stamp, including
    failures; no error path substitutes an earlier snapshot. -/
theorem returned_report_iff {W C O X : Type} (ops : Work W C O X)
    (work : W) (prepared : Prepared) (before : RequestEffects) (keyed : Bool) (report : Report W C O X) :
    dispatch.dispatch ops work (.Ok prepared) before keyed = Result.ok report ↔
      ∃ after, dispatch.run ops ⟨work, before, ⟨.Empty⟩, prepared.phase, false, none, none⟩ prepared keyed = Result.ok (report.outcome, after) ∧
        report.work = after.work ∧ report.effects = after.effects ∧ report.«local» = after.«local» ∧
          report.provider_stage = after.provider_stage ∧ report.current = after.current := by
  constructor
  · intro returned
    simp [dispatch.dispatch, Prepared.impl.phase, provider_exchange.SendState.new] at returned
    obtain ⟨⟨out, after⟩, ran, same⟩ := (bind_returns_iff _ _ _).mp returned
    have equal : report = ⟨out, after.work, after.effects, after.«local», after.provider_stage, after.current⟩ := by simpa using same.symm
    subst report
    exact ⟨after, ran, rfl, rfl, rfl, rfl, rfl⟩
  · rintro ⟨after, ran, workEq, effectsEq, localEq, stageEq, stampEq⟩
    cases report
    simp_all [dispatch.dispatch, Prepared.impl.phase, provider_exchange.SendState.new]

private def positiveOps (stamp : manifest.AdmissionStamp) : Work Unit Unit Unit Unit := {
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

/-- A useful extracted read succeeds in either dispatch phase. This kernel
    witness complements, rather than replaces, the native HTTPS witnesses. -/
theorem dispatch_positive_witness (stamp : manifest.AdmissionStamp) (phase : Phase) :
    ∃ initial report,
      RequestEffects.new = Result.ok initial ∧
      dispatch.dispatch (positiveOps stamp) () (.Ok ⟨phase, false⟩) initial false = Result.ok report ∧
        report.outcome = .Ok () ∧ report.provider_stage = some .Complete := by
  let emptyDispatch : DispatchRecord := ⟨false, false, false, none, false, false, false⟩
  let completedDispatch : DispatchRecord := ⟨true, true, true, some stamp, true, true, true⟩
  let emptyCompletion : CompletionRecord := ⟨false, false, false, false, false, false⟩
  let initial : RequestEffects := ⟨emptyDispatch, emptyDispatch, emptyCompletion, .Entry⟩
  let finished : RequestEffects := match phase with
    | .Preflight => ⟨completedDispatch, emptyDispatch, emptyCompletion, .DispatchReturned phase⟩
    | .Final => ⟨emptyDispatch, completedDispatch, emptyCompletion, .DispatchReturned phase⟩
  refine ⟨initial, ⟨.Ok (), (), finished, ⟨.Attempted stamp⟩, some .Complete, some stamp⟩, ?_, ?_, rfl, rfl⟩
  · simp [RequestEffects.new, DispatchRecord.empty, CompletionRecord.empty, initial, emptyDispatch, emptyCompletion]
  · cases phase <;> simp [dispatch.dispatch, dispatch.run, dispatch.audit, dispatch.exchange, dispatch.finish,
      provider_exchange.exchange, provider_exchange.Report.impl.stage, provider_exchange.Report.impl.current,
      provider_exchange.Report.into_result, provider_exchange.SendState.new,
      Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup,
      Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck,
      Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send,
      Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive,
      positiveOps, Prepared.impl.phase, Audited.impl.phase, Audited.is_write, read_transition.acknowledge,
      RequestEffects.begin_dispatch_audit, RequestEffects.acknowledge_dispatch,
      RequestEffects.begin_provider, RequestEffects.begin_send, RequestEffects.provider_completed,
      RequestEffects.finish_dispatch, RequestEffects.phase, RequestEffects.set_phase,
      SendState.begin_check, SendState.finish_check, SendState.begin_send, SendState.stamp,
      Phase.Insts.CoreCmpPartialEqPhase.eq, Phase.read_discriminant,
      initial, finished, emptyDispatch, emptyCompletion, completedDispatch]

theorem fresh_refusal_prefix {W C O X : Type} (ops : Work W C O X)
    (pending auditedState : Pending W C O X) (prepared : Prepared) (permit : Audited) (keyed : Bool)
    (configured checked : W) (error : X)
    (auditCall : dispatch.audit ops pending prepared = Result.ok (.Ok permit, auditedState))
    (configureCall : ops.configure auditedState.work keyed = Result.ok (.Ok (), configured))
    (refused : ops.check configured = Result.ok (.Err error, checked)) :
    dispatch.run ops pending prepared keyed = Result.ok (.Err error, {auditedState with work := checked}) := by
  simp [dispatch.run, auditCall, configureCall, refused]

theorem reservation_refusal_prefix {W C O X : Type} (ops : Work W C O X)
    (pending auditedState : Pending W C O X) (prepared : Prepared) (permit : Audited)
    (configured checked reserved : W) (error : X)
    (auditCall : dispatch.audit ops pending prepared = Result.ok (.Ok permit, auditedState))
    (configureCall : ops.configure auditedState.work true = Result.ok (.Ok (), configured))
    (checkCall : ops.check configured = Result.ok (.Ok (), checked))
    (refused : ops.reserve checked = Result.ok (.Err error, reserved)) :
    dispatch.run ops pending prepared true = Result.ok (.Err error, {auditedState with work := reserved}) := by
  simp [dispatch.run, auditCall, configureCall, checkCall, refused]

end aivm_secrets_garrett_core.dispatch.Proofs
