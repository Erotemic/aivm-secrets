import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std

/-!
NR-1: preservation for the actual extracted, production-called dispatch seam.
The native adapter constructs Prepared with prepare, then calls acknowledge
only after Audit::write_record succeeds. These theorems establish the decisions
and invariant carried by that path, not audit durability or provider I/O.
In particular arbitrary Lean structures are not assumed to be reachable Rust
permits: preservation starts with the result of prepare.
-/

namespace aivm_secrets_garrett_core.read_transition.Proofs

/-- The selected effect may write only in the final phase of an admitted
write operation. Read effects remain valid in either phase. -/
def Admitted (phase : Phase) (operationWrite effectWrite : Bool) : Prop :=
  effectWrite = true → phase = .Final ∧ operationWrite = true

theorem prepare_success_iff (phase : Phase) (operationWrite effectWrite : Bool)
    (prepared : Prepared) :
    prepare phase operationWrite effectWrite = Result.ok (.Ok prepared) ↔
      prepared.phase = phase ∧ prepared.write = effectWrite ∧
        Admitted phase operationWrite effectWrite := by
  cases phase <;> cases operationWrite <;> cases effectWrite <;>
    cases prepared <;> simp [prepare, Admitted, Result.ok.injEq,
      core.result.Result.Ok.injEq, Prepared.mk.injEq, and_comm, eq_comm]

theorem acknowledge_success_iff (prepared : Prepared) (ack : Bool)
    (audited : Audited) :
    acknowledge prepared ack = Result.ok (.Ok audited) ↔
      ack = true ∧ audited.phase = prepared.phase ∧
        audited.write = prepared.write := by
  cases ack <;> cases prepared <;> cases audited <;>
    simp [acknowledge, Result.ok.injEq, core.result.Result.Ok.injEq,
      Audited.mk.injEq, eq_comm]

/-- The first preservation lemma: successful preparation followed by audit
acknowledgment preserves phase/write authority and proves acknowledgment.
It does not treat acknowledgment as a proof of the filesystem contract. -/
theorem prepared_to_audited_preservation
    (phase : Phase) (operationWrite effectWrite ack : Bool)
    (prepared : Prepared) (audited : Audited)
    (hp : prepare phase operationWrite effectWrite = Result.ok (.Ok prepared))
    (ha : acknowledge prepared ack = Result.ok (.Ok audited)) :
    audited.phase = phase ∧ audited.write = effectWrite ∧
      Admitted audited.phase operationWrite audited.write ∧ ack = true := by
  obtain ⟨phaseP, writeP, admitted⟩ :=
    (prepare_success_iff phase operationWrite effectWrite prepared).mp hp
  obtain ⟨acknowledged, phaseA, writeA⟩ :=
    (acknowledge_success_iff prepared ack audited).mp ha
  have phaseEq := phaseA.trans phaseP
  have writeEq := writeA.trans writeP
  exact ⟨phaseEq, writeEq, by simpa [phaseEq, writeEq] using admitted, acknowledged⟩

theorem refused_audit_has_no_permit (prepared : Prepared) :
    acknowledge prepared false = Result.ok (.Err Denial.InvalidCapability) := by
  simp [acknowledge]

theorem preflight_write_has_no_prepared (operationWrite : Bool) :
    prepare .Preflight operationWrite true =
      Result.ok (.Err Denial.InvalidCapability) := by
  simp [prepare]

theorem unadmitted_final_write_has_no_prepared :
    prepare .Final false true = Result.ok (.Err Denial.InvalidCapability) := by
  simp [prepare]

/-- Non-vacuity of the extracted decisions for either native read phase. -/
theorem authorized_read_witness (phase : Phase) (operationWrite : Bool) :
    prepare phase operationWrite false =
      Result.ok (.Ok (Prepared.mk phase false)) ∧
    acknowledge (Prepared.mk phase false) true =
      Result.ok (.Ok (Audited.mk phase false)) := by
  simp [prepare, acknowledge]

theorem denied_before_completion {P O E : Type} (ops : Completion P O E)
    (pending : P) (error : E)
    (denied : ops.recheck pending .BeforeAudit = Result.ok (.Err error)) :
    complete_current ops pending = Result.ok (.Err error) := by
  simp [complete_current, denied]

theorem completion_audit_refusal {P O E : Type} (ops : Completion P O E)
    (pending : P) (error : E)
    (current : ops.recheck pending .BeforeAudit = Result.ok (.Ok ()))
    (refused : ops.audit pending = Result.ok (.Err error)) :
    complete_current ops pending = Result.ok (.Err error) := by
  simp [complete_current, current, refused]

/-- An audit acknowledged after authority was lost does not authorize release.
The two checkpoints are separate inputs in the extracted adapter interface. -/
theorem revoked_after_completion_audit {P O E : Type} (ops : Completion P O E)
    (pending : P) (error : E)
    (before : ops.recheck pending .BeforeAudit = Result.ok (.Ok ()))
    (ack : ops.audit pending = Result.ok (.Ok ()))
    (afterAudit : ops.recheck pending .BeforeRelease = Result.ok (.Err error)) :
    complete_current ops pending = Result.ok (.Err error) := by
  simp [complete_current, before, ack, afterAudit]

/-- Retain the release adapter's failures and divergence, as well as success.
The controller adds neither a cached authorization nor an automatic retry. -/
theorem current_completion_continuation {P O E : Type} (ops : Completion P O E)
    (pending : P)
    (before : ops.recheck pending .BeforeAudit = Result.ok (.Ok ()))
    (ack : ops.audit pending = Result.ok (.Ok ()))
    (afterAudit : ops.recheck pending .BeforeRelease = Result.ok (.Ok ())) :
    complete_current ops pending = ops.release pending := by
  simp [complete_current, before, ack, afterAudit]

/-- Conditional preservation through the production completion controller.
Adapters justify the individual sampled facts; the controller proves their
conjunction on success. No contract is assumed for unused continuations.
CurrentAfter holds at the last check, not throughout subsequent TLS writes. -/
theorem completion_preservation {P O E : Type} (ops : Completion P O E)
    (pending : P) (CurrentBefore Audited CurrentAfter : Prop) (Released : O → Prop)
    (before : ops.recheck pending .BeforeAudit ⦃ out => out = .Ok () → CurrentBefore ⦄)
    (audit : CurrentBefore → ops.audit pending ⦃ out => out = .Ok () → Audited ⦄)
    (afterAudit : CurrentBefore → Audited →
      ops.recheck pending .BeforeRelease ⦃ out => out = .Ok () → CurrentAfter ⦄)
    (release : CurrentBefore → Audited → CurrentAfter → ops.release pending
      ⦃ out => ∀ value, out = .Ok value → Released value ⦄) :
    complete_current ops pending ⦃ out => ∀ value, out = .Ok value →
      CurrentBefore ∧ Audited ∧ CurrentAfter ∧ Released value ⦄ := by
  unfold complete_current
  apply WP.spec_bind before
  intro first hfirst
  cases first with
  | Err error => simp
  | Ok u =>
    cases u
    have currentBefore := hfirst rfl
    apply WP.spec_bind (audit currentBefore)
    intro acknowledged hack
    cases acknowledged with
    | Err error => simp
    | Ok u =>
      cases u
      have audited := hack rfl
      apply WP.spec_bind (afterAudit currentBefore audited)
      intro last hlast
      cases last with
      | Err error => simp
      | Ok u =>
        cases u
        have currentAfter := hlast rfl
        apply WP.spec_mono (release currentBefore audited currentAfter)
        intro out released value success
        exact ⟨currentBefore, audited, currentAfter, released value success⟩

theorem authorized_completion_witness {P O E : Type} (ops : Completion P O E)
    (pending : P) (value : O)
    (before : ops.recheck pending .BeforeAudit = Result.ok (.Ok ()))
    (ack : ops.audit pending = Result.ok (.Ok ()))
    (afterAudit : ops.recheck pending .BeforeRelease = Result.ok (.Ok ()))
    (released : ops.release pending = Result.ok (.Ok value)) :
    complete_current ops pending = Result.ok (.Ok value) := by
  rw [current_completion_continuation ops pending before ack afterAudit, released]

/-- A successful extracted computation has a returned input and successful
continuation. This inversion does not require termination of unused adapters. -/
private theorem bind_returns_iff {A B : Type} (first : Result A)
    (next : A → Result B) (result : B) :
    (first >>= next) = Result.ok result ↔
      ∃ value, first = Result.ok value ∧ next value = Result.ok result := by
  cases first using Result.cases with
  | ret value => simp
  | vis effect continuation => simp
  | div => simp

/-- The request's facts are exactly its empty baseline or the actual returned
preflight value. This is a specification of origin, not a second interpreter. -/
def FactsFrom {P F E O X : Type} (ops : Request P F E O X) (pending : P)
    (facts : F) : Prop :=
  (ops.preflight pending = Result.ok (.Ok none) ∧
    ops.empty_facts pending = Result.ok facts) ∨
  ∃ effect, ops.preflight pending = Result.ok (.Ok (some effect)) ∧
    ops.dispatch pending .Preflight effect = Result.ok (.Ok facts)

theorem request_facts_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (facts : F) :
    request_facts ops pending = Result.ok (.Ok facts) ↔ FactsFrom ops pending facts := by
  cases h : ops.preflight pending using Result.cases with
  | ret planned =>
    cases planned with
    | Err error => simp [request_facts, h, FactsFrom]
    | Ok effect =>
      cases effect with
      | none =>
        cases empty : ops.empty_facts pending using Result.cases <;>
          simp [request_facts, h, FactsFrom, empty]
      | some effect => simp [request_facts, h, FactsFrom]
  | vis effect continuation => simp [request_facts, h, FactsFrom]
  | div => simp [request_facts, h, FactsFrom]

/-- The exact input to completion is either the checked facts for a no-final
operation or the successful final provider return. No unrelated value qualifies. -/
def RawFrom {P F E O X : Type} (ops : Request P F E O X) (pending : P)
    (facts raw : F) : Prop :=
  (ops.final_effect pending facts = Result.ok (.Ok none) ∧ raw = facts) ∨
  ∃ effect write, ops.final_effect pending facts = Result.ok (.Ok (some effect)) ∧
    ops.effect_write pending effect = Result.ok write ∧
    ops.dispatch pending .Final effect = Result.ok (.Ok raw)

def FinishSuccess {P F E O X : Type} (ops : Request P F E O X) (pending : P)
    (facts : F) (reply : O) : Prop :=
  ops.recheck pending = Result.ok (.Ok ()) ∧
    ∃ raw, RawFrom ops pending facts raw ∧
      ops.complete pending raw = Result.ok (.Ok reply)

theorem finish_request_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (facts : F) (reply : O) :
    finish_request ops pending facts = Result.ok (.Ok reply) ↔
      FinishSuccess ops pending facts reply := by
  constructor
  · intro success
    unfold finish_request at success
    obtain ⟨planned, compiled, rest⟩ := (bind_returns_iff _ _ _).mp success
    cases planned with
    | Err error => simp at rest
    | Ok selected =>
      obtain ⟨checked, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases checked with
      | Err error => simp at rest
      | Ok u =>
        cases u
        cases selected with
        | none =>
          exact ⟨current, facts, Or.inl ⟨compiled, rfl⟩, rest⟩
        | some effect =>
          obtain ⟨write, classified, rest⟩ := (bind_returns_iff _ _ _).mp rest
          obtain ⟨provider, dispatched, rest⟩ := (bind_returns_iff _ _ _).mp rest
          cases provider with
          | Err error => simp at rest
          | Ok raw =>
            have completed : ops.complete pending raw = Result.ok (.Ok reply) := by
              cases write with
              | false => simpa using rest
              | true =>
                obtain ⟨out, completion, rest⟩ := (bind_returns_iff _ _ _).mp rest
                cases out with
                | Ok value =>
                  have equal : value = reply := by simpa using rest
                  simpa [equal] using completion
                | Err error =>
                  obtain ⟨unknown, _, impossible⟩ := (bind_returns_iff _ _ _).mp rest
                  simp at impossible
            exact ⟨current, raw, Or.inr ⟨effect, write, compiled, classified, dispatched⟩,
              completed⟩
  · rintro ⟨current, raw, origin, completed⟩
    rcases origin with ⟨compiled, rfl⟩ | ⟨effect, write, compiled, classified, dispatched⟩
    · simp [finish_request, compiled, current, completed]
    · cases write <;> simp [finish_request, compiled, current, classified, dispatched, completed]

/-- Complete successful-request characterization of the extracted runtime
kernel. Current authority and completion are actual callback outcomes; the
meaning of those adapter facts and their concrete I/O remain separate contracts. -/
theorem request_current_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (reply : O) :
    request_current ops pending = Result.ok (.Ok reply) ↔
      ∃ facts, FactsFrom ops pending facts ∧ FinishSuccess ops pending facts reply := by
  constructor
  · intro success
    unfold request_current at success
    obtain ⟨out, produced, rest⟩ := (bind_returns_iff _ _ _).mp success
    cases out with
    | Err error => simp at rest
    | Ok facts =>
      exact ⟨facts, (request_facts_success_iff ops pending facts).mp produced,
        (finish_request_success_iff ops pending facts reply).mp rest⟩
  · rintro ⟨facts, produced, finished⟩
    simp [request_current, (request_facts_success_iff ops pending facts).mpr produced,
      (finish_request_success_iff ops pending facts reply).mpr finished]

theorem failed_preflight_compilation_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (error : X)
    (failed : ops.preflight pending = Result.ok (.Err error)) :
    request_current ops pending = Result.ok (.Err error) := by
  simp [request_current, request_facts, failed]

theorem failed_preflight_provider_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (effect : E) (error : X)
    (planned : ops.preflight pending = Result.ok (.Ok (some effect)))
    (failed : ops.dispatch pending .Preflight effect = Result.ok (.Err error)) :
    request_current ops pending = Result.ok (.Err error) := by
  simp [request_current, request_facts, planned, failed]

theorem failed_final_compilation_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (facts : F) (error : X)
    (produced : FactsFrom ops pending facts)
    (failed : ops.final_effect pending facts = Result.ok (.Err error)) :
    request_current ops pending = Result.ok (.Err error) := by
  simp [request_current, (request_facts_success_iff ops pending facts).mpr produced,
    finish_request, failed]

theorem stale_after_preflight_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (facts : F) (selected : Option E) (error : X)
    (produced : FactsFrom ops pending facts)
    (compiled : ops.final_effect pending facts = Result.ok (.Ok selected))
    (denied : ops.recheck pending = Result.ok (.Err error)) :
    request_current ops pending = Result.ok (.Err error) := by
  simp [request_current, (request_facts_success_iff ops pending facts).mpr produced,
    finish_request, compiled, denied]

theorem final_provider_failure_stops_completion {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (facts : F) (effect : E)
    (write : Bool) (error : X)
    (produced : FactsFrom ops pending facts)
    (compiled : ops.final_effect pending facts = Result.ok (.Ok (some effect)))
    (current : ops.recheck pending = Result.ok (.Ok ()))
    (classified : ops.effect_write pending effect = Result.ok write)
    (failed : ops.dispatch pending .Final effect = Result.ok (.Err error)) :
    request_current ops pending = Result.ok (.Err error) := by
  simp [request_current, (request_facts_success_iff ops pending facts).mpr produced,
    finish_request, compiled, current, classified, failed]

/-- Keep failures and divergence of disclosure/completion for read operations;
no successful-provider assumption can erase them from the controller contract. -/
theorem final_read_continuation {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (facts raw : F) (effect : E)
    (produced : FactsFrom ops pending facts)
    (compiled : ops.final_effect pending facts = Result.ok (.Ok (some effect)))
    (current : ops.recheck pending = Result.ok (.Ok ()))
    (classified : ops.effect_write pending effect = Result.ok false)
    (dispatched : ops.dispatch pending .Final effect = Result.ok (.Ok raw)) :
    request_current ops pending = ops.complete pending raw := by
  simp [request_current, (request_facts_success_iff ops pending facts).mpr produced,
    finish_request, compiled, current, classified, dispatched]

theorem checked_only_continuation {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (facts : F)
    (produced : FactsFrom ops pending facts)
    (compiled : ops.final_effect pending facts = Result.ok (.Ok none))
    (current : ops.recheck pending = Result.ok (.Ok ())) :
    request_current ops pending = ops.complete pending facts := by
  simp [request_current, (request_facts_success_iff ops pending facts).mpr produced,
    finish_request, compiled, current]

theorem sent_write_completion_failure_is_uncertain {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (facts raw : F) (effect : E)
    (error unknown : X)
    (produced : FactsFrom ops pending facts)
    (compiled : ops.final_effect pending facts = Result.ok (.Ok (some effect)))
    (current : ops.recheck pending = Result.ok (.Ok ()))
    (classified : ops.effect_write pending effect = Result.ok true)
    (dispatched : ops.dispatch pending .Final effect = Result.ok (.Ok raw))
    (failed : ops.complete pending raw = Result.ok (.Err error))
    (code : ops.outcome_unknown pending = Result.ok unknown) :
    request_current ops pending = Result.ok (.Err unknown) := by
  simp [request_current, (request_facts_success_iff ops pending facts).mpr produced,
    finish_request, compiled, current, classified, dispatched, failed, code]

theorem two_phase_read_successful_witness {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (preflight final : E) (facts raw : F)
    (reply : O)
    (preplanned : ops.preflight pending = Result.ok (.Ok (some preflight)))
    (prefetched : ops.dispatch pending .Preflight preflight = Result.ok (.Ok facts))
    (compiled : ops.final_effect pending facts = Result.ok (.Ok (some final)))
    (current : ops.recheck pending = Result.ok (.Ok ()))
    (classified : ops.effect_write pending final = Result.ok false)
    (dispatched : ops.dispatch pending .Final final = Result.ok (.Ok raw))
    (completed : ops.complete pending raw = Result.ok (.Ok reply)) :
    request_current ops pending = Result.ok (.Ok reply) := by
  rw [final_read_continuation ops pending facts raw final
    (Or.inr ⟨preflight, preplanned, prefetched⟩) compiled current classified dispatched,
    completed]

end aivm_secrets_garrett_core.read_transition.Proofs
