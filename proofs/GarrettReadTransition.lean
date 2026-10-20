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
    (pending after : P) (error : E)
    (denied : ops.recheck pending .BeforeAudit = Result.ok (.Err error, after)) :
    complete_current ops pending = Result.ok (.Err error, after) := by
  simp [complete_current, denied]

theorem completion_audit_refusal {P O E : Type} (ops : Completion P O E)
    (pending checked after : P) (error : E)
    (current : ops.recheck pending .BeforeAudit = Result.ok (.Ok (), checked))
    (refused : ops.audit checked = Result.ok (.Err error, after)) :
    complete_current ops pending = Result.ok (.Err error, after) := by
  simp [complete_current, current, refused]

theorem revoked_after_completion_audit {P O E : Type} (ops : Completion P O E)
    (pending checked audited after : P) (error : E)
    (before : ops.recheck pending .BeforeAudit = Result.ok (.Ok (), checked))
    (ack : ops.audit checked = Result.ok (.Ok (), audited))
    (afterAudit : ops.recheck audited .BeforeRelease = Result.ok (.Err error, after)) :
    complete_current ops pending = Result.ok (.Err error, after) := by
  simp [complete_current, before, ack, afterAudit]

theorem current_completion_continuation {P O E : Type} (ops : Completion P O E)
    (pending checked audited current : P)
    (before : ops.recheck pending .BeforeAudit = Result.ok (.Ok (), checked))
    (ack : ops.audit checked = Result.ok (.Ok (), audited))
    (afterAudit : ops.recheck audited .BeforeRelease = Result.ok (.Ok (), current)) :
    complete_current ops pending = ops.release current := by
  simp [complete_current, before, ack, afterAudit]

/-- Conditional preservation through the actual mutable completion controller.
    Every continuation receives the state returned by the preceding callback;
    unused continuations need no successful-outcome or termination contract. -/
theorem completion_preservation {P O E : Type} (ops : Completion P O E)
    (pending : P) (CurrentBefore Audited CurrentAfter : Prop) (Released : O → Prop)
    (before : ops.recheck pending .BeforeAudit ⦃ pair => pair.1 = .Ok () → CurrentBefore ⦄)
    (audit : ∀ checked, CurrentBefore → ops.audit checked ⦃ pair => pair.1 = .Ok () → Audited ⦄)
    (afterAudit : ∀ audited, CurrentBefore → Audited →
      ops.recheck audited .BeforeRelease ⦃ pair => pair.1 = .Ok () → CurrentAfter ⦄)
    (release : ∀ current, CurrentBefore → Audited → CurrentAfter → ops.release current
      ⦃ pair => ∀ value, pair.1 = .Ok value → Released value ⦄) :
    complete_current ops pending ⦃ pair => ∀ value, pair.1 = .Ok value →
      CurrentBefore ∧ Audited ∧ CurrentAfter ∧ Released value ⦄ := by
  unfold complete_current
  apply WP.spec_bind before
  rintro ⟨first, checked⟩ hfirst
  cases first with
  | Err error => simp
  | Ok u =>
    cases u
    have currentBefore := hfirst rfl
    apply WP.spec_bind (audit checked currentBefore)
    rintro ⟨acknowledged, audited⟩ hack
    cases acknowledged with
    | Err error => simp
    | Ok u =>
      cases u
      have auditAck := hack rfl
      apply WP.spec_bind (afterAudit audited currentBefore auditAck)
      rintro ⟨last, current⟩ hlast
      cases last with
      | Err error => simp
      | Ok u =>
        cases u
        have currentAfter := hlast rfl
        apply WP.spec_mono (release current currentBefore auditAck currentAfter)
        intro out released value success
        exact ⟨currentBefore, auditAck, currentAfter, released value success⟩

theorem authorized_completion_witness {P O E : Type} (ops : Completion P O E)
    (pending checked audited current after : P) (value : O)
    (before : ops.recheck pending .BeforeAudit = Result.ok (.Ok (), checked))
    (ack : ops.audit checked = Result.ok (.Ok (), audited))
    (afterAudit : ops.recheck audited .BeforeRelease = Result.ok (.Ok (), current))
    (released : ops.release current = Result.ok (.Ok value, after)) :
    complete_current ops pending = Result.ok (.Ok value, after) := by
  rw [current_completion_continuation ops pending checked audited current before ack afterAudit, released]

end aivm_secrets_garrett_core.read_transition.Proofs
