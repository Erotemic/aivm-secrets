import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.emission.Proofs

/-- The emission adapter has no role in a denied continuation. No termination,
    return-value or side-effect contract is required for it in this theorem. -/
theorem rejected_before_emission {P O E : Type} (ops : PendingEmission P O E)
    (pending : P) (error : E)
    (denied : ops.recheck pending = Result.ok (.Err error)) :
    emit_current ops pending = Result.ok (.Err error) := by
  simp [emit_current, denied]

theorem denied_emission_independent {P O E : Type}
    (a b : PendingEmission P O E) (pending : P) (error : E)
    (a_denied : a.recheck pending = Result.ok (.Err error))
    (b_denied : b.recheck pending = Result.ok (.Err error)) :
    emit_current a pending = emit_current b pending := by
  rw [rejected_before_emission a pending error a_denied,
    rejected_before_emission b pending error b_denied]

/-- This equality retains emission errors or divergence. It is not limited to
    successful provider replies, which would omit uncertain external effects. -/
theorem admitted_continuation {P O E : Type} (ops : PendingEmission P O E)
    (pending : P) (admitted : ops.recheck pending = Result.ok (.Ok ())) :
    emit_current ops pending = ops.emit pending := by
  simp [emit_current, admitted]

def Acknowledged (fact : Prop) {T E : Type} (out : core.result.Result T E) : Prop :=
  match out with | .Ok _ => fact | .Err _ => True

/-- The clock/authority adapters establish Current at their sampled admission
    point. This theorem does not assume successful HTTP or extend that instant
    into atomic wall-clock validity throughout a network write. -/
theorem emission_contract {P O E : Type} (ops : PendingEmission P O E)
    (pending : P) (Current : Prop) (Emitted : O → Prop)
    (check_contract : ops.recheck pending ⦃ out => Acknowledged Current out ⦄)
    (emit_contract : ops.emit pending ⦃ out =>
      match out with | .Ok value => Emitted value | .Err _ => True ⦄) :
    emit_current ops pending ⦃ out =>
      match out with | .Ok value => Current ∧ Emitted value | .Err _ => True ⦄ := by
  unfold emit_current
  apply WP.spec_bind check_contract
  intro checked current
  cases checked with
  | Err error => simp
  | Ok ack =>
    cases ack
    apply WP.spec_mono emit_contract
    intro out emitted
    cases out with
    | Err error => trivial
    | Ok value => exact ⟨current, emitted⟩

theorem successful_emission_witness {P O E : Type} (ops : PendingEmission P O E)
    (pending : P) (value : O)
    (admitted : ops.recheck pending = Result.ok (.Ok ()))
    (emitted : ops.emit pending = Result.ok (.Ok value)) :
    emit_current ops pending = Result.ok (.Ok value) := by
  rw [admitted_continuation ops pending admitted, emitted]

end aivm_secrets_garrett_core.emission.Proofs
