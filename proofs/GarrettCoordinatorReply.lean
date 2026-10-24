import AivmSecretsGarrettCore
import GarrettFoundation
import GarrettCoordinatorAuthority

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 2000000
namespace aivm_secrets_garrett_core.coordinator_authority.ReceiptProofs

def ValidReceipt (action : Action) (active : Bool) (revision : Option I64) : Prop :=
  match action with
  | .Activate => active = true ∧ revision = some 1#i64
  | .Revoke => active = false ∧ ∃ r, revision = some r ∧ 1 ≤ r.val
  | .Status => match revision with
    | none => active = false
    | some r => 1 ≤ r.val
  | .Check | .Reserve | .Finish => False

theorem operator_receipt_contract (action : Action) (active : Bool) (revision : Option I64) :
    operator_acknowledged action active revision ⦃ out => out ↔ ValidReceipt action active revision ⦄ := by
  cases action <;> cases revision <;> cases active <;>
    simp [operator_acknowledged, ValidReceipt, WP.spec_ok]

theorem confirmed_revocation_is_tombstone (active : Bool) (revision : Option I64)
    (accepted : operator_acknowledged .Revoke active revision = Result.ok true) :
    active = false ∧ ∃ r, revision = some r ∧ 1 ≤ r.val := by
  obtain ⟨out, returned, related⟩ := returned_of_spec
    (operator_receipt_contract .Revoke active revision)
  have same : out = true := Result.ok_injective (returned.symm.trans accepted)
  exact related.mp same

theorem absence_cannot_confirm_revocation (active : Bool) :
    operator_acknowledged .Revoke active none = Result.ok false := by
  simp [operator_acknowledged]

theorem active_state_cannot_confirm_revocation (revision : Option I64) :
    operator_acknowledged .Revoke true revision = Result.ok false := by
  cases revision <;> simp [operator_acknowledged]

theorem absent_status_is_admitted :
    operator_acknowledged .Status false none = Result.ok true := by rfl

theorem activation_receipt_exact (active : Bool) (revision : Option I64) :
    operator_acknowledged .Activate active revision ⦃ out =>
      out ↔ active = true ∧ revision = some 1#i64 ⦄ :=
  operator_receipt_contract .Activate active revision

/-- This joins two actual extracted functions. It does not authenticate a
    remote server or prove that its SQL commit occurred before a reply. -/
theorem successful_revocation_has_receipt (current : Option Principal) (result : Principal)
    (success : revoke current = Result.ok (.Ok result)) :
    operator_acknowledged .Revoke result.active (some result.revision) = Result.ok true := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (Proofs.revoke_contract current)
  have same : out = .Ok result := Result.ok_injective (returned.symm.trans success)
  rw [same] at property
  have positive : 1 ≤ result.revision.val := by
    cases current with
    | none =>
      have value : result.revision.val = 1 := property.2.2
      omega
    | some prior =>
      have lower : ¬ prior.revision < 1#i64 := by
        intro low
        simp [revoke, low] at success
      have value := property.2.2
      scalar_tac
  have bound : result.revision ≥ 1#i64 := by scalar_tac
  simp [operator_acknowledged, property.1, bound]

end aivm_secrets_garrett_core.coordinator_authority.ReceiptProofs

namespace aivm_secrets_garrett_core.coordinator_authority.ReceiptProofs

/-- What the member client accepts from the coordinator for each phase. -/
def MemberReceipt (action : Action) (flag : Bool) (revision : Option I64) : Prop :=
  match action with
  | .Check => flag = true ∧ ∃ r, revision = some r ∧ 1 ≤ r.val
  | .Reserve | .Finish => flag = true ∧ revision = none
  | .Activate | .Revoke | .Status => False

theorem member_receipt_contract (action : Action) (flag : Bool) (revision : Option I64) :
    member_acknowledged action flag revision ⦃ out => out ↔ MemberReceipt action flag revision ⦄ := by
  cases action <;> cases revision <;> cases flag <;>
    simp [member_acknowledged, MemberReceipt, WP.spec_ok]

/-- A reservation or completion is never acknowledged without its own flag. -/
theorem unflagged_phase_refused (action : Action) (revision : Option I64) :
    member_acknowledged action false revision = Result.ok false := by
  cases action <;> cases revision <;> simp [member_acknowledged]

end aivm_secrets_garrett_core.coordinator_authority.ReceiptProofs
