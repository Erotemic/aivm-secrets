import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 2000000
namespace aivm_secrets_garrett_core.approval.Proofs

def Issuable (now ttl : I64) : Prop :=
  0 ≤ now.val ∧ 1 ≤ ttl.val ∧ ttl.val ≤ 900 ∧ now.val + ttl.val ≤ 9223372036854775807

theorem issue_contract (digest : alloc.vec.Vec U8) (now ttl : I64) :
    issue digest now ttl ⦃ out =>
      (out = none ↔ ¬ Issuable now ttl) ∧
      (∀ slot, out = some slot → slot.digest = digest ∧
        slot.expires_at.val = now.val + ttl.val ∧ now.val < slot.expires_at.val) ⦄ := by
  have maximum : core.num.I64.MAX.val = 9223372036854775807 := by rfl
  unfold issue
  split
  · simp_all [Issuable, WP.spec_ok]
  · split
    · simp_all [Issuable, WP.spec_ok]
    · split
      · simp_all [Issuable, WP.spec_ok]
      · apply WP.spec_bind (@I64.sub_spec core.num.I64.MAX ttl (by simp only [maximum]; scalar_tac) (by simp only [maximum]; scalar_tac))
        intro limit limitEq
        simp only [maximum] at limitEq
        split
        · simp_all [Issuable, WP.spec_ok]
          scalar_tac
        · apply WP.spec_bind (@I64.add_spec now ttl (by scalar_tac) (by scalar_tac))
          intro deadline deadlineEq
          simp_all [Issuable, WP.spec_ok]
          all_goals scalar_tac

def Eligible (prior : Option Approval) (wanted : alloc.vec.Vec U8) (now : I64) : Prop :=
  ∃ slot, prior = some slot ∧ slot.digest = wanted ∧ now < slot.expires_at

def ApprovedOutcome (prior : Option Approval) (wanted : alloc.vec.Vec U8) (now : I64)
    (out : Decision × Option Approval) : Prop :=
  (out.1 = .Allowed ↔ Eligible prior wanted now) ∧
  (out.1 = .Required ↔ ¬ Eligible prior wanted now) ∧
  (out.1 = .Allowed → out.2 = none) ∧
  (out.1 = .Required → out.2 = prior)

theorem approved_write_contract (wanted : alloc.vec.Vec U8) (now : I64)
    (prior : Option Approval) :
    consume .Approve true wanted now prior ⦃ out => ApprovedOutcome prior wanted now out ⦄ := by
  cases prior with
  | none => simp [consume, ApprovedOutcome, Eligible]
  | some slot =>
    unfold consume
    simp only [↓reduceIte]
    apply WP.spec_bind (bytes_ne_spec slot.digest wanted)
    intro different related
    cases different with
    | true =>
      have mismatch : slot.digest ≠ wanted := related.mp rfl
      simp [ApprovedOutcome, Eligible, mismatch]
    | false =>
      have same : slot.digest = wanted := by
        by_contra mismatch
        have invalid := related.mpr mismatch
        simp at invalid
      by_cases expired : now ≥ slot.expires_at
      · have late : slot.expires_at.val ≤ now.val := by scalar_tac
        simp [expired, ApprovedOutcome, Eligible, same, late]
      · have timely : now.val < slot.expires_at.val := by scalar_tac
        simp [expired, ApprovedOutcome, Eligible, same, timely]

theorem reads_preserve_approval (mode : Mode) (wanted : alloc.vec.Vec U8) (now : I64)
    (prior : Option Approval) :
    consume mode false wanted now prior = Result.ok (.Allowed, prior) := by rfl

theorem allow_mode_preserves_approval (write : Bool) (wanted : alloc.vec.Vec U8) (now : I64)
    (prior : Option Approval) :
    consume .Allow write wanted now prior = Result.ok (.Allowed, prior) := by
  cases write <;> rfl

theorem deny_mode_refuses_write (wanted : alloc.vec.Vec U8) (now : I64)
    (prior : Option Approval) :
    consume .Deny true wanted now prior = Result.ok (.Denied, prior) := by rfl

theorem missing_approval_refuses_write (wanted : alloc.vec.Vec U8) (now : I64) :
    consume .Approve true wanted now none = Result.ok (.Required, none) := by rfl

theorem admitted_approval_is_consumed (wanted : alloc.vec.Vec U8) (now : I64)
    (prior : Option Approval) (remaining : Option Approval)
    (accepted : consume .Approve true wanted now prior = Result.ok (.Allowed, remaining)) :
    Eligible prior wanted now ∧ remaining = none := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (approved_write_contract wanted now prior)
  have same : out = (.Allowed, remaining) := Result.ok_injective (returned.symm.trans accepted)
  rw [same] at property
  exact ⟨property.1.mp rfl, property.2.2.1 rfl⟩

theorem refused_approval_is_preserved (wanted : alloc.vec.Vec U8) (now : I64)
    (prior : Option Approval) (remaining : Option Approval)
    (refused : consume .Approve true wanted now prior = Result.ok (.Required, remaining)) :
    ¬ Eligible prior wanted now ∧ remaining = prior := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (approved_write_contract wanted now prior)
  have same : out = (.Required, remaining) := Result.ok_injective (returned.symm.trans refused)
  rw [same] at property
  exact ⟨property.2.1.mp rfl, property.2.2.2 rfl⟩

theorem consumed_approval_cannot_be_reused (wanted : alloc.vec.Vec U8) (first later : I64)
    (prior : Option Approval) (remaining : Option Approval)
    (accepted : consume .Approve true wanted first prior = Result.ok (.Allowed, remaining)) :
    consume .Approve true wanted later remaining = Result.ok (.Required, none) := by
  have spent := (admitted_approval_is_consumed wanted first prior remaining accepted).2
  rw [spent]
  exact missing_approval_refuses_write wanted later

end aivm_secrets_garrett_core.approval.Proofs
