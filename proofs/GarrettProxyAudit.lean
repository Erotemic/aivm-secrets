import AivmSecretsGarrettCore
import GarrettFoundation

/-!
# The proxy audit row (work in progress, branch `wip/proxy-audit-rows`)

Source: `rust/crates/aivm-secrets-garrett-core/src/proxy_audit.rs`.
So far: `key_before_spec`, the key order the row's field merge uses.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs

namespace aivm_secrets_garrett_core.proxy_audit.Proofs

/-- Key order: compare scalar by scalar; a proper prefix comes first. -/
def KeyLt : List U32 → List U32 → Prop
  | [], [] => False
  | [], _ :: _ => True
  | _ :: _, [] => False
  | x :: xs, y :: ys => if x = y then KeyLt xs ys else x.val < y.val

theorem key_before_loop_spec (a b : Slice U32) (index : Usize)
    (inside : index.val ≤ a.length) :
    key_before_loop a b index ⦃ r =>
      r = true ↔ KeyLt (a.val.drop index.val) (b.val.drop index.val) ⦄ := by
  suffices ∀ n (index : Usize), a.length - index.val = n → index.val ≤ a.length →
      key_before_loop a b index ⦃ r =>
        r = true ↔ KeyLt (a.val.drop index.val) (b.val.drop index.val) ⦄ from this _ index rfl inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure inside
    rw [key_before_loop.eq_def]
    dsimp only
    split
    · rename_i ina
      split
      · rename_i inb
        step as ⟨x, hx⟩
        step as ⟨y, hy⟩
        have da : a.val.drop index.val = x :: a.val.drop (index.val + 1) := by
          rw [hx]; exact List.drop_eq_getElem_cons (by scalar_tac)
        have db : b.val.drop index.val = y :: b.val.drop (index.val + 1) := by
          rw [hy]; exact List.drop_eq_getElem_cons (by scalar_tac)
        rw [da, db]
        split
        · rename_i ne
          have ne' : x ≠ y := by simpa using ne
          simp [WP.spec_ok, KeyLt, ne']
        · rename_i eq
          have eq' : x = y := by
            have : x.val = y.val := by simpa using eq
            exact UScalar.eq_of_val_eq this
          step as ⟨next, hnext⟩
          refine WP.spec_mono (ih (a.length - next.val) (by scalar_tac) next rfl (by scalar_tac)) ?_
          intro r hr
          rw [hr, hnext]
          simp [KeyLt, eq']
      · rename_i outb
        have db : b.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
        have da : a.val.drop index.val ≠ [] := by
          intro e; have := congrArg List.length e; simp at this; scalar_tac
        obtain ⟨x, rest, hda⟩ := List.exists_cons_of_ne_nil da
        simp only [WP.spec_ok, decide_eq_true_eq, db, hda, KeyLt, iff_false]
        scalar_tac
    · rename_i outa
      have da : a.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
      simp only [WP.spec_ok, decide_eq_true_eq, da]
      cases hdb : b.val.drop index.val with
      | nil =>
        have : b.val.length ≤ index.val := by
          have := congrArg List.length hdb; simp at this; omega
        simp [KeyLt]; scalar_tac
      | cons y ys =>
        have : index.val < b.val.length := by
          by_contra h; rw [List.drop_eq_nil_of_le (by omega)] at hdb; cases hdb
        simp [KeyLt]; scalar_tac

end aivm_secrets_garrett_core.proxy_audit.Proofs
