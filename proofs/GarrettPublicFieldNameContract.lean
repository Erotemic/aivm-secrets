import AivmSecretsGarrettCore
import GarrettFoundation

/-!
# Host output field names: the accepted language of `public_field_name`

Source: `rust/crates/aivm-secrets-garrett-core/src/selected_conversion.rs`
(`public_field_name`), extracted by the pinned Aeneas pipeline into
`selected_conversion.public_field_name` and its loop. The native manifest
parser calls this function on every host-owned output field name.

Proved here, directly over the extracted definitions:

* `public_field_name_spec`: the function always returns, and returns `true`
  **exactly** for names of 1..32 bytes whose first byte is `a`-`z` and whose
  every byte is `a`-`z`, `A`-`Z`, `0`-`9` or `_`;
* `public_field_name_necessary`: the necessary condition that was tried as an
  Anodized 0.7 `ensures` contract (length 1..32, lowercase first byte).

Anodized pilot (2026-10-23): with the pinned Charon/Aeneas, an
`anodized::spec` contract on this function makes Charon fold the contract
into the function, and Aeneas then extracts `public_field_name` as a wrapper
around three new uninterpreted axioms (`anodized.__.eval_once`,
`apply_keep`, `eval`). That definition can no longer be reasoned about, and
the contract reaches Lean only as code, not as a statement or obligation.
So the specification here is a handwritten Lean predicate proved against the
unannotated production extraction. See
`docs/assurance/anodized-pilot-2026-10-23.md` and
`dev/verification/anodized_pilot.py`.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs

namespace aivm_secrets_garrett_core.selected_conversion.Proofs

/-- A byte allowed anywhere in a public field name. -/
def FieldNameByte (byte : U8) : Prop :=
  (97 ≤ byte.val ∧ byte.val ≤ 122) ∨ (65 ≤ byte.val ∧ byte.val ≤ 90) ∨
    (48 ≤ byte.val ∧ byte.val ≤ 57) ∨ byte.val = 95

/-- The accepted language: 1..32 bytes, a lowercase ASCII letter first, and
    ASCII letters, digits or `_` throughout. -/
def PublicFieldName (bytes : List U8) : Prop :=
  1 ≤ bytes.length ∧ bytes.length ≤ 32 ∧
    (∃ h : 0 < bytes.length, 97 ≤ (bytes[0]'h).val ∧ (bytes[0]'h).val ≤ 122) ∧
    ∀ byte ∈ bytes, FieldNameByte byte

/-- The extraction binds each range flag as `if lo then ok hi else ok false`. -/
theorem range_flag (c d : Prop) [Decidable c] [Decidable d] :
    (if c then (Result.ok (decide d) : Result Bool) else Result.ok false) = Result.ok (decide (c ∧ d)) := by
  by_cases h : c <;> simp [h]

-- One tactic covers all eight extracted branches; some need `scalar_tac`.
set_option linter.unusedTactic false in
set_option linter.unnecessarySeqFocus false in
theorem public_field_name_loop_spec (bytes : alloc.vec.Vec U8) (index : Usize) :
    public_field_name_loop bytes index ⦃ r =>
      r = true ↔ ∀ k (hk : k < bytes.length), index.val ≤ k → FieldNameByte bytes.val[k] ⦄ := by
  suffices ∀ n (index : Usize), bytes.length - index.val = n →
      public_field_name_loop bytes index ⦃ r =>
        r = true ↔ ∀ k (hk : k < bytes.length), index.val ≤ k → FieldNameByte bytes.val[k] ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure
    rw [public_field_name_loop.eq_def]
    dsimp only
    split
    · rename_i inside
      step as ⟨byte, hbyte⟩
      simp only [range_flag, bind_ok]
      -- Every accepting branch continues at `index + 1`; the refusing branch
      -- has found a byte outside the language at `index`.
      have continue_at : ∀ next : Usize, next.val = index.val + 1 → FieldNameByte byte →
          public_field_name_loop bytes next ⦃ r =>
            r = true ↔ ∀ k (hk : k < bytes.length), index.val ≤ k → FieldNameByte bytes.val[k] ⦄ := by
        intro next hnext good
        refine WP.spec_mono (ih (bytes.length - next.val) (by scalar_tac) next rfl) ?_
        intro r hr
        rw [hr]
        constructor
        · intro rest k hk lo
          by_cases same : k = index.val
          · subst same; rw [← hbyte]; exact good
          · exact rest k hk (by scalar_tac)
        · intro all k hk lo
          exact all k hk (by scalar_tac)
      repeat' split
      all_goals first
        | (step as ⟨next, hnext⟩
           exact continue_at next hnext (by unfold FieldNameByte; simp_all <;> scalar_tac))
        | (simp only [WP.spec_ok]
           constructor
           · intro h; cases h
           · intro all
             have := all index.val (by scalar_tac) (le_refl _)
             rw [← hbyte] at this
             unfold FieldNameByte at this
             simp_all <;> scalar_tac)
    · simp only [WP.spec_ok]
      constructor
      · intro _ k hk lo; exfalso; scalar_tac
      · intro _; simp

/-- **The accepted language.** `public_field_name` always returns, and
    accepts exactly the names in `PublicFieldName`. -/
theorem public_field_name_spec (bytes : alloc.vec.Vec U8) :
    public_field_name bytes ⦃ r => r = true ↔ PublicFieldName bytes.val ⦄ := by
  unfold public_field_name
  dsimp only
  split
  · simp only [WP.spec_ok]
    constructor
    · intro h; cases h
    · intro ⟨one, _⟩; scalar_tac
  · split
    · simp only [WP.spec_ok]
      constructor
      · intro h; cases h
      · intro ⟨_, short, _⟩; scalar_tac
    · step as ⟨first, hfirst⟩
      split
      · simp only [WP.spec_ok]
        constructor
        · intro h; cases h
        · intro ⟨_, _, ⟨h0, lo, _⟩, _⟩
          simp_all; scalar_tac
      · split
        · simp only [WP.spec_ok]
          constructor
          · intro h; cases h
          · intro ⟨_, _, ⟨h0, _, hi⟩, _⟩
            simp_all; scalar_tac
        · refine WP.spec_mono (public_field_name_loop_spec bytes 0#usize) ?_
          intro r hr
          rw [hr]
          have h0 : 0 < bytes.length := by scalar_tac
          constructor
          · intro all
            refine ⟨by scalar_tac, by scalar_tac, ⟨h0, ?_, ?_⟩, ?_⟩
            · simp_all
            · simp_all
            · intro byte mem
              obtain ⟨k, hk, at_k⟩ := List.getElem_of_mem mem
              rw [← at_k]
              exact all k hk (by simp)
          · intro ⟨_, _, _, every⟩ k hk _
            exact every _ (List.getElem_mem hk)

/-- **The condition tried as the Anodized `ensures` contract.** Acceptance
    implies a length of 1..32 and a lowercase ASCII first byte. -/
theorem public_field_name_necessary (bytes : alloc.vec.Vec U8) :
    public_field_name bytes ⦃ r => r = true →
      1 ≤ bytes.length ∧ bytes.length ≤ 32 ∧
        ∃ h : 0 < bytes.length, 97 ≤ (bytes.val[0]'h).val ∧ (bytes.val[0]'h).val ≤ 122 ⦄ := by
  refine WP.spec_mono (public_field_name_spec bytes) ?_
  intro r hr accepted
  obtain ⟨one, short, first, _⟩ := hr.mp accepted
  exact ⟨one, short, first⟩

end aivm_secrets_garrett_core.selected_conversion.Proofs
