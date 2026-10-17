import Aeneas

/-! Generic standard-model facts, independent of the extracted crate. Leaf
proofs can import these without rebuilding unrelated protocol theorems. -/
open Aeneas Aeneas.Std
namespace aivm_secrets_garrett_core.Proofs

@[step]
theorem bytes_ne_spec (a b : alloc.vec.Vec U8) :
    alloc.vec.partial_eq.PartialEqVec.ne core.cmp.PartialEqU8 a b
      ⦃ out => out ↔ a ≠ b ⦄ := by
  change core.slice.cmp.PartialEqSlice.ne core.cmp.PartialEqU8 a.slice b.slice
    ⦃ out => out ↔ a ≠ b ⦄
  apply WP.spec_mono (core.slice.cmp.PartialEqSlice.ne_homo_spec
    core.cmp.PartialEqU8 a.slice b.slice (by intro x y; simp))
  intro out h
  have heq : a.slice = b.slice ↔ a = b := by
    constructor
    · intro eq; exact congrArg alloc.vec.Vec.mk eq
    · intro eq; exact congrArg alloc.vec.Vec.slice eq
  simpa only [heq] using h

/-- Total correctness for a pure extracted computation gives an actual return. -/
theorem returned_of_spec {α : Type} {computation : Result α} {post : α → Prop}
    (h : computation ⦃ post ⦄) : ∃ value, computation = Result.ok value ∧ post value := by
  cases computation using Result.cases with
  | ret value => exact ⟨value, rfl, by simpa only [WP.spec_ok] using h⟩
  | vis effect continuation => simp only [WP.spec_vis] at h
  | div => simp only [WP.spec_div] at h

end aivm_secrets_garrett_core.Proofs
