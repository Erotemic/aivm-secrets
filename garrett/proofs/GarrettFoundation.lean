import Aeneas

/-! Generic standard-model facts, independent of the extracted crate. Leaf
proofs can import these without rebuilding unrelated protocol theorems. -/
open Aeneas Aeneas.Std
namespace garrett_stateless_core.Proofs

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

end garrett_stateless_core.Proofs

/-! Vector and arithmetic facts the proofs share. -/
namespace garrett_stateless_core.Lemmas
open garrett_stateless_core.Proofs (returned_of_spec)

theorem bind_ok_inv {A B : Type} {first : Result A} {next : A → Result B} {out : B}
    (h : (first >>= next) = Result.ok out) : ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp_all

theorem push_ok_val {α : Type} {v w : alloc.vec.Vec α} {x : α}
    (h : alloc.vec.Vec.push v x = Result.ok w) : w.val = v.val ++ [x] := by
  unfold alloc.vec.Vec.push at h
  dsimp only at h
  split at h
  · simp only [Result.ok.injEq] at h
    subst h
    simp
  · simp at h

theorem extend_ok_val {v w : alloc.vec.Vec U8} {bytes : Slice U8}
    (h : alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v bytes = Result.ok w) :
    w.val = v.val ++ bytes.val := by
  unfold alloc.vec.Vec.extend_from_slice at h
  split at h
  · obtain ⟨cloned, copied, h⟩ := bind_ok_inv h
    obtain ⟨c, hc, same⟩ := returned_of_spec (List.clone_spec (clone := core.clone.CloneU8.clone)
      (l := bytes.val) (by intro x _; rfl))
    rw [hc] at copied
    simp only [Result.ok.injEq] at copied h
    subst copied h
    simp [same]
  · simp at h

theorem index_usize_eq {α : Type} (s : Slice α) (i : Usize) (inside : i.val < s.length) :
    Slice.index_usize s i = Result.ok s.val[i.val] := by
  obtain ⟨y, hy, same⟩ := returned_of_spec (Slice.index_usize_spec s i inside)
  rw [hy, same]

theorem add_one_eq (a : Usize) (room : a.val + 1 ≤ Usize.max) :
    ∃ b : Usize, a + 1#usize = Result.ok b ∧ b.val = a.val + 1 := by
  obtain ⟨c, hc, value⟩ := returned_of_spec (Usize.add_spec (x := a) (y := 1#usize) (by simpa using room))
  exact ⟨c, hc, by simpa using value⟩

/-! ## Lookup -/

end garrett_stateless_core.Lemmas
