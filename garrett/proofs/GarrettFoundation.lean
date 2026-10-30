import Aeneas

/-! Generic facts about the Aeneas standard model: results, scalars, slices
and vectors. Nothing here mentions the extracted crate, so every proof module
can import this without importing another module's protocol theorems. Every
proof module opens `garrett_stateless_core.Proofs`, so these names are in
scope everywhere. -/
open Aeneas Aeneas.Std
namespace garrett_stateless_core.Proofs

/-! ## Results -/

/-- Total correctness for a pure extracted computation gives an actual return. -/
theorem returned_of_spec {α : Type} {computation : Result α} {post : α → Prop}
    (h : computation ⦃ post ⦄) : ∃ value, computation = Result.ok value ∧ post value := by
  cases computation using Result.cases with
  | ret value => exact ⟨value, rfl, by simpa only [WP.spec_ok] using h⟩
  | vis effect continuation => simp only [WP.spec_vis] at h
  | div => simp only [WP.spec_div] at h

theorem bind_ok_inv {A B : Type} {first : Result A} {next : A → Result B} {out : B}
    (h : (first >>= next) = Result.ok out) : ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp_all

/-- An `if` that returned: which branch, and what it returned. Applied by
    unification, so it also sees through the pair bindings Aeneas emits. -/
theorem ite_ok_inv {α : Type} {c : Prop} [Decidable c] {a b : Result α} {x : α}
    (h : (if c then a else b) = Result.ok x) : (c ∧ a = Result.ok x) ∨ (¬ c ∧ b = Result.ok x) := by
  split at h
  · exact Or.inl ⟨‹_›, h⟩
  · exact Or.inr ⟨‹_›, h⟩

theorem ok_pair_inv {α β : Type} {a c : α} {b d : β}
    (h : (Result.ok (a, b) : Result (α × β)) = Result.ok (c, d)) : a = c ∧ b = d :=
  Prod.mk.inj (Result.ok_injective h)

/-! ## Scalars -/

theorem usize_succ (i : Usize) (h : i.val + 1 ≤ Usize.max) :
    ∃ j : Usize, i + 1#usize = Result.ok j ∧ j.val = i.val + 1 := by
  obtain ⟨c, hc, v⟩ := returned_of_spec (Usize.add_spec (x := i) (y := 1#usize) (by simpa using h))
  exact ⟨c, hc, by simpa using v⟩

/-! ## Slices -/

/-- ASCII bytes of a literal. -/
def ascii (s : String) : List U8 := s.toList.map (fun c => ⟨BitVec.ofNat 8 c.toNat⟩)

theorem slice_index_eq {α : Type} (s : Slice α) (i : Usize) (inside : i.val < s.length) :
    Slice.index_usize s i = Result.ok s.val[i.val] := by
  obtain ⟨y, hy, same⟩ := returned_of_spec (Slice.index_usize_spec s i inside)
  rw [hy, same]

theorem array_slice_val {k : Usize} (l : List U8) (h : l.length = k.val) :
    (Array.make k l h).to_slice.val = l := by
  simp [Array.to_slice, Slice.from_val]

@[step]
theorem slice_bytes_equal (a b : Slice U8) :
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b
      ⦃ out => out ↔ a.val = b.val ⦄ := by
  apply WP.spec_mono (core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 a b (by intro x y; simp))
  intro out exact_bytes
  simpa [Slice.eq_iff] using exact_bytes

theorem slice_eq_eq (a b : Slice U8) :
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b = Result.ok (decide (a.val = b.val)) := by
  obtain ⟨out, returned, h⟩ := returned_of_spec (slice_bytes_equal a b)
  rw [returned]
  congr 1
  by_cases e : a.val = b.val
  · simpa [e] using h
  · simp only [e, decide_false]
    cases out <;> simp_all

theorem to_vec_eq (s : Slice U8) :
    alloc.slice.Slice.to_vec core.clone.CloneU8 s = Result.ok ⟨s⟩ := by
  obtain ⟨w, hw, eq⟩ := returned_of_spec (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 s (by intro x _; rfl))
  rw [hw]
  cases w
  simp_all

/-! ## Vectors -/

@[simp, scalar_tac_simps]
theorem vec_deref_length {T : Type} (value : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref value).length = value.length := by simp [alloc.vec.Vec.deref]

@[simp, scalar_tac_simps]
theorem vec_deref_val {T : Type} (value : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref value).val = value.val := by simp [alloc.vec.Vec.deref]

theorem vec_deref_mk (v : alloc.vec.Vec U8) : ({ slice := alloc.vec.Vec.deref v } : alloc.vec.Vec U8) = v := by
  cases v with
  | mk s =>
    congr 1
    rw [Slice.eq_iff]
    simp [alloc.vec.Vec.deref, alloc.vec.Vec.val]

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

end garrett_stateless_core.Proofs
