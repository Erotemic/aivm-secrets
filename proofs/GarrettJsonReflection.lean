import GarrettReflection

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.reflection.Proofs
open aivm_secrets_garrett_core.disclosure (Json)
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.json_reflection.Proofs

/-- Exact decoded-key/text admission, with explicit recursion exhaustion.
Numbers, booleans and punctuation require the separate serializer check. -/
def SafeWithin : Nat → Json → Slice U8 → Prop
  | 0, _, _ => False
  | _ + 1, .Text text, secret => ¬ LiteralOccurs text.slice secret
  | n + 1, .Array values, secret => ∀ child ∈ values.val, SafeWithin n child secret
  | n + 1, .Object fields, secret => ∀ entry ∈ fields.val,
      ¬ LiteralOccurs entry.1.slice secret ∧ SafeWithin n entry.2 secret
  | _ + 1, _, _ => True

private theorem deref_eq_slice {α : Type} (v : alloc.vec.Vec α) :
    v.deref = v.slice := by
  simp only [Slice.eq_iff, alloc.vec.Vec.deref, Slice.from_val, alloc.vec.Vec.val]

theorem index_exact {α : Type} (v : alloc.vec.Vec α) (i : Usize) (bound : i.val < v.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = Result.ok (v.val[i.val]) := by
  rw [alloc.vec.Vec.index_slice_index]
  obtain ⟨out, returned, eq⟩ := returned_of_spec (alloc.vec.Vec.index_usize_spec v i bound)
  simpa only [eq] using returned

theorem array_loop_contract (values : alloc.vec.Vec Json) (secret : Slice U8) (fuel index : Usize)
    (positive : 0 < fuel.val)
    (children : ∀ child (next : Usize), next.val = fuel.val - 1 →
      safe child secret next ⦃ out => out ↔ SafeWithin next.val child secret ⦄) :
    safe_loop0 values secret fuel index ⦃ out => out ↔
      ∀ child ∈ values.val.drop index.val, SafeWithin (fuel.val - 1) child secret ⦄ := by
  suffices ∀ n (i : Usize), values.length - i.val = n →
      safe_loop0 values secret fuel i ⦃ out => out ↔
        ∀ child ∈ values.val.drop i.val, SafeWithin (fuel.val - 1) child secret ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [safe_loop0.eq_def]
    by_cases inside : i < values.len
    · have bound : i.val < values.length := by scalar_tac
      simp only [inside, ↓reduceIte]
      rw [index_exact values i bound]
      simp only [bind_ok]
      obtain ⟨nextFuel, subReturned, subValue⟩ := returned_of_spec
        (@Usize.sub_spec fuel 1#usize (by scalar_tac))
      rw [subReturned]
      have nextFuelValue : nextFuel.val = fuel.val - 1 := by scalar_tac
      simp only [bind_ok]
      apply WP.spec_bind (children _ nextFuel (by simpa using subValue.1))
      intro admitted related
      cases admitted with
      | false =>
        have absent : ¬ SafeWithin (fuel.val - 1) values.val[i.val] secret := by
          simpa [nextFuelValue] using related
        simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
        rw [List.drop_eq_getElem_cons bound]
        simp only [List.forall_mem_cons, absent, false_and]
      | true =>
        have clean : SafeWithin (fuel.val - 1) values.val[i.val] secret := by
          simpa [nextFuelValue] using related
        simp only [↓reduceIte]
        obtain ⟨next, addReturned, addValue⟩ := returned_of_spec
          (@Usize.add_spec i 1#usize (by scalar_tac))
        rw [addReturned]
        have nextValue : next.val = i.val + 1 := by scalar_tac
        simp only [bind_ok]
        apply WP.spec_mono (ih (values.length - next.val) (by scalar_tac) next rfl)
        intro out tail
        rw [List.drop_eq_getElem_cons bound]
        simpa only [List.forall_mem_cons, clean, true_and, nextValue] using tail
    · have done : values.val.length ≤ i.val := by scalar_tac
      simp [inside, WP.spec_ok, List.drop_eq_nil_of_le done]

theorem object_loop_contract (fields : alloc.vec.Vec ((alloc.vec.Vec U8) × Json))
    (secret : Slice U8) (fuel index : Usize) (positive : 0 < fuel.val)
    (children : ∀ child (next : Usize), next.val = fuel.val - 1 →
      safe child secret next ⦃ out => out ↔ SafeWithin next.val child secret ⦄) :
    safe_loop1 fields secret fuel index ⦃ out => out ↔
      ∀ entry ∈ fields.val.drop index.val,
        ¬ LiteralOccurs entry.1.slice secret ∧ SafeWithin (fuel.val - 1) entry.2 secret ⦄ := by
  suffices ∀ n (i : Usize), fields.length - i.val = n →
      safe_loop1 fields secret fuel i ⦃ out => out ↔
        ∀ entry ∈ fields.val.drop i.val,
          ¬ LiteralOccurs entry.1.slice secret ∧ SafeWithin (fuel.val - 1) entry.2 secret ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [safe_loop1.eq_def]
    by_cases inside : i < fields.len
    · have bound : i.val < fields.length := by scalar_tac
      simp only [inside, ↓reduceIte]
      rw [index_exact fields i bound]
      cases entry : fields.val[i.val] with
      | mk keyName child =>
        simp only [bind_ok, Aeneas.Std.uncurry]
        simp only [deref_eq_slice]
        obtain ⟨reflected, keyReturned, keyRelated⟩ := returned_of_spec (contains_contract keyName.slice secret)
        rw [keyReturned]
        simp only [bind_ok]
        cases reflected with
        | true =>
          have unsafeKey : LiteralOccurs keyName.slice secret := by simpa using keyRelated
          simp only [↓reduceIte, WP.spec_ok]
          rw [List.drop_eq_getElem_cons bound]
          simp only [List.forall_mem_cons, entry, unsafeKey, not_true_eq_false, false_and]
          decide
        | false =>
          have cleanKey : ¬ LiteralOccurs keyName.slice secret := by simpa using keyRelated
          obtain ⟨nextFuel, subReturned, subValue⟩ := returned_of_spec
            (@Usize.sub_spec fuel 1#usize (by scalar_tac))
          rw [subReturned]
          have nextFuelValue : nextFuel.val = fuel.val - 1 := by scalar_tac
          simp only [bind_ok]
          apply WP.spec_bind (children child nextFuel (by simpa using subValue.1))
          intro admitted childRelated
          cases admitted with
          | false =>
            have absent : ¬ SafeWithin (fuel.val - 1) child secret := by
              simpa [nextFuelValue] using childRelated
            simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
            rw [List.drop_eq_getElem_cons bound]
            simp only [List.forall_mem_cons, entry, absent, and_false, false_and,
              ]
          | true =>
            have cleanChild : SafeWithin (fuel.val - 1) child secret := by
              simpa [nextFuelValue] using childRelated
            simp only [↓reduceIte]
            obtain ⟨next, addReturned, addValue⟩ := returned_of_spec
              (@Usize.add_spec i 1#usize (by scalar_tac))
            rw [addReturned]
            have nextValue : next.val = i.val + 1 := by scalar_tac
            simp only [bind_ok]
            apply WP.spec_mono (ih (fields.length - next.val) (by scalar_tac) next rfl)
            intro out tail
            rw [List.drop_eq_getElem_cons bound]
            simpa only [List.forall_mem_cons, entry, cleanKey, cleanChild, and_self,
              not_false_eq_true, true_and, nextValue] using tail
    · have done : fields.val.length ≤ i.val := by scalar_tac
      simp [inside, WP.spec_ok, List.drop_eq_nil_of_le done]

theorem safe_contract (value : Json) (secret : Slice U8) (fuel : Usize) :
    safe value secret fuel ⦃ out => out ↔ SafeWithin fuel.val value secret ⦄ := by
  suffices ∀ n (f : Usize), f.val = n → ∀ v,
      safe v secret f ⦃ out => out ↔ SafeWithin n v secret ⦄ from
    this _ fuel rfl value
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro f measure v
    rw [safe.eq_def]
    by_cases zero : f = 0#usize
    · have eq : n = 0 := by scalar_tac
      simp [zero, eq, SafeWithin, WP.spec_ok]
    · have positive : 0 < f.val := by scalar_tac
      have children : ∀ child (next : Usize), next.val = f.val - 1 →
          safe child secret next ⦃ out => out ↔ SafeWithin next.val child secret ⦄ := by
        intro child next subValue
        exact ih next.val (by scalar_tac) next rfl child
      simp only [zero, ↓reduceIte]
      obtain ⟨k, nk⟩ : ∃ k, n = k + 1 := ⟨n - 1, by scalar_tac⟩
      cases v with
      | Null => simp [WP.spec_ok, nk, SafeWithin]
      | Boolean b => simp [WP.spec_ok, nk, SafeWithin]
      | Integer i => simp [WP.spec_ok, nk, SafeWithin]
      | Opaque => simp [WP.spec_ok, nk, SafeWithin]
      | Text text =>
        simp only [deref_eq_slice]
        obtain ⟨reflected, returned, related⟩ := returned_of_spec (contains_contract text.slice secret)
        rw [returned]
        simp only [bind_ok, WP.spec_ok]
        simpa [nk, SafeWithin] using not_congr related
      | Array values =>
        apply WP.spec_mono (array_loop_contract values secret f 0#usize positive children)
        intro out related
        simpa [SafeWithin, nk, measure] using related
      | Object fields =>
        apply WP.spec_mono (object_loop_contract fields secret f 0#usize positive children)
        intro out related
        simpa [SafeWithin, nk, measure] using related

/-- A literal credential occurs in decoded text or an object key at any depth.
This deliberately does not classify numeric encodings or serialized punctuation. -/
inductive Occurs (secret : Slice U8) : Json → Prop where
  | text (value : alloc.vec.Vec U8) (literal : LiteralOccurs value.slice secret) :
      Occurs secret (.Text value)
  | array (values : alloc.vec.Vec Json) (child : Json)
      (member : child ∈ values.val) (nested : Occurs secret child) :
      Occurs secret (.Array values)
  | key (fields : alloc.vec.Vec ((alloc.vec.Vec U8) × Json))
      (entry : (alloc.vec.Vec U8) × Json) (member : entry ∈ fields.val)
      (literal : LiteralOccurs entry.1.slice secret) : Occurs secret (.Object fields)
  | field (fields : alloc.vec.Vec ((alloc.vec.Vec U8) × Json))
      (entry : (alloc.vec.Vec U8) × Json) (member : entry ∈ fields.val)
      (nested : Occurs secret entry.2) : Occurs secret (.Object fields)

theorem within_excludes_literal (fuel : Nat) (value : Json) (secret : Slice U8)
    (admitted : SafeWithin fuel value secret) : ¬ Occurs secret value := by
  intro occurrence
  induction occurrence generalizing fuel with
  | text value literal =>
    cases fuel <;> simp_all [SafeWithin]
  | array values child member nested ih =>
    cases fuel with
    | zero => exact admitted
    | succ n => exact ih n (admitted child member)
  | key fields entry member literal =>
    cases fuel with
    | zero => exact admitted
    | succ n => exact (admitted entry member).1 literal
  | field fields entry member nested ih =>
    cases fuel with
    | zero => exact admitted
    | succ n => exact ih n (admitted entry member).2

/-- Acceptance of the actual extracted traversal rules out a literal in every
visited decoded key/string, including nested array and object children. -/
theorem accepted_excludes_literal (value : Json) (secret : Slice U8) (fuel : Usize)
    (accepted : safe value secret fuel = Result.ok true) : ¬ Occurs secret value := by
  obtain ⟨out, returned, related⟩ := returned_of_spec (safe_contract value secret fuel)
  have same : out = true := Result.ok_injective (returned.symm.trans accepted)
  exact within_excludes_literal fuel.val value secret (related.mp same)

theorem reflected_json_is_refused (value : Json) (secret : Slice U8) (fuel : Usize)
    (occurs : Occurs secret value) : safe value secret fuel = Result.ok false := by
  obtain ⟨out, returned, _⟩ := returned_of_spec (safe_contract value secret fuel)
  cases out with
  | false => exact returned
  | true => exact False.elim (accepted_excludes_literal value secret fuel returned occurs)

theorem exhausted_is_refused (value : Json) (secret : Slice U8) :
    safe value secret 0#usize = Result.ok false := by
  rw [safe.eq_def]
  simp

theorem empty_object_positive_witness (secret : Slice U8) :
    safe (.Object (alloc.vec.Vec.from [] (by simp))) secret 1#usize = Result.ok true := by
  rw [safe.eq_def]
  simp only [show (1#usize : Usize) ≠ 0#usize by decide, ↓reduceIte]
  rw [safe_loop1.eq_def]
  simp

end aivm_secrets_garrett_core.json_reflection.Proofs
