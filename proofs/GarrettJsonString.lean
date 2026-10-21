import GarrettJsonStringScalar

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.json_string.Proofs

def ValidFrom (values : alloc.vec.Vec U32) (start : Nat) : Prop :=
  ∀ (i : Nat) (inside : i < values.length), start ≤ i → Scalar (values.val[i]'inside).val

def BodyBytes (values : List U32) : List U8 := values.flatMap (fun value => Escape value.val)
def StringBytes (values : List U32) : List U8 := [34#u8] ++ BodyBytes values ++ [34#u8]

theorem valid_from_step (values : alloc.vec.Vec U32) (start : Nat) (inside : start < values.length) :
    ValidFrom values start ↔ Scalar (values.val[start]'inside).val ∧ ValidFrom values (start + 1) := by
  constructor
  · intro valid
    exact ⟨valid start inside (Nat.le_refl _), fun i hi after => valid i hi (by omega)⟩
  · rintro ⟨first, rest⟩ i hi after
    by_cases same : i = start
    · subst i; exact first
    · exact rest i hi (by omega)

@[step] theorem valid_text_loop_contract (values : alloc.vec.Vec U32) (index : Usize) :
    valid_text_loop values index ⦃ out => out ↔ ValidFrom values index.val ⦄ := by
  suffices ∀ n (position : Usize), values.length - position.val = n →
      valid_text_loop values position ⦃ out => out ↔ ValidFrom values position.val ⦄ from this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro position measure
    rw [valid_text_loop.eq_def]
    by_cases inside : position < alloc.vec.Vec.len values
    · simp only [inside, ↓reduceIte]
      have within : position.val < values.length := by scalar_tac
      step (config := {scalarTac := true, simpStar := true})
      apply WP.spec_bind (valid_scalar_contract i1)
      intro accepted equivalent
      cases accepted with
      | false =>
        simp only [Bool.false_eq_true, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        simp only [Bool.false_eq_true, false_iff]
        intro valid
        have first := valid position.val within (Nat.le_refl _)
        have invalid : ¬Scalar i1.val := by simpa using equivalent
        apply invalid
        simp_all
      | true =>
        simp only [↓reduceIte]
        have first : Scalar i1.val := equivalent.mp rfl
        step (config := {scalarTac := true, simpStar := true})
        apply WP.spec_mono (ih (values.length - index1.val) (by scalar_tac) index1 rfl)
        intro out rest
        have next : index1.val = position.val + 1 := by scalar_tac
        rw [valid_from_step values position.val within]
        simp_all
    · simp only [inside, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      simp only [true_iff]
      intro i hi after
      scalar_tac

@[step] theorem valid_text_contract (values : alloc.vec.Vec U32) :
    valid_text values ⦃ out => out ↔ ValidFrom values 0 ⦄ := by
  simpa [valid_text] using valid_text_loop_contract values 0#usize

theorem body_length_bound (values : List U32) : (BodyBytes values).length ≤ 12 * values.length := by
  induction values with
  | nil => simp [BodyBytes]
  | cons value values ih =>
    have bound := escape_length value.val
    simp only [BodyBytes, List.flatMap_cons, List.length_append, List.length_cons]
    change (Escape value.val).length + (BodyBytes values).length ≤ 12 * (values.length + 1)
    omega

theorem body_bytes_step (values : alloc.vec.Vec U32) (index : Nat) (inside : index < values.length) :
    BodyBytes (values.val.drop index) = Escape (values.val[index]'inside).val ++ BodyBytes (values.val.drop (index + 1)) := by
  rw [List.drop_eq_getElem_cons inside]
  rfl

@[step] theorem append_loop_contract (output : alloc.vec.Vec U8) (values : alloc.vec.Vec U32) (index : Usize)
    (valid : ValidFrom values index.val)
    (room : output.length + 12 * (values.length - index.val) ≤ Usize.max) :
    append_loop output values index ⦃ out =>
      out.val = output.val ++ BodyBytes (values.val.drop index.val) ∧
      out.length = output.length + (BodyBytes (values.val.drop index.val)).length ⦄ := by
  suffices ∀ n (position : Usize), values.length - position.val = n →
      ∀ (buffer : alloc.vec.Vec U8), ValidFrom values position.val →
      buffer.length + 12 * (values.length - position.val) ≤ Usize.max →
      append_loop buffer values position ⦃ out =>
        out.val = buffer.val ++ BodyBytes (values.val.drop position.val) ∧
        out.length = buffer.length + (BodyBytes (values.val.drop position.val)).length ⦄ from
    this _ index rfl output valid room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro position measure buffer valid space
    rw [append_loop.eq_def]
    by_cases inside : position < alloc.vec.Vec.len values
    · simp only [inside, ↓reduceIte]
      have within : position.val < values.length := by scalar_tac
      step (config := {scalarTac := true, simpStar := true})
      have scalar : Scalar i1.val := by
        have first := valid position.val within (Nat.le_refl _)
        simp_all
      apply WP.spec_bind (append_scalar_contract buffer i1 scalar (by scalar_tac))
      intro next exact_bytes
      step (config := {scalarTac := true, simpStar := true})
      have next_index : index1.val = position.val + 1 := by scalar_tac
      have next_valid : ValidFrom values index1.val := by
        intro i hi after
        apply valid i hi
        omega
      have bound := escape_length i1.val
      have next_room : next.length + 12 * (values.length - index1.val) ≤ Usize.max := by scalar_tac
      apply WP.spec_mono (ih (values.length - index1.val) (by scalar_tac) index1 rfl next next_valid next_room)
      intro out result
      rw [body_bytes_step values position.val within]
      simp_all [List.append_assoc, List.length_append]
    · simp only [inside, ↓reduceIte]
      have ended : values.length ≤ position.val := by scalar_tac
      apply (WP.spec_ok _).mpr
      simp [List.drop_eq_nil_of_le ended, BodyBytes]

/-- Successful string construction is exact quoting of every accepted scalar;
invalid input is rejected before any mutation, including a late invalid unit. -/
theorem quote_contract (output : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (room : output.length + 12 * values.length + 2 ≤ Usize.max) :
    append output values ⦃ out =>
      (out.1 = true ↔ ValidFrom values 0) ∧
      (out.1 = false → out.2 = output) ∧
      (out.1 = true → out.2.val = output.val ++ StringBytes values.val) ⦄ := by
  obtain ⟨accepted, checked, equivalent⟩ := returned_of_spec (valid_text_contract values)
  unfold append
  rw [checked]
  simp only [bind_ok]
  cases accepted with
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp_all
  | true =>
    simp only [↓reduceIte]
    have valid : ValidFrom values 0 := equivalent.mp rfl
    step (config := {scalarTac := true, simpStar := true})
    apply WP.spec_bind (append_loop_contract output1 values 0#usize valid (by scalar_tac))
    intro encoded property
    have payload : encoded.val = output1.val ++ BodyBytes values.val ∧
        encoded.length = output1.length + (BodyBytes values.val).length := by simpa using property
    obtain ⟨payload_bytes, payload_length⟩ := payload
    have bound : (BodyBytes values.val).length ≤ 12 * values.length := body_length_bound values.val
    have closing_room : encoded.length < Usize.max := by omega
    step (config := {scalarTac := true, simpStar := true})
    simp_all [StringBytes, List.append_assoc]

theorem invalid_text_preserves_buffer (output : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (invalid : ¬ValidFrom values 0) : append output values = Result.ok (false, output) := by
  obtain ⟨accepted, checked, equivalent⟩ := returned_of_spec (valid_text_contract values)
  have refused : accepted = false := by cases accepted <;> simp_all
  simp [append, checked, refused]

theorem success_requires_valid_text (output result : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (returned : append output values = Result.ok (true, result)) : ValidFrom values 0 := by
  by_contra invalid
  rw [invalid_text_preserves_buffer output values invalid] at returned
  have impossible := congrArg Prod.fst (Result.ok_injective returned)
  cases impossible

theorem accepted_quote_exact (output : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (valid : ValidFrom values 0) (room : output.length + 12 * values.length + 2 ≤ Usize.max) :
    append output values ⦃ out => out.1 = true ∧ out.2.val = output.val ++ StringBytes values.val ⦄ := by
  apply WP.spec_mono (quote_contract output values room)
  intro out property
  have accepted : out.1 = true := property.1.mpr valid
  exact ⟨accepted, property.2.2 accepted⟩

theorem returned_quote_exact (output result : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (returned : append output values = Result.ok (true, result))
    (room : output.length + 12 * values.length + 2 ≤ Usize.max) :
    result.val = output.val ++ StringBytes values.val := by
  have property := accepted_quote_exact output values (success_requires_valid_text output result values returned) room
  rw [returned] at property
  simp only [WP.spec_ok] at property
  exact property.2

theorem accepted_quote_witness (output : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (valid : ValidFrom values 0) (room : output.length + 12 * values.length + 2 ≤ Usize.max) :
    ∃ result, append output values = Result.ok (true, result) ∧
      result.val = output.val ++ StringBytes values.val := by
  obtain ⟨⟨accepted, result⟩, returned, property⟩ := returned_of_spec (accepted_quote_exact output values valid room)
  obtain ⟨rfl, bytes⟩ := property
  exact ⟨result, returned, bytes⟩

theorem body_printable (values : List U32) : Printable (BodyBytes values) := by
  induction values with
  | nil => simp [BodyBytes, Printable]
  | cons value rest ih =>
    change Printable (Escape value.val ++ BodyBytes rest)
    exact (printable_append _ _).mpr ⟨escape_printable value.val, ih⟩

theorem string_printable (values : List U32) : Printable (StringBytes values) := by
  have quote : Printable [34#u8] := by simp [Printable]
  exact (printable_append _ _).mpr ⟨(printable_append _ _).mpr ⟨quote, body_printable values⟩, quote⟩

theorem returned_quote_printable (output result : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (returned : append output values = Result.ok (true, result))
    (room : output.length + 12 * values.length + 2 ≤ Usize.max) :
    Printable (result.val.drop output.length) := by
  rw [returned_quote_exact output result values returned room]
  simpa using string_printable values.val

theorem returned_quote_has_no_line_breaks (output result : alloc.vec.Vec U8) (values : alloc.vec.Vec U32)
    (returned : append output values = Result.ok (true, result))
    (room : output.length + 12 * values.length + 2 ≤ Usize.max) :
    10#u8 ∉ result.val.drop output.length ∧ 13#u8 ∉ result.val.drop output.length := by
  have printable := returned_quote_printable output result values returned room
  constructor
  · intro member
    have bounds := printable 10#u8 member
    scalar_tac
  · intro member
    have bounds := printable 13#u8 member
    scalar_tac

end aivm_secrets_garrett_core.json_string.Proofs
