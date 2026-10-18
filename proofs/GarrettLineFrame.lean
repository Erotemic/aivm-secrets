import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 1000000

namespace aivm_secrets_garrett_core.line_frame.Proofs

/-- Exactly one final newline. The payload is opaque to this framing primitive. -/
def CompleteLine (bytes : List U8) : Prop :=
  ∃ payload, bytes = payload ++ [10#u8] ∧ 10#u8 ∉ payload

theorem complete_line_nil : ¬CompleteLine [] := by
  rintro ⟨payload, impossible, _⟩
  have := congrArg List.length impossible
  simp at this

theorem complete_line_cons (byte : U8) (rest : List U8) :
    CompleteLine (byte :: rest) ↔
      if byte = 10#u8 then rest = [] else CompleteLine rest := by
  by_cases newline : byte = 10#u8
  · simp only [newline, ↓reduceIte]
    constructor
    · rintro ⟨payload, exact_bytes, no_newline⟩
      cases payload with
      | nil => simpa using exact_bytes
      | cons head tail =>
        simp only [List.cons_append, List.cons.injEq] at exact_bytes
        exact False.elim (no_newline (by simp [←exact_bytes.1]))
    · intro empty
      subst rest
      exact ⟨[], rfl, by simp⟩
  · simp only [newline, ↓reduceIte]
    constructor
    · rintro ⟨payload, exact_bytes, no_newline⟩
      cases payload with
      | nil =>
        simp only [List.nil_append, List.cons.injEq] at exact_bytes
        exact False.elim (newline exact_bytes.1)
      | cons head tail =>
        simp only [List.cons_append, List.cons.injEq] at exact_bytes
        exact ⟨tail, exact_bytes.2, fun member => no_newline (List.mem_cons_of_mem _ member)⟩
    · rintro ⟨payload, exact_bytes, no_newline⟩
      refine ⟨byte :: payload, by simp [exact_bytes], ?_⟩
      intro member
      rcases List.mem_cons.mp member with first | later
      · exact newline first.symm
      · exact no_newline later

theorem index_exact (data : Slice U8) (index : Usize)
    (inside : index.val < data.length) :
    Slice.index_usize data index = Result.ok (data.val[index.val]'inside) := by
  obtain ⟨value, returned, exact_value⟩ := returned_of_spec (Slice.index_usize_spec data index inside)
  simpa only [exact_value] using returned

@[step]
theorem complete_loop_contract (data : Slice U8) (index : Usize) :
    complete_loop data index ⦃ out => out ↔ CompleteLine (data.val.drop index.val) ⦄ := by
  suffices ∀ n (i : Usize), data.length - i.val = n →
      complete_loop data i ⦃ out => out ↔ CompleteLine (data.val.drop i.val) ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [complete_loop.eq_def]
    by_cases inside : i.val < data.length
    · have scalar_inside : i < data.len := by scalar_tac
      simp only [scalar_inside, ↓reduceIte, index_exact data i inside, bind_ok]
      have tail : data.val.drop i.val = (data.val[i.val]'inside) :: data.val.drop (i.val + 1) :=
        List.drop_eq_getElem_cons inside
      by_cases newline : (data.val[i.val]'inside) = 10#u8
      · simp only [newline, ↓reduceIte]
        step
        rw [tail, complete_line_cons]
        simp only [decide_eq_true_eq, newline, ↓reduceIte, List.drop_eq_nil_iff]
        scalar_tac
      · simp only [newline, ↓reduceIte]
        step
        apply WP.spec_mono (ih (data.length - i3.val) (by scalar_tac) i3 (by rfl))
        intro out exact_tail
        rw [tail, complete_line_cons]
        simpa only [newline, ↓reduceIte, i3_post] using exact_tail
    · have scalar_outside : ¬i < data.len := by scalar_tac
      simp only [scalar_outside, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      simp only [Bool.false_eq_true, false_iff]
      rw [List.drop_eq_nil_of_le (by scalar_tac)]
      exact complete_line_nil

/-- Admission includes the bytes already read beyond the first line. -/
def Admitted (data buffered : Slice U8) (limit : Usize) : Prop :=
  data.length ≤ limit.val ∧ buffered.length = 0 ∧ CompleteLine data.val

@[step]
theorem complete_contract (data buffered : Slice U8) (limit : Usize) :
    complete data buffered limit ⦃ out => out ↔ Admitted data buffered limit ⦄ := by
  unfold complete
  by_cases large : data.len > limit
  · simp only [large, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp only [Bool.false_eq_true, false_iff]
    intro valid
    have := valid.1
    scalar_tac
  · simp only [large, ↓reduceIte]
    by_cases pending : buffered.len != 0#usize
    · simp only [pending, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      simp only [Bool.false_eq_true, false_iff]
      intro valid
      have := valid.2.1
      scalar_tac
    · simp only [pending]
      apply WP.spec_mono (complete_loop_contract data 0#usize)
      intro out exact_line
      have fits : data.length ≤ limit.val := by scalar_tac
      have empty : buffered.length = 0 := by scalar_tac
      simpa [Admitted, fits, empty] using exact_line

theorem accepted_exact (data buffered : Slice U8) (limit : Usize)
    (accepted : complete data buffered limit = Result.ok true) :
    data.length ≤ limit.val ∧ buffered.length = 0 ∧
      ∃ payload, data.val = payload ++ [10#u8] ∧ 10#u8 ∉ payload := by
  have contract := complete_contract data buffered limit
  rw [accepted] at contract
  exact ((WP.spec_ok _).mp contract).mp rfl

theorem rejected_buffered_suffix (data buffered : Slice U8) (limit : Usize)
    (pending : buffered.length ≠ 0) : complete data buffered limit = Result.ok false := by
  obtain ⟨out, returned, contract⟩ := returned_of_spec (complete_contract data buffered limit)
  have false_result : out = false := by
    cases out with
    | false => rfl
    | true => exact False.elim (pending (contract.mp rfl).2.1)
  simpa only [false_result] using returned

theorem rejected_without_newline (data buffered : Slice U8) (limit : Usize)
    (absent : 10#u8 ∉ data.val) : complete data buffered limit = Result.ok false := by
  obtain ⟨out, returned, contract⟩ := returned_of_spec (complete_contract data buffered limit)
  have false_result : out = false := by
    cases out with
    | false => rfl
    | true =>
      obtain ⟨payload, exact_bytes, _⟩ := (contract.mp rfl).2.2
      exact False.elim (absent (by simp [exact_bytes]))
  simpa only [false_result] using returned

theorem accepted_positive_witness :
    ∃ (data buffered : Slice U8) (limit : Usize),
      complete data buffered limit = Result.ok true := by
  let data := Slice.from [123#u8, 125#u8, 10#u8] (by scalar_tac)
  let buffered := Slice.from ([] : List U8) (by scalar_tac)
  obtain ⟨out, returned, contract⟩ := returned_of_spec (complete_contract data buffered 3#usize)
  have admitted : Admitted data buffered 3#usize := by
    refine ⟨by simp [data], by simp [buffered], ?_⟩
    exact ⟨[123#u8, 125#u8], by simp [data], by decide⟩
  have positive : out = true := contract.mpr admitted
  exact ⟨data, buffered, 3#usize, by simpa only [positive] using returned⟩

end aivm_secrets_garrett_core.line_frame.Proofs
