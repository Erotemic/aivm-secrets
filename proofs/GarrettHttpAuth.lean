import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.http_auth.Proofs

def VisibleFrom (bytes : Slice U8) (start : Nat) : Prop :=
  ∀ (index : Nat) (inside : index < bytes.length), start ≤ index →
    33 ≤ bytes[index].val ∧ bytes[index].val ≤ 126

def ValidCredential (secret : Slice U8) : Prop :=
  0 < secret.length ∧ secret.length ≤ 4096 ∧ VisibleFrom secret 0

theorem visible_from_step (bytes : Slice U8) (start : Nat)
    (inside : start < bytes.length) :
    VisibleFrom bytes start ↔
      (33 ≤ bytes[start].val ∧ bytes[start].val ≤ 126) ∧ VisibleFrom bytes (start + 1) := by
  constructor
  · intro all
    exact ⟨all start inside (by omega), fun i hi after => all i hi (by omega)⟩
  · rintro ⟨head, tail⟩ i hi after
    by_cases same : i = start
    · subst i; exact head
    · exact tail i hi (by omega)

theorem valid_credential_loop_contract (iter : core.slice.iter.Iter U8) :
    valid_credential_loop iter ⦃ out => out ↔ VisibleFrom iter.slice iter.i ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter U8), it.slice.length - it.i = n →
      valid_credential_loop it ⦃ out => out ↔ VisibleFrom it.slice it.i ⦄ from
    this _ iter rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [valid_credential_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have next_return : core.slice.iter.IteratorSliceIter.next it =
          Result.ok (some it.slice[it.i], { it with i := it.i + 1 }) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
        rfl
      rw [next_return]
      simp only [bind_ok]
      change (if it.slice[it.i] < 33#u8 then Result.ok false
        else if it.slice[it.i] > 126#u8 then Result.ok false
        else valid_credential_loop {it with i := it.i + 1})
          ⦃ out => out ↔ VisibleFrom it.slice it.i ⦄
      by_cases low : it.slice[it.i] < 33#u8
      · simp only [low, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        simp only [Bool.false_eq_true, false_iff]
        intro all
        have byte := all it.i (by scalar_tac) (Nat.le_refl _)
        scalar_tac
      · simp only [low, ↓reduceIte]
        by_cases high : it.slice[it.i] > 126#u8
        · simp only [high, ↓reduceIte]
          apply (WP.spec_ok _).mpr
          simp only [Bool.false_eq_true, false_iff]
          intro all
          have byte := all it.i (by scalar_tac) (Nat.le_refl _)
          scalar_tac
        · simp only [high, ↓reduceIte]
          apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
            { it with i := it.i + 1 } rfl)
          intro out tail
          have head : 33 ≤ it.slice[it.i].val ∧ it.slice[it.i].val ≤ 126 := by scalar_tac
          have step : VisibleFrom it.slice it.i ↔ VisibleFrom it.slice (it.i + 1) := by
            rw [visible_from_step it.slice it.i (by scalar_tac)]
            simp [head]
          exact tail.trans step.symm
    · have next_return : core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
      rw [next_return]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      simp only [true_iff]
      intro i hi after
      have bound : it.slice.length ≤ it.i := by scalar_tac
      omega

theorem valid_credential_contract (secret : Slice U8) :
    valid_credential secret ⦃ out => out ↔ ValidCredential secret ⦄ := by
  unfold valid_credential
  by_cases empty : secret.len = 0#usize
  · simp only [empty, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp only [Bool.false_eq_true, false_iff]
    intro valid
    have := valid.1
    scalar_tac
  · simp only [empty, ↓reduceIte]
    by_cases large : secret.len > 4096#usize
    · simp only [large, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      simp only [Bool.false_eq_true, false_iff]
      intro valid
      have := valid.2.1
      scalar_tac
    · simp only [large, ↓reduceIte,
        SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
      apply WP.spec_mono (valid_credential_loop_contract ⟨secret, 0⟩)
      intro out visible
      have bounds : 0 < secret.length ∧ secret.length ≤ 4096 := by scalar_tac
      simpa [ValidCredential, bounds] using visible

@[step]
theorem extend_bytes_contract (output : alloc.vec.Vec U8) (bytes : Slice U8)
    (room : output.length + bytes.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 output bytes
      ⦃ out => out.val = output.val ++ bytes.val ∧
          out.length = output.length + bytes.length ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  rw [dite_eq_left room]
  apply WP.spec_bind (List.clone_spec (clone := core.clone.CloneU8.clone)
    (l := bytes.val) (by intro x hx; simp))
  intro cloned exact_copy
  simp [exact_copy.1]

/-- Literal ASCII prefixes, including the separating space. -/
def HeaderPrefix : credential_use.Authentication → List U8
  | .Bearer => [65#u8, 117#u8, 116#u8, 104#u8, 111#u8, 114#u8, 105#u8,
      122#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8, 58#u8, 32#u8,
      66#u8, 101#u8, 97#u8, 114#u8, 101#u8, 114#u8, 32#u8]
  | .ApiKey => [88#u8, 45#u8, 65#u8, 80#u8, 73#u8, 45#u8, 75#u8,
      101#u8, 121#u8, 58#u8, 32#u8]

theorem invalid_credential_leaves_buffer_unchanged (output : alloc.vec.Vec U8)
    (secret : Slice U8) (authentication : credential_use.Authentication)
    (invalid : ¬ ValidCredential secret) :
    append_header output secret authentication =
      Result.ok (.Err .InvalidCredential, output) := by
  obtain ⟨accepted, checked, equivalent⟩ := returned_of_spec (valid_credential_contract secret)
  have denied : accepted = false := by cases accepted <;> simp_all
  simp [append_header, checked, denied]

theorem accepted_header_exact (output : alloc.vec.Vec U8) (secret : Slice U8)
    (authentication : credential_use.Authentication) (valid : ValidCredential secret)
    (room : output.length + 22 + secret.length + 2 ≤ Usize.max) :
    append_header output secret authentication ⦃ out =>
      out.1 = .Ok () ∧ out.2.val =
        output.val ++ HeaderPrefix authentication ++ secret.val ++ [13#u8, 10#u8] ⦄ := by
  obtain ⟨accepted, checked, equivalent⟩ := returned_of_spec (valid_credential_contract secret)
  have admitted : accepted = true := equivalent.mpr valid
  unfold append_header
  rw [checked]
  simp only [bind_ok, admitted, ↓reduceIte]
  cases authentication <;> simp only [HeaderPrefix]
  all_goals
    step
    subst output1
    step
    step
    step
    step
    simp_all [List.append_assoc]

theorem valid_credential_has_no_crlf (secret : Slice U8) (valid : ValidCredential secret) :
    13#u8 ∉ secret.val ∧ 10#u8 ∉ secret.val := by
  constructor
  all_goals
    intro occurrence
    obtain ⟨index, inside, equal⟩ := List.getElem_of_mem occurrence
    have byte := valid.2.2 index inside (Nat.zero_le _)
    change 33 ≤ secret.val[index].val ∧ secret.val[index].val ≤ 126 at byte
    rw [equal] at byte
    scalar_tac

theorem header_is_single_line (secret : Slice U8)
    (authentication : credential_use.Authentication) (valid : ValidCredential secret) :
    (HeaderPrefix authentication ++ secret.val ++ [13#u8, 10#u8]).count 10#u8 = 1 ∧
    (HeaderPrefix authentication ++ secret.val ++ [13#u8, 10#u8]).count 13#u8 = 1 := by
  have forbidden := valid_credential_has_no_crlf secret valid
  have no_lf := List.count_eq_zero.mpr forbidden.2
  have no_cr := List.count_eq_zero.mpr forbidden.1
  cases authentication <;> simp [HeaderPrefix, no_lf, no_cr]

/-- Only the appended header is counted; the caller's preceding HTTP fields
    already contain line endings and are preserved byte-for-byte. -/
theorem accepted_header_cannot_split (output : alloc.vec.Vec U8) (secret : Slice U8)
    (authentication : credential_use.Authentication) (valid : ValidCredential secret)
    (room : output.length + 22 + secret.length + 2 ≤ Usize.max) :
    append_header output secret authentication ⦃ out =>
      out.1 = .Ok () ∧ out.2.val.take output.length = output.val ∧
      (out.2.val.drop output.length).count 10#u8 = 1 ∧
      (out.2.val.drop output.length).count 13#u8 = 1 ⦄ := by
  apply WP.spec_mono (accepted_header_exact output secret authentication valid room)
  intro out exact_bytes
  refine ⟨exact_bytes.1, ?_, ?_⟩
  · simp [exact_bytes.2]
  · simpa [exact_bytes.2, List.drop_append] using header_is_single_line secret authentication valid

/-- This implication needs no allocation/capacity premise: a rejected value
    cannot be reported as a successful authentication-header construction. -/
theorem successful_header_requires_valid_credential (output result : alloc.vec.Vec U8)
    (secret : Slice U8) (authentication : credential_use.Authentication)
    (success : append_header output secret authentication = Result.ok (.Ok (), result)) :
    ValidCredential secret := by
  by_contra invalid
  rw [invalid_credential_leaves_buffer_unchanged output secret authentication invalid] at success
  have impossible := congrArg Prod.fst (Result.ok_injective success)
  cases impossible

def witnessSecret : Slice U8 := Slice.from [84#u8] (by scalar_tac)

theorem valid_credential_positive_witness : ValidCredential witnessSecret := by
  unfold ValidCredential
  refine ⟨by simp [witnessSecret], by simp [witnessSecret], ?_⟩
  intro index inside after
  have zero : index = 0 := by
    simp [witnessSecret] at inside
    omega
  subst index
  simp [witnessSecret]

theorem successful_header_witness (authentication : credential_use.Authentication) :
    ∃ result, append_header (alloc.vec.Vec.new U8) witnessSecret authentication =
      Result.ok (.Ok (), result) ∧
      result.val = HeaderPrefix authentication ++ [84#u8, 13#u8, 10#u8] := by
  obtain ⟨out, returned, success, wire⟩ := returned_of_spec
    (accepted_header_exact (alloc.vec.Vec.new U8) witnessSecret authentication
      valid_credential_positive_witness (by simp [witnessSecret]; scalar_tac))
  refine ⟨out.2, ?_, ?_⟩
  · have pair : out = (.Ok (), out.2) := Prod.ext success rfl
    rw [pair] at returned
    exact returned
  · simpa [witnessSecret, List.append_assoc] using wire

end aivm_secrets_garrett_core.http_auth.Proofs
