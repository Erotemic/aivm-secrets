import AivmSecretsGarrettCore
import GarrettHttpAuth

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.http_auth.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.http_request.Proofs

def ValidMethod (method : Slice U8) : Prop :=
  method.val = [71#u8, 69#u8, 84#u8] ∨
  method.val = [80#u8, 79#u8, 83#u8, 84#u8] ∨
  method.val = [80#u8, 65#u8, 84#u8, 67#u8, 72#u8]

@[step]
theorem slice_bytes_equal (a b : Slice U8) :
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b
      ⦃ out => out ↔ a.val = b.val ⦄ := by
  apply WP.spec_mono (core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 a b (by intro x y; simp))
  intro out exact_bytes
  simpa [Slice.eq_iff] using exact_bytes

theorem valid_method_contract (method : Slice U8) :
    valid_method method ⦃ out => out ↔ ValidMethod method ⦄ := by
  unfold valid_method
  step
  subst get
  step
  subst post
  step
  subst patch
  step
  by_cases is_get : b = true
  · simp only [is_get, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp only [true_iff]
    exact Or.inl (by simpa using b_post.mp is_get)
  · simp only [is_get, Bool.false_eq_true, ↓reduceIte]
    have not_get : method.val ≠ [71#u8, 69#u8, 84#u8] := by simpa using mt b_post.mpr is_get
    step
    by_cases is_post : b1 = true
    · simp only [is_post, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      simp only [true_iff]
      exact Or.inr (Or.inl (by simpa using b1_post.mp is_post))
    · simp only [is_post, Bool.false_eq_true, ↓reduceIte]
      have not_post : method.val ≠ [80#u8, 79#u8, 83#u8, 84#u8] := by
        simpa using mt b1_post.mpr is_post
      apply WP.spec_mono (slice_bytes_equal _ _)
      intro out exact_bytes
      simpa [ValidMethod, not_get, not_post] using exact_bytes

def TargetBytesFrom (bytes : Slice U8) (start : Nat) : Prop :=
  ∀ (index : Nat) (inside : index < bytes.length), start ≤ index →
    33 ≤ bytes[index].val ∧ bytes[index].val ≤ 126 ∧ bytes[index] ≠ 35#u8

def ValidTarget (target : Slice U8) : Prop :=
  0 < target.length ∧ target.length ≤ 8192 ∧
    target.val[0]? = some 47#u8 ∧ target.val[1]? ≠ some 47#u8 ∧ TargetBytesFrom target 0

theorem target_bytes_step (bytes : Slice U8) (start : Nat)
    (inside : start < bytes.length) :
    TargetBytesFrom bytes start ↔
      (33 ≤ bytes[start].val ∧ bytes[start].val ≤ 126 ∧ bytes[start] ≠ 35#u8) ∧
        TargetBytesFrom bytes (start + 1) := by
  constructor
  · intro all
    exact ⟨all start inside (by omega), fun i hi after => all i hi (by omega)⟩
  · rintro ⟨head, tail⟩ i hi after
    by_cases same : i = start
    · subst i; exact head
    · exact tail i hi (by omega)

/-- Charon clones the same source loop into two control-flow branches. This
    shared proof consumes each actual loop's generated unfolding equation. -/
theorem target_loop_contract
    (loop : core.slice.iter.Iter U8 → Result Bool)
    (equation : ∀ it, loop it = do
      let (value, next) ← core.slice.iter.IteratorSliceIter.next it
      match value with
      | none => Result.ok true
      | some byte =>
        if byte < 33#u8 then Result.ok false
        else if byte > 126#u8 then Result.ok false
        else if byte = 35#u8 then Result.ok false
        else loop next)
    (iter : core.slice.iter.Iter U8) :
    loop iter ⦃ out => out ↔ TargetBytesFrom iter.slice iter.i ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter U8), it.slice.length - it.i = n →
      loop it ⦃ out => out ↔ TargetBytesFrom it.slice it.i ⦄ from this _ iter rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [equation]
    by_cases inside : it.i < it.slice.length
    · have next_return : core.slice.iter.IteratorSliceIter.next it =
          Result.ok (some it.slice[it.i], {it with i := it.i + 1}) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
        rfl
      rw [next_return]
      simp only [bind_ok]
      change (if it.slice[it.i] < 33#u8 then Result.ok false
        else if it.slice[it.i] > 126#u8 then Result.ok false
        else if it.slice[it.i] = 35#u8 then Result.ok false
        else loop {it with i := it.i + 1}) ⦃ out => out ↔ TargetBytesFrom it.slice it.i ⦄
      by_cases low : it.slice[it.i] < 33#u8
      · simp only [low, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        simp only [Bool.false_eq_true, false_iff]
        intro all
        have byte := all it.i inside (Nat.le_refl _)
        scalar_tac
      · simp only [low, ↓reduceIte]
        by_cases high : it.slice[it.i] > 126#u8
        · simp only [high, ↓reduceIte]
          apply (WP.spec_ok _).mpr
          simp only [Bool.false_eq_true, false_iff]
          intro all
          have byte := all it.i inside (Nat.le_refl _)
          scalar_tac
        · simp only [high, ↓reduceIte]
          by_cases fragment : it.slice[it.i] = 35#u8
          · simp only [fragment, ↓reduceIte]
            apply (WP.spec_ok _).mpr
            simp only [Bool.false_eq_true, false_iff]
            intro all
            exact (all it.i inside (Nat.le_refl _)).2.2 fragment
          · simp only [fragment, ↓reduceIte]
            apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
              {it with i := it.i + 1} rfl)
            intro out tail
            have head : 33 ≤ it.slice[it.i].val ∧ it.slice[it.i].val ≤ 126 ∧
                it.slice[it.i] ≠ 35#u8 := by
              exact ⟨by scalar_tac, by scalar_tac, fragment⟩
            have step : TargetBytesFrom it.slice it.i ↔ TargetBytesFrom it.slice (it.i + 1) := by
              rw [target_bytes_step it.slice it.i inside]
              simp [head]
            exact tail.trans step.symm
    · have next_return : core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
      rw [next_return]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      simp only [true_iff]
      intro i hi after
      omega

theorem valid_target_loop0_contract (iter : core.slice.iter.Iter U8) :
    valid_target_loop0 iter ⦃ out => out ↔ TargetBytesFrom iter.slice iter.i ⦄ :=
  target_loop_contract valid_target_loop0 valid_target_loop0.eq_def iter

theorem valid_target_loop1_contract (iter : core.slice.iter.Iter U8) :
    valid_target_loop1 iter ⦃ out => out ↔ TargetBytesFrom iter.slice iter.i ⦄ :=
  target_loop_contract valid_target_loop1 valid_target_loop1.eq_def iter

theorem valid_target_contract (target : Slice U8) :
    valid_target target ⦃ out => out ↔ ValidTarget target ⦄ := by
  unfold valid_target
  by_cases empty : target.len = 0#usize
  · simp only [empty, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp only [Bool.false_eq_true, false_iff]
    intro valid
    have := valid.1
    scalar_tac
  · simp only [empty, ↓reduceIte]
    by_cases large : target.len > 8192#usize
    · simp only [large, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      simp only [Bool.false_eq_true, false_iff]
      intro valid
      have := valid.2.1
      scalar_tac
    · simp only [large, ↓reduceIte]
      have bounds : 0 < target.length ∧ target.length ≤ 8192 := by scalar_tac
      step
      have first_lookup : target.val[0]? = some i2 :=
        List.getElem?_eq_some_iff.mpr ⟨by scalar_tac, by simpa using i2_post.symm⟩
      by_cases wrong : i2 != 47#u8
      · simp only [wrong, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        simp only [Bool.false_eq_true, false_iff]
        intro valid
        have same : i2 = 47#u8 := Option.some.inj (first_lookup.symm.trans valid.2.2.1)
        simp [same] at wrong
      · simp only [wrong, Bool.false_eq_true, ↓reduceIte]
        have first : target.val[0]? = some 47#u8 := by
          have same : i2 = 47#u8 := by scalar_tac
          simpa [same] using first_lookup
        by_cases multiple : target.len > 1#usize
        · simp only [multiple, ↓reduceIte]
          step
          have second_lookup : target.val[1]? = some i4 :=
            List.getElem?_eq_some_iff.mpr ⟨by scalar_tac, by simpa using i4_post.symm⟩
          by_cases double : i4 = 47#u8
          · simp only [double, ↓reduceIte]
            apply (WP.spec_ok _).mpr
            simp only [Bool.false_eq_true, false_iff]
            intro valid
            exact valid.2.2.2.1 (by simpa [double] using second_lookup)
          · simp only [double, ↓reduceIte,
              SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
            apply WP.spec_mono (valid_target_loop0_contract ⟨target, 0⟩)
            intro out bytes
            have second : target.val[1]? ≠ some 47#u8 := by
              simpa [second_lookup] using double
            exact bytes.trans ⟨fun all => ⟨bounds.1, bounds.2, first, second, all⟩,
              fun valid => valid.2.2.2.2⟩
        · simp only [multiple, ↓reduceIte,
            SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
          apply WP.spec_mono (valid_target_loop1_contract ⟨target, 0⟩)
          intro out bytes
          have second : target.val[1]? ≠ some 47#u8 := by
            rw [List.getElem?_eq_none_iff.mpr (by scalar_tac)]
            simp
          exact bytes.trans ⟨fun all => ⟨bounds.1, bounds.2, first, second, all⟩,
            fun valid => valid.2.2.2.2⟩

/-- The only suffix after the caller-selected target is the literal protocol
    version and terminating CRLF. -/
def LineSuffix : List U8 :=
  [32#u8, 72#u8, 84#u8, 84#u8, 80#u8, 47#u8, 49#u8, 46#u8, 49#u8, 13#u8, 10#u8]

theorem invalid_line_leaves_buffer_unchanged (output : alloc.vec.Vec U8)
    (method target : Slice U8) (invalid : ¬ (ValidMethod method ∧ ValidTarget target)) :
    append_line output method target = Result.ok (.Err .InvalidLine, output) := by
  obtain ⟨method_ok, method_checked, method_iff⟩ := returned_of_spec (valid_method_contract method)
  unfold append_line
  rw [method_checked]
  simp only [bind_ok]
  by_cases admitted_method : method_ok = true
  · simp only [admitted_method, ↓reduceIte]
    obtain ⟨target_ok, target_checked, target_iff⟩ := returned_of_spec (valid_target_contract target)
    have denied : target_ok = false := by
      cases target_ok
      · rfl
      · exact False.elim (invalid ⟨method_iff.mp admitted_method, target_iff.mp rfl⟩)
    simp [target_checked, denied]
  · have denied : method_ok = false := by cases method_ok <;> simp_all
    simp [denied]

theorem accepted_line_exact (output : alloc.vec.Vec U8) (method target : Slice U8)
    (method_valid : ValidMethod method) (target_valid : ValidTarget target)
    (room : output.length + method.length + 1 + target.length + 11 ≤ Usize.max) :
    append_line output method target ⦃ out =>
      out.1 = .Ok () ∧ out.2.val = output.val ++ method.val ++ [32#u8] ++
        target.val ++ LineSuffix ⦄ := by
  obtain ⟨method_ok, method_checked, method_iff⟩ := returned_of_spec (valid_method_contract method)
  obtain ⟨target_ok, target_checked, target_iff⟩ := returned_of_spec (valid_target_contract target)
  have method_true : method_ok = true := method_iff.mpr method_valid
  have target_true : target_ok = true := target_iff.mpr target_valid
  unfold append_line
  rw [method_checked]
  simp only [bind_ok, method_true, ↓reduceIte, target_checked, target_true]
  step
  step
  subst s
  step
  step
  step
  subst s1
  step
  simp_all [LineSuffix, List.append_assoc]

theorem successful_line_requires_validation (output result : alloc.vec.Vec U8)
    (method target : Slice U8)
    (success : append_line output method target = Result.ok (.Ok (), result)) :
    ValidMethod method ∧ ValidTarget target := by
  by_contra invalid
  rw [invalid_line_leaves_buffer_unchanged output method target invalid] at success
  have impossible := congrArg Prod.fst (Result.ok_injective success)
  cases impossible

theorem valid_target_has_no_delimiters (target : Slice U8) (valid : ValidTarget target) :
    13#u8 ∉ target.val ∧ 10#u8 ∉ target.val ∧ 32#u8 ∉ target.val := by
  refine ⟨?_, ?_, ?_⟩
  all_goals
    intro occurrence
    obtain ⟨index, inside, equal⟩ := List.getElem_of_mem occurrence
    have byte := valid.2.2.2.2 index inside (Nat.zero_le _)
    change 33 ≤ target.val[index].val ∧ target.val[index].val ≤ 126 ∧
      target.val[index] ≠ 35#u8 at byte
    rw [equal] at byte
    scalar_tac

theorem line_has_only_fixed_delimiters (method target : Slice U8)
    (method_valid : ValidMethod method) (target_valid : ValidTarget target) :
    (method.val ++ [32#u8] ++ target.val ++ LineSuffix).count 13#u8 = 1 ∧
    (method.val ++ [32#u8] ++ target.val ++ LineSuffix).count 10#u8 = 1 ∧
    (method.val ++ [32#u8] ++ target.val ++ LineSuffix).count 32#u8 = 2 := by
  have forbidden := valid_target_has_no_delimiters target target_valid
  have no_cr := List.count_eq_zero.mpr forbidden.1
  have no_lf := List.count_eq_zero.mpr forbidden.2.1
  have no_space := List.count_eq_zero.mpr forbidden.2.2
  rcases method_valid with get | post | patch <;>
    simp_all [LineSuffix]

theorem accepted_line_cannot_split (output : alloc.vec.Vec U8) (method target : Slice U8)
    (method_valid : ValidMethod method) (target_valid : ValidTarget target)
    (room : output.length + method.length + 1 + target.length + 11 ≤ Usize.max) :
    append_line output method target ⦃ out =>
      out.1 = .Ok () ∧ out.2.val.take output.length = output.val ∧
      (out.2.val.drop output.length).count 13#u8 = 1 ∧
      (out.2.val.drop output.length).count 10#u8 = 1 ∧
      (out.2.val.drop output.length).count 32#u8 = 2 ⦄ := by
  apply WP.spec_mono (accepted_line_exact output method target method_valid target_valid room)
  intro out exact_bytes
  refine ⟨exact_bytes.1, ?_, ?_⟩
  · simp [exact_bytes.2]
  · simpa [exact_bytes.2, List.drop_append] using
      line_has_only_fixed_delimiters method target method_valid target_valid

def witnessMethod : Slice U8 := Slice.from [71#u8, 69#u8, 84#u8] (by scalar_tac)
def witnessTarget : Slice U8 := Slice.from [47#u8] (by scalar_tac)

theorem valid_line_positive_witness : ValidMethod witnessMethod ∧ ValidTarget witnessTarget := by
  constructor
  · exact Or.inl (by rfl)
  · unfold ValidTarget
    refine ⟨by simp [witnessTarget], by simp [witnessTarget], by simp [witnessTarget],
      by simp [witnessTarget], ?_⟩
    intro index inside after
    have zero : index = 0 := by
      simp [witnessTarget] at inside
      omega
    subst index
    simp [witnessTarget]

theorem successful_line_witness :
    ∃ result, append_line (alloc.vec.Vec.new U8) witnessMethod witnessTarget =
      Result.ok (.Ok (), result) ∧
      result.val = witnessMethod.val ++ [32#u8] ++ witnessTarget.val ++ LineSuffix := by
  obtain ⟨out, returned, success, wire⟩ := returned_of_spec
    (accepted_line_exact (alloc.vec.Vec.new U8) witnessMethod witnessTarget
      valid_line_positive_witness.1 valid_line_positive_witness.2
      (by simp [witnessMethod, witnessTarget]; scalar_tac))
  refine ⟨out.2, ?_, ?_⟩
  · have pair : out = (.Ok (), out.2) := Prod.ext success rfl
    rw [pair] at returned
    exact returned
  · simpa [List.append_assoc] using wire

end aivm_secrets_garrett_core.http_request.Proofs
