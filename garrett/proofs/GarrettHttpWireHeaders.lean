import GarrettStatelessCore
import GarrettFoundation

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.http_wire.Proofs

def CaseFold (n : Nat) : Nat := if 65 ≤ n ∧ n ≤ 90 then n + 32 else n

def AlphaNumeric (byte : U8) : Prop :=
  (97 ≤ byte.val ∧ byte.val ≤ 122) ∨ (65 ≤ byte.val ∧ byte.val ≤ 90) ∨
    (48 ≤ byte.val ∧ byte.val ≤ 57)

@[step]
theorem ascii_lower_contract (byte : U8) :
    ascii_lower byte ⦃ out => out.val = CaseFold byte.val ⦄ := by
  unfold ascii_lower
  by_cases low : byte ≥ 65#u8
  · by_cases high : byte ≤ 90#u8
    · simp only [low, high, ↓reduceIte]
      step
      unfold CaseFold
      split <;> scalar_tac
    · simp only [low, high, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      unfold CaseFold
      split <;> scalar_tac
  · simp only [low, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    unfold CaseFold
    split <;> scalar_tac

@[step]
theorem alphanumeric_contract (byte : U8) :
    alphanumeric byte ⦃ out => out ↔ AlphaNumeric byte ⦄ := by
  unfold alphanumeric
  repeat' split
  all_goals simp only [WP.spec_ok, AlphaNumeric]
  all_goals scalar_tac

def PrefixTail (bytes needle : Slice U8) (start : Nat) : Prop :=
  ∀ (i : Nat) (hn : i < bytes.length) (hp : i < needle.length), start ≤ i →
    CaseFold (bytes.val[i]'hn).val = CaseFold (needle.val[i]'hp).val

def FoldedPrefix (bytes needle : Slice U8) : Prop :=
  needle.length ≤ bytes.length ∧ PrefixTail bytes needle 0

theorem prefix_tail_step (bytes needle : Slice U8) (start : Nat)
    (hn : start < bytes.length) (hp : start < needle.length) :
    PrefixTail bytes needle start ↔
      CaseFold (bytes.val[start]'hn).val = CaseFold (needle.val[start]'hp).val ∧ PrefixTail bytes needle (start + 1) := by
  constructor
  · intro tail
    exact ⟨tail start hn hp (Nat.le_refl _), fun i ni pi after => tail i ni pi (by omega)⟩
  · rintro ⟨first, rest⟩ i ni pi after
    by_cases same : i = start
    · subst i; exact first
    · exact rest i ni pi (by omega)

@[step]
theorem ascii_prefix_loop_contract (bytes needle : Slice U8) (index : Usize)
    (bound : needle.length ≤ bytes.length) :
    ascii_prefix_loop bytes needle index ⦃ out => out ↔ PrefixTail bytes needle index.val ⦄ := by
  suffices ∀ n (i : Usize), needle.length - i.val = n →
      ascii_prefix_loop bytes needle i ⦃ out => out ↔ PrefixTail bytes needle i.val ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [ascii_prefix_loop.eq_def]
    by_cases inside : i.val < needle.length
    · have within : i.val < bytes.length := by omega
      have scalar_inside : i < Slice.len needle := by scalar_tac
      simp only [scalar_inside, ↓reduceIte]
      step
      step
      step
      step
      by_cases same : i3 = i5
      · simp only [same, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
        step
        have smaller : needle.length - i6.val < n := by scalar_tac
        apply WP.spec_mono (ih (needle.length - i6.val) smaller i6 rfl)
        intro out rest
        have first : CaseFold (bytes.val[i.val]'within).val = CaseFold (needle.val[i.val]'inside).val := by
          calc
            _ = i3.val := by simpa [i2_post] using i3_post.symm
            _ = i5.val := congrArg UScalar.val same
            _ = _ := by simpa only [i4_post] using i5_post
        have next : i6.val = i.val + 1 := by scalar_tac
        rw [next] at rest
        rw [prefix_tail_step bytes needle i.val within inside]
        simpa [first] using rest
      · have different : (i3 != i5) = true := by simpa only [bne_iff_ne] using same
        simp only [different, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        simp only [Bool.false_eq_true, false_iff]
        intro tail
        have equal := tail i.val within inside (Nat.le_refl _)
        apply same
        apply UScalar.eq_of_val_eq
        simp_all
    · have outside : ¬i < Slice.len needle := by scalar_tac
      simp only [outside, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      simp only [true_iff]
      intro j nj pj after
      omega

@[step]
theorem ascii_prefix_contract (bytes needle : Slice U8) :
    ascii_prefix bytes needle ⦃ out => out ↔ FoldedPrefix bytes needle ⦄ := by
  unfold ascii_prefix
  by_cases short : bytes.length < needle.length
  · have check : Slice.len bytes < Slice.len needle := by scalar_tac
    simp only [check, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp only [Bool.false_eq_true, false_iff]
    intro valid; have := valid.1; omega
  · have check : ¬Slice.len bytes < Slice.len needle := by scalar_tac
    simp only [check, ↓reduceIte]
    apply WP.spec_mono (ascii_prefix_loop_contract bytes needle 0#usize (by omega))
    intro out tail
    simpa [FoldedPrefix, Nat.le_of_not_gt short] using tail

def FoldedEqual (bytes other : Slice U8) : Prop :=
  bytes.length = other.length ∧ PrefixTail bytes other 0

@[step]
theorem ascii_equal_contract (bytes other : Slice U8) :
    ascii_equal bytes other ⦃ out => out ↔ FoldedEqual bytes other ⦄ := by
  unfold ascii_equal
  by_cases same : bytes.length = other.length
  · have checked : Slice.len bytes = Slice.len other := by
      apply UScalar.eq_of_val_eq; simpa using same
    simp only [checked, ↓reduceIte]
    apply WP.spec_mono (ascii_prefix_contract bytes other)
    intro out relation
    simpa [FoldedEqual, FoldedPrefix, same] using relation
  · have checked : Slice.len bytes ≠ Slice.len other := by
      intro equal; apply same; simpa using congrArg UScalar.val equal
    simp only [checked, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp [FoldedEqual, same]

attribute [local instance] Classical.propDecidable

theorem ascii_equal_exact (bytes other : Slice U8) :
    ascii_equal bytes other = Result.ok (decide (FoldedEqual bytes other)) := by
  obtain ⟨out, returned, iff⟩ := returned_of_spec (ascii_equal_contract bytes other)
  cases out <;> simp_all

theorem ascii_prefix_exact (bytes needle : Slice U8) :
    ascii_prefix bytes needle = Result.ok (decide (FoldedPrefix bytes needle)) := by
  obtain ⟨out, returned, iff⟩ := returned_of_spec (ascii_prefix_contract bytes needle)
  cases out <;> simp_all

/-- Reviewed ASCII octets; comments name the reserved protocol fields.
    Keep these independent of the Rust implementation for mutation checking. -/
def ReservedWords : List (Slice U8) := [
  (Array.make 6#usize [97#u8, 99#u8, 99#u8, 101#u8, 112#u8, 116#u8]).to_slice, -- accept
  (Array.make 15#usize [97#u8, 99#u8, 99#u8, 101#u8, 112#u8, 116#u8, 45#u8, 101#u8, 110#u8, 99#u8, 111#u8, 100#u8, 105#u8, 110#u8, 103#u8]).to_slice, -- accept-encoding
  (Array.make 13#usize [97#u8, 117#u8, 116#u8, 104#u8, 111#u8, 114#u8, 105#u8, 122#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8]).to_slice, -- authorization
  (Array.make 10#usize [99#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8, 105#u8, 111#u8, 110#u8]).to_slice, -- connection
  (Array.make 16#usize [99#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8, 101#u8, 110#u8, 99#u8, 111#u8, 100#u8, 105#u8, 110#u8, 103#u8]).to_slice, -- content-encoding
  (Array.make 14#usize [99#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8, 108#u8, 101#u8, 110#u8, 103#u8, 116#u8, 104#u8]).to_slice, -- content-length
  (Array.make 12#usize [99#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8, 116#u8, 121#u8, 112#u8, 101#u8]).to_slice, -- content-type
  (Array.make 6#usize [99#u8, 111#u8, 111#u8, 107#u8, 105#u8, 101#u8]).to_slice, -- cookie
  (Array.make 6#usize [101#u8, 120#u8, 112#u8, 101#u8, 99#u8, 116#u8]).to_slice, -- expect
  (Array.make 9#usize [102#u8, 111#u8, 114#u8, 119#u8, 97#u8, 114#u8, 100#u8, 101#u8, 100#u8]).to_slice, -- forwarded
  (Array.make 4#usize [104#u8, 111#u8, 115#u8, 116#u8]).to_slice, -- host
  (Array.make 10#usize [107#u8, 101#u8, 101#u8, 112#u8, 45#u8, 97#u8, 108#u8, 105#u8, 118#u8, 101#u8]).to_slice, -- keep-alive
  (Array.make 19#usize [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 97#u8, 117#u8, 116#u8, 104#u8, 111#u8, 114#u8, 105#u8, 122#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8]).to_slice, -- proxy-authorization
  (Array.make 16#usize [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 99#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8, 105#u8, 111#u8, 110#u8]).to_slice, -- proxy-connection
  (Array.make 2#usize [116#u8, 101#u8]).to_slice, -- te
  (Array.make 7#usize [116#u8, 114#u8, 97#u8, 105#u8, 108#u8, 101#u8, 114#u8]).to_slice, -- trailer
  (Array.make 17#usize [116#u8, 114#u8, 97#u8, 110#u8, 115#u8, 102#u8, 101#u8, 114#u8, 45#u8, 101#u8, 110#u8, 99#u8, 111#u8, 100#u8, 105#u8, 110#u8, 103#u8]).to_slice, -- transfer-encoding
  (Array.make 7#usize [117#u8, 112#u8, 103#u8, 114#u8, 97#u8, 100#u8, 101#u8]).to_slice, -- upgrade
  (Array.make 10#usize [117#u8, 115#u8, 101#u8, 114#u8, 45#u8, 97#u8, 103#u8, 101#u8, 110#u8, 116#u8]).to_slice, -- user-agent
  (Array.make 3#usize [118#u8, 105#u8, 97#u8]).to_slice, -- via
  (Array.make 9#usize [120#u8, 45#u8, 97#u8, 112#u8, 105#u8, 45#u8, 107#u8, 101#u8, 121#u8]).to_slice -- x-api-key
]
def ReservedPrefixes : List (Slice U8) := [
  (Array.make 6#usize [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8]).to_slice, -- proxy-
  (Array.make 4#usize [115#u8, 101#u8, 99#u8, 45#u8]).to_slice, -- sec-
  (Array.make 12#usize [120#u8, 45#u8, 102#u8, 111#u8, 114#u8, 119#u8, 97#u8, 114#u8, 100#u8, 101#u8, 100#u8, 45#u8]).to_slice -- x-forwarded-
]
def Reserved (bytes : Slice U8) : Prop :=
  (∃ word ∈ ReservedWords, FoldedEqual bytes word) ∨
  ∃ word ∈ ReservedPrefixes, FoldedPrefix bytes word

theorem lifted_array_slice {n : Usize} (bytes : Array U8 n) :
    (lift bytes.to_slice : Result (Slice U8)) = Result.ok bytes.to_slice := by rfl

theorem bool_result_choice (p : Prop) [Decidable p] (yes no : Bool) :
    (if p then Result.ok yes else Result.ok no) = Result.ok (if p then yes else no) := by
  split <;> rfl

theorem bool_choice_truth (p : Prop) [Decidable p] (tail : Bool) :
    ((if p then true else tail) = true) ↔ p ∨ tail = true := by
  by_cases condition : p <;> simp [condition]

end garrett_stateless_core.http_wire.Proofs
