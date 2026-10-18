import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 2000000
namespace aivm_secrets_garrett_core.coordination.KeyProofs

def AllowedByte (byte : U8) : Prop :=
  (65 ≤ byte.val ∧ byte.val ≤ 90) ∨ (97 ≤ byte.val ∧ byte.val ≤ 122) ∨
  (48 ≤ byte.val ∧ byte.val ≤ 57) ∨ byte.val = 45 ∨ byte.val = 95

theorem retry_byte_contract (byte : U8) :
    retry_byte byte ⦃ out => out ↔ AllowedByte byte ⦄ := by
  unfold retry_byte
  repeat' first | split | (solve | simp_all [AllowedByte, WP.spec_ok]; all_goals scalar_tac)

def BytesFrom (key : Slice U8) (start : Nat) : Prop :=
  ∀ (i : Nat) (inside : i < key.length), start ≤ i → AllowedByte key.val[i]
def ValidRetryKey (key : Slice U8) : Prop :=
  8 ≤ key.length ∧ key.length ≤ 128 ∧ BytesFrom key 0

theorem bytes_step (key : Slice U8) (i : Nat) (inside : i < key.length) :
    BytesFrom key i ↔ AllowedByte key.val[i] ∧ BytesFrom key (i + 1) := by
  constructor
  · intro all
    exact ⟨all i inside (Nat.le_refl _), fun j hj after => all j hj (by omega)⟩
  · rintro ⟨head, tail⟩ j hj after
    by_cases same : j = i
    · subst j; exact head
    · exact tail j hj (by omega)

theorem retry_key_loop_contract (key : Slice U8) (index : Usize) :
    valid_retry_key_loop key index ⦃ out => out ↔ BytesFrom key index.val ⦄ := by
  suffices ∀ n (i : Usize), key.length - i.val = n →
      valid_retry_key_loop key i ⦃ out => out ↔ BytesFrom key i.val ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [valid_retry_key_loop.eq_def]
    by_cases inside : i < key.len
    · have bound : i.val < key.length := by scalar_tac
      simp only [inside, ↓reduceIte]
      obtain ⟨byte, returned, byteEq⟩ := returned_of_spec (Slice.index_usize_spec key i bound)
      rw [returned]
      simp only [bind_ok]
      apply WP.spec_bind (retry_byte_contract byte)
      intro accepted related
      cases accepted with
      | false =>
        have invalid : ¬ AllowedByte key.val[i.val] := by simpa [byteEq] using related
        simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok, false_iff]
        intro all
        exact invalid (all i.val bound (Nat.le_refl _))
      | true =>
        have valid : AllowedByte key.val[i.val] := by simpa [byteEq] using related
        simp only [↓reduceIte]
        obtain ⟨next, advanced, nextVal⟩ := returned_of_spec
          (@Usize.add_spec i 1#usize (by scalar_tac))
        have nextEq : next.val = i.val + 1 := by scalar_tac
        rw [advanced]
        simp only [bind_ok]
        apply WP.spec_mono (ih (key.length - next.val) (by scalar_tac) next rfl)
        intro out tail
        rw [bytes_step key i.val bound]
        simpa only [valid, true_and, nextEq] using tail
    · have done : key.length ≤ i.val := by scalar_tac
      simp only [inside, ↓reduceIte, WP.spec_ok, true_iff]
      intro j hj after
      omega

theorem valid_retry_key_contract (key : Slice U8) :
    valid_retry_key key ⦃ out => out ↔ ValidRetryKey key ⦄ := by
  unfold valid_retry_key
  by_cases short : key.len < 8#usize
  · simp only [short, ↓reduceIte, WP.spec_ok, Bool.false_eq_true, false_iff]
    intro valid
    have bound := valid.1
    scalar_tac
  · simp only [short, ↓reduceIte]
    by_cases long : key.len > 128#usize
    · simp only [long, ↓reduceIte, WP.spec_ok, Bool.false_eq_true, false_iff]
      intro valid
      have bound := valid.2.1
      scalar_tac
    · simp only [long, ↓reduceIte]
      apply WP.spec_mono (retry_key_loop_contract key 0#usize)
      intro out related
      have bounds : 8 ≤ key.length ∧ key.length ≤ 128 := by scalar_tac
      simpa [ValidRetryKey, bounds] using related

theorem accepted_key_has_no_line_breaks (key : Slice U8)
    (accepted : valid_retry_key key = Result.ok true) :
    ∀ (i : Nat) (inside : i < key.length), key.val[i].val ≠ 10 ∧ key.val[i].val ≠ 13 := by
  obtain ⟨out, returned, related⟩ := returned_of_spec (valid_retry_key_contract key)
  have same : out = true := Result.ok_injective (returned.symm.trans accepted)
  have valid := related.mp same
  intro i inside
  have byte := valid.2.2 i inside (Nat.zero_le _)
  unfold AllowedByte at byte
  omega

theorem valid_key_is_accepted (key : Slice U8) (valid : ValidRetryKey key) :
    valid_retry_key key = Result.ok true := by
  obtain ⟨out, returned, related⟩ := returned_of_spec (valid_retry_key_contract key)
  simpa [related.mpr valid] using returned

end aivm_secrets_garrett_core.coordination.KeyProofs
