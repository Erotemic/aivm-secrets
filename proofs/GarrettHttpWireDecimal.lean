import AivmSecretsGarrettCore
import GarrettHttpRequest

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.http_auth.Proofs
open aivm_secrets_garrett_core.http_request.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.http_wire.Proofs

def Digit (n : Nat) : U8 := U8.ofNatCore (48 + n % 10) (by scalar_tac)

def Digits (n : Nat) : List U8 :=
  if n ≥ 10 then Digits (n / 10) ++ [Digit n] else [Digit n]
termination_by n
decreasing_by omega

theorem digit_value (n : Nat) : (Digit n).val = 48 + n % 10 := by simp [Digit]

theorem digits_length_bound (n : Nat) : (Digits n).length ≤ n + 1 := by
  induction n using Nat.strong_induction_on with
  | h n ih =>
    rw [Digits]
    split
    · simp only [List.length_append, List.length_singleton]
      have tail := ih (n / 10) (by omega)
      omega
    · simp

def DecimalValue : List U8 → Nat
  | [] => 0
  | byte :: rest => (byte.val - 48) * 10 ^ rest.length + DecimalValue rest

theorem decimal_value_append_digit (bytes : List U8) (n : Nat) :
    DecimalValue (bytes ++ [Digit n]) = 10 * DecimalValue bytes + n % 10 := by
  induction bytes with
  | nil => simp [DecimalValue, digit_value]
  | cons byte rest ih =>
    simp only [List.cons_append, DecimalValue, List.length_append, List.length_singleton, ih]
    rw [pow_succ]
    ring

theorem decimal_value_exact (n : Nat) : DecimalValue (Digits n) = n := by
  induction n using Nat.strong_induction_on with
  | h n ih =>
    rw [Digits]
    split
    · rw [decimal_value_append_digit, ih (n / 10) (by omega)]
      omega
    · simp only [DecimalValue, List.length_nil, pow_zero, Nat.mul_one, digit_value]
      omega

theorem append_decimal_exact (output : alloc.vec.Vec U8) (value : Usize)
    (room : output.length + (Digits value.val).length ≤ Usize.max) :
    append_decimal output value ⦃ out => out.val = output.val ++ Digits value.val ⦄ := by
  suffices ∀ n (value : Usize), value.val = n → ∀ (output : alloc.vec.Vec U8),
      output.length + (Digits n).length ≤ Usize.max →
      append_decimal output value ⦃ out => out.val = output.val ++ Digits n ⦄ from
    this value.val value rfl output room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro value equal output space
    rw [append_decimal.eq_def]
    by_cases large : value ≥ 10#usize
    · simp only [large, ↓reduceIte]
      step
      have high : n ≥ 10 := by scalar_tac
      have digits : Digits n = Digits (n / 10) ++ [Digit n] := by
        rw [Digits]; simp only [high, ↓reduceIte]
      have quotient : output1.val = n / 10 := by scalar_tac
      have smaller : output1.val < n := by rw [quotient]; omega
      have subspace : output.length + (Digits output1.val).length ≤ Usize.max := by
        rw [digits] at space
        simp only [List.length_append, List.length_singleton] at space
        rw [quotient]; omega
      apply WP.spec_bind (ih output1.val smaller output1 rfl output subspace)
      intro previous exact_bytes
      step
      step
      step
      step
      have digit_eq : i2 = Digit n := by
        apply UScalar.eq_of_val_eq
        rw [digit_value]
        scalar_tac
      simp_all [List.append_assoc]
    · simp only [large, ↓reduceIte, bind_ok]
      have small : n < 10 := by scalar_tac
      have digits : Digits n = [Digit n] := by rw [Digits]; simp only [Nat.not_le.mpr small, ↓reduceIte]
      step
      step
      step
      step
      have digit_eq : i2 = Digit n := by
        apply UScalar.eq_of_val_eq
        rw [digit_value]
        scalar_tac
      simp_all

end aivm_secrets_garrett_core.http_wire.Proofs
