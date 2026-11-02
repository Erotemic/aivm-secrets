import Aeneas

/-!
# Random nonces repeat with small, nonzero probability

`STATELESS-CRYPTO-01` asks that no AES-256-GCM nonce repeat under one key.
Garrett draws every nonce as 96 fresh random bits (`ring`'s `SystemRandom`,
`os.urandom` in Python) and keeps no record of past nonces: replicas share
keys and no state. So uniqueness is **not** guaranteed; it holds except with
a probability that this module bounds, under the assumption that the draws
are independent and uniform (the random source is trusted).

`repeated_le`: of the `N ^ n` ways `n` draws from `N` values can come out,
at most `(n choose 2) * N ^ (n - 1)` contain a repeat — so under uniform,
independent draws the probability of any repeat is at most
`(n choose 2) / N`. For `N = 2 ^ 96` (`nonce_collision_bound`) and
`n = 2 ^ 32` sealings under one key (the NIST SP 800-38D limit for random
96-bit nonces) that is below `2 ^ -33`. Nothing here counts sealings: keeping
a key's use under such a limit is the operator's key rotation
(`STATELESS-DEPLOY-01`).
-/

namespace Garrett.Nonce

open Finset

/-- The outcomes of `n` draws from `N` values in which two draws agree. -/
def Repeated (n N : ℕ) : Finset (Fin n → Fin N) :=
  univ.filter fun f => ¬ Function.Injective f

/-- The outcomes in which draws `i` and `j` agree. -/
def Agree {n N : ℕ} (i j : Fin n) : Finset (Fin n → Fin N) :=
  univ.filter fun f => f i = f j

/-- Fixing that draw `j` equals draw `i` leaves `N ^ (n - 1)` outcomes at most:
    forgetting draw `j` loses nothing. -/
theorem agree_card_le {n N : ℕ} {i j : Fin n} (ne : i ≠ j) : (Agree (N := N) i j).card ≤ N ^ (n - 1) := by
  classical
  let forget : (Fin n → Fin N) → ({k : Fin n // k ≠ j} → Fin N) := fun f k => f k.1
  have inj : Set.InjOn forget (Agree (N := N) i j : Set (Fin n → Fin N)) := by
    intro f hf g hg same
    simp only [Agree, coe_filter, mem_univ, true_and] at hf hg
    funext k
    by_cases hk : k = j
    · subst hk
      rw [← hf, ← hg]
      exact congrFun same ⟨i, ne⟩
    · exact congrFun same ⟨k, hk⟩
  calc (Agree (N := N) i j).card = ((Agree (N := N) i j).image forget).card := (card_image_of_injOn inj).symm
    _ ≤ (univ : Finset ({k : Fin n // k ≠ j} → Fin N)).card := card_le_univ _
    _ = N ^ (n - 1) := by
      rw [card_univ, Fintype.card_fun, Fintype.card_fin, Fintype.card_subtype_compl, Fintype.card_fin,
        Fintype.card_subtype_eq]

/-- The outcomes in which two distinct draws of `s` agree. -/
def AgreeIn {n N : ℕ} (s : Finset (Fin n)) : Finset (Fin n → Fin N) :=
  univ.filter fun f => ∃ a ∈ s, ∃ b ∈ s, a ≠ b ∧ f a = f b

theorem agreeIn_card_le {n N : ℕ} {s : Finset (Fin n)} (two : s.card = 2) :
    (AgreeIn (N := N) s).card ≤ N ^ (n - 1) := by
  obtain ⟨x, y, ne, rfl⟩ := card_eq_two.mp two
  refine le_trans (card_le_card ?_) (agree_card_le (N := N) ne)
  intro f hf
  simp only [AgreeIn, mem_filter, mem_univ, true_and, mem_insert, mem_singleton] at hf
  simp only [Agree, mem_filter, mem_univ, true_and]
  obtain ⟨a, ha, b, hb, ab, same⟩ := hf
  rcases ha with rfl | rfl <;> rcases hb with rfl | rfl
  · exact absurd rfl ab
  · exact same
  · exact same.symm
  · exact absurd rfl ab

/-- **At most `(n choose 2) · N ^ (n - 1)` of the `N ^ n` outcomes of `n`
    draws from `N` values repeat a value.** -/
theorem repeated_le (n N : ℕ) : (Repeated n N).card ≤ n.choose 2 * N ^ (n - 1) := by
  classical
  let pairs := (univ : Finset (Fin n)).powersetCard 2
  have cover : Repeated n N ⊆ pairs.biUnion fun s => AgreeIn s := by
    intro f hf
    simp only [Repeated, mem_filter, mem_univ, true_and, Function.Injective, not_forall] at hf
    obtain ⟨a, b, same, ne⟩ := hf
    simp only [mem_biUnion, pairs, mem_powersetCard, subset_univ, true_and, AgreeIn, mem_filter, mem_univ]
    exact ⟨{a, b}, card_pair ne, a, by simp, b, by simp, ne, same⟩
  calc (Repeated n N).card ≤ (pairs.biUnion fun s => AgreeIn (N := N) s).card := card_le_card cover
    _ ≤ ∑ s ∈ pairs, (AgreeIn (N := N) s).card := card_biUnion_le
    _ ≤ ∑ _s ∈ pairs, N ^ (n - 1) := sum_le_sum fun s hs => agreeIn_card_le (mem_powersetCard.mp hs).2
    _ = n.choose 2 * N ^ (n - 1) := by
      simp [pairs, card_powersetCard]

/-- **The bound for 96-bit nonces.** Among `n` independent uniform 96-bit
    nonces, the fraction of outcomes with a repeat is at most
    `(n choose 2) / 2 ^ 96`. -/
theorem nonce_collision_bound (n : ℕ) (pos : 0 < n) :
    ((Repeated n (2 ^ 96)).card : ℚ) / ((2 : ℚ) ^ 96) ^ n ≤ (n.choose 2 : ℚ) / (2 : ℚ) ^ 96 := by
  have le : ((Repeated n (2 ^ 96)).card : ℚ) ≤ (n.choose 2 : ℚ) * ((2 : ℚ) ^ 96) ^ (n - 1) := by
    exact_mod_cast repeated_le n (2 ^ 96)
  have split : ((2 : ℚ) ^ 96) ^ n = ((2 : ℚ) ^ 96) ^ (n - 1) * (2 : ℚ) ^ 96 := by
    rw [← pow_succ, Nat.sub_add_cancel pos]
  have big : (0 : ℚ) < ((2 : ℚ) ^ 96) ^ (n - 1) := by positivity
  rw [split, div_le_div_iff₀ (by positivity) (by positivity)]
  calc ((Repeated n (2 ^ 96)).card : ℚ) * (2 : ℚ) ^ 96
      ≤ (n.choose 2 : ℚ) * ((2 : ℚ) ^ 96) ^ (n - 1) * (2 : ℚ) ^ 96 :=
        mul_le_mul_of_nonneg_right le (by positivity)
    _ = (n.choose 2 : ℚ) * (((2 : ℚ) ^ 96) ^ (n - 1) * (2 : ℚ) ^ 96) := by rw [mul_assoc]

end Garrett.Nonce
