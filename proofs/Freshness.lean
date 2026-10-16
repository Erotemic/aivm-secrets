import AivmSecretsPrimitives

open Aeneas Aeneas.Std

namespace aivm_secrets_primitives.Proofs

-- These predicates use mathematical integers, independently of Rust's control
-- flow. The theorems below connect them to the generated implementation.
abbrev Current (actual expected : Int) : Prop := 0 ≤ actual ∧ actual = expected

abbrev Active (now start expiry : Int) : Prop :=
  0 ≤ start ∧ 0 ≤ expiry ∧ start ≤ now ∧ now < expiry

abbrev Fresh (actual expected now start expiry : Int) : Prop :=
  Current actual expected ∧ Active now start expiry

def AdvanceSpec (current maximum : Int) (out : core.result.Result I64 Denial) : Prop :=
  match out with
  | .Err .InvalidCapability => maximum < 0 ∨ current < 0 ∨ maximum < current
  | .Err .Revoked => 0 ≤ current ∧ current = maximum
  | .Ok next => 0 ≤ current ∧ current < maximum ∧
      next.val = current + 1 ∧ next.val ≤ maximum

/-- Total correctness includes absence of panic/overflow on every typed input. -/
theorem advance_contract (current maximum : I64) :
    advance current maximum ⦃ out => AdvanceSpec current.val maximum.val out ⦄ := by
  unfold advance
  split
  · simp_all [AdvanceSpec]
  · split
    · simp_all [AdvanceSpec]
    · split
      · simp_all [AdvanceSpec]
      · split
        · simp_all [AdvanceSpec]
        · step
          simp_all [AdvanceSpec]
          scalar_tac

theorem current_exact (actual expected : I64) :
    require_current actual expected =
      Result.ok (if Current actual.val expected.val then
        core.result.Result.Ok () else core.result.Result.Err Denial.InvalidCapability) := by
  unfold require_current Current
  split <;> split <;> simp_all
  scalar_tac

theorem active_exact (now start expiry : I64) :
    require_active now start expiry =
      Result.ok (if Active now.val start.val expiry.val then
        core.result.Result.Ok () else core.result.Result.Err Denial.InvalidCapability) := by
  unfold require_active Active
  split_ifs <;> simp_all <;> scalar_tac

theorem fresh_exact (actual expected now start expiry : I64) :
    require_fresh actual expected now start expiry =
      Result.ok (if Fresh actual.val expected.val now.val start.val expiry.val then
        core.result.Result.Ok () else core.result.Result.Err Denial.InvalidCapability) := by
  unfold require_fresh Fresh
  rw [current_exact, active_exact]
  split_ifs <;> simp_all [Current] <;> omega

theorem fresh_accepted_iff (actual expected now start expiry : I64) :
    require_fresh actual expected now start expiry = Result.ok (core.result.Result.Ok ()) ↔
      Fresh actual.val expected.val now.val start.val expiry.val := by
  rw [fresh_exact]
  split_ifs with h
  · constructor
    · intro _; exact h
    · intro _; rfl
  · constructor
    · intro impossible
      simp at impossible
    · intro valid
      exact (h valid).elim

theorem fresh_rejects_stale (actual expected now start expiry : I64)
    (stale : actual.val ≠ expected.val) :
    require_fresh actual expected now start expiry =
      Result.ok (core.result.Result.Err Denial.InvalidCapability) := by
  rw [fresh_exact]
  simp [Fresh, Current, stale]

theorem fresh_rejects_expired (actual expected now start expiry : I64)
    (expired : expiry.val ≤ now.val) :
    require_fresh actual expected now start expiry =
      Result.ok (core.result.Result.Err Denial.InvalidCapability) := by
  rw [fresh_exact]
  simp [Fresh, Active, not_lt.mpr expired]

theorem advance_invalidates_old_epoch (current maximum next : I64)
    (advanced : advance current maximum = Result.ok (core.result.Result.Ok next)) :
    require_current current next = Result.ok (core.result.Result.Err Denial.InvalidCapability) := by
  have contract := advance_contract current maximum
  rw [advanced] at contract
  simp only [WP.spec_ok, AdvanceSpec] at contract
  rw [current_exact]
  have different : current.val ≠ next.val := by omega
  simp [Current, different]

-- Kernel-reduced successful witnesses guard against an always-refusing model.
theorem fresh_positive_witness :
    require_fresh 7#i64 7#i64 10#i64 10#i64 11#i64 =
      Result.ok (core.result.Result.Ok ()) := by
  rw [fresh_exact]
  rfl

theorem advance_positive_witness :
    advance 0#i64 1#i64 ⦃ out => out = core.result.Result.Ok 1#i64 ⦄ := by
  apply WP.spec_mono (advance_contract 0#i64 1#i64)
  intro out contract
  cases out with
  | Err denial => cases denial <;> norm_num [AdvanceSpec] at contract
  | Ok next =>
    simp only [AdvanceSpec] at contract
    have successor : next = 1#i64 := by scalar_tac
    simp [successor]

end aivm_secrets_primitives.Proofs
