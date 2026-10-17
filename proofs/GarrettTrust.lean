import Garrett

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.trust.Proofs

@[step]
theorem bytes_eq_spec (a b : alloc.vec.Vec U8) :
    alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 a b ⦃ out => out ↔ a = b ⦄ := by
  have same : alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 a b =
      core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a.slice b.slice := by
    unfold alloc.vec.partial_eq.PartialEqVec.eq core.slice.cmp.PartialEqSlice.eq
    congr 1
    congr 1
    funext pair
    simp
    all_goals scalar_tac
  rw [same]
  apply WP.spec_mono (core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 a.slice b.slice (by intro x y; simp))
  intro out h
  have heq : a.slice = b.slice ↔ a = b := by
    constructor
    · intro eq; exact congrArg alloc.vec.Vec.mk eq
    · intro eq; exact congrArg alloc.vec.Vec.slice eq
  simpa only [heq] using h

theorem bytes_eq_exact (a b : alloc.vec.Vec U8) :
    alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 a b =
      Result.ok (if a = b then true else false) := by
  classical
  obtain ⟨out, returned, related⟩ := returned_of_spec (bytes_eq_spec a b)
  cases out <;> simp_all

theorem require_root_exact (current expected : alloc.vec.Vec U8) :
    require_root current expected = Result.ok
      (if current = expected then core.result.Result.Ok () else core.result.Result.Err .Stale) := by
  classical
  obtain ⟨different, returned, related⟩ := returned_of_spec (bytes_ne_spec current expected)
  cases different <;> simp_all [require_root]

theorem changed_root_fences_old_authority (current pinned : alloc.vec.Vec U8)
    (changed : current ≠ pinned) :
    require_root current pinned = Result.ok (.Err .Stale) := by
  simp [require_root_exact, changed]

def Prefix (a b c r s t : alloc.vec.Vec U8) : Prop :=
  (a = b ∧ r = s) ∨ (a = b ∧ r = t) ∨ (a = c ∧ r = t)

def RecoverySpec (a b c r s t : alloc.vec.Vec U8) :
    core.result.Result RecoveryPhase TrustDenial → Prop
  | .Ok .Unchanged => a = b ∧ r = s
  | .Ok .Retired => a = b ∧ r = t ∧ r ≠ s
  | .Ok .Activated => a = c ∧ r = t ∧ a ≠ b
  | .Err .Stale => ¬ Prefix a b c r s t
  | .Err _ => False

theorem recovery_phase_contract (a b c r s t : alloc.vec.Vec U8) :
    recovery_phase a b c r s t ⦃ out => RecoverySpec a b c r s t out ⦄ := by
  classical
  simp only [recovery_phase, bytes_eq_exact]
  simp_all [RecoverySpec, Prefix]; aesop

theorem changed_enrollments_refuse_recovery (a b c r s t : alloc.vec.Vec U8)
    (not_before : r ≠ s) (not_after : r ≠ t) :
    recovery_phase a b c r s t = Result.ok (.Err .Stale) := by
  classical
  simp [recovery_phase, bytes_eq_exact, not_before, not_after]

theorem activation_without_retirement_refused (b c s t : alloc.vec.Vec U8)
    (new_anchor : c ≠ b) (old_enrollments : s ≠ t) :
    recovery_phase c b c s s t = Result.ok (.Err .Stale) := by
  simp [recovery_phase, bytes_eq_exact, new_anchor, old_enrollments]

theorem unchanged_recovery_positive (a c r t : alloc.vec.Vec U8) :
    recovery_phase a a c r r t = Result.ok (.Ok .Unchanged) := by
  simp [recovery_phase, bytes_eq_exact]

theorem retired_recovery_positive (a c r t : alloc.vec.Vec U8) (retired : t ≠ r) :
    recovery_phase a a c t r t = Result.ok (.Ok .Retired) := by
  simp [recovery_phase, bytes_eq_exact, retired]

theorem activated_recovery_positive (a c r t : alloc.vec.Vec U8) (changed : c ≠ a) :
    recovery_phase c a c t r t = Result.ok (.Ok .Activated) := by
  simp [recovery_phase, bytes_eq_exact, changed]

theorem stale_root_never_changes_trust {S : Type} (ops : TrustStore S) (store : S)
    (current expected : alloc.vec.Vec U8) (stale : current ≠ expected) :
    commit_trust ops store current expected = Result.ok (.Err .Stale) := by
  simp [commit_trust, require_root_exact, stale]

/-- Storage and lease properties are explicit adapter contracts. In particular,
    activation may assume retirement only after the controller obtained it. -/
theorem commit_trust_contract {S : Type} (ops : TrustStore S) (store : S)
    (current expected : alloc.vec.Vec U8)
    (Intended Staged Retired Activated Completed : Prop)
    (intent : ops.intent store ⦃ out => out = .Ok () → Intended ⦄)
    (stage : Intended → ops.stage store ⦃ out => out = .Ok () → Staged ⦄)
    (retire : Intended → Staged → ops.retire store ⦃ out => out = .Ok () → Retired ⦄)
    (activate : Intended → Staged → Retired → ops.activate store ⦃ out => out = .Ok () → Activated ⦄)
    (complete : Intended → Staged → Retired → Activated → ops.complete store ⦃ out => out = .Ok () → Completed ⦄) :
    commit_trust ops store current expected ⦃ out => out = .Ok () →
      current = expected ∧ Intended ∧ Staged ∧ Retired ∧ Activated ∧ Completed ⦄ := by
  classical
  unfold commit_trust
  rw [require_root_exact]
  split
  next matched =>
    simp only [bind_ok]
    apply WP.spec_bind intent
    intro i hi
    cases i with
    | Err e => simp
    | Ok u =>
      cases u
      have ii := hi rfl
      apply WP.spec_bind (stage ii)
      intro s hs
      cases s with
      | Err e => simp
      | Ok u =>
        cases u
        have ss := hs rfl
        apply WP.spec_bind (retire ii ss)
        intro r hr
        cases r with
        | Err e => simp
        | Ok u =>
          cases u
          have rr := hr rfl
          apply WP.spec_bind (activate ii ss rr)
          intro a ha
          cases a with
          | Err e => simp
          | Ok u =>
            cases u
            have aa := ha rfl
            apply WP.spec_bind (complete ii ss rr aa)
            intro c hc
            cases c with
            | Err e => simp
            | Ok u => cases u; simpa only [WP.spec_ok] using fun _ => And.intro matched ⟨ii,ss,rr,aa,hc rfl⟩
  next stale => simp

theorem intent_failure_preserves_trust {S : Type} (ops : TrustStore S) (store : S)
    (root : alloc.vec.Vec U8) (failed : ops.intent store = Result.ok (.Err .Failed)) :
    commit_trust ops store root root = Result.ok (.Err .Unpublished) := by
  simp [commit_trust, require_root_exact, failed]

theorem stage_failure_never_retires {S : Type} (ops : TrustStore S) (store : S)
    (root : alloc.vec.Vec U8) (intended : ops.intent store = Result.ok (.Ok ()))
    (failed : ops.stage store = Result.ok (.Err .Failed)) :
    commit_trust ops store root root = Result.ok (.Err .Unpublished) := by
  simp [commit_trust, require_root_exact, intended, failed]

theorem retirement_failure_never_activates {S : Type} (ops : TrustStore S) (store : S)
    (root : alloc.vec.Vec U8) (intended : ops.intent store = Result.ok (.Ok ()))
    (staged : ops.stage store = Result.ok (.Ok ()))
    (failed : ops.retire store = Result.ok (.Err .Failed)) :
    commit_trust ops store root root = Result.ok (.Err .OutcomeUnknown) := by
  simp [commit_trust, require_root_exact, intended, staged, failed]

theorem activation_failure_reports_uncertainty {S : Type} (ops : TrustStore S) (store : S)
    (root : alloc.vec.Vec U8) (intended : ops.intent store = Result.ok (.Ok ()))
    (staged : ops.stage store = Result.ok (.Ok ()))
    (retired : ops.retire store = Result.ok (.Ok ()))
    (failed : ops.activate store = Result.ok (.Err .Failed)) :
    commit_trust ops store root root = Result.ok (.Err .OutcomeUnknown) := by
  simp [commit_trust, require_root_exact, intended, staged, retired, failed]

theorem completion_failure_reports_uncertainty {S : Type} (ops : TrustStore S) (store : S)
    (root : alloc.vec.Vec U8) (intended : ops.intent store = Result.ok (.Ok ()))
    (staged : ops.stage store = Result.ok (.Ok ()))
    (retired : ops.retire store = Result.ok (.Ok ()))
    (activated : ops.activate store = Result.ok (.Ok ()))
    (failed : ops.complete store = Result.ok (.Err .Failed)) :
    commit_trust ops store root root = Result.ok (.Err .OutcomeUnknown) := by
  simp [commit_trust, require_root_exact, intended, staged, retired, activated, failed]

theorem trust_change_positive {S : Type} (ops : TrustStore S) (store : S)
    (root : alloc.vec.Vec U8) (intended : ops.intent store = Result.ok (.Ok ()))
    (staged : ops.stage store = Result.ok (.Ok ()))
    (retired : ops.retire store = Result.ok (.Ok ()))
    (activated : ops.activate store = Result.ok (.Ok ()))
    (completed : ops.complete store = Result.ok (.Ok ())) :
    commit_trust ops store root root = Result.ok (.Ok ()) := by
  simp [commit_trust, require_root_exact, intended, staged, retired, activated, completed]

end aivm_secrets_garrett_core.trust.Proofs
