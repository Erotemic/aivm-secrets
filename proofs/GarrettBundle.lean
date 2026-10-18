import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 2000000

namespace aivm_secrets_garrett_core.bundle.Proofs

/-- The comparison uses the actual extracted Vec comparison, with no opaque
Option equality axiom. Hash collision resistance belongs to the adapter. -/
theorem digest_ne_exact (a b : alloc.vec.Vec U8) :
    alloc.vec.partial_eq.PartialEqVec.ne core.cmp.PartialEqU8 a b =
      Result.ok (decide (a ≠ b)) := by
  obtain ⟨different, returned, related⟩ := returned_of_spec (bytes_ne_spec a b)
  rw [returned]
  cases different <;> simp_all

def publicationResult (staged published : core.result.Result Unit InstallFailure) :
    core.result.Result Unit InstallFailure :=
  match staged with
  | .Err error => .Err error
  | .Ok _ => match published with
    | .Ok _ => .Ok ()
    | .Err _ => .Err .OutcomeUnknown

/-- After the current read, a mismatched expected digest never reaches either
callback. Matching snapshots reach staging before publication. -/
theorem after_current {S : Type} (ops : BundleStore S) (store : S)
    (observed expected : Option (alloc.vec.Vec U8))
    (current_return : ops.current store = Result.ok (.Ok observed)) :
    install ops store expected =
      if observed = expected then
        (do
          let staged ← ops.stage store
          match staged with
          | .Ok _ =>
            let published ← ops.publish store
            match published with
            | .Ok _ => Result.ok (core.result.Result.Ok ())
            | .Err _ => Result.ok (core.result.Result.Err InstallFailure.OutcomeUnknown)
          | .Err _ => Result.ok staged)
      else Result.ok (.Err .Changed) := by
  cases observed <;> cases expected <;>
    simp [install, current_return, core.cmp.impls.PartialEqShared.ne,
      digest_ne_exact]
  all_goals rfl

/-- Current-read errors also require no staging or publication contract. -/
theorem current_failure_stops {S : Type} (ops : BundleStore S) (store : S)
    (expected : Option (alloc.vec.Vec U8)) (error : InstallFailure)
    (current_return : ops.current store = Result.ok (.Err error)) :
    install ops store expected = Result.ok (.Err error) := by
  simp [install, current_return]

theorem changed_never_stages {S : Type} (ops : BundleStore S) (store : S)
    (observed expected : Option (alloc.vec.Vec U8)) (changed : observed ≠ expected)
    (current_return : ops.current store = Result.ok (.Ok observed)) :
    install ops store expected = Result.ok (.Err .Changed) := by
  simp [after_current ops store observed expected current_return, changed]

theorem install_contract {S : Type} (ops : BundleStore S) (store : S)
    (observed expected : Option (alloc.vec.Vec U8))
    (staged published : core.result.Result Unit InstallFailure)
    (current_return : ops.current store = Result.ok (.Ok observed))
    (stage_return : ops.stage store = Result.ok staged)
    (publish_return : ops.publish store = Result.ok published) :
    install ops store expected = Result.ok
      (if observed = expected then publicationResult staged published else .Err .Changed) := by
  rw [after_current ops store observed expected current_return]
  split
  · cases staged <;> cases published <;> simp_all [publicationResult]
  · rfl

theorem stage_failure_never_publishes {S : Type} (ops : BundleStore S) (store : S)
    (expected : Option (alloc.vec.Vec U8)) (error : InstallFailure)
    (current_return : ops.current store = Result.ok (.Ok expected))
    (stage_return : ops.stage store = Result.ok (.Err error)) :
    install ops store expected = Result.ok (.Err error) := by
  rw [after_current ops store expected expected current_return]
  simp [stage_return]

theorem publication_failure_is_uncertain {S : Type} (ops : BundleStore S) (store : S)
    (expected : Option (alloc.vec.Vec U8)) (error : InstallFailure)
    (current_return : ops.current store = Result.ok (.Ok expected))
    (stage_return : ops.stage store = Result.ok (.Ok ()))
    (publish_return : ops.publish store = Result.ok (.Err error)) :
    install ops store expected = Result.ok (.Err .OutcomeUnknown) := by
  simpa [publicationResult] using
    install_contract ops store expected expected _ _ current_return stage_return publish_return

theorem successful_install_witness {S : Type} (ops : BundleStore S) (store : S)
    (expected : Option (alloc.vec.Vec U8))
    (current_return : ops.current store = Result.ok (.Ok expected))
    (stage_return : ops.stage store = Result.ok (.Ok ()))
    (publish_return : ops.publish store = Result.ok (.Ok ())) :
    install ops store expected = Result.ok (.Ok ()) := by
  simpa [publicationResult] using
    install_contract ops store expected expected _ _ current_return stage_return publish_return

/-- Success requires the expected snapshot and both positive storage returns.
This does not turn those returns into a proof of filesystem durability. -/
theorem success_exact {S : Type} (ops : BundleStore S) (store : S)
    (observed expected : Option (alloc.vec.Vec U8))
    (staged published : core.result.Result Unit InstallFailure)
    (current_return : ops.current store = Result.ok (.Ok observed))
    (stage_return : ops.stage store = Result.ok staged)
    (publish_return : ops.publish store = Result.ok published) :
    install ops store expected = Result.ok (.Ok ()) ↔
      observed = expected ∧ staged = .Ok () ∧ published = .Ok () := by
  rw [install_contract ops store observed expected staged published
    current_return stage_return publish_return]
  by_cases same : observed = expected
  · subst observed
    cases staged <;> cases published <;> simp [publicationResult]
  · simp [same]

end aivm_secrets_garrett_core.bundle.Proofs
