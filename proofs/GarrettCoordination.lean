import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.coordination.Proofs

/-- A denied check needs no contract for the provider continuation. -/
theorem rejected_before_provider {P O E : Type} (ops : Dispatch P O E)
    (pending : P) (keyed : Bool) (error : E)
    (denied : ops.check pending = Result.ok (.Err error)) :
    dispatch ops pending keyed = Result.ok (.Err error) := by
  simp [dispatch, denied]

theorem reservation_refusal_prevents_provider {P O E : Type} (ops : Dispatch P O E)
    (pending : P) (error : E)
    (admitted : ops.check pending = Result.ok (.Ok ()))
    (refused : ops.reserve pending = Result.ok (.Err error)) :
    dispatch ops pending true = Result.ok (.Err error) := by
  simp [dispatch, admitted, refused]

theorem provider_failure_propagated {P O E : Type} (ops : Dispatch P O E)
    (pending : P) (error : E)
    (admitted : ops.check pending = Result.ok (.Ok ()))
    (reserved : ops.reserve pending = Result.ok (.Ok ()))
    (failed : ops.emit pending = Result.ok (.Err error)) :
    dispatch ops pending true = Result.ok (.Err error) := by
  simp [dispatch, admitted, reserved, failed]

theorem failed_completion_is_uncertain {P O E : Type} (ops : Dispatch P O E)
    (pending : P) (value : O) (error unknown : E)
    (admitted : ops.check pending = Result.ok (.Ok ()))
    (reserved : ops.reserve pending = Result.ok (.Ok ()))
    (emitted : ops.emit pending = Result.ok (.Ok value))
    (failed : ops.finish pending = Result.ok (.Err error))
    (uncertain : ops.outcome_unknown pending = Result.ok unknown) :
    dispatch ops pending true = Result.ok (.Err unknown) := by
  simp [dispatch, admitted, reserved, emitted, failed, uncertain]

theorem read_success_witness {P O E : Type} (ops : Dispatch P O E)
    (pending : P) (value : O)
    (admitted : ops.check pending = Result.ok (.Ok ()))
    (emitted : ops.emit pending = Result.ok (.Ok value)) :
    dispatch ops pending false = Result.ok (.Ok value) := by
  simp [dispatch, admitted, emitted]

theorem write_success_witness {P O E : Type} (ops : Dispatch P O E)
    (pending : P) (value : O)
    (admitted : ops.check pending = Result.ok (.Ok ()))
    (reserved : ops.reserve pending = Result.ok (.Ok ()))
    (emitted : ops.emit pending = Result.ok (.Ok value))
    (finished : ops.finish pending = Result.ok (.Ok ())) :
    dispatch ops pending true = Result.ok (.Ok value) := by
  simp [dispatch, admitted, reserved, emitted, finished]

/-- These facts concern their acknowledged points. The remote server's
    authenticated durability/uniqueness and concrete I/O correspondence remain
    adapter obligations, not premises silently supplied by a network reply. -/
theorem write_acknowledgement_contract {P O E : Type} (ops : Dispatch P O E)
    (pending : P) (Admitted Reserved : Prop) (Emitted Finished : O → Prop)
    (check : ops.check pending ⦃ out => out = .Ok () → Admitted ⦄)
    (reserve : Admitted → ops.reserve pending ⦃ out => out = .Ok () → Reserved ⦄)
    (emit : Admitted → Reserved → ops.emit pending ⦃ out =>
      ∀ value, out = .Ok value → Emitted value ⦄)
    (finish : ∀ value, Admitted → Reserved → Emitted value →
      ops.finish pending ⦃ out => out = .Ok () → Finished value ⦄)
    (unknown : ops.outcome_unknown pending ⦃ _ => True ⦄) :
    dispatch ops pending true ⦃ out => ∀ value, out = .Ok value →
      Admitted ∧ Reserved ∧ Emitted value ∧ Finished value ⦄ := by
  unfold dispatch
  apply WP.spec_bind check
  intro checked hc
  cases checked with
  | Err error => simp
  | Ok u =>
    cases u
    have aa := hc rfl
    simp only [↓reduceIte]
    apply WP.spec_bind (reserve aa)
    intro reserved hr
    cases reserved with
    | Err error => simp
    | Ok u =>
      cases u
      have rr := hr rfl
      apply WP.spec_bind (emit aa rr)
      intro emitted he
      cases emitted with
      | Err error => simp
      | Ok value =>
        have ee := he value rfl
        apply WP.spec_bind (finish value aa rr ee)
        intro finished hf
        cases finished with
        | Ok u =>
          cases u
          simpa only [WP.spec_ok] using fun result h => by
            cases h
            exact ⟨aa, rr, ee, hf rfl⟩
        | Err error =>
          apply WP.spec_bind unknown
          intro code _
          simp

end aivm_secrets_garrett_core.coordination.Proofs
