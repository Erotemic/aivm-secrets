import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.client_material.Proofs

def publicationResult (key csr : core.result.Result Unit PublishFailure) : core.result.Result Unit PublishFailure :=
  match key with
  | .Err error => .Err error
  | .Ok _ => match csr with
    | .Ok _ => .Ok ()
    | .Err _ => .Err .OutcomeUnknown

theorem publish_request_contract {S : Type} (ops : RequestStore S) (store : S)
    (key csr : core.result.Result Unit PublishFailure)
    (key_return : ops.write_key store = Result.ok key)
    (csr_return : ops.write_csr store = Result.ok csr) :
    publish_request ops store = Result.ok (publicationResult key csr) := by
  simp only [publish_request, key_return, bind_ok]
  cases key with
  | Err error => rfl
  | Ok ack =>
    cases ack
    simp only [csr_return, bind_ok]
    cases csr <;> rfl

/-- No CSR contract is needed when private-key publication fails. -/
theorem failed_key_never_reaches_csr {S : Type} (ops : RequestStore S) (store : S)
    (error : PublishFailure) (key_return : ops.write_key store = Result.ok (.Err error)) :
    publish_request ops store = Result.ok (.Err error) := by
  simp [publish_request, key_return]

theorem failed_key_is_csr_independent {S : Type} (a b : RequestStore S) (store : S)
    (error : PublishFailure)
    (a_key : a.write_key store = Result.ok (.Err error))
    (b_key : b.write_key store = Result.ok (.Err error)) :
    publish_request a store = publish_request b store := by
  rw [failed_key_never_reaches_csr a store error a_key,
    failed_key_never_reaches_csr b store error b_key]

theorem csr_failure_retains_uncertainty {S : Type} (ops : RequestStore S) (store : S)
    (error : PublishFailure)
    (key_return : ops.write_key store = Result.ok (.Ok ()))
    (csr_return : ops.write_csr store = Result.ok (.Err error)) :
    publish_request ops store = Result.ok (.Err .OutcomeUnknown) := by
  simpa [publicationResult] using publish_request_contract ops store _ _ key_return csr_return

theorem key_uncertainty_is_not_erased {S : Type} (ops : RequestStore S) (store : S)
    (key_return : ops.write_key store = Result.ok (.Err .OutcomeUnknown)) :
    publish_request ops store = Result.ok (.Err .OutcomeUnknown) :=
  failed_key_never_reaches_csr ops store _ key_return

def Acknowledged (fact : Prop) (out : core.result.Result Unit PublishFailure) : Prop :=
  match out with
  | .Ok _ => fact
  | .Err _ => True

/-- Storage adapters supply the durability facts. Success requires both ordered
acknowledgements; this is not a proof of fsync or the filesystem itself. -/
theorem success_requires_both_acknowledgements {S : Type} (ops : RequestStore S) (store : S)
    (keyDurable csrDurable : Prop)
    (key_contract : ops.write_key store ⦃ out => Acknowledged keyDurable out ⦄)
    (csr_contract : ops.write_csr store ⦃ out => Acknowledged csrDurable out ⦄) :
    publish_request ops store ⦃ out => Acknowledged (keyDurable ∧ csrDurable) out ⦄ := by
  unfold publish_request
  apply WP.spec_bind key_contract
  intro key key_fact
  cases key with
  | Err error => simp [Acknowledged, WP.spec_ok]
  | Ok ack =>
    cases ack
    apply WP.spec_bind csr_contract
    intro csr csr_fact
    cases csr with
    | Err error => simp [Acknowledged, WP.spec_ok]
    | Ok ack =>
      cases ack
      simp only [WP.spec_ok, Acknowledged]
      exact ⟨key_fact, csr_fact⟩

theorem successful_request_witness {S : Type} (ops : RequestStore S) (store : S)
    (key_return : ops.write_key store = Result.ok (.Ok ()))
    (csr_return : ops.write_csr store = Result.ok (.Ok ())) :
    publish_request ops store = Result.ok (.Ok ()) := by
  simpa [publicationResult] using publish_request_contract ops store _ _ key_return csr_return

end aivm_secrets_garrett_core.client_material.Proofs
