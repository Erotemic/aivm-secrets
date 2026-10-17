import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.enrollment.Proofs

def Decision (c : Candidate) : Approval → core.result.Result Assurance EnrollmentDenial
  | .Software fp => if c.fingerprint = fp then .Ok .OperatorApproved else .Err .Denied
  | .Tpm spki => if c.spki = spki then .Ok .AttestedTpm else .Err .Denied

def KeyBound (c : Candidate) (approval : Approval) (assurance : Assurance) : Prop :=
  match approval with
  | .Software fp => c.fingerprint = fp ∧ assurance = .OperatorApproved
  | .Tpm spki => c.spki = spki ∧ assurance = .AttestedTpm

theorem approve_key_exact (c : Candidate) (approval : Approval) :
    approve_key c approval = Result.ok (Decision c approval) := by
  cases approval with
  | Software fp =>
    obtain ⟨different, returned, related⟩ := returned_of_spec (bytes_ne_spec c.fingerprint fp)
    cases different <;> simp_all [approve_key, Decision]
  | Tpm spki =>
    obtain ⟨different, returned, related⟩ := returned_of_spec (bytes_ne_spec c.spki spki)
    cases different <;> simp_all [approve_key, Decision]

theorem approve_key_contract (c : Candidate) (approval : Approval) :
    approve_key c approval ⦃ out =>
      match out with | .Ok assurance => KeyBound c approval assurance | .Err _ => True ⦄ := by
  rw [approve_key_exact]
  cases approval <;> simp [Decision, KeyBound] <;> split_ifs <;> simp_all

def WindowAllowed (input : EnrollmentInput) : Prop :=
  0 ≤ input.now.val ∧ input.now.val ≤ 253401695999 ∧
    input.ca_not_before.val ≤ input.now.val - 60 ∧ input.now.val + 604800 < input.ca_not_after.val

def PlanBound (input : EnrollmentInput) (approval : Approval) (plan : ClientPlan) : Prop :=
  plan.subject = input.subject ∧ plan.spki = input.candidate.spki ∧
    plan.not_before.val = input.now.val - 60 ∧ plan.not_after.val = input.now.val + 604800 ∧
    WindowAllowed input ∧ KeyBound input.candidate approval plan.assurance

theorem authorize_client_contract (input : EnrollmentInput) (approval : Approval) :
    authorize_client input approval ⦃ out =>
      match out with | .Ok plan => PlanBound input approval plan | .Err _ => True ⦄ := by
  unfold authorize_client
  apply WP.spec_bind (approve_key_contract input.candidate approval)
  intro approved bound
  cases approved with
  | Err error => simp
  | Ok assurance =>
    dsimp only at bound ⊢
    repeat' first
    | (solve | simp_all [WP.spec_ok, PlanBound, WindowAllowed]; all_goals scalar_tac)
    | split
    | step

theorem enroll_client_contract {S : Type} (ops : ClientSigner S) (signer : S)
    (input : EnrollmentInput) (approval : Approval)
    (Signed : ClientPlan → alloc.vec.Vec U8 → Prop)
    (sign_contract : ∀ plan, ops.sign signer plan ⦃ out =>
      match out with | .Ok cert => Signed plan cert | .Err _ => True ⦄) :
    enroll_client ops signer input approval ⦃ out =>
      match out with
      | .Ok issued => PlanBound input approval issued.plan ∧ Signed issued.plan issued.certificate
      | .Err _ => True ⦄ := by
  unfold enroll_client
  apply WP.spec_bind (authorize_client_contract input approval)
  intro prepared bound
  cases prepared with
  | Err error => simp
  | Ok plan =>
    dsimp only at bound ⊢
    apply WP.spec_bind (sign_contract plan)
    intro signed certificate
    cases signed with
    | Err error => simp
    | Ok cert => simpa only [WP.spec_ok] using And.intro bound certificate

theorem tpm_substitution_never_signed {S : Type} (ops : ClientSigner S) (signer : S)
    (input : EnrollmentInput) (attested : alloc.vec.Vec U8)
    (wrong : input.candidate.spki ≠ attested) :
    enroll_client ops signer input (.Tpm attested) = Result.ok (.Err .Denied) := by
  simp [enroll_client, authorize_client, approve_key_exact, Decision, wrong]

theorem unapproved_software_key_never_signed {S : Type} (ops : ClientSigner S) (signer : S)
    (input : EnrollmentInput) (approved : alloc.vec.Vec U8)
    (wrong : input.candidate.fingerprint ≠ approved) :
    enroll_client ops signer input (.Software approved) = Result.ok (.Err .Denied) := by
  simp [enroll_client, authorize_client, approve_key_exact, Decision, wrong]

/-- A software approval cannot acquire the TPM assurance label. -/
theorem software_is_not_tpm (c : Candidate) (approved : alloc.vec.Vec U8) :
    ¬ KeyBound c (.Software approved) .AttestedTpm := by
  simp [KeyBound]

/-- Successful TPM-labelled planning preserves the complete attested SPKI,
    rather than a caller-supplied boolean or an unrelated key fingerprint. -/
theorem tpm_plan_uses_attested_key (input : EnrollmentInput) (spki : alloc.vec.Vec U8)
    (plan : ClientPlan) (bound : PlanBound input (.Tpm spki) plan) : plan.spki = spki := by
  exact bound.2.1.trans bound.2.2.2.2.2.1

theorem enroll_client_successful {S : Type} (ops : ClientSigner S) (signer : S)
    (input : EnrollmentInput) (approval : Approval) (plan : ClientPlan) (certificate : alloc.vec.Vec U8)
    (authorized : authorize_client input approval = Result.ok (.Ok plan))
    (signed : ops.sign signer plan = Result.ok (.Ok certificate)) :
    enroll_client ops signer input approval = Result.ok (.Ok (IssuedClient.mk plan certificate)) := by
  simp [enroll_client, authorized, signed]

theorem authorize_tpm_success (subject spki fingerprint : alloc.vec.Vec U8) :
    authorize_client
      (EnrollmentInput.mk subject (Candidate.mk spki fingerprint) 0#i64 1000000#i64 1000#i64)
      (.Tpm spki) = Result.ok (.Ok (ClientPlan.mk subject spki 940#i64 605800#i64 .AttestedTpm)) := by
  simp [authorize_client, approve_key_exact, Decision]
  have sub : (1000#i64 - 60#i64 : Result I64) = Result.ok 940#i64 := by rfl
  have add : (1000#i64 + 604800#i64 : Result I64) = Result.ok 605800#i64 := by rfl
  simp [sub, add]

end aivm_secrets_garrett_core.enrollment.Proofs
