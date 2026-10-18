import AivmSecretsGarrettCore
import GarrettFoundation
import GarrettTrust

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.rebinding.Proofs

/-- This is a privileged host operation. Source expiry is not guest admission;
    the preserved opaque broker capability still enforces its original grant. -/
def Allowed (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) : Prop :=
  target.active = true ∧ source.issuer = target.identity.issuer ∧
    source.audience = target.identity.audience ∧ source.subject = target.identity.subject ∧
    key = target.key ∧ source.epoch.val ≤ target.identity.epoch.val ∧
    target.identity.epoch = epoch ∧ target.certificate = certificate ∧
    0 ≤ now.val ∧ now.val < target.not_after.val

instance (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) :
    Decidable (Allowed source key target epoch certificate now) := by
  unfold Allowed
  infer_instance

theorem permitted_contract (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) :
    permitted source key target epoch certificate now ⦃ out =>
      out = true ↔ Allowed source key target epoch certificate now ⦄ := by
  unfold permitted
  repeat' first
  | (solve | simp_all [WP.spec_ok, Allowed]; all_goals scalar_tac)
  | split
  | step

theorem permitted_exact (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) :
    permitted source key target epoch certificate now = Result.ok
      (if Allowed source key target epoch certificate now then true else false) := by
  obtain ⟨out, returned, allowed⟩ := returned_of_spec
    (permitted_contract source key target epoch certificate now)
  cases out <;> simp_all

theorem same_identity_and_key_required (source : Claims) (key : alloc.vec.Vec U8)
    (target : Target) (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) :
    permitted source key target epoch certificate now ⦃ out => out = true →
      source.issuer = target.identity.issuer ∧ source.audience = target.identity.audience ∧
      source.subject = target.identity.subject ∧ key = target.key ⦄ := by
  apply WP.spec_mono (permitted_contract source key target epoch certificate now)
  intro out contract accepted
  rcases contract.mp accepted with ⟨_, issuer, audience, subject, same_key, _⟩
  exact ⟨issuer, audience, subject, same_key⟩

theorem stale_target_epoch_refused (source : Claims) (key : alloc.vec.Vec U8)
    (target : Target) (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64)
    (stale : target.identity.epoch ≠ epoch) :
    permitted source key target epoch certificate now = Result.ok false := by
  simp [permitted_exact, Allowed, stale]

theorem changed_target_certificate_refused (source : Claims) (key : alloc.vec.Vec U8)
    (target : Target) (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64)
    (changed : target.certificate ≠ certificate) :
    permitted source key target epoch certificate now = Result.ok false := by
  simp [permitted_exact, Allowed, changed]

theorem changed_key_refused (source : Claims) (key : alloc.vec.Vec U8)
    (target : Target) (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64)
    (changed : key ≠ target.key) :
    permitted source key target epoch certificate now = Result.ok false := by
  simp [permitted_exact, Allowed, changed]

theorem inactive_target_refused (source : Claims) (key : alloc.vec.Vec U8)
    (target : Target) (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64)
    (inactive : target.active = false) :
    permitted source key target epoch certificate now = Result.ok false := by
  simp [permitted, inactive]

theorem expired_target_refused (source : Claims) (key : alloc.vec.Vec U8)
    (target : Target) (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64)
    (expired : target.not_after.val ≤ now.val) :
    permitted source key target epoch certificate now = Result.ok false := by
  simp [permitted_exact, Allowed, Int.not_lt.mpr expired]

theorem denied_before_open_or_issue {P S O E : Type} (ops : Rebinder P S O E)
    (pending : P) (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) (error : E)
    (denied : ¬ Allowed source key target epoch certificate now)
    (rejected : ops.rejected pending = Result.ok error) :
    rebind ops pending source key target epoch certificate now = Result.ok (.Err error) := by
  simp [rebind, permitted_exact, denied, rejected]

theorem open_failure_never_issues {P S O E : Type} (ops : Rebinder P S O E)
    (pending : P) (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) (error : E)
    (allowed : Allowed source key target epoch certificate now)
    (failed : ops.«open» pending = Result.ok (.Err error)) :
    rebind ops pending source key target epoch certificate now = Result.ok (.Err error) := by
  simp [rebind, permitted_exact, allowed, failed]

/-- The issuer receives exactly the source's opened opaque capability. No
    different secret is selected by renewal. Concrete crypto/file/lease and
    certificate-fingerprint facts remain explicit adapter obligations. -/
theorem same_secret_reissuance_contract {P S O E : Type} (ops : Rebinder P S O E)
    (pending : P) (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64)
    (Opened : S → Prop) (Issued : S → O → Prop)
    (open_contract : ops.«open» pending ⦃ out => ∀ secret, out = .Ok secret → Opened secret ⦄)
    (issue_contract : ∀ secret, Opened secret → ops.issue pending secret ⦃ out =>
      ∀ value, out = .Ok value → Issued secret value ⦄)
    (reject_total : ops.rejected pending ⦃ _ => True ⦄) :
    rebind ops pending source key target epoch certificate now ⦃ out => ∀ value,
      out = .Ok value → Allowed source key target epoch certificate now ∧
        ∃ secret, Opened secret ∧ Issued secret value ⦄ := by
  unfold rebind
  apply WP.spec_bind (permitted_contract source key target epoch certificate now)
  intro accepted contract
  cases accepted with
  | false =>
    apply WP.spec_bind reject_total
    intro error _
    simp
  | true =>
    have allowed := contract.mp rfl
    apply WP.spec_bind open_contract
    intro opened opened_contract
    cases opened with
    | Err error => simp
    | Ok secret =>
      have source_secret := opened_contract secret rfl
      apply WP.spec_mono (issue_contract secret source_secret)
      intro out issued value accepted
      exact ⟨allowed, secret, source_secret, issued value accepted⟩

theorem successful_rebind_witness {P S O E : Type} (ops : Rebinder P S O E)
    (pending : P) (source : Claims) (key : alloc.vec.Vec U8) (target : Target)
    (epoch : I64) (certificate : alloc.vec.Vec U8) (now : I64) (secret : S) (value : O)
    (allowed : Allowed source key target epoch certificate now)
    (opened : ops.«open» pending = Result.ok (.Ok secret))
    (issued : ops.issue pending secret = Result.ok (.Ok value)) :
    rebind ops pending source key target epoch certificate now = Result.ok (.Ok value) := by
  simp [rebind, permitted_exact, allowed, opened, issued]

end aivm_secrets_garrett_core.rebinding.Proofs
