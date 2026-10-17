import Garrett

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.authority.Proofs

def AssuranceAllowed : Assurance → Requirement → Prop
  | _, .Enrolled => True
  | .Tpm, .AttestedTpm => True
  | _, .AttestedTpm => False

def PeerAllowed (active : Bool) (certificate peer : alloc.vec.Vec U8)
    (expiry now : I64) (assurance : Assurance) (required : Requirement) : Prop :=
  active = true ∧ 0 ≤ now.val ∧ now.val < expiry.val ∧ certificate = peer ∧
    AssuranceAllowed assurance required

theorem require_peer_contract (active : Bool) (certificate peer : alloc.vec.Vec U8)
    (expiry now : I64) (assurance : Assurance) (required : Requirement) :
    require_peer active certificate peer expiry now assurance required ⦃ out =>
      (out = .Ok ()) ↔ PeerAllowed active certificate peer expiry now assurance required ⦄ := by
  obtain ⟨different, returned, related⟩ := returned_of_spec (bytes_ne_spec certificate peer)
  cases active <;> cases different <;> cases assurance <;> cases required <;>
    simp_all [require_peer, PeerAllowed, AssuranceAllowed, WP.spec_ok] <;>
    repeat' first | (solve | simp_all [WP.spec_ok]; all_goals scalar_tac) | split

theorem inactive_peer_denied (certificate peer : alloc.vec.Vec U8) (expiry now : I64)
    (assurance : Assurance) (required : Requirement) :
    require_peer false certificate peer expiry now assurance required = Result.ok (.Err .Revoked) := by
  simp [require_peer]

theorem wrong_peer_denied (certificate peer : alloc.vec.Vec U8) (expiry now : I64)
    (assurance : Assurance) (required : Requirement) (wrong : certificate ≠ peer) :
    require_peer true certificate peer expiry now assurance required ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (require_peer_contract true certificate peer expiry now assurance required)
  intro out bound accepted
  exact wrong (bound.mp accepted).2.2.2.1

theorem software_cannot_satisfy_tpm (active : Bool) (certificate peer : alloc.vec.Vec U8)
    (expiry now : I64) :
    require_peer active certificate peer expiry now .Software .AttestedTpm ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (require_peer_contract active certificate peer expiry now .Software .AttestedTpm)
  intro out bound accepted
  exact (bound.mp accepted).2.2.2.2

theorem unrecorded_cannot_satisfy_tpm (active : Bool) (certificate peer : alloc.vec.Vec U8)
    (expiry now : I64) :
    require_peer active certificate peer expiry now .Unrecorded .AttestedTpm ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (require_peer_contract active certificate peer expiry now .Unrecorded .AttestedTpm)
  intro out bound accepted
  exact (bound.mp accepted).2.2.2.2

theorem revoke_contract (active : Bool) (epoch : I64) :
    revoke active epoch ⦃ out =>
      match out with
      | .Ok row => row.active = false
      | .Err _ => True ⦄ := by
  unfold revoke
  repeat' first | (solve | simp_all [WP.spec_ok]; all_goals scalar_tac) | split | step

theorem revoked_peer_never_admitted (row : Revoked) (inactive : row.active = false)
    (certificate peer : alloc.vec.Vec U8) (expiry now : I64)
    (assurance : Assurance) (required : Requirement) :
    require_peer row.active certificate peer expiry now assurance required = Result.ok (.Err .Revoked) := by
  rw [inactive]
  exact inactive_peer_denied certificate peer expiry now assurance required

theorem revoke_prevents_admission (active : Bool) (epoch : I64)
    (certificate peer : alloc.vec.Vec U8) (expiry now : I64)
    (assurance : Assurance) (required : Requirement) :
    revoke active epoch ⦃ out =>
      match out with
      | .Ok row => require_peer row.active certificate peer expiry now assurance required =
          Result.ok (.Err .Revoked)
      | .Err _ => True ⦄ := by
  apply WP.spec_mono (revoke_contract active epoch)
  intro out inactive
  cases out with
  | Err e => trivial
  | Ok row => exact revoked_peer_never_admitted row inactive certificate peer expiry now assurance required

theorem expired_peer_denied (active : Bool) (certificate peer : alloc.vec.Vec U8)
    (expiry now : I64) (assurance : Assurance) (required : Requirement)
    (expired : expiry.val ≤ now.val) :
    require_peer active certificate peer expiry now assurance required ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (require_peer_contract active certificate peer expiry now assurance required)
  intro out bound accepted
  exact (Int.not_lt.mpr expired) (bound.mp accepted).2.2.1

theorem attested_peer_positive_witness (certificate : alloc.vec.Vec U8) :
    require_peer true certificate certificate 2000#i64 1000#i64 .Tpm .AttestedTpm ⦃ out => out = .Ok () ⦄ := by
  apply WP.spec_mono (require_peer_contract true certificate certificate 2000#i64 1000#i64 .Tpm .AttestedTpm)
  intro out bound
  apply bound.mpr
  simp [PeerAllowed, AssuranceAllowed]

/-- Adapter contracts are hypotheses: filesystem durability is not an axiom
    of this model. The controller must obtain each prerequisite in order. -/
theorem commit_change_contract {S : Type} (ops : ChangeStore S) (store : S)
    (Intended Staged Published Completed : Prop)
    (intent : ops.intent store ⦃ out => out = .Ok () → Intended ⦄)
    (stage : Intended → ops.stage store ⦃ out => out = .Ok () → Staged ⦄)
    (publish : Intended → Staged → ops.publish store ⦃ out => out = .Ok () → Published ⦄)
    (complete : Intended → Staged → Published → ops.complete store ⦃ out => out = .Ok () → Completed ⦄) :
    commit_change ops store ⦃ out => out = .Ok () → Intended ∧ Staged ∧ Published ∧ Completed ⦄ := by
  unfold commit_change
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
      apply WP.spec_bind (publish ii ss)
      intro p hp
      cases p with
      | Err e => simp
      | Ok u =>
        cases u
        have pp := hp rfl
        apply WP.spec_bind (complete ii ss pp)
        intro c hc
        cases c with
        | Err e => simp
        | Ok u => cases u; simpa only [WP.spec_ok] using fun _ => And.intro ii ⟨ss, pp, hc rfl⟩

theorem intent_failure_never_publishes {S : Type} (ops : ChangeStore S) (store : S)
    (failed : ops.intent store = Result.ok (.Err .Failed)) :
    commit_change ops store = Result.ok (.Err .Unpublished) := by
  simp [commit_change, failed]

theorem staging_failure_never_publishes {S : Type} (ops : ChangeStore S) (store : S)
    (intended : ops.intent store = Result.ok (.Ok ()))
    (failed : ops.stage store = Result.ok (.Err .Failed)) :
    commit_change ops store = Result.ok (.Err .Unpublished) := by
  simp [commit_change, intended, failed]

theorem publication_failure_is_uncertain {S : Type} (ops : ChangeStore S) (store : S)
    (intended : ops.intent store = Result.ok (.Ok ()))
    (staged : ops.stage store = Result.ok (.Ok ()))
    (failed : ops.publish store = Result.ok (.Err .Failed)) :
    commit_change ops store = Result.ok (.Err .OutcomeUnknown) := by
  simp [commit_change, intended, staged, failed]

theorem completion_failure_is_uncertain {S : Type} (ops : ChangeStore S) (store : S)
    (intended : ops.intent store = Result.ok (.Ok ()))
    (staged : ops.stage store = Result.ok (.Ok ()))
    (published : ops.publish store = Result.ok (.Ok ()))
    (failed : ops.complete store = Result.ok (.Err .Failed)) :
    commit_change ops store = Result.ok (.Err .OutcomeUnknown) := by
  simp [commit_change, intended, staged, published, failed]

theorem commit_change_positive_witness {S : Type} (ops : ChangeStore S) (store : S)
    (intended : ops.intent store = Result.ok (.Ok ()))
    (staged : ops.stage store = Result.ok (.Ok ()))
    (published : ops.publish store = Result.ok (.Ok ()))
    (completed : ops.complete store = Result.ok (.Ok ())) :
    commit_change ops store = Result.ok (.Ok ()) := by
  simp [commit_change, intended, staged, published, completed]

end aivm_secrets_garrett_core.authority.Proofs
