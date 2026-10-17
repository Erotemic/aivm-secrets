import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.oauth_state.Proofs

theorem unsent_classification (status : I64) (invalid : Bool) :
    classify false status invalid = Result.ok .NotSent := by simp [classify]

theorem invalid_grant_requires_reauthorization :
    classify true 400#i64 true = Result.ok .Rejected := by simp [classify]

theorem ambiguous_sent_is_uncertain (status : I64) (invalid : Bool)
    (ambiguous : status ≠ 400#i64 ∨ invalid = false) :
    classify true status invalid = Result.ok .Uncertain := by
  cases invalid <;> simp_all [classify]

theorem not_sent_preserves_prior (prior : RefreshState) :
    settled_failure prior .NotSent = Result.ok prior := by cases prior <;> rfl

theorem uncertain_never_restores_ready (prior : RefreshState) :
    settled_failure prior .Uncertain = Result.ok .InDoubt := by rfl

theorem rejection_requires_reauthorization (prior : RefreshState) :
    settled_failure prior .Rejected = Result.ok .Reauthorize := by rfl

def RefreshAllowed (active : Bool) (state : RefreshState) (refresh : Bool)
    (generation : I64) (retry : Bool) : Prop :=
  active = true ∧ (state = .Ready ∨ (state = .InDoubt ∧ retry = true)) ∧
    refresh = true ∧ 0 ≤ generation.val ∧ generation.val < 2147483647

theorem permit_refresh_contract (active : Bool) (state : RefreshState) (refresh : Bool)
    (generation : I64) (retry : Bool) :
    permit_refresh active state refresh generation retry ⦃ out =>
      out = .Ok () ↔ RefreshAllowed active state refresh generation retry ⦄ := by
  cases active <;> cases state <;> cases refresh <;> cases retry <;>
    simp_all [permit_refresh, RefreshAllowed, WP.spec_ok] <;>
    repeat' first | (solve | simp_all [WP.spec_ok]; all_goals scalar_tac) | split

theorem in_doubt_needs_explicit_retry (refresh : Bool) (generation : I64) :
    permit_refresh true .InDoubt refresh generation false = Result.ok (.Err .Unsettled) := by
  simp [permit_refresh]

theorem rejection_cannot_be_overridden (refresh retry : Bool) (generation : I64) :
    permit_refresh true .Reauthorize refresh generation retry = Result.ok (.Err .Unsettled) := by
  simp [permit_refresh]

theorem revoked_never_refreshes (state : RefreshState) (refresh retry : Bool) (generation : I64) :
    permit_refresh false state refresh generation retry = Result.ok (.Err .Revoked) := by
  simp [permit_refresh]

def LeaseAllowed (active : Bool) (state : RefreshState) (current leased : LeaseMeta)
    (now : I64) : Prop :=
  active = true ∧ state = .Ready ∧ current.epoch = leased.epoch ∧
    current.generation = leased.generation ∧ current.expires_at = leased.expires_at ∧
    0 ≤ now.val ∧ now.val < current.expires_at.val

theorem lease_contract (active : Bool) (state : RefreshState) (current leased : LeaseMeta)
    (now : I64) : require_lease active state current leased now ⦃ out =>
      out = .Ok () ↔ LeaseAllowed active state current leased now ⦄ := by
  cases active <;> cases state <;>
    simp_all [require_lease, LeaseAllowed, WP.spec_ok] <;>
    repeat' first | (solve | simp_all [WP.spec_ok]; all_goals scalar_tac) | split

theorem changed_epoch_fences_lease (state : RefreshState) (current leased : LeaseMeta)
    (now : I64) (changed : current.epoch ≠ leased.epoch) :
    require_lease true state current leased now = Result.ok (.Err .Revoked) := by
  simp [require_lease, changed]

theorem changed_generation_fences_lease (state : RefreshState) (current leased : LeaseMeta)
    (now : I64) (changed : current.generation ≠ leased.generation) :
    require_lease true state current leased now = Result.ok (.Err .Revoked) := by
  simp [require_lease, changed]

theorem unsettled_grant_cannot_dispatch (active : Bool) (state : RefreshState)
    (current leased : LeaseMeta) (now : I64) (unsettled : state ≠ .Ready) :
    require_lease active state current leased now ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (lease_contract active state current leased now)
  intro out contract accepted
  exact unsettled (contract.mp accepted).2.1

theorem expired_grant_cannot_dispatch (active : Bool) (state : RefreshState)
    (current leased : LeaseMeta) (now : I64) (expired : current.expires_at.val ≤ now.val) :
    require_lease active state current leased now ⦃ out => out ≠ .Ok () ⦄ := by
  apply WP.spec_mono (lease_contract active state current leased now)
  intro out contract accepted
  exact (Int.not_lt.mpr expired) (contract.mp accepted).2.2.2.2.2.2

theorem lease_positive_witness :
    require_lease true .Ready ⟨0#i64, 1#i64, 2000#i64⟩ ⟨0#i64, 1#i64, 2000#i64⟩ 1000#i64 =
      Result.ok (.Ok ()) := by simp [require_lease]

/-- Storage durability and transport behavior remain explicit adapter contracts.
    The extracted controller obtains durable quarantine before exchange and
    successor persistence before returning any usable successor. -/
theorem refresh_order_contract {S T : Type} (ops : RefreshOps S T) (store : S)
    (active : Bool) (prior : RefreshState) (refresh : Bool) (generation : I64) (retry : Bool)
    (Intended Quarantined : Prop) (Exchanged Committed : T → Prop)
    (intent : ops.intent store ⦃ out => out = .Ok () → Intended ⦄)
    (quarantine : Intended → ops.quarantine store ⦃ out => out = .Ok () → Quarantined ⦄)
    (exchange : Intended → Quarantined → ops.exchange store ⦃ out => ∀ token, out = .Ok token → Exchanged token ⦄)
    (commit : ∀ token, Intended → Quarantined → Exchanged token →
      ops.commit store token ⦃ out => out = .Ok () → Committed token ⦄)
    (settle : ∀ state, ops.settle store state ⦃ _ => True ⦄)
    (observe : ∀ event, ops.observe store event ⦃ _ => True ⦄) :
    refresh_once ops store active prior refresh generation retry ⦃ out => ∀ token, out = .Ok token →
      RefreshAllowed active prior refresh generation retry ∧ Intended ∧ Quarantined ∧ Exchanged token ∧ Committed token ⦄ := by
  unfold refresh_once
  apply WP.spec_bind (permit_refresh_contract active prior refresh generation retry)
  intro allowed ha
  cases allowed with
  | Err e => simp
  | Ok u =>
    cases u
    have permit := ha.mp rfl
    apply WP.spec_bind intent
    intro i hi
    cases i with
    | Err e => simp
    | Ok u =>
      cases u
      have ii := hi rfl
      apply WP.spec_bind (quarantine ii)
      intro q hq
      cases q with
      | Err e => simp
      | Ok u =>
        cases u
        have qq := hq rfl
        apply WP.spec_bind (exchange ii qq)
        intro exchanged he
        cases exchanged with
        | Ok token =>
          have ee := he token rfl
          apply WP.spec_bind (commit token ii qq ee)
          intro c hc
          cases c with
          | Ok u =>
            cases u
            apply WP.spec_bind (observe .Recorded)
            intro o ho
            cases o with
            | Err e => simp
            | Ok u => cases u; simpa only [WP.spec_ok] using fun t h => by cases h; exact ⟨permit, ii, qq, ee, hc rfl⟩
          | Err e =>
            apply WP.spec_bind (observe .InDoubt)
            intro o ho
            simp
        | Err failure =>
          cases failure with
          | Uncertain =>
            apply WP.spec_bind (observe .InDoubt)
            intro o ho
            simp
          | NotSent =>
            rw [not_sent_preserves_prior]
            simp only [bind_ok]
            apply WP.spec_bind (settle prior)
            intro s hs
            cases s with
            | Ok u =>
              cases u
              apply WP.spec_bind (observe .NotSent)
              intro o ho
              cases o <;> simp
            | Err e =>
              apply WP.spec_bind (observe .InDoubt)
              intro o ho
              simp
          | Rejected =>
            simp only [settled_failure, bind_ok]
            apply WP.spec_bind (settle .Reauthorize)
            intro s hs
            cases s with
            | Ok u =>
              cases u
              apply WP.spec_bind (observe .Rejected)
              intro o ho
              cases o <;> simp
            | Err e =>
              apply WP.spec_bind (observe .InDoubt)
              intro o ho
              simp


theorem intent_failure_never_sends {S T : Type} (ops : RefreshOps S T) (store : S)
    (failed : ops.intent store = Result.ok (.Err .Failed)) :
    refresh_once ops store true .Ready true 0#i64 false = Result.ok (.Err .Storage) := by
  simp [refresh_once, permit_refresh, failed]

theorem quarantine_failure_never_sends {S T : Type} (ops : RefreshOps S T) (store : S)
    (intended : ops.intent store = Result.ok (.Ok ()))
    (failed : ops.quarantine store = Result.ok (.Err .Failed)) :
    refresh_once ops store true .Ready true 0#i64 false = Result.ok (.Err .Uncertain) := by
  simp [refresh_once, permit_refresh, intended, failed]

theorem uncertain_exchange_never_settles {S T : Type} (ops : RefreshOps S T) (store : S)
    (intended : ops.intent store = Result.ok (.Ok ()))
    (quarantined : ops.quarantine store = Result.ok (.Ok ()))
    (uncertain : ops.exchange store = Result.ok (.Err .Uncertain))
    (observed : core.result.Result Unit StoreFailure)
    (logged : ops.observe store .InDoubt = Result.ok observed) :
    refresh_once ops store true .Ready true 0#i64 false = Result.ok (.Err .Uncertain) := by
  simp [refresh_once, permit_refresh, intended, quarantined, uncertain, logged]

theorem failed_commit_never_returns_token {S T : Type} (ops : RefreshOps S T) (store : S)
    (token : T) (intended : ops.intent store = Result.ok (.Ok ()))
    (quarantined : ops.quarantine store = Result.ok (.Ok ()))
    (exchanged : ops.exchange store = Result.ok (.Ok token))
    (failed : ops.commit store token = Result.ok (.Err .Failed))
    (observed : core.result.Result Unit StoreFailure)
    (logged : ops.observe store .InDoubt = Result.ok observed) :
    refresh_once ops store true .Ready true 0#i64 false = Result.ok (.Err .Uncertain) := by
  simp [refresh_once, permit_refresh, intended, quarantined, exchanged, failed, logged]

theorem refresh_positive_witness {S T : Type} (ops : RefreshOps S T) (store : S)
    (token : T) (intended : ops.intent store = Result.ok (.Ok ()))
    (quarantined : ops.quarantine store = Result.ok (.Ok ()))
    (exchanged : ops.exchange store = Result.ok (.Ok token))
    (committed : ops.commit store token = Result.ok (.Ok ()))
    (logged : ops.observe store .Recorded = Result.ok (.Ok ())) :
    refresh_once ops store true .Ready true 0#i64 false = Result.ok (.Ok token) := by
  simp [refresh_once, permit_refresh, intended, quarantined, exchanged, committed, logged]

end aivm_secrets_garrett_core.oauth_state.Proofs
