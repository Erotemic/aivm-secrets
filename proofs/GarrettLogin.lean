import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.oauth_login.Proofs

theorem bytes_ne_exact (a b : alloc.vec.Vec U8) :
    alloc.vec.partial_eq.PartialEqVec.ne core.cmp.PartialEqU8 a b =
      Result.ok (if a = b then false else true) := by
  classical
  obtain ⟨out, returned, related⟩ := returned_of_spec (bytes_ne_spec a b)
  cases out <;> simp_all

def Window (p : Pending) (now : I64) : Prop :=
  0 ≤ p.issued_at.val ∧ p.issued_at.val ≤ 9223372036854775207 ∧
  p.issued_at.val < p.expires_at.val ∧ p.expires_at.val ≤ p.issued_at.val + 600 ∧
  p.issued_at.val ≤ now.val ∧ now.val < p.expires_at.val

theorem current_contract (p : Pending) (now : I64) :
    current p now ⦃ out => out = .Ok () ↔ Window p now ⦄ := by
  unfold current
  repeat' first | (solve | simp_all [Window, WP.spec_ok]; all_goals scalar_tac) | split | step

def IssuerBound (rule : IssuerRule) (cb : Callback) : Prop :=
  match rule with
  | .Absent => cb.has_issuer = false
  | .Exact expected => cb.has_issuer = true ∧ cb.issuer = expected

def Bound (stage : Stage) (p : Pending) (cb : Callback) (now : I64) : Prop :=
  stage = .Pending ∧ Window p now ∧ cb.state = p.state ∧ IssuerBound p.issuer cb

theorem claim_contract (stage : Stage) (p : Pending) (cb : Callback) (now : I64) :
    claim stage p cb now ⦃ out => ∀ accepted, out = .Ok accepted ↔
      Bound stage p cb now ∧ accepted = (if cb.denied then .Denied else .Accepted) ⦄ := by
  classical
  obtain ⟨out, returned, allowed⟩ := returned_of_spec (current_contract p now)
  cases stage <;> cases rule : p.issuer <;> cases hi : cb.has_issuer <;> cases hd : cb.denied <;>
    cases out <;> simp_all [claim, bytes_ne_exact, Bound, IssuerBound, WP.spec_ok] <;>
    repeat' first | (solve | simp_all [WP.spec_ok]; aesop) | split
  all_goals simp_all [WP.spec_ok]

theorem accepted_requires_exact_state (stage : Stage) (p : Pending) (cb : Callback) (now : I64) :
    claim stage p cb now ⦃ out => ∀ accepted, out = .Ok accepted → cb.state = p.state ⦄ := by
  apply WP.spec_mono (claim_contract stage p cb now)
  intro out spec accepted h
  exact ((spec accepted).mp h).1.2.2.1

theorem accepted_requires_issuer_policy (stage : Stage) (p : Pending) (cb : Callback) (now : I64) :
    claim stage p cb now ⦃ out => ∀ accepted, out = .Ok accepted → IssuerBound p.issuer cb ⦄ := by
  apply WP.spec_mono (claim_contract stage p cb now)
  intro out spec accepted h
  exact ((spec accepted).mp h).1.2.2.2

theorem accepted_requires_current_window (stage : Stage) (p : Pending) (cb : Callback) (now : I64) :
    claim stage p cb now ⦃ out => ∀ accepted, out = .Ok accepted → Window p now ⦄ := by
  apply WP.spec_mono (claim_contract stage p cb now)
  intro out spec accepted h
  exact ((spec accepted).mp h).1.2.1

theorem consumed_callback_cannot_be_claimed_again (stage : Stage) (p : Pending)
    (cb another : Callback) (now later : I64) :
    claim stage p cb now ⦃ out => ∀ accepted, out = .Ok accepted →
      claim accepted p another later = Result.ok (.Err .Consumed) ⦄ := by
  apply WP.spec_mono (claim_contract stage p cb now)
  intro out spec accepted h
  have result := ((spec accepted).mp h).2
  rw [result]
  cases cb.denied <;> simp [claim]

theorem begin_contract (stage : Stage) (p : Pending) (now : I64) :
    begin stage p now ⦃ out => out = .Ok .Exchanging ↔ stage = .Accepted ∧ Window p now ⦄ := by
  obtain ⟨out, returned, allowed⟩ := returned_of_spec (current_contract p now)
  cases stage <;> cases out <;> simp_all [begin, WP.spec_ok]

theorem exchange_cannot_be_started_twice (p : Pending) (later : I64) :
    begin .Exchanging p later = Result.ok (.Err .Consumed) := by simp [begin]

theorem denial_never_exchanges (p : Pending) (now : I64) :
    begin .Denied p now = Result.ok (.Err .Consumed) := by simp [begin]

theorem unclaimed_never_exchanges (p : Pending) (now : I64) :
    begin .Pending p now = Result.ok (.Err .Consumed) := by simp [begin]

theorem expired_callback_never_exchanges (p : Pending) (now : I64)
    (expired : p.expires_at.val ≤ now.val) :
    begin .Accepted p now ⦃ out => out ≠ .Ok .Exchanging ⦄ := by
  apply WP.spec_mono (begin_contract .Accepted p now)
  intro out spec h
  exact (Int.not_lt.mpr expired) (spec.mp h).2.2.2.2.2.2

theorem finish_contract (stage : Stage) (installed : Bool) :
    finish stage installed ⦃ out => ∀ result, out = .Ok result ↔
      stage = .Exchanging ∧ result = (if installed then .Complete else .Uncertain) ⦄ := by
  cases stage <;> cases installed <;> simp [finish, WP.spec_ok, eq_comm]

theorem failed_install_is_uncertain :
    finish .Exchanging false = Result.ok (.Ok .Uncertain) := by rfl

theorem complete_never_reexchanges (p : Pending) (now : I64) :
    begin .Complete p now = Result.ok (.Err .Consumed) := by simp [begin]

theorem uncertain_never_reexchanges (p : Pending) (now : I64) :
    begin .Uncertain p now = Result.ok (.Err .Consumed) := by simp [begin]

theorem successful_callback_witness (state : alloc.vec.Vec U8) :
    claim .Pending ⟨state, .Absent, 1000#i64, 1200#i64⟩ ⟨state, state, false, false⟩ 1100#i64 =
      Result.ok (.Ok .Accepted) := by
  let p : Pending := ⟨state, .Absent, 1000#i64, 1200#i64⟩
  obtain ⟨out, returned, allowed⟩ := returned_of_spec (current_contract p 1100#i64)
  have valid : Window p 1100#i64 := by norm_num [Window, p]
  have accepted := allowed.mpr valid
  rw [accepted] at returned
  simp [claim, p, returned, bytes_ne_exact]

theorem successful_exchange_witness (state : alloc.vec.Vec U8) :
    begin .Accepted ⟨state, .Absent, 1000#i64, 1200#i64⟩ 1100#i64 =
      Result.ok (.Ok .Exchanging) := by
  let p : Pending := ⟨state, .Absent, 1000#i64, 1200#i64⟩
  obtain ⟨out, returned, allowed⟩ := returned_of_spec (current_contract p 1100#i64)
  have valid : Window p 1100#i64 := by norm_num [Window, p]
  have accepted := allowed.mpr valid
  rw [accepted] at returned
  simp [begin, p, returned]

end aivm_secrets_garrett_core.oauth_login.Proofs
