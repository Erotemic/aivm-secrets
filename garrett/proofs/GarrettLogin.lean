import GarrettStatelessCore
import GarrettFoundation

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.oauth_login.Proofs

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

theorem failed_install_is_uncertain :
    finish .Exchanging false = Result.ok (.Ok .Uncertain) := by rfl

end garrett_stateless_core.oauth_login.Proofs
