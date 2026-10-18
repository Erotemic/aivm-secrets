import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.coordinator_authority.Proofs

@[step]
theorem peer_bytes_equal (a b : alloc.vec.Vec U8) :
    alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 a b
      ⦃ out => out ↔ a = b ⦄ := by
  have representation : alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 a b =
      core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a.slice b.slice := by
    have byte_eq (x y : U8) : (x = y) ↔ (x.val = y.val) :=
      ⟨congrArg UScalar.val, UScalar.eq_of_val_eq⟩
    simp only [alloc.vec.partial_eq.PartialEqVec.eq, core.slice.cmp.PartialEqSlice.eq]
    simp [alloc.vec.Vec.val, byte_eq]
  rw [representation]
  apply WP.spec_mono (core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 a.slice b.slice (by intro x y; simp))
  intro out equal
  have slices : a.slice = b.slice ↔ a = b := by
    constructor
    · intro eq; exact congrArg alloc.vec.Vec.mk eq
    · intro eq; exact congrArg alloc.vec.Vec.slice eq
  simpa only [slices] using equal

def PeerFrom (members : Slice (alloc.vec.Vec U8)) (start : Nat)
    (peer : alloc.vec.Vec U8) : Prop :=
  ∃ (index : Nat) (inside : index < members.length), start ≤ index ∧ members[index] = peer

theorem peer_from_step (members : Slice (alloc.vec.Vec U8)) (start : Nat)
    (peer : alloc.vec.Vec U8) (inside : start < members.length) :
    PeerFrom members start peer ↔ members[start] = peer ∨ PeerFrom members (start + 1) peer := by
  constructor
  · rintro ⟨i, hi, after, equal⟩
    by_cases same : i = start
    · subst i; exact Or.inl equal
    · exact Or.inr ⟨i, hi, by omega, equal⟩
  · rintro (head | ⟨i, hi, after, equal⟩)
    · exact ⟨start, inside, Nat.le_refl _, head⟩
    · exact ⟨i, hi, by omega, equal⟩

theorem peer_from_zero (members : Slice (alloc.vec.Vec U8)) (peer : alloc.vec.Vec U8) :
    PeerFrom members 0 peer ↔ peer ∈ members.val := by
  constructor
  · rintro ⟨i, hi, after, equal⟩
    exact List.mem_iff_getElem.mpr ⟨i, hi, equal⟩
  · intro member
    obtain ⟨i, hi, equal⟩ := List.getElem_of_mem member
    exact ⟨i, hi, Nat.zero_le _, equal⟩

theorem contains_peer_loop_contract (iter : core.slice.iter.Iter (alloc.vec.Vec U8))
    (peer : alloc.vec.Vec U8) :
    contains_peer_loop iter peer ⦃ out => out ↔ PeerFrom iter.slice iter.i peer ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter (alloc.vec.Vec U8)), it.slice.length - it.i = n →
      contains_peer_loop it peer ⦃ out => out ↔ PeerFrom it.slice it.i peer ⦄ from this _ iter rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [contains_peer_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have next_return : core.slice.iter.IteratorSliceIter.next it =
          Result.ok (some it.slice[it.i], {it with i := it.i + 1}) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
        rfl
      rw [next_return]
      simp only [bind_ok]
      change (do
        let b ← alloc.vec.partial_eq.PartialEqVec.eq core.cmp.PartialEqU8 it.slice[it.i] peer
        if b then Result.ok true else contains_peer_loop {it with i := it.i + 1} peer)
          ⦃ out => out ↔ PeerFrom it.slice it.i peer ⦄
      obtain ⟨equal, checked, equivalent⟩ := returned_of_spec (peer_bytes_equal it.slice[it.i] peer)
      rw [checked]
      simp only [bind_ok]
      by_cases same : equal = true
      · simp only [same, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        simp only [true_iff]
        exact ⟨it.i, inside, Nat.le_refl _, equivalent.mp same⟩
      · have different : it.slice[it.i] ≠ peer := mt equivalent.mpr same
        have denied : equal = false := by cases equal <;> simp_all
        simp only [denied, Bool.false_eq_true, ↓reduceIte]
        apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by omega)
          {it with i := it.i + 1} rfl)
        intro out tail
        have rest : PeerFrom it.slice it.i peer ↔ PeerFrom it.slice (it.i + 1) peer := by
          rw [peer_from_step it.slice it.i peer inside]
          simp only [different, false_or]
        exact tail.trans rest.symm
    · have next_return : core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
      rw [next_return]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨i, hi, after, equal⟩
      omega

@[step]
theorem contains_peer_contract (members : Slice (alloc.vec.Vec U8)) (peer : alloc.vec.Vec U8) :
    contains_peer members peer ⦃ out => out ↔ peer ∈ members.val ⦄ := by
  unfold contains_peer
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  apply WP.spec_mono (contains_peer_loop_contract ⟨members, 0⟩ peer)
  intro out present
  exact present.trans (peer_from_zero members peer)

theorem require_operator_contract (operators : Slice (alloc.vec.Vec U8))
    (peer : alloc.vec.Vec U8) :
    require_operator operators peer ⦃ out =>
      (out = .Ok () ↔ peer ∈ operators.val) ∧
      (out = .Err .Denied ↔ peer ∉ operators.val) ⦄ := by
  unfold require_operator
  step
  cases b <;> simp_all

theorem activate_existing_rejected (principal : Principal)
    (members : alloc.vec.Vec (alloc.vec.Vec U8)) :
    activate (some principal) members = Result.ok (.Err .Revoked) := by rfl

theorem activate_new_exact (members : alloc.vec.Vec (alloc.vec.Vec U8)) :
    activate none members = Result.ok (.Ok ⟨true, members, 1#i64⟩) := by rfl

theorem admit_contract (current : Option Principal) (peer : alloc.vec.Vec U8) :
    admit current peer ⦃ out =>
      (∀ revision, out = .Ok revision ↔ ∃ principal,
        current = some principal ∧ principal.active = true ∧
        peer ∈ principal.members.val ∧ revision = principal.revision) ∧
      (out = .Err .Revoked ∨ ∃ revision, out = .Ok revision) ⦄ := by
  cases current with
  | none => simp [admit]
  | some principal =>
    unfold admit
    by_cases active : principal.active = true
    · simp only [active, ↓reduceIte]
      step
      have membership : (b = true ↔ peer ∈ principal.members.val) := by
        simpa [alloc.vec.Vec.deref] using b_post
      cases found : b with
      | false =>
        have absent : peer ∉ principal.members.val := by simpa only [found, Bool.false_eq_true, false_iff] using membership
        simp only [Bool.false_eq_true, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        constructor
        · intro revision
          constructor
          · intro impossible; cases impossible
          · rintro ⟨other, equal, _, member, _⟩
            cases Option.some.inj equal
            exact False.elim (absent member)
        · exact Or.inl rfl
      | true =>
        have present : peer ∈ principal.members.val := membership.mp found
        simp only [↓reduceIte]
        apply (WP.spec_ok _).mpr
        constructor
        · intro revision
          constructor
          · intro same
            have eq := core.result.Result.Ok.inj same
            exact ⟨principal, rfl, active, present, eq.symm⟩
          · rintro ⟨other, equal, _, _, revision_eq⟩
            cases Option.some.inj equal
            simp only [revision_eq]
        · exact Or.inr ⟨principal.revision, rfl⟩
    · have inactive : principal.active = false := by cases h : principal.active <;> simp_all
      simp [inactive]

/-- Successful revocation records a tombstone. Invalid persisted revisions
    fail with storage denial; the adapter may not acknowledge those as commits. -/
theorem revoke_contract (current : Option Principal) :
    revoke current ⦃ out => match out with
      | .Err denial => denial = .Storage ∧ ∃ prior, current = some prior ∧
          (prior.revision < 1#i64 ∨ prior.revision = core.num.I64.MAX)
      | .Ok result => result.active = false ∧
          result.members = (match current with | none => alloc.vec.Vec.new _ | some p => p.members) ∧
          result.revision.val = (match current with | none => 1 | some p => p.revision.val + 1) ⦄ := by
  cases current with
  | none => simp [revoke]
  | some prior =>
    unfold revoke
    by_cases low : prior.revision < 1#i64
    · simp only [low, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      exact ⟨rfl, prior, rfl, Or.inl low⟩
    · simp only [low, ↓reduceIte]
      by_cases maximum : prior.revision = core.num.I64.MAX
      · simp [maximum]
      · simp only [maximum, ↓reduceIte]
        have upper : prior.revision.val < 9223372036854775807 := by
          have maxval : core.num.I64.MAX.val = 9223372036854775807 := by rfl
          have different : prior.revision.val ≠ core.num.I64.MAX.val :=
            fun equal => maximum (IScalar.eq_of_val_eq equal)
          rw [maxval] at different
          have bound : prior.revision.val ≤ 9223372036854775807 := by scalar_tac
          omega
        step
        simp_all

theorem revoked_result_is_inactive (current : Option Principal) (result : Principal)
    (success : revoke current = Result.ok (.Ok result)) : result.active = false := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (revoke_contract current)
  have equal : out = .Ok result := Result.ok_injective (returned.symm.trans success)
  rw [equal] at property
  exact property.1

theorem revocation_denies_every_peer (current : Option Principal) (result : Principal)
    (success : revoke current = Result.ok (.Ok result)) (peer : alloc.vec.Vec U8) :
    admit (some result) peer = Result.ok (.Err .Revoked) := by
  have inactive := revoked_result_is_inactive current result success
  simp [admit, inactive]

theorem preemptive_revocation_exact :
    revoke none = Result.ok (.Ok ⟨false, alloc.vec.Vec.new _, 1#i64⟩) := by rfl

theorem reserve_new_exact (digest : alloc.vec.Vec U8) :
    reserve none digest = Result.ok (.Ok ⟨digest, false⟩) := by rfl

theorem existing_key_is_spent (prior : Reservation) (digest : alloc.vec.Vec U8) :
    reserve (some prior) digest = Result.ok (.Err .OutcomeUnknown) := by rfl

theorem finish_contract (current : Option Reservation) (digest : alloc.vec.Vec U8) :
    finish current digest ⦃ out => match out with
      | .Err denial => denial = .OutcomeUnknown ∧
          (current = none ∨ ∃ prior, current = some prior ∧ prior.digest ≠ digest)
      | .Ok result => ∃ prior, current = some prior ∧ prior.digest = digest ∧
          result = {prior with completed := true} ⦄ := by
  cases current with
  | none => simp [finish]
  | some prior =>
    unfold finish
    simp only
    obtain ⟨different, checked, equivalent⟩ := returned_of_spec (bytes_ne_spec prior.digest digest)
    rw [checked]
    simp only [bind_ok]
    cases different <;> simp_all

theorem successful_finish_preserves_digest (current : Option Reservation)
    (digest : alloc.vec.Vec U8) (result : Reservation)
    (success : finish current digest = Result.ok (.Ok result)) :
    result.digest = digest ∧ result.completed = true := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (finish_contract current digest)
  have equal : out = .Ok result := Result.ok_injective (returned.symm.trans success)
  rw [equal] at property
  obtain ⟨prior, _, same_digest, exact_result⟩ := property
  simp [exact_result, same_digest]

/-- Committed decisions for one principal name. Only actual successful Rust
    updates change the stored row; checks and denied/failed updates preserve it.
    Relating SQL execution/commit to these steps remains an adapter obligation. -/
inductive PrincipalStep : Option Principal → Option Principal → Prop where
  | activate (before : Option Principal) (members : alloc.vec.Vec (alloc.vec.Vec U8))
      (after : Principal) (success : activate before members = Result.ok (.Ok after)) :
      PrincipalStep before (some after)
  | revoke (before : Option Principal) (after : Principal)
      (success : revoke before = Result.ok (.Ok after)) : PrincipalStep before (some after)
  | unchanged (before : Option Principal) : PrincipalStep before before

inductive PrincipalHistory : Option Principal → Option Principal → Prop where
  | nil (state : Option Principal) : PrincipalHistory state state
  | next {first middle last : Option Principal} (step : PrincipalStep first middle)
      (tail : PrincipalHistory middle last) : PrincipalHistory first last

def Tombstone (state : Option Principal) : Prop :=
  ∃ row, state = some row ∧ row.active = false

theorem principal_step_preserves_tombstone {before after : Option Principal}
    (step : PrincipalStep before after) (tombstone : Tombstone before) : Tombstone after := by
  cases step with
  | activate members after success =>
    obtain ⟨prior, equal, _⟩ := tombstone
    rw [equal, activate_existing_rejected] at success
    cases Result.ok_injective success
  | revoke after success =>
    exact ⟨after, rfl, revoked_result_is_inactive _ after success⟩
  | unchanged => exact tombstone

theorem principal_history_preserves_tombstone {before after : Option Principal}
    (history : PrincipalHistory before after) (tombstone : Tombstone before) : Tombstone after := by
  induction history with
  | nil => exact tombstone
  | next step tail ih => exact ih (principal_step_preserves_tombstone step tombstone)

theorem no_future_member_admission_after_revocation {before after : Option Principal}
    (revoked : Tombstone before) (history : PrincipalHistory before after)
    (peer : alloc.vec.Vec U8) : admit after peer = Result.ok (.Err .Revoked) := by
  obtain ⟨row, equal, inactive⟩ := principal_history_preserves_tombstone history revoked
  simp [equal, admit, inactive]

def witnessPeer : alloc.vec.Vec U8 := alloc.vec.Vec.from [65#u8] (by scalar_tac)
def witnessMembers : alloc.vec.Vec (alloc.vec.Vec U8) := alloc.vec.Vec.from [witnessPeer] (by scalar_tac)
def witnessPrincipal : Principal := ⟨true, witnessMembers, 1#i64⟩

theorem member_admission_positive_witness :
    admit (some witnessPrincipal) witnessPeer = Result.ok (.Ok 1#i64) := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (admit_contract (some witnessPrincipal) witnessPeer)
  have admitted := (property.1 1#i64).mpr ⟨witnessPrincipal, rfl, rfl,
    by simp [witnessPrincipal, witnessMembers], rfl⟩
  rw [admitted] at returned
  exact returned

theorem matching_finish_exact (prior : Reservation) :
    finish (some prior) prior.digest = Result.ok (.Ok {prior with completed := true}) := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (finish_contract (some prior) prior.digest)
  cases out with
  | Err denial => simp at property
  | Ok result =>
    obtain ⟨old, equal, _, exact_result⟩ := property
    cases Option.some.inj equal
    rw [exact_result] at returned
    exact returned

/-- Reservation history for one principal-scoped key; no deletion/forget step
    exists in the authority. The SQLite adapter must preserve that vocabulary. -/
inductive ReservationStep : Option Reservation → Option Reservation → Prop where
  | reserve (before : Option Reservation) (digest : alloc.vec.Vec U8) (after : Reservation)
      (success : reserve before digest = Result.ok (.Ok after)) : ReservationStep before (some after)
  | finish (before : Option Reservation) (digest : alloc.vec.Vec U8) (after : Reservation)
      (success : finish before digest = Result.ok (.Ok after)) : ReservationStep before (some after)
  | unchanged (before : Option Reservation) : ReservationStep before before

inductive ReservationHistory : Option Reservation → Option Reservation → Prop where
  | nil (state : Option Reservation) : ReservationHistory state state
  | next {first middle last : Option Reservation} (step : ReservationStep first middle)
      (tail : ReservationHistory middle last) : ReservationHistory first last

def Spent (state : Option Reservation) : Prop := ∃ row, state = some row

theorem reservation_step_preserves_spent {before after : Option Reservation}
    (step : ReservationStep before after) (spent : Spent before) : Spent after := by
  cases step with
  | reserve digest after success =>
    obtain ⟨prior, equal⟩ := spent
    rw [equal, existing_key_is_spent] at success
    cases Result.ok_injective success
  | finish digest after success => exact ⟨after, rfl⟩
  | unchanged => exact spent

theorem reservation_history_preserves_spent {before after : Option Reservation}
    (history : ReservationHistory before after) (spent : Spent before) : Spent after := by
  induction history with
  | nil => exact spent
  | next step tail ih => exact ih (reservation_step_preserves_spent step spent)

theorem no_future_reservation_of_spent_key {before after : Option Reservation}
    (spent : Spent before) (history : ReservationHistory before after)
    (digest : alloc.vec.Vec U8) : reserve after digest = Result.ok (.Err .OutcomeUnknown) := by
  obtain ⟨row, equal⟩ := reservation_history_preserves_spent history spent
  rw [equal, existing_key_is_spent]

theorem operator_admission_positive_witness :
    require_operator (alloc.vec.Vec.deref witnessMembers) witnessPeer = Result.ok (.Ok ()) := by
  obtain ⟨out, returned, property⟩ := returned_of_spec
    (require_operator_contract (alloc.vec.Vec.deref witnessMembers) witnessPeer)
  have admitted : out = .Ok () := property.1.mpr (by simp [witnessMembers, alloc.vec.Vec.deref])
  rw [admitted] at returned
  exact returned

attribute [local instance] Classical.propDecidable

/-- Wire strings are parsed by the native adapter. This predicate classifies
    the closed action type passed to the actual extracted authorization gate. -/
def OperatorAction : Action → Prop
  | .Activate | .Revoke | .Status => True
  | .Check | .Reserve | .Finish => False

noncomputable def ExpectedMemberAdmission (current : Option Principal)
    (peer : alloc.vec.Vec U8) : core.result.Result (Option I64) Denial := by
  classical
  exact match current with
  | none => .Err .Revoked
  | some row => if row.active = true ∧ peer ∈ row.members.val
      then .Ok (some row.revision) else .Err .Revoked

noncomputable def ExpectedAuthorization (action : Action)
    (operators : Slice (alloc.vec.Vec U8)) (peer : alloc.vec.Vec U8)
    (current : Option Principal) : core.result.Result (Option I64) Denial := by
  classical
  exact if OperatorAction action then
    if peer ∈ operators.val then .Ok none else .Err .Denied
  else ExpectedMemberAdmission current peer

theorem require_operator_exact (operators : Slice (alloc.vec.Vec U8))
    (peer : alloc.vec.Vec U8) :
    require_operator operators peer = Result.ok
      (if peer ∈ operators.val then .Ok () else .Err .Denied) := by
  classical
  obtain ⟨out, returned, property⟩ := returned_of_spec (require_operator_contract operators peer)
  by_cases member : peer ∈ operators.val
  · simpa only [ite_eq_left member, property.1.mpr member] using returned
  · simpa only [ite_eq_right member, property.2.mpr member] using returned

theorem require_operator_for_exact (action : Action)
    (operators : Slice (alloc.vec.Vec U8)) (peer : alloc.vec.Vec U8) :
    require_operator_for action operators peer = Result.ok
      (if OperatorAction action ∧ peer ∉ operators.val then .Err .Denied else .Ok ()) := by
  classical
  cases action <;> simp [require_operator_for, require_operator_exact, OperatorAction]

theorem authorize_exact (action : Action) (operators : Slice (alloc.vec.Vec U8))
    (peer : alloc.vec.Vec U8) (current : Option Principal) :
    authorize action operators peer current = Result.ok (ExpectedAuthorization action operators peer current) := by
  classical
  obtain ⟨out, returned, property⟩ := returned_of_spec (admit_contract current peer)
  have member_exact : (do
      let r ← admit current peer
      match r with
      | .Ok revision => Result.ok (core.result.Result.Ok (some revision))
      | .Err denial => Result.ok (core.result.Result.Err denial)) =
        Result.ok (ExpectedMemberAdmission current peer) := by
    rw [returned]
    simp only [bind_ok]
    rcases property.2 with revoked | ⟨revision, allowed⟩
    · rw [revoked]
      cases current with
      | none => rfl
      | some row =>
        have unavailable : ¬(row.active = true ∧ peer ∈ row.members.val) := by
          intro present
          have positive := (property.1 row.revision).mpr ⟨row, rfl, present.1, present.2, rfl⟩
          rw [revoked] at positive
          cases positive
        simp [ExpectedMemberAdmission, unavailable]
    · rw [allowed]
      obtain ⟨row, snapshot, active, member, equal⟩ := (property.1 revision).mp allowed
      simp [ExpectedMemberAdmission, snapshot, active, member, equal]
  by_cases operator : peer ∈ operators.val <;> cases action <;>
    simp [authorize, require_operator_for, require_operator_exact,
      ExpectedAuthorization, OperatorAction, operator,
      core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  all_goals
    rw [returned] at member_exact ⊢
    cases out <;> simpa [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] using member_exact

/-- An operator certificate is not a substitute for principal membership. -/
theorem operator_without_membership_denied (action : Action)
    (member_action : ¬OperatorAction action) (operators : Slice (alloc.vec.Vec U8))
    (peer : alloc.vec.Vec U8) (current : Option Principal)
    (unavailable : ∀ row, current = some row →
      ¬(row.active = true ∧ peer ∈ row.members.val)) :
    authorize action operators peer current = Result.ok (.Err .Revoked) := by
  rw [authorize_exact]
  simp only [ExpectedAuthorization, ite_eq_right member_action]
  cases current with
  | none => rfl
  | some row => simp [ExpectedMemberAdmission, unavailable row rfl]

/-- Principal membership is not a substitute for configured operator authority. -/
theorem member_without_operator_denied (action : Action)
    (operator_action : OperatorAction action) (operators : Slice (alloc.vec.Vec U8))
    (peer : alloc.vec.Vec U8) (current : Option Principal) (absent : peer ∉ operators.val) :
    authorize action operators peer current = Result.ok (.Err .Denied) := by
  rw [authorize_exact]
  simp [ExpectedAuthorization, operator_action, absent]

theorem every_member_action_denied_after_revocation {before after : Option Principal}
    (revoked : Tombstone before) (history : PrincipalHistory before after)
    (action : Action) (member_action : ¬OperatorAction action)
    (operators : Slice (alloc.vec.Vec U8)) (peer : alloc.vec.Vec U8) :
    authorize action operators peer after = Result.ok (.Err .Revoked) := by
  obtain ⟨row, snapshot, inactive⟩ := principal_history_preserves_tombstone history revoked
  apply operator_without_membership_denied action member_action operators peer after
  intro other equal
  rw [snapshot] at equal
  cases Option.some.inj equal
  simp [inactive]

theorem every_action_authorization_positive_witness (action : Action) :
    authorize action witnessMembers.slice witnessPeer (some witnessPrincipal) =
      Result.ok (.Ok (if OperatorAction action then none else some 1#i64)) := by
  classical
  have member : witnessPeer ∈ witnessMembers.val := by simp [witnessMembers]
  have operator : witnessPeer ∈ witnessMembers.slice.val := member
  rw [authorize_exact]
  by_cases role : OperatorAction action <;>
    simp [ExpectedAuthorization, ExpectedMemberAdmission, witnessPrincipal, member, operator, role]

end aivm_secrets_garrett_core.coordinator_authority.Proofs
