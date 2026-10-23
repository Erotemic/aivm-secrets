import GarrettApproval
import GarrettTrust

/-!
# The host's approval store

Source: `rust/crates/aivm-secrets-garrett-core/src/approval.rs`
(`take`, `admit`, `install`), called by the native approval adapter
(`custody/approval.rs`) for every guest request and every host `approve`.

Proved here, over the extracted definitions:

* `take_spec`: `take` returns the **first** slot whose digest is the request
  digest, and the store with exactly that slot removed.
* `admit_spec`: the decision is `consume` applied to that slot, and the new
  store is the rest plus whatever `consume` handed back.
* `admit_write_spec`: in `approve` mode a write is `Allowed` exactly when the
  store holds a live slot for this digest; `Allowed` removes it, `Required`
  keeps the store's slots.
* `install_spec`, `install_unique`: a new slot replaces any slot with its
  digest; expired slots are dropped; a full store refuses. The store keeps at
  most one slot per digest.
* `spent_slot_is_gone`, `spent_approval_cannot_be_reused`: after an `Allowed`
  write, no slot for that digest remains, so the same request is `Required`
  again at any later time.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.trust.Proofs (bytes_eq_exact)
set_option maxHeartbeats 2000000

namespace aivm_secrets_garrett_core.approval.Proofs

/-- A slot for this request digest. -/
def ForDigest (wanted : alloc.vec.Vec U8) (slot : Approval) : Bool :=
  decide (slot.digest = wanted)

/-- At most one slot per digest. -/
def Unique (slots : List Approval) : Prop :=
  (slots.map (·.digest)).Nodup

/-- A slot that survives installing `slot` at `now`. -/
def Survives (slot : Approval) (now : I64) (here : Approval) : Bool :=
  decide (here.digest ≠ slot.digest ∧ now.val < here.expires_at.val)

theorem copy_exact (slot : Approval) : copy slot = Result.ok slot := by
  unfold copy
  have cloned : alloc.vec.CloneVec.clone core.clone.CloneU8 slot.digest = Result.ok slot.digest := by
    unfold alloc.vec.CloneVec.clone
    obtain ⟨copied, returned, property⟩ := returned_of_spec
      (Slice.clone_spec (s := slot.digest.slice) (clone := core.clone.CloneU8.clone) (by intro x hx; rfl))
    rw [returned]
    simp only [bind_tc_ok, ← property]
  simp [cloned]

theorem take_loop_spec (store : alloc.vec.Vec Approval) (wanted : alloc.vec.Vec U8)
    (slot : Option Approval) (rest : alloc.vec.Vec Approval) (index : Usize)
    (bound : index.val ≤ store.length)
    (found : slot = (store.val.take index.val).find? (ForDigest wanted))
    (erased : rest.val = (store.val.take index.val).eraseP (ForDigest wanted)) :
    take_loop store wanted slot rest index ⦃ out =>
      out.1 = store.val.find? (ForDigest wanted) ∧
        out.2.val = store.val.eraseP (ForDigest wanted) ⦄ := by
  suffices ∀ n (index : Usize) slot (rest : alloc.vec.Vec Approval), store.length - index.val = n →
      index.val ≤ store.length →
      slot = (store.val.take index.val).find? (ForDigest wanted) →
      rest.val = (store.val.take index.val).eraseP (ForDigest wanted) →
      take_loop store wanted slot rest index ⦃ out =>
        out.1 = store.val.find? (ForDigest wanted) ∧
          out.2.val = store.val.eraseP (ForDigest wanted) ⦄ from
    this _ index slot rest rfl bound found erased
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index slot rest measure bound found erased
    rw [take_loop.eq_def]
    dsimp only
    split
    · rename_i inside
      have grow : store.val.take (index.val + 1) =
          store.val.take index.val ++ [store.val[index.val]'(by scalar_tac)] := by
        exact List.take_succ_eq_append_getElem (by scalar_tac)
      have rest_short : rest.length ≤ index.val := by
        have := List.length_eraseP_le (p := ForDigest wanted) (l := store.val.take index.val)
        have : rest.val.length = rest.length := rfl
        simp_all
      cases slot with
      | none =>
        have missing : ∀ a ∈ store.val.take index.val, ForDigest wanted a = false := by
          intro a mem
          have := List.find?_eq_none.mp found.symm a mem
          simpa using this
        have unerased : (store.val.take index.val).eraseP (ForDigest wanted) = store.val.take index.val :=
          List.eraseP_of_forall_not (by intro a mem; simp [missing a mem])
        step as ⟨here, hhere⟩
        simp only [bytes_eq_exact, copy_exact]
        by_cases hit : here.digest = wanted
        · simp only [hit, ↓reduceIte, bind_ok]
          step as ⟨again, hagain⟩
          step as ⟨next, hnext⟩
          refine ih _ (by scalar_tac) next _ _ rfl (by scalar_tac) ?_ ?_
          · rw [hnext, grow, List.find?_append, ← found]
            simp [ForDigest, ← hhere, hit, hagain]
          · rw [hnext, grow, List.eraseP_append]
            have : ¬ (List.take ↑index ↑store).any (ForDigest wanted) = true := by
              simp only [List.any_eq_true, not_exists, not_and]
              intro a mem; simp [missing a mem]
            simp [this, unerased, erased, ForDigest, ← hhere, hit]
        · simp only [hit, ↓reduceIte, bind_ok, Bool.false_eq_true]
          step as ⟨again, hagain⟩
          step as ⟨pushed, hpushed⟩
          step as ⟨next, hnext⟩
          have miss : ForDigest wanted here = false := by simp [ForDigest, hit]
          refine ih _ (by scalar_tac) next _ _ rfl (by scalar_tac) ?_ ?_
          · rw [hnext, grow, List.find?_append, ← found]
            rw [← hhere]; simp [miss]
          · rw [hnext, grow, List.eraseP_append, hpushed, erased, unerased, ← hhere]
            have : ¬ (List.take ↑index ↑store).any (ForDigest wanted) = true := by
              simp only [List.any_eq_true, not_exists, not_and]
              intro a mem; simp [missing a mem]
            have kept : List.eraseP (ForDigest wanted) [here] = [here] := by simp [miss]
            simp only [this, Bool.false_eq_true, ↓reduceIte, hagain, hhere]
            congr 1
            rw [← hhere, kept]
      | some held =>
        have present : (List.take ↑index ↑store).any (ForDigest wanted) = true := by
          rw [List.any_eq_true]
          obtain ⟨mem, sat⟩ := List.mem_of_find?_eq_some found.symm, List.find?_some found.symm
          exact ⟨held, mem, sat⟩
        simp only [bind_ok, Bool.false_eq_true, ↓reduceIte, copy_exact]
        step as ⟨here, hhere⟩
        step as ⟨pushed, hpushed⟩
        step as ⟨next, hnext⟩
        refine ih _ (by scalar_tac) next _ _ rfl (by scalar_tac) ?_ ?_
        · rw [hnext, grow, List.find?_append, ← found]
          rfl
        · rw [hnext, grow, List.eraseP_append, hpushed, erased]
          simp [present, hhere]
    · have whole : store.val.take index.val = store.val := List.take_of_length_le (by scalar_tac)
      simp only [WP.spec_ok]
      rw [whole] at found erased
      exact ⟨found, erased⟩

/-- `take` returns the first slot for this digest and the store without it. -/
theorem take_spec (store : alloc.vec.Vec Approval) (wanted : alloc.vec.Vec U8) :
    take store wanted ⦃ out =>
      out.slot = store.val.find? (ForDigest wanted) ∧
        out.rest.val = store.val.eraseP (ForDigest wanted) ⦄ := by
  unfold take
  apply WP.spec_bind (take_loop_spec store wanted none (alloc.vec.Vec.new Approval) 0#usize
    (by scalar_tac) (by simp) (by simp [alloc.vec.Vec.new]))
  intro pair property
  obtain ⟨slot, rest⟩ := pair
  simpa [WP.spec_ok] using property

/-- `consume` always returns, and hands back either nothing or the slot it was given. -/
theorem consume_returns (mode : Mode) (write : Bool) (wanted : alloc.vec.Vec U8) (now : I64)
    (prior : Option Approval) :
    ∃ decided, consume mode write wanted now prior = Result.ok decided ∧
      (decided.2 = none ∨ decided.2 = prior) := by
  unfold consume
  cases write
  · simp
  · cases mode
    · simp
    · cases prior with
      | none => simp
      | some slot =>
        obtain ⟨different, returned, _⟩ := returned_of_spec (bytes_ne_spec slot.digest wanted)
        simp only [↓reduceIte, returned]
        split <;> cases different <;> simp
    · simp

/-- **The store-level decision.** `admit` decides with `consume` on exactly
    the first slot for this digest; the new store is the others plus whatever
    `consume` handed back. -/
theorem admit_spec (store : alloc.vec.Vec Approval) (mode : Mode) (write : Bool)
    (wanted : alloc.vec.Vec U8) (now : I64) :
    admit store mode write wanted now ⦃ out =>
      ∃ decided, consume mode write wanted now (store.val.find? (ForDigest wanted)) = Result.ok decided ∧
        out.decision = decided.1 ∧
        out.store.val = store.val.eraseP (ForDigest wanted) ++ decided.2.toList ⦄ := by
  unfold admit
  apply WP.spec_bind (take_spec store wanted)
  intro taken ⟨found, erased⟩
  obtain ⟨decided, returned, handed⟩ := consume_returns mode write wanted now taken.slot
  obtain ⟨decision, back⟩ := decided
  rw [returned]
  cases back with
  | none =>
    refine WP.spec_bind (Pₘ := fun x => x = (decision, none)) (by simp [WP.spec_ok]) ?_
    rintro _ rfl
    change (Result.ok ({ decision := decision, store := taken.rest } : Admitted)) ⦃ _ ⦄
    simp only [WP.spec_ok]
    exact ⟨(decision, none), by rw [← found]; exact returned, rfl, by simp [erased]⟩
  | some kept =>
    have was : taken.slot = some kept := (by simpa using handed : some kept = taken.slot).symm
    have shorter : taken.rest.length + 1 ≤ store.length := by
      have mem := List.mem_of_find?_eq_some (found ▸ was)
      have sat := List.find?_some (found ▸ was)
      have shrunk := List.length_eraseP_of_mem mem sat
      rw [← erased] at shrunk
      have : 0 < store.val.length := List.length_pos_of_mem mem
      simp only [alloc.vec.Vec.length]
      omega
    refine WP.spec_bind (Pₘ := fun x => x = (decision, some kept)) (by simp [WP.spec_ok]) ?_
    rintro _ rfl
    change (do
      let rest ← taken.rest.push kept
      Result.ok ({ decision := decision, store := rest } : Admitted)) ⦃ _ ⦄
    step as ⟨pushed, hpushed⟩
    exact ⟨(decision, some kept), by rw [← found]; exact returned, rfl, by simp [hpushed, erased]⟩

/-- **Exact-write admission in `approve` mode.** A write is `Allowed` exactly
    when the store holds a live slot for this digest. `Allowed` removes that
    slot; `Required` leaves the store's slots as they were. -/
theorem admit_write_spec (store : alloc.vec.Vec Approval) (wanted : alloc.vec.Vec U8) (now : I64) :
    admit store .Approve true wanted now ⦃ out =>
      (out.decision = .Allowed ↔ Eligible (store.val.find? (ForDigest wanted)) wanted now) ∧
      (out.decision = .Required ↔ ¬ Eligible (store.val.find? (ForDigest wanted)) wanted now) ∧
      (out.decision = .Allowed → out.store.val = store.val.eraseP (ForDigest wanted)) ∧
      (out.decision = .Required →
        out.store.val = store.val.eraseP (ForDigest wanted) ++ (store.val.find? (ForDigest wanted)).toList) ⦄ := by
  apply WP.spec_mono (admit_spec store .Approve true wanted now)
  intro out ⟨decided, returned, decision, stored⟩
  obtain ⟨result, returned', property⟩ := returned_of_spec
    (approved_write_contract wanted now (store.val.find? (ForDigest wanted)))
  have same : result = decided := Result.ok_injective (returned'.symm.trans returned)
  subst same
  obtain ⟨allowed, required, spent, kept⟩ := property
  refine ⟨by rw [decision]; exact allowed, by rw [decision]; exact required, ?_, ?_⟩
  · intro h; rw [stored, spent (decision ▸ h)]; simp
  · intro h; rw [stored, kept (decision ▸ h)]

/-- No slot left after removing the first slot for a digest is for that digest,
    when the store held at most one slot per digest. -/
theorem unique_erase_clears (wanted : alloc.vec.Vec U8) :
    ∀ (slots : List Approval), Unique slots →
      ∀ other ∈ slots.eraseP (ForDigest wanted), ForDigest wanted other = false
  | [], _ => by simp
  | head :: tail, unique => by
    have unique' : Unique tail := (List.nodup_cons.mp unique).2
    have fresh : head.digest ∉ tail.map (·.digest) := (List.nodup_cons.mp unique).1
    intro other mem
    by_cases hit : ForDigest wanted head = true
    · rw [List.eraseP_cons_of_pos hit] at mem
      have : head.digest = wanted := by simpa [ForDigest] using hit
      simp only [ForDigest, decide_eq_false_iff_not]
      intro same
      exact fresh (List.mem_map.mpr ⟨other, mem, by rw [same, this]⟩)
    · rw [List.eraseP_cons_of_neg hit] at mem
      rcases List.mem_cons.mp mem with same | rest
      · subst same; simpa using hit
      · exact unique_erase_clears wanted tail unique' other rest

theorem unique_sublist {small large : List Approval} (sub : small.Sublist large)
    (unique : Unique large) : Unique small :=
  List.Nodup.sublist (sub.map _) unique

/-- `admit` keeps at most one slot per digest. -/
theorem admit_unique (store : alloc.vec.Vec Approval) (mode : Mode) (write : Bool)
    (wanted : alloc.vec.Vec U8) (now : I64) (unique : Unique store.val) :
    admit store mode write wanted now ⦃ out => Unique out.store.val ⦄ := by
  apply WP.spec_mono (admit_spec store mode write wanted now)
  intro out ⟨decided, returned, _, stored⟩
  obtain ⟨decided', returned', handed⟩ := consume_returns mode write wanted now (store.val.find? (ForDigest wanted))
  have same : decided' = decided := Result.ok_injective (returned'.symm.trans returned)
  subst same
  have erased : Unique (store.val.eraseP (ForDigest wanted)) :=
    unique_sublist (List.eraseP_sublist) unique
  rw [stored]
  rcases handed with none | back
  · simpa [none] using erased
  · rw [back]
    cases found : store.val.find? (ForDigest wanted) with
    | none => simpa using erased
    | some slot =>
      have sat : slot.digest = wanted := by simpa [ForDigest] using List.find?_some found
      simp only [Option.toList_some, Unique, List.map_append, List.map_cons, List.map_nil]
      refine List.nodup_append.mpr ⟨erased, by simp, ?_⟩
      intro a mem b memb
      simp only [List.mem_singleton] at memb
      subst memb
      obtain ⟨other, mem', hother⟩ := List.mem_map.mp mem
      have := unique_erase_clears wanted store.val unique other mem'
      simp only [ForDigest, decide_eq_false_iff_not] at this
      intro equal
      exact this (by rw [hother, equal, sat])

/-- **A spent approval is gone.** After an `Allowed` write, no slot in the
    store is for that request digest. -/
theorem spent_slot_is_gone (store : alloc.vec.Vec Approval) (wanted : alloc.vec.Vec U8) (now : I64)
    (unique : Unique store.val) :
    admit store .Approve true wanted now ⦃ out =>
      out.decision = .Allowed → ∀ slot ∈ out.store.val, slot.digest ≠ wanted ⦄ := by
  apply WP.spec_mono (admit_write_spec store wanted now)
  intro out ⟨_, _, spent, _⟩ allowed slot mem
  rw [spent allowed] at mem
  have := unique_erase_clears wanted store.val unique slot mem
  simpa [ForDigest] using this

/-- **A spent approval cannot be reused.** The same request is `Required`
    again against the store an `Allowed` write left, at any later time. -/
theorem spent_approval_cannot_be_reused (store : alloc.vec.Vec Approval) (wanted : alloc.vec.Vec U8)
    (now later : I64) (unique : Unique store.val) (after : Admitted)
    (returned : admit store .Approve true wanted now = Result.ok after)
    (allowed : after.decision = .Allowed) :
    admit after.store .Approve true wanted later ⦃ out => out.decision = .Required ⦄ := by
  obtain ⟨first, ran, property⟩ := returned_of_spec (spent_slot_is_gone store wanted now unique)
  have same : first = after := Result.ok_injective (ran.symm.trans returned)
  rw [same] at property
  have gone := property allowed
  apply WP.spec_mono (admit_write_spec after.store wanted later)
  intro out ⟨_, required, _, _⟩
  apply required.mpr
  rintro ⟨slot, found, digest, _⟩
  exact gone slot (List.mem_of_find?_eq_some found) digest

theorem install_loop_spec (store : alloc.vec.Vec Approval) (slot : Approval) (now : I64)
    (kept : alloc.vec.Vec Approval) (index : Usize) (bound : index.val ≤ store.length)
    (filtered : kept.val = (store.val.take index.val).filter (Survives slot now)) :
    install_loop store slot now kept index ⦃ out =>
      out.1 = slot ∧ out.2.val = store.val.filter (Survives slot now) ⦄ := by
  suffices ∀ n (index : Usize) (kept : alloc.vec.Vec Approval), store.length - index.val = n →
      index.val ≤ store.length →
      kept.val = (store.val.take index.val).filter (Survives slot now) →
      install_loop store slot now kept index ⦃ out =>
        out.1 = slot ∧ out.2.val = store.val.filter (Survives slot now) ⦄ from
    this _ index kept rfl bound filtered
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index kept measure bound filtered
    rw [install_loop.eq_def]
    dsimp only
    split
    · have grow : store.val.take (index.val + 1) =
          store.val.take index.val ++ [store.val[index.val]'(by scalar_tac)] :=
        List.take_succ_eq_append_getElem (by scalar_tac)
      have short : kept.length ≤ index.val := by
        have := List.length_filter_le (Survives slot now) (store.val.take index.val)
        simp only [alloc.vec.Vec.length] at *
        rw [filtered]
        simp_all
      step as ⟨here, hhere⟩
      obtain ⟨different, returned, related⟩ := returned_of_spec (bytes_ne_spec here.digest slot.digest)
      rw [returned]
      simp only [copy_exact]
      have next_kept : ∀ kept' : alloc.vec.Vec Approval,
          kept'.val = kept.val ++ (if Survives slot now here then [here] else []) →
          (do
            let index1 ← index + 1#usize
            install_loop store slot now kept' index1) ⦃ out =>
              out.1 = slot ∧ out.2.val = store.val.filter (Survives slot now) ⦄ := by
        intro kept' hkept
        step as ⟨next, hnext⟩
        refine ih _ (by scalar_tac) next kept' rfl (by scalar_tac) ?_
        rw [hnext, grow, List.filter_append, hkept, filtered, ← hhere]
        by_cases keep : Survives slot now here <;> simp [keep]
      by_cases live : now.val < here.expires_at.val
      · cases different
        · have same : here.digest = slot.digest := by simpa using related
          simp only [bind_ok, Bool.false_eq_true, ↓reduceIte]
          exact next_kept kept (by simp [Survives, same])
        · have apart : here.digest ≠ slot.digest := related.mp rfl
          have lt : now < here.expires_at := by scalar_tac
          simp only [bind_ok, ↓reduceIte, lt]
          step as ⟨pushed, hpushed⟩
          exact next_kept pushed (by simp [hpushed, Survives, apart, live])
      · have not_lt : ¬ now < here.expires_at := by scalar_tac
        cases different <;> simp only [bind_ok, Bool.false_eq_true, ↓reduceIte, not_lt] <;>
          exact next_kept kept (by simp [Survives, live])
    · have whole : store.val.take index.val = store.val := List.take_of_length_le (by scalar_tac)
      simp only [WP.spec_ok, true_and]
      rw [whole] at filtered
      exact filtered

/-- **Installing an approval.** The new slot replaces any slot with its digest
    and expired slots are dropped; the store refuses when the survivors already
    fill it. -/
theorem install_spec (store : alloc.vec.Vec Approval) (slot : Approval) (now : I64) :
    install store slot now ⦃ out =>
      (out = none ↔ STORE_LIMIT.val ≤ (store.val.filter (Survives slot now)).length) ∧
      ∀ installed, out = some installed →
        installed.val = store.val.filter (Survives slot now) ++ [slot] ⦄ := by
  unfold install
  apply WP.spec_bind (install_loop_spec store slot now (alloc.vec.Vec.new Approval) 0#usize
    (by scalar_tac) (by simp [alloc.vec.Vec.new]))
  intro pair ⟨same, filtered⟩
  obtain ⟨slot', kept⟩ := pair
  change (if alloc.vec.Vec.len kept >= STORE_LIMIT then Result.ok none
    else do
      let kept1 ← alloc.vec.Vec.push kept slot'
      Result.ok (some kept1)) ⦃ _ ⦄
  have limit : STORE_LIMIT.val = 16 := by simp [STORE_LIMIT]
  have length : kept.length = (store.val.filter (Survives slot now)).length := by
    simp only [alloc.vec.Vec.length]; rw [filtered]
  simp only at same filtered
  subst same
  split
  · simp only [WP.spec_ok, true_iff, reduceCtorEq, false_implies, implies_true, and_true]
    rw [← length]; scalar_tac
  · step as ⟨pushed, hpushed⟩
    simp only [reduceCtorEq, false_iff, Option.some.injEq, forall_eq', not_le]
    refine ⟨?_, by rw [hpushed, filtered]⟩
    rw [← length]; scalar_tac

/-- `install` keeps at most one slot per digest. -/
theorem install_unique (store : alloc.vec.Vec Approval) (slot : Approval) (now : I64)
    (unique : Unique store.val) :
    install store slot now ⦃ out => ∀ installed, out = some installed → Unique installed.val ⦄ := by
  apply WP.spec_mono (install_spec store slot now)
  intro out ⟨_, shape⟩ installed h
  rw [shape installed h]
  have kept : Unique (store.val.filter (Survives slot now)) := unique_sublist List.filter_sublist unique
  simp only [Unique, List.map_append, List.map_cons, List.map_nil]
  refine List.nodup_append.mpr ⟨kept, by simp, ?_⟩
  intro a mem b memb
  simp only [List.mem_singleton] at memb
  subst memb
  obtain ⟨other, mem', hother⟩ := List.mem_map.mp mem
  have := (List.mem_filter.mp mem').2
  simp only [Survives, decide_eq_true_eq] at this
  intro equal
  exact this.1 (by rw [hother, equal])

end aivm_secrets_garrett_core.approval.Proofs
