import GarrettStatelessLogin

/-!
# `garrett-stateless-v1`: the broker's login mailbox, over every history

Source: `rust/crates/aivm-secrets-garrett-core/src/stateless_mailbox.rs`,
extracted by Aeneas (`stateless_mailbox.*`).
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.proxy_http.Proofs (bind_ok_inv slice_eq_eq)
open aivm_secrets_garrett_core.stateless.Proofs
open aivm_secrets_garrett_core.stateless_login.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.stateless_mailbox.Proofs

theorem slice_index_eq {α : Type} (s : Slice α) (i : Usize) (inside : i.val < s.length) :
    Slice.index_usize s i = Result.ok s.val[i.val] := by
  obtain ⟨y, hy, same⟩ := returned_of_spec (Slice.index_usize_spec s i inside)
  rw [hy, same]

/-! ## Pure views of the slot operations -/

/-- What `kept` decides. -/
def KeptB (now : I64) : Option Slot → Bool
  | none => false
  | some s => decide (s.entry.expires_at.val ≤ 9007199254740991 - 300) &&
      decide (now.val < s.entry.expires_at.val + 300)

/-- One slot after pruning. -/
def pruneOne (now : I64) (o : Option Slot) : Option Slot := if KeptB now o then o else none

/-- Whether a slot holds `login`. -/
def HoldsB (login : List U8) : Option Slot → Bool
  | none => false
  | some s => decide (s.entry.login.val = login)

theorem kept_eq (o : Option Slot) (now : I64) : kept o now = Result.ok (KeptB now o) := by
  unfold kept KeptB stateless.MAX_TIME stateless_login.DELIVERY_GRACE
  cases o with
  | none => rfl
  | some s =>
    simp only
    obtain ⟨c, hc, cv⟩ := returned_of_spec (I64.sub_spec (x := 9007199254740991#i64) (y := 300#i64) (by scalar_tac) (by scalar_tac))
    rw [hc]
    simp only [bind_ok]
    by_cases le : s.entry.expires_at ≤ c
    · have le' : s.entry.expires_at.val ≤ 9007199254740991 - 300 := by scalar_tac
      simp only [le, ↓reduceIte]
      obtain ⟨d, hd, dv⟩ := returned_of_spec (I64.add_spec (x := s.entry.expires_at) (y := 300#i64) (by scalar_tac) (by scalar_tac))
      rw [hd]
      simp only [bind_ok, Result.ok.injEq]
      have : (now < d) = (now.val < s.entry.expires_at.val + 300) := by
        apply propext; constructor <;> intro x <;> scalar_tac
      simp [this]
      omega
    · have le' : ¬ s.entry.expires_at.val ≤ 9007199254740991 - 300 := by scalar_tac
      simp [le]
      omega

theorem set_step {α : Type} (l : List α) (f : α → α) (i : Nat) (hi : i < l.length) :
    (l.set i (f l[i])).take (i + 1) ++ ((l.set i (f l[i])).drop (i + 1)).map f =
      l.take i ++ (l.drop i).map f := by
  have d : (l.set i (f l[i])).drop (i + 1) = l.drop (i + 1) := List.drop_set_of_lt (by omega)
  have t : (l.set i (f l[i])).take (i + 1) = l.take i ++ [f l[i]] := by
    rw [List.take_add_one, List.getElem?_set_self (by simpa using hi)]
    simp [List.take_set_of_le (Nat.le_refl i)]
  rw [d, t, List.append_assoc]
  congr 1
  rw [← List.getElem_cons_drop hi]
  simp only [List.map_cons, List.singleton_append]

theorem usize_succ (i : Usize) (h : i.val + 1 ≤ Usize.max) :
    ∃ j : Usize, i + 1#usize = Result.ok j ∧ j.val = i.val + 1 := by
  obtain ⟨c, hc, v⟩ := returned_of_spec (Usize.add_spec (x := i) (y := 1#usize) (by simpa using h))
  exact ⟨c, hc, by simpa using v⟩

/-- The extracted `prune` empties exactly the slots `kept` drops. -/
theorem prune_loop_eq (now : I64) :
    ∀ n (mb : Mailbox) (index : Usize), mb.slots.val.length - index.val = n →
      ∃ v, prune_loop mb now index = Result.ok (v, mb.next) ∧
        v.val = mb.slots.val.take index.val ++ (mb.slots.val.drop index.val).map (pruneOne now) := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro mb index measure
    rw [prune_loop.eq_def]
    by_cases inside : index.val < mb.slots.val.length
    · have cond : index < alloc.vec.Vec.len mb.slots := by scalar_tac
      simp only [cond, ↓reduceIte, alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
      obtain ⟨o, ho, ov⟩ := returned_of_spec (alloc.vec.Vec.index_usize_spec mb.slots index inside)
      rw [ho]
      simp only [bind_ok, kept_eq]
      have room := mb.slots.property
      obtain ⟨next, hnext, nval⟩ := usize_succ index (by omega)
      -- both branches replace slot `index` by `pruneOne now o`
      have step : ∃ v1, (if KeptB now o = true then Result.ok mb.slots else do
            let (_, back) ← alloc.vec.Vec.index_mut_usize mb.slots index
            Result.ok (back none)) = Result.ok v1 ∧
          v1.val = mb.slots.val.set index.val (pruneOne now o) := by
        by_cases k : KeptB now o = true
        · refine ⟨mb.slots, by simp [k], ?_⟩
          subst ov
          simp [pruneOne, k]
        · obtain ⟨⟨x, back⟩, hb, hx, hback⟩ := returned_of_spec (alloc.vec.Vec.index_mut_usize_spec mb.slots index inside)
          refine ⟨back none, by simp [k, hb], ?_⟩
          simp [hback, pruneOne, k]
      obtain ⟨v1, hv1, v1val⟩ := step
      rw [hv1]
      simp only [bind_ok, hnext]
      have len1 : v1.val.length = mb.slots.val.length := by simp [v1val]
      obtain ⟨v, hv, vval⟩ := ih (mb.slots.val.length - next.val) (by omega)
        { mb with slots := v1 } next (by simp only; rw [len1])
      refine ⟨v, hv, ?_⟩
      rw [vval]
      simp only
      rw [v1val, nval, ov]
      exact set_step _ _ _ inside
    · have cond : ¬ index < alloc.vec.Vec.len mb.slots := by scalar_tac
      simp only [cond, ↓reduceIte]
      refine ⟨mb.slots, rfl, ?_⟩
      have : mb.slots.val.length ≤ index.val := Nat.le_of_not_lt inside
      simp [List.take_of_length_le this, List.drop_of_length_le this]

theorem prune_eq (mb : Mailbox) (now : I64) :
    ∃ mb', prune mb now = Result.ok mb' ∧ mb'.slots.val = mb.slots.val.map (pruneOne now) ∧
      mb'.next = mb.next := by
  obtain ⟨v, hv, vval⟩ := prune_loop_eq now _ mb 0#usize rfl
  refine ⟨{ slots := v, next := mb.next }, by simp [prune, hv], ?_, rfl⟩
  simpa using vval

/-- `live` counts the occupied slots. -/
theorem live_loop_eq (slots : Slice (Option Slot)) :
    ∀ n (count index : Usize), slots.val.length - index.val = n →
      count.val + ((slots.val.drop index.val).filter Option.isSome).length ≤ Usize.max →
      ∃ c, live_loop slots count index = Result.ok c ∧
        c.val = count.val + ((slots.val.drop index.val).filter Option.isSome).length := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro count index measure room
    rw [live_loop.eq_def]
    by_cases inside : index.val < slots.val.length
    · have cond : index < Slice.len slots := by scalar_tac
      simp only [cond, ↓reduceIte]
      have split : slots.val.drop index.val = slots.val[index.val] :: slots.val.drop (index.val + 1) :=
        (List.getElem_cons_drop inside).symm
      rw [slice_index_eq slots index inside]
      simp only [bind_ok]
      have bound := slots.property
      obtain ⟨next, hnext, nval⟩ := usize_succ index (by omega)
      rw [split] at room
      cases hs : slots.val[index.val] with
      | none =>
        rw [hs] at room
        simp only [List.filter_cons, Option.isSome_none, Bool.false_eq_true, ↓reduceIte] at room
        simp only [bind_ok, hnext]
        obtain ⟨c, hc, cv⟩ := ih (slots.val.length - next.val) (by omega) count next (by omega)
          (by rw [nval]; exact room)
        refine ⟨c, hc, ?_⟩
        rw [cv, nval, split, hs]
        simp
      | some s =>
        rw [hs] at room
        simp only [List.filter_cons, Option.isSome_some, ↓reduceIte, List.length_cons] at room
        obtain ⟨c1, hc1, c1v⟩ := usize_succ count (by omega)
        simp only [hc1, bind_ok, hnext]
        obtain ⟨c, hc, cv⟩ := ih (slots.val.length - next.val) (by omega) c1 next (by omega)
          (by rw [nval, c1v]; omega)
        refine ⟨c, hc, ?_⟩
        rw [cv, nval, c1v, split, hs]
        simp only [List.filter_cons, Option.isSome_some, ↓reduceIte, List.length_cons]
        omega
    · have cond : ¬ index < Slice.len slots := by scalar_tac
      simp only [cond, ↓reduceIte]
      have : slots.val.length ≤ index.val := Nat.le_of_not_lt inside
      exact ⟨count, rfl, by simp [List.drop_of_length_le this]⟩

theorem live_eq (slots : Slice (Option Slot)) :
    ∃ c, live slots = Result.ok c ∧ c.val = (slots.val.filter Option.isSome).length := by
  obtain ⟨c, hc, cv⟩ := live_loop_eq slots _ 0#usize 0#usize rfl (by
    have := List.length_filter_le Option.isSome slots.val
    have := slots.property
    have z : (0#usize : Usize).val = 0 := rfl
    rw [z, List.drop_zero]; omega)
  exact ⟨c, hc, by simpa using cv⟩

theorem holds_eq (o : Option Slot) (login : Slice U8) :
    holds o login = Result.ok (HoldsB login.val o) := by
  unfold holds HoldsB
  cases o with
  | none => rfl
  | some s => simp [slice_eq_eq, alloc.vec.Vec.deref]

/-- `find` is `List.findIdx` of `HoldsB`. -/
theorem find_loop_eq (slots : Slice (Option Slot)) (login : Slice U8) :
    ∀ n (index : Usize), slots.val.length - index.val = n → index.val ≤ slots.val.length →
      (∀ j, j < index.val → (h : j < slots.val.length) → HoldsB login.val slots.val[j] = false) →
      ∃ i, find_loop slots login index = Result.ok i ∧ i.val = slots.val.findIdx (HoldsB login.val) := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure upto before
    rw [find_loop.eq_def]
    by_cases inside : index.val < slots.val.length
    · have cond : index < Slice.len slots := by scalar_tac
      simp only [cond, ↓reduceIte]
      rw [slice_index_eq slots index inside]
      simp only [bind_ok, holds_eq]
      split
      · rename_i yes
        refine ⟨index, rfl, ?_⟩
        rw [eq_comm, List.findIdx_eq inside]
        exact ⟨yes, fun j hj => by simpa using before j hj (by omega)⟩
      · rename_i no
        have bound := slots.property
        obtain ⟨next, hnext, nval⟩ := usize_succ index (by omega)
        rw [hnext]
        simp only [bind_ok]
        apply ih (slots.val.length - next.val) (by omega) next rfl (by omega)
        intro j hj hlen
        by_cases same : j = index.val
        · subst same; simpa using no
        · exact before j (by omega) hlen
    · have cond : ¬ index < Slice.len slots := by scalar_tac
      simp only [cond, ↓reduceIte]
      refine ⟨index, rfl, ?_⟩
      have len : slots.val.length ≤ index.val := Nat.le_of_not_lt inside
      have : slots.val.findIdx (HoldsB login.val) = slots.val.length := by
        rw [List.findIdx_eq_length]
        intro x mem
        obtain ⟨j, hj, at_j⟩ := List.getElem_of_mem mem
        rw [← at_j]; simpa using before j (by omega) hj
      omega

theorem find_eq (slots : Slice (Option Slot)) (login : Slice U8) :
    ∃ i, find slots login = Result.ok i ∧ i.val = slots.val.findIdx (HoldsB login.val) :=
  find_loop_eq slots login _ 0#usize rfl (by simp) (by intro j hj; simp at hj)

theorem occupied_eq (o : Option Slot) : occupied o = Result.ok (!o.isNone) := by
  unfold occupied; cases o <;> rfl

/-- `vacancy` is `List.findIdx` of an empty slot. -/
theorem vacancy_loop_eq (slots : Slice (Option Slot)) :
    ∀ n (index : Usize), slots.val.length - index.val = n → index.val ≤ slots.val.length →
      (∀ j, j < index.val → (h : j < slots.val.length) → slots.val[j].isNone = false) →
      ∃ i, vacancy_loop slots index = Result.ok i ∧ i.val = slots.val.findIdx Option.isNone := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure upto before
    rw [vacancy_loop.eq_def]
    by_cases inside : index.val < slots.val.length
    · have cond : index < Slice.len slots := by scalar_tac
      simp only [cond, ↓reduceIte]
      rw [slice_index_eq slots index inside]
      simp only [bind_ok, occupied_eq]
      split
      · rename_i full
        have bound := slots.property
        obtain ⟨next, hnext, nval⟩ := usize_succ index (by omega)
        rw [hnext]
        simp only [bind_ok]
        apply ih (slots.val.length - next.val) (by omega) next rfl (by omega)
        intro j hj hlen
        by_cases same : j = index.val
        · subst same; simpa using full
        · exact before j (by omega) hlen
      · rename_i empty
        refine ⟨index, rfl, ?_⟩
        rw [eq_comm, List.findIdx_eq inside]
        exact ⟨by simpa using empty, fun j hj => by simpa using before j hj (by omega)⟩
    · have cond : ¬ index < Slice.len slots := by scalar_tac
      simp only [cond, ↓reduceIte]
      refine ⟨index, rfl, ?_⟩
      have len : slots.val.length ≤ index.val := Nat.le_of_not_lt inside
      have : slots.val.findIdx Option.isNone = slots.val.length := by
        rw [List.findIdx_eq_length]
        intro x mem
        obtain ⟨j, hj, at_j⟩ := List.getElem_of_mem mem
        rw [← at_j]; simpa using before j (by omega) hj
      omega

theorem vacancy_eq (slots : Slice (Option Slot)) :
    ∃ i, vacancy slots = Result.ok i ∧ i.val = slots.val.findIdx Option.isNone :=
  vacancy_loop_eq slots _ 0#usize rfl (by simp) (by intro j hj; simp at hj)

/-! ## What each transition does to the slots -/

/-- The entry `start` records for a login state. -/
def entryOf (st : stateless_login.LoginState) : stateless_login.Entry :=
  { login := st.login, provider := st.provider, certificate := st.certificate,
    subject := st.subject, certificate_expires := st.certificate_expires,
    issued_at := st.issued_at, expires_at := st.expires_at, stage := .Pending }

/-- The slot `start` records. -/
def newSlot (st : stateless_login.LoginState) (serial : U64) : Slot :=
  { entry := entryOf st, serial := serial, token := alloc.vec.Vec.new U8,
    expires_at := 0#i64, renew_until := 0#i64 }

/-- Put `x` in the first empty slot, or after the last. -/
def place (l : List (Option Slot)) (x : Slot) : List (Option Slot) :=
  if l.findIdx Option.isNone < l.length then l.set (l.findIdx Option.isNone) (some x) else l ++ [some x]

theorem push_ok_val {α : Type} {v w : alloc.vec.Vec α} {x : α}
    (h : alloc.vec.Vec.push v x = Result.ok w) : w.val = v.val ++ [x] := by
  unfold alloc.vec.Vec.push at h
  dsimp only at h
  split at h
  · simp only [Result.ok.injEq] at h
    subst h
    simp
  · simp at h

/-- **`start`.** Either nothing but pruning happened and no login began, or
    `begin` accepted the login for `peer`, the pruned mailbox had room and no
    slot for this login, and the new slot — with the next serial — went into
    the first empty place. -/
theorem start_effect {mb : Mailbox} {policy : stateless_login.LoginPolicy}
    {provider peer subject : Slice U8} {ce : I64} {login verifier scope : Slice U8} {now : I64}
    {r : core.result.Result stateless_login.LoginState MailboxError} {mb' : Mailbox}
    (h : start mb policy provider peer subject ce login verifier scope now = Result.ok (r, mb')) :
    (mb'.next = mb.next ∧ (mb'.slots.val = mb.slots.val ∨ mb'.slots.val = mb.slots.val.map (pruneOne now)) ∧
      ∀ st, r ≠ .Ok st) ∨
    ∃ st, r = .Ok st ∧ BeginSpec policy provider peer subject ce login verifier scope now st ∧
      mb.next.val < 18446744073709551615 ∧ mb'.next.val = mb.next.val + 1 ∧
      ((mb.slots.val.map (pruneOne now)).filter Option.isSome).length < 1024 ∧
      (∀ o ∈ mb.slots.val.map (pruneOne now), HoldsB st.login.val o = false) ∧
      mb'.slots.val = place (mb.slots.val.map (pruneOne now)) (newSlot st mb.next) := by
  unfold start at h
  obtain ⟨r0, hr0, h⟩ := bind_ok_inv h
  cases r0 with
  | Err rej =>
    simp only [Result.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨e1, e2⟩ := h
    subst e1 e2
    exact Or.inl ⟨rfl, Or.inl rfl, by intro st; simp⟩
  | Ok st =>
    simp only at h
    obtain ⟨mb1, hp, slots1, next1⟩ := prune_eq mb now
    rw [hp] at h
    simp only [bind_ok] at h
    obtain ⟨c, hc, cv⟩ := live_eq (alloc.vec.Vec.deref mb1.slots)
    rw [hc] at h
    simp only [bind_ok] at h
    unfold MAX_PENDING at h
    split at h
    · simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨e1, e2⟩ := h
      subst e1 e2
      exact Or.inl ⟨next1, Or.inr slots1, by intro st; simp⟩
    · rename_i room
      obtain ⟨i, hi, iv⟩ := find_eq (alloc.vec.Vec.deref mb1.slots) (alloc.vec.Vec.deref st.login)
      rw [hi] at h
      simp only [bind_ok] at h
      split at h
      · simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨e1, e2⟩ := h
        subst e1 e2
        exact Or.inl ⟨next1, Or.inr slots1, by intro st; simp⟩
      · rename_i fresh
        unfold LAST_SERIAL at h
        split at h
        · simp only [Result.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨e1, e2⟩ := h
          subst e1 e2
          exact Or.inl ⟨next1, Or.inr slots1, by intro st; simp⟩
        · rename_i notLast
          rw [entry_of_eq] at h
          simp only [bind_ok] at h
          have lt : mb1.next.val < 18446744073709551615 := by
            have h1 : mb1.next.val ≤ U64.max := by scalar_tac
            have h2 : mb1.next.val ≠ 18446744073709551615 := by
              intro e; apply notLast; apply UScalar.eq_of_val_eq; simpa using e
            have h3 := U64.max_eq
            omega
          obtain ⟨n1, hn1, n1v⟩ := returned_of_spec (U64.add_spec (x := mb1.next) (y := 1#u64) (by have := U64.max_eq; simp; omega))
          rw [hn1] at h
          simp only [bind_ok] at h
          obtain ⟨vac, hvac, vacv⟩ := vacancy_eq (alloc.vec.Vec.deref mb1.slots)
          rw [hvac] at h
          simp only [bind_ok] at h
          have begun := begin_trace hr0
          have holdsNone : ∀ o ∈ mb.slots.val.map (pruneOne now), HoldsB st.login.val o = false := by
            have outside : ¬ (mb1.slots.val.findIdx (HoldsB st.login.val) < mb1.slots.val.length) := by
              have f : mb1.slots.val.length ≤ i.val := by scalar_tac
              simp [alloc.vec.Vec.deref] at iv
              omega
            rw [List.findIdx_lt_length] at outside
            intro o mem
            rw [← slots1] at mem
            by_contra yes
            exact outside ⟨o, mem, by simpa using yes⟩
          have count : ((mb.slots.val.map (pruneOne now)).filter Option.isSome).length < 1024 := by
            rw [← slots1]
            simp [alloc.vec.Vec.deref] at cv
            have r1 : ¬ (c.val ≥ 1024) := by scalar_tac
            omega
          split at h
          · rename_i inside
            obtain ⟨⟨x, back⟩, hb, hx, hback⟩ := returned_of_spec
              (alloc.vec.Vec.index_mut_usize_spec mb1.slots vac (by scalar_tac))
            rw [alloc.vec.Vec.index_mut_slice_index, hb] at h
            simp only [bind_ok] at h
            change Result.ok (core.result.Result.Ok st,
              ({ slots := back (some (newSlot st mb1.next)), next := n1 } : Mailbox)) = Result.ok (r, mb') at h
            simp only [Result.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨e1, e2⟩ := h
            subst e1 e2
            refine Or.inr ⟨st, rfl, begun, by rw [← next1]; exact lt, by simp [n1v, next1], count,
              holdsNone, ?_⟩
            simp only [hback, alloc.vec.Vec.set_val_eq, place]
            have vin : mb1.slots.val.findIdx Option.isNone < mb1.slots.val.length := by
              have f : vac.val < mb1.slots.val.length := by scalar_tac
              simp [alloc.vec.Vec.deref] at vacv; omega
            rw [← slots1]
            simp only [vin, ↓reduceIte]
            simp [alloc.vec.Vec.deref] at vacv
            rw [vacv]
            simp [newSlot, entryOf, next1]
          · rename_i outside
            obtain ⟨v, hv, h⟩ := bind_ok_inv h
            simp only [Result.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨e1, e2⟩ := h
            subst e1 e2
            have vout : ¬ mb1.slots.val.findIdx Option.isNone < mb1.slots.val.length := by
              have f : mb1.slots.val.length ≤ vac.val := by scalar_tac
              simp [alloc.vec.Vec.deref] at vacv; omega
            refine Or.inr ⟨st, rfl, begun, by rw [← next1]; exact lt, by simp [n1v, next1], count,
              holdsNone, ?_⟩
            have pushed := push_ok_val hv
            rw [pushed]
            simp only [place]
            rw [← slots1]
            simp only [vout, ↓reduceIte]
            simp [newSlot, entryOf, next1]

theorem index_mut_eq {α : Type} (v : alloc.vec.Vec α) (i : Usize) (inside : i.val < v.val.length) :
    alloc.vec.Vec.index_mut (core.slice.index.SliceIndexUsizeSlice α) v i =
      Result.ok (v.val[i.val], alloc.vec.Vec.set v i) := by
  rw [alloc.vec.Vec.index_mut_slice_index]
  simp only [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize]
  simp [inside]

theorem index_eq {α : Type} (v : alloc.vec.Vec α) (i : Usize) (inside : i.val < v.val.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = Result.ok v.val[i.val] := by
  rw [alloc.vec.Vec.index_slice_index]
  simp only [alloc.vec.Vec.index_usize]
  simp [inside]

/-- Writing back the slot that was read leaves the slots unchanged. -/
theorem set_same {v : alloc.vec.Vec (Option Slot)} {i : Usize} (inside : i.val < v.val.length) :
    (alloc.vec.Vec.set v i v.val[i.val]).val = v.val := by
  simp [List.set_getElem_self]

theorem begin_exchange_ok {e : stateless_login.Entry} {rule : oauth_login.IssuerRule} {now : I64}
    {stage : oauth_login.Stage}
    (h : stateless_login.begin_exchange e rule now = Result.ok (.Ok stage)) : stage = .Exchanging := by
  unfold stateless_login.begin_exchange at h
  obtain ⟨pending, hp, h⟩ := bind_ok_inv h
  generalize e.stage = st at h
  cases st <;> simp [oauth_login.begin] at h
  obtain ⟨c, hc, h⟩ := bind_ok_inv h
  cases c <;> simp at h
  exact h.symm

/-- A slot with a new stage. -/
def withStage (s : Slot) (stage : oauth_login.Stage) : Slot :=
  { s with entry := { s.entry with stage := stage } }

/-- A finished slot holding an issued surrogate. -/
def completed (s : Slot) (iss : stateless.Issued) : Slot :=
  { entry := { s.entry with stage := .Complete }, serial := s.serial, token := iss.token,
    expires_at := iss.claims.expires_at, renew_until := iss.claims.renew_until }

/-- **`accept`.** Either the slots are unchanged and no permit was made, or
    the first slot holding this login was pending, it and the callback's
    state are the same login on this replica, the clock was inside its
    window and the issuer rule held. Then only that slot's stage changed:
    to `Exchanging`, with the permit for exactly that slot, or (a denied
    redirect, or an exchange that could not start) to `Denied` or `Accepted`
    with no permit. -/
theorem accept_effect {mb : Mailbox} {policy : stateless_login.LoginPolicy} {st : stateless_login.LoginState}
    {rule : oauth_login.IssuerRule} {issuer : Slice U8} {has denied : Bool} {now : I64}
    {r : core.result.Result Permit MailboxError} {mb' : Mailbox}
    (h : accept mb policy st rule issuer has denied now = Result.ok (r, mb')) :
    mb'.next = mb.next ∧
    ((mb'.slots.val = mb.slots.val ∧ ∀ p, r ≠ .Ok p) ∨
     ∃ (k : Nat) (hk : k < mb.slots.val.length) (s : Slot), mb.slots.val[k] = some s ∧
       k = mb.slots.val.findIdx (HoldsB st.login.val) ∧
       SameLogin policy s.entry st ∧ s.entry.stage = .Pending ∧
       s.entry.issued_at.val ≤ now.val ∧ now.val < s.entry.expires_at.val ∧ IssuerHolds rule issuer has ∧
       ∃ stage, mb'.slots.val = mb.slots.val.set k (some (withStage s stage)) ∧
         ((stage = .Exchanging ∧ denied = false ∧
            r = .Ok { serial := s.serial, login := s.entry.login, provider := s.entry.provider,
                      verifier := st.verifier }) ∨
          ((stage = .Denied ∨ stage = .Accepted) ∧ ∀ p, r ≠ .Ok p))) := by
  unfold accept at h
  simp only at h
  obtain ⟨i, hi, iv⟩ := find_eq (alloc.vec.Vec.deref mb.slots) (alloc.vec.Vec.deref st.login)
  simp [alloc.vec.Vec.deref] at iv
  rw [hi] at h
  simp only [bind_ok] at h
  split at h
  · simp only [Result.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨e1, e2⟩ := h
    subst e1 e2
    exact ⟨rfl, Or.inl ⟨rfl, by intro p; simp⟩⟩
  · rename_i inside0
    have inside : i.val < mb.slots.val.length := by scalar_tac
    rw [index_mut_eq _ _ inside] at h
    simp only [bind_ok, Aeneas.Std.uncurry_apply_pair] at h
    cases hs : mb.slots.val[i.val] with
    | none =>
      simp only [hs] at h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨e1, e2⟩ := h
      subst e1 e2
      refine ⟨rfl, Or.inl ⟨?_, by intro p; simp⟩⟩
      rw [← hs]; exact set_same inside
    | some s =>
      simp only [hs] at h
      obtain ⟨r1, hr1, h⟩ := bind_ok_inv h
      cases r1 with
      | Err d =>
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨e1, e2⟩ := h
        subst e1 e2
        refine ⟨rfl, Or.inl ⟨?_, by intro p; simp⟩⟩
        simp only
        rw [← hs]; exact set_same inside
      | Ok stage =>
        obtain ⟨same, pending, after, before, _, issuerOk, stageEq⟩ := accept_callback_trace hr1
        simp only at h
        split at h
        · rename_i yes
          simp only [Result.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨e1, e2⟩ := h
          subst e1 e2
          refine ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, same, pending, after, before, issuerOk, stage,
            by simp [withStage], Or.inr ⟨?_, by intro p; simp⟩⟩⟩
          simp [stageEq, yes]
        · rename_i no
          have den : denied = false := by simpa using no
          rw [stageEq, den] at h
          simp only [Bool.false_eq_true, ↓reduceIte] at h
          obtain ⟨r2, hr2, h⟩ := bind_ok_inv h
          cases r2 with
          | Err d =>
            simp only [Result.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨e1, e2⟩ := h
            subst e1 e2
            exact ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, same, pending, after, before, issuerOk, .Accepted,
              by simp [withStage], Or.inr ⟨Or.inr rfl, by intro p; simp⟩⟩⟩
          | Ok stage1 =>
            have ex := begin_exchange_ok hr2
            subst ex
            simp only [to_vec_eq, bind_ok, Result.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨e1, e2⟩ := h
            subst e1 e2
            refine ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, same, pending, after, before, issuerOk, .Exchanging,
              by simp [withStage], Or.inl ⟨rfl, den, ?_⟩⟩⟩
            simp [vec_deref_mk]

/-- **`exchange`.** The token endpoint is asked once, with the permit's
    provider and verifier, and its answer is paired with that permit. -/
theorem exchange_eq {E : Type} (inst : CodeExchange E) (e : E) (p : Permit) (code : Slice U8)
    {x : Exchanged} {e' : E} (h : exchange inst e p code = Result.ok (x, e')) :
    ∃ tok, inst.token e (alloc.vec.Vec.deref p.provider) code (alloc.vec.Vec.deref p.verifier) = Result.ok (tok, e') ∧
      x = { permit := p, token := tok } := by
  unfold exchange at h
  obtain ⟨⟨tok, e1⟩, ht, h⟩ := bind_ok_inv h
  simp only [Aeneas.Std.uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨e2, e3⟩ := h
  subst e2 e3
  exact ⟨tok, ht, rfl⟩

theorem finish_complete : oauth_login.finish .Exchanging true = Result.ok (.Ok .Complete) := rfl

/-- The slot a transition for `login` acts on: the first that holds it. -/
def slotAt (mb : Mailbox) (login : List U8) : Option Slot :=
  (mb.slots.val[mb.slots.val.findIdx (HoldsB login)]?).join

theorem slotAt_of {mb : Mailbox} {login : List U8} {k : Nat} {hk : k < mb.slots.val.length} {s : Slot}
    (at_k : mb.slots.val[k] = some s) (idx : k = mb.slots.val.findIdx (HoldsB login)) :
    slotAt mb login = some s := by
  unfold slotAt
  rw [← idx, List.getElem?_eq_getElem hk, at_k]
  rfl

theorem slotAt_none_of_empty {mb : Mailbox} {login : List U8} {k : Nat} {hk : k < mb.slots.val.length}
    (at_k : mb.slots.val[k] = none) (idx : k = mb.slots.val.findIdx (HoldsB login)) :
    slotAt mb login = none := by
  unfold slotAt
  rw [← idx, List.getElem?_eq_getElem hk, at_k]
  rfl

theorem slotAt_none_of_outside {mb : Mailbox} {login : List U8}
    (out : mb.slots.val.length ≤ mb.slots.val.findIdx (HoldsB login)) : slotAt mb login = none := by
  unfold slotAt
  rw [List.getElem?_eq_none out]
  rfl

/-- **`finish`.** Either the slots are unchanged and nothing finished, or the
    first slot holding the permit's login has the permit's serial and was
    exchanging; then only that slot changed: to `Complete` holding exactly
    the surrogate `issued` produced from the exchange's token, or — no
    token, or issuance refused — to `Uncertain` with no new surrogate. -/
theorem finish_effect {S : Type} (ops : stateless.SurrogateSealer S) {mb : Mailbox} {x : Exchanged}
    {sealer : S} {policy : stateless.IssuePolicy} {tokenId : Slice U8} {now lifetime : I64}
    {r : core.result.Result Unit MailboxError} {mb' : Mailbox}
    (h : finish ops mb x sealer policy tokenId now lifetime = Result.ok (r, mb')) :
    mb'.next = mb.next ∧
    ((mb'.slots.val = mb.slots.val ∧ (∀ u, r ≠ .Ok u) ∧
       ∀ s, slotAt mb x.permit.login.val = some s → ¬ (s.serial = x.permit.serial ∧ s.entry.stage = .Exchanging)) ∨
     ∃ (k : Nat) (hk : k < mb.slots.val.length) (s : Slot), mb.slots.val[k] = some s ∧
       k = mb.slots.val.findIdx (HoldsB x.permit.login.val) ∧ s.serial = x.permit.serial ∧
       s.entry.stage = .Exchanging ∧
       ((∃ tok iss, x.token = some tok ∧
           issued ops sealer policy s.entry tok tokenId now lifetime = Result.ok (.Ok iss) ∧ r = .Ok () ∧
           mb'.slots.val = mb.slots.val.set k (some (completed s iss))) ∨
        ((x.token = none ∨ ∃ tok rej, x.token = some tok ∧
            issued ops sealer policy s.entry tok tokenId now lifetime = Result.ok (.Err rej)) ∧
          (∀ u, r ≠ .Ok u) ∧
          mb'.slots.val = mb.slots.val.set k (some (withStage s .Uncertain))))) := by
  unfold finish at h
  simp only at h
  obtain ⟨i, hi, iv⟩ := find_eq (alloc.vec.Vec.deref mb.slots) (alloc.vec.Vec.deref x.permit.login)
  simp [alloc.vec.Vec.deref] at iv
  rw [hi] at h
  simp only [bind_ok] at h
  split at h
  · rename_i outside0
    simp only [Result.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨e1, e2⟩ := h
    subst e1 e2
    have out : mb.slots.val.length ≤ mb.slots.val.findIdx (HoldsB x.permit.login.val) := by
      rw [← iv]; scalar_tac
    exact ⟨rfl, Or.inl ⟨rfl, by intro u; simp, by intro s hs; rw [slotAt_none_of_outside out] at hs; cases hs⟩⟩
  · rename_i inside0
    have inside : i.val < mb.slots.val.length := by scalar_tac
    rw [index_mut_eq _ _ inside] at h
    simp only [bind_ok, Aeneas.Std.uncurry_apply_pair] at h
    have unchanged : ∀ {e : MailboxError},
        (∀ s, slotAt mb x.permit.login.val = some s → ¬ (s.serial = x.permit.serial ∧ s.entry.stage = .Exchanging)) →
        Result.ok (core.result.Result.Err e, { mb with slots := alloc.vec.Vec.set mb.slots i mb.slots.val[i.val] }) =
          Result.ok (r, mb') →
        mb'.next = mb.next ∧ ((mb'.slots.val = mb.slots.val ∧ (∀ u, r ≠ .Ok u) ∧
          ∀ s, slotAt mb x.permit.login.val = some s → ¬ (s.serial = x.permit.serial ∧ s.entry.stage = .Exchanging)) ∨
          False) := by
      intro e F h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨e1, e2⟩ := h
      subst e1 e2
      exact ⟨rfl, Or.inl ⟨set_same inside, by intro u; simp, F⟩⟩
    cases hs : mb.slots.val[i.val] with
    | none =>
      simp only [hs] at h
      rw [← hs] at h
      have F : ∀ s, slotAt mb x.permit.login.val = some s → ¬ (s.serial = x.permit.serial ∧ s.entry.stage = .Exchanging) := by
        intro s' hs'; rw [slotAt_none_of_empty hs iv] at hs'; cases hs'
      obtain ⟨n, d⟩ := unchanged F h
      exact ⟨n, Or.inl (by simpa using d)⟩
    | some s =>
      simp only [hs] at h
      have at_s := slotAt_of hs iv
      split at h
      · rename_i mismatch
        rw [← hs] at h
        have F : ∀ s', slotAt mb x.permit.login.val = some s' → ¬ (s'.serial = x.permit.serial ∧ s'.entry.stage = .Exchanging) := by
          intro s' hs'; rw [at_s] at hs'; cases hs'
          intro both; simp [both.1] at mismatch
        obtain ⟨n, d⟩ := unchanged F h
        exact ⟨n, Or.inl (by simpa using d)⟩
      · rename_i serial
        have serialEq : s.serial = x.permit.serial := UScalar.eq_of_val_eq (by simpa using serial)
        cases hst : s.entry.stage
        all_goals simp only [hst] at h
        all_goals try (rw [← hs] at h
                       obtain ⟨n, d⟩ := unchanged (by intro s' hs'; rw [at_s] at hs'; cases hs'; intro both; rw [hst] at both; cases both.2) h
                       exact ⟨n, Or.inl (by simpa using d)⟩)
        -- the exchanging slot
        obtain ⟨res, hres, h⟩ := bind_ok_inv h
        cases ht : x.token with
        | none =>
          rw [ht] at hres
          simp only [Result.ok.injEq] at hres
          subst hres
          simp only [oauth_login.Proofs.failed_install_is_uncertain, bind_ok, Result.ok.injEq, Prod.mk.injEq] at h
          obtain ⟨e1, e2⟩ := h
          subst e1 e2
          refine ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, serialEq, hst, Or.inr ⟨Or.inl rfl, by intro u; simp, ?_⟩⟩⟩
          simp [withStage]
        | some tok =>
          rw [ht] at hres
          simp only at hres
          cases res with
          | Ok iss =>
            simp only [finish_complete, bind_ok, Result.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨e1, e2⟩ := h
            subst e1 e2
            refine ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, serialEq, hst, Or.inl ⟨tok, iss, rfl, hres, rfl, ?_⟩⟩⟩
            simp [completed]
          | Err rej =>
            simp only [oauth_login.Proofs.failed_install_is_uncertain, bind_ok, Result.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨e1, e2⟩ := h
            subst e1 e2
            refine ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, serialEq, hst,
              Or.inr ⟨Or.inr ⟨tok, rej, rfl, hres⟩, by intro u; simp, ?_⟩⟩⟩
            simp [withStage]

/-- **`poll`.** Either nothing changed and no surrogate was handed over, or
    the first slot holding this login was emptied; a surrogate handed over is
    exactly that slot's, and only when `deliver` said `Deliver` for this
    peer. -/
theorem poll_effect {mb : Mailbox} {peer login : Slice U8} {now : I64} {r : Polled} {mb' : Mailbox}
    (h : poll mb peer login now = Result.ok (r, mb')) :
    mb'.next = mb.next ∧
    ((mb'.slots.val = mb.slots.val ∧ ∀ t e n, r ≠ .Ready t e n) ∨
     ∃ (k : Nat) (hk : k < mb.slots.val.length) (s : Slot), mb.slots.val[k] = some s ∧
       k = mb.slots.val.findIdx (HoldsB login.val) ∧ mb'.slots.val = mb.slots.val.set k none ∧
       ∀ t e n, r = .Ready t e n →
         stateless_login.deliver s.entry peer now = Result.ok .Deliver ∧
           t = s.token ∧ e = s.expires_at ∧ n = s.renew_until) := by
  unfold poll at h
  simp only at h
  obtain ⟨i, hi, iv⟩ := find_eq (alloc.vec.Vec.deref mb.slots) login
  simp [alloc.vec.Vec.deref] at iv
  rw [hi] at h
  simp only [bind_ok] at h
  split at h
  · simp only [Result.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨e1, e2⟩ := h
    subst e1 e2
    exact ⟨rfl, Or.inl ⟨rfl, by intro t e n; simp⟩⟩
  · rename_i inside0
    have inside : i.val < mb.slots.val.length := by scalar_tac
    rw [index_eq _ _ inside] at h
    simp only [bind_ok] at h
    cases hs : mb.slots.val[i.val] with
    | none =>
      simp only [hs, Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨e1, e2⟩ := h
      subst e1 e2
      exact ⟨rfl, Or.inl ⟨rfl, by intro t e n; simp⟩⟩
    | some s =>
      simp only [hs] at h
      obtain ⟨d, hd, h⟩ := bind_ok_inv h
      cases d with
      | Deliver =>
        simp only at h
        rw [index_mut_eq _ _ inside] at h
        simp only [bind_ok, Aeneas.Std.uncurry_apply_pair, core.mem.replace, hs,
          Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨e1, e2⟩ := h
        subst e1 e2
        refine ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, by simp, ?_⟩⟩
        intro t e n same
        simp only [Polled.Ready.injEq] at same
        exact ⟨hd, same.1.symm, same.2.1.symm, same.2.2.symm⟩
      | Expired =>
        simp only at h
        rw [index_mut_eq _ _ inside] at h
        simp only [bind_ok, Aeneas.Std.uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨e1, e2⟩ := h
        subst e1 e2
        exact ⟨rfl, Or.inr ⟨i.val, inside, s, hs, iv, by simp, by intro t e n; simp⟩⟩
      | Pending | WrongCertificate | Denied | Failed =>
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨e1, e2⟩ := h
        subst e1 e2
        exact ⟨rfl, Or.inl ⟨rfl, by intro t e n; simp⟩⟩

/-! ## The occupied slots -/

/-- The occupied slots, in order. -/
def occ (l : List (Option Slot)) : List Slot := l.filterMap id

theorem occ_append (a b : List (Option Slot)) : occ (a ++ b) = occ a ++ occ b := List.filterMap_append

theorem occ_split {l : List (Option Slot)} {k : Nat} (hk : k < l.length) :
    occ l = occ (l.take k) ++ l[k].toList ++ occ (l.drop (k + 1)) := by
  conv => lhs; rw [← List.take_append_drop k l, ← List.getElem_cons_drop hk]
  simp only [occ, List.filterMap_append, List.filterMap_cons]
  cases l[k] <;> simp

theorem occ_set {l : List (Option Slot)} {k : Nat} (hk : k < l.length) (x : Option Slot) :
    occ (l.set k x) = occ (l.take k) ++ x.toList ++ occ (l.drop (k + 1)) := by
  rw [List.set_eq_take_append_cons_drop]
  simp only [hk, ↓reduceIte]
  simp only [occ, List.filterMap_append, List.filterMap_cons]
  cases x <;> simp

theorem occ_set_same_keys {β : Type} (f : Slot → β) {l : List (Option Slot)} {k : Nat} (hk : k < l.length)
    {s s' : Slot} (at_k : l[k] = some s) (same : f s' = f s) :
    (occ (l.set k (some s'))).map f = (occ l).map f := by
  rw [occ_set hk, occ_split hk, at_k]
  simp [same]

theorem occ_remove_sublist {l : List (Option Slot)} {k : Nat} (hk : k < l.length) :
    (occ (l.set k none)).Sublist (occ l) := by
  rw [occ_set hk, occ_split hk]
  simp only [Option.toList_none, List.append_nil]
  exact List.Sublist.append (List.sublist_append_left _ _) (List.Sublist.refl _)

theorem occ_prune_sublist (now : I64) (l : List (Option Slot)) : (occ (l.map (pruneOne now))).Sublist (occ l) := by
  induction l with
  | nil => simp [occ]
  | cons o rest ih =>
    by_cases k : KeptB now o = true
    · have e : pruneOne now o = o := by simp [pruneOne, k]
      simp only [List.map_cons, e]
      cases o with
      | none => simpa [occ] using ih
      | some x => simpa [occ] using (List.cons_sublist_cons (a := x)).mpr ih
    · have e : pruneOne now o = none := by simp [pruneOne, k]
      simp only [List.map_cons, e]
      cases o with
      | none => simpa [occ] using ih
      | some x => simpa [occ] using List.Sublist.cons x ih

theorem mem_occ {l : List (Option Slot)} {s : Slot} : s ∈ occ l ↔ some s ∈ l := by
  simp [occ, List.mem_filterMap]

theorem at_mem_occ {l : List (Option Slot)} {k : Nat} {hk : k < l.length} {s : Slot} (at_k : l[k] = some s) :
    s ∈ occ l := mem_occ.mpr (List.mem_of_getElem at_k)

/-- Every other occupied slot after `l.set k x` was occupied before, under a
    different key than the slot at `k`. -/
theorem occ_set_mem {β : Type} (f : Slot → β) {l : List (Option Slot)} {k : Nat} (hk : k < l.length)
    {s : Slot} (at_k : l[k] = some s) (nodup : ((occ l).map f).Nodup) (x : Option Slot) :
    ∀ y, y ∈ occ (l.set k x) → x = some y ∨ (y ∈ occ l ∧ f y ≠ f s) := by
  intro y mem
  rw [occ_set hk] at mem
  rw [occ_split hk, at_k] at nodup
  simp only [Option.toList_some, List.map_append, List.map_cons, List.map_nil] at nodup
  have nd := List.nodup_middle.mp (by simpa using nodup)
  simp only [List.nodup_cons, List.mem_append, List.mem_map, not_or, not_exists, not_and] at nd
  simp only [List.mem_append] at mem
  rcases mem with (inTake | inX) | inDrop
  · right
    refine ⟨?_, fun e => nd.1.1 y inTake e⟩
    rw [occ_split hk]; simp [inTake]
  · left
    cases x <;> simp_all
  · right
    refine ⟨?_, fun e => nd.1.2 y inDrop e⟩
    rw [occ_split hk]; simp [inDrop]

/-! ## Every history of broker transitions

A history is a list of `Event`s. `Step` runs one extracted transition on the
mailbox, with any arguments, any clock, any token-endpoint answer and any
sealer, and appends what it did. The only constraints on the arguments are
the ones the Rust type system enforces on the native broker: a `Permit` is
made only by `accept` and moved into `exchange` (it has private fields and no
`Clone`), and an `Exchanged` is made only by `exchange` and moved into
`finish`. Transitions run in any order: the native broker takes the mailbox
lock for each transition, so concurrent requests are some interleaving of
these steps, with the token request (`exchange`) between two of them. -/

/-- What one transition did, with the values it returned. -/
inductive Event where
  /-- `start` began this login; its slot has this serial. -/
  | started (state : stateless_login.LoginState) (serial : U64)
  /-- `accept` accepted the callback (state, issuer rule, `iss`, clock) and made `permit`. -/
  | accepted (state : stateless_login.LoginState) (rule : oauth_login.IssuerRule) (issuer : Slice U8)
      (has : Bool) (now : I64) (permit : Permit)
  /-- `exchange` spent a permit; `x` holds the endpoint's answer. -/
  | exchanged (x : Exchanged)
  /-- `finish` ended the exchange of slot `serial`: with the surrogate issued, or with none. -/
  | finished (serial : U64) (issued : Option stateless.Issued)
  /-- `poll` handed the surrogate of slot `serial` to `peer`. -/
  | delivered (serial : U64) (peer : List U8) (token : alloc.vec.Vec U8)

def Event.serial : Event → U64
  | .started _ σ => σ
  | .accepted _ _ _ _ _ p => p.serial
  | .exchanged x => x.permit.serial
  | .finished σ _ => σ
  | .delivered σ _ _ => σ

def isStart (σ : U64) : Event → Bool
  | .started _ τ => decide (τ = σ)
  | _ => false
def isAcc (σ : U64) : Event → Bool
  | .accepted _ _ _ _ _ p => decide (p.serial = σ)
  | _ => false
def isExch (σ : U64) : Event → Bool
  | .exchanged x => decide (x.permit.serial = σ)
  | _ => false
def isFin (σ : U64) : Event → Bool
  | .finished τ _ => decide (τ = σ)
  | _ => false
def isDel (σ : U64) : Event → Bool
  | .delivered τ _ _ => decide (τ = σ)
  | _ => false

/-- The number of events of a kind. -/
def cnt (p : Event → Bool) (H : List Event) : Nat := H.countP p

def startEvents (mb : Mailbox) : core.result.Result stateless_login.LoginState MailboxError → List Event
  | .Ok st => [.started st mb.next]
  | .Err _ => []

def acceptEvents (st : stateless_login.LoginState) (rule : oauth_login.IssuerRule) (issuer : Slice U8)
    (has : Bool) (now : I64) : core.result.Result Permit MailboxError → List Event
  | .Ok p => [.accepted st rule issuer has now p]
  | .Err _ => []

open Classical in
/-- What `issued` returned, when it issued. -/
noncomputable def issuedOf {S : Type} (ops : stateless.SurrogateSealer S) (sealer : S)
    (policy : stateless.IssuePolicy) (e : stateless_login.Entry) (tok : Token) (tokenId : Slice U8)
    (now lifetime : I64) : Option stateless.Issued :=
  if h : ∃ iss, issued ops sealer policy e tok tokenId now lifetime = Result.ok (.Ok iss)
  then some (Classical.choose h) else none

open Classical in
noncomputable def finishEvents {S : Type} (ops : stateless.SurrogateSealer S) (mb : Mailbox) (x : Exchanged)
    (sealer : S) (policy : stateless.IssuePolicy) (tokenId : Slice U8) (now lifetime : I64) : List Event :=
  match slotAt mb x.permit.login.val with
  | some s =>
    if s.serial = x.permit.serial ∧ s.entry.stage = .Exchanging then
      [.finished s.serial (match x.token with
        | some tok => issuedOf ops sealer policy s.entry tok tokenId now lifetime
        | none => none)]
    else []
  | none => []

def pollEvents (mb : Mailbox) (peer login : Slice U8) : Polled → List Event
  | .Ready t _ _ =>
    match slotAt mb login.val with
    | some s => [.delivered s.serial peer.val t]
    | none => []
  | _ => []

/-- One broker transition. `policy` is the replica's login configuration. -/
inductive Step {S : Type} (ops : stateless.SurrogateSealer S) (policy : stateless_login.LoginPolicy) :
    Mailbox × List Event → Mailbox × List Event → Prop where
  | start {mb : Mailbox} {H : List Event} {provider peer subject : Slice U8} {ce : I64}
      {login verifier scope : Slice U8} {now : I64}
      {r : core.result.Result stateless_login.LoginState MailboxError} {mb' : Mailbox}
      (run : stateless_mailbox.start mb policy provider peer subject ce login verifier scope now =
        Result.ok (r, mb')) :
      Step ops policy (mb, H) (mb', H ++ startEvents mb r)
  | pending {mb : Mailbox} {H : List Event} {st : stateless_login.LoginState} {now : I64}
      {r : core.result.Result Unit MailboxError}
      (run : stateless_mailbox.pending mb policy st now = Result.ok r) :
      Step ops policy (mb, H) (mb, H)
  | accept {mb : Mailbox} {H : List Event} {st : stateless_login.LoginState} {rule : oauth_login.IssuerRule}
      {issuer : Slice U8} {has denied : Bool} {now : I64} {r : core.result.Result Permit MailboxError}
      {mb' : Mailbox}
      (run : stateless_mailbox.accept mb policy st rule issuer has denied now = Result.ok (r, mb')) :
      Step ops policy (mb, H) (mb', H ++ acceptEvents st rule issuer has now r)
  | exchange {E : Type} (inst : CodeExchange E) (e : E) {mb : Mailbox} {H : List Event}
      {st : stateless_login.LoginState} {rule : oauth_login.IssuerRule} {issuer : Slice U8} {has : Bool}
      {now : I64} {p : Permit} {code : Slice U8} {x : Exchanged} {e' : E}
      (held : Event.accepted st rule issuer has now p ∈ H)
      (unspent : ∀ y, Event.exchanged y ∈ H → y.permit.serial ≠ p.serial)
      (run : stateless_mailbox.exchange inst e p code = Result.ok (x, e')) :
      Step ops policy (mb, H) (mb, H ++ [.exchanged x])
  | finish {mb : Mailbox} {H : List Event} {x : Exchanged} {sealer : S} {issuePolicy : stateless.IssuePolicy}
      {tokenId : Slice U8} {now lifetime : I64} {r : core.result.Result Unit MailboxError} {mb' : Mailbox}
      (held : Event.exchanged x ∈ H)
      (run : stateless_mailbox.finish ops mb x sealer issuePolicy tokenId now lifetime = Result.ok (r, mb')) :
      Step ops policy (mb, H) (mb', H ++ finishEvents ops mb x sealer issuePolicy tokenId now lifetime)
  | poll {mb : Mailbox} {H : List Event} {peer login : Slice U8} {now : I64} {r : Polled} {mb' : Mailbox}
      (run : stateless_mailbox.poll mb peer login now = Result.ok (r, mb')) :
      Step ops policy (mb, H) (mb', H ++ pollEvents mb peer login r)

/-- Every state reachable from the empty mailbox. -/
inductive Reachable {S : Type} (ops : stateless.SurrogateSealer S) (policy : stateless_login.LoginPolicy) :
    Mailbox × List Event → Prop where
  | init {mb : Mailbox} (made : stateless_mailbox.empty = Result.ok mb) : Reachable ops policy (mb, [])
  | step {c c' : Mailbox × List Event} (before : Reachable ops policy c) (move : Step ops policy c c') :
      Reachable ops policy c'

/-! ## The invariant -/

/-- The fields `start` fixed: a slot's entry never changes them. -/
def SameEntry (st : stateless_login.LoginState) (e : stateless_login.Entry) : Prop :=
  e.login = st.login ∧ e.provider = st.provider ∧ e.certificate = st.certificate ∧ e.subject = st.subject ∧
    e.certificate_expires = st.certificate_expires ∧ e.issued_at = st.issued_at ∧ e.expires_at = st.expires_at

/-- What a slot's stage says about its history. -/
def SlotOK (H : List Event) (s : Slot) : Prop :=
  (∃ st, Event.started st s.serial ∈ H ∧ SameEntry st s.entry) ∧
  match s.entry.stage with
  | .Pending | .Accepted | .Denied =>
    cnt (isAcc s.serial) H = 0 ∧ cnt (isFin s.serial) H = 0 ∧ cnt (isDel s.serial) H = 0
  | .Exchanging => cnt (isAcc s.serial) H = 1 ∧ cnt (isFin s.serial) H = 0 ∧ cnt (isDel s.serial) H = 0
  | .Complete => (∃ iss, Event.finished s.serial (some iss) ∈ H ∧ iss.token = s.token) ∧
      cnt (isFin s.serial) H = 1 ∧ cnt (isDel s.serial) H = 0
  | .Uncertain => Event.finished s.serial none ∈ H ∧ cnt (isFin s.serial) H = 1 ∧ cnt (isDel s.serial) H = 0

/-- What each recorded event established when it happened. -/
def EventOK {S : Type} (ops : stateless.SurrogateSealer S) (policy : stateless_login.LoginPolicy)
    (H : List Event) : Event → Prop
  | .started st _ => ∃ (provider peer subject : Slice U8) (ce : I64) (login verifier scope : Slice U8) (now : I64),
      BeginSpec policy provider peer subject ce login verifier scope now st
  | .accepted st rule issuer has now p =>
    ∃ st0, Event.started st0 p.serial ∈ H ∧ SameLogin policy (entryOf st0) st ∧
      st0.issued_at.val ≤ now.val ∧ now.val < st0.expires_at.val ∧ IssuerHolds rule issuer has ∧
      p.login = st0.login ∧ p.provider = st0.provider ∧ p.verifier = st.verifier
  | .exchanged x => ∃ st rule issuer has now, Event.accepted st rule issuer has now x.permit ∈ H
  | .finished σ none => ∃ x, Event.exchanged x ∈ H ∧ x.permit.serial = σ
  | .finished σ (some iss) =>
    ∃ st0, Event.started st0 σ ∈ H ∧ iss.claims.certificate = st0.certificate ∧
      iss.claims.provider = st0.provider ∧ iss.claims.subject = st0.subject ∧
      ∃ x tok, Event.exchanged x ∈ H ∧ x.permit.serial = σ ∧ x.token = some tok ∧
        http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref tok.credential) ∧
        ∃ sealer, ops.«seal» sealer iss.claims (alloc.vec.Vec.deref tok.credential) = Result.ok (.Ok iss.token)
  | .delivered σ peer t =>
    ∃ st0 iss, Event.started st0 σ ∈ H ∧ st0.certificate.val = peer ∧
      Event.finished σ (some iss) ∈ H ∧ t = iss.token

structure Inv {S : Type} (ops : stateless.SurrogateSealer S) (policy : stateless_login.LoginPolicy)
    (c : Mailbox × List Event) : Prop where
  serials : ((occ c.1.slots.val).map Slot.serial).Nodup
  logins : ((occ c.1.slots.val).map (fun s => s.entry.login.val)).Nodup
  slotsBelow : ∀ s ∈ occ c.1.slots.val, s.serial.val < c.1.next.val
  eventsBelow : ∀ e ∈ c.2, e.serial.val < c.1.next.val
  slots : ∀ s ∈ occ c.1.slots.val, SlotOK c.2 s
  once : ∀ σ, cnt (isStart σ) c.2 ≤ 1 ∧ cnt (isAcc σ) c.2 ≤ 1 ∧ cnt (isExch σ) c.2 ≤ 1 ∧
    cnt (isFin σ) c.2 ≤ 1 ∧ cnt (isDel σ) c.2 ≤ 1
  events : ∀ e ∈ c.2, EventOK ops policy c.2 e

/-! ## Bookkeeping -/

theorem cnt_append (p : Event → Bool) (H E : List Event) : cnt p (H ++ E) = cnt p H + cnt p E :=
  List.countP_append

theorem cnt_single (p : Event → Bool) (e : Event) : cnt p [e] = if p e then 1 else 0 := by
  simp [cnt, List.countP_cons]

theorem cnt_zero {p : Event → Bool} {E : List Event} (quiet : ∀ e ∈ E, p e = false) : cnt p E = 0 := by
  unfold cnt; rw [List.countP_eq_zero]; intro e mem; simp [quiet e mem]

theorem isStart_serial {σ : U64} {e : Event} (h : isStart σ e = true) : e.serial = σ := by
  cases e <;> simp_all [isStart, Event.serial]
theorem isAcc_serial {σ : U64} {e : Event} (h : isAcc σ e = true) : e.serial = σ := by
  cases e <;> simp_all [isAcc, Event.serial]
theorem isExch_serial {σ : U64} {e : Event} (h : isExch σ e = true) : e.serial = σ := by
  cases e <;> simp_all [isExch, Event.serial]
theorem isFin_serial {σ : U64} {e : Event} (h : isFin σ e = true) : e.serial = σ := by
  cases e <;> simp_all [isFin, Event.serial]
theorem isDel_serial {σ : U64} {e : Event} (h : isDel σ e = true) : e.serial = σ := by
  cases e <;> simp_all [isDel, Event.serial]

/-- No event of a history mentions a serial at or above every recorded one. -/
theorem cnt_fresh {p : Event → Bool} {σ : U64} (hp : ∀ e, p e = true → e.serial = σ) {H : List Event}
    (below : ∀ e ∈ H, e.serial.val < σ.val) : cnt p H = 0 := by
  apply cnt_zero
  intro e mem
  by_contra yes
  have := below e mem
  rw [hp e (by simpa using yes)] at this
  omega

theorem cnt_other {p : Event → Bool} {σ : U64} (hp : ∀ e, p e = true → e.serial = σ) {e : Event}
    (other : e.serial ≠ σ) : cnt p [e] = 0 := by
  rw [cnt_single]
  split
  · rename_i yes; exact absurd (hp e yes) other
  · rfl

theorem mem_of_cnt_pos {p : Event → Bool} {H : List Event} (pos : 0 < cnt p H) : ∃ e ∈ H, p e = true := by
  unfold cnt at pos
  exact List.countP_pos_iff.mp pos

theorem unique_of_cnt {p : Event → Bool} {H : List Event} (once : cnt p H ≤ 1) {a b : Event}
    (ha : a ∈ H) (hb : b ∈ H) (pa : p a = true) (pb : p b = true) : a = b := by
  unfold cnt at once
  rw [List.countP_eq_length_filter] at once
  have ma : a ∈ H.filter p := List.mem_filter.mpr ⟨ha, pa⟩
  have mb : b ∈ H.filter p := List.mem_filter.mpr ⟨hb, pb⟩
  generalize H.filter p = l at once ma mb
  match l, once with
  | [], _ => cases ma
  | [x], _ => simp at ma mb; rw [ma, mb]
  | _ :: _ :: _, h => simp at h

theorem started_unique {H : List Event} {σ : U64} (once : cnt (isStart σ) H ≤ 1)
    {a b : stateless_login.LoginState} (ha : Event.started a σ ∈ H) (hb : Event.started b σ ∈ H) : a = b := by
  have := unique_of_cnt once ha hb (by simp [isStart]) (by simp [isStart])
  cases this; rfl

theorem EventOK_mono {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {H : List Event} (E : List Event) {e : Event} (h : EventOK ops policy H e) : EventOK ops policy (H ++ E) e := by
  have up : ∀ {x : Event}, x ∈ H → x ∈ H ++ E := fun m => List.mem_append_left E m
  cases e with
  | started => exact h
  | accepted st rule issuer has now p =>
    obtain ⟨st0, m, rest⟩ := h
    exact ⟨st0, up m, rest⟩
  | exchanged x =>
    obtain ⟨a, b, c, d, f, m⟩ := h
    exact ⟨a, b, c, d, f, up m⟩
  | finished σ iss =>
    cases iss with
    | none =>
      obtain ⟨x, m, rest⟩ := h
      exact ⟨x, up m, rest⟩
    | some iss =>
      obtain ⟨st0, m, c1, c2, c3, x, tok, mx, rest⟩ := h
      exact ⟨st0, up m, c1, c2, c3, x, tok, up mx, rest⟩
  | delivered σ peer t =>
    obtain ⟨st0, iss, m1, c, m2, ht⟩ := h
    exact ⟨st0, iss, up m1, c, up m2, ht⟩

/-- Events that are not about a slot's serial leave what its stage says intact. -/
theorem SlotOK_append {H : List Event} (E : List Event) {s : Slot} (h : SlotOK H s)
    (quiet : ∀ e ∈ E, isAcc s.serial e = false ∧ isFin s.serial e = false ∧ isDel s.serial e = false) :
    SlotOK (H ++ E) s := by
  have za : cnt (isAcc s.serial) E = 0 := cnt_zero (fun e m => (quiet e m).1)
  have zf : cnt (isFin s.serial) E = 0 := cnt_zero (fun e m => (quiet e m).2.1)
  have zd : cnt (isDel s.serial) E = 0 := cnt_zero (fun e m => (quiet e m).2.2)
  obtain ⟨⟨st, m, same⟩, rest⟩ := h
  refine ⟨⟨st, List.mem_append_left E m, same⟩, ?_⟩
  simp only [cnt_append, za, zf, zd, Nat.add_zero]
  cases hs : s.entry.stage <;> simp only [hs] at rest ⊢
  all_goals first
    | exact rest
    | (obtain ⟨⟨iss, mi, ti⟩, rest⟩ := rest; exact ⟨⟨iss, List.mem_append_left E mi, ti⟩, rest⟩)
    | (obtain ⟨mi, rest⟩ := rest; exact ⟨List.mem_append_left E mi, rest⟩)

/-- Quiet for every slot whose serial differs from the event's. -/
theorem quiet_other {e : Event} {σ : U64} (other : e.serial ≠ σ) :
    isAcc σ e = false ∧ isFin σ e = false ∧ isDel σ e = false := by
  refine ⟨?_, ?_, ?_⟩
  · cases h : isAcc σ e
    · rfl
    · exact absurd (isAcc_serial h) other
  · cases h : isFin σ e
    · rfl
    · exact absurd (isFin_serial h) other
  · cases h : isDel σ e
    · rfl
    · exact absurd (isDel_serial h) other

theorem quiet_started (st : stateless_login.LoginState) (τ σ : U64) :
    isAcc σ (.started st τ) = false ∧ isFin σ (.started st τ) = false ∧ isDel σ (.started st τ) = false := by
  simp [isAcc, isFin, isDel]

theorem quiet_exchanged (x : Exchanged) (σ : U64) :
    isAcc σ (.exchanged x) = false ∧ isFin σ (.exchanged x) = false ∧ isDel σ (.exchanged x) = false := by
  simp [isAcc, isFin, isDel]

/-- An invariant over the same history and slots carries over when the slots
    only lose members. -/
theorem inv_of_sublist {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {mb mb' : Mailbox} {H : List Event} (inv : Inv ops policy (mb, H))
    (sub : (occ mb'.slots.val).Sublist (occ mb.slots.val)) (next : mb'.next = mb.next) :
    Inv ops policy (mb', H) where
  serials := List.Nodup.sublist (sub.map _) inv.serials
  logins := List.Nodup.sublist (sub.map _) inv.logins
  slotsBelow := fun s m => by rw [next]; exact inv.slotsBelow s (sub.subset m)
  eventsBelow := fun e m => by rw [next]; exact inv.eventsBelow e m
  slots := fun s m => inv.slots s (sub.subset m)
  once := inv.once
  events := inv.events

theorem initial_inv {S : Type} (ops : stateless.SurrogateSealer S) (policy : stateless_login.LoginPolicy)
    {mb : Mailbox} (made : stateless_mailbox.empty = Result.ok mb) : Inv ops policy (mb, []) := by
  simp only [stateless_mailbox.empty, Result.ok.injEq] at made
  subst made
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> simp [occ, alloc.vec.Vec.new, cnt]

theorem occ_place_perm (l : List (Option Slot)) (x : Slot) : (occ (place l x)).Perm (x :: occ l) := by
  unfold place
  split
  · rename_i inside
    have empty : l[l.findIdx Option.isNone]'inside = none := by
      have := ((List.findIdx_eq inside).mp rfl).1
      simpa using this
    rw [occ_set inside, occ_split inside (l := l), empty]
    simp
  · rw [occ_append]
    simp [occ]

theorem SameEntry_entryOf (st : stateless_login.LoginState) : SameEntry st (entryOf st) := by
  simp [SameEntry, entryOf]

theorem SameEntry_withStage {st : stateless_login.LoginState} {s : Slot} (h : SameEntry st s.entry)
    (stage : oauth_login.Stage) : SameEntry st (withStage s stage).entry := by
  simpa [SameEntry, withStage] using h

theorem SameEntry_completed {st : stateless_login.LoginState} {s : Slot} (h : SameEntry st s.entry)
    (iss : stateless.Issued) : SameEntry st (completed s iss).entry := by
  simpa [SameEntry, completed] using h

/-- **`start` preserves the invariant.** -/
theorem start_preserves {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {mb : Mailbox} {H : List Event} {provider peer subject : Slice U8} {ce : I64}
    {login verifier scope : Slice U8} {now : I64}
    {r : core.result.Result stateless_login.LoginState MailboxError} {mb' : Mailbox}
    (inv : Inv ops policy (mb, H))
    (run : stateless_mailbox.start mb policy provider peer subject ce login verifier scope now = Result.ok (r, mb')) :
    Inv ops policy (mb', H ++ startEvents mb r) := by
  rcases start_effect run with ⟨next, slots, notOk⟩ | ⟨st, rOk, begun, room, next, count, fresh, slots⟩
  · have none : startEvents mb r = [] := by
      cases r with
      | Ok st => exact absurd rfl (notOk st)
      | Err _ => rfl
    rw [none, List.append_nil]
    apply inv_of_sublist inv _ next
    rcases slots with same | pruned
    · rw [same]
    · rw [pruned]; exact occ_prune_sublist now _
  · subst rOk
    simp only [startEvents]
    let L := mb.slots.val.map (pruneOne now)
    have sub : (occ L).Sublist (occ mb.slots.val) := occ_prune_sublist now _
    have perm : (occ mb'.slots.val).Perm (newSlot st mb.next :: occ L) := by
      rw [slots]; exact occ_place_perm _ _
    have lowL : ∀ s ∈ occ L, s.serial.val < mb.next.val := fun s m => inv.slotsBelow s (sub.subset m)
    have freshLogin : ∀ s ∈ occ L, s.entry.login.val ≠ st.login.val := by
      intro s m same
      have := fresh (some s) (mem_occ.mp m)
      simp [HoldsB, same] at this
    have quietNew : ∀ y : Slot, y.serial ≠ mb.next →
        ∀ e ∈ [Event.started st mb.next], isAcc y.serial e = false ∧ isFin y.serial e = false ∧
          isDel y.serial e = false := by
      intro y _ e m
      simp only [List.mem_singleton] at m
      subst m
      exact quiet_started st _ _
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · show ((occ mb'.slots.val).map Slot.serial).Nodup
      rw [(perm.map _).nodup_iff]
      simp only [List.map_cons, List.nodup_cons, List.mem_map, not_exists, not_and]
      refine ⟨?_, List.Nodup.sublist (sub.map _) inv.serials⟩
      intro y m same
      have := lowL y m
      rw [same] at this
      simp [newSlot] at this
    · show ((occ mb'.slots.val).map (fun s => s.entry.login.val)).Nodup
      rw [(perm.map _).nodup_iff]
      simp only [List.map_cons, List.nodup_cons, List.mem_map, not_exists, not_and]
      refine ⟨?_, List.Nodup.sublist (sub.map _) inv.logins⟩
      intro y m same
      exact freshLogin y m (by simpa [newSlot, entryOf] using same)
    · intro y m
      show y.serial.val < mb'.next.val
      rw [next]
      rcases List.mem_cons.mp (perm.mem_iff.mp m) with e | m'
      · subst e; simp [newSlot]
      · have := lowL y m'; omega
    · intro e m
      show e.serial.val < mb'.next.val
      rw [next]
      rcases List.mem_append.mp m with old | new
      · have := inv.eventsBelow e old; simp only at this; omega
      · simp only [List.mem_singleton] at new
        subst new
        simp [Event.serial]
    · intro y m
      rcases List.mem_cons.mp (perm.mem_iff.mp m) with e | m'
      · subst e
        refine ⟨⟨st, by simp [newSlot], SameEntry_entryOf st⟩, ?_⟩
        have below := inv.eventsBelow
        simp only [newSlot, entryOf, cnt_append]
        refine ⟨?_, ?_, ?_⟩
        · rw [cnt_fresh (fun e h => isAcc_serial h) below, cnt_zero (by simp [isAcc])]
        · rw [cnt_fresh (fun e h => isFin_serial h) below, cnt_zero (by simp [isFin])]
        · rw [cnt_fresh (fun e h => isDel_serial h) below, cnt_zero (by simp [isDel])]
      · have ne : y.serial ≠ mb.next := by
          intro e; have := lowL y m'; rw [e] at this; omega
        exact SlotOK_append _ (inv.slots y (sub.subset m')) (quietNew y ne)
    · intro σ
      obtain ⟨a, b, c, d, f⟩ := inv.once σ
      simp only [cnt_append, cnt_single]
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · by_cases same : mb.next = σ
        · subst same
          rw [cnt_fresh (fun e h => isStart_serial h) inv.eventsBelow]
          simp [isStart]
        · simp [isStart, same]; omega
      all_goals simp [isAcc, isExch, isFin, isDel]; omega
    · intro e m
      rcases List.mem_append.mp m with old | new
      · exact EventOK_mono _ (inv.events e old)
      · simp only [List.mem_singleton] at new
        subst new
        exact ⟨provider, peer, subject, ce, login, verifier, scope, now, begun⟩

/-- The common shape of a transition that rewrites one slot `s` (at the
    login's index) to `s'` with the same serial and login, appending `E`
    about `s`'s serial only. -/
theorem inv_of_rewrite {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {mb mb' : Mailbox} {H E : List Event} (inv : Inv ops policy (mb, H))
    {k : Nat} {hk : k < mb.slots.val.length} {s s' : Slot} (at_k : mb.slots.val[k] = some s)
    (slots : mb'.slots.val = mb.slots.val.set k (some s')) (next : mb'.next = mb.next)
    (serial : s'.serial = s.serial) (login : s'.entry.login = s.entry.login)
    (about : ∀ e ∈ E, e.serial = s.serial)
    (newOK : SlotOK (H ++ E) s')
    (once : ∀ σ, cnt (isStart σ) (H ++ E) ≤ 1 ∧ cnt (isAcc σ) (H ++ E) ≤ 1 ∧ cnt (isExch σ) (H ++ E) ≤ 1 ∧
      cnt (isFin σ) (H ++ E) ≤ 1 ∧ cnt (isDel σ) (H ++ E) ≤ 1)
    (events : ∀ e ∈ E, EventOK ops policy (H ++ E) e) :
    Inv ops policy (mb', H ++ E) := by
  have sIn : s ∈ occ mb.slots.val := at_mem_occ at_k
  refine ⟨?_, ?_, ?_, ?_, ?_, once, ?_⟩
  · show ((occ mb'.slots.val).map Slot.serial).Nodup
    rw [slots, occ_set_same_keys Slot.serial hk at_k serial]; exact inv.serials
  · show ((occ mb'.slots.val).map (fun s => s.entry.login.val)).Nodup
    rw [slots, occ_set_same_keys (fun s => s.entry.login.val) hk at_k (by simp [login])]; exact inv.logins
  · intro y m
    show y.serial.val < mb'.next.val
    rw [next]
    rw [slots] at m
    rcases occ_set_mem Slot.serial hk at_k inv.serials _ y m with e | ⟨m', _⟩
    · simp only [Option.some.injEq] at e
      subst e
      rw [serial]; exact inv.slotsBelow s sIn
    · exact inv.slotsBelow y m'
  · intro e m
    show e.serial.val < mb'.next.val
    rw [next]
    rcases List.mem_append.mp m with old | new
    · exact inv.eventsBelow e old
    · rw [about e new]; exact inv.slotsBelow s sIn
  · intro y m
    rw [slots] at m
    rcases occ_set_mem Slot.serial hk at_k inv.serials _ y m with e | ⟨m', ne⟩
    · simp only [Option.some.injEq] at e
      subst e
      exact newOK
    · apply SlotOK_append _ (inv.slots y m')
      intro e me
      exact quiet_other (by rw [about e me]; exact fun h => ne h.symm)
  · intro e m
    rcases List.mem_append.mp m with old | new
    · exact EventOK_mono _ (inv.events e old)
    · exact events e new

/-- **`accept` preserves the invariant.** -/
theorem accept_preserves {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {mb : Mailbox} {H : List Event} {st : stateless_login.LoginState} {rule : oauth_login.IssuerRule}
    {issuer : Slice U8} {has denied : Bool} {now : I64} {r : core.result.Result Permit MailboxError}
    {mb' : Mailbox} (inv : Inv ops policy (mb, H))
    (run : stateless_mailbox.accept mb policy st rule issuer has denied now = Result.ok (r, mb')) :
    Inv ops policy (mb', H ++ acceptEvents st rule issuer has now r) := by
  obtain ⟨next, unchanged | ⟨k, hk, s, at_k, idx, same, pending, after, before, issuerOk, stage, slots, result⟩⟩ :=
    accept_effect run
  · obtain ⟨slots, notOk⟩ := unchanged
    have none : acceptEvents st rule issuer has now r = [] := by
      cases r with
      | Ok p => exact absurd rfl (notOk p)
      | Err _ => rfl
    rw [none, List.append_nil]
    exact inv_of_sublist inv (by rw [slots]) next
  · have sIn : s ∈ occ mb.slots.val := at_mem_occ at_k
    obtain ⟨⟨st0, started0, se⟩, counts⟩ := inv.slots s sIn
    rw [pending] at counts
    obtain ⟨za, zf, zd⟩ := counts
    rcases result with ⟨isEx, _, rOk⟩ | ⟨stageIs, notOk⟩
    · subst isEx rOk
      simp only [acceptEvents]
      refine inv_of_rewrite inv at_k slots next rfl rfl (by simp [Event.serial]) ?_ ?_ ?_
      · refine ⟨⟨st0, List.mem_append_left _ started0, SameEntry_withStage se _⟩, ?_⟩
        simp only [withStage, cnt_append, cnt_single, isAcc, isFin, isDel, decide_true, ↓reduceIte, za, zf, zd]
        simp
      · intro σ
        obtain ⟨a, b, c, d, f⟩ := inv.once σ
        simp only [cnt_append, cnt_single]
        refine ⟨by simp [isStart]; omega, ?_, by simp [isExch]; omega, by simp [isFin]; omega,
          by simp [isDel]; omega⟩
        by_cases same : s.serial = σ
        · subst same; simp [isAcc, za]
        · simp [isAcc, same]; omega
      · intro e m
        simp only [List.mem_singleton] at m
        subst m
        obtain ⟨l, pr, c, sb, ce, ia, ea⟩ := se
        refine ⟨st0, List.mem_append_left _ started0, ?_, by rw [← ia]; exact after, by rw [← ea]; exact before,
          issuerOk, l, pr, rfl⟩
        unfold SameLogin at same ⊢
        simp only [entryOf]
        rw [l, pr, c, sb, ce, ia, ea] at same
        exact same
    · have none : acceptEvents st rule issuer has now r = [] := by
        cases r with
        | Ok p => exact absurd rfl (notOk p)
        | Err _ => rfl
      rw [none, List.append_nil]
      have eqH : H = H ++ [] := by simp
      rw [eqH]
      refine inv_of_rewrite inv at_k slots next rfl rfl (by simp) ?_ (by simpa using inv.once) (by simp)
      refine ⟨⟨st0, by simpa [withStage] using started0, SameEntry_withStage se _⟩, ?_⟩
      simp only [List.append_nil]
      rcases stageIs with e | e <;> subst e <;> exact ⟨za, zf, zd⟩

/-- **`exchange` preserves the invariant.** -/
theorem exchange_preserves {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {E : Type} (inst : CodeExchange E) (e : E) {mb : Mailbox} {H : List Event}
    {st : stateless_login.LoginState} {rule : oauth_login.IssuerRule} {issuer : Slice U8} {has : Bool}
    {now : I64} {p : Permit} {code : Slice U8} {x : Exchanged} {e' : E} (inv : Inv ops policy (mb, H))
    (held : Event.accepted st rule issuer has now p ∈ H)
    (unspent : ∀ y, Event.exchanged y ∈ H → y.permit.serial ≠ p.serial)
    (run : stateless_mailbox.exchange inst e p code = Result.ok (x, e')) :
    Inv ops policy (mb, H ++ [.exchanged x]) := by
  obtain ⟨tok, _, hx⟩ := exchange_eq inst e p code run
  subst hx
  refine ⟨inv.serials, inv.logins, inv.slotsBelow, ?_, ?_, ?_, ?_⟩
  · intro ev m
    rcases List.mem_append.mp m with old | new
    · exact inv.eventsBelow ev old
    · simp only [List.mem_singleton] at new
      subst new
      simpa [Event.serial] using inv.eventsBelow _ held
  · intro y m
    exact SlotOK_append _ (inv.slots y m) (fun ev me => by
      simp only [List.mem_singleton] at me; subst me; exact quiet_exchanged _ _)
  · intro σ
    obtain ⟨a, b, c, d, f⟩ := inv.once σ
    simp only [cnt_append, cnt_single]
    refine ⟨by simp [isStart]; omega, by simp [isAcc]; omega, ?_, by simp [isFin]; omega, by simp [isDel]; omega⟩
    by_cases same : p.serial = σ
    · subst same
      have zero : cnt (isExch p.serial) H = 0 := by
        apply cnt_zero
        intro ev m
        cases ev with
        | exchanged y => simpa [isExch] using unspent y m
        | _ => rfl
      simp [isExch, zero]
    · simp [isExch, same]; omega
  · intro ev m
    rcases List.mem_append.mp m with old | new
    · exact EventOK_mono _ (inv.events ev old)
    · simp only [List.mem_singleton] at new
      subst new
      exact ⟨st, rule, issuer, has, now, List.mem_append_left _ held⟩

theorem issued_trace {S : Type} (ops : stateless.SurrogateSealer S) (sealer : S) {policy : stateless.IssuePolicy}
    {e : stateless_login.Entry} {tok : Token} {tokenId : Slice U8} {now lifetime : I64} {iss : stateless.Issued}
    (h : issued ops sealer policy e tok tokenId now lifetime = Result.ok (.Ok iss)) :
    e.stage = .Exchanging ∧ iss.claims.certificate = e.certificate ∧ iss.claims.provider = e.provider ∧
      iss.claims.subject = e.subject ∧ http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref tok.credential) ∧
      ops.«seal» sealer iss.claims (alloc.vec.Vec.deref tok.credential) = Result.ok (.Ok iss.token) := by
  unfold issued at h
  obtain ⟨r, _, h⟩ := bind_ok_inv h
  cases r with
  | Err _ => simp at h
  | Ok _ => exact complete_trace ops sealer h

theorem issuedOf_some {S : Type} {ops : stateless.SurrogateSealer S} {sealer : S} {policy : stateless.IssuePolicy}
    {e : stateless_login.Entry} {tok : Token} {tokenId : Slice U8} {now lifetime : I64} {iss : stateless.Issued}
    (h : issued ops sealer policy e tok tokenId now lifetime = Result.ok (.Ok iss)) :
    issuedOf ops sealer policy e tok tokenId now lifetime = some iss := by
  have ex : ∃ iss, issued ops sealer policy e tok tokenId now lifetime = Result.ok (.Ok iss) := ⟨iss, h⟩
  unfold issuedOf
  have spec := Classical.choose_spec ex
  have e2 := h.symm.trans spec
  simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at e2
  simp only [ex, ↓reduceDIte]
  rw [← e2]

theorem issuedOf_none {S : Type} {ops : stateless.SurrogateSealer S} {sealer : S} {policy : stateless.IssuePolicy}
    {e : stateless_login.Entry} {tok : Token} {tokenId : Slice U8} {now lifetime : I64} {rej : stateless.Rejection}
    (h : issued ops sealer policy e tok tokenId now lifetime = Result.ok (.Err rej)) :
    issuedOf ops sealer policy e tok tokenId now lifetime = none := by
  have no : ¬ ∃ iss, issued ops sealer policy e tok tokenId now lifetime = Result.ok (.Ok iss) := by
    rintro ⟨iss, hi⟩
    rw [h] at hi
    simp at hi
  unfold issuedOf
  simp only [no, ↓reduceDIte]

/-- **`finish` preserves the invariant.** -/
theorem finish_preserves {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {mb : Mailbox} {H : List Event} {x : Exchanged} {sealer : S} {issuePolicy : stateless.IssuePolicy}
    {tokenId : Slice U8} {now lifetime : I64} {r : core.result.Result Unit MailboxError} {mb' : Mailbox}
    (inv : Inv ops policy (mb, H)) (held : Event.exchanged x ∈ H)
    (run : stateless_mailbox.finish ops mb x sealer issuePolicy tokenId now lifetime = Result.ok (r, mb')) :
    Inv ops policy (mb', H ++ finishEvents ops mb x sealer issuePolicy tokenId now lifetime) := by
  obtain ⟨next, ⟨slots, _, F⟩ | ⟨k, hk, s, at_k, idx, serialEq, hst, outcome⟩⟩ := finish_effect ops run
  · have none : finishEvents ops mb x sealer issuePolicy tokenId now lifetime = [] := by
      unfold finishEvents
      cases hs : slotAt mb x.permit.login.val with
      | none => rfl
      | some s => simp only [F s hs, ↓reduceIte]
    rw [none, List.append_nil]
    exact inv_of_sublist inv (by rw [slots]) next
  · have sIn : s ∈ occ mb.slots.val := at_mem_occ at_k
    obtain ⟨⟨st0, started0, se⟩, counts⟩ := inv.slots s sIn
    rw [hst] at counts
    obtain ⟨oneAcc, zf, zd⟩ := counts
    have events : finishEvents ops mb x sealer issuePolicy tokenId now lifetime =
        [.finished s.serial (match x.token with
          | some tok => issuedOf ops sealer issuePolicy s.entry tok tokenId now lifetime
          | none => none)] := by
      unfold finishEvents
      rw [slotAt_of at_k idx]
      simp only
      have cond : s.serial = x.permit.serial ∧ s.entry.stage = .Exchanging := ⟨serialEq, hst⟩
      simp only [cond, and_self, ↓reduceIte]
    rw [events]
    have onceFin : ∀ o, ∀ σ, cnt (isStart σ) (H ++ [.finished s.serial o]) ≤ 1 ∧
        cnt (isAcc σ) (H ++ [.finished s.serial o]) ≤ 1 ∧ cnt (isExch σ) (H ++ [.finished s.serial o]) ≤ 1 ∧
        cnt (isFin σ) (H ++ [.finished s.serial o]) ≤ 1 ∧ cnt (isDel σ) (H ++ [.finished s.serial o]) ≤ 1 := by
      intro o σ
      obtain ⟨a, b, c, d, f⟩ := inv.once σ
      simp only [cnt_append, cnt_single]
      refine ⟨by simp [isStart]; omega, by simp [isAcc]; omega, by simp [isExch]; omega, ?_,
        by simp [isDel]; omega⟩
      by_cases same : s.serial = σ
      · subst same; simp [isFin, zf]
      · simp [isFin, same]; omega
    rcases outcome with ⟨tok, iss, ht, hiss, _, slots⟩ | ⟨failed, _, slots⟩
    · rw [ht]
      simp only [issuedOf_some hiss]
      refine inv_of_rewrite inv at_k slots next rfl rfl (by simp [Event.serial]) ?_ (onceFin _) ?_
      · refine ⟨⟨st0, List.mem_append_left _ started0, SameEntry_completed se _⟩, ?_⟩
        simp only [completed, cnt_append, cnt_single, isFin, isDel, decide_true, ↓reduceIte, zf, zd]
        exact ⟨⟨iss, by simp, rfl⟩, by simp, by simp⟩
      · intro ev m
        simp only [List.mem_singleton] at m
        subst m
        obtain ⟨_, cert, prov, subj, valid, sealed⟩ := issued_trace ops sealer hiss
        obtain ⟨_, pr, c, sb, _, _, _⟩ := se
        exact ⟨st0, List.mem_append_left _ started0, by rw [cert, c], by rw [prov, pr], by rw [subj, sb],
          x, tok, List.mem_append_left _ held, serialEq.symm, ht, valid, sealer, sealed⟩
    · have noneIssued : (match x.token with
          | some tok => issuedOf ops sealer issuePolicy s.entry tok tokenId now lifetime
          | none => none) = none := by
        rcases failed with ht | ⟨tok, rej, ht, hrej⟩
        · rw [ht]
        · rw [ht]; exact issuedOf_none hrej
      rw [noneIssued]
      refine inv_of_rewrite inv at_k slots next rfl rfl (by simp [Event.serial]) ?_ (onceFin _) ?_
      · refine ⟨⟨st0, List.mem_append_left _ started0, SameEntry_withStage se _⟩, ?_⟩
        simp only [withStage, cnt_append, cnt_single, isFin, isDel, decide_true, ↓reduceIte, zf, zd]
        exact ⟨by simp, by simp, by simp⟩
      · intro ev m
        simp only [List.mem_singleton] at m
        subst m
        exact ⟨x, List.mem_append_left _ held, serialEq.symm⟩

/-- **`poll` preserves the invariant.** -/
theorem poll_preserves {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {mb : Mailbox} {H : List Event} {peer login : Slice U8} {now : I64} {r : Polled} {mb' : Mailbox}
    (inv : Inv ops policy (mb, H))
    (run : stateless_mailbox.poll mb peer login now = Result.ok (r, mb')) :
    Inv ops policy (mb', H ++ pollEvents mb peer login r) := by
  obtain ⟨next, ⟨slots, notReady⟩ | ⟨k, hk, s, at_k, idx, slots, ready⟩⟩ := poll_effect run
  · have none : pollEvents mb peer login r = [] := by
      cases r with
      | Ready t e n => exact absurd rfl (notReady t e n)
      | _ => rfl
    rw [none, List.append_nil]
    exact inv_of_sublist inv (by rw [slots]) next
  · have sIn : s ∈ occ mb.slots.val := at_mem_occ at_k
    have sub : (occ mb'.slots.val).Sublist (occ mb.slots.val) := by rw [slots]; exact occ_remove_sublist hk
    by_cases isReady : ∃ t e n, r = .Ready t e n
    · obtain ⟨t, e, n, rr⟩ := isReady
      obtain ⟨delivered, ht, _, _⟩ := ready t e n rr
      subst rr ht
      obtain ⟨cert, stage, _⟩ := deliver_trace s.entry peer now delivered
      obtain ⟨⟨st0, started0, se⟩, counts⟩ := inv.slots s sIn
      rw [stage] at counts
      obtain ⟨⟨iss, finished0, tokenEq⟩, _, zd⟩ := counts
      have events : pollEvents mb peer login (.Ready s.token e n) = [.delivered s.serial peer.val s.token] := by
        simp only [pollEvents]
        rw [slotAt_of at_k idx]
      rw [events]
      refine ⟨List.Nodup.sublist (sub.map _) inv.serials, List.Nodup.sublist (sub.map _) inv.logins,
        fun y m => by rw [next]; exact inv.slotsBelow y (sub.subset m), ?_, ?_, ?_, ?_⟩
      · intro ev m
        show ev.serial.val < mb'.next.val
        rw [next]
        rcases List.mem_append.mp m with old | new
        · exact inv.eventsBelow ev old
        · simp only [List.mem_singleton] at new
          subst new
          exact inv.slotsBelow s sIn
      · intro y m
        rw [slots] at m
        rcases occ_set_mem Slot.serial hk at_k inv.serials none y m with e | ⟨m', ne⟩
        · cases e
        · exact SlotOK_append _ (inv.slots y m') (fun ev me => by
            simp only [List.mem_singleton] at me
            subst me
            exact quiet_other (by simp only [Event.serial]; exact fun h => ne h.symm))
      · intro σ
        obtain ⟨a, b, c, d, f⟩ := inv.once σ
        simp only [cnt_append, cnt_single]
        refine ⟨by simp [isStart]; omega, by simp [isAcc]; omega, by simp [isExch]; omega,
          by simp [isFin]; omega, ?_⟩
        by_cases same : s.serial = σ
        · subst same; simp [isDel, zd]
        · simp [isDel, same]; omega
      · intro ev m
        rcases List.mem_append.mp m with old | new
        · exact EventOK_mono _ (inv.events ev old)
        · simp only [List.mem_singleton] at new
          subst new
          obtain ⟨_, _, c, _, _, _, _⟩ := se
          exact ⟨st0, iss, List.mem_append_left _ started0, by rw [← c]; exact cert,
            List.mem_append_left _ finished0, tokenEq.symm⟩
    · have none : pollEvents mb peer login r = [] := by
        cases r with
        | Ready t e n => exact absurd ⟨t, e, n, rfl⟩ isReady
        | _ => rfl
      rw [none, List.append_nil]
      exact inv_of_sublist inv sub next

/-- **Every step preserves the invariant.** -/
theorem step_preserves {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {c c' : Mailbox × List Event} (inv : Inv ops policy c) (move : Step ops policy c c') : Inv ops policy c' := by
  cases move with
  | start run => exact start_preserves inv run
  | pending _ => exact inv
  | accept run => exact accept_preserves inv run
  | exchange inst e held unspent run => exact exchange_preserves inst e inv held unspent run
  | finish held run => exact finish_preserves inv held run
  | poll run => exact poll_preserves inv run

/-- **The invariant holds in every reachable state.** -/
theorem reachable_inv {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {c : Mailbox × List Event} (reach : Reachable ops policy c) : Inv ops policy c := by
  induction reach with
  | init made => exact initial_inv ops policy made
  | step _ move ih => exact step_preserves ih move

/-! ## What every history of the broker satisfies -/

section Global

variable {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
  {mb : Mailbox} {H : List Event}

/-- **Every mailbox entry comes from a login start, and keeps what it began
    with.** Whatever happened since — callbacks, exchanges, polls, pruning,
    other logins — a slot's login, provider, certificate, subject,
    certificate expiry and window are those of the `begin` that created it,
    for the peer that called `start`. -/
theorem slot_from_start (reach : Reachable ops policy (mb, H)) {s : Slot} (live : some s ∈ mb.slots.val) :
    ∃ st, Event.started st s.serial ∈ H ∧ SameEntry st s.entry ∧
      ∃ (provider peer subject : Slice U8) (ce : I64) (login verifier scope : Slice U8) (now : I64),
        BeginSpec policy provider peer subject ce login verifier scope now st := by
  have inv := reachable_inv reach
  obtain ⟨⟨st, m, same⟩, _⟩ := inv.slots s (mem_occ.mpr live)
  exact ⟨st, m, same, inv.events _ m⟩

/-- **A callback is accepted only for its own pending login.** The accepted
    state is the same login (id, provider, certificate, subject, certificate
    expiry, window, replica) as a start, the clock was inside that window,
    the provider's RFC 9207 issuer rule held, and the permit names exactly
    that login and the state's verifier. -/
theorem accepted_matches_start (reach : Reachable ops policy (mb, H))
    {st : stateless_login.LoginState} {rule : oauth_login.IssuerRule} {issuer : Slice U8} {has : Bool}
    {now : I64} {p : Permit} (acc : Event.accepted st rule issuer has now p ∈ H) :
    ∃ st0, Event.started st0 p.serial ∈ H ∧ SameLogin policy (entryOf st0) st ∧
      st0.issued_at.val ≤ now.val ∧ now.val < st0.expires_at.val ∧ IssuerHolds rule issuer has ∧
      p.login = st0.login ∧ p.provider = st0.provider ∧ p.verifier = st.verifier :=
  (reachable_inv reach).events _ acc

/-- **One login, one code exchange, one surrogate, one delivery.** For every
    login (every serial a start handed out), the history has at most one
    accepted callback, at most one code exchange, at most one finished
    exchange and at most one delivery — however callbacks are replayed and
    however transitions of other logins interleave. -/
theorem at_most_once (reach : Reachable ops policy (mb, H)) (σ : U64) :
    cnt (isAcc σ) H ≤ 1 ∧ cnt (isExch σ) H ≤ 1 ∧ cnt (isFin σ) H ≤ 1 ∧ cnt (isDel σ) H ≤ 1 := by
  obtain ⟨_, a, b, c, d⟩ := (reachable_inv reach).once σ
  exact ⟨a, b, c, d⟩

/-- **A surrogate is issued only for the peer that began the login.** It is
    bound to that start's certificate, provider and subject, it is what the
    sealer produced from a valid credential, and that credential is the token
    the code exchange of this very login returned. -/
theorem issued_for_starting_peer (reach : Reachable ops policy (mb, H)) {σ : U64} {iss : stateless.Issued}
    (fin : Event.finished σ (some iss) ∈ H) :
    ∃ st0, Event.started st0 σ ∈ H ∧ iss.claims.certificate = st0.certificate ∧
      iss.claims.provider = st0.provider ∧ iss.claims.subject = st0.subject ∧
      (∃ (provider peer subject : Slice U8) (ce : I64) (login verifier scope : Slice U8) (now : I64),
        BeginSpec policy provider peer subject ce login verifier scope now st0) ∧
      ∃ x tok, Event.exchanged x ∈ H ∧ x.permit.serial = σ ∧ x.token = some tok ∧
        http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref tok.credential) ∧
        ∃ sealer, ops.«seal» sealer iss.claims (alloc.vec.Vec.deref tok.credential) = Result.ok (.Ok iss.token) := by
  have inv := reachable_inv reach
  obtain ⟨st0, m, cert, prov, subj, rest⟩ := inv.events _ fin
  exact ⟨st0, m, cert, prov, subj, inv.events _ m, rest⟩

/-- **A completed surrogate is delivered only to the peer that began the
    login**, and it is exactly the surrogate issued for it. -/
theorem delivered_to_starting_peer (reach : Reachable ops policy (mb, H)) {σ : U64} {peer : List U8}
    {t : alloc.vec.Vec U8} (del : Event.delivered σ peer t ∈ H) :
    ∃ st0 iss, Event.started st0 σ ∈ H ∧ peer = st0.certificate.val ∧
      Event.finished σ (some iss) ∈ H ∧ t = iss.token ∧ iss.claims.certificate = st0.certificate := by
  have inv := reachable_inv reach
  obtain ⟨st0, iss, m, cert, fin, ht⟩ := inv.events _ del
  obtain ⟨st1, m1, c1, _⟩ := inv.events _ fin
  have same := started_unique (inv.once σ).1 m m1
  subst same
  exact ⟨st0, iss, m, cert.symm, fin, ht, c1⟩

/-- **A failed or uncertain exchange never yields a surrogate.** If a
    login's exchange finished without one, nothing is ever delivered for it,
    and it is never issued one later. -/
theorem failed_never_delivered (reach : Reachable ops policy (mb, H)) {σ : U64}
    (failed : Event.finished σ none ∈ H) :
    (∀ peer t, Event.delivered σ peer t ∉ H) ∧ ∀ iss, Event.finished σ (some iss) ∉ H := by
  have inv := reachable_inv reach
  have noIssue : ∀ iss, Event.finished σ (some iss) ∉ H := by
    intro iss fin
    have := unique_of_cnt (inv.once σ).2.2.2.1 failed fin (by simp [isFin]) (by simp [isFin])
    simp at this
  refine ⟨?_, noIssue⟩
  intro peer t del
  obtain ⟨_, iss, _, _, fin, _⟩ := inv.events _ del
  exact noIssue iss fin

/-- **A login in the mailbox that is not complete has never been
    delivered**, and a delivered login is gone: delivery is single-use. -/
theorem delivered_is_gone (reach : Reachable ops policy (mb, H)) {σ : U64} {peer : List U8}
    {t : alloc.vec.Vec U8} (del : Event.delivered σ peer t ∈ H) :
    ∀ s, some s ∈ mb.slots.val → s.serial ≠ σ := by
  have inv := reachable_inv reach
  intro s live same
  obtain ⟨_, rest⟩ := inv.slots s (mem_occ.mpr live)
  have pos : 0 < cnt (isDel σ) H := by
    unfold cnt
    exact List.countP_pos_iff.mpr ⟨_, del, by simp [isDel]⟩
  subst same
  cases hs : s.entry.stage <;> simp only [hs] at rest <;> omega

end Global

end aivm_secrets_garrett_core.stateless_mailbox.Proofs
