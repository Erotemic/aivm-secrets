import AivmSecretsGarrettCore
import GarrettFoundation
import GarrettSessionAudit

/-!
# The proxy audit row

Source: `rust/crates/aivm-secrets-garrett-core/src/proxy_audit.rs`, extracted
by Aeneas. `garrett-proxy`'s `Session::record` builds every audit row with
`proxy_audit::row` and writes exactly its extracted JSON encoding; the native
side keeps only the chain position, the clock, the detail values, the file
write and SHA-256 of the line.

Proved here:

* `key_before_spec`: the key order is `KeyLt`, scalar by scalar, a proper
  prefix first;
* `clone_value_exact`: copying a JSON value returns exactly that value;
* `merge_spec`: the field merge computes exactly `MergeL`, the merge of the
  two lists by `KeyLt` (every field kept, values unchanged);
* `row_exact`: a row is the object of the five fixed fields `event`, `prev`,
  `schema` (`"proxy-audit-1"`), `seq`, `timestamp` merged with the detail.

A Rust oracle (`extracted_proxy_audit_rows_match_the_serde_rows`) checks the
encoding against the serde rows it replaced; the two differ only for non-ASCII
text (the extracted encoder writes `\uXXXX`), which proxy rows never contain.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs

namespace aivm_secrets_garrett_core.proxy_audit.Proofs

/-- Key order: compare scalar by scalar; a proper prefix comes first. -/
def KeyLt : List U32 → List U32 → Prop
  | [], [] => False
  | [], _ :: _ => True
  | _ :: _, [] => False
  | x :: xs, y :: ys => if x = y then KeyLt xs ys else x.val < y.val

theorem key_before_loop_spec (a b : Slice U32) (index : Usize)
    (inside : index.val ≤ a.length) :
    key_before_loop a b index ⦃ r =>
      r = true ↔ KeyLt (a.val.drop index.val) (b.val.drop index.val) ⦄ := by
  suffices ∀ n (index : Usize), a.length - index.val = n → index.val ≤ a.length →
      key_before_loop a b index ⦃ r =>
        r = true ↔ KeyLt (a.val.drop index.val) (b.val.drop index.val) ⦄ from this _ index rfl inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure inside
    rw [key_before_loop.eq_def]
    dsimp only
    split
    · rename_i ina
      split
      · rename_i inb
        step as ⟨x, hx⟩
        step as ⟨y, hy⟩
        have da : a.val.drop index.val = x :: a.val.drop (index.val + 1) := by
          rw [hx]; exact List.drop_eq_getElem_cons (by scalar_tac)
        have db : b.val.drop index.val = y :: b.val.drop (index.val + 1) := by
          rw [hy]; exact List.drop_eq_getElem_cons (by scalar_tac)
        rw [da, db]
        split
        · rename_i ne
          have ne' : x ≠ y := by simpa using ne
          simp [WP.spec_ok, KeyLt, ne']
        · rename_i eq
          have eq' : x = y := by
            have : x.val = y.val := by simpa using eq
            exact UScalar.eq_of_val_eq this
          step as ⟨next, hnext⟩
          refine WP.spec_mono (ih (a.length - next.val) (by scalar_tac) next rfl (by scalar_tac)) ?_
          intro r hr
          rw [hr, hnext]
          simp [KeyLt, eq']
      · rename_i outb
        have db : b.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
        have da : a.val.drop index.val ≠ [] := by
          intro e; have := congrArg List.length e; simp at this; scalar_tac
        obtain ⟨x, rest, hda⟩ := List.exists_cons_of_ne_nil da
        simp only [WP.spec_ok, decide_eq_true_eq, db, hda, KeyLt, iff_false]
        scalar_tac
    · rename_i outa
      have da : a.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
      simp only [WP.spec_ok, decide_eq_true_eq, da]
      cases hdb : b.val.drop index.val with
      | nil =>
        have : b.val.length ≤ index.val := by
          have := congrArg List.length hdb; simp at this; omega
        simp [KeyLt]; scalar_tac
      | cons y ys =>
        have : index.val < b.val.length := by
          by_contra h; rw [List.drop_eq_nil_of_le (by omega)] at hdb; cases hdb
        simp [KeyLt]; scalar_tac

/-! ## Copying a JSON value -/

theorem vec_clone_exact {T : Type} (inst : core.clone.Clone T) (h : ∀ x, inst.clone x = Result.ok x)
    (v : alloc.vec.Vec T) : alloc.vec.CloneVec.clone inst v = Result.ok v := by
  unfold alloc.vec.CloneVec.clone
  obtain ⟨copied, returned, property⟩ := returned_of_spec
    (Slice.clone_spec (s := v.slice) (clone := inst.clone) (by intro x _; exact h x))
  rw [returned]
  simp only [bind_tc_ok, ← property]

theorem clone_u32 : ∀ x : U32, core.clone.CloneU32.clone x = Result.ok x := fun _ => rfl
theorem clone_u8 : ∀ x : U8, core.clone.CloneU8.clone x = Result.ok x := fun _ => rfl

theorem clone_value_loop0_exact (items out : alloc.vec.Vec json_wire.Value) (index : Usize)
    (each : ∀ x ∈ items.val, clone_value x = Result.ok x)
    (bound : out.length + (items.length - index.val) ≤ Usize.max) :
    clone_value_loop0 items out index ⦃ r => r.val = out.val ++ items.val.drop index.val ⦄ := by
  suffices ∀ n (out : alloc.vec.Vec json_wire.Value) (index : Usize), items.length - index.val = n →
      out.length + (items.length - index.val) ≤ Usize.max →
      clone_value_loop0 items out index ⦃ r => r.val = out.val ++ items.val.drop index.val ⦄ from
    this _ out index rfl bound
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out index measure bound
    rw [clone_value_loop0.eq_def]
    dsimp only
    split
    · step as ⟨x, hx⟩
      have mem : x ∈ items.val := by rw [hx]; exact List.getElem_mem _
      rw [each x mem]
      simp only [bind_ok]
      step as ⟨out1, hout1⟩
      step as ⟨next, hnext⟩
      refine WP.spec_mono (ih (items.length - next.val) (by scalar_tac) out1 next rfl (by scalar_tac)) ?_
      intro r hr
      rw [hr, hout1, hnext, List.append_assoc, hx]
      congr 1
      exact (List.drop_eq_getElem_cons (by scalar_tac)).symm
    · simp only [WP.spec_ok]
      rw [List.drop_eq_nil_of_le (by scalar_tac)]
      simp

theorem clone_value_loop1_exact (fields out : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
    (index : Usize) (each : ∀ x ∈ fields.val, clone_value x.2 = Result.ok x.2)
    (bound : out.length + (fields.length - index.val) ≤ Usize.max) :
    clone_value_loop1 fields out index ⦃ r => r.val = out.val ++ fields.val.drop index.val ⦄ := by
  suffices ∀ n (out : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value)) (index : Usize),
      fields.length - index.val = n → out.length + (fields.length - index.val) ≤ Usize.max →
      clone_value_loop1 fields out index ⦃ r => r.val = out.val ++ fields.val.drop index.val ⦄ from
    this _ out index rfl bound
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out index measure bound
    rw [clone_value_loop1.eq_def]
    dsimp only
    split
    · step as ⟨key, value, hkv⟩
      have mem : (key, value) ∈ fields.val := by rw [hkv]; exact List.getElem_mem _
      rw [vec_clone_exact _ clone_u32 key, each _ mem]
      simp only [bind_ok]
      step as ⟨out1, hout1⟩
      step as ⟨next, hnext⟩
      refine WP.spec_mono (ih (fields.length - next.val) (by scalar_tac) out1 next rfl (by scalar_tac)) ?_
      intro r hr
      rw [hr, hout1, hnext, List.append_assoc, hkv]
      congr 1
      exact (List.drop_eq_getElem_cons (by scalar_tac)).symm
    · simp only [WP.spec_ok]
      rw [List.drop_eq_nil_of_le (by scalar_tac)]
      simp

theorem listN_mem_size {α : Type} [SizeOf α] :
    ∀ {n : Nat} (l : Aeneas.Data.ListN.ListN α n) (x : α), x ∈ l.toList → sizeOf x < sizeOf l
  | _, .nil, x, h => by simp [Aeneas.Data.ListN.ListN.toList] at h
  | _, .cons a rest, x, h => by
    simp only [Aeneas.Data.ListN.ListN.toList, List.mem_cons] at h
    rcases h with rfl | h
    · simp; omega
    · have := listN_mem_size rest x h
      simp; omega

theorem vec_mem_size {α : Type} [SizeOf α] (v : alloc.vec.Vec α) (x : α) (h : x ∈ v.val) :
    sizeOf x < sizeOf v := by
  rcases v with ⟨⟨n, l, b⟩⟩
  have := listN_mem_size l x (by simpa [alloc.vec.Vec.val, Slice.val] using h)
  simp; omega

/-- **Copying is the identity.** `clone_value` returns exactly its input. -/
theorem clone_value_exact : ∀ v : json_wire.Value, clone_value v = Result.ok v
  | .Null => by rw [clone_value]
  | .Boolean b => by rw [clone_value]
  | .Number digits => by rw [clone_value]; simp [vec_clone_exact _ clone_u8]
  | .Text units => by rw [clone_value]; simp [vec_clone_exact _ clone_u32]
  | .Array items => by
    have each : ∀ x ∈ items.val, clone_value x = Result.ok x := fun x hx =>
      have := vec_mem_size items x hx
      clone_value_exact x
    rw [clone_value]
    obtain ⟨r, hr, post⟩ := returned_of_spec
      (clone_value_loop0_exact items (alloc.vec.Vec.new _) 0#usize each (by simp))
    rw [hr]
    simp only [bind_ok, Result.ok.injEq]
    congr 1
    apply alloc.vec.Vec.ext
    simpa [alloc.vec.Vec.new] using post
  | .Object fields => by
    have each : ∀ x ∈ fields.val, clone_value x.2 = Result.ok x.2 := fun x hx =>
      have := vec_mem_size fields x hx
      have : sizeOf x.2 < sizeOf x := by rcases x with ⟨a, b⟩; simp
      clone_value_exact x.2
    rw [clone_value]
    obtain ⟨r, hr, post⟩ := returned_of_spec
      (clone_value_loop1_exact fields (alloc.vec.Vec.new _) 0#usize each (by simp))
    rw [hr]
    simp only [bind_ok, Result.ok.injEq]
    congr 1
    apply alloc.vec.Vec.ext
    simpa [alloc.vec.Vec.new] using post
termination_by v => sizeOf v
decreasing_by all_goals simp_wf; omega

/-! ## Merging fields -/

abbrev Field := alloc.vec.Vec U32 × json_wire.Value

instance (a b : List U32) : Decidable (KeyLt a b) := by
  induction a generalizing b with
  | nil => cases b <;> simp [KeyLt] <;> infer_instance
  | cons x xs ih => cases b with
    | nil => simp [KeyLt]; infer_instance
    | cons y ys => simp only [KeyLt]; split <;> first | exact ih ys | infer_instance

/-- The merge of two field lists by `KeyLt` on their keys. -/
def MergeL : List Field → List Field → List Field
  | [], r => r
  | l, [] => l
  | x :: xs, y :: ys =>
    if KeyLt x.1.val y.1.val then x :: MergeL xs (y :: ys) else y :: MergeL (x :: xs) ys
termination_by l r => l.length + r.length

theorem merge_nil_left (r : List Field) : MergeL [] r = r := by
  cases r <;> simp [MergeL]

theorem merge_nil_right (l : List Field) : MergeL l [] = l := by
  cases l <;> simp [MergeL]

theorem merge_cons (x y : Field) (xs ys : List Field) :
    MergeL (x :: xs) (y :: ys) =
      if KeyLt x.1.val y.1.val then x :: MergeL xs (y :: ys) else y :: MergeL (x :: xs) ys := by
  rw [MergeL]

theorem key_before_spec (a b : Slice U32) :
    key_before a b ⦃ r => r = true ↔ KeyLt a.val b.val ⦄ := by
  unfold key_before
  simpa using key_before_loop_spec a b 0#usize (by simp)

theorem deref_val {T : Type} (v : alloc.vec.Vec T) : (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref]

theorem merge_loop_spec (left right : Slice Field) (out : alloc.vec.Vec Field) (i j : Usize)
    (hi : i.val ≤ left.length) (hj : j.val ≤ right.length)
    (bound : out.length + (left.length - i.val) + (right.length - j.val) ≤ Usize.max) :
    merge_loop left right out i j ⦃ r =>
      r.val = out.val ++ MergeL (left.val.drop i.val) (right.val.drop j.val) ⦄ := by
  suffices ∀ n (out : alloc.vec.Vec Field) (i j : Usize),
      (left.length - i.val) + (right.length - j.val) = n → i.val ≤ left.length → j.val ≤ right.length →
      out.length + (left.length - i.val) + (right.length - j.val) ≤ Usize.max →
      merge_loop left right out i j ⦃ r =>
        r.val = out.val ++ MergeL (left.val.drop i.val) (right.val.drop j.val) ⦄ from
    this _ out i j rfl hi hj bound
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out i j measure hi hj bound
    have dropL : ∀ (h : i.val < left.length),
        left.val.drop i.val = left.val[i.val] :: left.val.drop (i.val + 1) :=
      fun h => List.drop_eq_getElem_cons (by simpa using h)
    have dropR : ∀ (h : j.val < right.length),
        right.val.drop j.val = right.val[j.val] :: right.val.drop (j.val + 1) :=
      fun h => List.drop_eq_getElem_cons (by simpa using h)
    rw [merge_loop.eq_def]
    dsimp only
    split
    · rename_i iL
      split
      · -- right exhausted: take left
        rename_i jR
        step as ⟨key, value, hkv⟩
        rw [vec_clone_exact _ clone_u32 key, clone_value_exact value]
        simp only [bind_ok]
        step as ⟨out1, hout1⟩
        step as ⟨next, hnext⟩
        refine WP.spec_mono (ih _ (by scalar_tac) out1 next j rfl (by scalar_tac) hj (by scalar_tac)) ?_
        intro r hr
        have empty : right.val.drop j.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
        rw [hr, hout1, hnext, empty, merge_nil_right, merge_nil_right, dropL (by scalar_tac), ← hkv]
        simp
      · rename_i jR
        step as ⟨key, value, hkv⟩
        step as ⟨key2, value2, hkv2⟩
        obtain ⟨b, hb, lt⟩ := returned_of_spec (key_before_spec (alloc.vec.Vec.deref key) (alloc.vec.Vec.deref key2))
        rw [hb]
        simp only [bind_ok]
        have ml : MergeL (left.val.drop i.val) (right.val.drop j.val) =
            if KeyLt key.val key2.val then (key, value) :: MergeL (left.val.drop (i.val + 1)) (right.val.drop j.val)
            else (key2, value2) :: MergeL (left.val.drop i.val) (right.val.drop (j.val + 1)) := by
          rw [dropL (by scalar_tac), dropR (by scalar_tac), ← hkv, ← hkv2, merge_cons]
        simp only [deref_val] at lt
        split
        · rename_i yes
          rw [vec_clone_exact _ clone_u32 key, clone_value_exact value]
          simp only [bind_ok]
          step as ⟨out1, hout1⟩
          step as ⟨next, hnext⟩
          refine WP.spec_mono (ih _ (by scalar_tac) out1 next j rfl (by scalar_tac) hj (by scalar_tac)) ?_
          intro r hr
          rw [hr, hout1, hnext, ml]
          simp [lt.mp yes, dropR (by scalar_tac), ← hkv2]
        · rename_i no
          rw [vec_clone_exact _ clone_u32 key2, clone_value_exact value2]
          simp only [bind_ok]
          step as ⟨out1, hout1⟩
          step as ⟨next, hnext⟩
          refine WP.spec_mono (ih _ (by scalar_tac) out1 i next rfl hi (by scalar_tac) (by scalar_tac)) ?_
          intro r hr
          have notlt : ¬ KeyLt key.val key2.val := fun h => no (lt.mpr h)
          rw [hr, hout1, hnext, ml]
          simp [notlt, dropL (by scalar_tac), ← hkv]
    · rename_i iL
      split
      · rename_i jR
        split
        · exfalso; scalar_tac
        · step as ⟨key2, value2, hkv2⟩
          rw [vec_clone_exact _ clone_u32 key2, clone_value_exact value2]
          simp only [bind_ok]
          step as ⟨out1, hout1⟩
          step as ⟨next, hnext⟩
          refine WP.spec_mono (ih _ (by scalar_tac) out1 i next rfl hi (by scalar_tac) (by scalar_tac)) ?_
          intro r hr
          have empty : left.val.drop i.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
          rw [hr, hout1, hnext, empty, merge_nil_left, merge_nil_left, dropR (by scalar_tac), ← hkv2]
          simp
      · simp only [WP.spec_ok]
        have e1 : left.val.drop i.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
        have e2 : right.val.drop j.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
        rw [e1, e2, merge_nil_left]
        simp

theorem merge_spec (left right : Slice Field) (fits : left.length + right.length ≤ Usize.max) :
    merge left right ⦃ r => r.val = MergeL left.val right.val ⦄ := by
  unfold merge
  refine WP.spec_mono (merge_loop_spec left right _ 0#usize 0#usize (by simp) (by simp)
    (by simp [alloc.vec.Vec.new, alloc.vec.Vec.length]; scalar_tac)) ?_
  intro r hr
  simpa [alloc.vec.Vec.new] using hr

theorem merge_returned {left right : Slice Field} {fields : alloc.vec.Vec Field}
    (fits : left.length + right.length ≤ Usize.max) (h : merge left right = Result.ok fields) :
    fields.val = MergeL left.val right.val := by
  obtain ⟨r, hr, post⟩ := returned_of_spec (merge_spec left right fits)
  have same : r = fields := Result.ok_injective (hr.symm.trans h)
  subst same
  exact post

open aivm_secrets_garrett_core.control.Proofs (Units IsText text_ok text_units_ok)
open aivm_secrets_garrett_core.session_audit.Proofs (Key)
open aivm_secrets_garrett_core.route.Proofs (bind_ok_inv)

/-- **A proxy audit row.** For detail fields that fit in memory, the row is
    the object whose fields are the merge, by key, of the five fixed fields
    `event`, `prev`, `schema` (`"proxy-audit-1"`), `seq`, `timestamp` with the
    event's detail fields; every value is exactly the one passed in. -/
theorem row_exact {event prev seq timestamp v : json_wire.Value} {detail : alloc.vec.Vec Field}
    (fits : detail.length + 5 ≤ Usize.max)
    (h : row event prev seq timestamp detail = Result.ok v) :
    ∃ (fields : alloc.vec.Vec Field) (kevent kprev kschema kseq kts : alloc.vec.Vec U32)
      (schema : json_wire.Value),
      v = .Object fields ∧
      fields.val = MergeL [(kevent, event), (kprev, prev), (kschema, schema), (kseq, seq),
        (kts, timestamp)] detail.val ∧
      Key kevent [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      Key kprev [112#u8, 114#u8, 101#u8, 118#u8] ∧
      Key kschema [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      Key kseq [115#u8, 101#u8, 113#u8] ∧
      Key kts [116#u8, 105#u8, 109#u8, 101#u8, 115#u8, 116#u8, 97#u8, 109#u8, 112#u8] ∧
      IsText schema [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 97#u8, 117#u8, 100#u8, 105#u8,
        116#u8, 45#u8, 49#u8] := by
  unfold row at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kevent, h1, h⟩ := bind_ok_inv h
  obtain ⟨kprev, h2, h⟩ := bind_ok_inv h
  obtain ⟨kschema, h3, h⟩ := bind_ok_inv h
  obtain ⟨schema, h4, h⟩ := bind_ok_inv h
  obtain ⟨kseq, h5, h⟩ := bind_ok_inv h
  obtain ⟨kts, h6, h⟩ := bind_ok_inv h
  obtain ⟨fields, merged, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  have post := merge_returned (by
      simp [Slice.length, alloc.slice.Slice.into_vec, alloc.vec.Vec.val, Slice.from_val, Array.from]
      have : detail.slice.val.length = detail.length := rfl
      omega) merged
  obtain ⟨su, hs, hsu⟩ := text_ok h4
  refine ⟨fields, kevent, kprev, kschema, kseq, kts, schema, rfl, ?_,
    by simpa [Key] using text_units_ok h1, by simpa [Key] using text_units_ok h2,
    by simpa [Key] using text_units_ok h3, by simpa [Key] using text_units_ok h5,
    by simpa [Key] using text_units_ok h6, ⟨su, hs, by simpa using hsu⟩⟩
  rw [post, deref_val]
  simp [alloc.slice.Slice.into_vec, alloc.vec.Vec.val, Slice.from_val, Array.from_val]

end aivm_secrets_garrett_core.proxy_audit.Proofs
