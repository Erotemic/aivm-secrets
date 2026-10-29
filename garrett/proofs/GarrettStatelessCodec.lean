import GarrettStatelessMailbox
import GarrettBase64
import GarrettHttpWireDecimal

/-!
# `garrett-stateless-v1`: the surrogate codec

Source: `crates/garrett-stateless-core/src/stateless_token.rs`,
extracted by Aeneas (`stateless_token.*`).
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.proxy_http.Proofs (bind_ok_inv slice_eq_eq array_slice_val)
open garrett_stateless_core.proxy_http.Base64Proofs (symNat sexNat enc encode_unpadded_spec g g_lt
  s0 s1 s2 s3 sexNat_lt symNat_injective)
open garrett_stateless_core.stateless_mailbox.Proofs (slice_index_eq usize_succ)
open garrett_stateless_core.http_wire.Proofs (Digit Digits DecimalValue digit_value decimal_value_exact
  decimal_value_append_digit)
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.stateless_token.Proofs

/-! ## Strict b64url -/

/-- What `symbol_value` computes. -/
def symVal (b : Nat) : Nat :=
  if 65 ≤ b ∧ b ≤ 90 then b - 65
  else if 97 ≤ b ∧ b ≤ 122 then b - 71
  else if 48 ≤ b ∧ b ≤ 57 then b + 4
  else if b = 45 then 62
  else if b = 95 then 63
  else 64

@[step] theorem symbol_value_spec (s : U8) : symbol_value s ⦃ v => v.val = symVal s.val ⦄ := by
  unfold symbol_value
  split_ifs <;> step* <;> (unfold symVal; split_ifs <;> scalar_tac)

theorem symVal_lt (b : Nat) : symVal b ≤ 64 := by
  unfold symVal; split_ifs <;> omega

theorem symVal_symNat (v : Nat) (small : v < 64) : symVal (symNat v true) = v := by
  unfold symVal symNat
  split_ifs <;> simp_all <;> omega

theorem slice_ne_eq (a b : Slice U8) :
    core.cmp.impls.PartialEqShared.ne (Slice.Insts.CoreCmpPartialEqSlice core.cmp.PartialEqU8) a b =
      Result.ok (decide (a.val ≠ b.val)) := by
  simp only [core.cmp.impls.PartialEqShared.ne, core.cmp.PartialEq.ne.default, slice_eq_eq]
  simp

/-- Symbol `i` of a text, as a value (64 for a non-alphabet byte). -/
def sym (l : List U8) (i : Nat) : Nat := symVal (l.getD i 0#u8).val

/-- Position `p` of a group of `count` symbols at `index`: missing ones are zero. -/
def term (l : List U8) (index count p : Nat) : Nat := if p < count then sym l (index + p) else 0

/-- The group value the loop accumulates from position `position` on. -/
def fold (l : List U8) (index count value position : Nat) : Nat :=
  (List.range' position (4 - position)).foldl (fun acc p => acc * 64 + term l index count p) value

theorem fold_step (l : List U8) (index count value position : Nat) (below : position < 4) :
    fold l index count value position = fold l index count (value * 64 + term l index count position) (position + 1) := by
  unfold fold
  have : 4 - position = (4 - (position + 1)) + 1 := by omega
  rw [this, List.range'_succ]
  rfl

theorem fold_done (l : List U8) (index count value : Nat) : fold l index count value 4 = value := by
  simp [fold]

theorem group_loop_spec (text : Slice U8) (index count : Usize) (inside : index.val + count.val ≤ text.length)
    (small : count.val ≤ 4) :
    ∀ n (value : U32) (valid : Bool) (position : Usize), 4 - position.val = n → position.val ≤ 4 →
      value.val < 64 ^ position.val →
      group_loop text index count value valid position ⦃ r =>
        (r.2 = true ↔ (valid = true ∧ ∀ p, position.val ≤ p → p < count.val → sym text.val (index.val + p) < 64)) ∧
        (r.2 = true → r.1.val = fold text.val index.val count.val value.val position.val) ⦄ := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro value valid position measure upto room
    rw [group_loop.eq_def]
    by_cases more : position.val < 4
    · have cond : position < 4#usize := by scalar_tac
      simp only [cond, ↓reduceIte]
      have pnext := usize_succ position (by scalar_tac)
      obtain ⟨next, hnext, nval⟩ := pnext
      -- the symbol at this position
      have symbolSpec : (if position < count then do
            let i ← index + position
            let i1 ← Slice.index_usize text i
            symbol_value i1
          else Result.ok 0#u32) ⦃ sv => sv.val = term text.val index.val count.val position.val ⦄ := by
        unfold term
        split
        · rename_i lt
          have lt' : position.val < count.val := by scalar_tac
          simp only [lt', ↓reduceIte]
          step*
          have inb : index.val + position.val < text.val.length := by scalar_tac
          unfold sym
          rw [List.getD_eq_getElem _ _ inb]
          simp_all
        · rename_i ge
          have ge' : ¬ position.val < count.val := by scalar_tac
          simp [ge']
      apply WP.spec_bind symbolSpec
      intro sv svv
      by_cases bad : sv.val ≥ 64
      · have cond2 : sv ≥ 64#u32 := by scalar_tac
        simp only [cond2, ↓reduceIte, bind_ok, hnext]
        have := ih (4 - next.val) (by omega) value false next rfl (by omega)
          (by rw [nval, Nat.pow_succ]; have : value.val < 64 ^ position.val := room; omega)
        apply WP.spec_mono this
        rintro ⟨v, ok⟩ ⟨iff, _⟩
        refine ⟨?_, ?_⟩
        · simp only at iff ⊢
          rw [iff]
          constructor
          · rintro ⟨f, _⟩; cases f
          · rintro ⟨_, all⟩
            have lt : position.val < count.val := by
              by_contra no
              have : term text.val index.val count.val position.val = 0 := by simp [term, no]
              omega
            have := all position.val (Nat.le_refl _) lt
            have : term text.val index.val count.val position.val = sym text.val (index.val + position.val) := by
              simp [term, lt]
            omega
        · intro h; simp only at iff; rw [iff] at h; exact absurd h.1 (by simp)
      · have cond2 : ¬ sv ≥ 64#u32 := by scalar_tac
        simp only [cond2, ↓reduceIte]
        have vbound : value.val * 64 + sv.val < 64 ^ (position.val + 1) := by
          rw [Nat.pow_succ]; have : value.val < 64 ^ position.val := room; omega
        have p3 : 64 ^ (position.val + 1) ≤ 64 ^ 4 := Nat.pow_le_pow_right (by omega) (by omega)
        obtain ⟨m, hm, mv⟩ := returned_of_spec (U32.mul_spec (x := value) (y := 64#u32) (by
          have : 64 ^ 4 = 16777216 := by norm_num
          simp; scalar_tac))
        obtain ⟨a, ha, av⟩ := returned_of_spec (U32.add_spec (x := m) (y := sv) (by
          have : 64 ^ 4 = 16777216 := by norm_num
          rw [mv]; simp; scalar_tac))
        simp only [hm, ha, bind_ok, hnext]
        have aval : a.val = value.val * 64 + sv.val := by rw [av, mv]; simp
        have := ih (4 - next.val) (by omega) a valid next rfl (by omega) (by rw [aval, nval]; exact vbound)
        apply WP.spec_mono this
        rintro ⟨v, ok⟩ ⟨iff, val⟩
        simp only at iff val ⊢
        refine ⟨?_, ?_⟩
        · rw [iff, nval]
          constructor
          · rintro ⟨vt, all⟩
            refine ⟨vt, fun p lo hi => ?_⟩
            by_cases same : p = position.val
            · have hp : position.val < count.val := same ▸ hi
              have t : term text.val index.val count.val position.val = sym text.val (index.val + position.val) := by
                simp [term, hp]
              rw [same]; omega
            · exact all p (by omega) hi
          · rintro ⟨vt, all⟩
            exact ⟨vt, fun p lo hi => all p (by omega) hi⟩
        · intro h
          rw [val h, fold_step _ _ _ _ _ more, aval, svv, nval]
    · have cond : ¬ position < 4#usize := by scalar_tac
      simp only [cond, ↓reduceIte, WP.spec_ok]
      have four : position.val = 4 := by omega
      refine ⟨?_, fun _ => by rw [four, fold_done]⟩
      constructor
      · intro h; exact ⟨h, fun p lo hi => by omega⟩
      · intro h; exact h.1

/-- Every symbol of a group is in the alphabet. -/
def GroupOK (l : List U8) (index count : Nat) : Prop := ∀ p, p < count → sym l (index + p) < 64

theorem group_spec (text : Slice U8) (index : Usize) (inside : index.val < text.length) :
    group text index ⦃ r =>
      (r.isSome ↔ GroupOK text.val index.val (min 4 (text.length - index.val))) ∧
      ∀ v c, r = some (v, c) → c.val = min 4 (text.length - index.val) ∧
        v.val = fold text.val index.val (min 4 (text.length - index.val)) 0 0 ⦄ := by
  unfold group
  step*
  -- the count
  have countSpec : (if i1 < 4#usize then Slice.len text - index else Result.ok 4#usize) ⦃ c =>
      c.val = min 4 (text.length - index.val) ⦄ := by
    split
    · step*
    · simp only [WP.spec_ok]; scalar_tac
  apply WP.spec_bind countSpec
  intro count cv
  apply WP.spec_bind (group_loop_spec text index count (by scalar_tac) (by scalar_tac) _ 0#u32 true 0#usize rfl
    (by simp) (by simp))
  rintro ⟨value, valid⟩ ⟨iff, val⟩
  simp only at iff val
  simp only [Aeneas.Std.uncurry_apply_pair]
  split
  · rename_i yes
    simp only [WP.spec_ok, Option.isSome_some, true_iff, Option.some.injEq, Prod.mk.injEq]
    have ok := iff.mp yes
    refine ⟨fun p hp => ok.2 p (by simp) (by rw [cv]; exact hp), ?_⟩
    rintro v c ⟨rfl, rfl⟩
    exact ⟨cv, by rw [val yes, cv]; rfl⟩
  · rename_i no
    simp only [WP.spec_ok, Option.isSome_none, Bool.false_eq_true, false_iff, reduceCtorEq, false_imp_iff,
      implies_true, and_true]
    intro all
    apply no
    exact iff.mpr ⟨trivial, fun p _ hp => all p (by rw [← cv]; exact hp)⟩

/-- The bytes of group `q` from its sextets: the arithmetic `from_b64url` relies on. -/
theorem group_bytes (x : List U8) (q c : Nat) (two : 2 ≤ c) (four : c ≤ 4)
    (short : c < 4 → 3 * q + c - 1 = x.length) :
    let t := fun p => if p < c then sexNat x (4 * q + p) else 0
    let v := t 0 * 262144 + t 1 * 4096 + t 2 * 64 + t 3
    v / 65536 = g x (3 * q) ∧ (2 < c → v / 256 % 256 = g x (3 * q + 1)) ∧
      (3 < c → v % 256 = g x (3 * q + 2)) := by
  intro t v
  have a0 := s0 x q; have a1 := s1 x q; have a2 := s2 x q; have a3 := s3 x q
  have h0 := g_lt x (3 * q); have h1 := g_lt x (3 * q + 1); have h2 := g_lt x (3 * q + 2)
  have h3 := g_lt x (3 * q + 3)
  have zero : ∀ j, x.length ≤ j → g x j = 0 := by
    intro j hj; simp [g, List.getElem?_eq_none hj]
  simp only [t, v]
  rcases (by omega : c = 2 ∨ c = 3 ∨ c = 4) with rfl | rfl | rfl
  · have z1 := zero (3 * q + 1) (by have := short (by omega); omega)
    have z2 := zero (3 * q + 2) (by have := short (by omega); omega)
    simp only [show (0 : Nat) < 2 from by omega, show (1 : Nat) < 2 from by omega, show ¬ (2 : Nat) < 2 from by omega,
      show ¬ (3 : Nat) < 2 from by omega, ↓reduceIte, Nat.add_zero]
    refine ⟨?_, by omega, by omega⟩
    rw [a0, a1, z1]; omega
  · have z2 := zero (3 * q + 2) (by have := short (by omega); omega)
    simp only [show (0 : Nat) < 3 from by omega, show (1 : Nat) < 3 from by omega, show (2 : Nat) < 3 from by omega,
      show ¬ (3 : Nat) < 3 from by omega, ↓reduceIte, Nat.add_zero]
    rw [a0, a1, a2, z2]
    refine ⟨by omega, fun _ => by omega, by omega⟩
  · simp only [show (0 : Nat) < 4 from by omega, show (1 : Nat) < 4 from by omega, show (2 : Nat) < 4 from by omega,
      show (3 : Nat) < 4 from by omega, ↓reduceIte, Nat.add_zero]
    rw [a0, a1, a2, a3]
    refine ⟨by omega, fun _ => by omega, fun _ => by omega⟩

theorem push_val {α : Type} {v : alloc.vec.Vec α} {x : α} (room : v.val.length < Usize.max) :
    ∃ w, alloc.vec.Vec.push v x = Result.ok w ∧ w.val = v.val ++ [x] := by
  obtain ⟨w, hw, wv⟩ := returned_of_spec (alloc.vec.Vec.push_spec v x room)
  exact ⟨w, hw, wv⟩

theorem cast_u8 (v : U32) (small : v.val < 256) : (UScalar.cast .U8 v).val = v.val := by
  have := UScalar.cast_val_mod_pow_of_inBounds_eq .U8 v (by simpa using small)
  simpa using this

/-- The bytes one group appends: its first byte, the second for three or more
    symbols, the third for four. -/
def GroupBytes (v c : Nat) : List U8 :=
  [U8.ofNatCore (v / 65536 % 256) (by scalar_tac)] ++
    (if 2 < c then [U8.ofNatCore (v / 256 % 256) (by scalar_tac)] else []) ++
    (if 3 < c then [U8.ofNatCore (v % 256) (by scalar_tac)] else [])

theorem u8_ext {a : U8} {n : Nat} {h : n < 2 ^ 8} (e : a.val = n) : a = U8.ofNatCore n h := by
  apply UScalar.eq_of_val_eq; simpa using e

theorem ofNat_eq_of_val {n : Nat} {h : n < 2 ^ 8} {b : U8} (e : n = b.val) : U8.ofNatCore n h = b := by
  apply UScalar.eq_of_val_eq; simpa using e

/-- **One decoder iteration**: a valid group at `index` appends exactly its
    bytes and moves past its symbols. -/
theorem from_b64url_loop_some (text : Slice U8) (out : alloc.vec.Vec U8) (index : Usize)
    (value : U32) (count : Usize) (inside : index.val < text.length)
    (found : group text index = Result.ok (some (value, count)))
    (room : out.val.length + 3 ≤ Usize.max) (past : index.val + count.val ≤ Usize.max) :
    ∃ out3 index1, from_b64url_loop text out true index = from_b64url_loop text out3 true index1 ∧
      out3.val = out.val ++ GroupBytes value.val count.val ∧ index1.val = index.val + count.val := by
  rw [from_b64url_loop.eq_def]
  have cond : index < Slice.len text := by scalar_tac
  simp only [↓reduceIte, cond, found, bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain ⟨d0, hd0, d0v⟩ := UScalar.div_spec value (y := 65536#u32) (by simp)
  rw [hd0]
  simp only [bind_ok, lift]
  obtain ⟨o1, ho1, o1v⟩ := push_val (v := out) (x := UScalar.cast .U8 d0) (by omega)
  rw [ho1]
  simp only [bind_ok]
  have b0 : UScalar.cast .U8 d0 = U8.ofNatCore (value.val / 65536 % 256) (by scalar_tac) := by
    apply u8_ext; rw [UScalar.cast_val_eq, d0v]; simp
  -- the second byte
  obtain ⟨o2, ho2, o2v⟩ : ∃ o2, (if count > 2#usize then do
        let i3 ← value / 256#u32
        let i4 ← i3 % 256#u32
        alloc.vec.Vec.push o1 (UScalar.cast .U8 i4)
      else Result.ok o1) = Result.ok o2 ∧
      o2.val = o1.val ++ (if 2 < count.val then [U8.ofNatCore (value.val / 256 % 256) (by scalar_tac)] else []) := by
    by_cases c2 : 2 < count.val
    · have c2' : count > 2#usize := by scalar_tac
      simp only [c2', ↓reduceIte, c2]
      obtain ⟨d1, hd1, d1v⟩ := UScalar.div_spec value (y := 256#u32) (by simp)
      obtain ⟨m1, hm1, m1v⟩ := returned_of_spec (UScalar.rem_spec d1 (y := 256#u32) (by simp))
      obtain ⟨w, hw, wv⟩ := push_val (v := o1) (x := UScalar.cast .U8 m1) (by rw [o1v]; simp; omega)
      refine ⟨w, by rw [hd1]; simp only [bind_ok]; rw [hm1]; simp only [bind_ok]; exact hw, ?_⟩
      rw [wv]
      congr 2
      apply u8_ext; rw [UScalar.cast_val_eq, m1v, d1v]; simp
    · have c2' : ¬ count > 2#usize := by scalar_tac
      simp [c2', c2]
  rw [ho2]
  simp only [bind_ok]
  obtain ⟨o3, ho3, o3v⟩ : ∃ o3, (if count > 3#usize then do
        let i3 ← value % 256#u32
        alloc.vec.Vec.push o2 (UScalar.cast .U8 i3)
      else Result.ok o2) = Result.ok o3 ∧
      o3.val = o2.val ++ (if 3 < count.val then [U8.ofNatCore (value.val % 256) (by scalar_tac)] else []) := by
    by_cases c3 : 3 < count.val
    · have c3' : count > 3#usize := by scalar_tac
      simp only [c3', ↓reduceIte, c3]
      obtain ⟨m2, hm2, m2v⟩ := returned_of_spec (UScalar.rem_spec value (y := 256#u32) (by simp))
      obtain ⟨w, hw, wv⟩ := push_val (v := o2) (x := UScalar.cast .U8 m2) (by
        rw [o2v, o1v]; split <;> simp <;> omega)
      refine ⟨w, by rw [hm2]; simp only [bind_ok]; exact hw, ?_⟩
      rw [wv]
      congr 2
      apply u8_ext; rw [UScalar.cast_val_eq, m2v]; simp
    · have c3' : ¬ count > 3#usize := by scalar_tac
      simp [c3', c3]
  rw [ho3]
  simp only [bind_ok]
  obtain ⟨i1, hi1, i1v⟩ := returned_of_spec (Usize.add_spec (x := index) (y := count) (by scalar_tac))
  rw [hi1]
  simp only [bind_ok]
  refine ⟨o3, i1, rfl, ?_, i1v⟩
  rw [o3v, o2v, o1v, b0]
  simp [GroupBytes, List.append_assoc]

/-- The decoder never writes more bytes than it reads symbols. -/
theorem fold_expand (l : List U8) (index count : Nat) :
    fold l index count 0 0 = term l index count 0 * 262144 + term l index count 1 * 4096 +
      term l index count 2 * 64 + term l index count 3 := by
  simp [fold, List.range', List.foldl]
  ring

theorem fold_small (l : List U8) (index count : Nat) (ok : GroupOK l index count) :
    fold l index count 0 0 < 16777216 := by
  have t : ∀ p, term l index count p < 64 := by
    intro p; unfold term; split
    · rename_i lt; exact ok p lt
    · omega
  rw [fold_expand]
  have := t 0; have := t 1; have := t 2; have := t 3
  omega

theorem from_b64url_loop_length (text : Slice U8) (fits : text.length + 3 ≤ Usize.max) :
    ∀ n (out : alloc.vec.Vec U8) (valid : Bool) (index : Usize), text.length - index.val = n →
      index.val ≤ text.length → out.val.length ≤ index.val →
      from_b64url_loop text out valid index ⦃ r => r.1.val.length ≤ text.length ⦄ := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out valid index measure upto sized
    cases valid with
    | false =>
      rw [from_b64url_loop.eq_def]
      simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
      omega
    | true =>
      by_cases inside : index.val < text.length
      · obtain ⟨o, ho, shape⟩ := returned_of_spec (group_spec text index inside)
        cases o with
        | none =>
          rw [from_b64url_loop.eq_def]
          have cond : index < Slice.len text := by scalar_tac
          simp only [↓reduceIte, cond, ho, bind_ok]
          rw [from_b64url_loop.eq_def]
          simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
          omega
        | some pr =>
          obtain ⟨value, count⟩ := pr
          obtain ⟨cval, vval⟩ := shape.2 value count rfl
          have bound := text.property
          have small : value.val < 16777216 := by
            rw [vval]; exact fold_small _ _ _ (shape.1.mp rfl)
          obtain ⟨out3, index1, same, o3, i1⟩ := from_b64url_loop_some text out index value count inside ho
            (by scalar_tac) (by scalar_tac)
          rw [same]
          apply ih _ (by omega) out3 true index1 rfl (by omega)
          rw [o3, i1]
          simp only [GroupBytes, List.length_append, List.length_singleton]
          split <;> split <;> simp <;> omega
      · rw [from_b64url_loop.eq_def]
        have cond : ¬ index < Slice.len text := by scalar_tac
        simp only [↓reduceIte, cond, WP.spec_ok]
        omega

theorem vals_injective {a b : List U8} (h : a.map (·.val) = b.map (·.val)) : a = b := by
  induction a generalizing b with
  | nil => cases b <;> simp_all
  | cons x xs ih =>
    cases b with
    | nil => simp at h
    | cons y ys =>
      simp only [List.map_cons, List.cons.injEq] at h
      rw [UScalar.eq_of_val_eq h.1, ih h.2]

/-- **Strict decoding is sound**: whatever `from_b64url` accepts is exactly the
    unpadded url encoding of the bytes it returns (the trailing check), so
    every accepted text has one preimage. -/
theorem from_b64url_sound {text : Slice U8} {out : alloc.vec.Vec U8} (fits : 8 * text.length + 5 ≤ Usize.max)
    (h : from_b64url text = Result.ok (some out)) :
    text.val.map (·.val) = enc out.val true ∧ out.val.length ≤ text.length := by
  unfold from_b64url at h
  obtain ⟨i1, hi1, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  · obtain ⟨⟨out', valid⟩, hloop, h⟩ := bind_ok_inv h
    have len := from_b64url_loop_length text (by omega) _ (alloc.vec.Vec.new U8) true 0#usize rfl (by simp) (by simp)
    rw [hloop, WP.spec_ok] at len
    simp only at len h
    simp only [Aeneas.Std.uncurry_apply_pair] at h
    split at h
    · obtain ⟨encoded, henc, h⟩ := bind_ok_inv h
      rw [slice_ne_eq] at h
      simp only [bind_ok] at h
      split at h
      · simp at h
      · rename_i same
        simp only [Result.ok.injEq, Option.some.injEq] at h
        subst h
        have spec := encode_unpadded_spec (alloc.vec.Vec.deref out') true (by simp [alloc.vec.Vec.deref]; omega)
        rw [henc, WP.spec_ok] at spec
        simp only [decide_eq_true_eq, not_not] at same
        refine ⟨?_, len⟩
        have : encoded.val = text.val := by simpa [alloc.vec.Vec.deref] using same
        rw [← this, spec]
        simp [alloc.vec.Vec.deref]
    · simp at h

/-- `L = ceil(8n/6)`: how the group positions of an encoding relate to its bytes. -/
theorem enc_length (x : List U8) (url : Bool) : (enc x url).length = (8 * x.length + 5) / 6 := by
  simp [enc]

theorem sym_enc {x text : List U8} (h : text.map (·.val) = enc x true) (i : Nat) (hi : i < text.length) :
    sym text i = sexNat x i := by
  have lens : text.length = (8 * x.length + 5) / 6 := by
    rw [← enc_length x true, ← h]; simp
  have := congrArg (fun l => l[i]?) h
  simp only [List.getElem?_map, List.getElem?_eq_getElem hi, Option.map_some, enc,
    List.getElem?_range (by omega : i < (8 * x.length + 5) / 6), Option.some.injEq] at this
  unfold sym
  rw [List.getD_eq_getElem _ _ hi, this]
  exact symVal_symNat _ (sexNat_lt x i)

theorem g_eq {x : List U8} {j : Nat} (hj : j < x.length) : g x j = x[j].val := by
  simp [g, List.getElem?_eq_getElem hj]

/-- **Strict decoding is complete** on its own output: the decoder returns
    exactly the bytes that were encoded. -/
theorem from_b64url_loop_complete (x text : Slice U8) (h : text.val.map (·.val) = enc x.val true)
    (fits : 8 * text.val.length + 5 ≤ Usize.max) :
    ∀ n q (out : alloc.vec.Vec U8) (index : Usize), text.val.length - index.val = n → index.val = 4 * q →
      index.val ≤ text.val.length → out.val = x.val.take (3 * q) →
      ∃ out', from_b64url_loop text out true index = Result.ok (out', true) ∧ out'.val = x.val := by
  have lens : text.val.length = (8 * x.val.length + 5) / 6 := by
    have := congrArg List.length h; simp [enc] at this; simpa using this
  have xfits : x.val.length ≤ text.val.length := by omega
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro q out index measure at4 upto sofar
    by_cases inside : index.val < text.val.length
    · have symOk : GroupOK text.val index.val (min 4 (text.val.length - index.val)) := by
        intro p hp
        rw [sym_enc h _ (by omega)]
        exact sexNat_lt _ _
      obtain ⟨o, ho, shape⟩ := returned_of_spec (group_spec text index inside)
      simp only [Slice.length] at shape
      cases o with
      | none => exact absurd (shape.1.mpr symOk) (by simp)
      | some pr =>
        obtain ⟨value, count⟩ := pr
        obtain ⟨cval, vval⟩ := shape.2 value count rfl
        have small : value.val < 16777216 := by rw [vval]; exact fold_small _ _ _ symOk
        have bound := text.property
        obtain ⟨out3, index1, same, o3, i1⟩ := from_b64url_loop_some text out index value count inside ho
          (by rw [sofar]; simp; omega) (by scalar_tac)
        rw [same]
        -- the group's value from the sextets of `x`
        obtain ⟨c, hc⟩ : ∃ c, c = min 4 (text.val.length - index.val) := ⟨_, rfl⟩
        rw [← hc] at cval vval
        have two : 2 ≤ c := by omega
        have short : c < 4 → 3 * q + c - 1 = x.val.length := by intro; omega
        obtain ⟨b0, b1, b2⟩ := group_bytes x.val q c two (by omega) short
        simp only at b0 b1 b2
        have e : ∀ p, term text.val index.val c p = if p < c then sexNat x.val (4 * q + p) else 0 := by
          intro p; unfold term; split_ifs with hp
          · rw [sym_enc h _ (by omega), at4]
          · rfl
        have vexp : value.val = (if 0 < c then sexNat x.val (4 * q + 0) else 0) * 262144 +
            (if 1 < c then sexNat x.val (4 * q + 1) else 0) * 4096 +
            (if 2 < c then sexNat x.val (4 * q + 2) else 0) * 64 +
            (if 3 < c then sexNat x.val (4 * q + 3) else 0) := by
          rw [vval, fold_expand, e 0, e 1, e 2, e 3]
        rw [← vexp] at b0 b1 b2
        have byte0 : U8.ofNatCore (value.val / 65536 % 256) (by scalar_tac) = x.val[3 * q]'(by omega) := by
          apply ofNat_eq_of_val
          rw [Nat.mod_eq_of_lt (by omega), b0, g_eq (by omega)]
        by_cases full : 4 ≤ text.val.length - index.val
        · have c4 : c = 4 := by omega
          have byte1 : U8.ofNatCore (value.val / 256 % 256) (by scalar_tac) = x.val[3 * q + 1]'(by omega) := by
            apply ofNat_eq_of_val; rw [b1 (by omega), g_eq (by omega)]
          have byte2 : U8.ofNatCore (value.val % 256) (by scalar_tac) = x.val[3 * q + 2]'(by omega) := by
            apply ofNat_eq_of_val; rw [b2 (by omega), g_eq (by omega)]
          obtain ⟨out', run, val'⟩ := ih _ (by omega) (q + 1) out3 index1 rfl (by omega) (by omega) (by
            rw [o3, sofar, cval, c4]
            simp only [GroupBytes, show 2 < 4 from by omega, show 3 < 4 from by omega, ↓reduceIte]
            rw [show 3 * (q + 1) = 3 * q + 2 + 1 by omega, List.take_add_one, List.take_add_one, List.take_add_one]
            simp only [List.getElem?_eq_getElem (by omega : 3 * q < x.val.length),
              List.getElem?_eq_getElem (by omega : 3 * q + 1 < x.val.length),
              List.getElem?_eq_getElem (by omega : 3 * q + 2 < x.val.length), Option.toList_some,
              List.append_assoc, List.singleton_append, byte0, byte1, byte2])
          exact ⟨out', run, val'⟩
        · -- the last, partial group: then the text ends
          have stop : index1.val = text.val.length := by omega
          refine ⟨out3, ?_, ?_⟩
          · rw [from_b64url_loop.eq_def]
            have cond : ¬ index1 < Slice.len text := by scalar_tac
            simp [cond]
          · rw [o3, sofar, cval]
            rcases (by omega : c = 2 ∨ c = 3) with c2 | c3
            · have n1 : x.val.length = 3 * q + 1 := by omega
              simp only [GroupBytes, c2, show ¬ (2 : Nat) < 2 from by omega, show ¬ (3 : Nat) < 2 from by omega,
                ↓reduceIte, List.append_nil]
              conv => rhs; rw [← List.take_of_length_le (Nat.le_of_eq n1) (l := x.val)]
              rw [List.take_add_one, List.getElem?_eq_getElem (by omega : 3 * q < x.val.length), Option.toList_some,
                byte0]
            · have n2 : x.val.length = 3 * q + 2 := by omega
              have byte1 : U8.ofNatCore (value.val / 256 % 256) (by scalar_tac) = x.val[3 * q + 1]'(by omega) := by
                apply ofNat_eq_of_val; rw [b1 (by omega), g_eq (by omega)]
              simp only [GroupBytes, c3, show (2 : Nat) < 3 from by omega, show ¬ (3 : Nat) < 3 from by omega,
                ↓reduceIte, List.append_nil]
              conv => rhs; rw [← List.take_of_length_le (Nat.le_of_eq n2) (l := x.val)]
              rw [show 3 * q + 2 = 3 * q + 1 + 1 by omega, List.take_add_one, List.take_add_one,
                List.getElem?_eq_getElem (by omega : 3 * q < x.val.length),
                List.getElem?_eq_getElem (by omega : 3 * q + 1 < x.val.length), Option.toList_some,
                Option.toList_some, byte0, byte1, List.append_assoc, List.singleton_append]
    · have atEnd : index.val = text.val.length := by omega
      refine ⟨out, ?_, ?_⟩
      · rw [from_b64url_loop.eq_def]
        have cond : ¬ index < Slice.len text := by scalar_tac
        simp [cond]
      · rw [sofar, List.take_of_length_le (by omega)]

theorem from_b64url_complete (x text : Slice U8) (h : text.val.map (·.val) = enc x.val true)
    (fits : 8 * text.val.length + 5 ≤ Usize.max) :
    ∃ out, from_b64url text = Result.ok (some out) ∧ out.val = x.val := by
  have lens : text.val.length = (8 * x.val.length + 5) / 6 := by
    have := congrArg List.length h; simp [enc] at this; simpa using this
  obtain ⟨out, run, val⟩ := from_b64url_loop_complete x text h fits _ 0 (alloc.vec.Vec.new U8) 0#usize rfl
    (by simp) (by simp) (by simp)
  refine ⟨out, ?_, val⟩
  unfold from_b64url
  simp only
  obtain ⟨m, hm, mv⟩ := returned_of_spec (Usize.rem_spec (x := Slice.len text) (y := 4#usize) (by simp))
  rw [hm]
  simp only [bind_ok]
  have xle : x.val.length ≤ text.val.length := by omega
  have notOne : ¬ m = 1#usize := by
    intro e; have := congrArg UScalar.val e; simp [Slice.len] at this mv; omega
  simp only [notOne, ↓reduceIte, run, bind_ok, Aeneas.Std.uncurry_apply_pair]
  have spec := encode_unpadded_spec (alloc.vec.Vec.deref out) true (by simp [alloc.vec.Vec.deref, val]; omega)
  obtain ⟨encoded, henc, ev⟩ := returned_of_spec spec
  rw [henc]
  simp only [bind_ok, slice_ne_eq]
  have same : encoded.val = text.val := by
    apply vals_injective
    rw [ev, h]
    simp [alloc.vec.Vec.deref, val]
  simp [alloc.vec.Vec.deref, same]

/-! ## The exact layout -/

/-- `lit` occurs at `pos` in `b`. -/
def At (b : List U8) (pos : Nat) (lit : List U8) : Prop := pos + lit.length ≤ b.length ∧ (b.drop pos).take lit.length = lit

theorem word_spec (b : Slice U8) (pos : Usize) (lit : Slice U8) (room : pos.val + lit.length ≤ Usize.max) :
    word b pos lit ⦃ r => (∀ i, r = some i → i.val = pos.val + lit.length ∧ At b.val pos.val lit.val) ∧
      (r = none → ¬ At b.val pos.val lit.val) ⦄ := by
  unfold word
  step*
  · refine ⟨by simp, fun _ => ?_⟩
    rintro ⟨fits, _⟩
    scalar_tac
  · have hs : found.val = (b.val.drop pos.val).take lit.length := by
      rw [found_post]; simp only [List.slice]; congr 1; scalar_tac
    simp only [slice_ne_eq, bind_ok]
    split
    · rename_i differ
      simp only [WP.spec_ok, reduceCtorEq, false_imp_iff, implies_true, true_and, forall_const]
      rintro ⟨_, same⟩
      apply (decide_eq_true_iff.mp differ)
      rw [hs, same]
    · rename_i same
      simp only [decide_eq_true_eq, not_not] at same
      step*
      refine ⟨?_, by simp⟩
      intro i hi
      simp only [Option.some.injEq] at hi
      subst hi
      have fits : pos.val + lit.length ≤ b.length := by clear hs same found_post found_post1; scalar_tac
      refine ⟨by rw [i6_post, Slice.len_val], fits, ?_⟩
      rw [← hs, same]

theorem usize_big : 4294967295 ≤ Usize.max := by
  rcases Usize.bounds_eq with h | h <;> rw [h] <;> simp [U32.max_eq, U64.max_eq]

/-- **A literal, as a cursor step**: `word` accepts exactly where the bytes
    continue with the literal. -/
theorem word_some {b lit : Slice U8} {pos i : Usize} (room : pos.val + lit.length ≤ Usize.max)
    (h : word b pos lit = Result.ok (some i)) :
    i.val = pos.val + lit.length ∧ b.val.drop pos.val = lit.val ++ b.val.drop i.val := by
  have spec := word_spec b pos lit room
  rw [h, WP.spec_ok] at spec
  obtain ⟨iv, fits, same⟩ := spec.1 i rfl
  refine ⟨iv, ?_⟩
  rw [iv, ← same, ← List.drop_drop, List.take_append_drop]

theorem word_none {b lit : Slice U8} {pos : Usize} (room : pos.val + lit.length ≤ Usize.max)
    (inb : pos.val ≤ b.length) (h : word b pos lit = Result.ok none) : ¬ ∃ rest, b.val.drop pos.val = lit.val ++ rest := by
  have spec := word_spec b pos lit room
  rw [h, WP.spec_ok] at spec
  rintro ⟨rest, eq⟩
  apply spec.2 rfl
  refine ⟨?_, by rw [eq]; simp⟩
  have := congrArg List.length eq
  have inb' : pos.val ≤ b.val.length := inb
  simp at this
  omega

theorem word_of {b lit : Slice U8} {pos : Usize} {rest : List U8} (room : pos.val + lit.length ≤ Usize.max)
    (inb : pos.val ≤ b.length) (eq : b.val.drop pos.val = lit.val ++ rest) :
    ∃ i, word b pos lit = Result.ok (some i) ∧ i.val = pos.val + lit.length := by
  obtain ⟨r, hr, post⟩ := returned_of_spec (word_spec b pos lit room)
  cases r with
  | some i => exact ⟨i, hr, (post.1 i rfl).1⟩
  | none => exact absurd ⟨rest, eq⟩ (word_none room inb hr)

theorem word_absent {b lit : Slice U8} {pos : Usize} (room : pos.val + lit.length ≤ Usize.max)
    (absent : ¬ ∃ rest, b.val.drop pos.val = lit.val ++ rest) : word b pos lit = Result.ok none := by
  obtain ⟨r, hr, post⟩ := returned_of_spec (word_spec b pos lit room)
  cases r with
  | none => exact hr
  | some i =>
    obtain ⟨_, same⟩ := word_some room hr
    exact absurd ⟨_, same⟩ absent

/-- No quote and no backslash: what every grammar field satisfies. -/
def Plain (l : List U8) : Prop := ∀ x ∈ l, x.val ≠ 34 ∧ x.val ≠ 92

theorem plain_string_loop_spec (b : Slice U8) :
    ∀ n (index : Usize), b.length - index.val = n → index.val ≤ b.length →
      plain_string_loop b index ⦃ j => index.val ≤ j.val ∧ j.val ≤ b.length ∧
        Plain ((b.val.drop index.val).take (j.val - index.val)) ∧
        (∀ (inside : j.val < b.length), (b.val[j.val]'inside).val = 34 ∨ (b.val[j.val]'inside).val = 92) ⦄ := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure upto
    rw [plain_string_loop.eq_def]
    by_cases inside : index.val < b.length
    · have cond : index < Slice.len b := by scalar_tac
      simp only [cond, ↓reduceIte]
      obtain ⟨x, hx⟩ : ∃ x, b.val[index.val]'inside = x := ⟨_, rfl⟩
      rw [slice_index_eq b index inside, hx]
      simp only [bind_ok]
      by_cases q : x.val = 34
      · have e : x = 34#u8 := UScalar.eq_of_val_eq (by simpa using q)
        simp only [e, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
        refine ⟨Nat.le_refl _, by omega, by simp [Plain], fun _ => Or.inl (by rw [hx]; exact q)⟩
      · have e : (x != 34#u8) = true := by
          simp only [bne_iff_ne, ne_eq]; intro h; apply q; rw [h]; rfl
        simp only [e, ↓reduceIte]
        by_cases bs : x.val = 92
        · have e2 : x = 92#u8 := UScalar.eq_of_val_eq (by simpa using bs)
          simp only [e2, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
          refine ⟨Nat.le_refl _, by omega, by simp [Plain], fun _ => Or.inr (by rw [hx]; exact bs)⟩
        · have e2 : (x != 92#u8) = true := by
            simp only [bne_iff_ne, ne_eq]; intro h; apply bs; rw [h]; rfl
          simp only [e2, ↓reduceIte]
          have bound := b.property
          obtain ⟨next, hnext, nval⟩ := usize_succ index (by scalar_tac)
          rw [hnext]
          simp only [bind_ok]
          apply WP.spec_mono (ih _ (by omega) next rfl (by omega))
          rintro j ⟨lo, hi, plain, stop⟩
          refine ⟨by omega, hi, ?_, stop⟩
          rw [nval] at lo plain
          have split : (b.val.drop index.val).take (j.val - index.val) =
              x :: (b.val.drop (index.val + 1)).take (j.val - (index.val + 1)) := by
            rw [← List.getElem_cons_drop inside, hx]
            rw [show j.val - index.val = (j.val - (index.val + 1)) + 1 by omega, List.take_succ_cons]
          rw [split]
          intro y mem
          rcases List.mem_cons.mp mem with e | m
          · subst e; exact ⟨q, bs⟩
          · exact plain y m
    · have cond : ¬ index < Slice.len b := by scalar_tac
      simp only [cond, ↓reduceIte, WP.spec_ok]
      refine ⟨Nat.le_refl _, upto, by simp [Plain], fun h => absurd h (by omega)⟩

theorem slice_range_val {b : Slice U8} {lo hi : Usize} (le : lo.val ≤ hi.val) (inb : hi.val ≤ b.length) :
    ∃ found, core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice U8) b
        { start := lo, «end» := hi } = Result.ok found ∧
      found.val = (b.val.drop lo.val).take (hi.val - lo.val) := by
  obtain ⟨f, hf, fv, _⟩ := returned_of_spec
    (core.slice.index.SliceIndexRangeUsizeSlice.index.step_spec { start := lo, «end» := hi } b
      (by scalar_tac) (by simpa using inb))
  refine ⟨f, by simpa [core.slice.index.Slice.index] using hf, ?_⟩
  rw [fv]; simp [List.slice]

theorem to_vec_val (s : Slice U8) : ∃ v, alloc.slice.Slice.to_vec core.clone.CloneU8 s = Result.ok v ∧ v.val = s.val := by
  exact ⟨⟨s⟩, garrett_stateless_core.stateless.Proofs.to_vec_eq s, rfl⟩

/-- **A quoted field, as a cursor step.** What `plain_string` accepts is a
    quote, bytes with no quote or backslash, and a quote. -/
theorem plain_string_some {b : Slice U8} {pos next : Usize} {v : alloc.vec.Vec U8}
    (h : plain_string b pos = Result.ok (some (v, next))) :
    b.val.drop pos.val = 34#u8 :: (v.val ++ 34#u8 :: b.val.drop next.val) ∧ Plain v.val ∧
      next.val = pos.val + v.val.length + 2 := by
  unfold plain_string at h
  simp only at h
  split at h
  · simp at h
  · rename_i inside0
    have inside : pos.val < b.length := by scalar_tac
    obtain ⟨x, hx⟩ : ∃ x, b.val[pos.val]'inside = x := ⟨_, rfl⟩
    rw [slice_index_eq b pos inside, hx] at h
    simp only [bind_ok] at h
    split at h
    · simp at h
    · rename_i isQuote
      have xq : x = 34#u8 := UScalar.eq_of_val_eq (by simpa using isQuote)
      have bound := b.property
      obtain ⟨start, hs, sv⟩ := usize_succ pos (by scalar_tac)
      rw [hs] at h
      simp only [bind_ok] at h
      obtain ⟨j, hj, lo, hi, plain, stop⟩ := returned_of_spec (plain_string_loop_spec b _ start rfl (by omega))
      rw [hj] at h
      simp only [bind_ok] at h
      split at h
      · simp at h
      · rename_i jin0
        have jin : j.val < b.length := by scalar_tac
        obtain ⟨y, hy⟩ : ∃ y, b.val[j.val]'jin = y := ⟨_, rfl⟩
        rw [slice_index_eq b j jin, hy] at h
        simp only [bind_ok] at h
        split at h
        · simp at h
        · rename_i closes
          have yq : y = 34#u8 := UScalar.eq_of_val_eq (by simpa using closes)
          obtain ⟨found, hf, fv⟩ := slice_range_val (b := b) (lo := start) (hi := j) (by omega) (by omega)
          rw [hf] at h
          simp only [bind_ok, garrett_stateless_core.stateless.Proofs.to_vec_eq] at h
          obtain ⟨n2, hn2, n2v⟩ := usize_succ j (by scalar_tac)
          rw [hn2] at h
          simp only [bind_ok, Result.ok.injEq, Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨e1, e2⟩ := h
          subst e1 e2
          have vv : ({ slice := found } : alloc.vec.Vec U8).val = found.val := rfl
          rw [vv]
          rw [sv] at fv
          simp only [Slice.length] at hi jin
          have flen : found.val.length = j.val - (pos.val + 1) := by
            rw [fv, List.length_take, List.length_drop]; omega
          refine ⟨?_, by rw [fv]; rw [sv] at plain; exact plain, by rw [n2v, flen]; omega⟩
          rw [← List.getElem_cons_drop inside, hx, xq, fv]
          congr 1
          have dj : b.val.drop (pos.val + 1) =
              (b.val.drop (pos.val + 1)).take (j.val - (pos.val + 1)) ++ b.val.drop j.val := by
            conv => lhs; rw [← List.take_append_drop (j.val - (pos.val + 1)) (b.val.drop (pos.val + 1))]
            rw [List.drop_drop]; congr 2; omega
          rw [show b.val.drop j.val = 34#u8 :: b.val.drop (j.val + 1) from by
            rw [← List.getElem_cons_drop jin, hy, yq]] at dj
          rw [n2v]; exact dj

/-- The converse: a quote, plain bytes and a quote are accepted, exactly. -/
theorem plain_string_of {b : Slice U8} {pos : Usize} {f rest : List U8}
    (eq : b.val.drop pos.val = 34#u8 :: (f ++ 34#u8 :: rest)) (plain : Plain f) :
    ∃ v next, plain_string b pos = Result.ok (some (v, next)) ∧ v.val = f ∧
      next.val = pos.val + f.length + 2 := by
  have lens : b.val.length = pos.val + f.length + 2 + rest.length := by
    have := congrArg List.length eq
    simp at this
    omega
  have tail : b.val.drop (pos.val + 1) = f ++ 34#u8 :: rest := by
    rw [← List.drop_drop, eq]; rfl
  have bound := b.property
  obtain ⟨start, hs, sv⟩ := usize_succ pos (by omega)
  obtain ⟨j, hj, lo, hi, jplain, stop⟩ := returned_of_spec (plain_string_loop_spec b _ start rfl (by
    simp only [Slice.length]; omega))
  simp only [Slice.length] at hi stop
  rw [sv] at lo jplain
  -- the loop stops exactly at the closing quote
  have jval : j.val = pos.val + 1 + f.length := by
    rcases Nat.lt_trichotomy j.val (pos.val + 1 + f.length) with lt | e | gt
    · exfalso
      obtain ⟨k, hk⟩ : ∃ k, j.val = pos.val + 1 + k := ⟨j.val - (pos.val + 1), by omega⟩
      have kin : k < f.length := by omega
      have bj : b.val[j.val]? = some (f[k]'kin) := by
        rw [hk, ← List.getElem?_drop, tail, List.getElem?_append_left kin, List.getElem?_eq_getElem kin]
      rw [List.getElem?_eq_getElem (by rw [lens]; omega)] at bj
      simp only [Option.some.injEq] at bj
      have := stop (by rw [lens]; omega)
      rw [bj] at this
      have := plain _ (List.getElem_mem kin)
      omega
    · exact e
    · exfalso
      have inTake : (34#u8) ∈ (b.val.drop (pos.val + 1)).take (j.val - (pos.val + 1)) := by
        rw [tail, List.take_append]
        apply List.mem_append_right
        rw [show j.val - (pos.val + 1) - f.length = (j.val - (pos.val + 1) - f.length - 1) + 1 by omega,
          List.take_succ_cons]
        exact List.mem_cons_self
      exact (jplain _ inTake).1 rfl
  -- the code path
  have jin : j.val < b.val.length := by omega
  obtain ⟨x, hx⟩ : ∃ x, b.val[pos.val]'(by omega) = x := ⟨_, rfl⟩
  have xq : x = 34#u8 := by
    have := congrArg (fun l => l[0]?) eq
    simp only [List.getElem?_drop, Nat.add_zero, List.getElem?_cons_zero] at this
    rw [List.getElem?_eq_getElem (by omega), hx] at this
    simpa using this
  obtain ⟨y, hy⟩ : ∃ y, b.val[j.val]'jin = y := ⟨_, rfl⟩
  have yq : y = 34#u8 := by
    have := congrArg (fun l => l[f.length]?) tail
    simp only [List.getElem?_drop, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self,
      List.getElem?_cons_zero] at this
    rw [show pos.val + 1 + f.length = j.val by omega, List.getElem?_eq_getElem jin, hy] at this
    simpa using this
  obtain ⟨found, hf, fv⟩ := slice_range_val (b := b) (lo := start) (hi := j) (by omega) (by simp only [Slice.length]; omega)
  obtain ⟨n2, hn2, n2v⟩ := usize_succ j (by omega)
  refine ⟨⟨found⟩, n2, ?_, ?_, by rw [n2v, jval]; omega⟩
  · unfold plain_string
    simp only
    have c1 : ¬ pos ≥ Slice.len b := by scalar_tac
    have c3 : ¬ j ≥ Slice.len b := by scalar_tac
    simp only [c1, ↓reduceIte]
    rw [slice_index_eq b pos (by simp only [Slice.length]; omega), hx, xq]
    simp only [bind_ok, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, hs, hj, c3]
    rw [slice_index_eq b j (by simp only [Slice.length]; omega), hy, yq]
    simp only [bind_ok, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, hf,
      garrett_stateless_core.stateless.Proofs.to_vec_eq, hn2]
  · show found.val = f
    rw [fv, sv, tail, jval, show pos.val + 1 + f.length - (pos.val + 1) = f.length by omega,
      List.take_left' rfl]

/-! ### Decimal integers -/

abbrev IsDigit (x : U8) : Prop := 48 ≤ x.val ∧ x.val ≤ 57

theorem digit_eq (x : U8) : digit x = Result.ok (decide (IsDigit x)) := by
  unfold digit IsDigit
  split <;> simp_all

theorem digits_all (n : Nat) : ∀ x ∈ Digits n, IsDigit x := by
  induction n using Nat.strong_induction_on with
  | h n ih =>
    rw [Digits]
    intro x mem
    split at mem
    · rcases List.mem_append.mp mem with m | m
      · exact ih (n / 10) (by omega) x m
      · simp at m; subst m; unfold IsDigit; rw [digit_value]; omega
    · simp at mem; subst mem; unfold IsDigit; rw [digit_value]; omega

theorem digits_ne_nil (n : Nat) : Digits n ≠ [] := by
  rw [Digits]; split <;> simp

/-- The digits of `n ≥ 1` do not start with `0`. -/
theorem digits_head (n : Nat) (pos : 0 < n) : ∀ h, (Digits n).head h ≠ 48#u8 := by
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro h
    rw [List.head_eq_getElem]
    by_cases big : n ≥ 10
    · have e : Digits n = Digits (n / 10) ++ [Digit n] := by rw [Digits]; simp [big]
      have hd := ih (n / 10) (by omega) (by omega) (digits_ne_nil _)
      simp only [e]
      rw [List.getElem_append_left (by have := digits_ne_nil (n / 10); cases hh : Digits (n / 10) <;> simp_all)]
      rw [List.head_eq_getElem] at hd
      exact hd
    · have e : Digits n = [Digit n] := by rw [Digits]; simp [big]
      simp only [e, List.getElem_cons_zero]
      intro eq
      have := congrArg UScalar.val eq
      rw [digit_value] at this
      simp at this
      omega

theorem decimal_pos {x : U8} {xs : List U8} (dx : IsDigit x) (nz : x ≠ 48#u8) :
    0 < DecimalValue (x :: xs) := by
  simp only [DecimalValue]
  have one : 1 ≤ 10 ^ xs.length := Nat.one_le_pow _ _ (by omega)
  have xv : 49 ≤ x.val := by
    have : x.val ≠ 48 := fun e => nz (UScalar.eq_of_val_eq (by simpa using e))
    unfold IsDigit at dx; omega
  have := Nat.mul_le_mul (show 1 ≤ x.val - 48 by omega) one
  omega

/-- A digit run without a leading zero is the decimal form of its value. -/
theorem digits_of_canonical : ∀ (ds : List U8), ds ≠ [] → (∀ x ∈ ds, IsDigit x) →
    (ds.length = 1 ∨ ∀ h, ds.head h ≠ 48#u8) → Digits (DecimalValue ds) = ds := by
  intro ds
  induction ds using List.reverseRecOn with
  | nil => intro h; exact absurd rfl h
  | append_singleton init d ih =>
    intro _ alld canon
    have dd : IsDigit d := alld d (by simp)
    have dv : DecimalValue (init ++ [d]) = 10 * DecimalValue init + (d.val - 48) := by
      have := decimal_value_append_digit init (d.val - 48)
      have dig : Digit (d.val - 48) = d := by
        apply UScalar.eq_of_val_eq; rw [digit_value]; unfold IsDigit at dd; omega
      rw [dig] at this
      rw [this]; unfold IsDigit at dd; omega
    by_cases empty : init = []
    · subst empty
      simp only [List.nil_append] at dv ⊢
      rw [dv, Digits]
      unfold IsDigit at dd
      simp only [show ¬ (10 * DecimalValue [] + (d.val - 48) ≥ 10) by simp [DecimalValue]; omega, ↓reduceIte,
        List.cons.injEq, and_true]
      apply UScalar.eq_of_val_eq; rw [digit_value]; simp [DecimalValue]; omega
    · have initDigits : ∀ x ∈ init, IsDigit x := fun x m => alld x (by simp [m])
      have headOk : init.length = 1 ∨ ∀ h, init.head h ≠ 48#u8 := by
        right; intro h
        rcases canon with one | hd
        · exact absurd (by simpa using one) empty
        · have := hd (by simp)
          rwa [List.head_append_of_ne_nil] at this
      have recur := ih empty initDigits headOk
      have pos : 0 < DecimalValue init := by
        cases hi : init with
        | nil => exact absurd hi empty
        | cons x xs =>
          have xd : IsDigit x := initDigits x (by simp [hi])
          rcases headOk with one | hd
          · rw [hi] at one
            simp at one
            subst one
            rw [hi] at canon
            rcases canon with c1 | c2
            · simp at c1
            · have := c2 (by simp)
              simp at this
              exact decimal_pos xd (fun e => this (by rw [e]; rfl))
          · have := hd (by simp [hi])
            simp only [hi, List.head_cons] at this
            exact decimal_pos xd this
      rw [dv, Digits]
      simp only [show 10 * DecimalValue init + (d.val - 48) ≥ 10 by omega, ↓reduceIte]
      rw [show (10 * DecimalValue init + (d.val - 48)) / 10 = DecimalValue init by unfold IsDigit at dd; omega, recur]
      congr 1
      simp only [List.cons.injEq, and_true]
      apply UScalar.eq_of_val_eq; rw [digit_value]; unfold IsDigit at dd; omega

theorem decimal_cons (x : U8) (xs : List U8) :
    DecimalValue (x :: xs) = (x.val - 48) * 10 ^ xs.length + DecimalValue xs := rfl

theorem max_integer_val : MAX_INTEGER.val = 9007199254740991 := by
  simp [MAX_INTEGER]

/-- The arithmetic of one digit step (`digits_loop`): the digit's value and
    the overflow bound. -/
theorem digit_step (x : U8) (dx : IsDigit x) :
    ∃ i2 : U8, ∃ i3 i4 : I64, x - 48#u8 = Result.ok i2 ∧
      MAX_INTEGER - UScalar.hcast IScalarTy.I64 i2 = Result.ok i3 ∧ i3 / 10#i64 = Result.ok i4 ∧
      (UScalar.hcast IScalarTy.I64 i2).val = x.val - 48 ∧ i4.val = (9007199254740991 - (x.val - 48)) / 10 := by
  unfold IsDigit at dx
  have mn := I64.min_eq; have mx := I64.max_eq
  obtain ⟨i2, h2, v2⟩ := returned_of_spec (U8.sub_spec (x := x) (y := 48#u8) (by simp; omega))
  have n2 : (UScalar.hcast IScalarTy.I64 i2).val = (x.val - 48 : Nat) := by
    have := UScalar.hcast_inBounds_spec .I64 i2 (by scalar_tac)
    simp only [lift, WP.spec_ok] at this
    rw [this, v2.1]; simp
  obtain ⟨i3, h3, v3⟩ := returned_of_spec (I64.sub_spec (x := MAX_INTEGER) (y := UScalar.hcast IScalarTy.I64 i2)
    (by rw [max_integer_val, n2]; omega) (by rw [max_integer_val, n2]; omega))
  obtain ⟨i4, h4, v4⟩ := returned_of_spec (I64.div_spec (x := i3) (y := 10#i64) (by simp) (by
    rw [v3, max_integer_val, n2]; omega))
  refine ⟨i2, i3, i4, h2, h3, h4, by rw [n2]; omega, ?_⟩
  have ten : (10#i64 : I64).val = 10 := by simp
  rw [v4, v3, max_integer_val, n2, ten]
  rw [Int.tdiv_eq_ediv_of_nonneg (by omega)]
  omega

/-- **A digit run, as a cursor step.** When `digits_loop` reports no
    overflow, it consumed a run of digits whose value, appended to `value`,
    is what it returns and at most `2^53 - 1`. -/
theorem digits_loop_sound (b : Slice U8) :
    ∀ n (value : I64) (pos : Usize), b.val.length - pos.val = n → pos.val ≤ b.val.length →
      0 ≤ value.val → value.val ≤ 9007199254740991 →
      digits_loop b value true pos ⦃ r => r.2.2 = true →
        ∃ ds, b.val.drop pos.val = ds ++ b.val.drop r.2.1.val ∧ (∀ x ∈ ds, IsDigit x) ∧
          r.1.val = value.val * 10 ^ ds.length + DecimalValue ds ∧ r.1.val ≤ 9007199254740991 ∧
          (∀ (inside : r.2.1.val < b.val.length), ¬ IsDigit (b.val[r.2.1.val]'inside)) ∧
          r.2.1.val ≤ b.val.length ⦄ := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro value pos measure upto lo hi
    rw [digits_loop.eq_def]
    simp only [↓reduceIte]
    by_cases inside : pos.val < b.val.length
    · have cond : pos < Slice.len b := by scalar_tac
      simp only [cond, ↓reduceIte]
      obtain ⟨x, hx⟩ : ∃ x, b.val[pos.val]'inside = x := ⟨_, rfl⟩
      rw [slice_index_eq b pos inside, hx]
      simp only [bind_ok, digit_eq]
      by_cases dx : IsDigit x
      · simp only [show decide (IsDigit x) = true from decide_eq_true dx, ↓reduceIte]
        obtain ⟨i2, i3, i4, h2, h3, h4, nv, i4v⟩ := digit_step x dx
        rw [h2]
        simp only [bind_ok, lift, h3, h4]
        have dd := dx
        unfold IsDigit at dd
        split
        · rename_i over
          rw [digits_loop.eq_def]
          simp
        · rename_i fits
          have fits' : value.val * 10 + (x.val - 48) ≤ 9007199254740991 := by
            have : ¬ value.val > i4.val := by scalar_tac
            rw [i4v] at this
            omega
          have mn := I64.min_eq; have mx := I64.max_eq
          obtain ⟨i5, h5, v5⟩ := returned_of_spec (I64.mul_spec (x := value) (y := 10#i64) (by simp; omega)
            (by simp; omega))
          obtain ⟨v1, h6, vv1⟩ := returned_of_spec (I64.add_spec (x := i5) (y := UScalar.hcast IScalarTy.I64 i2)
            (by rw [v5, nv]; simp; omega) (by rw [v5, nv]; simp; omega))
          have bound := b.property
          obtain ⟨next, hnext, nval⟩ := usize_succ pos (by omega)
          simp only [h5, h6, hnext, bind_ok]
          have v1v : v1.val = value.val * 10 + (x.val - 48) := by rw [vv1, v5, nv]; simp
          apply WP.spec_mono (ih _ (by omega) v1 next rfl (by omega) (by rw [v1v]; omega) (by rw [v1v]; omega))
          rintro ⟨out, stop, ok⟩ post okTrue
          obtain ⟨ds, split, alld, value', small, ends, within⟩ := post okTrue
          refine ⟨x :: ds, ?_, ?_, ?_, small, ends, within⟩
          · rw [← List.getElem_cons_drop inside, hx, nval] at *
            simp only at split
            rw [List.cons_append, ← split]
          · intro y m
            rcases List.mem_cons.mp m with e | m
            · subst e; exact dx
            · exact alld y m
          · simp only at value' ⊢
            rw [value', v1v, decimal_cons]
            simp only [List.length_cons, pow_succ]
            have hx48 : ((x.val - 48 : Nat) : Int) = (x.val : Int) - 48 := by omega
            push_cast [hx48]
            ring
      · simp only [show decide (IsDigit x) = false from decide_eq_false dx, Bool.false_eq_true, ↓reduceIte,
          WP.spec_ok]
        intro _
        refine ⟨[], by simp, by simp, by simp [DecimalValue], hi, fun _ => by rw [hx]; exact dx, upto⟩
    · have cond : ¬ pos < Slice.len b := by scalar_tac
      simp only [cond, ↓reduceIte, WP.spec_ok]
      intro _
      exact ⟨[], by simp, by simp, by simp [DecimalValue], hi, fun h => absurd h inside, upto⟩

/-- The run ends: the bytes after it are empty or start with a non-digit. -/
def Ends (rest : List U8) : Prop := ∀ h : 0 < rest.length, ¬ IsDigit (rest[0]'h)

theorem digits_loop_complete (b : Slice U8) (rest : List U8) (ends : Ends rest) :
    ∀ (ds : List U8) (value : I64) (pos : Usize), b.val.drop pos.val = ds ++ rest →
      (∀ x ∈ ds, IsDigit x) → 0 ≤ value.val → value.val * 10 ^ ds.length + DecimalValue ds ≤ 9007199254740991 →
      ∃ r, digits_loop b value true pos = Result.ok r ∧ r.2.2 = true ∧ r.2.1.val = pos.val + ds.length ∧
        r.1.val = value.val * 10 ^ ds.length + DecimalValue ds := by
  intro ds
  induction ds with
  | nil =>
    intro value pos eq _ lo _
    refine ⟨(value, pos, true), ?_, rfl, by simp, by simp [DecimalValue]⟩
    rw [digits_loop.eq_def]
    simp only [↓reduceIte]
    split
    · rename_i inside0
      have inside : pos.val < b.val.length := by scalar_tac
      obtain ⟨x, hx⟩ : ∃ x, b.val[pos.val]'inside = x := ⟨_, rfl⟩
      rw [slice_index_eq b pos inside, hx]
      have nd : ¬ IsDigit x := by
        have := congrArg (fun l => l[0]?) eq
        simp only [List.getElem?_drop, Nat.add_zero, List.nil_append] at this
        rw [List.getElem?_eq_getElem inside, hx] at this
        have rl : 0 < rest.length := by cases rest <;> simp_all
        rw [List.getElem?_eq_getElem rl] at this
        simp only [Option.some.injEq] at this
        rw [this]; exact ends rl
      simp [digit_eq, nd]
    · rfl
  | cons x ds ih =>
    intro value pos eq alld lo small
    have dx : IsDigit x := alld x (by simp)
    have inside : pos.val < b.val.length := by
      have := congrArg List.length eq; simp at this; omega
    have hx : b.val[pos.val]'inside = x := by
      have := congrArg (fun l => l[0]?) eq
      simp only [List.getElem?_drop, Nat.add_zero, List.cons_append, List.getElem?_cons_zero] at this
      rw [List.getElem?_eq_getElem inside] at this
      simpa using this
    have dd := dx
    unfold IsDigit at dd
    have one : 1 ≤ 10 ^ ds.length := Nat.one_le_pow _ _ (by omega)
    have v1bound : value.val * 10 + (x.val - 48) ≤ 9007199254740991 := by
      rw [decimal_cons, List.length_cons, pow_succ] at small
      have : (value.val * 10 + (x.val - 48 : Nat)) * 1 ≤ (value.val * 10 + (x.val - 48 : Nat)) * 10 ^ ds.length :=
        Int.mul_le_mul_of_nonneg_left (by exact_mod_cast one) (by omega)
      have hx48 : ((x.val - 48 : Nat) : Int) = (x.val : Int) - 48 := by omega
      push_cast [hx48] at small this
      nlinarith [DecimalValue ds]
    obtain ⟨i2, i3, i4, h2, h3, h4, nv, i4v⟩ := digit_step x dx
    have mn := I64.min_eq; have mx := I64.max_eq
    obtain ⟨i5, h5, v5⟩ := returned_of_spec (I64.mul_spec (x := value) (y := 10#i64) (by simp; omega)
      (by simp; omega))
    obtain ⟨v1, h6, vv1⟩ := returned_of_spec (I64.add_spec (x := i5) (y := UScalar.hcast IScalarTy.I64 i2)
      (by rw [v5, nv]; simp; omega) (by rw [v5, nv]; simp; omega))
    have v1v : v1.val = value.val * 10 + (x.val - 48) := by rw [vv1, v5, nv]; simp
    have bound := b.property
    obtain ⟨next, hnext, nval⟩ := usize_succ pos (by omega)
    have tail : b.val.drop next.val = ds ++ rest := by
      rw [nval, ← List.drop_drop, eq]; rfl
    obtain ⟨r, hr, rok, rpos, rval⟩ := ih v1 next tail (fun y m => alld y (by simp [m])) (by rw [v1v]; omega) (by
      rw [v1v]
      rw [decimal_cons, List.length_cons, pow_succ] at small
      have hx48 : ((x.val - 48 : Nat) : Int) = (x.val : Int) - 48 := by omega
      push_cast [hx48] at small ⊢
      nlinarith)
    refine ⟨r, ?_, rok, by rw [rpos, nval]; simp; omega, ?_⟩
    · rw [digits_loop.eq_def]
      have cond : pos < Slice.len b := by scalar_tac
      simp only [↓reduceIte, cond]
      rw [slice_index_eq b pos inside, hx]
      simp only [bind_ok, digit_eq, show decide (IsDigit x) = true from decide_eq_true dx, ↓reduceIte, h2, lift,
        h3, h4]
      have notOver : ¬ value > i4 := by
        have : ¬ value.val > i4.val := by rw [i4v]; omega
        scalar_tac
      simp only [notOver, ↓reduceIte, h5, h6, hnext, bind_ok, hr]
    · rw [rval, v1v, decimal_cons]
      simp only [List.length_cons, pow_succ]
      have hx48 : ((x.val - 48 : Nat) : Int) = (x.val : Int) - 48 := by omega
      push_cast [hx48]
      ring

theorem digits_zero : Digits 0 = [48#u8] := by
  rw [Digits]; simp only [show ¬ (0 : Nat) ≥ 10 by omega, ↓reduceIte, List.cons.injEq, and_true]
  apply UScalar.eq_of_val_eq; rw [digit_value]; rfl

/-- **A non-negative integer field, as a cursor step**: `natural` accepts
    exactly the canonical decimal form of a value at most `2^53 - 1`. -/
theorem natural_some {b : Slice U8} {pos next : Usize} {v : I64}
    (h : natural b pos = Result.ok (some (v, next))) :
    b.val.drop pos.val = Digits v.val.toNat ++ b.val.drop next.val ∧ 0 ≤ v.val ∧ v.val ≤ 9007199254740991 ∧
      next.val ≤ b.val.length := by
  unfold natural at h
  simp only at h
  split at h
  · simp at h
  · rename_i inside0
    have inside : pos.val < b.val.length := by scalar_tac
    obtain ⟨x, hx⟩ : ∃ x, b.val[pos.val]'inside = x := ⟨_, rfl⟩
    rw [slice_index_eq b pos inside, hx] at h
    simp only [bind_ok, digit_eq] at h
    by_cases dx : IsDigit x
    · simp only [show decide (IsDigit x) = true from decide_eq_true dx, ↓reduceIte] at h
      split at h
      · rename_i zero
        have bound := b.property
        obtain ⟨n1, hn1, n1v⟩ := usize_succ pos (by omega)
        rw [hn1] at h
        simp only [bind_ok, Result.ok.injEq, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨e1, e2⟩ := h
        subst e1 e2
        refine ⟨?_, by simp, by simp, by rw [n1v]; omega⟩
        simp only [show (0#i64 : I64).val.toNat = 0 by simp, digits_zero, n1v]
        rw [← List.getElem_cons_drop inside, hx, zero]
        rfl
      · rename_i nonzero
        obtain ⟨⟨value, stop, ok⟩, hd, h⟩ := bind_ok_inv h
        simp only [Aeneas.Std.uncurry_apply_pair] at h
        split at h
        · rename_i valid
          simp only [Result.ok.injEq, Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨e1, e2⟩ := h
          subst e1 e2
          have sound := digits_loop_sound b _ 0#i64 pos rfl (by omega) (by simp) (by simp)
          simp only [digits] at hd
          rw [hd, WP.spec_ok] at sound
          obtain ⟨ds, split, alld, val, small, ends, within⟩ := sound valid
          simp only at split val small ends
          simp only [show (0#i64 : I64).val = 0 by simp, zero_mul, zero_add] at val
          have nonempty : ds ≠ [] := by
            intro e
            subst e
            simp only [List.nil_append] at split
            have stopPos : stop.val = pos.val := by
              have := congrArg List.length split
              simp only [List.length_drop] at this
              omega
            apply ends (by omega)
            simp only [stopPos, hx]
            exact dx
          have headIs : ds.head nonempty = x := by
            have := congrArg (fun l => l[0]?) split
            simp only [List.getElem?_drop, Nat.add_zero] at this
            rw [List.getElem?_eq_getElem inside, hx, List.getElem?_append_left (by cases ds <;> simp_all),
              List.getElem?_eq_getElem (by cases ds <;> simp_all)] at this
            rw [List.head_eq_getElem]
            simpa using this.symm
          have canon := digits_of_canonical ds nonempty alld (Or.inr (fun hh => by
            rw [show ds.head hh = ds.head nonempty from rfl, headIs]; exact nonzero))
          refine ⟨?_, by rw [val]; omega, small, within⟩
          rw [val]
          simp only [Int.toNat_natCast, canon]
          exact split
        · simp at h
    · simp only [show decide (IsDigit x) = false from decide_eq_false dx, Bool.false_eq_true, ↓reduceIte] at h
      simp at h

theorem natural_of {b : Slice U8} {pos : Usize} {n : Nat} {rest : List U8}
    (eq : b.val.drop pos.val = Digits n ++ rest) (ends : Ends rest) (small : n ≤ 9007199254740991) :
    ∃ v next, natural b pos = Result.ok (some (v, next)) ∧ v.val = n ∧ next.val = pos.val + (Digits n).length := by
  have inside : pos.val < b.val.length := by
    have := congrArg List.length eq; have := digits_ne_nil n
    simp at *; cases h : Digits n <;> simp_all; omega
  obtain ⟨x, hx⟩ : ∃ x, b.val[pos.val]'inside = x := ⟨_, rfl⟩
  have headIs : (Digits n).head (digits_ne_nil n) = x := by
    have := congrArg (fun l => l[0]?) eq
    simp only [List.getElem?_drop, Nat.add_zero] at this
    rw [List.getElem?_eq_getElem inside, hx, List.getElem?_append_left (by have := digits_ne_nil n; cases h : Digits n <;> simp_all),
      List.getElem?_eq_getElem (by have := digits_ne_nil n; cases h : Digits n <;> simp_all)] at this
    rw [List.head_eq_getElem]
    simpa using this.symm
  have dx : IsDigit x := by rw [← headIs]; exact digits_all n _ (List.head_mem _)
  unfold natural
  simp only
  have cond : ¬ pos ≥ Slice.len b := by scalar_tac
  simp only [cond, ↓reduceIte]
  rw [slice_index_eq b pos inside, hx]
  simp only [bind_ok, digit_eq, show decide (IsDigit x) = true from decide_eq_true dx, ↓reduceIte]
  by_cases zero : n = 0
  · subst zero
    have xz : x = 48#u8 := by rw [← headIs]; simp [digits_zero]
    have bound := b.property
    obtain ⟨n1, hn1, n1v⟩ := usize_succ pos (by omega)
    refine ⟨0#i64, n1, by simp [xz, hn1], by simp, by rw [n1v, digits_zero]; rfl⟩
  · have xnz : ¬ x = 48#u8 := by rw [← headIs]; exact digits_head n (by omega) _
    simp only [xnz, ↓reduceIte]
    obtain ⟨r, hr, rok, rpos, rval⟩ := digits_loop_complete b rest ends (Digits n) 0#i64 pos eq (digits_all n)
      (by simp) (by simp [decimal_value_exact]; omega)
    rw [show digits b pos = digits_loop b 0#i64 true pos from rfl, hr]
    obtain ⟨value, stop, ok⟩ := r
    simp only at rok rpos rval
    subst rok
    simp only [bind_ok, Aeneas.Std.uncurry_apply_pair, ↓reduceIte]
    refine ⟨value, stop, rfl, by rw [rval]; simp [decimal_value_exact], rpos⟩

/-! ### The writers -/

/-- A quoted field. -/
def Q (l : List U8) : List U8 := 34#u8 :: (l ++ [34#u8])

@[step] theorem lift_to_slice {k : Usize} (a : Array U8 k) : lift (Array.to_slice a) ⦃ s => s.val = a.val ⦄ := by
  simp [lift, Array.to_slice, WP.spec_ok, Slice.from_val]

@[step] theorem append_spec (out : alloc.vec.Vec U8) (bytes : Slice U8)
    (room : out.val.length + bytes.val.length ≤ Usize.max) :
    append out bytes ⦃ w => w.val = out.val ++ bytes.val ⦄ := by
  unfold append
  apply WP.spec_mono (garrett_stateless_core.http_auth.Proofs.extend_bytes_contract out bytes room)
  exact fun w h => h.1

theorem push_spec' {v : alloc.vec.Vec U8} {x : U8} (room : v.val.length < Usize.max) :
    alloc.vec.Vec.push v x ⦃ w => w.val = v.val ++ [x] ⦄ := alloc.vec.Vec.push_spec v x room

@[step] theorem append_quoted_spec (out : alloc.vec.Vec U8) (bytes : Slice U8)
    (room : out.val.length + bytes.val.length + 2 ≤ Usize.max) :
    append_quoted out bytes ⦃ w => w.val = out.val ++ Q bytes.val ⦄ := by
  unfold append_quoted
  apply WP.spec_bind (push_spec' (x := 34#u8) (by omega))
  intro o1 h1
  apply WP.spec_bind (append_spec o1 bytes (by rw [h1]; simp; omega))
  intro o2 h2
  apply WP.spec_mono (push_spec' (x := 34#u8) (by rw [h2, h1]; simp; omega))
  intro w h3
  rw [h3, h2, h1]
  simp [Q]

theorem digit_byte (n : Nat) (v : I64) (vn : v.val = n) :
    ∃ (r : I64) (i2 : U8), v % 10#i64 = Result.ok r ∧ 48#u8 + IScalar.hcast UScalarTy.U8 r = Result.ok i2 ∧
      i2 = Digit n := by
  have mn := I64.min_eq; have mx := I64.max_eq
  obtain ⟨r, hr, rv⟩ := returned_of_spec (I64.rem_spec v (y := 10#i64) (by simp))
  have rn : r.val = (n % 10 : Nat) := by
    rw [rv, vn]; simp only [show (10#i64 : I64).val = 10 by simp]
    rw [Int.tmod_eq_emod_of_nonneg (by omega : (0 : Int) ≤ n)]; omega
  have cn : (IScalar.hcast UScalarTy.U8 r).val = n % 10 := by
    rw [IScalar.hcast_val_eq, rn]; simp; omega
  have u8max := U8.max_eq
  obtain ⟨a, ha, av⟩ := returned_of_spec (U8.add_spec (x := 48#u8) (y := IScalar.hcast UScalarTy.U8 r) (by
    rw [cn]; simp; omega))
  refine ⟨r, a, hr, ha, ?_⟩
  apply UScalar.eq_of_val_eq; rw [av, cn, digit_value]; simp

@[step] theorem append_natural_spec : ∀ (n : Nat) (out : alloc.vec.Vec U8) (v : I64), v.val = n →
    out.val.length + (Digits n).length ≤ Usize.max →
    append_natural out v ⦃ w => w.val = out.val ++ Digits n ⦄ := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out v vn room
    rw [append_natural.eq_def]
    have mn := I64.min_eq; have mx := I64.max_eq
    obtain ⟨r, d, hr, hd, dv⟩ := digit_byte n v vn
    by_cases big : n ≥ 10
    · have cond : v ≥ 10#i64 := by scalar_tac
      simp only [cond, ↓reduceIte]
      have dsplit : Digits n = Digits (n / 10) ++ [Digit n] := by rw [Digits]; simp [big]
      obtain ⟨q, hq, qv⟩ := returned_of_spec (I64.div_spec (x := v) (y := 10#i64) (by simp) (by
        rw [vn]; simp))
      have qn : q.val = (n / 10 : Nat) := by
        rw [qv, vn]; simp only [show (10#i64 : I64).val = 10 by simp]
        rw [Int.tdiv_eq_ediv_of_nonneg (by omega)]; omega
      rw [hq]
      simp only [bind_ok]
      rw [dsplit] at room
      simp only [List.length_append, List.length_singleton] at room
      apply WP.spec_bind (ih (n / 10) (by omega) out q qn (by omega))
      intro out1 o1
      rw [hr]
      simp only [bind_ok, lift, hd]
      apply WP.spec_mono (push_spec' (x := d) (by rw [o1]; simp; omega))
      intro w hw
      rw [hw, o1, dsplit, dv]; simp
    · have cond : ¬ v ≥ 10#i64 := by scalar_tac
      simp only [cond, ↓reduceIte, bind_ok]
      have dsplit : Digits n = [Digit n] := by rw [Digits]; simp [big]
      rw [hr]
      simp only [bind_ok, lift, hd]
      apply WP.spec_mono (push_spec' (x := d) (by rw [dsplit] at room; simp at room; omega))
      intro w hw
      rw [hw, dsplit, dv]

theorem append_natural_spec' (out : alloc.vec.Vec U8) (v : I64) (lo : 0 ≤ v.val)
    (room : out.val.length + (Digits v.val.toNat).length ≤ Usize.max) :
    append_natural out v ⦃ w => w.val = out.val ++ Digits v.val.toNat ⦄ :=
  append_natural_spec v.val.toNat out v (by omega) room

/-! ### The payload layout -/

/-- A literal's bytes. -/
abbrev lit (s : String) : List U8 := garrett_stateless_core.proxy_http.Proofs.ascii s


/-- The canonical payload of `p`, byte for byte; without `enc` when `withEnc`
    is false. -/
def PayloadList (p : Payload) (withEnc : Bool) : List U8 :=
  lit "{\"aud\":" ++ Q p.claims.audience.val ++ lit ",\"cnf\":{\"x5t#S256\":" ++ Q p.claims.certificate.val ++
    [125#u8] ++ (if withEnc then lit ",\"enc\":" ++ Q p.enc.val else []) ++
    lit ",\"exp\":" ++ Digits p.claims.expires_at.val.toNat ++
    lit ",\"iat\":" ++ Digits p.claims.issued_at.val.toNat ++
    lit ",\"iss\":" ++ Q p.claims.issuer.val ++ lit ",\"jti\":" ++ Q p.claims.token_id.val ++
    lit ",\"prv\":" ++ Q p.claims.provider.val ++ lit ",\"ren\":" ++ Digits p.claims.renew_until.val.toNat ++
    (if p.info.has_scope then lit ",\"scope\":" ++ Q p.info.scope.val else []) ++
    lit ",\"sub\":" ++ Q p.claims.subject.val ++
    (if p.info.has_upstream then lit ",\"upstream\":" ++ p.info.upstream.val else []) ++ [125#u8]

/-! What a writer returned, when it returned. The callers below always have a
successful run in hand, so no buffer-room premise is needed. -/

theorem append_ok {out w : alloc.vec.Vec U8} {bytes : Slice U8} (h : append out bytes = Result.ok w) :
    w.val = out.val ++ bytes.val := by
  unfold append alloc.vec.Vec.extend_from_slice at h
  split at h
  · obtain ⟨cloned, copied, h⟩ := bind_ok_inv h
    obtain ⟨c, hc, same⟩ := returned_of_spec (List.clone_spec (clone := core.clone.CloneU8.clone)
      (l := bytes.val) (by intro x _; rfl))
    rw [hc] at copied
    simp only [Result.ok.injEq] at copied h
    subst copied h
    simp [same]
  · simp at h

theorem push_ok {v w : alloc.vec.Vec U8} {x : U8} (h : alloc.vec.Vec.push v x = Result.ok w) :
    w.val = v.val ++ [x] := garrett_stateless_core.stateless_mailbox.Proofs.push_ok_val h

theorem append_quoted_ok {out w : alloc.vec.Vec U8} {bytes : Slice U8} (h : append_quoted out bytes = Result.ok w) :
    w.val = out.val ++ Q bytes.val := by
  unfold append_quoted at h
  obtain ⟨o1, h1, h⟩ := bind_ok_inv h
  obtain ⟨o2, h2, h⟩ := bind_ok_inv h
  rw [push_ok h, append_ok h2, push_ok h1]
  simp [Q]

theorem append_natural_ok : ∀ (n : Nat) (out : alloc.vec.Vec U8) (v : I64) (w : alloc.vec.Vec U8), v.val = n →
    append_natural out v = Result.ok w → w.val = out.val ++ Digits n := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out v w vn h
    rw [append_natural.eq_def] at h
    obtain ⟨r, d, hr, hd, dv⟩ := digit_byte n v vn
    have mn := I64.min_eq; have mx := I64.max_eq
    obtain ⟨out1, h1, h⟩ := bind_ok_inv h
    rw [hr] at h
    simp only [bind_ok, lift, hd] at h
    rw [push_ok h, dv]
    by_cases big : n ≥ 10
    · have cond : v ≥ 10#i64 := by scalar_tac
      simp only [cond, ↓reduceIte] at h1
      obtain ⟨q, hq, qv⟩ := returned_of_spec (I64.div_spec (x := v) (y := 10#i64) (by simp) (by
        rw [vn]; simp))
      have qn : q.val = (n / 10 : Nat) := by
        rw [qv, vn]; simp only [show (10#i64 : I64).val = 10 by simp]
        rw [Int.tdiv_eq_ediv_of_nonneg (by omega)]; omega
      rw [hq] at h1
      simp only [bind_ok] at h1
      rw [ih (n / 10) (by omega) out q out1 qn h1]
      rw [show Digits n = Digits (n / 10) ++ [Digit n] by rw [Digits]; simp [big]]
      simp
    · have cond : ¬ v ≥ 10#i64 := by scalar_tac
      simp only [cond, ↓reduceIte, Result.ok.injEq] at h1
      subst h1
      rw [show Digits n = [Digit n] by rw [Digits]; simp [big]]

theorem append_natural_ok' {out w : alloc.vec.Vec U8} {v : I64} (lo : 0 ≤ v.val)
    (h : append_natural out v = Result.ok w) : w.val = out.val ++ Digits v.val.toNat :=
  append_natural_ok v.val.toNat out v w (by omega) h

theorem literal_val {k : Usize} {l : List U8} {h : l.length = k.val} {s : Slice U8}
    (e : lift (Array.to_slice (Array.make k l h)) = Result.ok s) : s.val = l := by
  simp only [lift, Result.ok.injEq] at e
  rw [← e]; exact array_slice_val l h

/-- **The payload writer**: what `payload_bytes` returns is exactly
    `PayloadList`. -/
theorem payload_bytes_ok {p : Payload} {withEnc : Bool} {w : alloc.vec.Vec U8}
    (times : 0 ≤ p.claims.expires_at.val ∧ 0 ≤ p.claims.issued_at.val ∧ 0 ≤ p.claims.renew_until.val)
    (h : payload_bytes p withEnc = Result.ok w) : w.val = PayloadList p withEnc := by
  obtain ⟨t1, t2, t3⟩ := times
  unfold payload_bytes at h
  obtain ⟨l0, e0, h⟩ := bind_ok_inv h
  obtain ⟨o0, a0, h⟩ := bind_ok_inv h
  obtain ⟨o1, a1, h⟩ := bind_ok_inv h
  obtain ⟨l2, e2, h⟩ := bind_ok_inv h
  obtain ⟨o2, a2, h⟩ := bind_ok_inv h
  obtain ⟨o3, a3, h⟩ := bind_ok_inv h
  obtain ⟨o4, a4, h⟩ := bind_ok_inv h
  obtain ⟨o5, a5, h⟩ := bind_ok_inv h
  obtain ⟨l4, e4, h⟩ := bind_ok_inv h
  obtain ⟨o6, a6, h⟩ := bind_ok_inv h
  obtain ⟨o7, a7, h⟩ := bind_ok_inv h
  obtain ⟨l5, e5, h⟩ := bind_ok_inv h
  obtain ⟨o8, a8, h⟩ := bind_ok_inv h
  obtain ⟨o9, a9, h⟩ := bind_ok_inv h
  obtain ⟨l6, e6, h⟩ := bind_ok_inv h
  obtain ⟨o10, a10, h⟩ := bind_ok_inv h
  obtain ⟨o11, a11, h⟩ := bind_ok_inv h
  obtain ⟨l7, e7, h⟩ := bind_ok_inv h
  obtain ⟨o12, a12, h⟩ := bind_ok_inv h
  obtain ⟨o13, a13, h⟩ := bind_ok_inv h
  obtain ⟨l8, e8, h⟩ := bind_ok_inv h
  obtain ⟨o14, a14, h⟩ := bind_ok_inv h
  obtain ⟨o15, a15, h⟩ := bind_ok_inv h
  obtain ⟨l9, e9, h⟩ := bind_ok_inv h
  obtain ⟨o16, a16, h⟩ := bind_ok_inv h
  obtain ⟨o17, a17, h⟩ := bind_ok_inv h
  obtain ⟨o18, a18, h⟩ := bind_ok_inv h
  obtain ⟨l13, e13, h⟩ := bind_ok_inv h
  obtain ⟨o19, a19, h⟩ := bind_ok_inv h
  obtain ⟨o20, a20, h⟩ := bind_ok_inv h
  obtain ⟨o21, a21, h⟩ := bind_ok_inv h
  have v0 := append_ok a0
  have v1 := append_quoted_ok a1
  have v2 := append_ok a2
  have v3 := append_quoted_ok a3
  have v4 := push_ok a4
  have v6 := append_ok a6
  have v7 := append_natural_ok' t1 a7
  have v8 := append_ok a8
  have v9 := append_natural_ok' t2 a9
  have v10 := append_ok a10
  have v11 := append_quoted_ok a11
  have v12 := append_ok a12
  have v13 := append_quoted_ok a13
  have v14 := append_ok a14
  have v15 := append_quoted_ok a15
  have v16 := append_ok a16
  have v17 := append_natural_ok' t3 a17
  have v19 := append_ok a19
  have v20 := append_quoted_ok a20
  have vw := push_ok h
  -- the three optional members
  have v5 : o5.val = o4.val ++ (if withEnc then lit ",\"enc\":" ++ Q p.enc.val else []) := by
    split at a5
    · obtain ⟨l, el, a5⟩ := bind_ok_inv a5
      obtain ⟨o, ao, a5⟩ := bind_ok_inv a5
      rw [append_quoted_ok a5, append_ok ao, literal_val el]
      simp [*]; rfl
    · simp only [Result.ok.injEq] at a5; subst a5; simp [*]
  have v18 : o18.val = o17.val ++ (if p.info.has_scope then lit ",\"scope\":" ++ Q p.info.scope.val else []) := by
    split at a18
    · obtain ⟨l, el, a18⟩ := bind_ok_inv a18
      obtain ⟨o, ao, a18⟩ := bind_ok_inv a18
      rw [append_quoted_ok a18, append_ok ao, literal_val el]
      simp [*]; rfl
    · simp only [Result.ok.injEq] at a18; subst a18; simp [*]
  have v21 : o21.val = o20.val ++ (if p.info.has_upstream then lit ",\"upstream\":" ++ p.info.upstream.val else []) := by
    split at a21
    · obtain ⟨l, el, a21⟩ := bind_ok_inv a21
      obtain ⟨o, ao, a21⟩ := bind_ok_inv a21
      rw [append_ok a21, append_ok ao, literal_val el]
      simp [*]; rfl
    · simp only [Result.ok.injEq] at a21; subst a21; simp [*]
  rw [vw, v21, v20, v19, literal_val e13, v18, v17, v16, literal_val e9, v15, v14, literal_val e8, v13, v12,
    literal_val e7, v11, v10, literal_val e6, v9, v8, literal_val e5, v7, v6, literal_val e4, v5, v4, v3, v2,
    literal_val e2, v1, v0, literal_val e0]
  simp [PayloadList, alloc.vec.Vec.deref, alloc.vec.Vec.new]
  try rfl

end garrett_stateless_core.stateless_token.Proofs
