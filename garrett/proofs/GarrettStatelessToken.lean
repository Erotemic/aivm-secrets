import GarrettStatelessGrammar

/-!
# `garrett-stateless-v1`: the exact token payload, opening and sealing

Source: `crates/garrett-stateless-core/src/stateless_token/` (`payload.rs`, `opening.rs`, `sealing.rs`)
(`parse_payload`, `payload_bytes`, `header_kid`, `select`, `verify_token`,
`unseal_token`, `seal_token`), extracted by Aeneas. Builds on the cursor
lemmas of `GarrettStatelessCodec`.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.http_wire.Proofs (Digit Digits DecimalValue digit_value decimal_value_exact)
open garrett_stateless_core.proxy_http.Base64Proofs (enc)
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.stateless_token.Proofs
open garrett_stateless_core.stateless_token.base64 garrett_stateless_core.stateless_token.grammar
  garrett_stateless_core.stateless_token.json garrett_stateless_core.stateless_token.payload
  garrett_stateless_core.stateless_token.keys garrett_stateless_core.stateless_token.opening
  garrett_stateless_core.stateless_token.sealing garrett_stateless_core.stateless_token.login_state

/-! ## Fields as cursor steps -/

/-- A string field: its key, then a quoted plain value. -/
theorem field_some {b key : Slice U8} {pos next : Usize} {v : alloc.vec.Vec U8}
    (room : pos.val + key.length ≤ Usize.max) (h : field b pos key = Result.ok (some (v, next))) :
    b.val.drop pos.val = key.val ++ 34#u8 :: (v.val ++ 34#u8 :: b.val.drop next.val) ∧ Plain v.val := by
  unfold field at h
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  cases o with
  | none => simp at h
  | some i =>
    simp only at h
    obtain ⟨iv, wk⟩ := word_some room ho
    obtain ⟨vk, plain, _⟩ := plain_string_some h
    exact ⟨by rw [wk, vk], plain⟩

theorem field_of {b key : Slice U8} {pos : Usize} {f rest : List U8}
    (room : pos.val + key.length ≤ Usize.max) (inb : pos.val ≤ b.length)
    (eq : b.val.drop pos.val = key.val ++ 34#u8 :: (f ++ 34#u8 :: rest)) (plain : Plain f) :
    ∃ v next, field b pos key = Result.ok (some (v, next)) ∧ v.val = f ∧
      next.val = pos.val + key.length + f.length + 2 := by
  obtain ⟨i, hi, iv⟩ := word_of room inb eq
  have tail : b.val.drop i.val = 34#u8 :: (f ++ 34#u8 :: rest) := by
    obtain ⟨_, same⟩ := word_some room hi
    rw [eq] at same
    simpa using same.symm
  obtain ⟨v, next, hp, vv, nv⟩ := plain_string_of tail plain
  refine ⟨v, next, ?_, vv, by rw [nv, iv]⟩
  unfold field
  rw [hi]
  simp only [bind_ok]
  exact hp

theorem field_absent {b key : Slice U8} {pos : Usize} (room : pos.val + key.length ≤ Usize.max)
    (absent : ¬ ∃ rest, b.val.drop pos.val = key.val ++ rest) : field b pos key = Result.ok none := by
  unfold field
  rw [word_absent room absent]
  simp only [bind_ok]

/-- A number field: its key, then a canonical non-negative integer. -/
theorem number_some {b key : Slice U8} {pos next : Usize} {v : I64}
    (room : pos.val + key.length ≤ Usize.max) (h : number b pos key = Result.ok (some (v, next))) :
    b.val.drop pos.val = key.val ++ (Digits v.val.toNat ++ b.val.drop next.val) ∧ 0 ≤ v.val ∧
      v.val ≤ 9007199254740991 ∧ next.val ≤ b.val.length := by
  unfold number at h
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  cases o with
  | none => simp at h
  | some i =>
    simp only at h
    obtain ⟨iv, wk⟩ := word_some room ho
    obtain ⟨vk, lo, hi, within⟩ := natural_some h
    exact ⟨by rw [wk, vk], lo, hi, within⟩

theorem number_of {b key : Slice U8} {pos : Usize} {n : Nat} {rest : List U8}
    (room : pos.val + key.length ≤ Usize.max) (inb : pos.val ≤ b.length)
    (eq : b.val.drop pos.val = key.val ++ (Digits n ++ rest)) (ends : Ends rest) (small : n ≤ 9007199254740991) :
    ∃ v next, number b pos key = Result.ok (some (v, next)) ∧ v.val = n ∧
      next.val = pos.val + key.length + (Digits n).length := by
  obtain ⟨i, hi, iv⟩ := word_of room inb eq
  have tail : b.val.drop i.val = Digits n ++ rest := by
    obtain ⟨_, same⟩ := word_some room hi
    rw [eq] at same
    simpa using same.symm
  obtain ⟨v, next, hp, vv, nv⟩ := natural_of tail ends small
  refine ⟨v, next, ?_, vv, by rw [nv, iv]⟩
  unfold number
  rw [hi]
  simp only [bind_ok]
  exact hp

/-- A cursor step that consumed a nonempty piece ends inside the bytes. -/
theorem cursor_le {b : List U8} {pos next : Nat} {l : List U8} (ne : l ≠ [])
    (eq : b.drop pos = l ++ b.drop next) (nv : next = pos + l.length) : next ≤ b.length := by
  have len := congrArg List.length eq
  simp only [List.length_drop, List.length_append] at len
  have : 0 < l.length := List.length_pos_of_ne_nil ne
  omega

theorem field_step {b key : Slice U8} {pos next : Usize} {v : alloc.vec.Vec U8}
    (room : pos.val + key.length ≤ Usize.max) (h : field b pos key = Result.ok (some (v, next))) :
    b.val.drop pos.val = (key.val ++ Q v.val) ++ b.val.drop next.val ∧ Plain v.val ∧ next.val ≤ b.val.length := by
  obtain ⟨eq, plain⟩ := field_some room h
  obtain ⟨_, _, nv⟩ : True ∧ True ∧ next.val = pos.val + key.length + v.val.length + 2 := by
    unfold field at h
    obtain ⟨o, ho, h⟩ := bind_ok_inv h
    cases o with
    | none => simp at h
    | some i =>
      simp only at h
      obtain ⟨iv, _⟩ := word_some room ho
      obtain ⟨_, _, n⟩ := plain_string_some h
      exact ⟨trivial, trivial, by rw [n, iv]⟩
  have eq' : b.val.drop pos.val = (key.val ++ Q v.val) ++ b.val.drop next.val := by
    rw [eq]; simp [Q]
  refine ⟨eq', plain, cursor_le (by simp [Q]) eq' (by rw [nv]; simp [Q]; omega)⟩

theorem number_step {b key : Slice U8} {pos next : Usize} {v : I64}
    (room : pos.val + key.length ≤ Usize.max) (h : number b pos key = Result.ok (some (v, next))) :
    b.val.drop pos.val = (key.val ++ Digits v.val.toNat) ++ b.val.drop next.val ∧ 0 ≤ v.val ∧
      v.val ≤ 9007199254740991 ∧ next.val ≤ b.val.length := by
  obtain ⟨eq, lo, hi, within⟩ := number_some room h
  exact ⟨by rw [eq]; simp, lo, hi, within⟩

/-! ## The payload parser is the exact inverse of the payload writer -/

theorem key_len {k : Usize} (a : Array U8 k) : (Array.to_slice a).length = k.val := by
  simp [Array.to_slice, Slice.length]

theorem parse_payload_sound {b : Slice U8} {p : Payload} (room : b.val.length + 64 ≤ Usize.max)
    (h : parse_payload b = Result.ok (some p)) : b.val = PayloadList p true ∧ payload_valid p = Result.ok true := by
  unfold parse_payload at h
  simp only [lift, bind_ok] at h
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨audience, i⟩
  · simp at h
  simp only at h
  obtain ⟨e0, _, l0⟩ := field_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨certificate, i1⟩
  · simp at h
  simp only at h
  obtain ⟨e1, _, l1⟩ := field_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | i2
  · simp at h
  simp only at h
  obtain ⟨_, e2⟩ := word_some (by rw [key_len]; simp; omega) ho
  have l2 : i2.val ≤ b.val.length := cursor_le (by simp) e2 (by rw [(word_some (by rw [key_len]; simp; omega) ho).1])
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨enc, i3⟩
  · simp at h
  simp only at h
  obtain ⟨e3, _, l3⟩ := field_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨expires_at, i4⟩
  · simp at h
  simp only at h
  obtain ⟨e4, _, _, l4⟩ := number_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨issued_at, i5⟩
  · simp at h
  simp only at h
  obtain ⟨e5, _, _, l5⟩ := number_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨issuer, i6⟩
  · simp at h
  simp only at h
  obtain ⟨e6, _, l6⟩ := field_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨token_id, i7⟩
  · simp at h
  simp only at h
  obtain ⟨e7, _, l7⟩ := field_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨provider, i8⟩
  · simp at h
  simp only at h
  obtain ⟨e8, _, l8⟩ := field_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨renew_until, i9⟩
  · simp at h
  simp only at h
  obtain ⟨e9, _, _, l9⟩ := number_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  obtain ⟨⟨has_scope, scope, i10⟩, hs, h⟩ := bind_ok_inv h
  obtain ⟨e10, l10⟩ : List.drop i9.val b.val =
      (if has_scope then [44#u8, 34#u8, 115#u8, 99#u8, 111#u8, 112#u8, 101#u8, 34#u8, 58#u8] ++ Q scope.val
        else []) ++ List.drop i10.val b.val ∧
      i10.val ≤ b.val.length := by
    rcases o with _ | ⟨sc, nx⟩
    · simp only [Result.ok.injEq, Prod.mk.injEq] at hs
      obtain ⟨e1, e2, e3⟩ := hs
      subst e1 e2 e3
      exact ⟨by simp, l9⟩
    · simp only [Aeneas.Std.uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at hs
      obtain ⟨e1, e2, e3⟩ := hs
      subst e1 e2 e3
      obtain ⟨e, _, l⟩ := field_step (by rw [key_len]; simp; omega) ho
      exact ⟨by simpa using e, l⟩
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨subject, i11⟩
  · simp at h
  simp only at h
  obtain ⟨e11, _, l11⟩ := field_step (by rw [key_len]; simp; omega) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  have start : b.val = List.drop (0#usize).val b.val := by simp
  rcases o with _ | up0
  · -- no `upstream`: exactly one `}` remains
    obtain ⟨n, hn, h⟩ := bind_ok_inv h
    obtain ⟨n', hn', nv⟩ := usize_succ i11 (by omega)
    rw [hn'] at hn; simp only [Result.ok.injEq] at hn; subst hn
    split at h
    · simp at h
    rename_i last
    have nlen : n'.val = b.val.length := by simpa using last
    obtain ⟨m, hm, h⟩ := bind_ok_inv h
    obtain ⟨m', hm', mv⟩ := returned_of_spec (Usize.sub_spec (x := b.len) (y := 1#usize)
      (by simp [Slice.len] at nlen ⊢; omega))
    rw [hm'] at hm; simp only [Result.ok.injEq] at hm; subst hm
    have inside : m'.val < b.val.length := by
      simp [Slice.len] at mv ⊢; omega
    obtain ⟨x, hx, h⟩ := bind_ok_inv h
    rw [slice_index_eq b m' inside] at hx; simp only [Result.ok.injEq] at hx; subst hx
    split at h
    · simp at h
    rename_i brace
    obtain ⟨bv, hv, h⟩ := bind_ok_inv h
    cases bv
    · simp at h
    simp only [↓reduceIte, Result.ok.injEq, Option.some.injEq] at h
    subst h
    refine ⟨?_, hv⟩
    have close : List.drop i11.val b.val = [125#u8] := by
      have mi : m'.val = i11.val := by simp [Slice.len] at mv; omega
      have br : b.val[m'.val]'inside = 125#u8 := by apply UScalar.eq_of_val_eq; simpa using brace
      rw [← mi, List.drop_eq_getElem_cons inside, br, List.drop_eq_nil_of_le (by omega)]
    rw [start, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, close]
    cases has_scope <;> simp [PayloadList] <;> rfl
  · -- `upstream`: everything after its key, but the closing `}`
    obtain ⟨_, ew⟩ := word_some (by rw [key_len]; simp; omega) ho
    simp only at h
    split at h
    · simp at h
    rename_i inside0
    have inside : up0.val < b.val.length := by simp [Slice.len] at inside0; omega
    obtain ⟨m, hm, h⟩ := bind_ok_inv h
    obtain ⟨m', hm', mv⟩ := returned_of_spec (Usize.sub_spec (x := b.len) (y := 1#usize)
      (by simp [Slice.len]; omega))
    rw [hm'] at hm; simp only [Result.ok.injEq] at hm; subst hm
    have mval : m'.val = b.val.length - 1 := by simp [Slice.len] at mv; omega
    obtain ⟨found, hf, h⟩ := bind_ok_inv h
    obtain ⟨found', hf', fv⟩ := slice_range_val (b := b) (lo := up0) (hi := m') (by omega) (by
      simp only [Slice.length]; omega)
    rw [hf'] at hf; simp only [Result.ok.injEq] at hf; subst hf
    obtain ⟨up, hu, h⟩ := bind_ok_inv h
    obtain ⟨up', hu', uv⟩ := to_vec_val found'
    rw [hu'] at hu; simp only [Result.ok.injEq] at hu; subst hu
    obtain ⟨m2, hm2, h⟩ := bind_ok_inv h
    rw [hm'] at hm2; simp only [Result.ok.injEq] at hm2; subst hm2
    have last : m'.val < b.val.length := by omega
    obtain ⟨x, hx, h⟩ := bind_ok_inv h
    rw [slice_index_eq b m' last] at hx; simp only [Result.ok.injEq] at hx; subst hx
    split at h
    · simp at h
    rename_i brace
    obtain ⟨bv, hv, h⟩ := bind_ok_inv h
    cases bv
    · simp at h
    simp only [↓reduceIte, Result.ok.injEq, Option.some.injEq] at h
    subst h
    refine ⟨?_, hv⟩
    have br : b.val[m'.val]'last = 125#u8 := by apply UScalar.eq_of_val_eq; simpa using brace
    have rest : List.drop up0.val b.val = up'.val ++ [125#u8] := by
      rw [uv, fv]
      have hd : List.drop (m'.val - up0.val) (List.drop up0.val b.val) = [125#u8] := by
        rw [List.drop_drop, show up0.val + (m'.val - up0.val) = m'.val by omega,
          List.drop_eq_getElem_cons last, br, List.drop_eq_nil_of_le (by omega)]
      conv => lhs; rw [← List.take_append_drop (m'.val - up0.val) (List.drop up0.val b.val)]
      rw [hd]
    rw [start, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, ew, rest]
    cases has_scope <;> simp [PayloadList] <;> rfl

/-! The payload as its sequence of members; `Pos p n` is where member `n` starts. -/

def Segs (p : Payload) : List (List U8) :=
  [[123#u8, 34#u8, 97#u8, 117#u8, 100#u8, 34#u8, 58#u8], Q p.claims.audience.val,
   [44#u8, 34#u8, 99#u8, 110#u8, 102#u8, 34#u8, 58#u8, 123#u8, 34#u8, 120#u8, 53#u8, 116#u8, 35#u8, 83#u8, 50#u8, 53#u8, 54#u8, 34#u8, 58#u8], Q p.claims.certificate.val, [125#u8],
   [44#u8, 34#u8, 101#u8, 110#u8, 99#u8, 34#u8, 58#u8], Q p.enc.val,
   [44#u8, 34#u8, 101#u8, 120#u8, 112#u8, 34#u8, 58#u8], Digits p.claims.expires_at.val.toNat,
   [44#u8, 34#u8, 105#u8, 97#u8, 116#u8, 34#u8, 58#u8], Digits p.claims.issued_at.val.toNat,
   [44#u8, 34#u8, 105#u8, 115#u8, 115#u8, 34#u8, 58#u8], Q p.claims.issuer.val,
   [44#u8, 34#u8, 106#u8, 116#u8, 105#u8, 34#u8, 58#u8], Q p.claims.token_id.val,
   [44#u8, 34#u8, 112#u8, 114#u8, 118#u8, 34#u8, 58#u8], Q p.claims.provider.val,
   [44#u8, 34#u8, 114#u8, 101#u8, 110#u8, 34#u8, 58#u8], Digits p.claims.renew_until.val.toNat,
   (if p.info.has_scope then [44#u8, 34#u8, 115#u8, 99#u8, 111#u8, 112#u8, 101#u8, 34#u8, 58#u8] ++ Q p.info.scope.val else []),
   [44#u8, 34#u8, 115#u8, 117#u8, 98#u8, 34#u8, 58#u8], Q p.claims.subject.val,
   (if p.info.has_upstream then [44#u8, 34#u8, 117#u8, 112#u8, 115#u8, 116#u8, 114#u8, 101#u8, 97#u8, 109#u8, 34#u8, 58#u8] ++ p.info.upstream.val else []),
   [125#u8]]

theorem payload_segs (p : Payload) : PayloadList p true = (Segs p).flatten := by
  cases h1 : p.info.has_scope <;> cases h2 : p.info.has_upstream <;> simp [PayloadList, Segs, h1, h2] <;> rfl

def Pos (p : Payload) (n : Nat) : Nat := ((Segs p).take n).flatten.length

theorem pos_total (p : Payload) (n : Nat) :
    Pos p n + ((Segs p).drop n).flatten.length = (Segs p).flatten.length := by
  unfold Pos
  rw [← List.length_append, ← List.flatten_append, List.take_append_drop]

theorem drop_pos {b : List U8} {p : Payload} (hb : b = (Segs p).flatten) (n : Nat) :
    b.drop (Pos p n) = ((Segs p).drop n).flatten := by
  rw [hb]
  conv => lhs; rw [← List.take_append_drop n (Segs p), List.flatten_append]
  exact List.drop_left

theorem pos_le {b : List U8} {p : Payload} (hb : b = (Segs p).flatten) (n : Nat) : Pos p n ≤ b.length := by
  have := pos_total p n
  rw [hb]; omega

theorem field_seg {b key : Slice U8} {p : Payload} (hb : b.val = (Segs p).flatten) {pos : Usize} {n m : Nat}
    (pv : pos.val = Pos p n) {v : List U8}
    (seg : ((Segs p).drop n).flatten = key.val ++ 34#u8 :: (v ++ 34#u8 :: ((Segs p).drop m).flatten))
    (plain : Plain v) (room : b.val.length + 64 ≤ Usize.max) (klen : key.length ≤ 64) :
    ∃ w next, field b pos key = Result.ok (some (w, next)) ∧ w.val = v ∧ next.val = Pos p m := by
  have t1 := pos_total p n
  have t2 := pos_total p m
  have tl := congrArg List.length hb
  have l := congrArg List.length seg
  simp only [List.length_append, List.length_cons] at l
  have eq : b.val.drop pos.val = key.val ++ 34#u8 :: (v ++ 34#u8 :: b.val.drop (Pos p m)) := by
    rw [pv, drop_pos hb, drop_pos hb, seg]
  obtain ⟨w, next, hf, wv, nv⟩ := field_of (by simp only [Slice.length] at *; omega)
    (by simp only [Slice.length]; rw [hb]; omega) eq plain
  refine ⟨w, next, hf, wv, ?_⟩
  rw [nv]; simp only [Slice.length] at *; omega

theorem number_seg {b key : Slice U8} {p : Payload} (hb : b.val = (Segs p).flatten) {pos : Usize} {n m : Nat}
    (pv : pos.val = Pos p n) {d : Nat}
    (seg : ((Segs p).drop n).flatten = key.val ++ (Digits d ++ ((Segs p).drop m).flatten))
    (ends : Ends ((Segs p).drop m).flatten) (small : d ≤ 9007199254740991)
    (room : b.val.length + 64 ≤ Usize.max) (klen : key.length ≤ 64) :
    ∃ v next, number b pos key = Result.ok (some (v, next)) ∧ v.val = d ∧ next.val = Pos p m := by
  have t1 := pos_total p n
  have t2 := pos_total p m
  have tl := congrArg List.length hb
  have l := congrArg List.length seg
  simp only [List.length_append] at l
  have eq : b.val.drop pos.val = key.val ++ (Digits d ++ b.val.drop (Pos p m)) := by
    rw [pv, drop_pos hb, drop_pos hb, seg]
  obtain ⟨v, next, hf, vv, nv⟩ := number_of (by simp only [Slice.length] at *; omega)
    (by simp only [Slice.length]; rw [hb]; omega) eq (by rw [drop_pos hb]; exact ends) small
  refine ⟨v, next, hf, vv, ?_⟩
  rw [nv]; simp only [Slice.length] at *; omega

theorem word_seg {b key : Slice U8} {p : Payload} (hb : b.val = (Segs p).flatten) {pos : Usize} {n m : Nat}
    (pv : pos.val = Pos p n)
    (seg : ((Segs p).drop n).flatten = key.val ++ ((Segs p).drop m).flatten)
    (room : b.val.length + 64 ≤ Usize.max) :
    ∃ next, word b pos key = Result.ok (some next) ∧ next.val = Pos p m := by
  have t1 := pos_total p n
  have t2 := pos_total p m
  have tl := congrArg List.length hb
  have l := congrArg List.length seg
  simp only [List.length_append] at l
  have eq : b.val.drop pos.val = key.val ++ ((Segs p).drop m).flatten := by rw [pv, drop_pos hb, seg]
  obtain ⟨next, hw, nv⟩ := word_of (by simp only [Slice.length] at *; omega)
    (by simp only [Slice.length]; rw [hb]; omega) eq
  refine ⟨next, hw, ?_⟩
  rw [nv]; simp only [Slice.length] at *; omega

/-- The absent optional members carry no data, as `parse_payload` returns them. -/
def Canonical (p : Payload) : Prop :=
  (p.info.has_scope = false → p.info.scope.val = []) ∧ (p.info.has_upstream = false → p.info.upstream.val = [])

/-- The string members a payload writes between quotes. -/
def PlainFields (p : Payload) : Prop :=
  Plain p.claims.audience.val ∧ Plain p.claims.certificate.val ∧ Plain p.enc.val ∧ Plain p.claims.issuer.val ∧
    Plain p.claims.token_id.val ∧ Plain p.claims.provider.val ∧ Plain p.claims.subject.val ∧
    (p.info.has_scope = true → Plain p.info.scope.val)

def Times (p : Payload) : Prop :=
  0 ≤ p.claims.expires_at.val ∧ p.claims.expires_at.val ≤ 9007199254740991 ∧
    0 ≤ p.claims.issued_at.val ∧ p.claims.issued_at.val ≤ 9007199254740991 ∧
    0 ≤ p.claims.renew_until.val ∧ p.claims.renew_until.val ≤ 9007199254740991

theorem vec_ext {v w : alloc.vec.Vec U8} (h : v.val = w.val) : v = w := alloc.vec.Vec.ext _ _ h

theorem i64_of_toNat {v w : I64} (h : v.val = (w.val.toNat : Int)) (nonneg : 0 ≤ w.val) : v = w :=
  IScalar.eq_of_val_eq (by rw [h]; omega)

/-- **Completeness**: the canonical bytes of a valid payload parse back to that
    very payload. -/
theorem parse_payload_complete {b : Slice U8} {p : Payload} (room : b.val.length + 64 ≤ Usize.max)
    (hb : b.val = PayloadList p true) (canon : Canonical p) (plain : PlainFields p) (times : Times p)
    (valid : payload_valid p = Result.ok true) : parse_payload b = Result.ok (some p) := by
  obtain ⟨⟨iss, aud, sub, jti, prv, cert, iat, exp, ren⟩, enc, ⟨hsc, sc, hup, up⟩⟩ := p
  rw [payload_segs] at hb
  obtain ⟨pa, pc, pe, pi, pj, pp, ps, psc⟩ := plain
  obtain ⟨t1, t2, t3, t4, t5, t6⟩ := times
  obtain ⟨c1, c2⟩ := canon
  dsimp only at pa pc pe pi pj pp ps psc t1 t2 t3 t4 t5 t6 c1 c2
  have ends : ∀ (x : U8) (l : List U8), x.val = 44 → Ends (x :: l) := by
    intro x l hx _
    simp only [List.getElem_cons_zero, IsDigit, hx]
    omega
  unfold parse_payload
  simp only [lift, bind_ok]
  cases hsc
  all_goals
    obtain ⟨w0, i0, h0, v0, n0⟩ := field_seg (key := (Array.make 7#usize [123#u8, 34#u8, 97#u8, 117#u8, 100#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := 0#usize) (n := 0) (m := 2)
      hb (by simp [Pos]) (by simp [Segs, Q]) pa room (by simp [Slice.length])
    rw [h0]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w0 = aud := vec_ext v0
    obtain ⟨w2, i2, h2, v2, n2⟩ := field_seg (key := (Array.make 19#usize [44#u8, 34#u8, 99#u8, 110#u8, 102#u8, 34#u8, 58#u8, 123#u8, 34#u8, 120#u8, 53#u8, 116#u8, 35#u8, 83#u8, 50#u8, 53#u8, 54#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i0) (n := 2) (m := 4)
      hb n0 (by simp [Segs, Q]) pc room (by simp [Slice.length])
    rw [h2]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w2 = cert := vec_ext v2
    obtain ⟨i4, h4, n4⟩ := word_seg (key := (Array.make 1#usize [125#u8] (by simp)).to_slice) (pos := i2) (n := 4) (m := 5) hb n2
      (by simp [Segs]) room
    rw [h4]; simp only [bind_ok]
    obtain ⟨w5, i5, h5, v5, n5⟩ := field_seg (key := (Array.make 7#usize [44#u8, 34#u8, 101#u8, 110#u8, 99#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i4) (n := 5) (m := 7)
      hb n4 (by simp [Segs, Q]) pe room (by simp [Slice.length])
    rw [h5]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w5 = enc := vec_ext v5
    obtain ⟨w7, i7, h7, v7, n7⟩ := number_seg (key := (Array.make 7#usize [44#u8, 34#u8, 101#u8, 120#u8, 112#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i5) (n := 7) (m := 9)
      (d := exp.val.toNat) hb n5 (by simp [Segs]) (ends _ _ (by simp)) (by omega) room
      (by simp [Slice.length])
    rw [h7]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w7 = exp := i64_of_toNat v7 t1
    obtain ⟨w9, i9, h9, v9, n9⟩ := number_seg (key := (Array.make 7#usize [44#u8, 34#u8, 105#u8, 97#u8, 116#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i7) (n := 9) (m := 11)
      (d := iat.val.toNat) hb n7 (by simp [Segs]) (ends _ _ (by simp)) (by omega) room
      (by simp [Slice.length])
    rw [h9]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w9 = iat := i64_of_toNat v9 t3
    obtain ⟨w11, i11, h11, v11, n11⟩ := field_seg (key := (Array.make 7#usize [44#u8, 34#u8, 105#u8, 115#u8, 115#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i9) (n := 11) (m := 13)
      hb n9 (by simp [Segs, Q]) pi room (by simp [Slice.length])
    rw [h11]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w11 = iss := vec_ext v11
    obtain ⟨w13, i13, h13, v13, n13⟩ := field_seg (key := (Array.make 7#usize [44#u8, 34#u8, 106#u8, 116#u8, 105#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i11) (n := 13) (m := 15)
      hb n11 (by simp [Segs, Q]) pj room (by simp [Slice.length])
    rw [h13]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w13 = jti := vec_ext v13
    obtain ⟨w15, i15, h15, v15, n15⟩ := field_seg (key := (Array.make 7#usize [44#u8, 34#u8, 112#u8, 114#u8, 118#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i13) (n := 15) (m := 17)
      hb n13 (by simp [Segs, Q]) pp room (by simp [Slice.length])
    rw [h15]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w15 = prv := vec_ext v15
    obtain ⟨w17, i17, h17, v17, n17⟩ := number_seg (key := (Array.make 7#usize [44#u8, 34#u8, 114#u8, 101#u8, 110#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i15) (n := 17) (m := 19)
      (d := ren.val.toNat) hb n15 (by simp [Segs]) (ends _ _ (by simp)) (by omega) room
      (by simp [Slice.length])
    rw [h17]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w17 = ren := i64_of_toNat v17 t5
  case false =>
    rw [field_absent (key := (Array.make 9#usize [44#u8, 34#u8, 115#u8, 99#u8, 111#u8, 112#u8, 101#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i17)
      (by have := pos_le hb 19; rw [key_len, n17]; simp; omega)
      (by rw [n17, drop_pos hb]; simp [Segs])]
    simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : sc = alloc.vec.Vec.new U8 := vec_ext (by simpa using c1 rfl)
    obtain ⟨w20, i20, h20, v20, n20⟩ := field_seg (key := (Array.make 7#usize [44#u8, 34#u8, 115#u8, 117#u8, 98#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i17) (n := 19) (m := 22)
      hb n17 (by simp [Segs, Q]) ps room (by simp [Slice.length])
    rw [h20]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w20 = sub := vec_ext v20
    cases hup
    · rw [word_absent (lit := (Array.make 12#usize [44#u8, 34#u8, 117#u8, 112#u8, 115#u8, 116#u8, 114#u8, 101#u8, 97#u8, 109#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i20)
        (by have := pos_le hb 22; rw [key_len, n20]; simp; omega)
        (by rw [n20, drop_pos hb]; simp [Segs])]
      simp only [bind_ok]
      obtain rfl : up = alloc.vec.Vec.new U8 := vec_ext (by simpa using c2 rfl)
      have d := drop_pos hb 22
      rw [← n20] at d
      simp [Segs] at d
      have tl := congrArg List.length d
      have le := pos_le hb 22
      rw [← n20] at le
      simp only [List.length_drop, List.length_singleton] at tl
      obtain ⟨n', hn', nv⟩ := usize_succ i20 (by omega)
      rw [hn']; simp only [bind_ok]
      have same : n' = b.len := UScalar.eq_of_val_eq (by simp [Slice.len]; omega)
      simp only [same, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
      obtain ⟨m', hm', mv⟩ := returned_of_spec (Usize.sub_spec (x := b.len) (y := 1#usize)
        (by simp [Slice.len]; omega))
      have inside : m'.val < b.val.length := by simp [Slice.len] at mv; omega
      rw [hm']; simp only [bind_ok]
      rw [slice_index_eq b m' inside]; simp only [bind_ok]
      have last : b.val[m'.val]'inside = 125#u8 := by
        have mi : m'.val = i20.val := by simp [Slice.len] at mv; omega
        have key := congrArg (fun l => l[0]?) d
        simp only [List.getElem?_drop, Nat.add_zero, List.getElem?_cons_zero] at key
        rw [← mi, List.getElem?_eq_getElem inside] at key
        simpa using key
      simp only [last, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, valid, bind_ok]
    · obtain ⟨nx, hx, nxv⟩ := word_of (b := b) (lit := (Array.make 12#usize [44#u8, 34#u8, 117#u8, 112#u8, 115#u8, 116#u8, 114#u8, 101#u8, 97#u8, 109#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i20)
        (by have := pos_le hb 22; rw [key_len, n20]; simp; omega) (by have := pos_le hb 22; simp only [Slice.length]; omega)
        (rest := up.val ++ [125#u8]) (by rw [n20, drop_pos hb]; simp [Segs])
      rw [hx]; simp only [bind_ok]
      have e : b.val.drop i20.val = [44#u8, 34#u8, 117#u8, 112#u8, 115#u8, 116#u8, 114#u8, 101#u8, 97#u8, 109#u8, 34#u8, 58#u8] ++ (up.val ++ [125#u8]) := by
        rw [n20, drop_pos hb]; simp [Segs]
      have rest : b.val.drop nx.val = up.val ++ [125#u8] := by
        rw [nxv, key_len, ← List.drop_drop, e]; simp
      have tl := congrArg List.length rest
      simp only [List.length_drop, List.length_append, List.length_singleton] at tl
      have inside : ¬ nx ≥ b.len := by
        have : nx.val < b.val.length := by
          by_contra hc
          rw [List.drop_eq_nil_of_le (by omega)] at rest
          simp at rest
        intro hc
        have h2 : b.len.val ≤ nx.val := hc
        simp [Slice.len] at h2; omega
      simp only [inside, ↓reduceIte]
      obtain ⟨m', hm', mv⟩ := returned_of_spec (Usize.sub_spec (x := b.len) (y := 1#usize)
        (by simp [Slice.len]; omega))
      have mval : m'.val = b.val.length - 1 := by simp [Slice.len] at mv; omega
      rw [hm']; simp only [bind_ok]
      obtain ⟨found, hf, fv⟩ := slice_range_val (b := b) (lo := nx) (hi := m') (by omega) (by
        simp only [Slice.length]; omega)
      rw [hf]; simp only [bind_ok]
      obtain ⟨up', hu', uv⟩ := to_vec_val found
      rw [hu']; simp only [bind_ok]
      obtain rfl : up' = up := vec_ext (by
        rw [uv, fv, rest, show m'.val - nx.val = up.val.length by omega]; simp)
      have last : m'.val < b.val.length := by omega
      rw [slice_index_eq b m' last]; simp only [bind_ok]
      have br : b.val[m'.val]'last = 125#u8 := by
        have key := congrArg (fun l => l[up'.val.length]?) rest
        simp only [List.getElem?_drop, List.getElem?_append_right (le_refl _), Nat.sub_self,
          List.getElem?_cons_zero] at key
        rw [show nx.val + up'.val.length = m'.val by omega, List.getElem?_eq_getElem last] at key
        simpa using key
      simp only [br, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, valid, bind_ok]
  case true =>
    obtain ⟨w19, i19, h19, v19, n19⟩ := field_seg (key := (Array.make 9#usize [44#u8, 34#u8, 115#u8, 99#u8, 111#u8, 112#u8, 101#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i17) (n := 19) (m := 20)
      hb n17 (by simp [Segs, Q]) (psc rfl) room (by simp [Slice.length])
    rw [h19]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w19 = sc := vec_ext v19
    obtain ⟨w20, i20, h20, v20, n20⟩ := field_seg (key := (Array.make 7#usize [44#u8, 34#u8, 115#u8, 117#u8, 98#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i19) (n := 20) (m := 22)
      hb n19 (by simp [Segs, Q]) ps room (by simp [Slice.length])
    rw [h20]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    obtain rfl : w20 = sub := vec_ext v20
    cases hup
    · rw [word_absent (lit := (Array.make 12#usize [44#u8, 34#u8, 117#u8, 112#u8, 115#u8, 116#u8, 114#u8, 101#u8, 97#u8, 109#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i20)
        (by have := pos_le hb 22; rw [key_len, n20]; simp; omega)
        (by rw [n20, drop_pos hb]; simp [Segs])]
      simp only [bind_ok]
      obtain rfl : up = alloc.vec.Vec.new U8 := vec_ext (by simpa using c2 rfl)
      have d := drop_pos hb 22
      rw [← n20] at d
      simp [Segs] at d
      have tl := congrArg List.length d
      have le := pos_le hb 22
      rw [← n20] at le
      simp only [List.length_drop, List.length_singleton] at tl
      obtain ⟨n', hn', nv⟩ := usize_succ i20 (by omega)
      rw [hn']; simp only [bind_ok]
      have same : n' = b.len := UScalar.eq_of_val_eq (by simp [Slice.len]; omega)
      simp only [same, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
      obtain ⟨m', hm', mv⟩ := returned_of_spec (Usize.sub_spec (x := b.len) (y := 1#usize)
        (by simp [Slice.len]; omega))
      have inside : m'.val < b.val.length := by simp [Slice.len] at mv; omega
      rw [hm']; simp only [bind_ok]
      rw [slice_index_eq b m' inside]; simp only [bind_ok]
      have last : b.val[m'.val]'inside = 125#u8 := by
        have mi : m'.val = i20.val := by simp [Slice.len] at mv; omega
        have key := congrArg (fun l => l[0]?) d
        simp only [List.getElem?_drop, Nat.add_zero, List.getElem?_cons_zero] at key
        rw [← mi, List.getElem?_eq_getElem inside] at key
        simpa using key
      simp only [last, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, valid, bind_ok]
    · obtain ⟨nx, hx, nxv⟩ := word_of (b := b) (lit := (Array.make 12#usize [44#u8, 34#u8, 117#u8, 112#u8, 115#u8, 116#u8, 114#u8, 101#u8, 97#u8, 109#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i20)
        (by have := pos_le hb 22; rw [key_len, n20]; simp; omega) (by have := pos_le hb 22; simp only [Slice.length]; omega)
        (rest := up.val ++ [125#u8]) (by rw [n20, drop_pos hb]; simp [Segs])
      rw [hx]; simp only [bind_ok]
      have e : b.val.drop i20.val = [44#u8, 34#u8, 117#u8, 112#u8, 115#u8, 116#u8, 114#u8, 101#u8, 97#u8, 109#u8, 34#u8, 58#u8] ++ (up.val ++ [125#u8]) := by
        rw [n20, drop_pos hb]; simp [Segs]
      have rest : b.val.drop nx.val = up.val ++ [125#u8] := by
        rw [nxv, key_len, ← List.drop_drop, e]; simp
      have tl := congrArg List.length rest
      simp only [List.length_drop, List.length_append, List.length_singleton] at tl
      have inside : ¬ nx ≥ b.len := by
        have : nx.val < b.val.length := by
          by_contra hc
          rw [List.drop_eq_nil_of_le (by omega)] at rest
          simp at rest
        intro hc
        have h2 : b.len.val ≤ nx.val := hc
        simp [Slice.len] at h2; omega
      simp only [inside, ↓reduceIte]
      obtain ⟨m', hm', mv⟩ := returned_of_spec (Usize.sub_spec (x := b.len) (y := 1#usize)
        (by simp [Slice.len]; omega))
      have mval : m'.val = b.val.length - 1 := by simp [Slice.len] at mv; omega
      rw [hm']; simp only [bind_ok]
      obtain ⟨found, hf, fv⟩ := slice_range_val (b := b) (lo := nx) (hi := m') (by omega) (by
        simp only [Slice.length]; omega)
      rw [hf]; simp only [bind_ok]
      obtain ⟨up', hu', uv⟩ := to_vec_val found
      rw [hu']; simp only [bind_ok]
      obtain rfl : up' = up := vec_ext (by
        rw [uv, fv, rest, show m'.val - nx.val = up.val.length by omega]; simp)
      have last : m'.val < b.val.length := by omega
      rw [slice_index_eq b m' last]; simp only [bind_ok]
      have br : b.val[m'.val]'last = 125#u8 := by
        have key := congrArg (fun l => l[up'.val.length]?) rest
        simp only [List.getElem?_drop, List.getElem?_append_right (le_refl _), Nat.sub_self,
          List.getElem?_cons_zero] at key
        rw [show nx.val + up'.val.length = m'.val by omega, List.getElem?_eq_getElem last] at key
        simpa using key
      simp only [br, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, valid, bind_ok]
/-! ## Opening: what `verify_token` and `unseal_token` return, when they return -/

theorem usize_add_ok {a b c : Usize} (h : a + b = Result.ok c) : c.val = a.val + b.val := by
  have := UScalar.add_equiv a b
  rw [h] at this
  simp at this
  exact this.2.1

theorem usize_sub_ok {a b c : Usize} (h : a - b = Result.ok c) : c.val = a.val - b.val ∧ b.val ≤ a.val := by
  have := UScalar.sub_equiv a b
  rw [h] at this
  simp at this
  omega

theorem range_to_ok {α : Type} {s s1 : Slice α} {e : Usize}
    (h : core.slice.index.Slice.index (core.slice.index.SliceIndexRangeToUsizeSlice α) s { «end» := e } =
      Result.ok s1) : s1.val = s.val.take e.val ∧ e.val ≤ s.length := by
  simp only [Slice.index_SliceIndexRangeToUsizeSliceInst, core.slice.index.SliceIndexRangeToUsizeSlice.index] at h
  split at h
  · simp only [Result.ok.injEq] at h
    subst h
    refine ⟨?_, by assumption⟩
    simp [List.slice]
  · simp at h

theorem range_from_ok {α : Type} {s s1 : Slice α} {b : Usize}
    (h : core.slice.index.Slice.index (core.slice.index.SliceIndexRangeFromUsizeSlice α) s { start := b } =
      Result.ok s1) : s1.val = s.val.drop b.val ∧ b.val ≤ s.length := by
  simp only [Slice.index_SliceIndexRangeFromUsizeSliceInst, core.slice.index.SliceIndexRangeFromUsizeSlice.index] at h
  split at h
  · simp only [Result.ok.injEq] at h
    subst h
    exact ⟨by simp [Slice.drop], by assumption⟩
  · simp at h

theorem range_ok {α : Type} {s s1 : Slice α} {a b : Usize}
    (h : core.slice.index.Slice.index (core.slice.index.SliceIndexRangeUsizeSlice α) s { start := a, «end» := b } =
      Result.ok s1) : s1.val = (s.val.drop a.val).take (b.val - a.val) ∧ a.val ≤ b.val ∧ b.val ≤ s.length := by
  simp only [core.slice.index.Slice.index, core.slice.index.SliceIndexRangeUsizeSlice.index] at h
  split at h
  · simp only [Result.ok.injEq] at h
    subst h
    rename_i c
    refine ⟨?_, by scalar_tac, by scalar_tac⟩
    simp [List.slice]
  · simp at h

/-- The credential's associated-data label, `garrett-stateless-v1/credential` and a zero byte. -/
def CredentialLabel : List U8 := lit "garrett-stateless-v1/credential" ++ [0#u8]

theorem associated_ok {header pub : Slice U8} {w : alloc.vec.Vec U8} (h : associated header pub = Result.ok w) :
    w.val = CredentialLabel ++ header.val ++ [0#u8] ++ pub.val := by
  unfold associated at h
  obtain ⟨a0, h0, h⟩ := bind_ok_inv h
  obtain ⟨a1, h1, h⟩ := bind_ok_inv h
  obtain ⟨a2, h2, h⟩ := bind_ok_inv h
  rw [append_ok h, push_ok h2, append_ok h1, append_ok h0]
  unfold CREDENTIAL_LABEL
  simp [CredentialLabel, alloc.vec.Vec.new]
  rfl

/-- **What an accepted token is.** `verify_token` returns `Ok v` only after
    this exact sequence: the token splits at its two dots; the first segment
    decodes to a header whose `kid` selects entry `v.key`; the third segment
    decodes to a 64-byte signature that this entry's `verify` primitive accepted
    over the token's first two segments, exactly; the second segment decodes to
    payload bytes that `parse_payload` accepts; `v.claims` are that payload's
    claims; `v.sealed` decodes from its `enc`; and `v.aad` is the label, the
    header, a zero and the payload without `enc`. -/
theorem verify_token_ok {M : Type} {inst : KeyMaterial M} {entries : Slice (KeyEntry M)} {t : Slice U8}
    {v : stateless.Verified} (h : verify_token inst entries t = Result.ok (core.result.Result.Ok v)) :
    ∃ (first second : Usize) (hs ss bs ps : Slice U8) (header kid signature bytes : alloc.vec.Vec U8)
      (p : Payload) (pub : alloc.vec.Vec U8) (entry : KeyEntry M),
      segments t = Result.ok (some (first, second)) ∧
      hs.val = t.val.take first.val ∧ from_b64url hs = Result.ok (some header) ∧
      header_kid (alloc.vec.Vec.deref header) = Result.ok (some kid) ∧
      select entries (alloc.vec.Vec.deref kid) = Result.ok v.key ∧
      entries.val[v.key.val]? = some entry ∧
      ss.val = t.val.drop (second.val + 1) ∧ from_b64url ss = Result.ok (some signature) ∧
      signature.val.length = 64 ∧
      bs.val = t.val.take second.val ∧
      inst.verify entry.material bs (alloc.vec.Vec.deref signature) = Result.ok true ∧
      ps.val = (t.val.drop (first.val + 1)).take (second.val - (first.val + 1)) ∧
      from_b64url ps = Result.ok (some bytes) ∧
      parse_payload (alloc.vec.Vec.deref bytes) = Result.ok (some p) ∧
      from_b64url (alloc.vec.Vec.deref p.enc) = Result.ok (some v.sealed) ∧ 29 ≤ v.sealed.val.length ∧
      payload_bytes p false = Result.ok pub ∧
      v.claims = p.claims ∧ v.aad.val = CredentialLabel ++ header.val ++ [0#u8] ++ pub.val ∧
      v.key_issuer.val = entry.issuer.val := by
  unfold verify_token at h
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨first, second⟩
  · simp at h
  simp only [Aeneas.Std.uncurry_apply_pair] at h
  obtain ⟨hs, hhs, h⟩ := bind_ok_inv h
  obtain ⟨hsv, _⟩ := range_to_ok hhs
  obtain ⟨o, hh, h⟩ := bind_ok_inv h
  rcases o with _ | header
  · simp at h
  simp only at h
  obtain ⟨o, hk, h⟩ := bind_ok_inv h
  rcases o with _ | kid
  · simp at h
  simp only at h
  obtain ⟨key, hsel, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  rename_i inside
  have inside' : key.val < entries.length := by simp only [Slice.len] at inside; scalar_tac
  obtain ⟨entry, he, h⟩ := bind_ok_inv h
  rw [slice_index_eq entries key inside'] at he
  simp only [Result.ok.injEq] at he
  subst he
  obtain ⟨i1, hi1, h⟩ := bind_ok_inv h
  obtain ⟨ss, hss, h⟩ := bind_ok_inv h
  obtain ⟨ssv, _⟩ := range_from_ok hss
  obtain ⟨o, hsig, h⟩ := bind_ok_inv h
  rcases o with _ | signature
  · simp at h
  simp only at h
  split at h
  · simp at h
  rename_i siglen
  obtain ⟨body, hbody, h⟩ := bind_ok_inv h
  obtain ⟨bodyv, _⟩ := range_to_ok hbody
  obtain ⟨ok1, hver, h⟩ := bind_ok_inv h
  cases ok1
  · simp at h
  simp only [↓reduceIte] at h
  obtain ⟨i3, hi3, h⟩ := bind_ok_inv h
  obtain ⟨ps, hps, h⟩ := bind_ok_inv h
  obtain ⟨psv, _⟩ := range_ok hps
  obtain ⟨o, hpb, h⟩ := bind_ok_inv h
  rcases o with _ | bytes
  · simp at h
  simp only at h
  obtain ⟨o, hpp, h⟩ := bind_ok_inv h
  rcases o with _ | p
  · simp at h
  simp only at h
  obtain ⟨o, hse, h⟩ := bind_ok_inv h
  rcases o with _ | sealed
  · simp at h
  simp only at h
  obtain ⟨i5, hi5, h⟩ := bind_ok_inv h
  obtain ⟨i6, hi6, h⟩ := bind_ok_inv h
  have v5 := usize_add_ok hi5
  have v6 := usize_add_ok hi6
  split at h
  · simp at h
  rename_i long
  obtain ⟨pub, hpub, h⟩ := bind_ok_inv h
  obtain ⟨aad, haad, h⟩ := bind_ok_inv h
  obtain ⟨iss, hiss, h⟩ := bind_ok_inv h
  obtain ⟨iss', hiss', issv⟩ := to_vec_val (alloc.vec.Vec.deref (entries.val[key.val]).issuer)
  rw [hiss'] at hiss; simp only [Result.ok.injEq] at hiss; subst hiss
  simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
  subst h
  have av := associated_ok haad
  refine ⟨first, second, hs, ss, body, ps, header, kid, signature, bytes, p, pub, entries.val[key.val], ho, hsv,
    hh, hk, hsel, by simp, ?_, hsig, ?_, bodyv, hver, ?_, hpb, hpp, hse, ?_, hpub, rfl, ?_, ?_⟩
  · rw [ssv, usize_add_ok hi1]; rfl
  · have e : signature.val.length = SIGNATURE.val := by simpa using siglen
    unfold SIGNATURE at e
    simpa using e
  · rw [psv, usize_add_ok hi3]; simp
  · unfold NONCE TAG at v5
    simp [alloc.vec.Vec.len] at long v5 ⊢
    scalar_tac
  · simpa using av
  · simpa using issv

/-- **Opening uses the verifying key.** `unseal_token` returns a plaintext only
    as the answer of the `open` primitive of entry `v.key` — the entry the
    token's `kid` selected in `verify_token` — on the nonce and ciphertext of
    `v.sealed` under exactly `v.aad`. -/
theorem unseal_token_ok {M : Type} {inst : KeyMaterial M} {entries : Slice (KeyEntry M)}
    {v : stateless.Verified} {plain : alloc.vec.Vec U8}
    (h : unseal_token inst entries v = Result.ok (core.result.Result.Ok plain)) :
    ∃ (entry : KeyEntry M) (nonce sealed : Slice U8),
      entries.val[v.key.val]? = some entry ∧
      nonce.val = v.sealed.val.take 12 ∧ sealed.val = v.sealed.val.drop 12 ∧
      inst.open entry.material nonce (alloc.vec.Vec.deref v.aad) sealed = Result.ok (some plain) := by
  unfold unseal_token at h
  simp only at h
  split at h
  · simp at h
  rename_i inside
  have inside' : v.key.val < entries.length := by simp only [Slice.len] at inside; scalar_tac
  obtain ⟨i2, h2, h⟩ := bind_ok_inv h
  obtain ⟨i3, h3, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  obtain ⟨nonce, hn, h⟩ := bind_ok_inv h
  obtain ⟨sealed, hs, h⟩ := bind_ok_inv h
  obtain ⟨nv, _⟩ := range_to_ok (s := v.sealed.slice) hn
  obtain ⟨sv, _⟩ := range_from_ok (s := v.sealed.slice) hs
  obtain ⟨ke, hke, h⟩ := bind_ok_inv h
  rw [slice_index_eq entries v.key inside'] at hke
  simp only [Result.ok.injEq] at hke
  subst hke
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | pl
  · simp at h
  simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
  subst h
  refine ⟨_, nonce, sealed, by simp, ?_, ?_, ho⟩
  · rw [nv]; unfold NONCE; simp [alloc.vec.Vec.val]
  · rw [sv]; unfold NONCE; simp [alloc.vec.Vec.val]

/-- `text` is the unpadded url-alphabet encoding of `bytes`. -/
def B64 (text bytes : List U8) : Prop := text.map (·.val) = enc bytes true

/-- **Token soundness.** Under a valid key set, a token `verify_token` accepts
    is exactly three url-b64 segments: the canonical header of a `kid` that
    names exactly one entry, the canonical bytes of a valid payload, and a
    64-byte signature that this entry's `verify` primitive accepted over the
    first two segments as they appear. The claims authorization receives are
    that payload's claims; the associated data binds the header and every
    public member; the sealed credential is what `enc` encodes. -/
theorem verify_token_sound {M : Type} {inst : KeyMaterial M} {entries : Slice (KeyEntry M)} {t : Slice U8}
    {v : stateless.Verified} (keys : KeysValid entries.val)
    (h : verify_token inst entries t = Result.ok (core.result.Result.Ok v)) :
    ∃ (a b c kid sig : List U8) (p : Payload) (entry : KeyEntry M),
      t.val = a ++ 46#u8 :: (b ++ 46#u8 :: c) ∧ t.val.length ≤ 16384 ∧
      B64 a (HS ++ kid ++ HE) ∧ Kid kid ∧
      B64 b (PayloadList p true) ∧ PayloadValid p ∧
      B64 c sig ∧ sig.length = 64 ∧
      entries.val[v.key.val]? = some entry ∧ entry.kid.val = kid ∧
      (∀ j (hj : j < entries.val.length), (entries.val[j]'hj).kid.val = kid → j = v.key.val) ∧
      (∃ body sigs : Slice U8, body.val = a ++ 46#u8 :: b ∧ sigs.val = sig ∧
        inst.verify entry.material body sigs = Result.ok true) ∧
      v.claims = p.claims ∧
      v.aad.val = CredentialLabel ++ (HS ++ kid ++ HE) ++ [0#u8] ++ PayloadList p false ∧
      B64 p.enc.val v.sealed.val ∧ 29 ≤ v.sealed.val.length ∧
      v.key_issuer.val = entry.issuer.val := by
  obtain ⟨first, second, hs, ss, bs, ps, header, kid, signature, bytes, p, pub, entry, hseg, hsv, hh, hk, hsel,
    hentry, ssv, hsig, siglen, bsv, hver, psv, hpb, hpp, hse, slen, hpub, hclaims, haad, hiss⟩ := verify_token_ok h
  obtain ⟨o, ho, sound, _⟩ := segments_spec t
  rw [hseg] at ho; simp only [Result.ok.injEq] at ho; subst ho
  obtain ⟨tlen, _, a, b, c, ⟨tv, _, _, _⟩, fv, sv⟩ := sound first second rfl
  have fits : ∀ n, n ≤ t.val.length → 8 * n + 5 ≤ Usize.max := by
    intro n hn; have := usize_big; omega
  -- the three segments
  have ha : hs.val = a := by rw [hsv, fv, tv]; simp
  have hb : ps.val = b := by
    rw [psv, fv, sv, tv]; simp [List.drop_append]
  have hc : ss.val = c := by
    rw [ssv, sv, tv, show a ++ 46#u8 :: (b ++ 46#u8 :: c) = (a ++ 46#u8 :: b ++ [46#u8]) ++ c by simp]
    exact List.drop_left' (by simp; omega)
  have hbody : bs.val = a ++ 46#u8 :: b := by
    rw [bsv, sv, tv, show a ++ 46#u8 :: (b ++ 46#u8 :: c) = (a ++ 46#u8 :: b) ++ 46#u8 :: c by simp]
    exact List.take_left' (by simp; omega)
  have tl : t.val.length = a.length + b.length + c.length + 2 := by rw [tv]; simp; omega
  -- header
  obtain ⟨ea, la⟩ := from_b64url_sound (fits _ (by simp only [Slice.length, ha]; omega)) hh
  obtain ⟨ok, hk', kidSome, _⟩ := header_kid_spec (alloc.vec.Vec.deref header)
  rw [hk] at hk'; simp only [Result.ok.injEq] at hk'; subst hk'
  obtain ⟨hv, kidOk⟩ := kidSome kid rfl
  rw [deref_val] at hv
  -- key selection
  obtain ⟨r, hr, cases⟩ := select_unique entries (alloc.vec.Vec.deref kid) keys
  rw [hsel] at hr; simp only [Result.ok.injEq] at hr; subst hr
  have inside : v.key.val < entries.val.length := by
    rcases List.getElem?_eq_some_iff.mp hentry with ⟨i, _⟩; exact i
  have entryEq : entries.val[v.key.val]'inside = entry := by
    rcases List.getElem?_eq_some_iff.mp hentry with ⟨_, e⟩; exact e
  rcases cases with ⟨_, named, unique⟩ | ⟨atEnd, _⟩
  swap
  · omega
  -- signature
  obtain ⟨ec, _⟩ := from_b64url_sound (fits _ (by simp only [Slice.length, hc]; omega)) hsig
  -- payload
  obtain ⟨eb, lb⟩ := from_b64url_sound (fits _ (by simp only [Slice.length, hb]; omega)) hpb
  obtain ⟨pv, valid⟩ := parse_payload_sound (by
    rw [deref_val]; have := usize_big; simp only [Slice.length, hb] at lb; omega) hpp
  rw [deref_val] at pv
  have pvalid := (payload_valid_true p).mp valid
  have times := pvalid
  obtain ⟨_, _, _, _, _, _, t1, _, t2, _, t3, _⟩ := times
  -- sealed credential
  have encLen : p.enc.val.length ≤ bytes.val.length := by
    have := congrArg List.length pv
    simp [PayloadList, Q] at this
    omega
  obtain ⟨ee, _⟩ := from_b64url_sound (fits _ (by
    simp only [Slice.length, deref_val]; simp only [Slice.length, hb] at lb; omega)) hse
  have pubv := payload_bytes_ok ⟨t2, t1, t3⟩ hpub
  refine ⟨a, b, c, kid.val, signature.val, p, entry, tv, tlen, ?_, kidOk, ?_, pvalid, ?_, siglen, hentry, ?_,
    ?_, ⟨bs, alloc.vec.Vec.deref signature, hbody, deref_val _, hver⟩, hclaims, ?_, ?_, slen, hiss⟩
  · rw [← ha, ← hv]; exact ea
  · rw [← hb, ← pv]; exact eb
  · rw [← hc]; exact ec
  · rw [← entryEq, named, deref_val]
  · intro j hj e
    exact unique j hj (by rw [e, deref_val])
  · rw [haad, hv, pubv]
  · simpa [deref_val, B64] using ee

/-! ## Sealing: what `seal_token` returns, when it returns -/

/-- A successful `b64url` already computed `8 n + 5` without overflow. -/
theorem b64url_fits {x : Slice U8} {w : alloc.vec.Vec U8} (h : b64url x = Result.ok w) :
    8 * x.val.length + 5 ≤ Usize.max := by
  unfold b64url proxy_http.response.encode_unpadded at h
  obtain ⟨i1, h1, h⟩ := bind_ok_inv h
  obtain ⟨i2, h2, _⟩ := bind_ok_inv h
  have m := UScalar.mul_equiv 8#usize (Slice.len x)
  have e1 : (8#usize * Slice.len x) = UScalar.mul 8#usize (Slice.len x) := rfl
  rw [← e1, h1] at m
  simp at m
  have v2 := usize_add_ok h2
  have := i2.hBounds
  simp [Slice.len] at m
  scalar_tac

theorem b64url_ok' {x : Slice U8} {w : alloc.vec.Vec U8} (h : b64url x = Result.ok w) :
    B64 w.val x.val ∧ Plain w.val ∧ (∀ y ∈ w.val, y.val ≠ 46 ∧ y.val ≤ 127) := by
  obtain ⟨e, pl, safe⟩ := b64url_ok (b64url_fits h) h
  exact ⟨e, pl, safe⟩

theorem copy_claims_eq (c : stateless.SurrogateClaims) : copy_claims c = Result.ok c := by
  unfold copy_claims
  simp only [to_vec_eq, bind_ok, vec_deref_mk]

theorem copy_info_eq (i : Informational) : copy_info i = Result.ok i := by
  unfold copy_info
  simp only [to_vec_eq, bind_ok, vec_deref_mk]

/-- The payload without `enc` does not depend on `enc`. -/
theorem payload_list_public (c : stateless.SurrogateClaims) (i : Informational) (e e' : alloc.vec.Vec U8) :
    PayloadList { claims := c, enc := e, info := i } false = PayloadList { claims := c, enc := e', info := i } false := by
  simp [PayloadList]

theorem payload_list_le (p : Payload) : (PayloadList p false).length ≤ (PayloadList p true).length := by
  unfold PayloadList
  simp only [List.length_append, Bool.false_eq_true, ↓reduceIte, List.length_nil]
  omega

theorem occurs_false {hay n : Slice U8} (room : hay.val.length < Usize.max) (h : occurs hay n = Result.ok false) :
    ¬ n.val <:+: hay.val := by
  obtain ⟨b, hb, iff⟩ := occurs_spec hay n room
  rw [h] at hb; simp only [Result.ok.injEq] at hb; subst hb
  simpa using iff

/-- **What a sealed token is.** `seal_token` returns `Ok token` only after the
    credential passed `valid_credential`, the `kid` and every member passed
    their grammars, and the credential occurs in neither the header nor the
    public payload; the AEAD `seal` primitive of this entry was called on the
    credential under exactly the label, the header, a zero and the public
    payload; the `sign` primitive was called on exactly the first two segments;
    and the token is those segments and the signature's encoding. -/
theorem seal_token_ok {M : Type} {inst : KeyMaterial M} {entry : KeyEntry M} {info : Informational}
    {claims : stateless.SurrogateClaims} {cred nonce : Slice U8} {token : alloc.vec.Vec U8}
    (h : seal_token inst entry info claims cred nonce = Result.ok (core.result.Result.Ok token)) :
    ∃ (aad body : Slice U8) (ciphertext signature : alloc.vec.Vec U8) (p : Payload) (H P S : List U8),
      http_auth.valid_credential cred = Result.ok true ∧ Kid entry.kid.val ∧ nonce.val.length = 12 ∧
      p.claims = claims ∧ p.info = info ∧ PayloadValid { p with enc := alloc.vec.Vec.new U8 } ∧
      ¬ cred.val <:+: (HS ++ entry.kid.val ++ HE) ∧ ¬ cred.val <:+: PayloadList p false ∧
      aad.val = CredentialLabel ++ (HS ++ entry.kid.val ++ HE) ++ [0#u8] ++ PayloadList p false ∧
      inst.seal entry.material nonce aad cred = Result.ok (some ciphertext) ∧
      B64 p.enc.val (nonce.val ++ ciphertext.val) ∧
      B64 H (HS ++ entry.kid.val ++ HE) ∧ B64 P (PayloadList p true) ∧
      body.val = H ++ 46#u8 :: P ∧
      inst.sign entry.material body = Result.ok (some signature) ∧ signature.val.length = 64 ∧
      B64 S signature.val ∧ token.val = H ++ 46#u8 :: (P ++ 46#u8 :: S) ∧ token.val.length ≤ 16384 := by
  unfold seal_token at h
  obtain ⟨vc, hvc, h⟩ := bind_ok_inv h
  cases vc
  · simp at h
  simp only [↓reduceIte] at h
  obtain ⟨vk, hvk, h⟩ := bind_ok_inv h
  cases vk
  · simp at h
  simp only [↓reduceIte] at h
  split at h
  · simp at h
  rename_i nlen
  obtain ⟨header, hh, h⟩ := bind_ok_inv h
  obtain ⟨sc, hsc, h⟩ := bind_ok_inv h
  rw [copy_claims_eq] at hsc; simp only [Result.ok.injEq] at hsc; subst hsc
  obtain ⟨i1, hi1, h⟩ := bind_ok_inv h
  rw [copy_info_eq] at hi1; simp only [Result.ok.injEq] at hi1; subst hi1
  obtain ⟨b2, hb2, h⟩ := bind_ok_inv h
  cases b2
  · simp at h
  simp only [↓reduceIte] at h
  obtain ⟨pub, hpub, h⟩ := bind_ok_inv h
  obtain ⟨b3, hb3, h⟩ := bind_ok_inv h
  cases b3
  swap
  · simp at h
  simp only [Bool.false_eq_true, ↓reduceIte] at h
  obtain ⟨b4, hb4, h⟩ := bind_ok_inv h
  cases b4
  swap
  · simp at h
  simp only [Bool.false_eq_true, ↓reduceIte] at h
  obtain ⟨aad, haad, h⟩ := bind_ok_inv h
  obtain ⟨o, hseal, h⟩ := bind_ok_inv h
  rcases o with _ | ciphertext
  · simp at h
  simp only at h
  obtain ⟨sealed, hs0, h⟩ := bind_ok_inv h
  obtain ⟨sealed1, hs1, h⟩ := bind_ok_inv h
  obtain ⟨v, hv, h⟩ := bind_ok_inv h
  obtain ⟨body, hbody, h⟩ := bind_ok_inv h
  obtain ⟨body1, hbody1, h⟩ := bind_ok_inv h
  obtain ⟨v1, hv1, h⟩ := bind_ok_inv h
  obtain ⟨v2, hv2, h⟩ := bind_ok_inv h
  obtain ⟨body2, hbody2, h⟩ := bind_ok_inv h
  obtain ⟨o, hsign, h⟩ := bind_ok_inv h
  rcases o with _ | signature
  · simp at h
  simp only at h
  split at h
  · simp at h
  rename_i slen
  obtain ⟨body3, hbody3, h⟩ := bind_ok_inv h
  obtain ⟨v3, hv3, h⟩ := bind_ok_inv h
  obtain ⟨body4, hbody4, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  rename_i tlen
  simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
  subst h
  rw [is_kid_eq, deref_val] at hvk
  simp only [Result.ok.injEq, decide_eq_true_eq] at hvk
  have nl : nonce.val.length = 12 := by
    have : nonce.val.length = NONCE.val := by simpa using nlen
    unfold NONCE at this
    simpa using this
  have hv' := header_bytes_ok hh
  rw [deref_val] at hv'
  have pvalid := (payload_valid_true _).mp hb2
  have times := pvalid
  obtain ⟨_, _, _, _, _, _, t1, _, t2, _, t3, _⟩ := times
  have pubv := payload_bytes_ok ⟨t2, t1, t3⟩ hpub
  have v1v := payload_bytes_ok (p := { claims := claims, enc := v, info := info }) ⟨t2, t1, t3⟩ hv1
  obtain ⟨e2, _, _⟩ := b64url_ok' hv2
  have fit2 := b64url_fits hv2
  have pubLen : pub.val.length < Usize.max := by
    have := payload_list_le { claims := claims, enc := v, info := info }
    rw [deref_val] at fit2
    rw [pubv, payload_list_public claims info _ v]
    rw [v1v] at fit2
    omega
  have notHeader := occurs_false (by
    rw [deref_val, hv', List.length_append, List.length_append, hs_len, he_len]
    have := usize_big; have := hvk.2.1; omega) hb3
  have notPublic := occurs_false (by rw [deref_val]; exact pubLen) hb4
  rw [deref_val, hv'] at notHeader
  rw [deref_val, pubv] at notPublic
  have aadv := associated_ok haad
  rw [deref_val, deref_val, hv', pubv] at aadv
  have s1v : sealed1.val = nonce.val ++ ciphertext.val := by
    rw [append_ok hs1, append_ok hs0, deref_val]; simp
  obtain ⟨ev, _, _⟩ := b64url_ok' hv
  obtain ⟨eb, _, _⟩ := b64url_ok' hbody
  obtain ⟨e3, _, _⟩ := b64url_ok' hv3
  have b1v := push_ok hbody1
  have b2v := append_ok hbody2
  have b3v := push_ok hbody3
  have b4v := append_ok hbody4
  refine ⟨alloc.vec.Vec.deref aad, alloc.vec.Vec.deref body2, ciphertext, signature,
    { claims := claims, enc := v, info := info }, body.val, v2.val, v3.val, hvc, hvk, nl, rfl, rfl, pvalid,
    notHeader, ?_, ?_, hseal, ?_, ?_, ?_, ?_, hsign, ?_, ?_, ?_, ?_⟩
  · rw [payload_list_public claims info v (alloc.vec.Vec.new U8)]; exact notPublic
  · rw [deref_val, aadv, payload_list_public claims info v (alloc.vec.Vec.new U8)]
  · rw [deref_val] at ev; rw [← s1v]; exact ev
  · rw [deref_val, hv'] at eb; exact eb
  · rw [deref_val, v1v] at e2; exact e2
  · rw [deref_val, b2v, b1v, deref_val]; simp
  · have e : signature.val.length = SIGNATURE.val := by simpa using slen
    unfold SIGNATURE at e
    simpa using e
  · rw [deref_val] at e3; exact e3
  · rw [b4v, b3v, b2v, b1v, deref_val, deref_val]; simp
  · have : ¬ body4.val.length > 16384 := by
      have := congrArg UScalar.val (show MAX_TOKEN = MAX_TOKEN from rfl)
      unfold MAX_TOKEN at tlen
      simpa [alloc.vec.Vec.len] using tlen
    omega

theorem b64_length {l x : List U8} (h : B64 l x) : x.length ≤ l.length := by
  have := congrArg List.length h
  rw [List.length_map, enc_length] at this
  omega

end garrett_stateless_core.stateless_token.Proofs
