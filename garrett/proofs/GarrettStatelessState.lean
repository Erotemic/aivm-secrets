import GarrettStatelessToken

/-!
# `garrett-stateless-v1`: the sealed login state

Source: `crates/garrett-stateless-core/src/stateless_token.rs`
(`state_bytes`, `parse_state`, `seal_state`, `open_state`), extracted by
Aeneas. The state key's `seal`/`open` are the external AES-256-GCM
primitive: arbitrary results here, and one stated inverse premise for the
positive round trip.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.http_wire.Proofs (Digit Digits DecimalValue digit_value decimal_value_exact)
open garrett_stateless_core.proxy_http.Base64Proofs (enc)
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.stateless_token.Proofs

/-! ## The canonical plaintext -/

/-- The login state as its sequence of members; `StatePos s n` is where member
    `n` starts. -/
def StateSegs (s : stateless_login.LoginState) : List (List U8) :=
  [[123#u8, 34#u8, 99#u8, 101#u8, 114#u8, 116#u8, 95#u8, 101#u8, 120#u8, 112#u8, 34#u8, 58#u8], Digits s.certificate_expires.val.toNat,
   [44#u8, 34#u8, 99#u8, 110#u8, 102#u8, 34#u8, 58#u8], Q s.certificate.val,
   [44#u8, 34#u8, 101#u8, 120#u8, 112#u8, 34#u8, 58#u8], Digits s.expires_at.val.toNat,
   [44#u8, 34#u8, 105#u8, 97#u8, 116#u8, 34#u8, 58#u8], Digits s.issued_at.val.toNat,
   [44#u8, 34#u8, 108#u8, 111#u8, 103#u8, 105#u8, 110#u8, 34#u8, 58#u8], Q s.login.val,
   [44#u8, 34#u8, 112#u8, 114#u8, 118#u8, 34#u8, 58#u8], Q s.provider.val,
   [44#u8, 34#u8, 114#u8, 101#u8, 112#u8, 34#u8, 58#u8], Q s.replica.val,
   [44#u8, 34#u8, 115#u8, 99#u8, 111#u8, 112#u8, 101#u8, 34#u8, 58#u8], Q s.scope.val,
   [44#u8, 34#u8, 115#u8, 117#u8, 98#u8, 34#u8, 58#u8], Q s.subject.val,
   [44#u8, 34#u8, 118#u8, 101#u8, 114#u8, 105#u8, 102#u8, 105#u8, 101#u8, 114#u8, 34#u8, 58#u8], Q s.verifier.val,
   [125#u8]]

/-- The exact canonical plaintext of a login state. -/
def StateList (s : stateless_login.LoginState) : List U8 := (StateSegs s).flatten

/-- **The state writer**: what `state_bytes` returns is exactly `StateList`. -/
theorem state_bytes_ok {s : stateless_login.LoginState} {w : alloc.vec.Vec U8}
    (times : 0 ≤ s.certificate_expires.val ∧ 0 ≤ s.expires_at.val ∧ 0 ≤ s.issued_at.val)
    (h : state_bytes s = Result.ok w) : w.val = StateList s := by
  obtain ⟨t1, t2, t3⟩ := times
  unfold state_bytes at h
  simp only [lift, bind_ok] at h

  obtain ⟨o0, a0, h⟩ := bind_ok_inv h
  obtain ⟨o1, a1, h⟩ := bind_ok_inv h
  obtain ⟨o2, a2, h⟩ := bind_ok_inv h
  obtain ⟨o3, a3, h⟩ := bind_ok_inv h
  obtain ⟨o4, a4, h⟩ := bind_ok_inv h
  obtain ⟨o5, a5, h⟩ := bind_ok_inv h
  obtain ⟨o6, a6, h⟩ := bind_ok_inv h
  obtain ⟨o7, a7, h⟩ := bind_ok_inv h
  obtain ⟨o8, a8, h⟩ := bind_ok_inv h
  obtain ⟨o9, a9, h⟩ := bind_ok_inv h
  obtain ⟨o10, a10, h⟩ := bind_ok_inv h
  obtain ⟨o11, a11, h⟩ := bind_ok_inv h
  obtain ⟨o12, a12, h⟩ := bind_ok_inv h
  obtain ⟨o13, a13, h⟩ := bind_ok_inv h
  obtain ⟨o14, a14, h⟩ := bind_ok_inv h
  obtain ⟨o15, a15, h⟩ := bind_ok_inv h
  obtain ⟨o16, a16, h⟩ := bind_ok_inv h
  obtain ⟨o17, a17, h⟩ := bind_ok_inv h
  obtain ⟨o18, a18, h⟩ := bind_ok_inv h
  obtain ⟨o19, a19, h⟩ := bind_ok_inv h
  have v0 := append_ok a0
  have v2 := append_ok a2
  have v3 := append_quoted_ok a3
  have v4 := append_ok a4
  have v6 := append_ok a6
  have v8 := append_ok a8
  have v9 := append_quoted_ok a9
  have v10 := append_ok a10
  have v11 := append_quoted_ok a11
  have v12 := append_ok a12
  have v13 := append_quoted_ok a13
  have v14 := append_ok a14
  have v15 := append_quoted_ok a15
  have v16 := append_ok a16
  have v17 := append_quoted_ok a17
  have v18 := append_ok a18
  have v19 := append_quoted_ok a19
  have v1 := append_natural_ok' t1 a1
  have v5 := append_natural_ok' t2 a5
  have v7 := append_natural_ok' t3 a7
  rw [push_ok h, v19, v18, v17, v16, v15, v14, v13, v12, v11, v10, v9, v8, v7, v6, v5, v4, v3, v2, v1, v0]
  simp [StateList, StateSegs, alloc.vec.Vec.new]

/-! ## The state parser is the exact inverse of the state writer

A literal step that returned at all did not overflow: the cursor arithmetic
needs no separate room premise, so the parser's soundness holds for plaintexts
of any length (the state key's `open` is external and bounds nothing). -/

theorem word_room {b lit : Slice U8} {pos : Usize} {o : Option Usize} (h : word b pos lit = Result.ok o) :
    pos.val + lit.length ≤ Usize.max := by
  unfold word at h
  obtain ⟨i1, h1, _⟩ := bind_ok_inv h
  have v := usize_add_ok h1
  have : i1.val ≤ Usize.max := by scalar_tac
  simp only [Slice.len] at v
  simp only [Slice.length]
  scalar_tac

theorem field_room {b key : Slice U8} {pos : Usize} {x : alloc.vec.Vec U8 × Usize}
    (h : field b pos key = Result.ok (some x)) : pos.val + key.length ≤ Usize.max := by
  unfold field at h
  obtain ⟨o, ho, _⟩ := bind_ok_inv h
  exact word_room ho

theorem number_room {b key : Slice U8} {pos : Usize} {x : I64 × Usize}
    (h : number b pos key = Result.ok (some x)) : pos.val + key.length ≤ Usize.max := by
  unfold number at h
  obtain ⟨o, ho, _⟩ := bind_ok_inv h
  exact word_room ho

/-- **Soundness**: whatever `parse_state` accepts is exactly the canonical
    plaintext of the valid state it returns. -/
theorem parse_state_sound {b : Slice U8} {s : stateless_login.LoginState}
    (h : parse_state b = Result.ok (some s)) : b.val = StateList s ∧ state_valid s = Result.ok true := by
  unfold parse_state at h
  simp only [lift, bind_ok] at h
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨certificate_expires, i0⟩
  · simp at h
  simp only at h
  obtain ⟨e0, _, _, l0⟩ := number_step (number_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨certificate, i1⟩
  · simp at h
  simp only at h
  obtain ⟨e1, _, l1⟩ := field_step (field_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨expires_at, i2⟩
  · simp at h
  simp only at h
  obtain ⟨e2, _, _, l2⟩ := number_step (number_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨issued_at, i3⟩
  · simp at h
  simp only at h
  obtain ⟨e3, _, _, l3⟩ := number_step (number_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨login, i4⟩
  · simp at h
  simp only at h
  obtain ⟨e4, _, l4⟩ := field_step (field_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨provider, i5⟩
  · simp at h
  simp only at h
  obtain ⟨e5, _, l5⟩ := field_step (field_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨replica, i6⟩
  · simp at h
  simp only at h
  obtain ⟨e6, _, l6⟩ := field_step (field_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨scope, i7⟩
  · simp at h
  simp only at h
  obtain ⟨e7, _, l7⟩ := field_step (field_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨subject, i8⟩
  · simp at h
  simp only at h
  obtain ⟨e8, _, l8⟩ := field_step (field_room ho) ho
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | ⟨verifier, i9⟩
  · simp at h
  simp only at h
  obtain ⟨e9, _, l9⟩ := field_step (field_room ho) ho
  obtain ⟨n, hn, h⟩ := bind_ok_inv h
  have nv := usize_add_ok hn
  split at h
  · simp at h
  rename_i last
  have nlen : n.val = b.val.length := by simpa using last
  have inside : i9.val < b.val.length := by simp at nv; omega
  obtain ⟨x, hx, h⟩ := bind_ok_inv h
  rw [slice_index_eq b i9 inside] at hx; simp only [Result.ok.injEq] at hx; subst hx
  split at h
  · simp at h
  rename_i brace
  obtain ⟨bv, hv, h⟩ := bind_ok_inv h
  cases bv
  · simp at h
  simp only [↓reduceIte, Result.ok.injEq, Option.some.injEq] at h
  subst h
  refine ⟨?_, hv⟩
  have br : b.val[i9.val]'inside = 125#u8 := by apply UScalar.eq_of_val_eq; simpa using brace
  have close : List.drop i9.val b.val = [125#u8] := by
    rw [List.drop_eq_getElem_cons inside, br, List.drop_eq_nil_of_le (by simp at nv; omega)]
  have start : b.val = List.drop (0#usize).val b.val := by simp
  rw [start, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, close]
  simp [StateList, StateSegs]

/-! Cursor steps over an arbitrary member list (the payload's are specialised
to `Segs`). -/

def LPos (L : List (List U8)) (n : Nat) : Nat := (L.take n).flatten.length

theorem lpos_total (L : List (List U8)) (n : Nat) : LPos L n + (L.drop n).flatten.length = L.flatten.length := by
  unfold LPos
  rw [← List.length_append, ← List.flatten_append, List.take_append_drop]

theorem ldrop_pos {b : List U8} {L : List (List U8)} (hb : b = L.flatten) (n : Nat) :
    b.drop (LPos L n) = (L.drop n).flatten := by
  unfold LPos
  rw [hb]
  conv => lhs; arg 2; rw [← List.take_append_drop n L, List.flatten_append]
  exact List.drop_left

theorem lpos_le {b : List U8} {L : List (List U8)} (hb : b = L.flatten) (n : Nat) : LPos L n ≤ b.length := by
  have := lpos_total L n
  rw [hb]; omega

theorem lfield_seg {b key : Slice U8} {L : List (List U8)} (hb : b.val = L.flatten) {pos : Usize} {n m : Nat}
    (pv : pos.val = LPos L n) {v : List U8}
    (seg : (L.drop n).flatten = key.val ++ 34#u8 :: (v ++ 34#u8 :: (L.drop m).flatten))
    (plain : Plain v) (room : b.val.length + 64 ≤ Usize.max) (klen : key.length ≤ 64) :
    ∃ w next, field b pos key = Result.ok (some (w, next)) ∧ w.val = v ∧ next.val = LPos L m := by
  have t1 := lpos_total L n
  have t2 := lpos_total L m
  have tl := congrArg List.length hb
  have l := congrArg List.length seg
  simp only [List.length_append, List.length_cons] at l
  have eq : b.val.drop pos.val = key.val ++ 34#u8 :: (v ++ 34#u8 :: b.val.drop (LPos L m)) := by
    rw [pv, ldrop_pos hb, ldrop_pos hb, seg]
  obtain ⟨w, next, hf, wv, nv⟩ := field_of (by simp only [Slice.length] at *; omega)
    (by simp only [Slice.length]; rw [hb]; omega) eq plain
  refine ⟨w, next, hf, wv, ?_⟩
  rw [nv]; simp only [Slice.length] at *; omega

theorem lnumber_seg {b key : Slice U8} {L : List (List U8)} (hb : b.val = L.flatten) {pos : Usize} {n m : Nat}
    (pv : pos.val = LPos L n) {d : Nat}
    (seg : (L.drop n).flatten = key.val ++ (Digits d ++ (L.drop m).flatten))
    (ends : Ends (L.drop m).flatten) (small : d ≤ 9007199254740991)
    (room : b.val.length + 64 ≤ Usize.max) (klen : key.length ≤ 64) :
    ∃ v next, number b pos key = Result.ok (some (v, next)) ∧ v.val = d ∧ next.val = LPos L m := by
  have t1 := lpos_total L n
  have t2 := lpos_total L m
  have tl := congrArg List.length hb
  have l := congrArg List.length seg
  simp only [List.length_append] at l
  have eq : b.val.drop pos.val = key.val ++ (Digits d ++ b.val.drop (LPos L m)) := by
    rw [pv, ldrop_pos hb, ldrop_pos hb, seg]
  obtain ⟨v, next, hf, vv, nv⟩ := number_of (by simp only [Slice.length] at *; omega)
    (by simp only [Slice.length]; rw [hb]; omega) eq (by rw [ldrop_pos hb]; exact ends) small
  refine ⟨v, next, hf, vv, ?_⟩
  rw [nv]; simp only [Slice.length] at *; omega

/-- **Completeness**: the canonical plaintext of a valid login state parses back
    to that very state. -/
theorem parse_state_complete {b : Slice U8} {s : stateless_login.LoginState} (room : b.val.length + 64 ≤ Usize.max)
    (hb : b.val = StateList s) (valid : StateValid s) : parse_state b = Result.ok (some s) := by
  have hv := (state_valid_true s).mpr valid
  obtain ⟨pc, pl, pp, pr, ps, psu, pve⟩ := state_valid_plain valid
  obtain ⟨_, _, _, _, _, _, _, t1, t2, t3, t4, t5, t6⟩ := valid
  obtain ⟨login, provider, cert, subject, cexp, replica, scope, verifier, iat, exp⟩ := s
  dsimp only at pc pl pp pr ps psu pve t1 t2 t3 t4 t5 t6
  unfold StateList at hb
  have ends : ∀ (x : U8) (l : List U8), x.val = 44 → Ends (x :: l) := by
    intro x l hx _
    simp only [List.getElem_cons_zero, IsDigit, hx]
    omega
  unfold parse_state
  simp only [lift, bind_ok]
  obtain ⟨w0, i0, h0, v0, n0⟩ := lnumber_seg (key := (Array.make 12#usize [123#u8, 34#u8, 99#u8, 101#u8, 114#u8, 116#u8, 95#u8, 101#u8, 120#u8, 112#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := 0#usize) (n := 0) (m := 2)
    (d := cexp.val.toNat) hb (by simp [LPos]) (by simp [StateSegs]) (ends _ _ (by simp)) (by omega) room
    (by simp [Slice.length])
  rw [h0]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w0 = cexp := i64_of_toNat v0 t1
  obtain ⟨w2, i2, h2, v2, n2⟩ := lfield_seg (key := (Array.make 7#usize [44#u8, 34#u8, 99#u8, 110#u8, 102#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i0) (n := 2) (m := 4)
    hb n0 (by simp [StateSegs, Q]) pc room (by simp [Slice.length])
  rw [h2]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w2 = cert := vec_ext v2
  obtain ⟨w4, i4, h4, v4, n4⟩ := lnumber_seg (key := (Array.make 7#usize [44#u8, 34#u8, 101#u8, 120#u8, 112#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i2) (n := 4) (m := 6)
    (d := exp.val.toNat) hb n2 (by simp [StateSegs]) (ends _ _ (by simp)) (by omega) room
    (by simp [Slice.length])
  rw [h4]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w4 = exp := i64_of_toNat v4 t5
  obtain ⟨w6, i6, h6, v6, n6⟩ := lnumber_seg (key := (Array.make 7#usize [44#u8, 34#u8, 105#u8, 97#u8, 116#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i4) (n := 6) (m := 8)
    (d := iat.val.toNat) hb n4 (by simp [StateSegs]) (ends _ _ (by simp)) (by omega) room
    (by simp [Slice.length])
  rw [h6]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w6 = iat := i64_of_toNat v6 t3
  obtain ⟨w8, i8, h8, v8, n8⟩ := lfield_seg (key := (Array.make 9#usize [44#u8, 34#u8, 108#u8, 111#u8, 103#u8, 105#u8, 110#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i6) (n := 8) (m := 10)
    hb n6 (by simp [StateSegs, Q]) pl room (by simp [Slice.length])
  rw [h8]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w8 = login := vec_ext v8
  obtain ⟨w10, i10, h10, v10, n10⟩ := lfield_seg (key := (Array.make 7#usize [44#u8, 34#u8, 112#u8, 114#u8, 118#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i8) (n := 10) (m := 12)
    hb n8 (by simp [StateSegs, Q]) pp room (by simp [Slice.length])
  rw [h10]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w10 = provider := vec_ext v10
  obtain ⟨w12, i12, h12, v12, n12⟩ := lfield_seg (key := (Array.make 7#usize [44#u8, 34#u8, 114#u8, 101#u8, 112#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i10) (n := 12) (m := 14)
    hb n10 (by simp [StateSegs, Q]) pr room (by simp [Slice.length])
  rw [h12]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w12 = replica := vec_ext v12
  obtain ⟨w14, i14, h14, v14, n14⟩ := lfield_seg (key := (Array.make 9#usize [44#u8, 34#u8, 115#u8, 99#u8, 111#u8, 112#u8, 101#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i12) (n := 14) (m := 16)
    hb n12 (by simp [StateSegs, Q]) ps room (by simp [Slice.length])
  rw [h14]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w14 = scope := vec_ext v14
  obtain ⟨w16, i16, h16, v16, n16⟩ := lfield_seg (key := (Array.make 7#usize [44#u8, 34#u8, 115#u8, 117#u8, 98#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i14) (n := 16) (m := 18)
    hb n14 (by simp [StateSegs, Q]) psu room (by simp [Slice.length])
  rw [h16]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w16 = subject := vec_ext v16
  obtain ⟨w18, i18, h18, v18, n18⟩ := lfield_seg (key := (Array.make 12#usize [44#u8, 34#u8, 118#u8, 101#u8, 114#u8, 105#u8, 102#u8, 105#u8, 101#u8, 114#u8, 34#u8, 58#u8] (by simp)).to_slice) (pos := i16) (n := 18) (m := 20)
    hb n16 (by simp [StateSegs, Q]) pve room (by simp [Slice.length])
  rw [h18]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  obtain rfl : w18 = verifier := vec_ext v18
  have d := ldrop_pos hb 20
  rw [← n18] at d
  simp [StateSegs] at d
  have tl := congrArg List.length d
  have le := lpos_le hb 20
  rw [← n18] at le
  simp only [List.length_drop, List.length_singleton] at tl
  obtain ⟨n', hn', nv⟩ := usize_succ i18 (by omega)
  rw [hn']; simp only [bind_ok]
  have same : n' = b.len := UScalar.eq_of_val_eq (by simp [Slice.len]; omega)
  simp only [same, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
  have inside : i18.val < b.val.length := by omega
  rw [slice_index_eq b i18 inside]; simp only [bind_ok]
  have last : b.val[i18.val]'inside = 125#u8 := by
    have key := congrArg (fun l => l[0]?) d
    simp only [List.getElem?_drop, Nat.add_zero, List.getElem?_cons_zero] at key
    rw [List.getElem?_eq_getElem inside] at key
    simpa using key
  simp only [last, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, hv, bind_ok]

/-! ## Sealing and opening the `state` parameter -/

/-- `garrett-stateless-v1/login` and a zero byte: the state's associated data. -/
def LoginLabel : List U8 := lit "garrett-stateless-v1/login" ++ [0#u8]

/-- `gs1.` -/
def StatePrefix : List U8 := lit "gs1."

theorem login_label_val : LOGIN_LABEL.val = LoginLabel := by
  unfold LOGIN_LABEL
  simp [LoginLabel]
  rfl

theorem state_prefix_val : STATE_PREFIX.val = StatePrefix := by
  unfold STATE_PREFIX
  simp [StatePrefix]
  rfl

/-- **What a sealed state is.** `seal_state` returns `out` only for a 12-byte
    nonce and a valid state, after the state key's `seal` primitive answered
    `c` for exactly that nonce, the login label and the canonical plaintext;
    `out` is `gs1.` and the url-b64 of the nonce and `c`, at most 4096 bytes. -/
theorem seal_state_ok {K : Type} {inst : StateKey K} {key : K} {s : stateless_login.LoginState}
    {nonce : Slice U8} {out : alloc.vec.Vec U8} (h : seal_state inst key s nonce = Result.ok (some out)) :
    ∃ (pt : Slice U8) (c : alloc.vec.Vec U8) (t : List U8),
      nonce.val.length = 12 ∧ StateValid s ∧ pt.val = StateList s ∧
      inst.seal key nonce LOGIN_LABEL pt = Result.ok (some c) ∧
      out.val = StatePrefix ++ t ∧ B64 t (nonce.val ++ c.val) ∧ out.val.length ≤ 4096 := by
  unfold seal_state at h
  simp only at h
  split at h
  · simp at h
  rename_i nlen
  obtain ⟨b, hb, h⟩ := bind_ok_inv h
  cases b
  · simp at h
  simp only [↓reduceIte] at h
  obtain ⟨v, hv, h⟩ := bind_ok_inv h
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | c
  · simp at h
  simp only at h
  obtain ⟨s0, h0, h⟩ := bind_ok_inv h
  obtain ⟨s1, h1, h⟩ := bind_ok_inv h
  obtain ⟨o0, h2, h⟩ := bind_ok_inv h
  obtain ⟨v1, h3, h⟩ := bind_ok_inv h
  obtain ⟨o1, h4, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  rename_i small
  simp only [Result.ok.injEq, Option.some.injEq] at h
  subst h
  have valid := (state_valid_true s).mp hb
  have times := valid
  obtain ⟨_, _, _, _, _, _, _, t1, _, t2, _, t3, _⟩ := times
  have pv := state_bytes_ok ⟨t1, t3, t2⟩ hv
  obtain ⟨e, _, _⟩ := b64url_ok (b64url_fits h3) h3
  refine ⟨alloc.vec.Vec.deref v, c, v1.val, ?_, valid, by rw [deref_val, pv], ho, ?_, ?_, ?_⟩
  · have e : nonce.val.length = NONCE.val := by simpa using nlen
    unfold NONCE at e
    simpa using e
  · rw [append_ok h4, append_ok h2, state_prefix_val]
    simp
  · simpa [B64, deref_val, append_ok h1, append_ok h0, alloc.vec.Vec.new] using e
  · unfold MAX_STATE at small
    simp [alloc.vec.Vec.len] at small
    scalar_tac

/-- **What an opened state is.** `open_state` returns `Ok s` only for a text of
    at most 4096 bytes that is `gs1.` and the url-b64 of at least 29 bytes,
    after the state key's `open` primitive answered a plaintext for exactly
    their first 12 bytes, the login label and the rest; that plaintext is the
    canonical plaintext of `s`, and `s` is valid. Every other outcome is an
    `Err`. -/
theorem open_state_ok {K : Type} {inst : StateKey K} {key : K} {text : Slice U8} {s : stateless_login.LoginState}
    (h : open_state inst key text = Result.ok (core.result.Result.Ok s)) :
    ∃ (t : List U8) (sealed : alloc.vec.Vec U8) (n c : Slice U8) (pl : alloc.vec.Vec U8),
      text.val = StatePrefix ++ t ∧ text.val.length ≤ 4096 ∧ B64 t sealed.val ∧ 29 ≤ sealed.val.length ∧
      n.val = sealed.val.take 12 ∧ c.val = sealed.val.drop 12 ∧
      inst.open key n LOGIN_LABEL c = Result.ok (some pl) ∧ pl.val = StateList s ∧ StateValid s := by
  unfold open_state at h
  simp only at h
  split at h
  · simp at h
  rename_i notBig
  split at h
  · simp at h
  obtain ⟨pre, hpre, h⟩ := bind_ok_inv h
  obtain ⟨prev, _⟩ := range_to_ok hpre
  obtain ⟨b, hb, h⟩ := bind_ok_inv h
  rw [slice_ne_eq] at hb
  simp only [Result.ok.injEq] at hb
  subst hb
  split at h
  · simp at h
  rename_i same
  obtain ⟨rest, hrest, h⟩ := bind_ok_inv h
  obtain ⟨restv, _⟩ := range_from_ok hrest
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  rcases o with _ | sealed
  · simp at h
  simp only at h
  obtain ⟨i6, h6, h⟩ := bind_ok_inv h
  obtain ⟨i7, h7, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  rename_i long
  obtain ⟨n, hn, h⟩ := bind_ok_inv h
  obtain ⟨c, hc, h⟩ := bind_ok_inv h
  obtain ⟨nv, _⟩ := range_to_ok (s := sealed.slice) hn
  obtain ⟨cv, _⟩ := range_from_ok (s := sealed.slice) hc
  obtain ⟨o1, hop, h⟩ := bind_ok_inv h
  rcases o1 with _ | pl
  · simp at h
  simp only at h
  obtain ⟨o2, hps, h⟩ := bind_ok_inv h
  rcases o2 with _ | st
  · simp at h
  simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
  subst h
  obtain ⟨plv, valid⟩ := parse_state_sound hps
  have small : text.val.length ≤ 4096 := by
    unfold MAX_STATE at notBig
    simp [Slice.len] at notBig
    scalar_tac
  have pre4 : pre.val = StatePrefix := by
    have : pre.val = STATE_PREFIX.val := by simpa using same
    rw [this, state_prefix_val]
  have plen : (Slice.len STATE_PREFIX).val = 4 := by unfold STATE_PREFIX; simp
  have tv : text.val = StatePrefix ++ rest.val := by
    rw [restv, ← pre4, prev, plen, List.take_append_drop]
  obtain ⟨eb, _⟩ := from_b64url_sound (by
    have := usize_big; simp only [Slice.length, restv, List.length_drop]; omega) ho
  refine ⟨rest.val, sealed, n, c, pl, tv, small, eb, ?_, ?_, ?_, hop, by rw [← deref_val, plv],
    (state_valid_true _).mp valid⟩
  · have a6 := usize_add_ok h6
    have a7 := usize_add_ok h7
    unfold NONCE TAG at a6
    have l : ¬ (alloc.vec.Vec.len sealed).val < i7.val := long
    clear * - l a6 a7
    simp [alloc.vec.Vec.len] at l a6 a7
    omega
  · rw [nv]; unfold NONCE; simp [alloc.vec.Vec.val]
  · rw [cv]; unfold NONCE; simp [alloc.vec.Vec.val]

/-- The one property of the external state key (AES-256-GCM) the positive
    round trip needs, stated for the login label only: a ciphertext the
    `seal` primitive returns is 16 bytes longer than its plaintext, and the
    `open` primitive returns that plaintext for the same nonce and ciphertext.
    A premise of the witness below, not an axiom. -/
def StateAeadInverse {K : Type} (inst : StateKey K) (key : K) : Prop :=
  ∀ (n p : Slice U8) (c : alloc.vec.Vec U8), inst.seal key n LOGIN_LABEL p = Result.ok (some c) →
    c.val.length = p.val.length + 16 ∧
    ∀ (n' c' : Slice U8), n'.val = n.val → c'.val = c.val →
      ∃ pl : alloc.vec.Vec U8, inst.open key n' LOGIN_LABEL c' = Result.ok (some pl) ∧ pl.val = p.val

/-- **Positive witness**: under the AEAD inverse contract, the state
    `seal_state` produced opens to exactly the state that was sealed. -/
theorem seal_open_state {K : Type} {inst : StateKey K} {key : K} (aead : StateAeadInverse inst key)
    {s : stateless_login.LoginState} {nonce : Slice U8} {out : alloc.vec.Vec U8}
    (h : seal_state inst key s nonce = Result.ok (some out)) :
    ∀ text : Slice U8, text.val = out.val → open_state inst key text = Result.ok (core.result.Result.Ok s) := by
  intro text htext
  obtain ⟨pt, c, t, nl, valid, ptv, hseal, outv, b64, olen⟩ := seal_state_ok h
  obtain ⟨clen, opens⟩ := aead nonce pt c hseal
  have big := usize_big
  have tlen : t.length = (8 * (nonce.val ++ c.val).length + 5) / 6 := by
    have := congrArg List.length b64; simp only [List.length_map, enc_length] at this; exact this
  have plen : StatePrefix.length = 4 := by simp [StatePrefix, lit, garrett_stateless_core.Proofs.ascii]
  have textv : text.val = StatePrefix ++ t := by rw [htext, outv]
  have textLen : text.val.length = 4 + t.length := by rw [textv]; simp [plen]
  have olen' : text.val.length ≤ 4096 := by rw [htext]; exact olen
  have Llen : (nonce.val ++ c.val).length = 12 + (pt.val.length + 16) := by simp [nl, clen]
  have ptLen : pt.val.length ≤ 4096 := by omega
  have ptPos : 1 ≤ pt.val.length := by rw [ptv]; simp [StateList, StateSegs]
  have spl : (Slice.len STATE_PREFIX).val = 4 := by unfold STATE_PREFIX; simp
  unfold open_state
  simp only
  have c1 : ¬ (Slice.len text > MAX_STATE) := by unfold MAX_STATE; simp [Slice.len]; omega
  simp only [c1, ↓reduceIte]
  have c2 : ¬ (Slice.len text < Slice.len STATE_PREFIX) := by
    intro hc; have : (Slice.len text).val < (Slice.len STATE_PREFIX).val := hc
    simp [Slice.len] at this spl; omega
  simp only [c2, ↓reduceIte]
  rw [slice_to_val (b := text) (hi := Slice.len STATE_PREFIX) (by rw [spl]; omega)]
  simp only [bind_ok]
  rw [slice_ne_eq]
  have pre : (text.val.take (Slice.len STATE_PREFIX).val) = STATE_PREFIX.val := by
    rw [spl, textv, state_prefix_val, ← plen, List.take_left]
  simp only [Slice.from_val, pre, ne_eq, not_true_eq_false, decide_false, Bool.false_eq_true, ↓reduceIte, bind_ok]
  obtain ⟨f, hf, fv⟩ := slice_from_val (b := text) (lo := Slice.len STATE_PREFIX) (by rw [spl]; omega)
  rw [hf]; simp only [bind_ok]
  have ft : f.val = t := by rw [fv, spl, textv, ← plen, List.drop_left]
  obtain ⟨sealed, hs, sv⟩ := from_b64url_complete (Slice.from (nonce.val ++ c.val) (by omega)) f
    (by rw [ft, Slice.from_val]; exact b64) (by rw [ft]; omega)
  rw [hs]; simp only [bind_ok]
  rw [Slice.from_val] at sv
  obtain ⟨i6, h6, v6⟩ := returned_of_spec (Usize.add_spec (x := NONCE) (y := TAG) (by unfold NONCE TAG; simp; omega))
  rw [h6]; simp only [bind_ok]
  obtain ⟨i7, h7, v7⟩ := returned_of_spec (Usize.add_spec (x := i6) (y := 1#usize) (by
    unfold NONCE TAG at v6; simp at v6; rw [v6]; simp; omega))
  rw [h7]; simp only [bind_ok]
  have c3 : ¬ (alloc.vec.Vec.len sealed < i7) := by
    intro hc
    have : (alloc.vec.Vec.len sealed).val < i7.val := hc
    unfold NONCE TAG at v6
    simp [alloc.vec.Vec.len, sv] at this v6 v7
    omega
  simp only [c3, ↓reduceIte]
  have slen : sealed.val.length = 12 + (pt.val.length + 16) := by rw [sv, Llen]
  obtain ⟨n, hn, nv, _⟩ := returned_of_spec (alloc.vec.Vec.index_RangeTo_spec sealed { «end» := NONCE } (by
    unfold NONCE; simp [alloc.vec.Vec.length] at slen ⊢; scalar_tac))
  rw [hn]; simp only [bind_ok]
  obtain ⟨c', hc', cv, _⟩ := returned_of_spec (alloc.vec.Vec.index_RangeFrom_spec sealed { start := NONCE } (by
    unfold NONCE; simp [alloc.vec.Vec.length] at slen ⊢; scalar_tac))
  rw [hc']; simp only [bind_ok]
  have n12 : n.val = nonce.val := by
    rw [nv, sv]; unfold NONCE; simp [List.slice, ← nl]
  have c12 : c'.val = c.val := by
    rw [cv, sv]; unfold NONCE; simp [← nl]
  obtain ⟨pl, hpl, plv⟩ := opens n c' n12 c12
  rw [hpl]; simp only [bind_ok]
  rw [parse_state_complete (by rw [deref_val, plv]; omega) (by rw [deref_val, plv, ptv]) valid]
  simp

end garrett_stateless_core.stateless_token.Proofs
