import GarrettStatelessToken
import GarrettStatelessBoundary
import GarrettHttpAuth

/-!
# `garrett-stateless-v1`: a sealed surrogate opens (positive witness)

Source: `crates/garrett-stateless-core/src/stateless_token.rs`
(`seal_token`, `verify_token`, `unseal_token`). Under the two crypto
correctness contracts of `GarrettStatelessBoundary` — Ed25519 signatures
verify, AES-256-GCM opens what it sealed — every token the broker's
`seal_token` returns is accepted by `verify_token` under any valid key set
holding the signing `kid`, with exactly the sealed claims, and
`unseal_token` returns exactly the sealed credential. The informational
members need not be canonical: the parser drops absent ones, which carry no
authority.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.proxy_http.Proofs (bind_ok_inv)
open garrett_stateless_core.stateless_mailbox.Proofs (slice_index_eq usize_succ)
open garrett_stateless_core.proxy_http.Base64Proofs (enc)
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.stateless_token.Proofs

theorem cred_nonempty {cred : Slice U8} (h : http_auth.valid_credential cred = Result.ok true) :
    0 < cred.val.length := by
  obtain ⟨b, hb, iff⟩ := returned_of_spec (http_auth.Proofs.valid_credential_contract cred)
  rw [h] at hb; simp only [Result.ok.injEq] at hb; subst hb
  exact (iff.mp rfl).1

/-- The public payload bytes read `scope` and `upstream` only when present,
    and never `enc`. -/
theorem payload_bytes_congr {p q : Payload} (claims : p.claims = q.claims)
    (hs : p.info.has_scope = q.info.has_scope) (hu : p.info.has_upstream = q.info.has_upstream)
    (scope : p.info.has_scope = true → p.info.scope = q.info.scope)
    (upstream : p.info.has_upstream = true → p.info.upstream = q.info.upstream) :
    payload_bytes p false = payload_bytes q false := by
  obtain ⟨c, e, ⟨s, sc, u, up⟩⟩ := p
  obtain ⟨c', e', ⟨s', sc', u', up'⟩⟩ := q
  simp only at claims hs hu scope upstream
  subst claims hs hu
  cases s <;> cases u <;> simp_all [payload_bytes]

/-- What `seal_token` computed on the way: the header, the public payload
    and the associated data. -/
theorem seal_token_internals {M : Type} {inst : KeyMaterial M} {entry : KeyEntry M} {info : Informational}
    {claims : stateless.SurrogateClaims} {cred nonce : Slice U8} {token : alloc.vec.Vec U8}
    (h : seal_token inst entry info claims cred nonce = Result.ok (core.result.Result.Ok token)) :
    ∃ header pub aad : alloc.vec.Vec U8,
      header_bytes (alloc.vec.Vec.deref entry.kid) = Result.ok header ∧
      payload_bytes { claims := claims, enc := alloc.vec.Vec.new U8, info := info } false = Result.ok pub ∧
      associated (alloc.vec.Vec.deref header) (alloc.vec.Vec.deref pub) = Result.ok aad := by
  unfold seal_token at h
  obtain ⟨vc, _, h⟩ := bind_ok_inv h
  cases vc
  · simp at h
  simp only [↓reduceIte] at h
  obtain ⟨vk, _, h⟩ := bind_ok_inv h
  cases vk
  · simp at h
  simp only [↓reduceIte] at h
  split at h
  · simp at h
  obtain ⟨header, hh, h⟩ := bind_ok_inv h
  obtain ⟨sc, hsc, h⟩ := bind_ok_inv h
  rw [copy_claims_eq] at hsc; simp only [Result.ok.injEq] at hsc; subst hsc
  obtain ⟨i1, hi1, h⟩ := bind_ok_inv h
  rw [copy_info_eq] at hi1; simp only [Result.ok.injEq] at hi1; subst hi1
  obtain ⟨b2, _, h⟩ := bind_ok_inv h
  cases b2
  · simp at h
  simp only [↓reduceIte] at h
  obtain ⟨pub, hpub, h⟩ := bind_ok_inv h
  obtain ⟨b3, _, h⟩ := bind_ok_inv h
  cases b3
  swap
  · simp at h
  simp only [Bool.false_eq_true, ↓reduceIte] at h
  obtain ⟨b4, _, h⟩ := bind_ok_inv h
  cases b4
  swap
  · simp at h
  simp only [Bool.false_eq_true, ↓reduceIte] at h
  obtain ⟨aad, haad, _⟩ := bind_ok_inv h
  exact ⟨header, pub, aad, hh, hpub, haad⟩

/-! ## The informational members the parser returns -/

/-- Absent informational members carry no bytes. -/
def normInfo (i : Informational) : Informational :=
  { has_scope := i.has_scope, scope := if i.has_scope then i.scope else alloc.vec.Vec.new U8,
    has_upstream := i.has_upstream, upstream := if i.has_upstream then i.upstream else alloc.vec.Vec.new U8 }

theorem norm_list (c : stateless.SurrogateClaims) (e : alloc.vec.Vec U8) (i : Informational) (w : Bool) :
    PayloadList { claims := c, enc := e, info := normInfo i } w = PayloadList { claims := c, enc := e, info := i } w := by
  obtain ⟨s, sc, u, up⟩ := i
  cases s <;> cases u <;> simp [PayloadList, normInfo]

theorem norm_canonical (c : stateless.SurrogateClaims) (e : alloc.vec.Vec U8) (i : Informational) :
    Canonical { claims := c, enc := e, info := normInfo i } := by
  obtain ⟨s, sc, u, up⟩ := i
  cases s <;> cases u <;> simp [Canonical, normInfo]

theorem norm_valid {c : stateless.SurrogateClaims} {e e' : alloc.vec.Vec U8} {i : Informational}
    (h : PayloadValid { claims := c, enc := e, info := i }) : PayloadValid { claims := c, enc := e', info := normInfo i } := by
  obtain ⟨s, sc, u, up⟩ := i
  unfold PayloadValid at *
  cases s <;> cases u <;> simp_all [normInfo]

theorem b64_safe {l x : List U8} (h : B64 l x) : ∀ y ∈ l, y.val ≠ 46 ∧ y.val ≤ 127 :=
  fun y my => ⟨(b64_byte_safe (enc_alphabet h y my)).2.2.1, (b64_byte_safe (enc_alphabet h y my)).2.2.2⟩

theorem b64_length {l x : List U8} (h : B64 l x) : x.length ≤ l.length := by
  have := congrArg List.length h
  rw [List.length_map, enc_length] at this
  omega

/-- A slice with the given bytes, when they fit. -/
theorem slice_of (l : List U8) (fits : l.length ≤ Usize.max) : ∃ x : Slice U8, x.val = l :=
  ⟨Slice.from l fits, Slice.from_val l fits⟩

theorem decode_of {text : Slice U8} {l : List U8} (h : B64 text.val l) (small : text.val.length ≤ 16384) :
    ∃ out, from_b64url text = Result.ok (some out) ∧ out.val = l := by
  have big := usize_big
  have := b64_length h
  obtain ⟨x, xv⟩ := slice_of l (by omega)
  obtain ⟨out, ho, ov⟩ := from_b64url_complete x text (by rw [xv]; exact h) (by omega)
  exact ⟨out, ho, by rw [ov, xv]⟩

/-- **A sealed surrogate opens.** Under Ed25519 and AES-256-GCM correctness
    for the signing entry and a verification entry with the same `kid`, every
    token `seal_token` returns is accepted by `verify_token` — selecting that
    entry, with exactly the sealed claims — and `unseal_token` then returns
    exactly the sealed credential. -/
theorem seal_then_open {M : Type} {inst : KeyMaterial M} {entry e : KeyEntry M} {entries : Slice (KeyEntry M)}
    {info : Informational} {claims : stateless.SurrogateClaims} {cred nonce : Slice U8} {token : alloc.vec.Vec U8}
    {i : Nat} (keys : KeysValid entries.val) (at_i : entries.val[i]? = some e) (sameKid : e.kid.val = entry.kid.val)
    (sig : stateless_boundary.SignVerifies inst entry.material e.material)
    (aead : stateless_boundary.AeadInverse inst entry.material e.material)
    (h : seal_token inst entry info claims cred nonce = Result.ok (core.result.Result.Ok token)) :
    ∃ v, verify_token inst entries (alloc.vec.Vec.deref token) = Result.ok (core.result.Result.Ok v) ∧
      v.key.val = i ∧ v.claims = claims ∧ v.key_issuer.val = e.issuer.val ∧
      ∃ out : alloc.vec.Vec U8, unseal_token inst entries v = Result.ok (core.result.Result.Ok out) ∧
        out.val = cred.val := by
  obtain ⟨header, pub, aad, hhdr, hpub, haad⟩ := seal_token_internals h
  obtain ⟨aadS, body, ct, signature, p, H, P, S, hvc, hkid, nl, pc, pinfo, pvalid, _, _, haadS, hseal, henc,
    hH, hP, hbody, hsign, slen, hS, htok, tlen⟩ := seal_token_ok h
  obtain ⟨c, en, inf⟩ := p
  simp only at pc pinfo
  subst c inf
  have big := usize_big
  have tv : (alloc.vec.Vec.deref token).val = H ++ 46#u8 :: (P ++ 46#u8 :: S) := by rw [deref_val, htok]
  have tl : (alloc.vec.Vec.deref token).val.length = H.length + P.length + S.length + 2 := by rw [tv]; simp; omega
  have tl1 := tl
  rw [deref_val] at tl1
  have safeH := b64_safe hH
  have safeP := b64_safe hP
  have safeS := b64_safe hS
  unfold verify_token
  -- the three segments
  obtain ⟨o, ho, _, complete⟩ := segments_spec (alloc.vec.Vec.deref token)
  obtain ⟨first, second, os, fv, sv⟩ := complete H P S
    ⟨tv, fun x m => (safeH x m).1, fun x m => (safeP x m).1, fun x m => (safeS x m).1⟩
    (by rw [deref_val]; exact tlen)
    (by
      intro x m
      rw [tv] at m
      simp only [List.mem_append, List.mem_cons] at m
      rcases m with m | m | m | m | m
      · exact (safeH x m).2
      · rw [m]; simp [AsciiByte]
      · exact (safeP x m).2
      · rw [m]; simp [AsciiByte]
      · exact (safeS x m).2)
  subst os
  rw [ho]; simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
  have tprop := (alloc.vec.Vec.deref token).property
  -- the header
  rw [slice_to_val (by rw [fv]; omega)]
  simp only [bind_ok]
  obtain ⟨hd, hhd, hdv⟩ := decode_of
    (text := Slice.from ((alloc.vec.Vec.deref token).val.take first.val) (by simp only [List.length_take]; omega))
    (l := HS ++ entry.kid.val ++ HE) (by rw [Slice.from_val, fv, tv]; simpa using hH)
    (by rw [Slice.from_val]; simp only [List.length_take]; omega)
  rw [hhd]; simp only [bind_ok]
  obtain ⟨kid', hk', kv⟩ := header_kid_of (b := alloc.vec.Vec.deref hd) (by rw [deref_val, hdv]) hkid
  rw [hk']; simp only [bind_ok]
  -- the key
  have inside : i < entries.val.length := (List.getElem?_eq_some_iff.mp at_i).1
  have ei : entries.val[i]'inside = e := (List.getElem?_eq_some_iff.mp at_i).2
  obtain ⟨r, hr, choice⟩ := select_unique entries (alloc.vec.Vec.deref kid') keys
  have named : (entries.val[i]'inside).kid.val = (alloc.vec.Vec.deref kid').val := by
    rw [ei, sameKid, deref_val, kv]
  obtain ⟨rlt, rv⟩ : ∃ h : r.val < entries.val.length, r.val = i := by
    rcases choice with ⟨rlt, _, unique⟩ | ⟨_, none⟩
    · exact ⟨rlt, (unique i inside named).symm⟩
    · exact absurd named (none i inside)
  rw [hr]
  have nge : ¬ r ≥ Slice.len entries := by scalar_tac
  simp only [bind_ok, nge, ↓reduceIte]
  rw [slice_index_eq entries r rlt]
  simp only [bind_ok]
  have er : entries.val[r.val]'rlt = e := by simp only [rv]; exact ei
  rw [er]
  -- the signature
  obtain ⟨i1, hi1, i1v⟩ := usize_succ second (by omega)
  rw [hi1]; simp only [bind_ok]
  obtain ⟨fS, hfS, fSv⟩ := slice_from_val (b := alloc.vec.Vec.deref token) (lo := i1) (by rw [i1v, sv]; omega)
  rw [hfS]; simp only [bind_ok]
  have dropS : (H ++ 46#u8 :: (P ++ 46#u8 :: S)).drop (H.length + 1 + P.length + 1) = S := by
    rw [show H ++ 46#u8 :: (P ++ 46#u8 :: S) = (H ++ 46#u8 :: P ++ [46#u8]) ++ S by simp]
    exact List.drop_left' (by simp; omega)
  obtain ⟨sg, hsg, sgv⟩ := decode_of (text := fS) (l := signature.val)
    (by rw [fSv, i1v, sv, tv, dropS]; exact hS) (by rw [fSv]; simp only [List.length_drop]; omega)
  rw [hsg]; simp only [bind_ok]
  have sglen : alloc.vec.Vec.len sg = SIGNATURE := by
    apply UScalar.eq_of_val_eq
    unfold SIGNATURE
    simp [alloc.vec.Vec.len, sgv, slen]
  simp only [sglen, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
  have takeB : (H ++ 46#u8 :: (P ++ 46#u8 :: S)).take (H.length + 1 + P.length) = H ++ 46#u8 :: P := by
    rw [show H ++ 46#u8 :: (P ++ 46#u8 :: S) = (H ++ 46#u8 :: P) ++ 46#u8 :: S by simp]
    exact List.take_left' (by simp; omega)
  rw [slice_to_val (by rw [sv]; omega)]
  simp only [bind_ok]
  rw [sig body _ signature (alloc.vec.Vec.deref sg) hsign (by rw [Slice.from_val, sv, tv, takeB, hbody])
    (by rw [deref_val, sgv])]
  simp only [bind_ok, ↓reduceIte]
  -- the payload
  obtain ⟨i3, hi3, i3v⟩ := usize_succ first (by omega)
  rw [hi3]; simp only [bind_ok]
  obtain ⟨fp, hfp, fpv⟩ := slice_range_val (b := alloc.vec.Vec.deref token) (lo := i3) (hi := second)
    (by rw [i3v, fv, sv]; omega) (by simp only [Slice.length]; rw [sv]; omega)
  rw [hfp]; simp only [bind_ok]
  have midP : ((H ++ 46#u8 :: (P ++ 46#u8 :: S)).drop (H.length + 1)).take
      (H.length + 1 + P.length - (H.length + 1)) = P := by
    rw [show H ++ 46#u8 :: (P ++ 46#u8 :: S) = (H ++ [46#u8]) ++ (P ++ 46#u8 :: S) by simp,
      List.drop_left' (by simp), show H.length + 1 + P.length - (H.length + 1) = P.length by omega]
    exact List.take_left' rfl
  obtain ⟨bytes, hbytes, bv⟩ := decode_of (text := fp) (l := PayloadList { claims := claims, enc := en, info := info } true)
    (by rw [fpv, i3v, fv, sv, tv, midP]; exact hP)
    (by rw [fpv]; simp only [List.length_take, List.length_drop]; omega)
  rw [hbytes]; simp only [bind_ok]
  have qvalid := norm_valid (e' := en) pvalid
  obtain ⟨_, _, _, _, _, _, t1, t2, t3, t4, t5, t6, _⟩ := id qvalid
  obtain ⟨pa, pc, pi, pj, pp, ps, psc⟩ := payload_valid_plain qvalid
  have plen := b64_length hP
  rw [parse_payload_complete (p := { claims := claims, enc := en, info := normInfo info })
    (by rw [deref_val, bv]; omega) (by rw [deref_val, bv, norm_list]) (norm_canonical _ _ _)
    ⟨pa, pc, enc_plain henc, pi, pj, pp, ps, psc⟩ ⟨t3, t4, t1, t2, t5, t6⟩ ((payload_valid_true _).mpr qvalid)]
  simp only [bind_ok]
  -- the sealed credential
  have enl : en.val.length ≤ (PayloadList { claims := claims, enc := en, info := info } true).length := by
    simp [PayloadList, Q]; omega
  obtain ⟨sd, hsd, sdv⟩ := decode_of (text := alloc.vec.Vec.deref en) (l := nonce.val ++ ct.val)
    (by rw [deref_val]; exact henc) (by rw [deref_val]; omega)
  rw [hsd]; simp only [bind_ok]
  obtain ⟨ctlen, opens⟩ := aead nonce aadS cred ct hseal
  have cpos := cred_nonempty hvc
  obtain ⟨i5, h5, v5⟩ := returned_of_spec (Usize.add_spec (x := NONCE) (y := TAG) (by unfold NONCE TAG; scalar_tac))
  obtain ⟨i6, h6, v6⟩ := usize_succ i5 (by unfold NONCE TAG at v5; scalar_tac)
  rw [h5]; simp only [bind_ok]; rw [h6]; simp only [bind_ok]
  have sdl : sd.val.length = nonce.val.length + cred.val.length + 16 := by rw [sdv]; simp; omega
  have nlt : ¬ alloc.vec.Vec.len sd < i6 := by
    unfold NONCE TAG at v5
    have : i6.val ≤ sd.val.length := by simp at v5; omega
    simp only [alloc.vec.Vec.len]; scalar_tac
  simp only [nlt, ↓reduceIte]
  -- the associated data: the header and public payload the seal used
  have same : payload_bytes { claims := claims, enc := en, info := normInfo info } false =
      payload_bytes { claims := claims, enc := alloc.vec.Vec.new U8, info := info } false :=
    payload_bytes_congr rfl rfl rfl (by intro hs; simp only [normInfo] at hs ⊢; simp [hs])
      (by intro hu; simp only [normInfo] at hu ⊢; simp [hu])
  rw [same, hpub]
  simp only [bind_ok]
  obtain rfl : hd = header := vec_ext (by rw [hdv, header_bytes_ok hhdr, deref_val])
  rw [haad]; simp only [bind_ok, garrett_stateless_core.stateless.Proofs.to_vec_eq]
  refine ⟨_, rfl, rv, rfl, deref_val _, ?_⟩
  -- unsealing, with the entry that verified
  unfold unseal_token
  simp only [nge, ↓reduceIte]
  rw [h5]; simp only [bind_ok]; rw [h6]; simp only [bind_ok, nlt, ↓reduceIte]
  have l12 : (NONCE : Usize).val ≤ sd.val.length := by unfold NONCE; simp; omega
  obtain ⟨n', hn', n'v, _⟩ := returned_of_spec (alloc.vec.Vec.index_RangeTo_spec sd { «end» := NONCE }
    (by simpa using l12))
  obtain ⟨c', hc', c'v, _⟩ := returned_of_spec (alloc.vec.Vec.index_RangeFrom_spec sd { start := NONCE }
    (by simpa using l12))
  rw [hn']; simp only [bind_ok]; rw [hc']; simp only [bind_ok]
  rw [slice_index_eq entries r rlt, er]; simp only [bind_ok]
  have pubv := payload_bytes_ok (p := { claims := claims, enc := alloc.vec.Vec.new U8, info := info }) ⟨t3, t1, t5⟩ hpub
  obtain ⟨out, hout, outv⟩ := opens n' (alloc.vec.Vec.deref aad) c'
    (by rw [n'v, sdv]; unfold NONCE; simp [List.slice, nl])
    (by rw [deref_val, associated_ok haad, haadS, deref_val, header_bytes_ok hhdr, deref_val, deref_val, pubv,
      payload_list_public claims info (alloc.vec.Vec.new U8) en])
    (by rw [c'v, sdv]; unfold NONCE; simp [nl])
  rw [hout]; simp only [bind_ok]
  exact ⟨out, rfl, outv⟩

end garrett_stateless_core.stateless_token.Proofs
