import GarrettStatelessMailbox
import GarrettStatelessConnection
import GarrettStatelessToken
import GarrettStatelessBoundary

/-!
# `garrett-stateless-v1`: the whole protocol, over every execution

Builds on the extracted transitions and their proofs: the login mailbox
(`GarrettStatelessMailbox`), the token codec (`GarrettStatelessToken`), the
admission core (`GarrettStateless`) and the proxy connection loop
(`GarrettStatelessConnection`). External effects enter only through the
interfaces of `GarrettStatelessBoundary`.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.proxy_http.Proofs (bind_ok_inv)
open aivm_secrets_garrett_core.proxy_http.Base64Proofs (enc enc_injective)

namespace aivm_secrets_garrett_core.stateless_protocol

open aivm_secrets_garrett_core.stateless_token
open aivm_secrets_garrett_core.stateless_token.Proofs

/-! ## One token, two directions: what was sealed is what verifies -/

/-- The payload as `parse_payload` returns it: absent optional members are empty. -/
def normal (p : Payload) : Payload :=
  { p with info := { p.info with
      scope := if p.info.has_scope then p.info.scope else alloc.vec.Vec.new U8,
      upstream := if p.info.has_upstream then p.info.upstream else alloc.vec.Vec.new U8 } }

theorem normal_list (p : Payload) (b : Bool) : PayloadList (normal p) b = PayloadList p b := by
  cases h1 : p.info.has_scope <;> cases h2 : p.info.has_upstream <;> simp [PayloadList, normal, h1, h2]

theorem normal_canonical (p : Payload) : Canonical (normal p) := by
  refine ⟨fun h => ?_, fun h => ?_⟩ <;> simp_all [normal]

theorem normal_valid {p : Payload} (h : PayloadValid p) : PayloadValid (normal p) := by
  obtain ⟨a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14⟩ := h
  refine ⟨a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, fun hs => ?_, fun hu => ?_⟩
  · simp only [normal] at hs ⊢; simp only [hs, ↓reduceIte]; exact a13 hs
  · simp only [normal] at hu ⊢; simp only [hu, ↓reduceIte]; exact a14 hu

/-- **Parsing inverts writing**, for every valid payload: the canonical
    bytes of `p` parse to `p` with its absent optional members emptied. -/
theorem parse_payload_of {b : Slice U8} {p : Payload} (room : b.val.length + 64 ≤ Usize.max)
    (hb : b.val = PayloadList p true) (valid : PayloadValid p) (encPlain : Plain p.enc.val) :
    parse_payload b = Result.ok (some (normal p)) := by
  have nv := normal_valid valid
  obtain ⟨pa, pc, pi, pj, pp, ps, psc⟩ := payload_valid_plain nv
  have times := nv
  obtain ⟨_, _, _, _, _, _, t1, t2, t3, t4, t5, t6, _⟩ := times
  exact parse_payload_complete room (by rw [normal_list]; exact hb) (normal_canonical p)
    ⟨pa, pc, encPlain, pi, pj, pp, ps, psc⟩ ⟨t3, t4, t1, t2, t5, t6⟩ ((payload_valid_true _).mpr nv)

theorem b64_no_dot {l x : List U8} (h : B64 l x) : ∀ y ∈ l, y.val ≠ 46 :=
  fun y my => (b64_byte_safe (enc_alphabet h y my)).2.2.1

theorem b64_inj {l x y : List U8} (hx : B64 l x) (hy : B64 l y) : x = y :=
  enc_injective x y true (by rw [← hx, ← hy])

/-- Two dot-free first segments split a signed part the same way. -/
theorem split_dot : ∀ {a H b P : List U8}, (∀ y ∈ a, y.val ≠ 46) → (∀ y ∈ H, y.val ≠ 46) →
    a ++ 46#u8 :: b = H ++ 46#u8 :: P → a = H ∧ b = P
  | [], [], _, _, _, _, e => by simpa using e
  | [], y :: H, _, _, _, nH, e => by
    simp only [List.nil_append, List.cons_append, List.cons.injEq] at e
    exact absurd (congrArg UScalar.val e.1).symm (nH y (by simp))
  | x :: a, [], _, _, na, _, e => by
    simp only [List.nil_append, List.cons_append, List.cons.injEq] at e
    exact absurd (congrArg UScalar.val e.1) (na x (by simp))
  | x :: a, y :: H, _, _, na, nH, e => by
    simp only [List.cons_append, List.cons.injEq] at e
    obtain ⟨xy, rest⟩ := e
    obtain ⟨ah, bp⟩ := split_dot (fun z m => na z (by simp [m])) (fun z m => nH z (by simp [m])) rest
    exact ⟨by rw [xy, ah], bp⟩

/-- A payload's canonical bytes determine its claims and `enc`. -/
theorem payload_list_inj {p q : Payload} (vp : PayloadValid p) (vq : PayloadValid q) (ep : Plain p.enc.val)
    (eq' : Plain q.enc.val) (same : PayloadList p true = PayloadList q true)
    (small : (PayloadList p true).length + 64 ≤ Usize.max) :
    p.claims = q.claims ∧ p.enc = q.enc ∧ normal p = normal q := by
  have hs : (Slice.from (PayloadList p true) (by omega)).val = PayloadList p true := by simp
  have h1 := parse_payload_of (by rw [hs]; omega) hs vp ep
  have h2 := parse_payload_of (by rw [hs]; omega) (by rw [hs, same]) vq eq'
  rw [h1] at h2
  simp only [Result.ok.injEq, Option.some.injEq] at h2
  exact ⟨by simpa [normal] using congrArg Payload.claims h2, by simpa [normal] using congrArg Payload.enc h2, h2⟩

theorem slice_index_some {α : Type} {s : Slice α} {i : Usize} {x : α} (h : s.val[i.val]? = some x) :
    Slice.index_usize s i = Result.ok x := by
  obtain ⟨inside, e⟩ := List.getElem?_eq_some_iff.mp h
  rw [aivm_secrets_garrett_core.stateless_mailbox.Proofs.slice_index_eq s i inside, e]

/-- `unseal_token` runs to the answer of the selected entry's `open`. -/
theorem unseal_token_of {M : Type} {inst : KeyMaterial M} {entries : Slice (KeyEntry M)}
    {v : stateless.Verified} {e : KeyEntry M} {out : alloc.vec.Vec U8}
    (at_key : entries.val[v.key.val]? = some e) (long : 29 ≤ v.sealed.val.length)
    (opens : ∀ n c : Slice U8, n.val = v.sealed.val.take 12 → c.val = v.sealed.val.drop 12 →
      inst.open e.material n (alloc.vec.Vec.deref v.aad) c = Result.ok (some out)) :
    unseal_token inst entries v = Result.ok (core.result.Result.Ok out) := by
  have inside : v.key.val < entries.val.length := (List.getElem?_eq_some_iff.mp at_key).1
  unfold unseal_token
  simp only
  have notGe : ¬ v.key ≥ Slice.len entries := by simp [Slice.len]; scalar_tac
  simp only [notGe, ↓reduceIte]
  obtain ⟨i2, h2, v2⟩ := returned_of_spec (Usize.add_spec (x := NONCE) (y := TAG) (by unfold NONCE TAG; scalar_tac))
  obtain ⟨i3, h3, v3⟩ := returned_of_spec (Usize.add_spec (x := i2) (y := 1#usize) (by unfold NONCE TAG at v2; scalar_tac))
  rw [h2]; simp only [bind_ok]; rw [h3]; simp only [bind_ok]
  have notLt : ¬ v.sealed.len < i3 := by
    unfold NONCE TAG at v2; simp [alloc.vec.Vec.len]; scalar_tac
  simp only [notLt, ↓reduceIte]
  obtain ⟨n, hn, nv⟩ := returned_of_spec (alloc.vec.Vec.index_RangeTo_spec v.sealed { «end» := NONCE }
    (by unfold NONCE; simp [alloc.vec.Vec.length]; omega))
  obtain ⟨c, hc, cv⟩ := returned_of_spec (alloc.vec.Vec.index_RangeFrom_spec v.sealed { start := NONCE }
    (by unfold NONCE; simp [alloc.vec.Vec.length]; omega))
  rw [hn]; simp only [bind_ok]; rw [hc]; simp only [bind_ok]
  rw [slice_index_some at_key]; simp only [bind_ok]
  rw [opens n c (by rw [nv.1]; unfold NONCE; simp [List.slice]) (by rw [cv.1]; unfold NONCE; simp)]
  simp only [bind_ok]

/-- `m` is the signed part of the three-segment token `t`: its first two
    segments and the dot between them. -/
def SignedPart (t m : List U8) : Prop := ∃ a b c, Segments t a b c ∧ m = a ++ 46#u8 :: b

theorem segments_unique {t a b c a' b' c' : List U8} (h : Segments t a b c) (h' : Segments t a' b' c') :
    a = a' ∧ b = b' ∧ c = c' := by
  obtain ⟨e, na, nb, _⟩ := h
  obtain ⟨e', na', nb', _⟩ := h'
  rw [e] at e'
  obtain ⟨ha, rest⟩ := split_dot na na' e'
  obtain ⟨hb, hc⟩ := split_dot nb nb' rest
  exact ⟨ha, hb, hc⟩

theorem b64_length {l x : List U8} (h : B64 l x) : x.length ≤ l.length := by
  have := congrArg List.length h
  rw [List.length_map, enc_length] at this
  omega

theorem payload_valid_enc {p : Payload} (e : alloc.vec.Vec U8) (h : PayloadValid { p with enc := e }) :
    PayloadValid p := h

/-- **What verifies is what was sealed.** If `verify_token` accepts a token
    whose signed part is the signed part of a token `seal_token` produced,
    then — with no assumption on any primitive — the claims authorization
    receives are the sealed claims, the selected entry has the sealing
    entry's `kid`, and the associated data and sealed bytes are the ones the
    seal used. If the AEAD primitive is correct for the two entries' keys,
    `unseal_token` returns exactly the sealed credential. -/
theorem accepts_sealed {M : Type} {inst : KeyMaterial M} {entries : Slice (KeyEntry M)} {t : Slice U8}
    {v : stateless.Verified} {entry : KeyEntry M} {info : Informational} {claims : stateless.SurrogateClaims}
    {cred nonce : Slice U8} {token : alloc.vec.Vec U8} {m : List U8}
    (keys : KeysValid entries.val)
    (hv : verify_token inst entries t = Result.ok (core.result.Result.Ok v))
    (hs : seal_token inst entry info claims cred nonce = Result.ok (core.result.Result.Ok token))
    (part : SignedPart t.val m) (part' : SignedPart token.val m) :
    ∃ e, entries.val[v.key.val]? = some e ∧ e.kid.val = entry.kid.val ∧ v.claims = claims ∧
      (stateless_boundary.AeadInverse inst entry.material e.material →
        ∃ out : alloc.vec.Vec U8, unseal_token inst entries v = Result.ok (core.result.Result.Ok out) ∧
          out.val = cred.val) := by
  obtain ⟨a, b, c, kid, sig, p, e, tv, tlen, Ha, _, Hb, pvalid, Hc, _, he, ekid, _, _, vclaims, vaad, Henc,
    slen, _⟩ := verify_token_sound keys hv
  obtain ⟨aad, _, ct, _, p0, H, P, S, _, _, nlen, p0claims, _, pvalid0, _, _, aadv, hseal, Hp0enc, HH, HP, _,
    _, _, HS', tokv, _⟩ := seal_token_ok hs
  -- the two signed parts are the same two segments
  obtain ⟨a1, b1, c1, seg1, m1⟩ := part
  obtain ⟨a2, b2, c2, seg2, m2⟩ := part'
  obtain ⟨ea, eb, _⟩ := segments_unique seg1 ⟨tv, b64_no_dot Ha, b64_no_dot Hb, b64_no_dot Hc⟩
  obtain ⟨eH, eP, _⟩ := segments_unique seg2 ⟨tokv, b64_no_dot HH, b64_no_dot HP, b64_no_dot HS'⟩
  subst ea eb eH eP
  obtain ⟨aH, bP⟩ := split_dot seg1.2.1 seg2.2.1 (m1.symm.trans m2)
  subst aH bP
  -- the header: the same `kid`
  have hdr := b64_inj Ha HH
  have kidEq : kid = entry.kid.val := by
    simpa using hdr
  -- the payload: the same claims, `enc` and public members
  have pl := b64_inj Hb HP
  have small : (PayloadList p true).length + 64 ≤ Usize.max := by
    have := b64_length Hb; have := usize_big
    have := congrArg List.length tv
    simp only [List.length_append, List.length_cons] at this
    omega
  obtain ⟨cl, en, nm⟩ := payload_list_inj pvalid (payload_valid_enc _ pvalid0) (enc_plain Henc)
    (enc_plain Hp0enc) pl small
  have sealedEq : v.sealed.val = nonce.val ++ ct.val := by
    rw [en] at Henc; exact b64_inj Henc Hp0enc
  have aadEq : v.aad.val = aad.val := by
    rw [vaad, aadv, kidEq, ← normal_list p false, nm, normal_list]
  refine ⟨e, he, by rw [ekid, kidEq], by rw [vclaims, cl, p0claims], fun aead => ?_⟩
  obtain ⟨_, opens⟩ := aead nonce aad cred ct hseal
  have l12 : (v.sealed.val.take 12).length ≤ Usize.max := by
    have := v.sealed.property; simp only [List.length_take]; omega
  have ld : (v.sealed.val.drop 12).length ≤ Usize.max := by
    have := v.sealed.property; simp only [List.length_drop]; omega
  obtain ⟨out, ho, ov⟩ := opens (Slice.from _ l12) (alloc.vec.Vec.deref v.aad) (Slice.from _ ld)
    (by simp [sealedEq, nlen]) (by rw [deref_val, aadEq]) (by simp [sealedEq, nlen])
  refine ⟨out, unseal_token_of he slen (fun n c hn hc => ?_), ov⟩
  rw [show n = Slice.from _ l12 from Slice.ext _ _ (by simp [hn]), show c = Slice.from _ ld from Slice.ext _ _ (by simp [hc])]
  exact ho

/-- **Informational claims have no influence.** Two tokens sealed by the same
    entry over the same claims — whatever their informational claims
    (`scope`, `upstream`) — verify, if they verify, to the same claims, the
    same key and the same key issuer: everything `admit` reads. -/
theorem informational_no_influence {M : Type} {inst : KeyMaterial M} {entries : Slice (KeyEntry M)}
    {entry : KeyEntry M} {info1 info2 : Informational} {claims : stateless.SurrogateClaims}
    {cred1 cred2 nonce1 nonce2 : Slice U8} {t1 t2 : alloc.vec.Vec U8} {v1 v2 : stateless.Verified}
    (keys : KeysValid entries.val)
    (s1 : seal_token inst entry info1 claims cred1 nonce1 = Result.ok (core.result.Result.Ok t1))
    (s2 : seal_token inst entry info2 claims cred2 nonce2 = Result.ok (core.result.Result.Ok t2))
    (h1 : verify_token inst entries (alloc.vec.Vec.deref t1) = Result.ok (core.result.Result.Ok v1))
    (h2 : verify_token inst entries (alloc.vec.Vec.deref t2) = Result.ok (core.result.Result.Ok v2)) :
    v1.claims = v2.claims ∧ v1.key = v2.key ∧ v1.key_issuer.val = v2.key_issuer.val := by
  have part {t : alloc.vec.Vec U8} {v : stateless.Verified}
      (h : verify_token inst entries (alloc.vec.Vec.deref t) = Result.ok (core.result.Result.Ok v)) :
      ∃ m, SignedPart (alloc.vec.Vec.deref t).val m ∧ SignedPart t.val m := by
    obtain ⟨a, b, c, _, _, _, _, tv, _, Ha, _, Hb, _, Hc, _⟩ := verify_token_sound keys h
    have sp : SignedPart (alloc.vec.Vec.deref t).val (a ++ 46#u8 :: b) :=
      ⟨a, b, c, ⟨tv, b64_no_dot Ha, b64_no_dot Hb, b64_no_dot Hc⟩, rfl⟩
    exact ⟨_, sp, by rw [← deref_val]; exact sp⟩
  obtain ⟨m1, p1, p1'⟩ := part h1
  obtain ⟨m2, p2, p2'⟩ := part h2
  obtain ⟨e1, he1, k1, c1, _⟩ := accepts_sealed keys h1 s1 p1 p1'
  obtain ⟨e2, he2, k2, c2, _⟩ := accepts_sealed keys h2 s2 p2 p2'
  obtain ⟨_, _, _, _, _, _, f1, _, _, _, _, _, _, _, _, hf1, _, _, _, _, _, _, _, iss1⟩ := verify_token_sound keys h1
  obtain ⟨_, _, _, _, _, _, f2, _, _, _, _, _, _, _, _, hf2, _, _, _, _, _, _, _, iss2⟩ := verify_token_sound keys h2
  rw [he1] at hf1; rw [he2] at hf2
  simp only [Option.some.injEq] at hf1 hf2
  subst hf1 hf2
  obtain ⟨i1, ee1⟩ := List.getElem?_eq_some_iff.mp he1
  obtain ⟨i2, ee2⟩ := List.getElem?_eq_some_iff.mp he2
  have same : v1.key.val = v2.key.val :=
    keys_distinct keys _ _ i1 i2 (by rw [ee1, ee2, k1, k2])
  have keyEq : v1.key = v2.key := UScalar.eq_of_val_eq same
  refine ⟨by rw [c1, c2], keyEq, ?_⟩
  rw [iss1, iss2]
  have : e1 = e2 := by rw [← ee1, ← ee2]; simp only [same]
  rw [this]

/-! ## Connections that are still open

`GarrettStatelessConnection` follows a connection loop that returns. A
long-lived connection writes to providers while it is still open, so the
world below records any finite prefix of a connection's steps. -/

section prefixes
open stateless_proxy.Proofs

variable {V C P : Type} (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
  (ch : stateless_proxy.Channel C) (opener : V) (policy : P)
  (routes : Slice stateless_proxy.Route) (a : stateless.Acceptance) (authority peer : Slice U8) (limit : Usize)

/-- The first steps of a connection: from `state` with the channel at `io`
    to `final` with the channel at `after`, each a `connection_step` for the
    connection's own `peer`, the connection open before each. -/
inductive Prefix : C → proxy_controller.Tunnel → C → proxy_controller.Tunnel → Prop where
  | here {io : C} {state : proxy_controller.Tunnel} : Prefix io state io state
  | step {io io1 after : C} {state next final : proxy_controller.Tunnel} (running : state.open = true)
      (stepped : stateless_proxy.connection_step ops pol ch opener policy io state.buffer routes a authority peer limit =
        Result.ok (next, io1))
      (rest : Prefix io1 next after final) : Prefix io state after final

/-- A connection that returned is one of its prefixes. -/
theorem runs_prefix {io after : C} {state : proxy_controller.Tunnel}
    (run : Runs ops pol ch opener policy routes a authority peer limit io state after) :
    ∃ final, Prefix ops pol ch opener policy routes a authority peer limit io state after final := by
  induction run with
  | closed _ => exact ⟨_, .here⟩
  | step running stepped _ ih =>
    obtain ⟨final, rest⟩ := ih
    exact ⟨final, .step running stepped rest⟩

theorem connection_prefix {io after : C}
    (h : stateless_proxy.connection ops pol ch opener policy io routes a authority peer limit = Result.ok after) :
    ∃ final, Prefix ops pol ch opener policy routes a authority peer limit io
      { buffer := alloc.vec.Vec.new U8, «open» := true } after final :=
  runs_prefix ops pol ch opener policy routes a authority peer limit (connection_runs ops pol ch opener policy routes a authority peer limit io after h)

/-- Every prefix of a logged connection logged one `StepLog` segment per step. -/
theorem prefix_logged {io after : C × List ProxyEvent} {state final : proxy_controller.Tunnel}
    (run : Prefix ops pol (logged ch) opener policy routes a authority peer limit io state after final) :
    ∃ segs : List (List ProxyEvent), after.2 = io.2 ++ segs.flatten ∧
      ∀ seg ∈ segs, StepLog ops pol opener policy routes a peer seg := by
  induction run with
  | here => exact ⟨[], by simp, by simp⟩
  | @step io io1 after state next final running stepped rest ih =>
    obtain ⟨seg, log1, ok1⟩ := step_logged ops pol opener policy routes a authority peer limit ch io.1 io.2 state.buffer
      next io1 stepped
    obtain ⟨segs, log2, ok2⟩ := ih
    refine ⟨seg :: segs, by rw [log2, log1]; simp, ?_⟩
    intro s m
    rcases List.mem_cons.mp m with e | m'
    · rw [e]; exact ok1
    · exact ok2 s m'

end prefixes

/-! ## The deployment, as one transition system

A world is the broker's login mailbox with its history, and the record of
every other broker and proxy action. Each step runs one extracted Rust
function on arbitrary inputs: any clock value, any random draw, any TLS peer,
any OAuth answer, any channel behaviour and any configured key set. Steps
interleave arbitrarily. The mailbox is shared state, guarded by one mutex in
`broker.rs`, so its transitions are atomic; renewal and the proxy share no
state with anything (they read only their configuration and their inputs),
so running each atomically loses no interleaving. -/

variable {M P : Type}

/-- The broker's sealer: `seal_token` with one signing entry, one set of
    informational claims and one nonce (`impl SurrogateSealer for TokenSealer`). -/
abbrev Sealing (inst : KeyMaterial M) : stateless.SurrogateSealer (TokenSealer M) :=
  TokenSealer.Insts.Aivm_secrets_garrett_coreStatelessSurrogateSealer inst

/-- A configured key set opens with `verify_token`/`unseal_token`
    (`impl SurrogateOpener for KeySet`). -/
abbrev Opening (inst : KeyMaterial M) : stateless.SurrogateOpener (KeySet M) :=
  KeySet.Insts.Aivm_secrets_garrett_coreStatelessSurrogateOpener inst

theorem sealing_seal (inst : KeyMaterial M) (s : TokenSealer M) (c : stateless.SurrogateClaims) (k : Slice U8) :
    (Sealing inst).seal s c k = seal_token inst s.entry s.info c k (alloc.vec.Vec.deref s.nonce) := rfl

theorem opening_verify (inst : KeyMaterial M) (ks : KeySet M) (t : Slice U8) :
    (Opening inst).verify ks t = verify_token inst (alloc.vec.Vec.deref ks.entries) t := rfl

theorem opening_unseal (inst : KeyMaterial M) (ks : KeySet M) (v : stateless.Verified) :
    (Opening inst).unseal ks v = unseal_token inst (alloc.vec.Vec.deref ks.entries) v := rfl

/-- The public configuration of one deployment. Replicas share it. -/
structure Config (P : Type) where
  login : stateless_login.LoginPolicy
  issue : stateless.IssuePolicy
  acceptance : stateless.Acceptance
  routes : Slice stateless_proxy.Route
  authority : Slice U8
  limit : Usize
  /-- The proxy's static operation policy (`stateless_policy`). -/
  policyInst : stateless_policy.OperationPolicy P
  policy : P

/-- Every broker and proxy action besides the mailbox's own history. -/
inductive Act (M : Type) where
  /-- `renew` for `peer` on the presented token, under the configured key set `keys`. -/
  | renewed (keys : KeySet M) (sealer : TokenSealer M) (token peer : Slice U8) (certExpires : I64)
      (tokenId : Slice U8) (now lifetime : I64) (issued : stateless.Issued)
  /-- Operator issuance (`mint`) of a credential the operator supplied. -/
  | minted (sealer : TokenSealer M) (grant : stateless.Grant) (credential tokenId : Slice U8) (now lifetime : I64)
      (issued : stateless.Issued)
  /-- One whole proxy connection with the authenticated `peer`, under `keys`. -/
  | served (keys : KeySet M) (peer : Slice U8) (log : List stateless_proxy.Proofs.ProxyEvent)

structure World (M : Type) where
  mb : stateless_mailbox.Mailbox
  logins : List stateless_mailbox.Proofs.Event
  acts : List (Act M)

/-- Where a surrogate came from. -/
inductive Source where
  | login (serial : U64)
  | renewal
  | mint

open stateless_mailbox.Proofs in
/-- **The broker issued `token`**, sealing `credential` under `claims` with
    `sealer`: as the end of a login, as a renewal of a token that opened to
    that credential, or as an operator mint. -/
def IssuedIn (inst : KeyMaterial M) (cfg : Config P) (W : World M) (sealer : TokenSealer M)
    (claims : stateless.SurrogateClaims) (credential : Slice U8) (token : alloc.vec.Vec U8) : Source → Prop
  | .login σ => ∃ iss x tok, Event.finished σ (some iss) ∈ W.logins ∧ Event.exchanged x ∈ W.logins ∧
      x.permit.serial = σ ∧ x.token = some tok ∧ alloc.vec.Vec.deref tok.credential = credential ∧
      iss.claims = claims ∧ iss.token = token ∧
      (Sealing inst).seal sealer claims credential = Result.ok (.Ok token)
  | .renewal => ∃ keys t peer ce tid now lifetime,
      Act.renewed keys sealer t peer ce tid now lifetime ⟨claims, token⟩ ∈ W.acts ∧
      ∃ opened : stateless.Opened, stateless.open (Opening inst) keys t cfg.acceptance peer now =
        Result.ok (.Ok opened) ∧ alloc.vec.Vec.deref opened.credential = credential ∧
      (Sealing inst).seal sealer claims credential = Result.ok (.Ok token)
  | .mint => ∃ grant tid now lifetime, Act.minted sealer grant credential tid now lifetime ⟨claims, token⟩ ∈ W.acts ∧
      (Sealing inst).seal sealer claims credential = Result.ok (.Ok token)

/-- **No forgery so far** (the Ed25519 boundary, `SignaturesAuthentic`, for
    this world): every byte string an entry of `keys` verifies is the signed
    part of a token this broker issued with a key paired to it. -/
def Unforged (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) (keys : KeySet M) : Prop :=
  ∀ e ∈ keys.entries.val, ∀ (msg sig : Slice U8), inst.verify e.material msg sig = Result.ok true →
    ∃ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
      Paired sealer.entry.material e.material ∧ SignedPart token.val msg.val

/-- A key set as the shell builds one (`KeySet::new`). -/
def Configured (keys : KeySet M) : Prop := keys_valid (alloc.vec.Vec.deref keys.entries) = Result.ok true

inductive Step (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) : World M → World M → Prop where
  /-- One mailbox transition: start, pending, accept, exchange, finish or poll. -/
  | login {W : World M} {mb' : stateless_mailbox.Mailbox} {L' : List stateless_mailbox.Proofs.Event}
      (run : stateless_mailbox.Proofs.Step (Sealing inst) cfg.login (W.mb, W.logins) (mb', L')) :
      Step inst Paired cfg W { W with mb := mb', logins := L' }
  /-- One renewal; `unforged` is the signature boundary at the moment it verified. -/
  | renew {W : World M} {keys : KeySet M} {sealer : TokenSealer M} {token peer tokenId : Slice U8}
      {ce now lifetime : I64} {issued : stateless.Issued}
      (configured : Configured keys) (unforged : Unforged inst Paired cfg W keys)
      (run : stateless.renew (Opening inst) (Sealing inst) keys sealer cfg.acceptance cfg.issue token peer ce
        tokenId now lifetime = Result.ok (.Ok issued)) :
      Step inst Paired cfg W { W with acts := W.acts ++ [.renewed keys sealer token peer ce tokenId now lifetime issued] }
  /-- One operator mint. -/
  | mint {W : World M} {sealer : TokenSealer M} {grant : stateless.Grant} {credential tokenId : Slice U8}
      {now lifetime : I64} {issued : stateless.Issued}
      (run : stateless.issue (Sealing inst) sealer cfg.issue grant credential tokenId now lifetime =
        Result.ok (.Ok issued)) :
      Step inst Paired cfg W { W with acts := W.acts ++ [.minted sealer grant credential tokenId now lifetime issued] }
  /-- Any finite prefix of one proxy connection — closed or still open — on any
      channel, with any authenticated peer. -/
  | serve {W : World M} {C : Type} (ch : stateless_proxy.Channel C) (io : C) {keys : KeySet M} {peer : Slice U8}
      {after : C × List stateless_proxy.Proofs.ProxyEvent} {final : proxy_controller.Tunnel}
      (configured : Configured keys)
      (run : Prefix (Opening inst) cfg.policyInst (stateless_proxy.Proofs.logged ch) keys cfg.policy cfg.routes cfg.acceptance cfg.authority
        peer cfg.limit (io, []) { buffer := alloc.vec.Vec.new U8, «open» := true } after final) :
      Step inst Paired cfg W { W with acts := W.acts ++ [.served keys peer after.2] }

inductive Reachable (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) : World M → Prop where
  | init {mb : stateless_mailbox.Mailbox} (made : stateless_mailbox.empty = Result.ok mb) :
      Reachable inst Paired cfg ⟨mb, [], []⟩
  | step {W W' : World M} (before : Reachable inst Paired cfg W) (move : Step inst Paired cfg W W') :
      Reachable inst Paired cfg W'

/-- The login part of every reachable world is a reachable mailbox. -/
theorem mailbox_reachable {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    (reach : Reachable inst Paired cfg W) :
    stateless_mailbox.Proofs.Reachable (Sealing inst) cfg.login (W.mb, W.logins) := by
  induction reach with
  | init made => exact .init made
  | step _ move ih =>
    cases move with
    | login run => exact .step ih run
    | renew => exact ih
    | mint => exact ih
    | serve => exact ih

theorem issued_sealed {inst : KeyMaterial M} {cfg : Config P} {W : World M} {sealer : TokenSealer M}
    {claims : stateless.SurrogateClaims} {credential : Slice U8} {token : alloc.vec.Vec U8} {src : Source}
    (h : IssuedIn inst cfg W sealer claims credential token src) :
    (Sealing inst).seal sealer claims credential = Result.ok (.Ok token) := by
  cases src with
  | login σ => obtain ⟨_, _, _, _, _, _, _, _, _, _, s⟩ := h; exact s
  | renewal => obtain ⟨_, _, _, _, _, _, _, _, _, _, _, s⟩ := h; exact s
  | mint => obtain ⟨_, _, _, _, _, s⟩ := h; exact s

theorem deref_any {α : Type} (x : alloc.vec.Vec α) : (alloc.vec.Vec.deref x).val = x.val := by
  simp [alloc.vec.Vec.deref]

theorem configured_keys {keys : KeySet M} (h : Configured keys) : KeysValid keys.entries.val := by
  have := (keys_valid_true _).mp h
  simpa [deref_val] using this

/-- **Whatever opens was issued.** In a world without forgery under `keys`,
    a token that `stateless::open` accepts is a token this broker issued:
    the claims it admitted are the issued claims, and — if the AEAD primitive
    is correct for paired keys — the credential it decrypted is the issued
    credential. -/
theorem opened_issued {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    {keys : KeySet M} (configured : Configured keys) (unforged : Unforged inst Paired cfg W keys)
    (aead : ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V)
    {t peer : Slice U8} {a : stateless.Acceptance} {now : I64} {opened : stateless.Opened}
    (h : stateless.open (Opening inst) keys t a peer now = Result.ok (.Ok opened)) :
    ∃ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
      opened.claims = claims ∧ opened.credential.val = credential.val ∧
      ∃ e ∈ keys.entries.val, e.kid.val = sealer.entry.kid.val ∧ Paired sealer.entry.material e.material := by
  obtain ⟨v, hv, _, oc, hu, _⟩ := stateless.Proofs.open_ok_trace (Opening inst) keys t a peer now opened h
  rw [opening_verify] at hv
  rw [opening_unseal] at hu
  have kv : KeysValid (alloc.vec.Vec.deref keys.entries).val := by
    rw [deref_any]; exact configured_keys configured
  obtain ⟨a1, b1, c1, kid, sig, p, e, tv, _, Ha, _, Hb, _, Hc, _, he, _, _, ⟨body, sigs, bodyv, _, hver⟩, _⟩ :=
    verify_token_sound kv hv
  have eMem : e ∈ keys.entries.val := by
    have := List.mem_of_getElem? he
    rwa [deref_any] at this
  obtain ⟨sealer, claims, credential, token, src, iss, paired, part'⟩ := unforged e eMem body sigs hver
  have part : SignedPart t.val body.val := ⟨a1, b1, c1, ⟨tv, b64_no_dot Ha, b64_no_dot Hb, b64_no_dot Hc⟩, bodyv⟩
  have hs := issued_sealed iss
  rw [sealing_seal] at hs
  obtain ⟨e', he', kidEq, claimsEq, unseals⟩ := accepts_sealed kv hv hs part part'
  rw [he] at he'
  simp only [Option.some.injEq] at he'
  subst he'
  obtain ⟨out, hout, ov⟩ := unseals (aead _ _ paired)
  rw [hu] at hout
  simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at hout
  subst hout
  exact ⟨sealer, claims, credential, token, src, iss, by rw [oc, claimsEq], ov, e, eMem, kidEq, paired⟩

/-! ## Renewal lineage -/

theorem mailbox_step_extends {S : Type} {ops : stateless.SurrogateSealer S} {policy : stateless_login.LoginPolicy}
    {c c' : stateless_mailbox.Mailbox × List stateless_mailbox.Proofs.Event}
    (h : stateless_mailbox.Proofs.Step ops policy c c') : ∃ E, c'.2 = c.2 ++ E := by
  cases h with
  | start => exact ⟨_, rfl⟩
  | pending => exact ⟨[], by simp⟩
  | accept => exact ⟨_, rfl⟩
  | exchange => exact ⟨_, rfl⟩
  | finish => exact ⟨_, rfl⟩
  | poll => exact ⟨_, rfl⟩

/-- Records only accumulate: whatever a world issued, every later world issued. -/
theorem issued_mono {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W W' : World M}
    (move : Step inst Paired cfg W W') {sealer : TokenSealer M} {claims : stateless.SurrogateClaims}
    {credential : Slice U8} {token : alloc.vec.Vec U8} {src : Source}
    (h : IssuedIn inst cfg W sealer claims credential token src) : IssuedIn inst cfg W' sealer claims credential token src := by
  have grow : (∀ e, e ∈ W.logins → e ∈ W'.logins) ∧ (∀ a, a ∈ W.acts → a ∈ W'.acts) := by
    cases move with
    | login run =>
      obtain ⟨E, e⟩ := mailbox_step_extends run
      exact ⟨fun x m => by simp only at e ⊢; rw [e]; exact List.mem_append_left _ m, fun _ m => m⟩
    | renew => exact ⟨fun _ m => m, fun _ m => List.mem_append_left _ m⟩
    | mint => exact ⟨fun _ m => m, fun _ m => List.mem_append_left _ m⟩
    | serve => exact ⟨fun _ m => m, fun _ m => List.mem_append_left _ m⟩
  cases src with
  | login σ =>
    obtain ⟨iss, x, tok, f, ex, rest⟩ := h
    exact ⟨iss, x, tok, grow.1 _ f, grow.1 _ ex, rest⟩
  | renewal =>
    obtain ⟨keys, t, peer, ce, tid, now, lifetime, m, rest⟩ := h
    exact ⟨keys, t, peer, ce, tid, now, lifetime, grow.2 _ m, rest⟩
  | mint =>
    obtain ⟨grant, tid, now, lifetime, m, rest⟩ := h
    exact ⟨grant, tid, now, lifetime, grow.2 _ m, rest⟩

/-- `token` descends from a root issuance (a login's end or an operator mint)
    with the same binding, provider and credential, and a `ren` no later. -/
def Lineage (inst : KeyMaterial M) (cfg : Config P) (W : World M) (claims : stateless.SurrogateClaims)
    (credential : Slice U8) : Prop :=
  ∃ sealer0 claims0 credential0 token0 src0, IssuedIn inst cfg W sealer0 claims0 credential0 token0 src0 ∧
    (src0 = .mint ∨ ∃ σ, src0 = .login σ) ∧
    claims.certificate.val = claims0.certificate.val ∧ claims.provider.val = claims0.provider.val ∧
    claims.renew_until.val ≤ claims0.renew_until.val ∧ credential.val = credential0.val

theorem lineage_mono {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W W' : World M}
    (move : Step inst Paired cfg W W') {claims : stateless.SurrogateClaims} {credential : Slice U8}
    (h : Lineage inst cfg W claims credential) : Lineage inst cfg W' claims credential := by
  obtain ⟨s0, c0, k0, t0, src0, iss, root, rest⟩ := h
  exact ⟨s0, c0, k0, t0, src0, issued_mono move iss, root, rest⟩

theorem root_lineage {inst : KeyMaterial M} {cfg : Config P} {W : World M} {sealer : TokenSealer M}
    {claims : stateless.SurrogateClaims} {credential : Slice U8} {token : alloc.vec.Vec U8} {src : Source}
    (h : IssuedIn inst cfg W sealer claims credential token src) (root : src = .mint ∨ ∃ σ, src = .login σ) :
    Lineage inst cfg W claims credential :=
  ⟨sealer, claims, credential, token, src, h, root, rfl, rfl, le_refl _, rfl⟩

/-- **Renewal never extends a surrogate's life or changes what it is.** In
    every execution in which no signature is forged at a renewal, every
    surrogate the broker ever issued descends from a login or an operator
    mint: same certificate binding, same provider, same credential, and an
    absolute limit (`ren`) no later than the root's — over any number of
    renewals. -/
theorem lineage {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
    (aead : ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V) {W : World M}
    (reach : Reachable inst Paired cfg W) :
    ∀ {sealer claims credential token src}, IssuedIn inst cfg W sealer claims credential token src →
      Lineage inst cfg W claims credential := by
  induction reach with
  | init _ =>
    intro sealer claims credential token src h
    cases src with
    | login σ => obtain ⟨_, _, _, f, _⟩ := h; simp at f
    | renewal => obtain ⟨_, _, _, _, _, _, _, m, _⟩ := h; simp at m
    | mint => obtain ⟨_, _, _, _, m, _⟩ := h; simp at m
  | @step W W' before move ih =>
    intro sealer claims credential token src h
    cases src with
    | login σ => exact root_lineage h (Or.inr ⟨σ, rfl⟩)
    | mint => exact root_lineage h (Or.inl rfl)
    | renewal =>
      obtain ⟨keys, t, peer, ce, tid, now, lifetime, m, opened, ho, oc, hs⟩ := h
      -- an old renewal: the induction hypothesis
      have old : Act.renewed keys sealer t peer ce tid now lifetime ⟨claims, token⟩ ∈ W.acts →
          Lineage inst cfg W' claims credential := fun m' =>
        lineage_mono move (ih (sealer := sealer) (token := token) (src := .renewal)
          ⟨keys, t, peer, ce, tid, now, lifetime, m', opened, ho, oc, hs⟩)
      cases move with
      | login run => exact old m
      | mint run =>
        rcases List.mem_append.mp m with m' | m'
        · exact old m'
        · simp at m'
      | serve ch io configured run =>
        rcases List.mem_append.mp m with m' | m'
        · exact old m'
        · simp at m'
      | @renew keys' sealer' token' peer' tid' ce' now' lifetime' issued' configured unforged run =>
        rcases List.mem_append.mp m with m' | m'
        · exact old m'
        · simp only [List.mem_singleton, Act.renewed.injEq] at m'
          obtain ⟨ek, es, et, ep, ece, etid, enow, elt, eiss⟩ := m'
          subst ek es et ep ece etid enow elt
          obtain ⟨opened', ho', cert1, _, prov1, _, ren1, _, _⟩ :=
            stateless.Proofs.renew_trace (Opening inst) (Sealing inst) keys sealer run
          rw [ho] at ho'
          simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at ho'
          subst ho'
          subst eiss
          simp only at cert1 prov1 ren1
          obtain ⟨s1, c1, k1, t1, src1, iss1, ocl, ocr, _⟩ := opened_issued configured unforged aead ho
          obtain ⟨s0, c0, k0, t0, src0, iss0, root, cert0, prov0, ren0, cred0⟩ := ih iss1
          refine ⟨s0, c0, k0, t0, src0, issued_mono (.renew configured unforged run) iss0, root, ?_, ?_, ?_, ?_⟩
          · rw [cert1, ocl, cert0]
          · rw [prov1, ocl, prov0]
          · rw [ocl] at ren1; omega
          · rw [← oc, deref_val, ocr, cred0]

/-- A login's surrogate is bound to the certificate, provider and subject
    of the client that started that login (`issued_for_starting_peer`). -/
theorem login_root {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    (reach : Reachable inst Paired cfg W) {sealer : TokenSealer M} {claims : stateless.SurrogateClaims}
    {credential : Slice U8} {token : alloc.vec.Vec U8} {σ : U64}
    (h : IssuedIn inst cfg W sealer claims credential token (.login σ)) :
    ∃ st0, stateless_mailbox.Proofs.Event.started st0 σ ∈ W.logins ∧ claims.certificate = st0.certificate ∧
      claims.provider = st0.provider ∧ claims.subject = st0.subject := by
  obtain ⟨iss, _, _, f, _, _, _, _, ic, _⟩ := h
  obtain ⟨st0, m, cert, prov, subj, _⟩ :=
    stateless_mailbox.Proofs.issued_for_starting_peer (mailbox_reachable reach) f
  exact ⟨st0, m, by rw [← ic, cert], by rw [← ic, prov], by rw [← ic, subj]⟩

/-! ## The proxy -/

/-- Every recorded connection is a prefix of a run of the extracted
    connection loop, and so a sequence of per-request `StepLog` segments. -/
theorem served_segs {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    (reach : Reachable inst Paired cfg W) {keys : KeySet M} {peer : Slice U8}
    {log : List stateless_proxy.Proofs.ProxyEvent} (m : Act.served keys peer log ∈ W.acts) :
    Configured keys ∧ ∃ segs : List (List stateless_proxy.Proofs.ProxyEvent), log = segs.flatten ∧
      ∀ seg ∈ segs, stateless_proxy.Proofs.StepLog (Opening inst) cfg.policyInst keys cfg.policy cfg.routes cfg.acceptance peer seg := by
  induction reach with
  | init _ => simp at m
  | step _ move ih =>
    cases move with
    | login run => exact ih m
    | renew _ _ run =>
      rcases List.mem_append.mp m with m' | m'
      · exact ih m'
      · simp at m'
    | mint run =>
      rcases List.mem_append.mp m with m' | m'
      · exact ih m'
      · simp at m'
    | serve ch io configured run =>
      rcases List.mem_append.mp m with m' | m'
      · exact ih m'
      · simp only [List.mem_singleton, Act.served.injEq] at m'
        obtain ⟨ek, ep, el⟩ := m'
        subst ek ep el
        obtain ⟨segs, log, ok⟩ := prefix_logged _ _ _ _ _ _ _ _ _ _ run
        exact ⟨configured, segs, by simpa using log, ok⟩

section guest
open stateless_proxy.Proofs

/-- What one segment writes to the guest. -/
theorem seg_guest {V P : Type} {ops : stateless.SurrogateOpener V} {pol : stateless_policy.OperationPolicy P} {opener : V}
    {policy : P} {routes : Slice stateless_proxy.Route}
    {a : stateless.Acceptance} {peer : Slice U8} {seg : List ProxyEvent} (ok : StepLog ops pol opener policy routes a peer seg)
    {bytes : List U8} (inSeg : ProxyEvent.guestSent bytes ∈ seg) :
    (∃ code refusal, proxy_http.refusal code = Result.ok refusal ∧ bytes = refusal.val) ∨
    ∃ request now served, GuestReply ops pol opener policy routes a peer request now served ∧ bytes = served.reply.val := by
  rcases ok with e | ⟨code, refusal, hr, e⟩ | ⟨request, now, d, E, served, _, slog, reply, shape⟩
  · subst e; cases inSeg
  · subst e
    simp only [List.mem_cons, reduceCtorEq, ProxyEvent.guestSent.injEq, List.not_mem_nil, or_false,
      false_or] at inSeg
    exact Or.inl ⟨code, refusal, hr, inSeg⟩
  · refine Or.inr ⟨request, now, served, reply, ?_⟩
    have noneE : ∀ b, ProxyEvent.guestSent b ∉ E := by
      intro b mb
      cases d with
      | unauthorized _ => rw [slog] at mb; simp at mb
      | refused _ => rw [slog] at mb; simp at mb
      | dispatch index wire opened =>
        rcases slog with e | e | ⟨_, _, e⟩ <;> subst e <;> simp at mb
    rcases shape with ⟨_, e⟩ | ⟨_, e⟩ <;> subst e <;>
      simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false, reduceCtorEq, false_or,
        ProxyEvent.guestSent.injEq] at inSeg <;>
      rcases inSeg with inE | same
    all_goals first | exact absurd inE (noneE _) | exact same

end guest

/-- **Every credential-bearing provider write has an authorized origin.** In
    any execution, each `sent` record of any proxy connection is preceded,
    in that connection's log, by the acknowledged admission of the same route
    and claims; it was decided by `decide_request` for that connection's
    TLS peer on a surrogate taken from the request; and, if no signature
    under the connection's key set was forged and AEAD is correct for paired
    keys, that surrogate is one this broker issued — bound to exactly this
    peer's certificate, for the route's provider — and the bytes sent are
    exactly the encoder's request carrying exactly the issued credential,
    which descends from a login or mint root. -/
theorem send_origin {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
    (aead : ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V) {W : World M}
    (reach : Reachable inst Paired cfg W) {keys : KeySet M} {peer : Slice U8}
    {log : List stateless_proxy.Proofs.ProxyEvent} (m : Act.served keys peer log ∈ W.acts)
    (unforged : Unforged inst Paired cfg W keys)
    {r : Usize} {w : alloc.vec.Vec U8} (sent : stateless_proxy.Proofs.ProxyEvent.sent r w ∈ log) :
    ∃ request now opened, stateless_proxy.Proofs.decide_request (Opening inst) cfg.policyInst keys cfg.policy request cfg.routes
        cfg.acceptance peer now = Result.ok (.dispatch r w opened) ∧
      (∃ A B, log = A ++ [.admitted opened.claims r true, .sent r w] ++ B) ∧
      ∃ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
        opened.claims = claims ∧ opened.credential.val = credential.val ∧
        claims.certificate.val = peer.val ∧ Lineage inst cfg W claims credential ∧
        ∃ (inside : r.val < cfg.routes.length),
          (cfg.routes[r.val]'inside).provider.val = claims.provider.val ∧
          proxy_http.encode_upstream (alloc.vec.Vec.new U8) request
            (alloc.vec.Vec.deref (cfg.routes[r.val]'inside).host)
            (alloc.vec.Vec.deref (cfg.routes[r.val]'inside).rules)
            (alloc.vec.Vec.deref opened.credential) (cfg.routes[r.val]'inside).authentication =
            Result.ok (.Ok (), w) := by
  obtain ⟨configured, segs, log, ok⟩ := served_segs reach m
  rw [log] at sent ⊢
  obtain ⟨seg, inSegs, inSeg⟩ := List.mem_flatten.mp sent
  obtain ⟨request, now, opened, hd, A, B, e⟩ := stateless_proxy.Proofs.seg_sent (Opening inst) cfg.policyInst keys cfg.policy cfg.routes
    cfg.acceptance peer (ok seg inSegs) inSeg
  have order : ∃ A B, segs.flatten = A ++ [.admitted opened.claims r true, .sent r w] ++ B := by
    obtain ⟨s1, s2, split⟩ := List.append_of_mem inSegs
    exact ⟨s1.flatten ++ A, B ++ s2.flatten, by rw [split, e]; simp⟩
  obtain ⟨token, _, ho, inside, prov, wire⟩ := stateless_proxy.Proofs.dispatch_trace (Opening inst) cfg.policyInst keys cfg.policy request
    cfg.routes cfg.acceptance peer now hd
  obtain ⟨sealer, claims, credential, tok, src, iss, oc, ok, _⟩ := opened_issued configured unforged aead ho
  have bound := (stateless.Proofs.open_binds_peer (Opening inst) keys _ cfg.acceptance peer now opened ho).1
  refine ⟨request, now, opened, hd, order, sealer, claims, credential, tok, src, iss, oc, ok, by rw [← oc]; exact bound,
    lineage aead reach iss, inside, by rw [prov, oc], wire⟩

section logs
open stateless_proxy.Proofs

variable {V P : Type} {ops : stateless.SurrogateOpener V} {pol : stateless_policy.OperationPolicy P} {opener : V}
    {policy : P} {routes : Slice stateless_proxy.Route}
  {a : stateless.Acceptance} {peer : Slice U8}

/-- An admission record comes only from a dispatch decision, and records
    the claims of the surrogate that decision opened. -/
theorem seg_admitted {seg : List ProxyEvent} (ok : StepLog ops pol opener policy routes a peer seg)
    {claims : stateless.SurrogateClaims} {r : Usize} {acked : Bool} (m : ProxyEvent.admitted claims r acked ∈ seg) :
    ∃ request now wire opened, decide_request ops pol opener policy request routes a peer now =
      Result.ok (.dispatch r wire opened) ∧ claims = opened.claims := by
  rcases ok with e | ⟨code, bytes, _, e⟩ | ⟨request, now, d, E, served, hd, slog, _, shape⟩
  · subst e; cases m
  · subst e; simp at m
  · have inE : ProxyEvent.admitted claims r acked ∈ E := by
      rcases shape with ⟨_, e⟩ | ⟨_, e⟩ <;> subst e <;> simpa using m
    cases d with
    | unauthorized _ => rw [slog] at inE; simp at inE
    | refused _ => rw [slog] at inE; simp at inE
    | dispatch index wire opened =>
      rcases slog with e | e | ⟨status, acked', e⟩ <;> subst e <;>
        simp only [List.mem_cons, ProxyEvent.admitted.injEq, List.not_mem_nil, or_false, reduceCtorEq] at inE <;>
        obtain ⟨rfl, rfl, _⟩ := inE <;> exact ⟨request, now, wire, opened, hd, rfl⟩

/-- A request refused before egress — its surrogate rejected, or any
    pre-egress refusal — records no `sent`; and no request records two. -/
theorem seg_rejected_quiet {seg : List ProxyEvent} (ok : StepLog ops pol opener policy routes a peer seg)
    {rej : stateless.Rejection} (m : ProxyEvent.rejected rej ∈ seg) {r : Usize} {w : alloc.vec.Vec U8} :
    ProxyEvent.sent r w ∉ seg := by
  intro ms
  obtain ⟨request, now, opened, hd, A, B, e⟩ := seg_sent ops pol opener policy routes a peer ok ms
  rcases ok with e' | ⟨code, bytes, _, e'⟩ | ⟨request', now', d, E, served, hd', slog, _, shape⟩
  · subst e'; cases m
  · subst e'; simp at m
  · have inE : ProxyEvent.rejected rej ∈ E := by
      rcases shape with ⟨_, e'⟩ | ⟨_, e'⟩ <;> subst e' <;> simpa using m
    have inE' : ProxyEvent.sent r w ∈ E := by
      rcases shape with ⟨_, e'⟩ | ⟨_, e'⟩ <;> subst e' <;> simpa using ms
    cases d with
    | unauthorized _ => rw [slog] at inE'; simp at inE'
    | refused _ => rw [slog] at inE; simp at inE
    | dispatch index wire opened' =>
      rcases slog with e'' | e'' | ⟨status, acked, e''⟩ <;> subst e'' <;> simp at inE

end logs

/-- **A rejection creates no send.** Every recorded connection's log is a
    sequence of per-request segments; a segment with a rejection has no
    `sent`, and no segment has more than one. -/
theorem rejection_never_sends {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    (reach : Reachable inst Paired cfg W) {keys : KeySet M} {peer : Slice U8}
    {log : List stateless_proxy.Proofs.ProxyEvent} (m : Act.served keys peer log ∈ W.acts) :
    ∃ segs : List (List stateless_proxy.Proofs.ProxyEvent), log = segs.flatten ∧ ∀ seg ∈ segs,
      seg.countP stateless_proxy.Proofs.ProxyEvent.isSent ≤ 1 ∧
      ∀ rej, stateless_proxy.Proofs.ProxyEvent.rejected rej ∈ seg →
        ∀ r w, stateless_proxy.Proofs.ProxyEvent.sent r w ∉ seg := by
  obtain ⟨_, segs, log, ok⟩ := served_segs reach m
  exact ⟨segs, log, fun seg ms => ⟨stateless_proxy.Proofs.seg_sends_at_most_once (Opening inst) cfg.policyInst keys cfg.policy cfg.routes
    cfg.acceptance peer (ok seg ms), fun rej mr r w => seg_rejected_quiet (ok seg ms) mr⟩⟩

/-! ## Key retirement -/

/-- **A retired `kid` opens nothing.** Under a configured key set, a token
    is accepted only if the `kid` of its header names an entry of that set:
    once a `kid` is removed, no token carrying it verifies, opens, renews or
    reaches a provider. -/
theorem kid_configured {inst : KeyMaterial M} {keys : KeySet M} (configured : Configured keys)
    {t : Slice U8} {v : stateless.Verified} (h : (Opening inst).verify keys t = Result.ok (.Ok v))
    {x y z kid : List U8} (seg : Segments t.val x y z) (header : B64 x (HS ++ kid ++ HE)) :
    ∃ e ∈ keys.entries.val, e.kid.val = kid := by
  rw [opening_verify] at h
  have kv : KeysValid (alloc.vec.Vec.deref keys.entries).val := by
    rw [deref_any]; exact configured_keys configured
  obtain ⟨a1, b1, c1, kid', _, _, e, tv, _, Ha, _, Hb, _, Hc, _, he, ekid, _⟩ := verify_token_sound kv h
  obtain ⟨ea, _, _⟩ := segments_unique seg ⟨tv, b64_no_dot Ha, b64_no_dot Hb, b64_no_dot Hc⟩
  subst ea
  have same : kid' = kid := by simpa using b64_inj Ha header
  refine ⟨e, ?_, by rw [ekid, same]⟩
  have := List.mem_of_getElem? he
  rwa [deref_any] at this

theorem retired_never_opens {inst : KeyMaterial M} {keys : KeySet M} (configured : Configured keys)
    {t peer : Slice U8} {a : stateless.Acceptance} {now : I64} {opened : stateless.Opened}
    {x y z kid : List U8} (seg : Segments t.val x y z) (header : B64 x (HS ++ kid ++ HE))
    (retired : ∀ e ∈ keys.entries.val, e.kid.val ≠ kid) :
    stateless.open (Opening inst) keys t a peer now ≠ Result.ok (.Ok opened) := by
  intro h
  obtain ⟨v, hv, _⟩ := stateless.Proofs.open_ok_trace (Opening inst) keys t a peer now opened h
  obtain ⟨e, me, ek⟩ := kid_configured configured hv seg header
  exact retired e me ek

/-! ## Disclosure -/

/-- The string claims every surrogate carries in the clear. -/
def ClaimFields (c : stateless.SurrogateClaims) : List (List U8) :=
  [c.issuer.val, c.audience.val, c.subject.val, c.token_id.val, c.provider.val, c.certificate.val]

/-- The public payload, as its members. -/
def PublicSegs (p : Payload) : List (List U8) :=
  [lit "{\"aud\":", Q p.claims.audience.val, lit ",\"cnf\":{\"x5t#S256\":", Q p.claims.certificate.val, [125#u8],
   lit ",\"exp\":", http_wire.Proofs.Digits p.claims.expires_at.val.toNat,
   lit ",\"iat\":", http_wire.Proofs.Digits p.claims.issued_at.val.toNat,
   lit ",\"iss\":", Q p.claims.issuer.val, lit ",\"jti\":", Q p.claims.token_id.val,
   lit ",\"prv\":", Q p.claims.provider.val, lit ",\"ren\":", http_wire.Proofs.Digits p.claims.renew_until.val.toNat,
   (if p.info.has_scope then lit ",\"scope\":" ++ Q p.info.scope.val else []),
   lit ",\"sub\":", Q p.claims.subject.val,
   (if p.info.has_upstream then lit ",\"upstream\":" ++ p.info.upstream.val else []), [125#u8]]

theorem public_segs (p : Payload) : PayloadList p false = (PublicSegs p).flatten := by
  simp [PayloadList, PublicSegs]

theorem claim_fields_public (p : Payload) : ∀ f ∈ ClaimFields p.claims, f <:+: PayloadList p false := by
  intro f mf
  have inner : ∀ l : List U8, l <:+: Q l := fun l => ⟨[34#u8], [34#u8], by simp [Q]⟩
  rw [public_segs]
  simp only [ClaimFields, List.mem_cons, List.not_mem_nil, or_false] at mf
  rcases mf with e | e | e | e | e | e <;> subst e <;> exact (inner _).trans (List.infix_of_mem_flatten (by simp [PublicSegs]))

/-- **No issued surrogate shows its credential.** For every token the broker
    issued, the credential occurs in neither the signed header nor any public
    member of the payload — in particular in no claim; it leaves the broker
    only as the plaintext of the AEAD `seal` primitive. -/
theorem issued_secret {inst : KeyMaterial M} {cfg : Config P} {W : World M} {sealer : TokenSealer M}
    {claims : stateless.SurrogateClaims} {credential : Slice U8} {token : alloc.vec.Vec U8} {src : Source}
    (h : IssuedIn inst cfg W sealer claims credential token src) :
    ¬ credential.val <:+: (HS ++ sealer.entry.kid.val ++ HE) ∧
    (∃ p : Payload, p.claims = claims ∧ ¬ credential.val <:+: PayloadList p false) ∧
    ∀ f ∈ ClaimFields claims, ¬ credential.val <:+: f := by
  have hs := issued_sealed h
  rw [sealing_seal] at hs
  obtain ⟨_, _, _, _, p, _, _, _, _, _, _, pc, _, _, notH, notP, _⟩ := seal_token_ok hs
  refine ⟨notH, ⟨p, pc, notP⟩, fun f mf inf => notP (inf.trans (claim_fields_public p f (by rw [pc]; exact mf)))⟩

/-- What a proxy record may carry. -/
def Permitted (inst : KeyMaterial M) (cfg : Config P) (W : World M) (keys : KeySet M) (peer : Slice U8) :
    stateless_proxy.Proofs.ProxyEvent → Prop
  -- the claims of a surrogate this broker issued, which never contain its credential
  | .admitted claims _ _ => ∃ sealer credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
      claims.certificate.val = peer.val ∧ ∀ f ∈ ClaimFields claims, ¬ credential.val <:+: f
  -- exactly the encoder's request for an issued credential, on its route
  | .sent r w => ∃ request now opened, stateless_proxy.Proofs.decide_request (Opening inst) cfg.policyInst keys cfg.policy request cfg.routes
        cfg.acceptance peer now = Result.ok (.dispatch r w opened) ∧
      ∃ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
        opened.credential.val = credential.val ∧ claims.certificate.val = peer.val
  -- a fixed refusal, or a reply released by `guest_response`
  | .guestSent bytes => (∃ code refusal, proxy_http.refusal code = Result.ok refusal ∧ bytes = refusal.val) ∨
      ∃ request now served, stateless_proxy.Proofs.GuestReply (Opening inst) cfg.policyInst keys cfg.policy cfg.routes cfg.acceptance peer
        request now served ∧ bytes = served.reply.val
  -- codes, statuses and the guest's own request: nothing of a credential
  | .began _ | .rejected _ | .completed _ _ | .refused _ | .stopped _ => True

/-- **Every proxy output is permitted.** In any execution, under the
    signature and AEAD boundaries, every record of every proxy connection is
    one of: the guest's own request; a rejection code; the admission of a
    surrogate this broker issued for this very peer, whose claims do not
    contain its credential; exactly the encoder's request for that
    credential (the one permitted effect); a status or refusal code; or bytes
    to the guest that are a fixed refusal or a `guest_response` release (in
    which the raw credential does not occur, `serve_guest_reply`). -/
theorem log_permitted {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
    (aead : ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V) {W : World M}
    (reach : Reachable inst Paired cfg W) {keys : KeySet M} {peer : Slice U8}
    {log : List stateless_proxy.Proofs.ProxyEvent} (m : Act.served keys peer log ∈ W.acts)
    (unforged : Unforged inst Paired cfg W keys) :
    ∀ ev ∈ log, Permitted inst cfg W keys peer ev := by
  intro ev mev
  obtain ⟨configured, segs, log, ok⟩ := served_segs reach m
  have mev' := mev
  rw [log] at mev'
  obtain ⟨seg, inSegs, inSeg⟩ := List.mem_flatten.mp mev'
  cases ev with
  | admitted claims r acked =>
    obtain ⟨request, now, wire, opened, hd, ce⟩ := seg_admitted (ok seg inSegs) inSeg
    obtain ⟨_, _, ho, _⟩ := stateless_proxy.Proofs.dispatch_trace (Opening inst) cfg.policyInst keys cfg.policy request cfg.routes
      cfg.acceptance peer now hd
    obtain ⟨sealer, c, credential, token, src, iss, oc, _, _⟩ := opened_issued configured unforged aead ho
    have bound := (stateless.Proofs.open_binds_peer (Opening inst) keys _ cfg.acceptance peer now opened ho).1
    subst ce
    rw [oc] at bound ⊢
    exact ⟨sealer, credential, token, src, iss, bound, (issued_secret iss).2.2⟩
  | sent r w =>
    obtain ⟨request, now, opened, hd, _, sealer, claims, credential, token, src, iss, _, ok, cert, _⟩ :=
      send_origin aead reach m unforged mev
    exact ⟨request, now, opened, hd, sealer, claims, credential, token, src, iss, ok, cert⟩
  | guestSent bytes => exact seg_guest (ok seg inSegs) inSeg
  | began _ => trivial
  | rejected _ => trivial
  | completed _ _ => trivial
  | refused _ => trivial
  | stopped _ => trivial

/-! ## Logins, delivery and the global statement -/

section logins
open stateless_mailbox.Proofs

/-- **A delivered surrogate belongs to its initiator.** Every surrogate the
    mailbox hands out goes to the certificate that began its login, is the
    surrogate issued for that login, is bound to that certificate, and is one
    this broker issued (so `issued_secret` applies to it). -/
theorem delivered_to_initiator {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    (reach : Reachable inst Paired cfg W) {σ : U64} {peer : List U8} {t : alloc.vec.Vec U8}
    (del : Event.delivered σ peer t ∈ W.logins) :
    ∃ st0 sealer claims credential, Event.started st0 σ ∈ W.logins ∧ peer = st0.certificate.val ∧
      claims.certificate = st0.certificate ∧ IssuedIn inst cfg W sealer claims credential t (.login σ) := by
  obtain ⟨st0, iss, m, hp, fin, ht, cert⟩ := delivered_to_starting_peer (mailbox_reachable reach) del
  obtain ⟨_, _, _, _, _, _, x, tok, ex, xs, xt, _, sealer, hs⟩ := issued_for_starting_peer (mailbox_reachable reach) fin
  subst ht
  exact ⟨st0, sealer, iss.claims, _, m, hp, cert, iss, x, tok, fin, ex, xs, xt, rfl, rfl, rfl, hs⟩

/-- **No login is exchanged, issued or delivered twice**, whatever the
    interleaving of callbacks, polls and replays. -/
theorem login_once {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    (reach : Reachable inst Paired cfg W) (σ : U64) :
    cnt (isAcc σ) W.logins ≤ 1 ∧ cnt (isExch σ) W.logins ≤ 1 ∧ cnt (isFin σ) W.logins ≤ 1 ∧
      cnt (isDel σ) W.logins ≤ 1 :=
  at_most_once (mailbox_reachable reach) σ

/-- **A failed or uncertain exchange issues and delivers nothing.** -/
theorem failed_login_quiet {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} {W : World M}
    (reach : Reachable inst Paired cfg W) {σ : U64} (failed : Event.finished σ none ∈ W.logins) :
    (∀ peer t, Event.delivered σ peer t ∉ W.logins) ∧ ∀ iss, Event.finished σ (some iss) ∉ W.logins :=
  failed_never_delivered (mailbox_reachable reach) failed

end logins

/-- **Every provider write traces to its root.** The credential a proxy
    sends is either one an operator minted for a certificate, or the token
    that the code exchange of a login returned — a login started by a client
    holding exactly the certificate of the connection that sends it. -/
theorem send_root {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
    (aead : ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V) {W : World M}
    (reach : Reachable inst Paired cfg W) {keys : KeySet M} {peer : Slice U8}
    {log : List stateless_proxy.Proofs.ProxyEvent} (m : Act.served keys peer log ∈ W.acts)
    (unforged : Unforged inst Paired cfg W keys)
    {r : Usize} {w : alloc.vec.Vec U8} (sent : stateless_proxy.Proofs.ProxyEvent.sent r w ∈ log) :
    ∃ opened : stateless.Opened, (∃ request now, stateless_proxy.Proofs.decide_request (Opening inst) cfg.policyInst keys cfg.policy request
        cfg.routes cfg.acceptance peer now = Result.ok (.dispatch r w opened)) ∧
      ((∃ sealer0 claims0 credential0 token0, IssuedIn inst cfg W sealer0 claims0 credential0 token0 .mint ∧
          claims0.certificate.val = peer.val ∧ opened.credential.val = credential0.val) ∨
       (∃ σ st0 x tok, stateless_mailbox.Proofs.Event.started st0 σ ∈ W.logins ∧ st0.certificate.val = peer.val ∧
          stateless_mailbox.Proofs.Event.exchanged x ∈ W.logins ∧ x.permit.serial = σ ∧ x.token = some tok ∧
          opened.credential.val = tok.credential.val)) := by
  obtain ⟨request, now, opened, hd, _, sealer, claims, credential, token, src, iss, _, ok, cert, lin, _⟩ :=
    send_origin aead reach m unforged sent
  obtain ⟨s0, c0, k0, t0, src0, iss0, root, cert0, _, _, cred0⟩ := lin
  refine ⟨opened, ⟨request, now, hd⟩, ?_⟩
  rcases root with e | ⟨σ, e⟩ <;> subst e
  · exact Or.inl ⟨s0, c0, k0, t0, iss0, by rw [← cert0, cert], by rw [ok, cred0]⟩
  · obtain ⟨st0, started, c0cert, _, _⟩ := login_root reach iss0
    obtain ⟨_, x, tok, _, ex, xs, xt, kc, _⟩ := iss0
    refine Or.inr ⟨σ, st0, x, tok, started, by rw [← c0cert, ← cert0, cert], ex, xs, xt, ?_⟩
    rw [ok, cred0, ← kc, deref_any]

/-- **Internal protocol safety of `garrett-stateless-v1`.** For every
    finite execution of the extracted broker and proxy — any interleaving
    of login starts, callbacks, code exchanges with any OAuth answer,
    issuance, polls, renewals, operator mints, key-set changes and proxy
    connections over any channel, clock, randomness and TLS peer — and
    assuming only the external boundary (AES-GCM is correct for paired keys;
    no Ed25519 signature was forged before a renewal or under a proxy's key
    set):

    1. every provider write was decided for an issued surrogate bound to the
       connection's own peer, follows its acknowledged admission, carries
       exactly the issued credential in exactly the encoder's bytes for the
       surrogate's provider route, and descends from a login or mint;
    2. a rejected request sends nothing, and no request sends twice;
    3. every delivered surrogate goes to, and is bound to, the client that
       began its login; no login is exchanged, issued or delivered twice;
    4. renewal never extends `ren` or changes binding, provider or
       credential, however many times it is applied;
    5. every proxy record is one of the permitted forms, and no issued
       surrogate shows its credential in its header, payload or claims. -/
theorem protocol_safety {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
    (aead : ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V) {W : World M}
    (reach : Reachable inst Paired cfg W) :
    -- 1, 2, 5: every connection under a key set without forgery
    (∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
      (∀ r w, stateless_proxy.Proofs.ProxyEvent.sent r w ∈ log →
        ∃ request now opened, stateless_proxy.Proofs.decide_request (Opening inst) cfg.policyInst keys cfg.policy request cfg.routes
            cfg.acceptance peer now = Result.ok (.dispatch r w opened) ∧
          (∃ A B, log = A ++ [.admitted opened.claims r true, .sent r w] ++ B) ∧
          ∃ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
            opened.claims = claims ∧ opened.credential.val = credential.val ∧
            claims.certificate.val = peer.val ∧ Lineage inst cfg W claims credential) ∧
      (∀ ev ∈ log, Permitted inst cfg W keys peer ev)) ∧
    (∀ keys peer log, Act.served keys peer log ∈ W.acts →
      ∃ segs : List (List stateless_proxy.Proofs.ProxyEvent), log = segs.flatten ∧ ∀ seg ∈ segs,
        seg.countP stateless_proxy.Proofs.ProxyEvent.isSent ≤ 1 ∧
        ∀ rej, stateless_proxy.Proofs.ProxyEvent.rejected rej ∈ seg →
          ∀ r w, stateless_proxy.Proofs.ProxyEvent.sent r w ∉ seg) ∧
    -- 3
    (∀ σ peer t, stateless_mailbox.Proofs.Event.delivered σ peer t ∈ W.logins →
      ∃ st0 sealer claims credential, stateless_mailbox.Proofs.Event.started st0 σ ∈ W.logins ∧
        peer = st0.certificate.val ∧ claims.certificate = st0.certificate ∧
        IssuedIn inst cfg W sealer claims credential t (.login σ)) ∧
    (∀ σ, stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isAcc σ) W.logins ≤ 1 ∧
      stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isExch σ) W.logins ≤ 1 ∧
      stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isFin σ) W.logins ≤ 1 ∧
      stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isDel σ) W.logins ≤ 1) ∧
    -- 4, 5
    (∀ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src →
      Lineage inst cfg W claims credential ∧ ∀ f ∈ ClaimFields claims, ¬ credential.val <:+: f) := by
  refine ⟨fun keys peer log m unforged => ⟨fun r w sent => ?_, log_permitted aead reach m unforged⟩,
    fun keys peer log m => rejection_never_sends reach m,
    fun σ peer t del => delivered_to_initiator reach del,
    fun σ => login_once reach σ,
    fun sealer claims credential token src iss => ⟨lineage aead reach iss, (issued_secret iss).2.2⟩⟩
  obtain ⟨request, now, opened, hd, order, sealer, claims, credential, token, src, iss, oc, ok, cert, lin, _⟩ :=
    send_origin aead reach m unforged sent
  exact ⟨request, now, opened, hd, order, sealer, claims, credential, token, src, iss, oc, ok, cert, lin⟩

end aivm_secrets_garrett_core.stateless_protocol
