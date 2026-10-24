import Garrett
import GarrettRoute
import GarrettJsonWire

/-!
# The guest's control verbs: `describe` and `renounce`

Source: `rust/crates/aivm-secrets-garrett-core/src/control.rs`, extracted by
Aeneas. Both native sessions (`custody.rs` account profile and
`custody/manifest_session.rs` manifest profile) call `control::control`
after the capability is authorized, supplying three side effects
(`Control`: revoke the control state, durably append an audit record,
deactivate the grant). The revocation record itself is built here
(`revoked_record`) and encoded by the extracted JSON encoder; the native
`record` callback is the session audit's `append_bytes`, which runs the
extracted `audit_record::append_durable_record` (as read-path records do). The reply value is framed by the extracted JSON encoder.

Proved here, for **any** callbacks:

* `control_paths`: `renounce` revokes first, then passes exactly the
  encoder's bytes for the revocation record to `record`; only if the
  record succeeds is the grant deactivated and `renounced` replied, otherwise
  the error is returned with no reply (the control state stays revoked).
  `describe` replies with the description and invokes no callback. Any
  other verb is `Denied` and invokes no callback. No path can reach a
  provider: `Control` has no provider operation.
* `renounce_records_exactly`, `revoked_record_exact`: those bytes are the
  encoding of `{"event":"revoked","grant":G,["operation":O,]"policy":P,
  "schema":1}`, whose only inputs are the session's grant, policy and the
  account profile's operation name;
* `manifest_description_exact`: the manifest description is exactly the
  policy's operation names (as text, in order), the fixed profile name, the
  fixed request limit and the write mode's name; nothing else is an input.

A Rust oracle test (`custody::control_oracle`) checks that the framed bytes
equal the serde replies these functions replaced.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.route.Proofs (bind_ok_inv push_ok_val index_usize_eq add_one_eq)
open aivm_secrets_garrett_core.proxy_http.Proofs (slice_eq_eq)
set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace aivm_secrets_garrett_core.control.Proofs

/-- The text units of ASCII bytes. -/
def Units (bytes : List U8) : List U32 := bytes.map (fun b => UScalar.cast .U32 b)

def RenounceVerb : List U8 := [114#u8, 101#u8, 110#u8, 111#u8, 117#u8, 110#u8, 99#u8, 101#u8]
def DescribeVerb : List U8 := [100#u8, 101#u8, 115#u8, 99#u8, 114#u8, 105#u8, 98#u8, 101#u8]

/-! ## Text -/

theorem text_loop_ok (bytes : Slice U8) :
    ∀ n (out r : alloc.vec.Vec U32) (index : Usize), bytes.length - index.val = n →
      text_loop bytes out index = Result.ok r → r.val = out.val ++ Units (bytes.val.drop index.val) := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out r index measure h
    rw [text_loop.eq_def] at h
    dsimp only at h
    split at h
    · rename_i inside
      obtain ⟨b, indexed, h⟩ := bind_ok_inv h
      rw [index_usize_eq bytes index (by scalar_tac)] at indexed
      simp only [Result.ok.injEq] at indexed
      have cons : bytes.val.drop index.val = b :: bytes.val.drop (index.val + 1) := by
        rw [← indexed]; exact List.drop_eq_getElem_cons (by scalar_tac)
      simp only [bind_ok, lift] at h
      obtain ⟨out1, pushed, h⟩ := bind_ok_inv h
      obtain ⟨next, added, value⟩ := add_one_eq index (by scalar_tac)
      simp only [added, bind_ok] at h
      have rest := ih (bytes.length - next.val) (by scalar_tac) out1 r next rfl h
      rw [rest, push_ok_val pushed, value, cons]
      simp [Units]
    · simp only [Result.ok.injEq] at h
      subst h
      have : bytes.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
      simp [this, Units]

theorem text_ok {bytes : Slice U8} {v : json_wire.Value} (h : text bytes = Result.ok v) :
    ∃ units : alloc.vec.Vec U32, v = .Text units ∧ units.val = Units bytes.val := by
  unfold text at h
  obtain ⟨out, looped, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  refine ⟨out, rfl, ?_⟩
  have := text_loop_ok bytes _ (alloc.vec.Vec.new U32) out 0#usize rfl looped
  simpa [alloc.vec.Vec.new] using this

/-! ## The control verbs -/

variable {C E : Type}

/-- **The control verbs' only paths.** Any returned `control` took exactly
    one of these, for any native callbacks:
    1. `renounce`: `revoke`, then encode `revoked` with the extracted JSON
       encoder and pass **exactly those bytes** to `record`; on success mark
       the grant inactive and reply `renounced`; on failure return the error,
       no reply, grant untouched; if encoding fails, `Unencodable`, nothing
       recorded, grant untouched;
    2. `describe`: reply with the description, no callback, grant untouched;
    3. anything else: `Denied`, no callback, grant untouched. -/
theorem control_paths (inst : Control C E) (io : C) (grant : credential_use.UseGrant)
    (verb : Slice U8) (description revoked : json_wire.Value)
    (out : Controlled E) (after : C) (grant' : credential_use.UseGrant)
    (h : control.control inst io grant verb description revoked = Result.ok (out, after, grant')) :
    (verb.val = RenounceVerb ∧ ∃ io1 encoded bytes, inst.revoke io = Result.ok io1 ∧
      json_wire.append (alloc.vec.Vec.new U8) revoked = Result.ok (encoded, bytes) ∧
      ((encoded = false ∧ out = .Unencodable ∧ after = io1 ∧ grant' = grant) ∨
       (encoded = true ∧ ∃ io2 r, inst.record io1 (alloc.vec.Vec.deref bytes) = Result.ok (r, io2) ∧
        ((∃ reply, r = .Ok () ∧ renounced = Result.ok reply ∧ out = .Reply reply ∧
            after = io2 ∧ grant' = { grant with active := false }) ∨
         (∃ error, r = .Err error ∧ out = .Failed error ∧ after = io2 ∧ grant' = grant))))) ∨
    (verb.val = DescribeVerb ∧ ∃ reply, described description = Result.ok reply ∧
      out = .Reply reply ∧ after = io ∧ grant' = grant) ∨
    (verb.val ≠ RenounceVerb ∧ verb.val ≠ DescribeVerb ∧ out = .Denied ∧ after = io ∧
      grant' = grant) := by
  unfold control.control at h
  simp only [lift, Array.to_slice, Array.make, bind_ok, slice_eq_eq] at h
  split at h
  · rename_i is_renounce
    simp only [decide_eq_true_eq] at is_renounce
    left
    refine ⟨by simpa [RenounceVerb] using is_renounce, ?_⟩
    obtain ⟨io1, revoked_ok, h⟩ := bind_ok_inv h
    obtain ⟨⟨encoded, bytes⟩, appended, h⟩ := bind_ok_inv h
    refine ⟨io1, encoded, bytes, revoked_ok, appended, ?_⟩
    cases encoded with
    | false =>
      have h : Result.ok (Controlled.Unencodable, io1, grant) = Result.ok (out, after, grant') := h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      exact Or.inl ⟨rfl, h.1.symm, h.2.1.symm, h.2.2.symm⟩
    | true =>
      refine Or.inr ⟨rfl, ?_⟩
      obtain ⟨⟨r, io2⟩, recorded, h⟩ := bind_ok_inv h
      refine ⟨io2, r, recorded, ?_⟩
      cases r with
      | Ok u =>
        cases u
        obtain ⟨reply, replied, h⟩ := bind_ok_inv h
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨o, a, g⟩ := h
        exact Or.inl ⟨reply, rfl, replied, o.symm, a.symm, g.symm⟩
      | Err error =>
        have h : Result.ok (Controlled.Failed error, io2, grant) = Result.ok (out, after, grant') := h
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨o, a, g⟩ := h
        exact Or.inr ⟨error, rfl, o.symm, a.symm, g.symm⟩
  · rename_i not_renounce
    simp only [decide_eq_true_eq] at not_renounce
    split at h
    · rename_i is_describe
      simp only [decide_eq_true_eq] at is_describe
      obtain ⟨reply, replied, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨o, a, g⟩ := h
      exact Or.inr (Or.inl ⟨by simpa [DescribeVerb] using is_describe, reply, replied,
        o.symm, a.symm, g.symm⟩)
    · rename_i not_describe
      simp only [decide_eq_true_eq] at not_describe
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨o, a, g⟩ := h
      exact Or.inr (Or.inr ⟨by simpa [RenounceVerb] using not_renounce,
        by simpa [DescribeVerb] using not_describe, o.symm, a.symm, g.symm⟩)

/-- **A renounce the guest saw succeed ended the grant.** If `renounce`
    replied, the grant it returns is inactive. On every other outcome the
    grant is returned unchanged. -/
theorem renounce_reply_deactivates (inst : Control C E) (io : C) (grant : credential_use.UseGrant)
    (verb : Slice U8) (description revoked : json_wire.Value)
    (out : Controlled E) (after : C) (grant' : credential_use.UseGrant)
    (h : control.control inst io grant verb description revoked = Result.ok (out, after, grant'))
    (renounce : verb.val = RenounceVerb) (replied : ∃ reply, out = .Reply reply) :
    grant'.active = false := by
  rcases control_paths inst io grant verb description revoked out after grant' h with
    ⟨_, io1, encoded, bytes, _, _, paths⟩ | ⟨describe, _⟩ | ⟨not_renounce, _⟩
  · rcases paths with ⟨_, rfl, _, _⟩ | ⟨_, io2, r, _, ⟨reply, _, _, _, _, rfl⟩ | ⟨error, _, rfl, _, _⟩⟩
    · obtain ⟨_, h⟩ := replied; cases h
    · rfl
    · obtain ⟨_, h⟩ := replied; cases h
  · simp [renounce, RenounceVerb, DescribeVerb] at describe
  · exact absurd renounce not_renounce

/-- **After a recorded renounce, every later use of the grant is refused.**
    This is the same `authorize_use` the request path's current-admission
    controller runs, so no request can use a grant the guest renounced. -/
theorem renounced_grant_refuses_every_use (inst : Control C E) (io : C)
    (grant : credential_use.UseGrant) (verb : Slice U8) (description revoked : json_wire.Value)
    (out : Controlled E) (after : C) (grant' : credential_use.UseGrant)
    (h : control.control inst io grant verb description revoked = Result.ok (out, after, grant'))
    (renounce : verb.val = RenounceVerb) (replied : ∃ reply, out = .Reply reply)
    (claims : credential_use.UseClaims) (operation : alloc.vec.Vec U8) (now elapsed : I64) :
    credential_use.authorize_use claims grant' operation now elapsed =
      Result.ok (.Err credential_use.UseDenial.InvalidCapability) := by
  have inactive := renounce_reply_deactivates inst io grant verb description revoked out after
    grant' h renounce replied
  rw [credential_use.Proofs.authorize_use_exact]
  simp [credential_use.Proofs.Current, inactive]

/-- **The audit record of a renounced grant is exactly the encoding of
    `revoked`.** Whenever `renounce` called `record`, its argument was the
    extracted encoder's bytes for `revoked` (`json_wire.Proofs.Bytes`), for
    any fuel that bounds the value: read it with `control_paths`, which says
    `record` received exactly the bytes of this `append`. -/
theorem renounce_records_exactly (revoked : json_wire.Value)
    (fuel : Nat) (valid : json_wire.Proofs.Valid fuel revoked)
    (room : json_wire.Proofs.Bound fuel revoked ≤ Usize.max)
    (encoded : Bool) (bytes : alloc.vec.Vec U8)
    (appended : json_wire.append (alloc.vec.Vec.new U8) revoked = Result.ok (encoded, bytes)) :
    encoded = true ∧ bytes.val = json_wire.Proofs.Bytes fuel revoked := by
  obtain ⟨result, returned, property⟩ := returned_of_spec
    (json_wire.Proofs.append_contract fuel revoked (alloc.vec.Vec.new U8) valid (by simpa using room))
  have same : result = (encoded, bytes) := Result.ok_injective (returned.symm.trans appended)
  subst same
  exact ⟨property.1, by simpa [alloc.vec.Vec.new] using property.2.1⟩

/-! ## The manifest description -/

theorem names_loop_ok (operations : Slice (alloc.vec.Vec U8)) :
    ∀ n (out r : alloc.vec.Vec json_wire.Value) (index : Usize), operations.length - index.val = n →
      names_loop operations out index = Result.ok r →
      ∃ extra : List (alloc.vec.Vec U32), r.val = out.val ++ extra.map json_wire.Value.Text ∧
        extra.map (·.val) = (operations.val.drop index.val).map (fun op => Units op.val) := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out r index measure h
    rw [names_loop.eq_def] at h
    dsimp only at h
    split at h
    · obtain ⟨op, indexed, h⟩ := bind_ok_inv h
      rw [index_usize_eq operations index (by scalar_tac)] at indexed
      simp only [Result.ok.injEq] at indexed
      have cons : operations.val.drop index.val = op :: operations.val.drop (index.val + 1) := by
        rw [← indexed]; exact List.drop_eq_getElem_cons (by scalar_tac)
      obtain ⟨v1, texted, h⟩ := bind_ok_inv h
      obtain ⟨units, hv1, hunits⟩ := text_ok texted
      obtain ⟨out1, pushed, h⟩ := bind_ok_inv h
      obtain ⟨next, added, value⟩ := add_one_eq index (by scalar_tac)
      simp only [added, bind_ok] at h
      obtain ⟨extra, hr, hextra⟩ := ih (operations.length - next.val) (by scalar_tac) out1 r next rfl h
      refine ⟨units :: extra, ?_, ?_⟩
      · rw [hr, push_ok_val pushed, hv1]; simp
      · rw [cons, ← value]
        simp [hextra, hunits, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]
    · simp only [Result.ok.injEq] at h
      subst h
      refine ⟨[], by simp, ?_⟩
      have : operations.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
      simp [this]

/-- `v` is the text of exactly these bytes. -/
def IsText (v : json_wire.Value) (bytes : List U8) : Prop :=
  ∃ units : alloc.vec.Vec U32, v = .Text units ∧ units.val = Units bytes

def ModeName : approval.Mode → List U8
  | .Allow => [97#u8, 108#u8, 108#u8, 111#u8, 119#u8]
  | .Deny => [100#u8, 101#u8, 110#u8, 121#u8]
  | .Approve => [97#u8, 112#u8, 112#u8, 114#u8, 111#u8, 118#u8, 101#u8]

theorem text_units_ok {bytes : Slice U8} {units : alloc.vec.Vec U32}
    (h : text_units bytes = Result.ok units) : units.val = Units bytes.val := by
  unfold text_units at h
  obtain ⟨v, texted, h⟩ := bind_ok_inv h
  obtain ⟨u, hv, hu⟩ := text_ok texted
  subst hv
  simp only [Result.ok.injEq] at h
  subst h
  exact hu

theorem mode_name_ok {writes : approval.Mode} {v : json_wire.Value}
    (h : mode_name writes = Result.ok v) : IsText v (ModeName writes) := by
  unfold mode_name at h
  cases writes <;> simp only [lift, Array.to_slice, Array.make, bind_ok] at h <;>
    obtain ⟨u, hv, hu⟩ := text_ok h <;> exact ⟨u, hv, by simpa [ModeName] using hu⟩

/-- **What `describe` can say (manifest profile).** The description is the
    object `{"operations":[names],"profile":"manifest-https-v1",
    "request_limit":"unbounded","writes":MODE}`: the array holds exactly the
    policy's operation names in order, and every other value is fixed or the
    write mode's name. Its only inputs are the names and the mode, so
    nothing session-specific (credential, token, identity, audit) can
    appear in a `describe` reply. -/
theorem manifest_description_exact {operations : Slice (alloc.vec.Vec U8)} {writes : approval.Mode}
    {v : json_wire.Value} (h : manifest_description operations writes = Result.ok v) :
    ∃ (fields : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (k1 k2 k3 k4 : alloc.vec.Vec U32) (arr : alloc.vec.Vec json_wire.Value)
      (texts : List (alloc.vec.Vec U32)) (profile limit mode : json_wire.Value),
      v = .Object fields ∧ fields.val = [(k1, .Array arr), (k2, profile), (k3, limit), (k4, mode)] ∧
      k1.val = Units [111#u8, 112#u8, 101#u8, 114#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8, 115#u8] ∧ k2.val = Units [112#u8, 114#u8, 111#u8, 102#u8, 105#u8, 108#u8, 101#u8] ∧
      k3.val = Units [114#u8, 101#u8, 113#u8, 117#u8, 101#u8, 115#u8, 116#u8, 95#u8, 108#u8, 105#u8, 109#u8, 105#u8, 116#u8] ∧ k4.val = Units [119#u8, 114#u8, 105#u8, 116#u8, 101#u8, 115#u8] ∧
      arr.val = texts.map json_wire.Value.Text ∧
      texts.map (·.val) = operations.val.map (fun op => Units op.val) ∧
      IsText profile [109#u8, 97#u8, 110#u8, 105#u8, 102#u8, 101#u8, 115#u8, 116#u8, 45#u8, 104#u8, 116#u8, 116#u8, 112#u8, 115#u8, 45#u8, 118#u8, 49#u8] ∧ IsText limit [117#u8, 110#u8, 98#u8, 111#u8, 117#u8, 110#u8, 100#u8, 101#u8, 100#u8] ∧
      IsText mode (ModeName writes) := by
  unfold manifest_description at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨k1, h1, h⟩ := bind_ok_inv h
  obtain ⟨arr, harr, h⟩ := bind_ok_inv h
  obtain ⟨k2, h2, h⟩ := bind_ok_inv h
  obtain ⟨profile, hprofile, h⟩ := bind_ok_inv h
  obtain ⟨k3, h3, h⟩ := bind_ok_inv h
  obtain ⟨limit, hlimit, h⟩ := bind_ok_inv h
  obtain ⟨k4, h4, h⟩ := bind_ok_inv h
  obtain ⟨mode, hmode, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨texts, harr_val, htexts⟩ := names_loop_ok operations _ (alloc.vec.Vec.new _) arr 0#usize rfl
    (by simpa [names] using harr)
  obtain ⟨pu, hp, hpu⟩ := text_ok hprofile
  obtain ⟨lu, hl, hlu⟩ := text_ok hlimit
  refine ⟨_, k1, k2, k3, k4, arr, texts, profile, limit, mode, rfl, rfl, ?_, ?_, ?_, ?_, ?_, ?_,
    ⟨pu, hp, by simpa using hpu⟩, ⟨lu, hl, by simpa using hlu⟩, mode_name_ok hmode⟩
  · simpa using text_units_ok h1
  · simpa using text_units_ok h2
  · simpa using text_units_ok h3
  · simpa using text_units_ok h4
  · simpa [alloc.vec.Vec.new] using harr_val
  · simpa using htexts

/-- **The revocation record's structure.** `{"event":"revoked","grant":G,
    ["operation":O,]"policy":P,"schema":1}`, keys in byte order; its only
    inputs are the session's grant, policy and (account profile) operation
    name. -/
theorem revoked_record_exact {grant policy : json_wire.Value} {operation : Option json_wire.Value}
    {v : json_wire.Value} (h : revoked_record grant policy operation = Result.ok v) :
    ∃ (fields : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kevent kgrant kpolicy kschema : alloc.vec.Vec U32) (event : json_wire.Value)
      (one : alloc.vec.Vec U8) (middle : List (alloc.vec.Vec U32 × json_wire.Value)),
      v = .Object fields ∧
      fields.val = [(kevent, event), (kgrant, grant)] ++ middle ++
        [(kpolicy, policy), (kschema, .Number one)] ∧
      kevent.val = Units [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      IsText event [114#u8, 101#u8, 118#u8, 111#u8, 107#u8, 101#u8, 100#u8] ∧
      kgrant.val = Units [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      kpolicy.val = Units [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      kschema.val = Units [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      one.val = [49#u8] ∧
      (match operation with
       | none => middle = []
       | some op => ∃ kop : alloc.vec.Vec U32, middle = [(kop, op)] ∧
           kop.val = Units [111#u8, 112#u8, 101#u8, 114#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8]) := by
  unfold revoked_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kevent, hevent, h⟩ := bind_ok_inv h
  obtain ⟨event, hev, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, hgrant, h⟩ := bind_ok_inv h
  obtain ⟨fields, hfields, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, hpolicy, h⟩ := bind_ok_inv h
  obtain ⟨fields1, hfields1, h⟩ := bind_ok_inv h
  obtain ⟨kschema, hschema, h⟩ := bind_ok_inv h
  obtain ⟨one, hone, h⟩ := bind_ok_inv h
  obtain ⟨fields2, hfields2, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨eu, he, heu⟩ := text_ok hev
  have one_val : one.val = [49#u8] := by
    obtain ⟨w, hw, eq⟩ := returned_of_spec (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 _
      (by intro x _; rfl))
    rw [hw] at hone
    simp only [Result.ok.injEq] at hone
    subst hone
    have := congrArg (fun x : Slice U8 => x.val) eq
    exact this.symm
  have fields_val : fields1.val = fields.val ++ [(kpolicy, policy)] := push_ok_val hfields1
  have fields2_val : fields2.val = fields1.val ++ [(kschema, .Number one)] := push_ok_val hfields2
  cases operation with
  | none =>
    simp only [Result.ok.injEq] at hfields
    subst hfields
    refine ⟨fields2, kevent, kgrant, kpolicy, kschema, event, one, [], rfl, ?_,
      by simpa using text_units_ok hevent, ⟨eu, he, by simpa using heu⟩,
      by simpa using text_units_ok hgrant, by simpa using text_units_ok hpolicy,
      by simpa using text_units_ok hschema, one_val, rfl⟩
    rw [fields2_val, fields_val]
    simp
    rfl
  | some op =>
    obtain ⟨kop, hkop, hpush⟩ := bind_ok_inv hfields
    refine ⟨fields2, kevent, kgrant, kpolicy, kschema, event, one, [(kop, op)], rfl, ?_,
      by simpa using text_units_ok hevent, ⟨eu, he, by simpa using heu⟩,
      by simpa using text_units_ok hgrant, by simpa using text_units_ok hpolicy,
      by simpa using text_units_ok hschema, one_val, ⟨kop, rfl, by simpa using text_units_ok hkop⟩⟩
    rw [fields2_val, fields_val, push_ok_val hpush]
    simp
    rfl

end aivm_secrets_garrett_core.control.Proofs
