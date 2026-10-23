import GarrettRoute

/-!
# The guest's control verbs: `describe` and `renounce`

Source: `rust/crates/aivm-secrets-garrett-core/src/control.rs`, extracted by
Aeneas. Both native sessions (`custody.rs` account profile and
`custody/manifest_session.rs` manifest profile) call `control::control`
after the capability is authorized, supplying three side effects
(`Control`: revoke the control state, record the revocation, deactivate the
grant). The reply value is framed by the extracted JSON encoder.

Proved here, for **any** callbacks:

* `control_paths`: `renounce` revokes first, then records; only if the
  record succeeds is the grant deactivated and `renounced` replied, otherwise
  the error is returned with no reply (the control state stays revoked).
  `describe` replies with the description and invokes no callback. Any
  other verb is `Denied` and invokes no callback. No path can reach a
  provider: `Control` has no provider operation.
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
    1. `renounce`: `revoke`, then `record_revoked`; on success `deactivate`
       and reply `renounced`; on failure return the error, no reply, grant
       untouched;
    2. `describe`: reply with the description, no callback;
    3. anything else: `Denied`, no callback. -/
theorem control_paths (inst : Control C E) (io : C) (verb : Slice U8) (description : json_wire.Value)
    (out : Controlled E) (after : C)
    (h : control.control inst io verb description = Result.ok (out, after)) :
    (verb.val = RenounceVerb ∧ ∃ io1 io2 r, inst.revoke io = Result.ok io1 ∧
      inst.record_revoked io1 = Result.ok (r, io2) ∧
      ((∃ io3 reply, r = .Ok () ∧ inst.deactivate io2 = Result.ok io3 ∧
          renounced = Result.ok reply ∧ out = .Reply reply ∧ after = io3) ∨
       (∃ error, r = .Err error ∧ out = .Failed error ∧ after = io2))) ∨
    (verb.val = DescribeVerb ∧ ∃ reply, described description = Result.ok reply ∧
      out = .Reply reply ∧ after = io) ∨
    (verb.val ≠ RenounceVerb ∧ verb.val ≠ DescribeVerb ∧ out = .Denied ∧ after = io) := by
  unfold control.control at h
  simp only [lift, Array.to_slice, Array.make, bind_ok, slice_eq_eq] at h
  split at h
  · rename_i is_renounce
    simp only [decide_eq_true_eq] at is_renounce
    left
    refine ⟨by simpa [RenounceVerb] using is_renounce, ?_⟩
    obtain ⟨io1, revoked, h⟩ := bind_ok_inv h
    obtain ⟨⟨r, io2⟩, recorded, h⟩ := bind_ok_inv h
    refine ⟨io1, io2, r, revoked, recorded, ?_⟩
    cases r with
    | Ok u =>
      cases u
      obtain ⟨io3, deactivated, h⟩ := bind_ok_inv h
      obtain ⟨reply, replied, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨o, a⟩ := h
      exact Or.inl ⟨io3, reply, rfl, deactivated, replied, o.symm, a.symm⟩
    | Err error =>
      have h : Result.ok (Controlled.Failed error, io2) = Result.ok (out, after) := h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨o, a⟩ := h
      exact Or.inr ⟨error, rfl, o.symm, a.symm⟩
  · rename_i not_renounce
    simp only [decide_eq_true_eq] at not_renounce
    split at h
    · rename_i is_describe
      simp only [decide_eq_true_eq] at is_describe
      obtain ⟨reply, replied, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨o, a⟩ := h
      exact Or.inr (Or.inl ⟨by simpa [DescribeVerb] using is_describe, reply, replied, o.symm, a.symm⟩)
    · rename_i not_describe
      simp only [decide_eq_true_eq] at not_describe
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨o, a⟩ := h
      exact Or.inr (Or.inr ⟨by simpa [RenounceVerb] using not_renounce,
        by simpa [DescribeVerb] using not_describe, o.symm, a.symm⟩)

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

end aivm_secrets_garrett_core.control.Proofs
