import GarrettJsonFrame

/-!
# Guest denial frames are a fixed table

Source: `rust/crates/aivm-secrets-garrett-core/src/public_error.rs`, extracted
by Aeneas. The native bridge (`tls.rs`, `GuestFrame::from_answer`) builds every
failure frame with `public_error::denial_frame(error.into(), MAX_REPLY)`.

Proved here, for every one of the 17 `PublicError` variants:
* `code_contract` / `message_contract`: the extracted tables return exactly the
  readable strings `codeText e` / `messageText e`;
* `denial_contract`: `denial e` is a valid JSON value whose exact encoding is
  `denialText e`, e.g. `{"error":{"code":"denied","message":"..."},"ok":false,"version":1}`;
* `denial_frame_exact` / `denial_frame_send_exact`: the frame handed to the
  guest writer is that text plus one newline.

Consequence: a denial frame depends only on which of 17 public errors occurred.
It cannot contain provider data, error detail or credential bytes. This holds
for any native `Error -> PublicError` mapping, so the mapping is not trusted
for this property.

Still trusted: that `from_answer`'s error branch calls `denial_frame` (a
reviewed source shape, checked by the W3 guard), and the guest writer's I/O.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000
namespace aivm_secrets_garrett_core.public_error.Proofs


/-- Byte-to-scalar widening performed by `public_error::text`. -/
def widen (bytes : List U8) : List U32 := bytes.map (fun b => UScalar.cast .U32 b)

theorem text_loop_contract (bytes : Slice U8) (out : alloc.vec.Vec U32) (i : Usize)
    (prefix_ : out.val = widen (bytes.val.take i.val)) (len : out.length = i.val)
    (inside : i.val ≤ bytes.length) :
    public_error.text_loop bytes out i ⦃ r => r.val = widen bytes.val ⦄ := by
  suffices ∀ n (i : Usize) (out : alloc.vec.Vec U32), bytes.length - i.val = n →
      out.val = widen (bytes.val.take i.val) → out.length = i.val → i.val ≤ bytes.length →
      public_error.text_loop bytes out i ⦃ r => r.val = widen bytes.val ⦄ from
    this _ i out rfl prefix_ len inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i out measure pre length within
    rw [public_error.text_loop.eq_def]
    by_cases more : i < Slice.len bytes
    · have lt : i.val < bytes.length := by scalar_tac
      simp only [more, ↓reduceIte]
      step*
      · exact bytes.length - i4.val
      · scalar_tac
      · rfl
      · rw [out1_post, pre, i4_post, i3_post, i2_post, List.take_add_one, List.getElem?_eq_getElem lt]
        simp only [widen, List.map_append, Option.toList_some, List.map_cons, List.map_nil]
      · have : out1.length = out.length + 1 := by
          change out1.val.length = out.val.length + 1
          simp [out1_post]
        scalar_tac
    · have ge : bytes.length ≤ i.val := by scalar_tac
      simp only [more, ↓reduceIte, WP.spec_ok]
      have : i.val = bytes.length := by omega
      simp [pre, this, List.take_length]


/-- The bytes of an ASCII string literal. -/
def ascii (s : String) : List U8 := s.toList.map (fun c => ⟨BitVec.ofNat 8 c.toNat⟩)

open public_error (PublicError)

/-- The public code of each error, as text. -/
def codeText : PublicError → String
  | .InvalidCapability => "invalid_capability"
  | .InvalidPolicy => "invalid_policy"
  | .ResourceMismatch => "resource_mismatch"
  | .InvalidRequest => "invalid_request"
  | .Denied => "denied"
  | .Unreachable => "unreachable"
  | .UpstreamResponse => "upstream_response"
  | .UpstreamRejected => "upstream_rejected"
  | .UpstreamError => "upstream_error"
  | .InternalError => "internal_error"
  | .UnsafeFile => "unsafe_file"
  | .OutcomeUnknown => "outcome_unknown"
  | .Exhausted => "exhausted"
  | .Revoked => "revoked"
  | .CredentialSource => "credential_source"
  | .Expired => "expired"
  | .AuthorizationDenied => "credential_source"

/-- The public message of each error, as text. -/
def messageText : PublicError → String
  | .InvalidCapability => "Capability authentication failed."
  | .InvalidRequest => "Malformed or unsupported request."
  | .Denied => "Operation is outside the granted authority."
  | .UnsafeFile => "Host file ownership, permissions, or type is unsafe."
  | .OutcomeUnknown => "A dispatched request may have completed; reconcile before retrying."
  | _ => "Broker failed closed."

theorem extend_new (bytes : Slice U8) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 (alloc.vec.Vec.new U8) bytes ⦃ out =>
      out.val = bytes.val ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  have room : (alloc.vec.Vec.new U8).length + bytes.length ≤ Usize.max := by simp
  rw [dite_eq_left room]
  apply WP.spec_bind (List.clone_spec (clone := core.clone.CloneU8.clone)
    (l := bytes.val) (by intro x hx; simp))
  intro cloned exact_copy
  simp [exact_copy.1]

@[step] theorem code_contract (e : PublicError) :
    public_error.code e ⦃ out => out.val = ascii (codeText e) ⦄ := by
  cases e <;> (unfold public_error.code; simp only [lift, bind_ok]
               apply WP.spec_mono (extend_new _); intro out h; rw [h]; decide)

@[step] theorem message_contract (e : PublicError) :
    public_error.message e ⦃ out => out.val = ascii (messageText e) ⦄ := by
  cases e <;> (unfold public_error.message; simp only [lift, bind_ok]
               apply WP.spec_mono (extend_new _); intro out h; rw [h]; decide)

@[step] theorem text_contract (bytes : Slice U8) :
    public_error.text bytes ⦃ r => r.val = widen bytes.val ⦄ := by
  unfold public_error.text
  exact text_loop_contract bytes _ 0#usize (by simp [widen]) (by simp) (by simp)

/-- The exact JSON text of each guest denial. -/
def denialText (e : PublicError) : String :=
  "{\"error\":{\"code\":\"" ++ codeText e ++ "\",\"message\":\"" ++ messageText e ++
    "\"},\"ok\":false,\"version\":1}"

theorem widen_valid (text : alloc.vec.Vec U32) (bytes : List U8) (h : text.val = widen bytes) :
    json_string.Proofs.ValidFrom text 0 := by
  intro i inside _
  have small : (text.val[i]'inside).val < 256 := by
    have : text.val[i]'inside = UScalar.cast .U32 (bytes[i]'(by
        have := congrArg List.length h; simp [widen] at this; simp [alloc.vec.Vec.length] at inside; omega)) := by
      simp only [h, widen, List.getElem_map]
    rw [this]; simp [UScalar.cast_val_eq]; scalar_tac
  unfold json_string.Proofs.Scalar; omega

set_option maxRecDepth 100000 in
theorem denial_contract (e : PublicError) :
    public_error.denial e ⦃ v =>
      json_wire.Proofs.Valid 3 v ∧ json_wire.Proofs.Bound 3 v ≤ Usize.max ∧
      json_wire.Proofs.Bytes 3 v = ascii (denialText e) ⦄ := by
  unfold public_error.denial
  step*
  have fields : (alloc.slice.Slice.into_vec y1).val =
      [(v, json_wire.Value.Object (alloc.slice.Slice.into_vec y)),
       (v7, json_wire.Value.Boolean false), (v8, json_wire.Value.Number v9)] := by
    simp [y1_post, alloc.slice.Slice.into_vec, alloc.vec.Vec.val, Array.to_slice, Slice.from_val]
  have inner : (alloc.slice.Slice.into_vec y).val =
      [(v1, json_wire.Value.Text v3), (v4, json_wire.Value.Text v6)] := by
    simp [y_post, alloc.slice.Slice.into_vec, alloc.vec.Vec.val, Array.to_slice, Slice.from_val]
  rename s7 = (Array.make _ _ _).to_slice => s7_def
  have one : v9.val = [49#u8] := by
    have := congrArg Slice.val s7_post
    simp [s7_def, Array.to_slice, Slice.from_val] at this
    simpa [alloc.vec.Vec.val] using this.symm
  have sv : ∀ (l : List U8) (n : Usize) (h : l.length = n.val), ((Array.make n l h).to_slice).val = l := by
    intro l n h; simp [Array.to_slice, Slice.from_val]
  rw [s_post, sv] at v_post
  rw [s1_post, sv] at v1_post
  rw [s3_post, sv] at v4_post
  rw [s5_post, sv] at v7_post
  rw [s6_post, sv] at v8_post
  have deref_val : ∀ (x : alloc.vec.Vec U8), (alloc.vec.Vec.deref x).val = x.val := by
    intro x; simp [alloc.vec.Vec.deref, alloc.vec.Vec.val]
  rw [deref_val, v2_post] at v3_post
  rw [deref_val, v5_post] at v6_post
  refine ⟨?_, ?_, ?_⟩
  · rw [json_wire.Proofs.valid_object_iff]
    intro field mem
    rw [fields] at mem
    simp only [List.mem_cons, List.not_mem_nil, or_false] at mem
    rcases mem with rfl | rfl | rfl
    · refine ⟨widen_valid _ _ v_post, ?_⟩
      rw [json_wire.Proofs.valid_object_iff]
      intro field mem
      rw [inner] at mem
      simp only [List.mem_cons, List.not_mem_nil, or_false] at mem
      rcases mem with rfl | rfl
      · exact ⟨widen_valid _ _ v1_post, (json_wire.Proofs.valid_text_iff _ _).mpr (widen_valid _ _ v3_post)⟩
      · exact ⟨widen_valid _ _ v4_post, (json_wire.Proofs.valid_text_iff _ _).mpr (widen_valid _ _ v6_post)⟩
    · exact ⟨widen_valid _ _ v7_post, trivial⟩
    · exact ⟨widen_valid _ _ v8_post, trivial⟩
  · have lens : ∀ (x : alloc.vec.Vec U32) (l : List U8), x.val = widen l → x.length = l.length := by
      intro x l h; change x.val.length = _; simp [h, widen]
    simp only [json_wire.Proofs.Bound, json_wire.Proofs.SeriesBound, fields, inner,
      lens _ _ v_post, lens _ _ v1_post, lens _ _ v3_post, lens _ _ v4_post, lens _ _ v6_post,
      lens _ _ v7_post, lens _ _ v8_post, alloc.vec.Vec.length, one, Bool.false_eq_true, ↓reduceIte]
    have small : (ascii (codeText e)).length + (ascii (messageText e)).length ≤ 100 := by
      cases e <;> decide
    have : 4294967295 ≤ Usize.max := by scalar_tac
    simp only [List.length_cons, List.length_nil] at *
    omega
  · simp only [json_wire.Proofs.Bytes, json_wire.Proofs.Series, fields, inner,
      v_post, v1_post, v3_post, v4_post, v6_post, v7_post, v8_post, one]
    cases e <;> decide

set_option maxRecDepth 100000 in
/-- Every denial text is short ASCII with no line break. -/
theorem denial_text_short (e : PublicError) :
    (ascii (denialText e)).length < 200 ∧ 10#u8 ∉ ascii (denialText e) := by
  cases e <;> decide

/-- **Guest denial frames are fixed.** For every public error and every frame
    limit of at least 200 bytes, the extracted `public_error::denial_frame`
    returns a frame whose bytes are exactly the JSON text `denialText e`
    followed by one newline. The bytes depend on nothing but `e`. -/
theorem denial_frame_exact (e : PublicError) (limit : Usize) (large : 200 ≤ limit.val) :
    ∃ frame, public_error.denial_frame e limit = Result.ok (.Ok frame) ∧
      frame.wire.val = ascii (denialText e) ++ [10#u8] ∧ frame.attempted = false := by
  obtain ⟨value, built, valid, room, bytes⟩ := returned_of_spec (denial_contract e)
  have short := denial_text_short e
  obtain ⟨frame, prepared, wire, ready⟩ := json_wire.Proofs.framed_value_witness 3 value valid room
    limit (by rw [bytes]; omega) (by rw [bytes]; exact short.2)
  refine ⟨frame, ?_, by rw [wire, bytes], ready⟩
  simp [public_error.denial_frame, built, prepared]

/-- Sending a built denial frame hands exactly that text and one newline to
    the guest writer callback, once. Delivery is the writer's contract. -/
theorem denial_frame_send_exact {W X : Type} (ops : guest_frame.Writer W X)
    (e : PublicError) (limit : Usize) (frame after : guest_frame.Frame) (writer next : W)
    (out : core.result.Result Unit X)
    (built : public_error.denial_frame e limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send ops frame writer = Result.ok (out, after, next)) :
    ops.write_frame writer (alloc.vec.Vec.deref frame.wire) = Result.ok (out, next) ∧
      frame.wire.val = ascii (denialText e) ++ [10#u8] ∧
      after.attempted = true ∧ after.wire = frame.wire := by
  obtain ⟨value, returned, valid, room, bytes⟩ := returned_of_spec (denial_contract e)
  have prepared : json_wire.prepare value limit = Result.ok (.Ok frame) := by
    simpa [public_error.denial_frame, returned] using built
  have origin := json_wire.Proofs.prepared_send_value_origin ops 3 value valid room limit frame
    after writer next out prepared sent
  rw [bytes] at origin
  exact origin

end aivm_secrets_garrett_core.public_error.Proofs
