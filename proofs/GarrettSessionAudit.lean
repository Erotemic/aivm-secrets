import GarrettControl

/-!
# The session audit's event records

Source: `rust/crates/aivm-secrets-garrett-core/src/session_audit.rs`
(`event_record`), extracted by Aeneas. The account session's
`Audit::record` (`session_open`, `completed`, `failed`, `revoked`) and the
manifest session's completion audit build their records with this function
and append exactly its extracted encoding (`json_wire::encode`) through the
extracted durable append (`audit_record::append_durable_record`).

Proved here:

* `event_record_exact`: the record is the object
  `{"event":E,"grant":G,["operation":O,]"policy":P,["request_digest":D,]"schema":1}`,
  keys in byte order, whose only inputs are the five values the session
  passes. Nothing else (in particular no credential) can enter a record
  unless a caller passes it as one of those values.

A Rust oracle test (`custody::control_oracle`) checks the encoded bytes equal
the serde records these replaced, for every account event and the manifest
completion record. Still native: the strings the sessions pass (event name,
grant id, policy digest, operation name, request digest).
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.route.Proofs (bind_ok_inv push_ok_val)
open aivm_secrets_garrett_core.control.Proofs (Units text_units_ok)

namespace aivm_secrets_garrett_core.session_audit.Proofs

/-- An optional field: absent, or one `(key, value)` pair whose key is the
    text of `name`. -/
def OptionalField (label : List U8) (value : Option json_wire.Value)
    (part : List (alloc.vec.Vec U32 × json_wire.Value)) : Prop :=
  match value with
  | none => part = []
  | some v => ∃ key : alloc.vec.Vec U32, part = [(key, v)] ∧ key.val = Units label

def OperationKey : List U8 := [111#u8, 112#u8, 101#u8, 114#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8]
def DigestKey : List U8 :=
  [114#u8, 101#u8, 113#u8, 117#u8, 101#u8, 115#u8, 116#u8, 95#u8, 100#u8, 105#u8, 103#u8, 101#u8, 115#u8, 116#u8]

theorem one_vec {one : alloc.vec.Vec U8} {s : Slice U8} (hs : s.val = [49#u8])
    (h : alloc.slice.Slice.to_vec core.clone.CloneU8 s = Result.ok one) : one.val = [49#u8] := by
  obtain ⟨w, hw, eq⟩ := returned_of_spec (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 s
    (by intro x _; rfl))
  rw [hw] at h
  simp only [Result.ok.injEq] at h
  subst h
  have := congrArg (fun x : Slice U8 => x.val) eq
  exact this.symm.trans hs

/-- **The record's structure and only inputs.** -/
theorem event_record_exact {event grant policy : json_wire.Value}
    {operation digest : Option json_wire.Value} {v : json_wire.Value}
    (h : event_record event grant policy operation digest = Result.ok v) :
    ∃ (fields : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kevent kgrant kpolicy kschema : alloc.vec.Vec U32) (one : alloc.vec.Vec U8)
      (opPart digestPart : List (alloc.vec.Vec U32 × json_wire.Value)),
      v = .Object fields ∧
      fields.val = [(kevent, event), (kgrant, grant)] ++ opPart ++ [(kpolicy, policy)] ++
        digestPart ++ [(kschema, .Number one)] ∧
      kevent.val = Units [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      kgrant.val = Units [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      kpolicy.val = Units [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      kschema.val = Units [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      one.val = [49#u8] ∧
      OptionalField OperationKey operation opPart ∧ OptionalField DigestKey digest digestPart := by
  unfold event_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kevent, hevent, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, hgrant, h⟩ := bind_ok_inv h
  obtain ⟨fields, hfields, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, hpolicy, h⟩ := bind_ok_inv h
  obtain ⟨fields1, hfields1, h⟩ := bind_ok_inv h
  obtain ⟨fields2, hfields2, h⟩ := bind_ok_inv h
  obtain ⟨kschema, hschema, h⟩ := bind_ok_inv h
  obtain ⟨one, hone, h⟩ := bind_ok_inv h
  obtain ⟨fields3, hfields3, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  -- The two optional fields: each adds nothing or exactly one keyed pair.
  have operation_part : ∃ opPart, fields.val = [(kevent, event), (kgrant, grant)] ++ opPart ∧
      OptionalField OperationKey operation opPart := by
    cases operation with
    | none =>
      simp only [Result.ok.injEq] at hfields
      subst hfields
      exact ⟨[], by simp; rfl, rfl⟩
    | some op =>
      obtain ⟨kop, hkop, hpush⟩ := bind_ok_inv hfields
      refine ⟨[(kop, op)], ?_, kop, rfl, by simpa [OperationKey] using text_units_ok hkop⟩
      rw [push_ok_val hpush]
      simp; rfl
  have digest_part : ∃ digestPart, fields2.val = fields1.val ++ digestPart ∧
      OptionalField DigestKey digest digestPart := by
    cases digest with
    | none =>
      simp only [Result.ok.injEq] at hfields2
      subst hfields2
      exact ⟨[], by simp, rfl⟩
    | some d =>
      obtain ⟨kd, hkd, hpush⟩ := bind_ok_inv hfields2
      exact ⟨[(kd, d)], push_ok_val hpush, kd, rfl, by simpa [DigestKey] using text_units_ok hkd⟩
  obtain ⟨opPart, hop, op_ok⟩ := operation_part
  obtain ⟨digestPart, hdig, dig_ok⟩ := digest_part
  refine ⟨fields3, kevent, kgrant, kpolicy, kschema, one, opPart, digestPart, rfl, ?_,
    by simpa using text_units_ok hevent, by simpa using text_units_ok hgrant,
    by simpa using text_units_ok hpolicy, by simpa using text_units_ok hschema,
    one_vec rfl hone, op_ok, dig_ok⟩
  rw [push_ok_val hfields3, hdig, push_ok_val hfields1, hop]

end aivm_secrets_garrett_core.session_audit.Proofs
