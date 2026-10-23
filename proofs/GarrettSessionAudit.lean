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

/-- `key` holds the text of `label`. -/
def Key (key : alloc.vec.Vec U32) (label : List U8) : Prop := key.val = Units label

/-- **The dispatch record's structure and only inputs.** Written before every
    manifest provider send:
    `{"event":"dispatch","grant":G,"identity":I,"operation":O,"phase":PH,
    "policy":P,"request_digest":D,"route":{"host":H,"method":M,"path":T,
    "port":N},"schema":1}`; the ten values the session passes are its only
    inputs. -/
theorem dispatch_record_exact {phase grant policy identity operation digest host port method path v : json_wire.Value}
    (h : dispatch_record phase grant policy identity operation digest host port method path = Result.ok v) :
    ∃ (top route : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kevent kgrant kidentity koperation kphase kpolicy kdigest kroute kschema
        khost kmethod kpath kport : alloc.vec.Vec U32) (event : json_wire.Value) (one : alloc.vec.Vec U8),
      v = .Object top ∧
      top.val = [(kevent, event), (kgrant, grant), (kidentity, identity), (koperation, operation),
        (kphase, phase), (kpolicy, policy), (kdigest, digest), (kroute, .Object route),
        (kschema, .Number one)] ∧
      route.val = [(khost, host), (kmethod, method), (kpath, path), (kport, port)] ∧
      control.Proofs.IsText event [100#u8, 105#u8, 115#u8, 112#u8, 97#u8, 116#u8, 99#u8, 104#u8] ∧
      Key kevent [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      Key kgrant [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      Key kidentity [105#u8, 100#u8, 101#u8, 110#u8, 116#u8, 105#u8, 116#u8, 121#u8] ∧
      Key koperation OperationKey ∧
      Key kphase [112#u8, 104#u8, 97#u8, 115#u8, 101#u8] ∧
      Key kpolicy [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      Key kdigest DigestKey ∧
      Key kroute [114#u8, 111#u8, 117#u8, 116#u8, 101#u8] ∧
      Key kschema [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      Key khost [104#u8, 111#u8, 115#u8, 116#u8] ∧
      Key kmethod [109#u8, 101#u8, 116#u8, 104#u8, 111#u8, 100#u8] ∧
      Key kpath [112#u8, 97#u8, 116#u8, 104#u8] ∧
      Key kport [112#u8, 111#u8, 114#u8, 116#u8] ∧
      one.val = [49#u8] := by
  unfold dispatch_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨khost, h1, h⟩ := bind_ok_inv h
  obtain ⟨kmethod, h2, h⟩ := bind_ok_inv h
  obtain ⟨kpath, h3, h⟩ := bind_ok_inv h
  obtain ⟨kport, h4, h⟩ := bind_ok_inv h
  obtain ⟨kevent, h5, h⟩ := bind_ok_inv h
  obtain ⟨event, h6, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, h7, h⟩ := bind_ok_inv h
  obtain ⟨kidentity, h8, h⟩ := bind_ok_inv h
  obtain ⟨koperation, h9, h⟩ := bind_ok_inv h
  obtain ⟨kphase, h10, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, h11, h⟩ := bind_ok_inv h
  obtain ⟨kdigest, h12, h⟩ := bind_ok_inv h
  obtain ⟨kroute, h13, h⟩ := bind_ok_inv h
  obtain ⟨kschema, h14, h⟩ := bind_ok_inv h
  obtain ⟨one, h15, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨eu, he, heu⟩ := control.Proofs.text_ok h6
  refine ⟨_, _, kevent, kgrant, kidentity, koperation, kphase, kpolicy, kdigest, kroute, kschema,
    khost, kmethod, kpath, kport, event, one, rfl, rfl, rfl, ⟨eu, he, by simpa using heu⟩,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, one_vec rfl h15⟩
  · simpa [Key] using text_units_ok h5
  · simpa [Key] using text_units_ok h7
  · simpa [Key] using text_units_ok h8
  · simpa [Key, OperationKey] using text_units_ok h9
  · simpa [Key] using text_units_ok h10
  · simpa [Key] using text_units_ok h11
  · simpa [Key, DigestKey] using text_units_ok h12
  · simpa [Key] using text_units_ok h13
  · simpa [Key] using text_units_ok h14
  · simpa [Key] using text_units_ok h1
  · simpa [Key] using text_units_ok h2
  · simpa [Key] using text_units_ok h3
  · simpa [Key] using text_units_ok h4

/-- **The manifest session's opening record.**
    `{"event":"session_open","grant":G,"policy":P,"profile":R,"schema":1}`. -/
theorem opened_record_exact {profile grant policy v : json_wire.Value}
    (h : opened_record profile grant policy = Result.ok v) :
    ∃ (top : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kevent kgrant kpolicy kprofile kschema : alloc.vec.Vec U32) (event : json_wire.Value)
      (one : alloc.vec.Vec U8),
      v = .Object top ∧
      top.val = [(kevent, event), (kgrant, grant), (kpolicy, policy), (kprofile, profile),
        (kschema, .Number one)] ∧
      control.Proofs.IsText event
        [115#u8, 101#u8, 115#u8, 115#u8, 105#u8, 111#u8, 110#u8, 95#u8, 111#u8, 112#u8, 101#u8, 110#u8] ∧
      Key kevent [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      Key kgrant [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      Key kpolicy [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      Key kprofile [112#u8, 114#u8, 111#u8, 102#u8, 105#u8, 108#u8, 101#u8] ∧
      Key kschema [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      one.val = [49#u8] := by
  unfold opened_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kevent, h1, h⟩ := bind_ok_inv h
  obtain ⟨event, h2, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, h3, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, h4, h⟩ := bind_ok_inv h
  obtain ⟨kprofile, h5, h⟩ := bind_ok_inv h
  obtain ⟨kschema, h6, h⟩ := bind_ok_inv h
  obtain ⟨one, h7, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨eu, he, heu⟩ := control.Proofs.text_ok h2
  exact ⟨_, kevent, kgrant, kpolicy, kprofile, kschema, event, one, rfl, rfl, ⟨eu, he, by simpa using heu⟩,
    by simpa [Key] using text_units_ok h1, by simpa [Key] using text_units_ok h3,
    by simpa [Key] using text_units_ok h4, by simpa [Key] using text_units_ok h5,
    by simpa [Key] using text_units_ok h6, one_vec rfl h7⟩

/-- **The issuance record.**
    `{"event":"issued","grant":G,"identity":I,"policy":P,"schema":1}`. -/
theorem issued_record_exact {identity grant policy v : json_wire.Value}
    (h : issued_record identity grant policy = Result.ok v) :
    ∃ (top : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kevent kgrant kidentity kpolicy kschema : alloc.vec.Vec U32) (event : json_wire.Value)
      (one : alloc.vec.Vec U8),
      v = .Object top ∧
      top.val = [(kevent, event), (kgrant, grant), (kidentity, identity), (kpolicy, policy),
        (kschema, .Number one)] ∧
      control.Proofs.IsText event [105#u8, 115#u8, 115#u8, 117#u8, 101#u8, 100#u8] ∧
      Key kevent [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      Key kgrant [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      Key kidentity [105#u8, 100#u8, 101#u8, 110#u8, 116#u8, 105#u8, 116#u8, 121#u8] ∧
      Key kpolicy [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      Key kschema [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      one.val = [49#u8] := by
  unfold issued_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kevent, h1, h⟩ := bind_ok_inv h
  obtain ⟨event, h2, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, h3, h⟩ := bind_ok_inv h
  obtain ⟨kidentity, h4, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, h5, h⟩ := bind_ok_inv h
  obtain ⟨kschema, h6, h⟩ := bind_ok_inv h
  obtain ⟨one, h7, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨eu, he, heu⟩ := control.Proofs.text_ok h2
  exact ⟨_, kevent, kgrant, kidentity, kpolicy, kschema, event, one, rfl, rfl, ⟨eu, he, by simpa using heu⟩,
    by simpa [Key] using text_units_ok h1, by simpa [Key] using text_units_ok h3,
    by simpa [Key] using text_units_ok h4, by simpa [Key] using text_units_ok h5,
    by simpa [Key] using text_units_ok h6, one_vec rfl h7⟩

/-- The authentication scheme's audit name. -/
def AuthenticationName : credential_use.Authentication → List U8
  | .Bearer => [98#u8, 101#u8, 97#u8, 114#u8, 101#u8, 114#u8]
  | .ApiKey => [120#u8, 45#u8, 97#u8, 112#u8, 105#u8, 45#u8, 107#u8, 101#u8, 121#u8]

theorem authentication_name_ok {authentication : credential_use.Authentication} {v : json_wire.Value}
    (h : authentication_name authentication = Result.ok v) :
    control.Proofs.IsText v (AuthenticationName authentication) := by
  unfold authentication_name at h
  cases authentication <;> simp only [lift, Array.to_slice, Array.make, bind_ok] at h <;>
    obtain ⟨u, hv, hu⟩ := control.Proofs.text_ok h <;>
    exact ⟨u, hv, by simpa [AuthenticationName] using hu⟩

/-- **The account profile's dispatch record**, written and acknowledged before
    its one provider GET. The method is the fixed `GET`, the authentication
    name is decided by the scheme, and the eleven passed values are the only
    other inputs. -/
theorem account_dispatch_record_exact
    {grant policy identity operation binding issued expires host port path v : json_wire.Value}
    {authentication : credential_use.Authentication}
    (h : account_dispatch_record grant policy identity operation binding issued expires host port path
      authentication = Result.ok v) :
    ∃ (top inner route : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kbinding kexpires kissued kauth khost kmethod kpath kport kevent kgrant kidentity kinner
        koperation kpolicy kroute kschema : alloc.vec.Vec U32)
      (scheme method event : json_wire.Value) (one : alloc.vec.Vec U8),
      v = .Object top ∧
      top.val = [(kevent, event), (kgrant, grant), (kidentity, identity), (kinner, .Object inner),
        (koperation, operation), (kpolicy, policy), (kroute, .Object route), (kschema, .Number one)] ∧
      inner.val = [(kbinding, binding), (kexpires, expires), (kissued, issued)] ∧
      route.val = [(kauth, scheme), (khost, host), (kmethod, method), (kpath, path), (kport, port)] ∧
      control.Proofs.IsText scheme (AuthenticationName authentication) ∧
      control.Proofs.IsText method [71#u8, 69#u8, 84#u8] ∧
      control.Proofs.IsText event [100#u8, 105#u8, 115#u8, 112#u8, 97#u8, 116#u8, 99#u8, 104#u8] ∧
      Key kbinding [98#u8, 105#u8, 110#u8, 100#u8, 105#u8, 110#u8, 103#u8] ∧
      Key kexpires [101#u8, 120#u8, 112#u8, 105#u8, 114#u8, 101#u8, 115#u8, 95#u8, 97#u8, 116#u8] ∧
      Key kissued [105#u8, 115#u8, 115#u8, 117#u8, 101#u8, 100#u8, 95#u8, 97#u8, 116#u8] ∧
      Key kauth [97#u8, 117#u8, 116#u8, 104#u8, 101#u8, 110#u8, 116#u8, 105#u8, 99#u8, 97#u8, 116#u8,
        105#u8, 111#u8, 110#u8] ∧
      Key khost [104#u8, 111#u8, 115#u8, 116#u8] ∧
      Key kmethod [109#u8, 101#u8, 116#u8, 104#u8, 111#u8, 100#u8] ∧
      Key kpath [112#u8, 97#u8, 116#u8, 104#u8] ∧
      Key kport [112#u8, 111#u8, 114#u8, 116#u8] ∧
      Key kevent [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      Key kgrant [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      Key kidentity [105#u8, 100#u8, 101#u8, 110#u8, 116#u8, 105#u8, 116#u8, 121#u8] ∧
      Key kinner [105#u8, 110#u8, 110#u8, 101#u8, 114#u8] ∧
      Key koperation OperationKey ∧
      Key kpolicy [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      Key kroute [114#u8, 111#u8, 117#u8, 116#u8, 101#u8] ∧
      Key kschema [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      one.val = [49#u8] := by
  unfold account_dispatch_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kbinding, h1, h⟩ := bind_ok_inv h
  obtain ⟨kexpires, h2, h⟩ := bind_ok_inv h
  obtain ⟨kissued, h3, h⟩ := bind_ok_inv h
  obtain ⟨kauth, h4, h⟩ := bind_ok_inv h
  obtain ⟨scheme, h5, h⟩ := bind_ok_inv h
  obtain ⟨khost, h6, h⟩ := bind_ok_inv h
  obtain ⟨kmethod, h7, h⟩ := bind_ok_inv h
  obtain ⟨method, h8, h⟩ := bind_ok_inv h
  obtain ⟨kpath, h9, h⟩ := bind_ok_inv h
  obtain ⟨kport, h10, h⟩ := bind_ok_inv h
  obtain ⟨kevent, h11, h⟩ := bind_ok_inv h
  obtain ⟨event, h12, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, h13, h⟩ := bind_ok_inv h
  obtain ⟨kidentity, h14, h⟩ := bind_ok_inv h
  obtain ⟨kinner, h15, h⟩ := bind_ok_inv h
  obtain ⟨koperation, h16, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, h17, h⟩ := bind_ok_inv h
  obtain ⟨kroute, h18, h⟩ := bind_ok_inv h
  obtain ⟨kschema, h19, h⟩ := bind_ok_inv h
  obtain ⟨one, h20, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨mu, hm, hmu⟩ := control.Proofs.text_ok h8
  obtain ⟨eu, he, heu⟩ := control.Proofs.text_ok h12
  exact ⟨_, _, _, kbinding, kexpires, kissued, kauth, khost, kmethod, kpath, kport, kevent, kgrant,
    kidentity, kinner, koperation, kpolicy, kroute, kschema, scheme, method, event, one,
    rfl, rfl, rfl, rfl, authentication_name_ok h5,
    ⟨mu, hm, by simpa using hmu⟩, ⟨eu, he, by simpa using heu⟩,
    by simpa [Key] using text_units_ok h1, by simpa [Key] using text_units_ok h2,
    by simpa [Key] using text_units_ok h3, by simpa [Key] using text_units_ok h4,
    by simpa [Key] using text_units_ok h6, by simpa [Key] using text_units_ok h7,
    by simpa [Key] using text_units_ok h9, by simpa [Key] using text_units_ok h10,
    by simpa [Key] using text_units_ok h11, by simpa [Key] using text_units_ok h13,
    by simpa [Key] using text_units_ok h14, by simpa [Key] using text_units_ok h15,
    by simpa [Key, OperationKey] using text_units_ok h16, by simpa [Key] using text_units_ok h17,
    by simpa [Key] using text_units_ok h18, by simpa [Key] using text_units_ok h19,
    one_vec rfl h20⟩

/-- **A write waiting for approval.**
    `{"approval":{"digest":D},"event":"approval_requested","grant":G,
    "operation":O,"policy":P,"schema":1}`. -/
theorem approval_requested_record_exact {digest grant operation policy v : json_wire.Value}
    (h : approval_requested_record digest grant operation policy = Result.ok v) :
    ∃ (top approval : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kapproval kdigest kevent kgrant koperation kpolicy kschema : alloc.vec.Vec U32)
      (event : json_wire.Value) (one : alloc.vec.Vec U8),
      v = .Object top ∧
      top.val = [(kapproval, .Object approval), (kevent, event), (kgrant, grant),
        (koperation, operation), (kpolicy, policy), (kschema, .Number one)] ∧
      approval.val = [(kdigest, digest)] ∧
      control.Proofs.IsText event [97#u8, 112#u8, 112#u8, 114#u8, 111#u8, 118#u8, 97#u8, 108#u8, 95#u8,
        114#u8, 101#u8, 113#u8, 117#u8, 101#u8, 115#u8, 116#u8, 101#u8, 100#u8] ∧
      Key kapproval [97#u8, 112#u8, 112#u8, 114#u8, 111#u8, 118#u8, 97#u8, 108#u8] ∧
      Key kdigest [100#u8, 105#u8, 103#u8, 101#u8, 115#u8, 116#u8] ∧
      Key kevent [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      Key kgrant [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      Key koperation OperationKey ∧
      Key kpolicy [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      Key kschema [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      one.val = [49#u8] := by
  unfold approval_requested_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kapproval, h1, h⟩ := bind_ok_inv h
  obtain ⟨kdigest, h2, h⟩ := bind_ok_inv h
  obtain ⟨kevent, h3, h⟩ := bind_ok_inv h
  obtain ⟨event, h4, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, h5, h⟩ := bind_ok_inv h
  obtain ⟨koperation, h6, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, h7, h⟩ := bind_ok_inv h
  obtain ⟨kschema, h8, h⟩ := bind_ok_inv h
  obtain ⟨one, h9, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨eu, he, heu⟩ := control.Proofs.text_ok h4
  exact ⟨_, _, kapproval, kdigest, kevent, kgrant, koperation, kpolicy, kschema, event, one,
    rfl, rfl, rfl, ⟨eu, he, by simpa using heu⟩,
    by simpa [Key] using text_units_ok h1, by simpa [Key] using text_units_ok h2,
    by simpa [Key] using text_units_ok h3, by simpa [Key] using text_units_ok h5,
    by simpa [Key, OperationKey] using text_units_ok h6, by simpa [Key] using text_units_ok h7,
    by simpa [Key] using text_units_ok h8, one_vec rfl h9⟩

/-- **A host approval.**
    `{"digest":D,"event":"approved","grant":G,"policy":P,"schema":1}`. -/
theorem approved_record_exact {digest grant policy v : json_wire.Value}
    (h : approved_record digest grant policy = Result.ok v) :
    ∃ (top : alloc.vec.Vec (alloc.vec.Vec U32 × json_wire.Value))
      (kdigest kevent kgrant kpolicy kschema : alloc.vec.Vec U32) (event : json_wire.Value)
      (one : alloc.vec.Vec U8),
      v = .Object top ∧
      top.val = [(kdigest, digest), (kevent, event), (kgrant, grant), (kpolicy, policy),
        (kschema, .Number one)] ∧
      control.Proofs.IsText event [97#u8, 112#u8, 112#u8, 114#u8, 111#u8, 118#u8, 101#u8, 100#u8] ∧
      Key kdigest [100#u8, 105#u8, 103#u8, 101#u8, 115#u8, 116#u8] ∧
      Key kevent [101#u8, 118#u8, 101#u8, 110#u8, 116#u8] ∧
      Key kgrant [103#u8, 114#u8, 97#u8, 110#u8, 116#u8] ∧
      Key kpolicy [112#u8, 111#u8, 108#u8, 105#u8, 99#u8, 121#u8] ∧
      Key kschema [115#u8, 99#u8, 104#u8, 101#u8, 109#u8, 97#u8] ∧
      one.val = [49#u8] := by
  unfold approved_record at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨kdigest, h1, h⟩ := bind_ok_inv h
  obtain ⟨kevent, h2, h⟩ := bind_ok_inv h
  obtain ⟨event, h3, h⟩ := bind_ok_inv h
  obtain ⟨kgrant, h4, h⟩ := bind_ok_inv h
  obtain ⟨kpolicy, h5, h⟩ := bind_ok_inv h
  obtain ⟨kschema, h6, h⟩ := bind_ok_inv h
  obtain ⟨one, h7, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  obtain ⟨eu, he, heu⟩ := control.Proofs.text_ok h3
  exact ⟨_, kdigest, kevent, kgrant, kpolicy, kschema, event, one, rfl, rfl, ⟨eu, he, by simpa using heu⟩,
    by simpa [Key] using text_units_ok h1, by simpa [Key] using text_units_ok h2,
    by simpa [Key] using text_units_ok h4, by simpa [Key] using text_units_ok h5,
    by simpa [Key] using text_units_ok h6, one_vec rfl h7⟩

end aivm_secrets_garrett_core.session_audit.Proofs
