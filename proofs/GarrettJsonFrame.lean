import GarrettJsonWire

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.json_wire.Proofs

/-- Any returned encoding refusal prevents frame construction. No capacity or
number-token assumption is needed for this failure implication. -/
theorem encoding_refusal_blocks_frame (value : Value) (limit : Usize) (reason : EncodingDenial)
    (refused : encode value = Result.ok (.Err reason)) :
    prepare value limit = Result.ok (.Err guest_frame.FrameDenial.Invalid) := by
  simp [prepare, refused]

theorem prepared_encoding_origin (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) (limit : Usize) (frame : guest_frame.Frame)
    (prepared : prepare value limit = Result.ok (.Ok frame)) :
    ∃ payload, encode value = Result.ok (.Ok payload) ∧ payload.val = Bytes fuel value ∧
      guest_frame.prepare payload limit = Result.ok (.Ok frame) := by
  obtain ⟨payload, encoded, bytes⟩ := encoded_witness fuel value valid room
  exact ⟨payload, encoded, bytes, by simpa [prepare, encoded] using prepared⟩

/-- Native Captured::prepare calls this exact encoder-to-frame composition.
Neither pre-encoded replacement bytes nor a supplied readiness bit is used. -/
theorem prepared_wire_exact (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) (limit : Usize) (frame : guest_frame.Frame)
    (prepared : prepare value limit = Result.ok (.Ok frame)) :
    frame.wire.val = Bytes fuel value ++ [10#u8] ∧ frame.wire.length ≤ limit.val ∧
      line_frame.Proofs.CompleteLine frame.wire.val ∧ frame.attempted = false := by
  obtain ⟨payload, _, bytes, framed⟩ := prepared_encoding_origin fuel value valid room limit frame prepared
  obtain ⟨wire, bounded, line, ready⟩ := guest_frame.Proofs.prepared_wire_is_bounded_single_line payload limit frame framed
  exact ⟨by simpa [bytes] using wire, bounded, line, ready⟩

theorem prepare_admitted_iff (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) (limit : Usize) :
    (∃ frame, prepare value limit = Result.ok (.Ok frame)) ↔
      (Bytes fuel value).length < limit.val ∧ 10#u8 ∉ Bytes fuel value := by
  obtain ⟨payload, encoded, bytes⟩ := encoded_witness fuel value valid room
  simpa only [prepare, encoded, bind_ok, guest_frame.Proofs.Admitted, bytes] using
    guest_frame.Proofs.prepare_admitted_iff payload limit

theorem prepare_denied_iff (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) (limit : Usize) :
    prepare value limit = Result.ok (.Err guest_frame.FrameDenial.Invalid) ↔
      ¬((Bytes fuel value).length < limit.val ∧ 10#u8 ∉ Bytes fuel value) := by
  obtain ⟨payload, encoded, bytes⟩ := encoded_witness fuel value valid room
  obtain ⟨out, returned, property⟩ := returned_of_spec (guest_frame.Proofs.prepare_contract payload limit)
  have call : prepare value limit = Result.ok out := by simpa [prepare, encoded] using returned
  cases out with
  | Err reason =>
    cases reason
    simp only [call, true_iff]
    simpa [guest_frame.Proofs.Admitted, bytes] using property
  | Ok frame =>
    simp only [call, Result.ok.injEq, reduceCtorEq, false_iff, not_not]
    simpa [guest_frame.Proofs.Admitted, bytes] using property.1

theorem framed_value_witness (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) (limit : Usize)
    (fits : (Bytes fuel value).length < limit.val) (line : 10#u8 ∉ Bytes fuel value) :
    ∃ frame, prepare value limit = Result.ok (.Ok frame) ∧
      frame.wire.val = Bytes fuel value ++ [10#u8] ∧ frame.attempted = false := by
  obtain ⟨frame, prepared⟩ := (prepare_admitted_iff fuel value valid room limit).mpr ⟨fits, line⟩
  have actual := prepared_wire_exact fuel value valid room limit frame prepared
  exact ⟨frame, prepared, actual.1, actual.2.2.2⟩

/-- The actual frame send passes exactly the captured value's encoding and LF
 to the writer, including returned write/flush failures and changed writer state. -/
theorem prepared_send_value_origin {W X : Type} (ops : guest_frame.Writer W X)
    (fuel : Nat) (value : Value) (valid : Valid fuel value) (room : Bound fuel value ≤ Usize.max)
    (limit : Usize) (frame after : guest_frame.Frame) (writer next : W)
    (out : core.result.Result Unit X)
    (prepared : prepare value limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send ops frame writer = Result.ok (out, after, next)) :
    ops.write_frame writer (alloc.vec.Vec.deref frame.wire) = Result.ok (out, next) ∧
      frame.wire.val = Bytes fuel value ++ [10#u8] ∧ after.attempted = true ∧ after.wire = frame.wire := by
  obtain ⟨payload, _, bytes, framed⟩ := prepared_encoding_origin fuel value valid room limit frame prepared
  simpa only [bytes] using guest_frame.Proofs.prepared_send_exact ops payload limit frame after writer next out framed sent

/-- This is bounded wire equality for two captured values, not native adaptive
noninterference, delivery/close equality or a disclosure-policy theorem. -/
theorem paired_preparations_same_wire (fuelLeft fuelRight : Nat) (left right : Value)
    (leftValid : Valid fuelLeft left) (rightValid : Valid fuelRight right)
    (leftRoom : Bound fuelLeft left ≤ Usize.max) (rightRoom : Bound fuelRight right ≤ Usize.max)
    (same : Bytes fuelLeft left = Bytes fuelRight right) (limit : Usize)
    (leftFrame rightFrame : guest_frame.Frame)
    (leftPrepared : prepare left limit = Result.ok (.Ok leftFrame))
    (rightPrepared : prepare right limit = Result.ok (.Ok rightFrame)) :
    leftFrame.wire.val = rightFrame.wire.val ∧ leftFrame.attempted = false ∧ rightFrame.attempted = false := by
  have first := prepared_wire_exact fuelLeft left leftValid leftRoom limit leftFrame leftPrepared
  have second := prepared_wire_exact fuelRight right rightValid rightRoom limit rightFrame rightPrepared
  exact ⟨by rw [first.1, second.1, same], first.2.2.2, second.2.2.2⟩

end aivm_secrets_garrett_core.json_wire.Proofs
