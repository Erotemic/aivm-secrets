import GarrettNR23ProductionBoundary
import GarrettNoninterference
import GarrettSelectedConversionInput

open Aeneas Aeneas.Std
set_option maxHeartbeats 6000000

/-!
NR-4 source disclosure to native *offered byte* refinement.

The key improvement over NR-3's paired frame theorem is that we no longer
assume an arbitrary equality of encoded guest buffers.  For successful
selected disclosures, equality is derived from the actual extracted recursive
projection under W5's ProjectionAgreement.  The remaining conversion
obligation has a narrow shape: the production path must turn the *selected*
value, not an unreviewed raw provider response, into the captured JSON.

Nothing here asserts that write_all delivers bytes, that denial messages are
constant, or that timing/close/status metadata is secret-independent.
-/
namespace aivm_secrets_garrett_core.nr4.ProjectedRelease

open aivm_secrets_garrett_core.confinement.W5
open aivm_secrets_garrett_core.nr23.Guest
open aivm_secrets_garrett_core.nr23.GuestObservations

/-- Under the actual extracted recursive projection's agreement relation,
    successful projections must select the same value.  Unlike a postulated
    equal-JSON-output premise, this follows from the source-linked recursive
    projection noninterference theorem. -/
theorem selected_values_equal_of_recursive_agreement
    (left right : Json) (schema : Projection) (fuel budget : Usize)
    (agree : disclosure.Proofs.ProjectionAgreement fuel.val left right schema)
    (selectedLeft selectedRight : Selection)
    (leftReturned : disclosure.project left schema fuel budget =
      Result.ok (.Ok selectedLeft))
    (rightReturned : disclosure.project right schema fuel budget =
      Result.ok (.Ok selectedRight)) :
    selectedLeft = selectedRight := by
  have projected := disclosure.Proofs.recursive_projection_noninterference
    left right schema fuel budget agree
  rw [leftReturned, rightReturned] at projected
  have inner := Result.ok_injective projected
  injection inner with sameSelection

/-- The production-specific representation conversion must be related to a
    host-chosen encoding of the extracted selected value. This is NOT an
    inferred Rust/serde property: it is the outstanding bridge to be proved
    from Completed::into_value, json::capture and the native frame path. -/
def SelectedConversion {O : Type}
    (capture : completion.Completed O → json_wire.Value)
    (encodeSelected : Selection → json_wire.Value)
    (completed : completion.Completed O)
    (selected : Selection) : Prop :=
  capture completed = encodeSelected selected

/-- The selected-value conversion bridge and recursive agreement derive
    equality of captured JSON values, before any byte-encoder assumption. -/
theorem selected_conversion_preserves_projection_agreement
    {O : Type}
    (left right : Json) (schema : Projection) (fuel budget : Usize)
    (agree : disclosure.Proofs.ProjectionAgreement fuel.val left right schema)
    (selectedLeft selectedRight : Selection)
    (leftReturned : disclosure.project left schema fuel budget =
      Result.ok (.Ok selectedLeft))
    (rightReturned : disclosure.project right schema fuel budget =
      Result.ok (.Ok selectedRight))
    (completedLeft completedRight : completion.Completed O)
    (capture : completion.Completed O → json_wire.Value)
    (encodeSelected : Selection → json_wire.Value)
    (linkedLeft : SelectedConversion capture encodeSelected
      completedLeft selectedLeft)
    (linkedRight : SelectedConversion capture encodeSelected
      completedRight selectedRight) :
    capture completedLeft = capture completedRight := by
  have selectedEq := selected_values_equal_of_recursive_agreement
    left right schema fuel budget agree selectedLeft selectedRight
    leftReturned rightReturned
  unfold SelectedConversion at linkedLeft linkedRight
  rw [linkedLeft, linkedRight, selectedEq]

/-- Equal source-approved captured JSON values have equal encoded bytes under
    a COMMON reviewed encoder and depth. No equality of output bytes is
    postulated. -/
theorem approved_conversion_yields_equal_byte_encoding
    {O : Type}
    (left right : Json) (schema : Projection) (fuel budget : Usize)
    (agree : disclosure.Proofs.ProjectionAgreement fuel.val left right schema)
    (selectedLeft selectedRight : Selection)
    (leftReturned : disclosure.project left schema fuel budget =
      Result.ok (.Ok selectedLeft))
    (rightReturned : disclosure.project right schema fuel budget =
      Result.ok (.Ok selectedRight))
    (completedLeft completedRight : completion.Completed O)
    (capture : completion.Completed O → json_wire.Value)
    (encodeSelected : Selection → json_wire.Value)
    (linkedLeft : SelectedConversion capture encodeSelected
      completedLeft selectedLeft)
    (linkedRight : SelectedConversion capture encodeSelected
      completedRight selectedRight)
    (depth : Nat) :
    json_wire.Proofs.Bytes depth (capture completedLeft) =
      json_wire.Proofs.Bytes depth (capture completedRight) := by
  have equal := selected_conversion_preserves_projection_agreement
    left right schema fuel budget agree selectedLeft selectedRight
    leftReturned rightReturned completedLeft completedRight capture
    encodeSelected linkedLeft linkedRight
  rw [equal]

/-- This theorem finally joins the recursive source projection to the
    *actual extracted* JSON frame preparation result. It removes NR-3's
    independent byte-equality assumption. The remaining selected-conversion
    assumptions are the exact production serde/Completed edge. -/
theorem successful_approved_projection_prepares_identical_guest_frames
    {O : Type}
    (left right : Json) (schema : Projection) (fuel budget : Usize)
    (agree : disclosure.Proofs.ProjectionAgreement fuel.val left right schema)
    (selectedLeft selectedRight : Selection)
    (leftReturned : disclosure.project left schema fuel budget =
      Result.ok (.Ok selectedLeft))
    (rightReturned : disclosure.project right schema fuel budget =
      Result.ok (.Ok selectedRight))
    (completedLeft completedRight : completion.Completed O)
    (capture : completion.Completed O → json_wire.Value)
    (encodeSelected : Selection → json_wire.Value)
    (linkedLeft : SelectedConversion capture encodeSelected
      completedLeft selectedLeft)
    (linkedRight : SelectedConversion capture encodeSelected
      completedRight selectedRight)
    (depth : Nat)
    (validLeft : json_wire.Proofs.Valid depth (capture completedLeft))
    (validRight : json_wire.Proofs.Valid depth (capture completedRight))
    (roomLeft : json_wire.Proofs.Bound depth (capture completedLeft) ≤ Usize.max)
    (roomRight : json_wire.Proofs.Bound depth (capture completedRight) ≤ Usize.max)
    (limit : Usize) (frameLeft frameRight : guest_frame.Frame)
    (preparedLeft : json_wire.prepare (capture completedLeft) limit =
      Result.ok (.Ok frameLeft))
    (preparedRight : json_wire.prepare (capture completedRight) limit =
      Result.ok (.Ok frameRight)) :
    frameLeft.wire.val = frameRight.wire.val ∧
      frameLeft.attempted = false ∧ frameRight.attempted = false := by
  have equalBytes := approved_conversion_yields_equal_byte_encoding
    left right schema fuel budget agree selectedLeft selectedRight
    leftReturned rightReturned completedLeft completedRight capture
    encodeSelected linkedLeft linkedRight depth
  exact matching_approved_json_bytes_have_matching_guest_frames
    depth depth (capture completedLeft) (capture completedRight)
    validLeft validRight roomLeft roomRight equalBytes limit
    frameLeft frameRight preparedLeft preparedRight

/-- Submission does not invalidate the byte-equality guarantee, even when
    one writer returns a failure and the other returns success. The *public*
    difference in writer outcomes remains explicitly observable. -/
theorem successful_approved_projection_offers_identical_bytes_after_send
    {O WriterLeft WriterRight ErrorLeft ErrorRight : Type}
    (left right : Json) (schema : Projection) (fuel budget : Usize)
    (agree : disclosure.Proofs.ProjectionAgreement fuel.val left right schema)
    (selectedLeft selectedRight : Selection)
    (leftReturned : disclosure.project left schema fuel budget =
      Result.ok (.Ok selectedLeft))
    (rightReturned : disclosure.project right schema fuel budget =
      Result.ok (.Ok selectedRight))
    (completedLeft completedRight : completion.Completed O)
    (capture : completion.Completed O → json_wire.Value)
    (encodeSelected : Selection → json_wire.Value)
    (linkedLeft : SelectedConversion capture encodeSelected
      completedLeft selectedLeft)
    (linkedRight : SelectedConversion capture encodeSelected
      completedRight selectedRight)
    (depth : Nat)
    (validLeft : json_wire.Proofs.Valid depth (capture completedLeft))
    (validRight : json_wire.Proofs.Valid depth (capture completedRight))
    (roomLeft : json_wire.Proofs.Bound depth (capture completedLeft) ≤ Usize.max)
    (roomRight : json_wire.Proofs.Bound depth (capture completedRight) ≤ Usize.max)
    (limit : Usize)
    (frameLeft frameRight afterLeft afterRight : guest_frame.Frame)
    (writerLeft : guest_frame.Writer WriterLeft ErrorLeft)
    (writerRight : guest_frame.Writer WriterRight ErrorRight)
    (beforeLeft nextLeft : WriterLeft) (beforeRight nextRight : WriterRight)
    (outLeft : core.result.Result Unit ErrorLeft)
    (outRight : core.result.Result Unit ErrorRight)
    (preparedLeft : json_wire.prepare (capture completedLeft) limit =
      Result.ok (.Ok frameLeft))
    (preparedRight : json_wire.prepare (capture completedRight) limit =
      Result.ok (.Ok frameRight))
    (sentLeft : guest_frame.Frame.send writerLeft frameLeft beforeLeft =
      Result.ok (outLeft, afterLeft, nextLeft))
    (sentRight : guest_frame.Frame.send writerRight frameRight beforeRight =
      Result.ok (outRight, afterRight, nextRight)) :
    frameLeft.wire.val = frameRight.wire.val ∧
    afterLeft.wire.val = afterRight.wire.val ∧
    afterLeft.attempted = true ∧ afterRight.attempted = true ∧
    writerLeft.write_frame beforeLeft (alloc.vec.Vec.deref frameLeft.wire) =
      Result.ok (outLeft, nextLeft) ∧
    writerRight.write_frame beforeRight (alloc.vec.Vec.deref frameRight.wire) =
      Result.ok (outRight, nextRight) := by
  have equalBytes := approved_conversion_yields_equal_byte_encoding
    left right schema fuel budget agree selectedLeft selectedRight
    leftReturned rightReturned completedLeft completedRight capture
    encodeSelected linkedLeft linkedRight depth
  exact paired_prepared_frames_preserve_equal_bytes_after_send
    writerLeft writerRight depth depth (capture completedLeft)
    (capture completedRight) validLeft validRight roomLeft roomRight
    equalBytes limit frameLeft frameRight afterLeft afterRight
    beforeLeft nextLeft beforeRight nextRight outLeft outRight
    preparedLeft preparedRight sentLeft sentRight

/-- Ignored fields supply concrete variation in secret provider data without
    requiring a guessed equality of declassified observations. The extracted
    disclosure proof establishes their equality for a selected projection. -/
theorem ignored_field_change_preserves_modeled_guest_messages
    (schema : Projection) (keyName hidden : alloc.vec.Vec U8)
    (different : hidden ≠ keyName) (pathTail : List (alloc.vec.Vec U8))
    (starts : schema.at.val = keyName :: pathTail)
    (left right : Json) (rest : List ((alloc.vec.Vec U8) × Json))
    (bound : rest.length + 1 ≤ Usize.max) (fuel budget : Usize) :
    observeTrace (aivm_secrets_garrett_core.confinement.Proofs.disclose
      (.Object (alloc.vec.Vec.from ((hidden, left) :: rest) (by simpa using bound)))
      schema fuel budget) =
    observeTrace (aivm_secrets_garrett_core.confinement.Proofs.disclose
      (.Object (alloc.vec.Vec.from ((hidden, right) :: rest) (by simpa using bound)))
      schema fuel budget) := by
  exact ignored_provider_field_noninterference schema keyName hidden
    different pathTail starts left right rest bound fuel budget

end aivm_secrets_garrett_core.nr4.ProjectedRelease
