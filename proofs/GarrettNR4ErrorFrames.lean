import GarrettNR4ProjectedRelease

open Aeneas Aeneas.Std
set_option maxHeartbeats 6000000

/-!
NR-4 denial-path byte semantics, separated from successful selection.

Actual native `tls::failure(Error)` uses a bounded public error taxonomy.
This module verifies what follows when native errors are classified into that
taxonomy and the resulting JSON is passed to the extracted encoder and
single-use frame writer. The Rust Error -> category -> serde_json conversion
is still a production correspondence obligation; the theorem explicitly
requires that bridge and does not confuse it with a secret-independent error.
-/
namespace aivm_secrets_garrett_core.nr4.ErrorFrames

open aivm_secrets_garrett_core.nr23.Guest
open aivm_secrets_garrett_core.nr23.GuestObservations

/-- Externally distinguishable classes in the reviewed native `failure`
    function. The taxonomy is a model, not an extracted Rust enum. -/
inductive PublicDenial where
  | invalidCapability
  | invalidRequest
  | denied
  | unsafeFile
  | outcomeUnknown
  | generic
  deriving DecidableEq, Repr

/-- An explicit native correspondence contract. Returning an arbitrary error
    string or private `Debug` dump would violate this contract. -/
def SanitizesTo {Error : Type}
    (classify : Error → PublicDenial)
    (publicJson : PublicDenial → json_wire.Value)
    (captureNativeFailure : Error → json_wire.Value)
    (error : Error) : Prop :=
  captureNativeFailure error = publicJson (classify error)

/-- Equal public denial classes force equal JSON inputs to the frame encoder,
    even if the underlying native error values are different. -/
theorem same_denial_class_has_equal_sanitized_json
    {ErrorLeft ErrorRight : Type}
    (classifyLeft : ErrorLeft → PublicDenial)
    (classifyRight : ErrorRight → PublicDenial)
    (publicJson : PublicDenial → json_wire.Value)
    (nativeLeft : ErrorLeft → json_wire.Value)
    (nativeRight : ErrorRight → json_wire.Value)
    (errorLeft : ErrorLeft) (errorRight : ErrorRight)
    (linkedLeft : SanitizesTo classifyLeft publicJson nativeLeft errorLeft)
    (linkedRight : SanitizesTo classifyRight publicJson nativeRight errorRight)
    (sameClass : classifyLeft errorLeft = classifyRight errorRight) :
    nativeLeft errorLeft = nativeRight errorRight := by
  unfold SanitizesTo at linkedLeft linkedRight
  rw [linkedLeft, linkedRight, sameClass]

/-- Equal public error classes give identical complete, bounded native JSON
    frame buffers, without assuming equality of secret native errors. -/
theorem same_denial_class_prepares_equal_wire
    {ErrorLeft ErrorRight : Type}
    (classifyLeft : ErrorLeft → PublicDenial)
    (classifyRight : ErrorRight → PublicDenial)
    (publicJson : PublicDenial → json_wire.Value)
    (nativeLeft : ErrorLeft → json_wire.Value)
    (nativeRight : ErrorRight → json_wire.Value)
    (errorLeft : ErrorLeft) (errorRight : ErrorRight)
    (linkedLeft : SanitizesTo classifyLeft publicJson nativeLeft errorLeft)
    (linkedRight : SanitizesTo classifyRight publicJson nativeRight errorRight)
    (sameClass : classifyLeft errorLeft = classifyRight errorRight)
    (depth : Nat)
    (validLeft : json_wire.Proofs.Valid depth (nativeLeft errorLeft))
    (validRight : json_wire.Proofs.Valid depth (nativeRight errorRight))
    (roomLeft : json_wire.Proofs.Bound depth (nativeLeft errorLeft) ≤ Usize.max)
    (roomRight : json_wire.Proofs.Bound depth (nativeRight errorRight) ≤ Usize.max)
    (limit : Usize) (frameLeft frameRight : guest_frame.Frame)
    (preparedLeft : json_wire.prepare (nativeLeft errorLeft) limit =
      Result.ok (.Ok frameLeft))
    (preparedRight : json_wire.prepare (nativeRight errorRight) limit =
      Result.ok (.Ok frameRight)) :
    frameLeft.wire.val = frameRight.wire.val ∧
    frameLeft.attempted = false ∧ frameRight.attempted = false := by
  have equalJson := same_denial_class_has_equal_sanitized_json
    classifyLeft classifyRight publicJson nativeLeft nativeRight
    errorLeft errorRight linkedLeft linkedRight sameClass
  have equalBytes :
      json_wire.Proofs.Bytes depth (nativeLeft errorLeft) =
      json_wire.Proofs.Bytes depth (nativeRight errorRight) := by
    rw [equalJson]
  exact matching_approved_json_bytes_have_matching_guest_frames
    depth depth (nativeLeft errorLeft) (nativeRight errorRight)
    validLeft validRight roomLeft roomRight equalBytes limit
    frameLeft frameRight preparedLeft preparedRight

/-- Even if both native writer outcomes differ, the attempted error-frame
    BYTES remain equal, provided the public classes agree. Observable success,
    failure, timing, partial transport and close behavior remain separate. -/
theorem same_denial_class_has_equal_offered_bytes_after_send
    {ErrorLeft ErrorRight WriterLeft WriterRight WriteErrorLeft WriteErrorRight : Type}
    (classifyLeft : ErrorLeft → PublicDenial)
    (classifyRight : ErrorRight → PublicDenial)
    (publicJson : PublicDenial → json_wire.Value)
    (nativeLeft : ErrorLeft → json_wire.Value)
    (nativeRight : ErrorRight → json_wire.Value)
    (errorLeft : ErrorLeft) (errorRight : ErrorRight)
    (linkedLeft : SanitizesTo classifyLeft publicJson nativeLeft errorLeft)
    (linkedRight : SanitizesTo classifyRight publicJson nativeRight errorRight)
    (sameClass : classifyLeft errorLeft = classifyRight errorRight)
    (depth : Nat)
    (validLeft : json_wire.Proofs.Valid depth (nativeLeft errorLeft))
    (validRight : json_wire.Proofs.Valid depth (nativeRight errorRight))
    (roomLeft : json_wire.Proofs.Bound depth (nativeLeft errorLeft) ≤ Usize.max)
    (roomRight : json_wire.Proofs.Bound depth (nativeRight errorRight) ≤ Usize.max)
    (limit : Usize)
    (frameLeft frameRight afterLeft afterRight : guest_frame.Frame)
    (writerLeft : guest_frame.Writer WriterLeft WriteErrorLeft)
    (writerRight : guest_frame.Writer WriterRight WriteErrorRight)
    (beforeLeft nextLeft : WriterLeft) (beforeRight nextRight : WriterRight)
    (outLeft : core.result.Result Unit WriteErrorLeft)
    (outRight : core.result.Result Unit WriteErrorRight)
    (preparedLeft : json_wire.prepare (nativeLeft errorLeft) limit =
      Result.ok (.Ok frameLeft))
    (preparedRight : json_wire.prepare (nativeRight errorRight) limit =
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
  have equalJson := same_denial_class_has_equal_sanitized_json
    classifyLeft classifyRight publicJson nativeLeft nativeRight
    errorLeft errorRight linkedLeft linkedRight sameClass
  have equalBytes :
      json_wire.Proofs.Bytes depth (nativeLeft errorLeft) =
      json_wire.Proofs.Bytes depth (nativeRight errorRight) := by
    rw [equalJson]
  exact paired_prepared_frames_preserve_equal_bytes_after_send
    writerLeft writerRight depth depth (nativeLeft errorLeft)
    (nativeRight errorRight) validLeft validRight roomLeft roomRight
    equalBytes limit frameLeft frameRight afterLeft afterRight
    beforeLeft nextLeft beforeRight nextRight outLeft outRight
    preparedLeft preparedRight sentLeft sentRight

/-- A guest-frame write failure cannot turn a spent frame into a second
    attempt. The partial bytes already transmitted by the writer are unknown,
    and this theorem correctly does not assert that they were rolled back. -/
theorem native_error_frame_failure_is_single_attempt
    {WriterState WriteError : Type}
    (writerOps : guest_frame.Writer WriterState WriteError)
    (value : json_wire.Value) (depth : Nat)
    (valid : json_wire.Proofs.Valid depth value)
    (room : json_wire.Proofs.Bound depth value ≤ Usize.max)
    (limit : Usize) (frame after : guest_frame.Frame)
    (before next : WriterState) (writeError denied : WriteError)
    (prepared : json_wire.prepare value limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame before =
      Result.ok (.Err writeError, after, next))
    (constant : writerOps.ALREADY_ATTEMPTED = Result.ok denied) :
    after.attempted = true ∧
    after.wire.val = json_wire.Proofs.Bytes depth value ++ [10#u8] ∧
    guest_frame.Frame.send writerOps after next =
      Result.ok (.Err denied, after, next) := by
  exact failed_guest_send_preserves_exact_bytes_and_blocks_replay
    writerOps depth value valid room limit frame after before next
    writeError denied prepared sent constant

/-- Error taxonomy is not a noninterference guarantee: these distinct
    public classifications are *intentionally* observable. -/
theorem revoked_and_generic_are_distinguishable :
    PublicDenial.invalidCapability ≠ PublicDenial.generic := by
  decide

end aivm_secrets_garrett_core.nr4.ErrorFrames
