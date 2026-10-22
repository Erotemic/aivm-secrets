import GarrettNR23Request
import GarrettJsonFrame

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-2/NR-3 completion-to-guest edge. The returned request kernel and the
*source-owned* `json_wire.prepare`/`guest_frame.Frame.send` are composed.
This is not a theorem about `serde_json::Value` -> `json_wire::Value`, nor
about rustls delivery or connection close: those native conversion/transport
bindings remain explicit obligations. Successful completion is not conflated
with successful frame delivery. All writer errors consume the attempt.
-/
namespace aivm_secrets_garrett_core.nr23.Guest

open aivm_secrets_garrett_core.nr23.Request
open aivm_secrets_garrett_core.request_adapter.TraceRefinement

private abbrev adapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

/-- The selected value has passed the *actual* source completion controller,
    both post-selection freshness checks, and completion audit before the
    native writer sees exactly the prepared JSON value bytes plus LF.

    `toCapturedJson` is a supplied native conversion function. The production
    bridge must be shown to feed the `Completed::into_value` result through
    `json::capture` and `json_wire::prepare`; this theorem does not assume
    the source-produced reply equals arbitrary guest input. -/
theorem selected_current_completed_value_has_exact_guest_frame
    {W F E O X D C V H WriterState WriteError : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (native : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (reply : completion.Completed O)
    (created : request_adapter.Pending.new ops native = Result.ok pending)
    (returned : read_transition.run_current (adapter ops) pending =
      Result.ok (.Ok reply))
    (toCapturedJson : completion.Completed O → json_wire.Value)
    (fuel : Nat)
    (valid : json_wire.Proofs.Valid fuel (toCapturedJson reply))
    (room : json_wire.Proofs.Bound fuel (toCapturedJson reply) ≤ Usize.max)
    (limit : Usize) (frame after : guest_frame.Frame)
    (writer next : WriterState) (out : core.result.Result Unit WriteError)
    (writerOps : guest_frame.Writer WriterState WriteError)
    (prepared : json_wire.prepare (toCapturedJson reply) limit =
      Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer =
      Result.ok (out, after, next)) :
    (∃ completed : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H,
      request_effects.Proofs.Reachable completed.effects ∧
      completed.effects.completion.selected = true ∧
      completed.effects.completion.before_checked = true ∧
      completed.effects.completion.audit_attempted = true ∧
      completed.effects.completion.audit_acknowledged = true ∧
      completed.effects.completion.after_checked = true ∧
      completed.effects.completion.value_ready = true) ∧
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) =
      Result.ok (out, next) ∧
    frame.wire.val = json_wire.Proofs.Bytes fuel (toCapturedJson reply) ++
      [10#u8] ∧
    frame.wire.length ≤ limit.val ∧
    line_frame.Proofs.CompleteLine frame.wire.val ∧
    after.attempted = true ∧ after.wire = frame.wire := by
  have completed := returned_success_has_selected_audited_current_value
    ops native pending reply created returned
  have exact := json_wire.Proofs.prepared_send_value_origin writerOps fuel
    (toCapturedJson reply) valid room limit frame after writer next out
    prepared sent
  have bounded := json_wire.Proofs.prepared_wire_exact fuel
    (toCapturedJson reply) valid room limit frame prepared
  exact ⟨completed, exact.1, exact.2.1, bounded.2.1,
    bounded.2.2.1, exact.2.2.1, exact.2.2.2⟩

/-- If the native captured reply cannot be encoded, the source-owned
    `json_wire.prepare` refuses *before* constructing any frame. This does not
    imply that a separate unreviewed native writer cannot be reached. -/
theorem refused_encoding_constructs_no_guest_frame
    (value : json_wire.Value) (limit : Usize)
    (reason : json_wire.EncodingDenial)
    (refused : json_wire.encode value = Result.ok (.Err reason)) :
    ∀ frame, json_wire.prepare value limit ≠ Result.ok (.Ok frame) := by
  intro frame hypothetical
  have denied := json_wire.Proofs.encoding_refusal_blocks_frame
    value limit reason refused
  -- `Result.ok` is coinductive in the Aeneas model, so eliminating its
  -- equality directly does not discriminate the inner `Err`/`Ok` constructors.
  -- First use the proved result-constructor injectivity lemma.
  simp only [denied, Result.ok.injEq, reduceCtorEq] at hypothetical

/-- Even when a native writer partially accepts a JSON frame and then fails,
    a second call through the same frame is refused without another callback.
    The source-produced single newline frame remains immutable. -/
theorem failed_guest_send_preserves_exact_bytes_and_blocks_replay
    {WriterState WriteError : Type}
    (writerOps : guest_frame.Writer WriterState WriteError)
    (fuel : Nat) (value : json_wire.Value)
    (valid : json_wire.Proofs.Valid fuel value)
    (room : json_wire.Proofs.Bound fuel value ≤ Usize.max)
    (limit : Usize) (frame after : guest_frame.Frame)
    (writer next : WriterState) (error denied : WriteError)
    (prepared : json_wire.prepare value limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer =
      Result.ok (.Err error, after, next))
    (constant : writerOps.ALREADY_ATTEMPTED = Result.ok denied) :
    after.attempted = true ∧
    after.wire.val = json_wire.Proofs.Bytes fuel value ++ [10#u8] ∧
    guest_frame.Frame.send writerOps after next =
      Result.ok (.Err denied, after, next) := by
  have boundary := json_wire.Proofs.prepared_wire_exact fuel value valid room
    limit frame prepared
  have failed := json_wire.Proofs.prepared_send_value_origin writerOps fuel
    value valid room limit frame after writer next (.Err error) prepared sent
  have cannotRetry := guest_frame.Proofs.failed_send_cannot_retry writerOps
    frame after writer next error denied boundary.2.2.2 sent constant
  exact ⟨failed.2.2.1, by rw [failed.2.2.2]; exact boundary.1, cannotRetry⟩

/-- Two native prepared replies for the same allowed JSON bytes have exactly
    equal bounded wire contents; caller must prove the two values encode to
    the same permitted bytes. This is a byte bridge for later NR-4, not a
    postulated native noninterference result. -/
theorem matching_approved_json_bytes_have_matching_guest_frames
    (fuelA fuelB : Nat) (valueA valueB : json_wire.Value)
    (validA : json_wire.Proofs.Valid fuelA valueA)
    (validB : json_wire.Proofs.Valid fuelB valueB)
    (roomA : json_wire.Proofs.Bound fuelA valueA ≤ Usize.max)
    (roomB : json_wire.Proofs.Bound fuelB valueB ≤ Usize.max)
    (same : json_wire.Proofs.Bytes fuelA valueA =
      json_wire.Proofs.Bytes fuelB valueB)
    (limit : Usize) (frameA frameB : guest_frame.Frame)
    (preparedA : json_wire.prepare valueA limit = Result.ok (.Ok frameA))
    (preparedB : json_wire.prepare valueB limit = Result.ok (.Ok frameB)) :
    frameA.wire.val = frameB.wire.val ∧
    frameA.attempted = false ∧ frameB.attempted = false := by
  exact json_wire.Proofs.paired_preparations_same_wire fuelA fuelB
    valueA valueB validA validB roomA roomB same limit frameA frameB
    preparedA preparedB

/-- A returned native error converted to a *host-chosen* fixed denial JSON
    value cannot be emitted through the reviewed frame path without passing
    the same exact encoder, bound, LF and single-send gate as a successful
    value. The native `Error -> failure(error) -> serde_json::Value` conversion
    is a distinct, still-unproved Rust correspondence obligation; the caller
    cannot use this theorem to claim the native error was safely sanitized. -/
theorem returned_denial_frame_has_exact_bounded_single_attempt
    {WriterState WriteError : Type}
    (failureJson : json_wire.Value) (fuel : Nat)
    (valid : json_wire.Proofs.Valid fuel failureJson)
    (room : json_wire.Proofs.Bound fuel failureJson ≤ Usize.max)
    (limit : Usize) (frame after : guest_frame.Frame)
    (writer next : WriterState) (out : core.result.Result Unit WriteError)
    (writerOps : guest_frame.Writer WriterState WriteError)
    (prepared : json_wire.prepare failureJson limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer =
      Result.ok (out, after, next)) :
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) =
      Result.ok (out, next) ∧
    frame.wire.val = json_wire.Proofs.Bytes fuel failureJson ++ [10#u8] ∧
    frame.wire.length ≤ limit.val ∧
    line_frame.Proofs.CompleteLine frame.wire.val ∧
    after.attempted = true ∧ after.wire = frame.wire := by
  have exact := json_wire.Proofs.prepared_send_value_origin writerOps fuel
    failureJson valid room limit frame after writer next out prepared sent
  have bounded := json_wire.Proofs.prepared_wire_exact fuel failureJson
    valid room limit frame prepared
  exact ⟨exact.1, exact.2.1, bounded.2.1, bounded.2.2.1,
    exact.2.2.1, exact.2.2.2⟩

end aivm_secrets_garrett_core.nr23.Guest
