import GarrettNR23WriterOrigin
import GarrettNR23Guest
import GarrettNoninterference

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-3 to NR-4 bridge. The source completion gate and native JSON frame encoder
are analyzed as two distinct steps: authorization never by itself emits a
byte; `prepare` and `send` require their own native conversion and writer
correspondence. These paired-run results state precise declassification
conditions instead of asserting unconditional whole-process secrecy.
-/
namespace aivm_secrets_garrett_core.nr23.GuestObservations

open aivm_secrets_garrett_core.nr23.Request
open aivm_secrets_garrett_core.nr23.Guest

private abbrev boundAdapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

/-- A deliberately *internal* completion fact, not a guest observation. -/
def SourceReady {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) : Prop :=
  ∃ completed : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H,
    request_effects.Proofs.Reachable completed.effects ∧
    completed.effects.completion.selected = true ∧
    completed.effects.completion.before_checked = true ∧
    completed.effects.completion.audit_attempted = true ∧
    completed.effects.completion.audit_acknowledged = true ∧
    completed.effects.completion.after_checked = true ∧
    completed.effects.completion.value_ready = true

/-- A returned source success necessarily passed all six completion gates.
    The completion result is still NOT proof of a transmitted native frame. -/
theorem returned_success_establishes_source_ready
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (native : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (reply : completion.Completed O)
    (created : request_adapter.Pending.new ops native = Result.ok pending)
    (returned : read_transition.run_current (boundAdapter ops) pending =
      Result.ok (.Ok reply)) : SourceReady ops := by
  exact returned_success_has_selected_audited_current_value ops native
    pending reply created returned

/-- Two successful source executions whose host-chosen JSON disclosures
    encode to the same bytes produce *identical prepared guest frames*, even
    if their private provider states and raw replies differed. All observable
    error status, reflection rejection, metadata and close behavior remain
    explicit declassification conditions, not conclusions of this theorem. -/
theorem paired_successful_source_reads_prepare_same_guest_bytes
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (nativeA nativeB : W)
    (pendingA pendingB : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (replyA replyB : completion.Completed O)
    (createdA : request_adapter.Pending.new ops nativeA = Result.ok pendingA)
    (createdB : request_adapter.Pending.new ops nativeB = Result.ok pendingB)
    (returnedA : read_transition.run_current (boundAdapter ops) pendingA =
      Result.ok (.Ok replyA))
    (returnedB : read_transition.run_current (boundAdapter ops) pendingB =
      Result.ok (.Ok replyB))
    (toJson : completion.Completed O → json_wire.Value)
    (fuelA fuelB : Nat)
    (validA : json_wire.Proofs.Valid fuelA (toJson replyA))
    (validB : json_wire.Proofs.Valid fuelB (toJson replyB))
    (roomA : json_wire.Proofs.Bound fuelA (toJson replyA) ≤ Usize.max)
    (roomB : json_wire.Proofs.Bound fuelB (toJson replyB) ≤ Usize.max)
    (declassified : json_wire.Proofs.Bytes fuelA (toJson replyA) =
      json_wire.Proofs.Bytes fuelB (toJson replyB))
    (limit : Usize) (frameA frameB : guest_frame.Frame)
    (preparedA : json_wire.prepare (toJson replyA) limit =
      Result.ok (.Ok frameA))
    (preparedB : json_wire.prepare (toJson replyB) limit =
      Result.ok (.Ok frameB)) :
    SourceReady ops ∧
    frameA.wire.val = frameB.wire.val ∧
    frameA.attempted = false ∧ frameB.attempted = false := by
  have first := returned_success_establishes_source_ready ops nativeA
    pendingA replyA createdA returnedA
  have second := returned_success_establishes_source_ready ops nativeB
    pendingB replyB createdB returnedB
  have framed := matching_approved_json_bytes_have_matching_guest_frames
    fuelA fuelB (toJson replyA) (toJson replyB) validA validB roomA roomB
    declassified limit frameA frameB preparedA preparedB
  exact ⟨first, framed.1, framed.2.1, framed.2.2⟩

/-- An attempted frame cannot be silently resent through this source-owned
    frame even when the native writer failed after sending a byte prefix.
    This is a returned-call guarantee, not a network delivery guarantee. -/
theorem failed_public_frame_is_single_attempt
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
    (invalid : writerOps.ALREADY_ATTEMPTED = Result.ok denied) :
    after.attempted = true ∧
    after.wire.val = json_wire.Proofs.Bytes fuel value ++ [10#u8] ∧
    guest_frame.Frame.send writerOps after next =
      Result.ok (.Err denied, after, next) := by
  exact failed_guest_send_preserves_exact_bytes_and_blocks_replay
    writerOps fuel value valid room limit frame after writer next error denied
    prepared sent invalid

/-- Paired *attempted* native frames also preserve the exact byte string
    across writer success/failure. Only the bytes offered to the callback are
    equal: callback returns, partial TCP delivery, timing and connection close
    can still differ and must be included in any stronger NR-4 relation. -/
theorem paired_prepared_frames_preserve_equal_bytes_after_send
    {WriterA WriterB ErrorA ErrorB : Type}
    (writerA : guest_frame.Writer WriterA ErrorA)
    (writerB : guest_frame.Writer WriterB ErrorB)
    (fuelA fuelB : Nat) (jsonA jsonB : json_wire.Value)
    (validA : json_wire.Proofs.Valid fuelA jsonA)
    (validB : json_wire.Proofs.Valid fuelB jsonB)
    (roomA : json_wire.Proofs.Bound fuelA jsonA ≤ Usize.max)
    (roomB : json_wire.Proofs.Bound fuelB jsonB ≤ Usize.max)
    (same : json_wire.Proofs.Bytes fuelA jsonA =
      json_wire.Proofs.Bytes fuelB jsonB)
    (limit : Usize) (frameA frameB afterA afterB : guest_frame.Frame)
    (beforeA nextA : WriterA) (beforeB nextB : WriterB)
    (outA : core.result.Result Unit ErrorA)
    (outB : core.result.Result Unit ErrorB)
    (preparedA : json_wire.prepare jsonA limit = Result.ok (.Ok frameA))
    (preparedB : json_wire.prepare jsonB limit = Result.ok (.Ok frameB))
    (sentA : guest_frame.Frame.send writerA frameA beforeA =
      Result.ok (outA, afterA, nextA))
    (sentB : guest_frame.Frame.send writerB frameB beforeB =
      Result.ok (outB, afterB, nextB)) :
    frameA.wire.val = frameB.wire.val ∧
    afterA.wire.val = afterB.wire.val ∧
    afterA.attempted = true ∧ afterB.attempted = true ∧
    writerA.write_frame beforeA (alloc.vec.Vec.deref frameA.wire) =
      Result.ok (outA, nextA) ∧
    writerB.write_frame beforeB (alloc.vec.Vec.deref frameB.wire) =
      Result.ok (outB, nextB) := by
  have source := matching_approved_json_bytes_have_matching_guest_frames
    fuelA fuelB jsonA jsonB validA validB roomA roomB same limit frameA frameB
    preparedA preparedB
  have left := json_wire.Proofs.prepared_send_value_origin writerA fuelA jsonA
    validA roomA limit frameA afterA beforeA nextA outA preparedA sentA
  have right := json_wire.Proofs.prepared_send_value_origin writerB fuelB jsonB
    validB roomB limit frameB afterB beforeB nextB outB preparedB sentB
  have frameEq : afterA.wire.val = afterB.wire.val := by
    rw [left.2.2.2, right.2.2.2]
    exact source.1
  exact ⟨source.1, frameEq, left.2.2.1, right.2.2.1,
    left.1, right.1⟩

end aivm_secrets_garrett_core.nr23.GuestObservations
