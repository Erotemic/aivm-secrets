import GarrettNR23ExactSinks
import GarrettNR23WriterOrigin
import GarrettNR23NativeRoute
import GarrettNR23GuestObservations

open Aeneas Aeneas.Std
set_option maxHeartbeats 6000000

/-!
NR-2/NR-3 consolidated stronger *conditional* native-read boundary.
The source-extracted `request_adapter` produces its actual receipts. Every
observed native credential-bearing attempt must then be accounted exactly
ONCE, in order. A successful guest frame is linked to the actual source
completion gates and exact, bounded JSON bytes.

Remaining named, nontrivial native obligations: (1) bind the production
`ManifestProvider` request/audit/setup/send/receive callbacks and `AuditState`
to their extracted core primitives; (2) prove the native sink transcript
matches the extracted sends, including all transitive Rust/TLS/OS/panic paths;
(3) prove the actual serde_json/disclosure to captured JSON conversion;
(4) establish OS audit sync/durability and outside-world observation contracts.
No field of these obligations is silently inferred by Lean compilation.
-/
namespace aivm_secrets_garrett_core.nr23.ProductionBoundary

open aivm_secrets_garrett_core.request_adapter.TraceRefinement
open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.nr23.Effects
open aivm_secrets_garrett_core.nr23.ExactSinks

private abbrev boundAdapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

/-- This is the strongest composed returned *successful* read claim so far.

    Source-derived: the actual request trace, current admission, audit/send
    gate soundness, completed disclosure/audit/freshness, captured request
    binding, exact guest JSON frame and single frame submission.

    External native premises are STILL REQUIRED for all real credential-bearing
    attempts to match modeled sends one-for-one and for actual native
    `Completed::into_value`/`serde_json` to yield the supplied captured JSON.
    A successful `write_all` does not mean provider or guest delivery. -/
theorem accepted_read_has_exact_provider_attempt_accounting_and_guest_frame
    {W F E O X D C V H WriterState WriteError : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (context : NativeContext ops primitive checks capture)
    (initial : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (reply : completion.Completed O)
    (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new ops initial = Result.ok pending)
    (returned : read_transition.run_current (boundAdapter ops) pending =
      Result.ok (.Ok reply))
    (coverage : ExactNativeSinkCoverage ops capture pending (.Ok reply) attempts)
    (toCapturedJson : completion.Completed O → json_wire.Value)
    (fuel : Nat)
    (valid : json_wire.Proofs.Valid fuel (toCapturedJson reply))
    (room : json_wire.Proofs.Bound fuel (toCapturedJson reply) ≤ Usize.max)
    (limit : Usize) (frame afterFrame : guest_frame.Frame)
    (writer nextWriter : WriterState)
    (out : core.result.Result Unit WriteError)
    (writerOps : guest_frame.Writer WriterState WriteError)
    (prepared : json_wire.prepare (toCapturedJson reply) limit =
      Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer =
      Result.ok (out, afterFrame, nextWriter)) :
    (∃ after events,
      read_transition.Proofs.RequestRun (boundAdapter ops) pending (.Ok reply) after ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture pending.work))
        pending.effects after.adapter.effects events ∧
      SoundTrace (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X)) ∧
      BoundTrace (current_admission.Proofs.view (capture pending.work)).binding
        (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X)) ∧
      ExactNativeSinkSequence attempts (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X)) ∧
      (∀ attempt, attempt ∈ attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate =
          (current_admission.Proofs.view (capture pending.work)).binding) ∧
      attempts.length = (sourceSends (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X))).length) ∧
    (∃ completed : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H,
      Reachable completed.effects ∧
      completed.effects.completion.selected = true ∧
      completed.effects.completion.before_checked = true ∧
      completed.effects.completion.audit_attempted = true ∧
      completed.effects.completion.audit_acknowledged = true ∧
      completed.effects.completion.after_checked = true ∧
      completed.effects.completion.value_ready = true) ∧
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) =
      Result.ok (out, nextWriter) ∧
    frame.wire.val = json_wire.Proofs.Bytes fuel (toCapturedJson reply) ++
      [10#u8] ∧
    frame.wire.length ≤ limit.val ∧
    line_frame.Proofs.CompleteLine frame.wire.val ∧
    afterFrame.attempted = true ∧ afterFrame.wire = frame.wire := by
  have recorded := returned_request_has_exactly_accounted_authorized_native_sends
    ops primitive checks capture context initial pending (.Ok reply)
    attempts created returned coverage
  have released := aivm_secrets_garrett_core.nr23.Guest.selected_current_completed_value_has_exact_guest_frame
    ops initial pending reply created returned toCapturedJson fuel valid room
    limit frame afterFrame writer nextWriter out writerOps prepared sent
  obtain ⟨completed, writerCalled, exactBytes, bound, line, marked, retained⟩ :=
    released
  exact ⟨recorded, completed, writerCalled, exactBytes, bound,
    line, marked, retained⟩

/-- Returned source DENIAL does not itself write a native public frame.
    A separately supplied, sanitized fixed error value must still pass
    `json_wire.prepare` and `guest_frame.Frame.send`; source traces and the
    actual returned failure cannot be substituted with a fabricated success.
    The native `Error -> failure(error)` conversion remains external. -/
theorem returned_denial_needs_separate_checked_public_frame
    {W F E O X D C V H WriterState WriteError : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (context : NativeContext ops primitive checks capture)
    (initial : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (error : X) (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new ops initial = Result.ok pending)
    (returned : read_transition.run_current (boundAdapter ops) pending =
      Result.ok (.Err error))
    (coverage : ExactNativeSinkCoverage ops capture pending (.Err error) attempts)
    (denialJson : json_wire.Value) (fuel : Nat)
    (valid : json_wire.Proofs.Valid fuel denialJson)
    (room : json_wire.Proofs.Bound fuel denialJson ≤ Usize.max)
    (limit : Usize) (frame afterFrame : guest_frame.Frame)
    (writer nextWriter : WriterState) (out : core.result.Result Unit WriteError)
    (writerOps : guest_frame.Writer WriterState WriteError)
    (prepared : json_wire.prepare denialJson limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer =
      Result.ok (out, afterFrame, nextWriter)) :
    (∃ after events,
      read_transition.Proofs.RequestRun (boundAdapter ops) pending (.Err error) after ∧
      ExactNativeSinkSequence attempts (withOutcome events (core.result.Result.Err error :
          core.result.Result (completion.Completed O) X)) ∧
      (∀ attempt, attempt ∈ attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate =
          (current_admission.Proofs.view (capture pending.work)).binding) ∧
      attempts.length = (sourceSends (withOutcome events (core.result.Result.Err error :
          core.result.Result (completion.Completed O) X))).length) ∧
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) =
      Result.ok (out, nextWriter) ∧
    frame.wire.val = json_wire.Proofs.Bytes fuel denialJson ++ [10#u8] ∧
    frame.wire.length ≤ limit.val ∧
    line_frame.Proofs.CompleteLine frame.wire.val ∧
    afterFrame.attempted = true ∧ afterFrame.wire = frame.wire := by
  obtain ⟨after, events, ran, _, _, _, exact, secure, count⟩ :=
    returned_request_has_exactly_accounted_authorized_native_sends
      ops primitive checks capture context initial pending (.Err error)
      attempts created returned coverage
  have framed := aivm_secrets_garrett_core.nr23.Guest.returned_denial_frame_has_exact_bounded_single_attempt
    denialJson fuel valid room limit frame afterFrame writer nextWriter out
    writerOps prepared sent
  obtain ⟨wrote, wire, bounded, line, marked, retained⟩ := framed
  exact ⟨⟨after, events, ran, exact, secure, count⟩,
    wrote, wire, bounded, line, marked, retained⟩

/-- Combined provider-byte and guest-frame witness for one selected native
    attempt in a returned successful request. Event coverage comes from the
    actual source-derived trace; `PayloadCorresponds` is the still-external
    link between this particular OS/TLS attempt and the SAME extracted
    channel. Neither callback success nor frame construction asserts delivery.

    This deliberately asks for both the concrete `Channel.submit` result and
    the resulting `Channel.into_parts` success, so a writer error/flush error
    cannot be used as a successful provider response. -/
theorem selected_native_attempt_and_guest_frame_have_exact_captured_bytes
    {W F E O X D C V H WriterState WriteError B PW M PX : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (context : NativeContext ops primitive checks capture)
    (initial : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (reply : completion.Completed O)
    (attempts : List NativeAttempt)
    (chosen : NativeAttempt) (member : chosen ∈ attempts)
    (created : request_adapter.Pending.new ops initial = Result.ok pending)
    (returned : read_transition.run_current (boundAdapter ops) pending =
      Result.ok (.Ok reply))
    (coverage : ExactNativeSinkCoverage ops capture pending (.Ok reply) attempts)
    (wireBytes : provider_io.WireBytes B)
    (providerWriter : provider_io.Writer PW PX)
    (channel afterChannel : provider_io.Channel B PW M PX)
    (providerResult : core.result.Result Unit PX)
    (parts : PW × provider_io.Request B × M)
    (submitted : provider_io.Channel.submit wireBytes providerWriter channel =
      Result.ok (providerResult, afterChannel))
    (released : provider_io.Channel.into_parts wireBytes providerWriter afterChannel =
      Result.ok (.Ok parts))
    (payloadLinked : aivm_secrets_garrett_core.nr23.WriterOrigin.PayloadCorresponds
      wireBytes chosen channel)
    (toCapturedJson : completion.Completed O → json_wire.Value)
    (fuel : Nat)
    (valid : json_wire.Proofs.Valid fuel (toCapturedJson reply))
    (room : json_wire.Proofs.Bound fuel (toCapturedJson reply) ≤ Usize.max)
    (limit : Usize) (frame afterFrame : guest_frame.Frame)
    (guestWriterState nextGuestWriterState : WriterState)
    (guestResult : core.result.Result Unit WriteError)
    (guestWriterOps : guest_frame.Writer WriterState WriteError)
    (prepared : json_wire.prepare (toCapturedJson reply) limit =
      Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send guestWriterOps frame guestWriterState =
      Result.ok (guestResult, afterFrame, nextGuestWriterState)) :
    (chosen.gate.accepted ∧ chosen.auditAck = true ∧
      gateBinding chosen.gate =
        (current_admission.Proofs.view (capture pending.work)).binding) ∧
    (∃ wire written,
      chosen.payload = wire.val ∧
      wireBytes.bytes channel.request.body = Result.ok wire ∧
      providerWriter.write_all channel.writer wire = Result.ok (.Ok (), written) ∧
      providerWriter.flush written = Result.ok (.Ok (), afterChannel.writer)) ∧
    guestWriterOps.write_frame guestWriterState
      (alloc.vec.Vec.deref frame.wire) =
      Result.ok (guestResult, nextGuestWriterState) ∧
    frame.wire.val = json_wire.Proofs.Bytes fuel (toCapturedJson reply) ++
      [10#u8] ∧
    afterFrame.attempted = true := by
  obtain ⟨_, _, _, _, _, _, _, admitted, _⟩ :=
    returned_request_has_exactly_accounted_authorized_native_sends
      ops primitive checks capture context initial pending (.Ok reply)
      attempts created returned coverage
  have nativeBytes :=
    aivm_secrets_garrett_core.nr23.WriterOrigin.admitted_released_channel_pins_observed_native_payload
      wireBytes providerWriter channel afterChannel providerResult parts chosen
      submitted released payloadLinked
  have guestBytes :=
    aivm_secrets_garrett_core.nr23.Guest.selected_current_completed_value_has_exact_guest_frame
      ops initial pending reply created returned toCapturedJson fuel valid room
      limit frame afterFrame guestWriterState nextGuestWriterState guestResult
      guestWriterOps prepared sent
  obtain ⟨_, guestWrote, guestExact, _, _, guestAttempted, _⟩ :=
    guestBytes
  exact ⟨admitted chosen member, nativeBytes, guestWrote, guestExact,
    guestAttempted⟩

end aivm_secrets_garrett_core.nr23.ProductionBoundary
