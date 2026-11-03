import GarrettNR23ProductionBoundary
import GarrettRequestContext
import GarrettPublicError
import GarrettNativeSendLog

open Aeneas Aeneas.Std
set_option maxHeartbeats 6000000

/-!
NR-2/NR-3 top-level read statements specialized to the request type that
production actually runs: `custody/manifest_session.rs` wraps its native
closures in the extracted `request_context::ScopedRequest` and then calls
`request_adapter::Pending::new` and `read_transition::run_current`.

For that instance the former `NativeContext` premise (the native adapter must
keep its captured admission context and build every dispatch plan from it) is
*proved* by `request_context.Proofs.native_context_contract`, and the context
seen by every trace is the exact one passed to `ScopedRequest::new`. These
theorems therefore drop `NativeContext` and the caller-chosen `capture`
function; the remaining native premises are named below, unchanged.

The denial frame is no longer a premise either: `GarrettPublicError` proves
the extracted `public_error::denial_frame` emits one of 17 fixed JSON lines.

The first three theorems still assume `ExactNativeSinkCoverage`: a list of
native attempts, labelled with source gates, equals the source sends. The
last three (`production_request_sends_are_the_logged_sends` and the two that
build on it) drop it. They derive the count instead: the extracted request
asks its dispatch primitive's `send` for exactly as many provider sends as
the source trace has `providerSend` events (`GarrettNativeSendLog`), and
labelling those sends in order with the source events gives an exact sink
sequence. What stays native is narrower (`NATIVE-SINK-01`): every
credential-bearing provider write happens inside one call of the
primitive's `send` (`Submitting::send` → `Channel::submit` →
`ProviderWriter::write_all` in `custody/provider_stream.rs`), at most once
per call. Also still assumed: the native completion-to-JSON conversion
(`toCapturedJson` and its `Valid`/`Bound`). No delivery, durability or TLS
property is stated.
-/
namespace aivm_secrets_garrett_core.production.Assurance

open aivm_secrets_garrett_core.request_adapter.TraceRefinement
open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.nr23.Effects
open aivm_secrets_garrett_core.nr23.ExactSinks
open aivm_secrets_garrett_core.request_context

/-- The production `request_adapter::Work` instance: `ScopedRequest` over the
    native closures `work`, check factory `factory` and route callbacks. -/
abbrev scopedOps {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X) :=
  ScopedRequest.Insts.Aivm_secrets_garrett_coreRequest_adapterWorkClause0_FactsClause0_EffectClause0_OutputClause0_ErrorBoundARoutedClause1_ChecksClause0_Clause0_Clause0_ChannelClause0_FactsClause0_ErrorClause0_CompletionClause0_Clause0_Clause0_Channel work factory routes

/-- The dispatch primitive that `ScopedRequest` binds every plan to. -/
abbrev routedPrimitive {W A E O X D V H : Type}
    (work : request_adapter.Work W A E O X D V H) (routes : provider_io.RouteWork D H X) :=
  provider_io.Routed.Insts.Aivm_secrets_garrett_coreDispatchWork work.dispatchWorkInst routes

/-- The pending request created from a scoped request carries the exact
    context supplied to `ScopedRequest::new`. -/
theorem created_context {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending) :
    pending.work.context = context :=
  request_context.Proofs.initial_context work factory routes context native state
    ⟨context, native, state⟩ pending (request_context.Proofs.scoped_constructor
      work factory routes context native state) created

/-- Production successful read. Compared with
    `nr23.ProductionBoundary.accepted_read_has_exact_provider_attempt_accounting_and_guest_frame`,
    `NativeContext` and `capture` are gone: authorization, audit and binding
    are stated against the context actually given to `ScopedRequest::new`. -/
theorem production_accepted_read_has_exact_attempt_accounting_and_guest_frame
    {W F A E O X D V H C WriterState WriteError : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (reply : completion.Completed O)
    (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) pending = Result.ok (.Ok reply))
    (coverage : ExactNativeSinkCoverage (scopedOps work factory routes)
      (fun pending => pending.context) pending (.Ok reply) attempts)
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
      read_transition.Proofs.RequestRun
        (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
          (scopedOps work factory routes)) pending (.Ok reply) after ∧
      TraceSteps (fun _ => current_admission.Proofs.view context)
        pending.effects after.adapter.effects events ∧
      SoundTrace (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X)) ∧
      BoundTrace (current_admission.Proofs.view context).binding
        (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X)) ∧
      ExactNativeSinkSequence attempts (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X)) ∧
      (∀ attempt, attempt ∈ attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate = (current_admission.Proofs.view context).binding) ∧
      attempts.length = (sourceSends (withOutcome events (core.result.Result.Ok reply :
          core.result.Result (completion.Completed O) X))).length) ∧
    (∃ completed : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H,
      Reachable completed.effects ∧
      completed.effects.completion.selected = true ∧
      completed.effects.completion.before_checked = true ∧
      completed.effects.completion.audit_attempted = true ∧
      completed.effects.completion.audit_acknowledged = true ∧
      completed.effects.completion.after_checked = true ∧
      completed.effects.completion.value_ready = true) ∧
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) =
      Result.ok (out, nextWriter) ∧
    frame.wire.val = json_wire.Proofs.Bytes fuel (toCapturedJson reply) ++ [10#u8] ∧
    frame.wire.length ≤ limit.val ∧
    line_frame.Proofs.CompleteLine frame.wire.val ∧
    afterFrame.attempted = true ∧ afterFrame.wire = frame.wire := by
  have initial := created_context work factory routes context native state pending created
  have result :=
    aivm_secrets_garrett_core.nr23.ProductionBoundary.accepted_read_has_exact_provider_attempt_accounting_and_guest_frame
      (scopedOps work factory routes) (routedPrimitive work routes)
      factory.current_admissionChecksInst (fun pending => pending.context)
      (request_context.Proofs.native_context_contract work factory routes)
      ⟨context, native, state⟩ pending reply attempts created returned coverage
      toCapturedJson fuel valid room limit frame afterFrame writer nextWriter out
      writerOps prepared sent
  simpa only [initial] using result

/-- Production returned denial: attempt accounting holds against the actual
    constructor context without `NativeContext`. The fixed public denial value
    is still supplied separately (see `returned_denial_needs_separate_checked_public_frame`). -/
theorem production_denial_attempts_are_authorized_and_bound
    {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) pending = Result.ok out)
    (coverage : ExactNativeSinkCoverage (scopedOps work factory routes)
      (fun pending => pending.context) pending out attempts) :
    ∃ after events,
      read_transition.Proofs.RequestRun
        (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
          (scopedOps work factory routes)) pending out after ∧
      TraceSteps (fun _ => current_admission.Proofs.view context)
        pending.effects after.adapter.effects events ∧
      SoundTrace (withOutcome events out) ∧
      BoundTrace (current_admission.Proofs.view context).binding (withOutcome events out) ∧
      ExactNativeSinkSequence attempts (withOutcome events out) ∧
      (∀ attempt, attempt ∈ attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate = (current_admission.Proofs.view context).binding) ∧
      attempts.length = (sourceSends (withOutcome events out)).length := by
  have initial := created_context work factory routes context native state pending created
  have result := returned_request_has_exactly_accounted_authorized_native_sends
    (scopedOps work factory routes) (routedPrimitive work routes)
    factory.current_admissionChecksInst (fun pending => pending.context)
    (request_context.Proofs.native_context_contract work factory routes)
    ⟨context, native, state⟩ pending out attempts created returned coverage
  simpa only [initial] using result

/-- Production returned denial, end to end: attempt accounting against the
    constructor context, and the guest frame is the fixed text for whichever
    public error the bridge reports. Compared with
    `nr23.ProductionBoundary.returned_denial_needs_separate_checked_public_frame`,
    `NativeContext`, `capture`, `denialJson`, `valid`, `room` and `prepared`
    are all gone. The bridge's `Error -> PublicError` mapping is not trusted:
    the statement holds for every `PublicError`. -/
theorem production_denial_has_authorized_attempts_and_fixed_guest_frame
    {W F A E O X D V H C WriterState WriteError : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (error : X) (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) pending = Result.ok (.Err error))
    (coverage : ExactNativeSinkCoverage (scopedOps work factory routes)
      (fun pending => pending.context) pending (.Err error) attempts)
    (reported : public_error.PublicError) (limit : Usize)
    (frame afterFrame : guest_frame.Frame) (writer nextWriter : WriterState)
    (out : core.result.Result Unit WriteError)
    (writerOps : guest_frame.Writer WriterState WriteError)
    (built : public_error.denial_frame reported limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer =
      Result.ok (out, afterFrame, nextWriter)) :
    (∀ attempt, attempt ∈ attempts →
      attempt.gate.accepted ∧ attempt.auditAck = true ∧
      gateBinding attempt.gate = (current_admission.Proofs.view context).binding) ∧
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) = Result.ok (out, nextWriter) ∧
    frame.wire.val = public_error.Proofs.ascii (public_error.Proofs.denialText reported) ++ [10#u8] ∧
    afterFrame.attempted = true := by
  obtain ⟨_, _, _, _, _, _, _, secured, _⟩ :=
    production_denial_attempts_are_authorized_and_bound work factory routes context native
      state pending (.Err error) attempts created returned coverage
  obtain ⟨wrote, exact, attempted, _⟩ :=
    public_error.Proofs.denial_frame_send_exact writerOps reported limit frame afterFrame writer
      nextWriter out built sent
  exact ⟨secured, wrote, exact, attempted⟩

/-- **Production request, exact sink accounting without a coverage
    premise.** For every returned outcome of the production request:
    the source trace is sound and bound to the constructor context; the
    request's dispatch callbacks asked their primitive for the sends `cs`
    (`SendLog.Calls`, read from the ghost send log of each actual dispatch);
    there are exactly as many as source sends; and labelling them in order
    with the source sends is an exact native sink sequence whose every
    attempt was accepted, audited and bound to the constructor context.
    `payload` names the bytes of a send's channel and is unconstrained. -/
theorem production_request_sends_are_the_logged_sends
    {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (payload : H → List U8)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) pending = Result.ok out) :
    ∃ after events cs,
      read_transition.Proofs.RequestRun
        (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
          (scopedOps work factory routes)) pending out after ∧
      TraceSteps (fun _ => current_admission.Proofs.view context)
        pending.effects after.adapter.effects events ∧
      SoundTrace (withOutcome events out) ∧
      BoundTrace (current_admission.Proofs.view context).binding (withOutcome events out) ∧
      nr23.SendLog.Calls (scopedOps work factory routes) (routedPrimitive work routes)
        factory.current_admissionChecksInst pending after.adapter cs ∧
      cs.length = (sourceSends (withOutcome events out)).length ∧
      ExactNativeSinkSequence (nr23.SendLog.label payload (sourceSends events) cs) (withOutcome events out) ∧
      (nr23.SendLog.label payload (sourceSends events) cs).map (·.payload) = cs.map payload ∧
      (∀ attempt, attempt ∈ nr23.SendLog.label payload (sourceSends events) cs →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate = (current_admission.Proofs.view context).binding) := by
  have initial := created_context work factory routes context native state pending created
  have contract := request_context.Proofs.native_context_contract work factory routes
  obtain ⟨after, events, ran, _, trace, _, sound, bound, _⟩ :=
    aivm_secrets_garrett_core.nr23.Request.all_returned_request_events_are_authorized_and_bound
      (scopedOps work factory routes) (routedPrimitive work routes) factory.current_admissionChecksInst
      (fun pending => pending.context) contract ⟨context, native, state⟩ pending out created returned
  obtain ⟨cs, calls⟩ := nr23.SendLog.run_calls (scopedOps work factory routes) (routedPrimitive work routes)
    factory.current_admissionChecksInst contract.dispatch_binding pending out after ran
  have reach : Reachable pending.effects :=
    ⟨pending.effects, (request_adapter.Proofs.initial_receipt _ _ pending created).1, .refl⟩
  have count := nr23.SendLog.calls_match_sends (scopedOps work factory routes) (routedPrimitive work routes)
    factory.current_admissionChecksInst contract.dispatch_binding _ calls reach trace
  obtain ⟨exact, payloads⟩ := nr23.SendLog.labelled_exact payload events out cs count
  have secured := exact_sequence_preserves_audit_and_binding _ _ _ sound bound exact
  refine ⟨after, events, cs, ran, ?_, sound, ?_, calls,
    by rw [nr23.SendLog.sourceSends_withOutcome]; exact count, exact, payloads, ?_⟩
  · simpa only [initial] using trace
  · simpa only [initial] using bound
  · simpa only [initial] using secured.1

/-- Production successful read, end to end, without `ExactNativeSinkCoverage`:
    the logged sends are exactly accounted and the guest receives the exact
    frame of the selected value. -/
theorem production_accepted_read_has_logged_sends_and_guest_frame
    {W F A E O X D V H C WriterState WriteError : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (reply : completion.Completed O) (payload : H → List U8)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) pending = Result.ok (.Ok reply))
    (toCapturedJson : completion.Completed O → json_wire.Value)
    (fuel : Nat)
    (valid : json_wire.Proofs.Valid fuel (toCapturedJson reply))
    (room : json_wire.Proofs.Bound fuel (toCapturedJson reply) ≤ Usize.max)
    (limit : Usize) (frame afterFrame : guest_frame.Frame)
    (writer nextWriter : WriterState)
    (out : core.result.Result Unit WriteError)
    (writerOps : guest_frame.Writer WriterState WriteError)
    (prepared : json_wire.prepare (toCapturedJson reply) limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer = Result.ok (out, afterFrame, nextWriter)) :
    (∃ after events cs,
      read_transition.Proofs.RequestRun
        (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
          (scopedOps work factory routes)) pending (.Ok reply) after ∧
      nr23.SendLog.Calls (scopedOps work factory routes) (routedPrimitive work routes)
        factory.current_admissionChecksInst pending after.adapter cs ∧
      ExactNativeSinkSequence (nr23.SendLog.label payload (sourceSends events) cs)
        (withOutcome events (core.result.Result.Ok reply : core.result.Result (completion.Completed O) X)) ∧
      (nr23.SendLog.label payload (sourceSends events) cs).map (·.payload) = cs.map payload ∧
      (∀ attempt, attempt ∈ nr23.SendLog.label payload (sourceSends events) cs →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate = (current_admission.Proofs.view context).binding)) ∧
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) = Result.ok (out, nextWriter) ∧
    frame.wire.val = json_wire.Proofs.Bytes fuel (toCapturedJson reply) ++ [10#u8] ∧
    frame.wire.length ≤ limit.val ∧
    line_frame.Proofs.CompleteLine frame.wire.val ∧
    afterFrame.attempted = true ∧ afterFrame.wire = frame.wire := by
  obtain ⟨after, events, cs, ran, _, _, _, calls, _, exact, payloads, secured⟩ :=
    production_request_sends_are_the_logged_sends work factory routes context native state pending (.Ok reply)
      payload created returned
  obtain ⟨_, writerCalled, exactBytes, bounded, line, marked, retained⟩ :=
    aivm_secrets_garrett_core.nr23.Guest.selected_current_completed_value_has_exact_guest_frame
      (scopedOps work factory routes) ⟨context, native, state⟩ pending reply created returned toCapturedJson fuel
      valid room limit frame afterFrame writer nextWriter out writerOps prepared sent
  exact ⟨⟨after, events, cs, ran, calls, exact, payloads, secured⟩, writerCalled, exactBytes, bounded, line,
    marked, retained⟩

/-- Production returned denial, end to end, without `ExactNativeSinkCoverage`:
    the logged sends are exactly accounted and the guest frame is the fixed
    text of whichever public error the bridge reports. -/
theorem production_denial_has_logged_sends_and_fixed_guest_frame
    {W F A E O X D V H C WriterState WriteError : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (error : X) (payload : H → List U8)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) pending = Result.ok (.Err error))
    (reported : public_error.PublicError) (limit : Usize)
    (frame afterFrame : guest_frame.Frame) (writer nextWriter : WriterState)
    (out : core.result.Result Unit WriteError)
    (writerOps : guest_frame.Writer WriterState WriteError)
    (built : public_error.denial_frame reported limit = Result.ok (.Ok frame))
    (sent : guest_frame.Frame.send writerOps frame writer = Result.ok (out, afterFrame, nextWriter)) :
    (∃ after events cs,
      nr23.SendLog.Calls (scopedOps work factory routes) (routedPrimitive work routes)
        factory.current_admissionChecksInst pending after cs ∧
      ExactNativeSinkSequence (nr23.SendLog.label payload (sourceSends events) cs)
        (withOutcome events (core.result.Result.Err error : core.result.Result (completion.Completed O) X)) ∧
      (∀ attempt, attempt ∈ nr23.SendLog.label payload (sourceSends events) cs →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate = (current_admission.Proofs.view context).binding)) ∧
    writerOps.write_frame writer (alloc.vec.Vec.deref frame.wire) = Result.ok (out, nextWriter) ∧
    frame.wire.val = public_error.Proofs.ascii (public_error.Proofs.denialText reported) ++ [10#u8] ∧
    afterFrame.attempted = true := by
  obtain ⟨after, events, cs, _, _, _, _, calls, _, exact, _, secured⟩ :=
    production_request_sends_are_the_logged_sends work factory routes context native state pending (.Err error)
      payload created returned
  obtain ⟨wrote, exactFrame, attempted, _⟩ :=
    public_error.Proofs.denial_frame_send_exact writerOps reported limit frame afterFrame writer
      nextWriter out built sent
  exact ⟨⟨after.adapter, events, cs, calls, exact, secured⟩, wrote, exactFrame, attempted⟩

end aivm_secrets_garrett_core.production.Assurance
