import GarrettNR23ProductionBoundary
import GarrettRequestContext

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

Still assumed here: `ExactNativeSinkCoverage` (every native credential-bearing
write is one ordered source send), the native completion-to-JSON conversion
(`toCapturedJson` and its `Valid`/`Bound`), and the native denial-to-JSON
conversion. No delivery, durability or TLS property is stated.
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

end aivm_secrets_garrett_core.production.Assurance
