import GarrettDispatchTrace
import GarrettNativeWriterEvents

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-!
Composition at the actual extracted owned-dispatch/provider-write seam.
`dispatch.dispatch` and `provider_io.Channel.submit` are the production-called
functions. A returned dispatch has an extracted chronological receipt trace;
when that trace is split at the actual `RequestEffects.begin_send` call, the
native channel callback history supplies exactly the send-attempt segment.

The `beforeTrace`/`after` hypotheses identify the source gate within a particular
native adapter invocation. They do not assert that a TLS peer received bytes.
Binding the actual Rust File/Write effects, the split and exceptional/unwinding
paths remains NR-2/NR-3 work; none is discharged by this composition lemma.
-/
namespace aivm_secrets_garrett_core.native_dispatch.Events

open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.provider_io.NativeWriterEvents

private theorem traces_append {contexts : read_transition.Phase → Context}
    {first middle last : request_effects.RequestEffects}
    {a b : List confinement.Proofs.Event}
    (left : TraceSteps contexts first middle a)
    (right : TraceSteps contexts middle last b) :
    TraceSteps contexts first last (a ++ b) := by
  induction right with
  | refl => simpa using left
  | next prior step origin ih =>
      simpa [List.append_assoc] using TraceSteps.next ih step origin

/-- Source-linked returned-dispatch trace with the writer's high-level
    callbacks projected at the *same* composite `begin_send` gate. Both
    failure and success of the native callback count as one attempt, and
    the dispatch trace preserves the immutable current-admission context.

    The source-to-adapter proof still has to provide `beforeTrace` and `after`
    for this particular dispatch, plus the origin from its bound current
    callback. A caller cannot supply an unrelated `providerReached` flag. -/
theorem returned_dispatch_with_writer_segment
    {W C H O X B V M E : Type}
    (work : dispatch.Work W H O X)
    (checks : current_admission.Checks C X)
    (primitive : current_admission.Bound W C H O X)
    (prepared : core.result.Result read_transition.Prepared X)
    (initial : request_effects.RequestEffects) (keyed : Bool)
    (report : dispatch.Report (current_admission.Bound W C H O X) H O X)
    (startReachable : Reachable initial)
    (dispatched : dispatch.dispatch
      (current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks)
      primitive prepared initial keyed = Result.ok report)
    (gateBefore gateAfter : request_effects.RequestEffects)
    (phase : read_transition.Phase) (write : Bool)
    (localState nextLocal : provider_exchange.SendState)
    (stamp : manifest.AdmissionStamp)
    (beforeEvents afterEvents : List confinement.Proofs.Event)
    (beforeReachable : Reachable gateBefore)
    (beforeTrace : TraceSteps
      (fun _ => current_admission.Proofs.view primitive.context)
      initial gateBefore beforeEvents)
    (marked : request_effects.RequestEffects.begin_send gateBefore phase localState write =
      Result.ok (true, gateAfter, nextLocal))
    (checkedOrigin : ∀ stamp', localState.progress = .Checked stamp' →
      Issued (current_admission.Proofs.view primitive.context) stamp')
    (checked : localState.progress = .Checked stamp)
    (stamped : nextLocal.progress = .Attempted stamp)
    (after : TraceSteps
      (fun _ => current_admission.Proofs.view primitive.context)
      gateAfter report.effects afterEvents)
    (bytes : provider_io.WireBytes B) (writerOps : provider_io.Writer V E)
    (pending final : provider_io.Channel B V M E)
    (out : core.result.Result Unit E)
    (fresh : pending.request.attempted = false)
    (returned : provider_io.Channel.submit bytes writerOps pending = Result.ok (out, final)) :
    ∃ calls, Observed bytes writerOps pending.request pending.writer out
        final.request final.writer calls ∧
      projected phase (current_admission.Proofs.view primitive.context) stamp calls =
        [attemptedEvent phase (current_admission.Proofs.view primitive.context) stamp] ∧
      TraceSteps (fun _ => current_admission.Proofs.view primitive.context)
        initial report.effects
        (beforeEvents ++
          [attemptedEvent phase (current_admission.Proofs.view primitive.context) stamp] ++
          afterEvents) ∧
      confinement.Proofs.SoundTrace
        (beforeEvents ++
          [attemptedEvent phase (current_admission.Proofs.view primitive.context) stamp] ++
          afterEvents) ∧
      report.work.context = primitive.context ∧
      final.request.attempted = true := by
  let contexts : read_transition.Phase → Context :=
    fun _ => current_admission.Proofs.view primitive.context
  have bound :=
    (dispatch.TraceRefinement.dispatch_trace work checks primitive prepared
      initial keyed report dispatched).1
  have issued : Issued (contexts phase) stamp := checkedOrigin stamp checked
  obtain ⟨calls, observed, sameDelta, _, spent⟩ :=
    guarded_channel_callback_projection bytes writerOps contexts
      gateBefore gateAfter localState nextLocal phase write stamp pending final out
      beforeReachable marked stamped issued fresh returned
  have projection := fresh_callback_projects_one bytes writerOps
    pending.request final.request pending.writer final.writer out calls phase
    (contexts phase) stamp fresh observed
  have gateDelta : delta contexts gateBefore gateAfter =
      [attemptedEvent phase (contexts phase) stamp] := sameDelta.trans projection
  have origin := checked_send_establishes_origin contexts gateBefore gateAfter
    localState nextLocal phase write true checkedOrigin marked
  have gateTrace : TraceSteps contexts initial gateAfter
      (beforeEvents ++ [attemptedEvent phase (contexts phase) stamp]) := by
    simpa only [gateDelta] using
      (TraceSteps.next beforeTrace
        (request_effects.Step.begin_send true phase localState nextLocal write marked)
        origin)
  have completedTrace : TraceSteps contexts initial report.effects
      (beforeEvents ++ [attemptedEvent phase (contexts phase) stamp] ++ afterEvents) := by
    simpa only [List.append_assoc] using (traces_append gateTrace after)
  have completedSound : confinement.Proofs.SoundTrace
      (beforeEvents ++ [attemptedEvent phase (contexts phase) stamp] ++ afterEvents) :=
    (trace_steps_preserve_soundness contexts initial report.effects _
      startReachable completedTrace).2
  exact ⟨calls, observed, projection, completedTrace, completedSound, bound, spent⟩

end aivm_secrets_garrett_core.native_dispatch.Events
