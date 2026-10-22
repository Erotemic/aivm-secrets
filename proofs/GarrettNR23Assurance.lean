import GarrettNR23Request
import GarrettNR23Effects
import GarrettNR23Failures
import GarrettNR23Guest

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-2/NR-3 conditional *integration* statements. These theorems compose
source-extracted Rust request runs, their *derived* receipt traces, the exact
native-writer effect-coverage contract, and source-owned guest-frame encoding.

The hard native premises are deliberately present in the theorem telescope:
  * NativeContext: actual native request-adapter callback/capture binding;
  * NativeSinkCoverage: *all* reachable native credentialed sends map into
    the extracted trace; no proof of this transitive callgraph is claimed;
  * guest conversion / frame handoff: the host converts the *actual* approved
    completion to a json_wire.Value and passes it to the native frame writer.
No theorem here states transport delivery, complete OS/TLS reachability,
whole-service secrecy, or unconditional adaptive noninterference.
-/
namespace aivm_secrets_garrett_core.nr23.Assurance

open aivm_secrets_garrett_core.request_adapter.TraceRefinement
open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.nr23.Effects

private abbrev boundAdapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

/-- This is an *obligation* about the actual native Rust process. It is
    intentionally not automatically inhabited by the modeled trace.
    It requires every credential-bearing native send that happened during
    this exact source invocation to have a matching source-derived event.

    Later source-to-I/O work must discharge this for the selected production
    executable and startup profile, including callbacks, error handling,
    setup/teardown, Drop and OS/TLS write paths. -/
def NativeSinkCoverage {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (capture : W → current_admission.Context)
    (initial : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (attempts : List NativeAttempt) : Prop :=
  ∀ after events,
    read_transition.Proofs.RequestRun (boundAdapter ops) initial out after →
    TraceSteps (fun _ => current_admission.Proofs.view (capture initial.work))
      initial.effects after.adapter.effects events →
    AllNativeAttemptsAccounted attempts (withOutcome events out)

/-- The complete returned source request provides the history itself. Under
    the separately named native sink-coverage assumption, EVERY observed
    native credential-bearing attempt from this invocation has a currently
    authorized, acknowledged, bound send gate. No arbitrary `SoundTrace`,
    `BoundTrace`, or caller-chosen event history is accepted as a premise. -/
theorem returned_native_attempts_have_derived_authority_audit_and_binding
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (context : NativeContext ops primitive checks capture)
    (native : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new ops native = Result.ok pending)
    (returned : read_transition.run_current (boundAdapter ops) pending =
      Result.ok out)
    (covered : NativeSinkCoverage ops capture pending out attempts) :
    ∃ after events,
      read_transition.Proofs.RequestRun (boundAdapter ops) pending out after ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture pending.work))
        pending.effects after.adapter.effects events ∧
      SoundTrace (withOutcome events out) ∧
      BoundTrace (current_admission.Proofs.view (capture pending.work)).binding
        (withOutcome events out) ∧
      (∀ attempt, attempt ∈ attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate =
          (current_admission.Proofs.view (capture pending.work)).binding) := by
  obtain ⟨after, events, ran, fixed, trace, _, sound, bound, _⟩ :=
    aivm_secrets_garrett_core.nr23.Request.all_returned_request_events_are_authorized_and_bound
      ops primitive checks capture context native pending out created returned
  have coveredHere : AllNativeAttemptsAccounted attempts
      (withOutcome events out) := covered after events ran trace
  have secured := accounted_native_attempts_have_current_bound_audit
    attempts (withOutcome events out)
    (current_admission.Proofs.view (capture pending.work)).binding
    sound bound coveredHere
  exact ⟨after, events, ran, trace, sound, bound, secured⟩

/-- Source-owned *successful* completion has all selected/current/audit gates.
    Separately, its approved captured JSON result, once prepared and submitted,
    has one bounded, newline-terminated exact byte string and one frame attempt.

    This theorem does not equate the abstract `Completed O` with an arbitrary
    native `serde_json::Value`: `toCapturedJson` and the actual call through
    `GuestFrame::from_answer` / `Bridge::answer` remain explicit native linkage
    obligations. `sent` records a returned high-level callback, not delivery. -/
theorem accepted_native_read_has_completed_audit_and_exact_guest_frame
    {W F E O X D C V H WriterState WriteError : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (native : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (reply : completion.Completed O)
    (created : request_adapter.Pending.new ops native = Result.ok pending)
    (returned : read_transition.run_current (boundAdapter ops) pending =
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
      Reachable completed.effects ∧
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
  exact aivm_secrets_garrett_core.nr23.Guest.selected_current_completed_value_has_exact_guest_frame
    ops native pending reply created returned toCapturedJson fuel valid room
    limit frame after writer next out writerOps prepared sent

end aivm_secrets_garrett_core.nr23.Assurance
