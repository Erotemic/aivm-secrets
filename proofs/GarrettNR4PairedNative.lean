import GarrettNR4ProjectedRelease
import GarrettNR4ErrorFrames

open Aeneas Aeneas.Std
set_option maxHeartbeats 7000000

/-!
NR-4 pair of *returned production-extracted source sessions*. We carry the
previously compiled NR-2/3 exact sink-coverage and current-audit proof for
EACH run, not merely a single projection equality. The resulting frame-byte
equality is derived from recursive projection agreement via SelectedConversion.

`ExactNativeSinkCoverage`, `NativeContext`, and SelectedConversion remain
specific source-to-native obligations. Two successful requests cannot be
called observationally indistinguishable unless public writer outcomes, error
classification, metadata and close behavior also agree.
-/
namespace aivm_secrets_garrett_core.nr4.PairedNative

open aivm_secrets_garrett_core.confinement.W5
open aivm_secrets_garrett_core.nr23.ExactSinks
open aivm_secrets_garrett_core.nr23.Effects
open aivm_secrets_garrett_core.nr4.ProjectedRelease
open aivm_secrets_garrett_core.request_adapter.TraceRefinement
open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs

private abbrev boundAdapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

/-- One SOURCE-RETURNED, native-coverage-constrained successful request.
    This packages actual equality witnesses instead of introducing a new
    guessed request state machine. `coverage` is *not* automatically true of
    the Rust process; it must be obtained from the production sink audit. -/
structure NativeSuccess
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (capture : W → current_admission.Context)
    (depth : Nat) (limit : Usize)
    (toJson : completion.Completed O → json_wire.Value) where
  initial : W
  pending : request_adapter.Pending W F E O X
    (current_admission.Bound D C H F X) V H
  reply : completion.Completed O
  attempts : List NativeAttempt
  created : request_adapter.Pending.new ops initial = Result.ok pending
  returned : read_transition.run_current (boundAdapter ops) pending =
    Result.ok (.Ok reply)
  coverage : ExactNativeSinkCoverage ops capture pending (.Ok reply) attempts
  valid : json_wire.Proofs.Valid depth (toJson reply)
  room : json_wire.Proofs.Bound depth (toJson reply) ≤ Usize.max
  frame : guest_frame.Frame
  prepared : json_wire.prepare (toJson reply) limit = Result.ok (.Ok frame)

/-- All native attempts of this returned read have source-derived current
    authorization, pre-send audit acknowledgements, and immutable binding,
    provided complete ordered native sink coverage holds. -/
theorem native_success_has_accounted_authorized_send_history
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (ctx : NativeContext ops primitive checks capture)
    (depth : Nat) (limit : Usize)
    (toJson : completion.Completed O → json_wire.Value)
    (run : NativeSuccess ops capture depth limit toJson) :
    ∃ after events,
      read_transition.Proofs.RequestRun (boundAdapter ops) run.pending
        (.Ok run.reply) after ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture run.pending.work))
        run.pending.effects after.adapter.effects events ∧
      SoundTrace (withOutcome events (core.result.Result.Ok run.reply :
        core.result.Result (completion.Completed O) X)) ∧
      BoundTrace (current_admission.Proofs.view (capture run.pending.work)).binding
        (withOutcome events (core.result.Result.Ok run.reply :
          core.result.Result (completion.Completed O) X)) ∧
      ExactNativeSinkSequence run.attempts
        (withOutcome events (core.result.Result.Ok run.reply :
          core.result.Result (completion.Completed O) X)) ∧
      (∀ attempt, attempt ∈ run.attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate =
          (current_admission.Proofs.view (capture run.pending.work)).binding) ∧
      run.attempts.length =
        (sourceSends (withOutcome events (core.result.Result.Ok run.reply :
          core.result.Result (completion.Completed O) X))).length := by
  exact returned_request_has_exactly_accounted_authorized_native_sends
    ops primitive checks capture ctx run.initial run.pending (.Ok run.reply)
    run.attempts run.created run.returned run.coverage

/-- A returned source success has all audited completion gates, independently
    of whether the public frame was ever delivered over the network. -/
theorem native_success_source_completion_is_audited
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (capture : W → current_admission.Context)
    (depth : Nat) (limit : Usize)
    (toJson : completion.Completed O → json_wire.Value)
    (run : NativeSuccess ops capture depth limit toJson) :
    aivm_secrets_garrett_core.nr23.GuestObservations.SourceReady ops := by
  exact aivm_secrets_garrett_core.nr23.GuestObservations.returned_success_establishes_source_ready
    ops run.initial run.pending run.reply run.created run.returned

/-- Two source returns with equivalent approved projections, both linked
    through the same selected-value native converter, prepare equal frames.
    The runs may have different native state, different private raw provider
    JSON, and different numbers of internal audit steps. -/
theorem paired_native_source_successes_prepare_equal_public_bytes
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (capture : W → current_admission.Context)
    (depth : Nat) (limit : Usize)
    (toJson : completion.Completed O → json_wire.Value)
    (first second : NativeSuccess ops capture depth limit toJson)
    (rawFirst rawSecond : Json) (schema : Projection) (fuel budget : Usize)
    (agree : disclosure.Proofs.ProjectionAgreement fuel.val
      rawFirst rawSecond schema)
    (selectedFirst selectedSecond : Selection)
    (projectedFirst : disclosure.project rawFirst schema fuel budget =
      Result.ok (.Ok selectedFirst))
    (projectedSecond : disclosure.project rawSecond schema fuel budget =
      Result.ok (.Ok selectedSecond))
    (encodeSelected : Selection → json_wire.Value)
    (linkedFirst : SelectedConversion toJson encodeSelected
      first.reply selectedFirst)
    (linkedSecond : SelectedConversion toJson encodeSelected
      second.reply selectedSecond) :
    first.frame.wire.val = second.frame.wire.val ∧
    first.frame.attempted = false ∧ second.frame.attempted = false ∧
    aivm_secrets_garrett_core.nr23.GuestObservations.SourceReady ops := by
  have frames := successful_approved_projection_prepares_identical_guest_frames
    rawFirst rawSecond schema fuel budget agree selectedFirst selectedSecond
    projectedFirst projectedSecond first.reply second.reply toJson
    encodeSelected linkedFirst linkedSecond depth first.valid second.valid
    first.room second.room limit first.frame second.frame
    first.prepared second.prepared
  have complete := native_success_source_completion_is_audited
    ops capture depth limit toJson first
  exact ⟨frames.1, frames.2.1, frames.2.2, complete⟩

/-- NR-2/3 authorization/audit/sink accounting holds for EACH of the two
    executions, while NR-4 proves equality of the offered frame bytes from
    recursive selected-field agreement. There is no assumption that raw
    provider values, audit histories, credentials, or native work states are
    equal. This is a relational source-linked theorem, not yet a claim about
    every externally observable TLS/OS effect. -/
theorem paired_native_reads_have_independent_sound_traces_and_same_guest_bytes
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (ctx : NativeContext ops primitive checks capture)
    (depth : Nat) (limit : Usize)
    (toJson : completion.Completed O → json_wire.Value)
    (first second : NativeSuccess ops capture depth limit toJson)
    (rawFirst rawSecond : Json) (schema : Projection) (fuel budget : Usize)
    (agree : disclosure.Proofs.ProjectionAgreement fuel.val
      rawFirst rawSecond schema)
    (selectedFirst selectedSecond : Selection)
    (projectedFirst : disclosure.project rawFirst schema fuel budget =
      Result.ok (.Ok selectedFirst))
    (projectedSecond : disclosure.project rawSecond schema fuel budget =
      Result.ok (.Ok selectedSecond))
    (encodeSelected : Selection → json_wire.Value)
    (linkedFirst : SelectedConversion toJson encodeSelected
      first.reply selectedFirst)
    (linkedSecond : SelectedConversion toJson encodeSelected
      second.reply selectedSecond) :
    (∃ after events,
      read_transition.Proofs.RequestRun (boundAdapter ops) first.pending
        (.Ok first.reply) after ∧
      ExactNativeSinkSequence first.attempts
        (withOutcome events (core.result.Result.Ok first.reply :
          core.result.Result (completion.Completed O) X)) ∧
      ∀ attempt, attempt ∈ first.attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true) ∧
    (∃ after events,
      read_transition.Proofs.RequestRun (boundAdapter ops) second.pending
        (.Ok second.reply) after ∧
      ExactNativeSinkSequence second.attempts
        (withOutcome events (core.result.Result.Ok second.reply :
          core.result.Result (completion.Completed O) X)) ∧
      ∀ attempt, attempt ∈ second.attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true) ∧
    first.frame.wire.val = second.frame.wire.val ∧
    aivm_secrets_garrett_core.nr23.GuestObservations.SourceReady ops := by
  obtain ⟨endFirst, eventsFirst, ranFirst, _, _, _, exactFirst, securedFirst, _⟩ :=
    native_success_has_accounted_authorized_send_history
      ops primitive checks capture ctx depth limit toJson first
  obtain ⟨endSecond, eventsSecond, ranSecond, _, _, _, exactSecond, securedSecond, _⟩ :=
    native_success_has_accounted_authorized_send_history
      ops primitive checks capture ctx depth limit toJson second
  have paired := paired_native_source_successes_prepare_equal_public_bytes
    ops capture depth limit toJson first second rawFirst rawSecond
    schema fuel budget agree selectedFirst selectedSecond projectedFirst
    projectedSecond encodeSelected linkedFirst linkedSecond
  have savedFirst : ∀ attempt, attempt ∈ first.attempts →
      attempt.gate.accepted ∧ attempt.auditAck = true := by
    intro attempt member
    exact ⟨(securedFirst attempt member).1,
      (securedFirst attempt member).2.1⟩
  have savedSecond : ∀ attempt, attempt ∈ second.attempts →
      attempt.gate.accepted ∧ attempt.auditAck = true := by
    intro attempt member
    exact ⟨(securedSecond attempt member).1,
      (securedSecond attempt member).2.1⟩
  exact ⟨⟨endFirst, eventsFirst, ranFirst, exactFirst, savedFirst⟩,
    ⟨endSecond, eventsSecond, ranSecond, exactSecond, savedSecond⟩,
    paired.1, paired.2.2.2⟩

end aivm_secrets_garrett_core.nr4.PairedNative
