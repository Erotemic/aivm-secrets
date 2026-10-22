import GarrettNR4AdaptiveWire

open Aeneas Aeneas.Std
set_option maxHeartbeats 7500000

/-!
NR-4 composed assurance target.

This file connects the accepted NR-2/NR-3 source-extracted request and exact
ordered native-send contract to W5 recursive projection and W6 JSON framing.
For paired successful native requests the source-produced authorization/audit
traces are proved independently, and frame byte equality follows from the
approved projection and a *single* selected-value conversion. A separate
adaptive theorem allows an arbitrary next request based on previous complete
public observations. The final deployed system still owes its concrete Rust
step refinement, serde/error conversion, transitive I/O closure, and external
metadata/TLS/OS contracts. No statement below says the live process is
unconditionally noninterfering.
-/
namespace aivm_secrets_garrett_core.nr4.Assurance

open aivm_secrets_garrett_core.confinement.W5
open aivm_secrets_garrett_core.nr4.ProjectedRelease
open aivm_secrets_garrett_core.nr4.PairedNative
open aivm_secrets_garrett_core.nr4.AdaptiveWire
open aivm_secrets_garrett_core.nr23.ExactSinks
open aivm_secrets_garrett_core.nr23.Effects
open aivm_secrets_garrett_core.request_adapter.TraceRefinement
open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs

private abbrev boundAdapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

/-- One returned successful request's complete public observation, including
    exact offered bytes, the outcome classification and modeled metadata.
    The operator-supplied RequestCase must describe this very execution;
    `ObservedStep` is not secretly inferred from a raw provider response. -/
noncomputable def sourceSuccessObservation
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (capture : W → current_admission.Context)
    (depth : Nat) (limit : Usize)
    (toJson : completion.Completed O → json_wire.Value)
    (run : NativeSuccess ops capture depth limit toJson)
    (model : RequestCase) (publicResult : Nat) : NativeObservation :=
  { wire := run.frame.wire.val,
    outcomeCode := publicResult,
    modeled := observed model }

/-- A strict read-only two-run result, composed from the actual returned
    request controller and the extracted JSON frame encoder. The two runs
    independently establish current admission, audit acknowledgement and
    ordered sink accounting. Equality of offered wire bytes follows from
    W5's recursive projection agreement and the selected-value bridge. W5's
    status/reflection/error and metadata releases remain explicitly visible.

    In particular, *nothing* here postulates that the two native frames have
    equal bytes or that their full private source states are equal. -/
theorem paired_returned_native_reads_have_sound_sends_and_public_equivalence
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
    (caseFirst caseSecond : RequestCase)
    (agree : DeclassificationAgreement caseFirst caseSecond)
    (selectedFirst selectedSecond : Selection)
    (projectedFirst : disclosure.project
      caseFirst.raw caseFirst.schema caseFirst.fuel caseFirst.budget =
      Result.ok (.Ok selectedFirst))
    (projectedSecond : disclosure.project
      caseSecond.raw caseFirst.schema caseFirst.fuel caseFirst.budget =
      Result.ok (.Ok selectedSecond))
    (encodeSelected : Selection → json_wire.Value)
    (linkedFirst : SelectedConversion toJson encodeSelected
      first.reply selectedFirst)
    (linkedSecond : SelectedConversion toJson encodeSelected
      second.reply selectedSecond)
    (publicFirst publicSecond : Nat)
    (sameOutcome : publicFirst = publicSecond) :
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
    sourceSuccessObservation ops capture depth limit toJson first caseFirst publicFirst =
      sourceSuccessObservation ops capture depth limit toJson second caseSecond publicSecond := by
  have paired := paired_native_reads_have_independent_sound_traces_and_same_guest_bytes
    ops primitive checks capture ctx depth limit toJson first second
    caseFirst.raw caseSecond.raw caseFirst.schema caseFirst.fuel
    caseFirst.budget agree.projected selectedFirst selectedSecond
    projectedFirst projectedSecond encodeSelected linkedFirst linkedSecond
  have sameModel := request_noninterference caseFirst caseSecond agree
  obtain ⟨fromFirst, fromSecond, sameFrame, _⟩ := paired
  have samePublic : sourceSuccessObservation ops capture depth limit toJson
      first caseFirst publicFirst =
      sourceSuccessObservation ops capture depth limit toJson
        second caseSecond publicSecond := by
    unfold sourceSuccessObservation
    rw [sameFrame, sameOutcome, sameModel]
  exact ⟨fromFirst, fromSecond, samePublic⟩

/-- A concrete public error taxonomy difference is a real distinguishing
    channel. A purported noninterference theorem must either require category
    equality or declare the categories an intentional release. -/
theorem changed_error_category_remains_observable
    (wire : List U8) (metadata : ObservedStep)
    (errorLeft errorRight : Nat) (different : errorLeft ≠ errorRight) :
    NativeObservation.mk wire errorLeft metadata ≠
      NativeObservation.mk wire errorRight metadata := by
  exact different_native_outcome_code_is_visible wire
    errorLeft errorRight metadata different

/-- Full adaptive security theorem over a variable-length session. The
    native per-step correspondence certificate is the real remaining task;
    the theorem handles arbitrary feedback strategies once each source-linked
    step establishes its approval/projection, frame conversion and outcome
    premises. Neither assuming equal observations nor ignoring errors is
    allowed by the certificate. -/
theorem arbitrary_adaptive_guest_strategy_sees_equivalent_public_history
    {LeftState RightState Request : Type}
    (encodePublic : List GuestMessage → List U8)
    (strategy : List NativeObservation → Nat → Request)
    (stepLeft : LeftState → Request → NativeStep × LeftState)
    (stepRight : RightState → Request → NativeStep × RightState)
    (related : LeftState → RightState → Prop)
    (stepCorrect : ∀ left right request, related left right →
      PairedStepCertificate encodePublic stepLeft stepRight related
        left right request)
    (rounds : Nat) (left : LeftState) (right : RightState)
    (history : List NativeObservation) (initial : related left right) :
    adaptiveNativeRun strategy stepLeft rounds left history =
      adaptiveNativeRun strategy stepRight rounds right history := by
  exact adaptive_native_noninterference encodePublic strategy stepLeft
    stepRight related stepCorrect rounds left right history initial

end aivm_secrets_garrett_core.nr4.Assurance
