import GarrettDispatchTrace
import GarrettNativeWriterEvents

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-!
A returned *source-owned* read driver, its current-admission check and the
native channel writer are considered together. Unlike a theorem supplied with
an arbitrary trace split, this proof recovers the five possible outcomes from
`provider_exchange.exchange` itself. The chronological receipt trace and
current stamp come from the extracted controller and the bound current checker.

Two concrete native adapter contracts remain: `ManifestProvider::setup_route`
returns a *fresh* `Channel.new`, and a returned `ManifestProvider::send` on that
channel invokes `Channel.submit` with the same result and post-state.
The native `setup_route` and `send_manifest_bytes` implementations are outside
this Aeneas extraction. Neither contract enumerates all native I/O.
`Writer.write_all`/`flush` retain their explicit external return semantics;
partial writes, rustls/TCP, panics, crash durability and guest-visible
responses are NOT proved by this theorem.
-/
namespace aivm_secrets_garrett_core.native_dispatch.ReadBoundary

open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.provider_io.NativeWriterEvents
open aivm_secrets_garrett_core.provider_io.ChannelProofs

private abbrev NativeChannel (B V M X : Type) := provider_io.Channel B V M X
private abbrev NativePending (W C B V M X O : Type) :=
  dispatch.Pending (current_admission.Bound W C (NativeChannel B V M X) O X)
    (NativeChannel B V M X) O X
private abbrev boundOps {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X) :=
  current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks
private abbrev driver {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X) :=
  dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider
    (boundOps work checks)

/-- An exact returned submission of the extracted `Channel.submit` has a
    concrete callback schedule. On a fresh channel that schedule projects to
    one attempt, whether a native write or a flush returns an error. -/
private theorem fresh_channel_observes_one {B V M X : Type}
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (before after : NativeChannel B V M X) (result : core.result.Result Unit X)
    (phase : read_transition.Phase) (ctx : Context)
    (stamp : manifest.AdmissionStamp)
    (fresh : before.request.attempted = false)
    (called : provider_io.Channel.submit bytes writer before = Result.ok (result, after)) :
    ∃ calls, Observed bytes writer before.request before.writer result
        after.request after.writer calls ∧
      projected phase ctx stamp calls = [attemptedEvent phase ctx stamp] ∧
      after.request.attempted = true := by
  have run := (channel_submission_run bytes writer before after result).mp called
  have requestCall :=
    (provider_io.Proofs.submit_run_iff bytes writer before.request after.request
      before.writer after.writer result).mpr run.1
  obtain ⟨calls, observed⟩ :=
    submit_observes_callbacks bytes writer before.request after.request
      before.writer after.writer result requestCall
  exact ⟨calls, observed,
    fresh_callback_projects_one bytes writer before.request after.request
      before.writer after.writer result calls phase ctx stamp fresh observed,
    channel_spent bytes writer before after result called⟩

/-- The native `setup_route` factory returns a new, unused `Channel.new`,
    not a channel with a previous credential-bearing attempt. This is an
    explicit source-to-core adapter obligation for the native manifest path;
    it is deliberately restricted to the *actual returned setup callback*. -/
def SetupReturnsFresh {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X) : Prop :=
  ∀ (before after : NativePending W C B V M X O)
    (channel : NativeChannel B V M X),
    (driver work checks).setup before = Result.ok (.Ok channel, after) →
      channel.request.attempted = false

/-- `ManifestProvider::send` calls the production `send_manifest_bytes` shim,
    which invokes the source-owned `Channel.submit` on the *same channel*.
    This is a second narrow native adapter obligation, not a theorem about
    OS/TLS delivery. A duplicate raw invocation must not be treated as a
    fresh send; freshness is separately obtained from the setup callback. -/
def SendsThroughChannel {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X) : Prop :=
  ∀ (before after : NativePending W C B V M X O)
    (channel next : NativeChannel B V M X) (result : core.result.Result Unit X),
    (driver work checks).send before channel = Result.ok (result, after, next) →
      provider_io.Channel.submit bytes writer channel = Result.ok (result, next)

/-- A returned read that stops at setup or current admission cannot change
    the request-wide receipt (in particular it cannot mark a provider attempt).
    The context is fixed by the source-owned bound adapter. The underlying
    `setup`/`recheck` primitives still have external I/O contracts; this
    theorem does NOT say that opening TLS or checking a clock has no effects. -/
theorem rejected_before_send_keeps_receipt
    {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (start finish : NativePending W C B V M X O)
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (driver work checks)
        start ⟨phase, false⟩ = Result.ok (report, finish))
    (early : report.stage = .Setup ∨ report.stage = .Admission) :
    finish.effects = start.effects ∧
      finish.work.context = start.work.context ∧
      report.current = none := by
  have fixed := (current_admission.Proofs.owned_read_driver_stamp_origin
    work checks start finish phase report returned).1
  have run :=
    (provider_exchange.Proofs.read_run_iff (driver work checks) start
      phase report finish).mp returned
  cases run with
  | setupDenied after error setup =>
      have same := (dispatch.Proofs.setup_frame (boundOps work checks)
        start finish (.Err error) setup).1
      exact ⟨same, fixed, rfl⟩
  | admissionDenied channel first after error setup checked =>
      have setupFrame := (dispatch.Proofs.setup_frame (boundOps work checks)
        start first (.Ok channel) setup).1
      have currentFrame := (dispatch.Proofs.current_frame (boundOps work checks)
        first finish (.Err error) checked).1
      exact ⟨currentFrame.trans setupFrame, fixed, rfl⟩
  | sendDenied =>
      simp [provider_exchange.Proofs.receipt] at early
  | responseDenied =>
      simp [provider_exchange.Proofs.receipt] at early
  | complete =>
      simp [provider_exchange.Proofs.receipt] at early

/-- For *any returned attempted read* of the extracted bound provider driver,
    recover the actual current-issued stamp and an actual native submit from
    the SAME `exchange` execution. All send, response and success outcomes are
    included; setup/current denials are impossible under `attempted`.

    The sound chronological trace, the immutable route/operation binding and
    the current-stamp origin require no supplied artificial trace, split,
    `checkedOrigin`, `auditOK` or `providerReached` flag.

    The remaining adapter assumptions are `SetupReturnsFresh` and
    `SendsThroughChannel`; in particular
    this result does not yet establish that every possible credential-bearing
    OS/TLS send comes through that adapter. `Observed` counts high-level
    callbacks, not accepted TCP bytes or delivery. -/
theorem returned_attempted_read_has_checked_writer
    {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (start finish : NativePending W C B V M X O)
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (startReachable : Reachable start.effects)
    (returned : provider_exchange.exchange (driver work checks)
        start ⟨phase, false⟩ = Result.ok (report, finish))
    (attempted : provider_exchange.Stage.attempted report.stage = Result.ok true)
    (freshSetup : SetupReturnsFresh work checks)
    (linked : SendsThroughChannel work checks bytes writer) :
    ∃ events,
      TraceSteps (fun _ => current_admission.Proofs.view start.work.context)
        start.effects finish.effects events ∧
      confinement.Proofs.SoundTrace events ∧
      BoundTrace (current_admission.Proofs.view start.work.context).binding events ∧
      finish.work.context = start.work.context ∧
      ∃ (stamp : manifest.AdmissionStamp)
        (sendBefore sendAfter : NativePending W C B V M X O)
        (channel next : NativeChannel B V M X)
        (result : core.result.Result Unit X) (calls : List Call),
        report.current = some stamp ∧
        Issued (current_admission.Proofs.view start.work.context) stamp ∧
        (driver work checks).send sendBefore channel = Result.ok (result, sendAfter, next) ∧
        provider_io.Channel.submit bytes writer channel = Result.ok (result, next) ∧
        Observed bytes writer channel.request channel.writer result
          next.request next.writer calls ∧
        projected phase (current_admission.Proofs.view start.work.context) stamp calls =
          [attemptedEvent phase (current_admission.Proofs.view start.work.context) stamp] ∧
        next.request.attempted = true := by
  let ctx : Context := current_admission.Proofs.view start.work.context
  have origin := current_admission.Proofs.owned_read_driver_stamp_origin
    work checks start finish phase report returned
  obtain ⟨frame, events, trace⟩ :=
    dispatch.TraceRefinement.driver_trace work checks start finish
      ⟨phase, false⟩ report returned
  have sound :=
    (trace_steps_preserve_soundness (fun _ => ctx) start.effects finish.effects
      events startReachable trace).2
  have binding : BoundTrace ctx.binding events :=
    trace_steps_keep_binding (fun _ => ctx) ctx.binding
      (by intro _; rfl) start.effects finish.effects events trace
  refine ⟨events, trace, sound, binding, frame, ?_⟩
  -- `ReadRun` is an exact classification of the extracted driver, not a
  -- second, permissive model of dispatch.
  have run :=
    (provider_exchange.Proofs.read_run_iff (driver work checks) start
      phase report finish).mp returned
  cases run with
  | setupDenied after error setup =>
      simp [provider_exchange.Proofs.receipt,
        provider_exchange.Stage.attempted] at attempted
  | admissionDenied channel first after error setup checked =>
      simp [provider_exchange.Proofs.receipt,
        provider_exchange.Stage.attempted] at attempted
  | sendDenied channel next stamp first checked after error setup current sent =>
      have issued : Issued ctx stamp := origin.2 stamp (by rfl)
      have fresh := freshSetup start first channel setup
      have submitted := linked checked finish channel next (.Err error) sent
      obtain ⟨calls, seen, projected, spent⟩ :=
        fresh_channel_observes_one bytes writer channel next (.Err error)
          phase ctx stamp fresh submitted
      exact ⟨stamp, checked, finish, channel, next, .Err error, calls,
        rfl, issued, sent, submitted, seen, projected, spent⟩
  | responseDenied channel next stamp first checked sentState after error setup current sent received =>
      have issued : Issued ctx stamp := origin.2 stamp (by rfl)
      have fresh := freshSetup start first channel setup
      have submitted := linked checked sentState channel next (.Ok ()) sent
      obtain ⟨calls, seen, projected, spent⟩ :=
        fresh_channel_observes_one bytes writer channel next (.Ok ())
          phase ctx stamp fresh submitted
      exact ⟨stamp, checked, sentState, channel, next, .Ok (), calls,
        rfl, issued, sent, submitted, seen, projected, spent⟩
  | complete channel next stamp first checked sentState after value setup current sent received =>
      have issued : Issued ctx stamp := origin.2 stamp (by rfl)
      have fresh := freshSetup start first channel setup
      have submitted := linked checked sentState channel next (.Ok ()) sent
      obtain ⟨calls, seen, projected, spent⟩ :=
        fresh_channel_observes_one bytes writer channel next (.Ok ())
          phase ctx stamp fresh submitted
      exact ⟨stamp, checked, sentState, channel, next, .Ok (), calls,
        rfl, issued, sent, submitted, seen, projected, spent⟩

end aivm_secrets_garrett_core.native_dispatch.ReadBoundary
