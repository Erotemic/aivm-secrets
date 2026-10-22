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


/-! ### Source-bound constructor and terminal-response refinements

These results do not replace the two native adapter contracts with a model of
arbitrary native I/O. Instead, successful setup must now be *explained by a
specific returned `Channel.new` call*. This syntactically narrower contract
implies freshness and pre-submit parser refusal in the extracted core.

For the source-owned read driver, a response-stage or complete-stage result is
connected to an actual successful `Channel.submit`, exact captured wire bytes,
a successful high-level write and flush, and a response-eligible channel.
Conversely, a send-stage failure leaves its channel spent and locked. The
provider's `Write`, TLS, audit-file and response-parser implementations remain
external primitives; `write_all` success is NOT TCP delivery or durable I/O.
-/

/-- Native `ManifestProvider::setup_route` ends its successful branch with
    `Channel::new(request, ProviderWriter(stream), deadline)`. Aeneas extracts
    the channel factory, but not the preceding native TLS setup. This contract
    records the *exact returned constructor call* instead of directly assuming
    that an arbitrary successful setup returned a fresh channel. -/
def SetupReturnsConstructed {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X) : Prop :=
  ∀ (before after : NativePending W C B V M X O)
    (channel : NativeChannel B V M X),
    (driver work checks).setup before = Result.ok (.Ok channel, after) →
      ∃ body native metadata,
        provider_io.Channel.new bytes writer body native metadata = Result.ok channel

/-- The exact native constructor contract discharges the previously separate
    `SetupReturnsFresh` assumption using the extracted `Channel.new` body. -/
theorem constructed_setup_implies_fresh
    {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (constructed : SetupReturnsConstructed work checks bytes writer) :
    SetupReturnsFresh work checks := by
  intro before after channel setup
  obtain ⟨body, native, metadata, made⟩ := constructed before after channel setup
  have exact : channel =
      (⟨⟨body, false⟩, native, metadata, false⟩ : NativeChannel B V M X) := by
    simpa [provider_io.Channel.new, provider_io.Request.new] using made.symm
  rw [exact]

/-- Immediately after the actual returned setup callback the extracted
    response handoff is locked, even if native TCP/TLS setup has succeeded.
    This property relies on `Channel.new` and the native writer's selected
    invalid-transition error, not on an arbitrary `ready` assertion. -/
theorem constructed_setup_locks_response
    {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (before after : NativePending W C B V M X O)
    (channel : NativeChannel B V M X) (invalidError : X)
    (setup : (driver work checks).setup before = Result.ok (.Ok channel, after))
    (constructed : SetupReturnsConstructed work checks bytes writer)
    (invalid : writer.INVALID_TRANSITION = Result.ok invalidError) :
    channel.request.attempted = false ∧ channel.ready = false ∧
    provider_io.Channel.into_parts bytes writer channel = Result.ok (.Err invalidError) := by
  obtain ⟨body, native, metadata, made⟩ := constructed before after channel setup
  have exact : channel =
      (⟨⟨body, false⟩, native, metadata, false⟩ : NativeChannel B V M X) := by
    simpa [provider_io.Channel.new, provider_io.Request.new] using made.symm
  have denied := provider_io.ChannelProofs.fresh_parts_refused
    bytes writer body native metadata channel invalidError made invalid
  rw [exact] at denied ⊢
  exact ⟨rfl, rfl, denied⟩

/-- A returned successful `Channel.submit` alone supplies response eligibility
    and the exact captured bytes accepted by the native writer callback before
    `flush` succeeds. No caller may assert parser readiness or select arbitrary
    bytes. The still-abstract callbacks are `Writer.bytes`, `write_all`, `flush`. -/
private theorem successful_submit_has_exact_flushed_wire
    {B V M X : Type}
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (channel next : NativeChannel B V M X)
    (submitted : provider_io.Channel.submit bytes writer channel =
      Result.ok (.Ok (), next)) :
    next.ready = true ∧
    provider_io.Channel.into_parts bytes writer next =
      Result.ok (.Ok (next.writer, next.request, next.metadata)) ∧
    channel.request.attempted = false ∧ next.request.attempted = true ∧
    next.request.body = channel.request.body ∧ next.metadata = channel.metadata ∧
    ∃ wire written, bytes.bytes channel.request.body = Result.ok wire ∧
      writer.write_all channel.writer wire = Result.ok (.Ok (), written) ∧
      writer.flush written = Result.ok (.Ok (), next.writer) := by
  have run := (provider_io.ChannelProofs.channel_submission_run
    bytes writer channel next (.Ok ())).mp submitted
  have ready : next.ready = true := by
    simpa [provider_io.ChannelProofs.succeeded] using run.2.2
  have released : provider_io.Channel.into_parts bytes writer next =
      Result.ok (.Ok (next.writer, next.request, next.metadata)) :=
    (provider_io.ChannelProofs.parts_success_iff bytes writer next _).mpr
      ⟨ready, rfl⟩
  have facts := provider_io.ChannelProofs.released_parts_require_exact_flushed_bytes
    bytes writer channel next (.Ok ())
    (next.writer, next.request, next.metadata) submitted released
  obtain ⟨_, fresh, sameBody, sameMetadata, _, wire, written, viewed,
    writeCall, flushed⟩ := facts
  exact ⟨ready, released, fresh,
    provider_io.ChannelProofs.channel_spent bytes writer channel next (.Ok ()) submitted,
    sameBody, sameMetadata, wire, written, viewed, writeCall, flushed⟩

/-- A returned read at the response-failure or complete stage passed the
    exact captured body to the actual source-owned native channel writer and
    successfully flushed it *before* invoking the response callback. This
    composes the source-owned admission/audit trace and immutable binding with
    the production-called `Channel.submit`/`into_parts` path.

    Important boundary: we prove `into_parts` is eligible, not that the native
    `ManifestProvider::receive` function called it; that latter native source
    linkage remains a separate, reviewable adapter obligation. -/
theorem returned_postsend_read_has_exact_flushed_wire
    {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (start finish : NativePending W C B V M X O)
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (reachable : Reachable start.effects)
    (returned : provider_exchange.exchange (driver work checks)
      start ⟨phase, false⟩ = Result.ok (report, finish))
    (postSend : report.stage = .Response ∨ report.stage = .Complete)
    (constructed : SetupReturnsConstructed work checks bytes writer)
    (linked : SendsThroughChannel work checks bytes writer) :
    ∃ events,
      TraceSteps (fun _ => current_admission.Proofs.view start.work.context)
        start.effects finish.effects events ∧
      confinement.Proofs.SoundTrace events ∧
      BoundTrace (current_admission.Proofs.view start.work.context).binding events ∧
      finish.work.context = start.work.context ∧
      ∃ (stamp : manifest.AdmissionStamp)
        (sendBefore receiveBefore : NativePending W C B V M X O)
        (channel next : NativeChannel B V M X)
        (received : core.result.Result O X),
        report.current = some stamp ∧ report.result = received ∧
        Issued (current_admission.Proofs.view start.work.context) stamp ∧
        (driver work checks).send sendBefore channel =
          Result.ok (.Ok (), receiveBefore, next) ∧
        (driver work checks).receive receiveBefore next =
          Result.ok (received, finish) ∧
        next.ready = true ∧
        provider_io.Channel.into_parts bytes writer next =
          Result.ok (.Ok (next.writer, next.request, next.metadata)) ∧
        channel.request.attempted = false ∧ next.request.attempted = true ∧
        next.request.body = channel.request.body ∧ next.metadata = channel.metadata ∧
        ∃ wire written, bytes.bytes channel.request.body = Result.ok wire ∧
          writer.write_all channel.writer wire = Result.ok (.Ok (), written) ∧
          writer.flush written = Result.ok (.Ok (), next.writer) := by
  have attempted : provider_exchange.Stage.attempted report.stage = Result.ok true := by
    rcases postSend with h | h <;> simp [h, provider_exchange.Stage.attempted]
  have fresh := constructed_setup_implies_fresh work checks bytes writer constructed
  obtain ⟨events, traced, sound, binding, framed, _⟩ :=
    returned_attempted_read_has_checked_writer work checks bytes writer
      start finish phase report reachable returned attempted fresh linked
  refine ⟨events, traced, sound, binding, framed, ?_⟩
  have origin := current_admission.Proofs.owned_read_driver_stamp_origin
    work checks start finish phase report returned
  have run := (provider_exchange.Proofs.read_run_iff (driver work checks)
    start phase report finish).mp returned
  cases run with
  | setupDenied =>
      simp [provider_exchange.Proofs.receipt] at postSend
  | admissionDenied =>
      simp [provider_exchange.Proofs.receipt] at postSend
  | sendDenied =>
      simp [provider_exchange.Proofs.receipt] at postSend
  | responseDenied channel next stamp first checked sendAfter after error setup current sent received =>
      have issued : Issued (current_admission.Proofs.view start.work.context) stamp :=
        origin.2 stamp (by rfl)
      have submitted := linked checked sendAfter channel next (.Ok ()) sent
      obtain ⟨ready, released, fresh, spent, body, metadata, wire, written,
        viewed, writeCall, flushed⟩ :=
        successful_submit_has_exact_flushed_wire bytes writer channel next submitted
      exact ⟨stamp, checked, sendAfter, channel, next, .Err error,
        rfl, rfl, issued, sent, received, ready, released, fresh, spent,
        body, metadata, wire, written, viewed, writeCall, flushed⟩
  | complete channel next stamp first checked sendAfter after value setup current sent received =>
      have issued : Issued (current_admission.Proofs.view start.work.context) stamp :=
        origin.2 stamp (by rfl)
      have submitted := linked checked sendAfter channel next (.Ok ()) sent
      obtain ⟨ready, released, fresh, spent, body, metadata, wire, written,
        viewed, writeCall, flushed⟩ :=
        successful_submit_has_exact_flushed_wire bytes writer channel next submitted
      exact ⟨stamp, checked, sendAfter, channel, next, .Ok value,
        rfl, rfl, issued, sent, received, ready, released, fresh, spent,
        body, metadata, wire, written, viewed, writeCall, flushed⟩

/-- A returned read failing in `send` cannot hand its channel to the native
    response parser. The request is spent even if `write_all` or `flush` failed
    and even if the underlying writer accepted a partial prefix. A second
    `submit` returns the invalid-transition error without invoking the writer.
    The fixed receipt stamp is recovered from the source-owned current check. -/
theorem returned_send_failure_is_spent_and_cannot_retry
    {W C B V M X O : Type}
    (work : dispatch.Work W (NativeChannel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (start finish : NativePending W C B V M X O)
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (driver work checks)
      start ⟨phase, false⟩ = Result.ok (report, finish))
    (failedSend : report.stage = .Send)
    (constructed : SetupReturnsConstructed work checks bytes writer)
    (linked : SendsThroughChannel work checks bytes writer)
    (invalidError : X)
    (invalid : writer.INVALID_TRANSITION = Result.ok invalidError) :
    ∃ (stamp : manifest.AdmissionStamp)
      (sendBefore : NativePending W C B V M X O)
      (channel next : NativeChannel B V M X) (error : X) (calls : List Call),
      report.current = some stamp ∧
      Issued (current_admission.Proofs.view start.work.context) stamp ∧
      (driver work checks).send sendBefore channel =
        Result.ok (.Err error, finish, next) ∧
      provider_io.Channel.submit bytes writer channel = Result.ok (.Err error, next) ∧
      channel.request.attempted = false ∧
      Observed bytes writer channel.request channel.writer (.Err error)
        next.request next.writer calls ∧
      projected phase (current_admission.Proofs.view start.work.context) stamp calls =
        [attemptedEvent phase (current_admission.Proofs.view start.work.context) stamp] ∧
      next.request.attempted = true ∧ next.ready = false ∧
      provider_io.Channel.into_parts bytes writer next = Result.ok (.Err invalidError) ∧
      provider_io.Channel.submit bytes writer next =
        Result.ok (.Err invalidError, {next with ready := false}) ∧
      provider_io.Channel.into_parts bytes writer {next with ready := false} =
        Result.ok (.Err invalidError) := by
  have run := (provider_exchange.Proofs.read_run_iff (driver work checks)
    start phase report finish).mp returned
  have origin := current_admission.Proofs.owned_read_driver_stamp_origin
    work checks start finish phase report returned
  have freshSetup := constructed_setup_implies_fresh work checks bytes writer constructed
  cases run with
  | setupDenied =>
      simp [provider_exchange.Proofs.receipt] at failedSend
  | admissionDenied =>
      simp [provider_exchange.Proofs.receipt] at failedSend
  | responseDenied =>
      simp [provider_exchange.Proofs.receipt] at failedSend
  | complete =>
      simp [provider_exchange.Proofs.receipt] at failedSend
  | sendDenied channel next stamp first checked after error setup current sent =>
      have issued : Issued (current_admission.Proofs.view start.work.context) stamp :=
        origin.2 stamp (by rfl)
      have fresh := freshSetup start first channel setup
      have submitted := linked checked finish channel next (.Err error) sent
      obtain ⟨calls, observed, projection, spent⟩ :=
        fresh_channel_observes_one bytes writer channel next (.Err error)
          phase (current_admission.Proofs.view start.work.context) stamp fresh submitted
      have runSubmit := (provider_io.ChannelProofs.channel_submission_run
        bytes writer channel next (.Err error)).mp submitted
      have locked : next.ready = false := by
        simpa [provider_io.ChannelProofs.succeeded] using runSubmit.2.2
      have refused := provider_io.ChannelProofs.blocked_parts
        bytes writer next invalidError locked invalid
      have replay := provider_io.ChannelProofs.replay_withdraws_readiness
        bytes writer next invalidError spent invalid
      exact ⟨stamp, checked, channel, next, error, calls, rfl, issued,
        sent, submitted, fresh, observed, projection, spent, locked,
        refused, replay.1, replay.2⟩

end aivm_secrets_garrett_core.native_dispatch.ReadBoundary
