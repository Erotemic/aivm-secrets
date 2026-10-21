import GarrettProviderChannel
import GarrettRequestTrace

open Aeneas Aeneas.Std
set_option maxHeartbeats 1500000

/-!
A returned-call bridge from the *extracted* `provider_io::Request.submit`
and `Channel.submit` to the W4 provider-attempt event. The only primitive
hypotheses are the exact `Writer.write_all`/`flush` callback returns exposed
by `SubmitRun`; those callbacks can have partial external effects even on
failure. This does not model TLS delivery or non-returning executions.
-/
namespace aivm_secrets_garrett_core.provider_io.NativeWriterEvents

open aivm_secrets_garrett_core.provider_io.Proofs
open aivm_secrets_garrett_core.provider_io.ChannelProofs
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement

/-- Invocation of a high-level native `Writer` callback. `write_all` can
    internally accept any byte prefix and make multiple operating-system
    writes. A write event records an attempt, not accepted bytes or delivery. -/
inductive Call where
  | write (bytes : alloc.vec.Vec U8)
  | flush

/-- Relate a callback invocation history to the existing exhaustive
    classification of the actual extracted `Request.submit`. This relation
    does not introduce a second implementation of submission. -/
inductive Observed {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request : Request B) (writer : W) :
    core.result.Result Unit X → Request B → W → List Call → Prop where
  | replay (error : X) (spent : request.attempted = true)
      (invalid : ops.INVALID_TRANSITION = Result.ok error) :
      Observed bytes ops request writer (.Err error) request writer []
  | writeDenied (wire : alloc.vec.Vec U8) (after : W) (error : X)
      (fresh : request.attempted = false)
      (view : bytes.bytes request.body = Result.ok wire)
      (written : ops.write_all writer wire = Result.ok (.Err error, after)) :
      Observed bytes ops request writer (.Err error)
        {request with attempted := true} after [.write wire]
  | flushed (wire : alloc.vec.Vec U8) (written after : W)
      (out : core.result.Result Unit X)
      (fresh : request.attempted = false)
      (view : bytes.bytes request.body = Result.ok wire)
      (writeCall : ops.write_all writer wire = Result.ok (.Ok (), written))
      (flushCall : ops.flush written = Result.ok (out, after)) :
      Observed bytes ops request writer out
        {request with attempted := true} after [.write wire, .flush]

/-- Every *returned* source-owned submission has an exact primitive callback
    schedule. In particular a failed high-level write invokes no flush;
    a flush failure follows one successful high-level write. -/
theorem submit_observes_callbacks {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request after : Request B) (writer final : W) (out : core.result.Result Unit X)
    (returned : Request.submit bytes ops request writer = Result.ok (out, after, final)) :
    ∃ calls, Observed bytes ops request writer out after final calls := by
  cases (submit_run_iff bytes ops request after writer final out).mp returned with
  | replay error spent invalid =>
      exact ⟨[], .replay error spent invalid⟩
  | writeDenied =>
      -- `after` and the final writer are fixed by the constructor's indices.
      rename_i wire error fresh view writeCall
      exact ⟨[.write wire], .writeDenied wire final error fresh view writeCall⟩
  | flushed =>
      -- The return value and final writer are indexed; name only the remaining
      -- callback witnesses instead of asking elaboration to infer `wire`.
      rename_i wire written fresh view writeCall flushCall
      exact ⟨[.write wire, .flush],
        .flushed wire written final out fresh view writeCall flushCall⟩

/-- A W4 `providerSend` is counted when the guarded native write is attempted.
    A subsequent flush only changes uncertainty/response eligibility. -/
def projected (phase : read_transition.Phase) (ctx : Context)
    (stamp : manifest.AdmissionStamp) : List Call → List Event
  | [] => []
  | .write _ :: rest => attemptedEvent phase ctx stamp :: projected phase ctx stamp rest
  | .flush :: rest => projected phase ctx stamp rest

/-- After consuming a fresh request, either callback failure still produces
    exactly one abstract provider *attempt*, never a claimed arrival. -/
theorem fresh_callback_projects_one {B W X : Type} (bytes : WireBytes B)
    (ops : Writer W X) (request after : Request B) (writer final : W)
    (out : core.result.Result Unit X) (calls : List Call)
    (phase : read_transition.Phase) (ctx : Context) (stamp : manifest.AdmissionStamp)
    (fresh : request.attempted = false)
    (seen : Observed bytes ops request writer out after final calls) :
    projected phase ctx stamp calls = [attemptedEvent phase ctx stamp] := by
  cases seen with
  | replay error spent invalid => simp_all
  | writeDenied wire written error fresh view called => rfl
  | flushed wire written final outcome fresh view called flushed => rfl

/-- A spent request replays no credential-bearing callbacks or provider
    event. An earlier attempt belongs to its earlier history prefix. -/
theorem replay_projects_nothing {B W X : Type} (bytes : WireBytes B)
    (ops : Writer W X) (request after : Request B) (writer final : W)
    (out : core.result.Result Unit X) (calls : List Call)
    (phase : read_transition.Phase) (ctx : Context) (stamp : manifest.AdmissionStamp)
    (spent : request.attempted = true)
    (seen : Observed bytes ops request writer out after final calls) :
    projected phase ctx stamp calls = [] := by
  cases seen with
  | replay error spent invalid => rfl
  | writeDenied wire written error fresh view called => simp_all
  | flushed wire written final outcome fresh view called flushed => simp_all

/-- A fresh, admitted provider attempt is sound even if the high-level
    writer refuses zero bytes, accepts a prefix, or fails during flush. -/
theorem attempted_event_sound (phase : read_transition.Phase)
    (ctx : Context) (stamp : manifest.AdmissionStamp) (issued : Issued ctx stamp) :
    SoundTrace [attemptedEvent phase ctx stamp] := by
  intro event member
  have equal : event = attemptedEvent phase ctx stamp := by
    simpa only [List.mem_singleton] using member
  subst event
  exact ⟨issued_snapshot_is_accepted ctx stamp issued, rfl⟩

/-- Compose the ACTUAL source-owned receipt gate and captured native channel
    submission. No independent `providerReached` or `auditOK` flag is supplied.
    The caller must establish that it invoked this channel after this gate,
    that the channel was fresh, and that the checked stamp is source-issued.
    These adapter bindings and external callback/OS semantics remain NR-2/3
    obligations, not consequences of the present conditional theorem. -/
theorem guarded_channel_callback_projection {B W M X : Type}
    (bytes : WireBytes B) (ops : Writer W X)
    (contexts : read_transition.Phase → Context)
    (before after : request_effects.RequestEffects)
    (sendState nextSendState : provider_exchange.SendState)
    (phase : read_transition.Phase) (write : Bool)
    (stamp : manifest.AdmissionStamp)
    (pending final : Channel B W M X) (out : core.result.Result Unit X)
    (reachable : request_effects.Proofs.Reachable before)
    (marked : request_effects.RequestEffects.begin_send before phase sendState write =
      Result.ok (true, after, nextSendState))
    (stamped : nextSendState.progress = .Attempted stamp)
    (issued : Issued (contexts phase) stamp)
    (fresh : pending.request.attempted = false)
    (returned : Channel.submit bytes ops pending = Result.ok (out, final)) :
    ∃ calls, Observed bytes ops pending.request pending.writer out
        final.request final.writer calls ∧
      delta contexts before after = projected phase (contexts phase) stamp calls ∧
      SoundTrace (projected phase (contexts phase) stamp calls) ∧
      final.request.attempted = true := by
  obtain ⟨request, writer, called, finalState⟩ :=
    (channel_submit_iff bytes ops pending final out).mp returned
  obtain ⟨calls, observed⟩ :=
    submit_observes_callbacks bytes ops pending.request request pending.writer writer out called
  have exactProjection := fresh_callback_projects_one bytes ops pending.request request
    pending.writer writer out calls phase (contexts phase) stamp fresh observed
  have gate : delta contexts before after = [attemptedEvent phase (contexts phase) stamp] := by
    simpa [recordedEvents, stamped] using
      (send_counts_exactly contexts before after sendState nextSendState phase write true reachable marked)
  have spent := channel_spent bytes ops pending final out returned
  cases finalState
  exact ⟨calls, observed, gate.trans exactProjection.symm,
    by rw [exactProjection]; exact attempted_event_sound phase (contexts phase) stamp issued,
    spent⟩

end aivm_secrets_garrett_core.provider_io.NativeWriterEvents
