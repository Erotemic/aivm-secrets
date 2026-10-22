import GarrettNR23ExactSinks
import GarrettNativeWriterEvents

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-3 provider-write *byte* provenance. A W4 `providerSend` event has no
payload; event membership alone cannot prove the correct credentialed request
bytes were presented to the native writer. These theorems start instead from
an actual returned extracted `Channel.submit`, recover its exact callback
schedule and tie its `write` argument to the captured immutable request body.

The additional equality connecting the real `ManifestWire` wrapper to the
`provider_wire` encoder is still a native callback premise; TCP/TLS and kernel
send outcomes are never inferred from a returned `write_all` call.
-/
namespace aivm_secrets_garrett_core.nr23.WriterOrigin

open aivm_secrets_garrett_core.provider_io.Proofs
open aivm_secrets_garrett_core.provider_io.ChannelProofs
open aivm_secrets_garrett_core.provider_io.NativeWriterEvents
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.nr23.Effects

/-- Every *fresh*, returned channel submission invokes exactly one high-level
    `write_all` on the bytes returned by the captured body's `WireBytes`
    implementation. If the write fails, `flush` is not called; if it succeeds,
    the callback schedule includes one flush (success or failure). -/
theorem fresh_returned_channel_exposes_exact_writer_bytes
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writerOps : provider_io.Writer W X)
    (channel after : provider_io.Channel B W M X)
    (out : core.result.Result Unit X)
    (fresh : channel.request.attempted = false)
    (submitted : provider_io.Channel.submit bytes writerOps channel =
      Result.ok (out, after)) :
    ∃ calls wire,
      Observed bytes writerOps channel.request channel.writer out
        after.request after.writer calls ∧
      bytes.bytes channel.request.body = Result.ok wire ∧
      Call.write wire ∈ calls ∧
      after.request.attempted = true ∧
      after.request.body = channel.request.body ∧
      after.metadata = channel.metadata := by
  obtain ⟨request, writer, called, same⟩ :=
    (channel_submit_iff bytes writerOps channel after out).mp submitted
  have exactBody := channel_preserves_capture bytes writerOps
    channel after out submitted
  have spent := channel_spent bytes writerOps channel after out submitted
  obtain ⟨calls, seen⟩ := submit_observes_callbacks bytes writerOps
    channel.request request channel.writer writer out called
  have concrete : ∃ wire,
      bytes.bytes channel.request.body = Result.ok wire ∧
      Call.write wire ∈ calls := by
    cases seen with
    | replay error spent invalid =>
        simp_all
    | writeDenied wire written error wasFresh viewed failed =>
        exact ⟨wire, viewed, by simp⟩
    | flushed wire written final result wasFresh viewed accepted flushed =>
        exact ⟨wire, viewed, by simp⟩
  obtain ⟨wire, viewed, member⟩ := concrete
  cases same
  exact ⟨calls, wire, seen, viewed, member, spent,
    exactBody.1, exactBody.2⟩

/-- The callback-event projection for a source-issued stamp counts ONE
    attempt, regardless of successful flush, failed write, or failed flush.
    The native entry must still show the returned channel is the one from
    the checked source phase. -/
theorem admitted_fresh_channel_emits_one_exact_attempt
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writerOps : provider_io.Writer W X)
    (channel after : provider_io.Channel B W M X)
    (out : core.result.Result Unit X)
    (phase : read_transition.Phase) (ctx : Context)
    (stamp : manifest.AdmissionStamp)
    (issued : Issued ctx stamp)
    (fresh : channel.request.attempted = false)
    (submitted : provider_io.Channel.submit bytes writerOps channel =
      Result.ok (out, after)) :
    ∃ calls wire,
      Observed bytes writerOps channel.request channel.writer out
        after.request after.writer calls ∧
      bytes.bytes channel.request.body = Result.ok wire ∧
      Call.write wire ∈ calls ∧
      projected phase ctx stamp calls = [attemptedEvent phase ctx stamp] ∧
      SoundTrace (projected phase ctx stamp calls) ∧
      after.request.attempted = true := by
  obtain ⟨calls, wire, seen, viewed, member, spent, _, _⟩ :=
    fresh_returned_channel_exposes_exact_writer_bytes bytes writerOps
      channel after out fresh submitted
  have projection := fresh_callback_projects_one bytes writerOps
    channel.request after.request channel.writer after.writer out calls
    phase ctx stamp fresh seen
  have sound : SoundTrace (projected phase ctx stamp calls) := by
    rw [projection]
    exact attempted_event_sound phase ctx stamp issued
  exact ⟨calls, wire, seen, viewed, member, projection, sound, spent⟩

/-- Complete provider result parsing requires the EXACT captured request to
    have been passed to a successful high-level write AND flush callback.
    There is no separate, caller-asserted `providerReached` boolean. -/
theorem actual_response_handoff_requires_write_then_flush
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writerOps : provider_io.Writer W X)
    (channel after : provider_io.Channel B W M X)
    (out : core.result.Result Unit X)
    (parts : W × provider_io.Request B × M)
    (submitted : provider_io.Channel.submit bytes writerOps channel =
      Result.ok (out, after))
    (released : provider_io.Channel.into_parts bytes writerOps after =
      Result.ok (.Ok parts)) :
    out = .Ok () ∧
    channel.request.attempted = false ∧
    after.request.attempted = true ∧
    after.request.body = channel.request.body ∧
    after.metadata = channel.metadata ∧
    parts = (after.writer, after.request, after.metadata) ∧
    ∃ wire written,
      bytes.bytes channel.request.body = Result.ok wire ∧
      writerOps.write_all channel.writer wire = Result.ok (.Ok (), written) ∧
      writerOps.flush written = Result.ok (.Ok (), after.writer) := by
  obtain ⟨success, fresh, body, metadata, partsOrigin, wire, written,
    viewed, writeCall, flushCall⟩ :=
    released_parts_require_exact_flushed_bytes bytes writerOps
      channel after out parts submitted released
  have spent := channel_spent bytes writerOps channel after out submitted
  exact ⟨success, fresh, spent, body, metadata, partsOrigin,
    wire, written, viewed, writeCall, flushCall⟩

/-- Failure is intentionally NOT equated with zero bytes sent. The source
    channel consumes the attempt and disables response parsing; a replay
    through that channel has no writer callback even if the failed write
    already transferred an unknown prefix to rustls/TCP. -/
theorem returned_failed_writer_cannot_replay_or_release
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writerOps : provider_io.Writer W X)
    (channel after : provider_io.Channel B W M X)
    (error denied : X)
    (submitted : provider_io.Channel.submit bytes writerOps channel =
      Result.ok (.Err error, after))
    (invalid : writerOps.INVALID_TRANSITION = Result.ok denied) :
    after.request.attempted = true ∧ after.ready = false ∧
    provider_io.Channel.into_parts bytes writerOps after =
      Result.ok (.Err denied) ∧
    provider_io.Channel.submit bytes writerOps after =
      Result.ok (.Err denied, {after with ready := false}) := by
  obtain ⟨_, _, ready⟩ :=
    (channel_submission_run bytes writerOps channel after (.Err error)).mp submitted
  have spent := channel_spent bytes writerOps channel after (.Err error) submitted
  have locked : after.ready = false := by
    simpa [succeeded] using ready
  have refused := blocked_parts bytes writerOps after denied locked invalid
  have replay := (replay_withdraws_readiness bytes writerOps after denied
    spent invalid).1
  exact ⟨spent, locked, refused, replay⟩

/-- Model-level exact-byte evidence for a *native observation*. The bridge
    from an actual OS/TLS write attempt to this high-level callback remains a
    distinct implementation theorem/contract; it must not be constructed
    from a guessed `payload` or simply from event membership. -/
def PayloadCorresponds {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (attempt : NativeAttempt)
    (channel : provider_io.Channel B W M X) : Prop :=
  ∃ wire,
    bytes.bytes channel.request.body = Result.ok wire ∧
    attempt.payload = wire.val

/-- For a successful, released source channel, any externally observed
    native attempt which is byte-corresponding to that SAME channel has the
    exact writer payload. The premise identifies the OS event with that call;
    it is not inferred by observing a returned `Channel.submit`. -/
theorem admitted_released_channel_pins_observed_native_payload
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writerOps : provider_io.Writer W X)
    (channel after : provider_io.Channel B W M X)
    (out : core.result.Result Unit X)
    (parts : W × provider_io.Request B × M)
    (attempt : NativeAttempt)
    (submitted : provider_io.Channel.submit bytes writerOps channel =
      Result.ok (out, after))
    (released : provider_io.Channel.into_parts bytes writerOps after =
      Result.ok (.Ok parts))
    (linked : PayloadCorresponds bytes attempt channel) :
    ∃ wire written,
      attempt.payload = wire.val ∧
      bytes.bytes channel.request.body = Result.ok wire ∧
      writerOps.write_all channel.writer wire = Result.ok (.Ok (), written) ∧
      writerOps.flush written = Result.ok (.Ok (), after.writer) := by
  obtain ⟨wire, written, viewed, writeCall, flushCall⟩ :=
    (actual_response_handoff_requires_write_then_flush bytes writerOps
      channel after out parts submitted released).2.2.2.2.2.2
  obtain ⟨reported, reportedView, same⟩ := linked
  have equal : reported = wire := by
    have eqOuter : Result.ok reported = Result.ok wire :=
      reportedView.symm.trans viewed
    exact Result.ok_injective eqOuter
  subst reported
  exact ⟨wire, written, same, viewed, writeCall, flushCall⟩

end aivm_secrets_garrett_core.nr23.WriterOrigin
