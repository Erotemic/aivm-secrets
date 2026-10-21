import GarrettProviderIO

open Aeneas Aeneas.Std
set_option maxHeartbeats 3000000

/-! Actual production channel ownership, exact submission fields and consuming
response gate. Native buffer/std-TLS/parser/storage semantics remain contracts. -/
namespace aivm_secrets_garrett_core.provider_io.ChannelProofs
open provider_io.Proofs

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

def succeeded {X : Type} (out : core.result.Result Unit X) : Bool :=
  match out with | .Ok _ => true | .Err _ => false

theorem channel_constructor {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (body : B) (writer : W) (metadata : M) :
    Channel.new bytes ops body writer metadata = Result.ok ⟨⟨body, false⟩, writer, metadata, false⟩ := by simp [Channel.new, Request.new]

/-- Exact request/writer selection and returned states. An unsuccessful extra
submission withdraws earlier readiness rather than retaining a sticky success. -/
theorem channel_submit_iff {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (pending after : Channel B W M X) (out : core.result.Result Unit X) :
    Channel.submit bytes ops pending = Result.ok (out, after) ↔
      ∃ request writer, Request.submit bytes ops pending.request pending.writer = Result.ok (out, request, writer) ∧
        after = {pending with request, writer, ready := succeeded out} := by
  constructor
  · intro returned
    unfold Channel.submit at returned
    obtain ⟨⟨result, request, writer⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp returned
    cases result with
    | Ok u =>
      cases u
      have equal : ((.Ok () : core.result.Result Unit X), {pending with request, writer, ready := true}) = (out, after) := by simpa using rest
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj equal
      exact ⟨request, writer, called, rfl⟩
    | Err error =>
      have equal : ((.Err error : core.result.Result Unit X), {pending with request, writer, ready := false}) = (out, after) := by simpa using rest
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj equal
      exact ⟨request, writer, called, rfl⟩
  · rintro ⟨request, writer, called, rfl⟩
    cases out with
    | Ok u => cases u; simp [Channel.submit, called, succeeded]
    | Err error => simp [Channel.submit, called, succeeded]

theorem channel_submission_run {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (pending after : Channel B W M X) (out : core.result.Result Unit X) :
    Channel.submit bytes ops pending = Result.ok (out, after) ↔
      SubmitRun bytes ops pending.request pending.writer out after.request after.writer ∧
        after.metadata = pending.metadata ∧ after.ready = succeeded out := by
  rw [channel_submit_iff]
  constructor
  · rintro ⟨request, writer, called, rfl⟩
    exact ⟨(submit_run_iff _ _ _ _ _ _ _).mp called, rfl, rfl⟩
  · rintro ⟨run, metadata, ready⟩
    refine ⟨after.request, after.writer, (submit_run_iff _ _ _ _ _ _ _).mpr run, ?_⟩
    cases pending; cases after; simp_all

theorem channel_preserves_capture {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (pending after : Channel B W M X) (out : core.result.Result Unit X)
    (returned : Channel.submit bytes ops pending = Result.ok (out, after)) :
    after.request.body = pending.request.body ∧ after.metadata = pending.metadata := by
  obtain ⟨request, writer, called, rfl⟩ := (channel_submit_iff bytes ops pending after out).mp returned
  exact ⟨returned_body_is_captured bytes ops pending.request request pending.writer writer out called, rfl⟩

theorem channel_spent {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (pending after : Channel B W M X) (out : core.result.Result Unit X)
    (returned : Channel.submit bytes ops pending = Result.ok (out, after)) : after.request.attempted = true := by
  obtain ⟨request, writer, called, rfl⟩ := (channel_submit_iff bytes ops pending after out).mp returned
  exact every_return_is_spent bytes ops pending.request request pending.writer writer out called

theorem parts_success_iff {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (pending : Channel B W M X) (parts : W × Request B × M) :
    Channel.into_parts bytes ops pending = Result.ok (.Ok parts) ↔
      pending.ready = true ∧ parts = (pending.writer, pending.request, pending.metadata) := by
  cases ready : pending.ready with
  | true => simp [Channel.into_parts, ready, eq_comm]
  | false =>
    cases invalid : ops.INVALID_TRANSITION <;> simp [Channel.into_parts, ready, invalid]

theorem blocked_parts {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (pending : Channel B W M X) (error : X) (blocked : pending.ready = false)
    (invalid : ops.INVALID_TRANSITION = Result.ok error) :
    Channel.into_parts bytes ops pending = Result.ok (.Err error) := by
  simp [Channel.into_parts, blocked, invalid]

theorem fresh_parts_refused {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (body : B) (writer : W) (metadata : M) (pending : Channel B W M X) (error : X)
    (created : Channel.new bytes ops body writer metadata = Result.ok pending)
    (invalid : ops.INVALID_TRANSITION = Result.ok error) :
    Channel.into_parts bytes ops pending = Result.ok (.Err error) := by
  have same : pending = ⟨⟨body, false⟩, writer, metadata, false⟩ := by simpa [Channel.new, Request.new] using created.symm
  subst pending
  exact blocked_parts bytes ops _ error rfl invalid

theorem replay_withdraws_readiness {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (pending : Channel B W M X) (error : X) (spent : pending.request.attempted = true)
    (invalid : ops.INVALID_TRANSITION = Result.ok error) :
    Channel.submit bytes ops pending = Result.ok (.Err error, {pending with ready := false}) ∧
      Channel.into_parts bytes ops {pending with ready := false} = Result.ok (.Err error) := by
  constructor
  · simp [Channel.submit, Request.submit, spent, invalid]
  · exact blocked_parts bytes ops _ error rfl invalid

private theorem successful_submit_origin {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request after : Request B) (writer final : W)
    (run : SubmitRun bytes ops request writer (.Ok ()) after final) :
    request.attempted = false ∧ after.body = request.body ∧
      ∃ wire written, bytes.bytes request.body = Result.ok wire ∧
        ops.write_all writer wire = Result.ok (.Ok (), written) ∧
        ops.flush written = Result.ok (.Ok (), final) := by
  cases run with
  | flushed wire written final out fresh viewed writeCall flushCall =>
    exact ⟨fresh, rfl, wire, written, viewed, writeCall, flushCall⟩

/-- Parser eligibility after an actual submission originates in exact captured
bytes accepted by the actual write callback followed by successful flush.
No readiness/provider-arrival/whole-callback history is supplied as a premise. -/
theorem released_parts_require_exact_flushed_bytes {B W M X : Type}
    (bytes : WireBytes B) (ops : Writer W X) (pending after : Channel B W M X)
    (out : core.result.Result Unit X) (parts : W × Request B × M)
    (returned : Channel.submit bytes ops pending = Result.ok (out, after))
    (released : Channel.into_parts bytes ops after = Result.ok (.Ok parts)) :
    out = .Ok () ∧ pending.request.attempted = false ∧
      after.request.body = pending.request.body ∧ after.metadata = pending.metadata ∧
      parts = (after.writer, after.request, after.metadata) ∧
      ∃ wire written, bytes.bytes pending.request.body = Result.ok wire ∧
        ops.write_all pending.writer wire = Result.ok (.Ok (), written) ∧
        ops.flush written = Result.ok (.Ok (), after.writer) := by
  obtain ⟨ready, parts⟩ := (parts_success_iff bytes ops after parts).mp released
  obtain ⟨run, metadata, success⟩ := (channel_submission_run bytes ops pending after out).mp returned
  have good : succeeded out = true := success.symm.trans ready
  have exactOut : out = .Ok () := by
    cases out with
    | Ok u => cases u; rfl
    | Err error => simp [succeeded] at good
  subst out
  obtain ⟨fresh, body, origin⟩ := successful_submit_origin bytes ops pending.request after.request pending.writer after.writer run
  exact ⟨rfl, fresh, body, metadata, parts, origin⟩

/-- A successful write and flush really enable the consuming response gate;
the channel is not an always-denying substitute for a working provider. -/
theorem successful_channel_witness {B W M X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (body : B) (writer written final : W) (metadata : M) (wire : alloc.vec.Vec U8)
    (viewed : bytes.bytes body = Result.ok wire)
    (writeCall : ops.write_all writer wire = Result.ok (.Ok (), written))
    (flushCall : ops.flush written = Result.ok (.Ok (), final)) :
    Channel.submit bytes ops (⟨⟨body, false⟩, writer, metadata, false⟩ : Channel B W M X) =
      Result.ok (.Ok (), ⟨⟨body, true⟩, final, metadata, true⟩) ∧
    Channel.into_parts bytes ops (⟨⟨body, true⟩, final, metadata, true⟩ : Channel B W M X) =
      Result.ok (.Ok (final, ⟨body, true⟩, metadata)) := by
  constructor
  · simp [Channel.submit, Request.submit, viewed, writeCall, flushCall]
  · rfl

end aivm_secrets_garrett_core.provider_io.ChannelProofs
