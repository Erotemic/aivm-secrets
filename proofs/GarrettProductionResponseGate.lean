import GarrettProductionSelectedRelease
import GarrettProviderChannel

open Aeneas Aeneas.Std
set_option maxHeartbeats 6500000

/-!
The production `ManifestProvider::receive` obtains a sealed, non-cloneable
`response_gate.Released` token from the Aeneas-extracted `response_gate.receive`
function. Its native parser consumes that token, not a Channel or arbitrary
writer/request tuple. This avoids an Aeneas symbolic-interpreter failure in
the former generic Parser trait without introducing a hand-modeled callback.

The source-derived lemmas below prove that a successful token release requires
the actual channel's ready gate. Combined with the extracted `Channel.submit`
theorems, a token-producing execution has exact captured byte and successful
write/flush witnesses. Concrete parser, TLS and socket effects remain native.
-/
namespace aivm_secrets_garrett_core.response_gate.Proofs

/-- Failed readiness returns the actual extracted writer's transition error;
    no native parser token is minted. -/
theorem unreadied_channel_cannot_mint_parse_token
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writer : provider_io.Writer W X)
    (channel : provider_io.Channel B W M X)
    (error : X) (notReady : channel.ready = false)
    (invalid : writer.INVALID_TRANSITION = Result.ok error) :
    response_gate.receive bytes writer channel =
      Result.ok (.Err error) := by
  simp [response_gate.receive, provider_io.Channel.into_parts, notReady, invalid,
    core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]

/-- A returned token cannot be created on a not-ready channel. This is a
    property of the production-extracted source function, not of a supplied
    parser callback model. -/
theorem returned_parse_token_implies_ready
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writer : provider_io.Writer W X)
    (channel : provider_io.Channel B W M X)
    (returned : ∃ token,
      response_gate.receive bytes writer channel = Result.ok (.Ok token)) :
    channel.ready = true := by
  cases hready : channel.ready with
  | true => rfl
  | false =>
    obtain ⟨token, got⟩ := returned
    cases hinvalid : writer.INVALID_TRANSITION using Result.cases <;>
      simp [response_gate.receive, provider_io.Channel.into_parts,
        hready, hinvalid, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at got

/-- Successfully producing a token implies *the actual source channel*
    would release exactly its current writer, captured request and metadata.
    There is no alternate success path through the response gate. -/
theorem returned_token_has_exact_channel_parts
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writer : provider_io.Writer W X)
    (channel : provider_io.Channel B W M X)
    (returned : ∃ token,
      response_gate.receive bytes writer channel = Result.ok (.Ok token)) :
    provider_io.Channel.into_parts bytes writer channel =
      Result.ok (.Ok (channel.writer, channel.request, channel.metadata)) := by
  have ready := returned_parse_token_implies_ready
    bytes writer channel returned
  simp [provider_io.Channel.into_parts, ready]

/-- The extracted Rust submit + returned parse token form one gate.
    The successful source path supplies byte provenance, one attempted send,
    the successful high-level write and flush callbacks, and the identical
    writer/request/metadata triple eligible for the native parser.
    No statement about actual TCP bytes or native parser correctness is made. -/
theorem actual_release_after_submit_has_exact_writer_origin
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writer : provider_io.Writer W X)
    (before after : provider_io.Channel B W M X)
    (sent : core.result.Result Unit X)
    (submitted : provider_io.Channel.submit bytes writer before =
      Result.ok (sent, after))
    (returned : ∃ token,
      response_gate.receive bytes writer after = Result.ok (.Ok token)) :
    sent = .Ok () ∧ before.request.attempted = false ∧
      after.request.body = before.request.body ∧
      after.metadata = before.metadata ∧
      ∃ wire written,
        provider_io.Channel.into_parts bytes writer after =
          Result.ok (.Ok (after.writer, after.request, after.metadata)) ∧
        bytes.bytes before.request.body = Result.ok wire ∧
        writer.write_all before.writer wire = Result.ok (.Ok (), written) ∧
        writer.flush written = Result.ok (.Ok (), after.writer) := by
  have released := returned_token_has_exact_channel_parts bytes writer after returned
  obtain ⟨successful, fresh, body, sameMetadata, _, wire, written,
    viewed, writeCall, flushed⟩ :=
    provider_io.ChannelProofs.released_parts_require_exact_flushed_bytes
      bytes writer before after sent
      (after.writer, after.request, after.metadata)
      submitted released
  exact ⟨successful, fresh, body, sameMetadata, wire, written,
    released, viewed, writeCall, flushed⟩

end aivm_secrets_garrett_core.response_gate.Proofs
