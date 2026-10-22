import GarrettProductionAuditRecord
import GarrettProductionSelectedRelease
import GarrettProductionResponseGate

open Aeneas Aeneas.Std
set_option maxHeartbeats 6500000

/-!
Production extraction campaign, entrypoint.

Native production now calls three Aeneas-extractable controllers:
  * `audit_record.append_durable_record`: poison, payload, LF, sync, ack;
  * `selected_release.select`: current/page/project/assemble/reflection;
  * `response_gate.receive`: mint a sealed, single-use parse eligibility
    token only after `provider_io.Channel.into_parts` succeeds.

The first two controllers expose returned callback witnesses; the third
produces a proof-carrying owned token. `ManifestResponse::parse` consumes it
in native Rust. No generic Parser trait is hand-represented in Lean.
The actual File/TLS/socket/serde/callback behavior and complete sink reachability
remain independently scoped assumptions.
-/
namespace aivm_secrets_garrett_core.production.AdapterRefinement

open aivm_secrets_garrett_core.audit_record.Proofs
open aivm_secrets_garrett_core.selected_release.Proofs
open aivm_secrets_garrett_core.response_gate.Proofs

/-- Independent extracted fail-stop properties, without sequencing contracts
    provided by the caller. -/
theorem poisoned_audit_and_revoked_selection_refuse
    {S X W M Sel Reply : Type}
    (audit : audit_record.Sink S X)
    (release : selected_release.Work W M Sel Reply X)
    (file : S) (payload : alloc.vec.Vec U8)
    (work afterWork : W) (code : X)
    (poisoned : audit.POISONED = Result.ok code)
    (revoked : release.current work = Result.ok (.Err code, afterWork)) :
    audit_record.append_durable_record audit file true payload =
      Result.ok (.Err code, file, true) ∧
    selected_release.select release work = Result.ok (.Err code, afterWork) := by
  exact ⟨poisoned_record_refuses_before_any_callback audit file payload code poisoned,
    stale_current_control_refuses_release release work afterWork code revoked⟩

/-- The source-owned response gate cannot yield a parse token before the
    successfully flushed channel permits release. -/
theorem extracted_response_gate_is_refusal_preserving
    {B W M X : Type}
    (bytes : provider_io.WireBytes B)
    (writer : provider_io.Writer W X)
    (channel : provider_io.Channel B W M X)
    (code : X) (notReady : channel.ready = false)
    (invalid : writer.INVALID_TRANSITION = Result.ok code) :
    response_gate.receive bytes writer channel = Result.ok (.Err code) := by
  exact unreadied_channel_cannot_mint_parse_token
    bytes writer channel code notReady invalid

/-- Three successful source executions yield actual ordered payload/LF/sync
    audit callbacks, all five selected-release callbacks, and exact captured
    writer/flush provenance for the channel that minted its parser token.

    The native parser consumes a sealed token by value; its behavior is not
    modeled by a fictitious generic parser callback. Linking all three source
    executions to the same native request and proving the primitive callbacks
    remain outstanding implementation-refinement obligations. -/
theorem returned_audit_selection_and_receive_have_source_callback_witnesses
    {S A W Meta Sel Reply B Writer M X : Type}
    (auditOps : audit_record.Sink S A)
    (selectedOps : selected_release.Work W Meta Sel Reply X)
    (bytes : provider_io.WireBytes B)
    (writerOps : provider_io.Writer Writer X)
    (auditStart auditDone : S) (record : alloc.vec.Vec U8)
    (selectStart selectDone : W) (reply : Reply)
    (before after : provider_io.Channel B Writer M X)
    (submittedResult : core.result.Result Unit X)
    (auditReturned : audit_record.append_durable_record auditOps auditStart false record =
      Result.ok (.Ok (), auditDone, false))
    (selectReturned : selected_release.select selectedOps selectStart =
      Result.ok (.Ok reply, selectDone))
    (submitReturned : provider_io.Channel.submit bytes writerOps before =
      Result.ok (submittedResult, after))
    (receiveReturned : ∃ token,
      response_gate.receive bytes writerOps after = Result.ok (.Ok token)) :
    (∃ first second : S, ∃ delimiter : alloc.vec.Vec U8,
      audit_record.record_delimiter = Result.ok delimiter ∧
      delimiter.val = [10#u8] ∧
      auditOps.append auditStart record = Result.ok (.Ok (), first) ∧
      auditOps.append first delimiter = Result.ok (.Ok (), second) ∧
      auditOps.sync_record second = Result.ok (.Ok (), auditDone)) ∧
    (∃ checked paged projected assembled : W, ∃ metadata : Option Meta,
      ∃ selected : Sel,
      selectedOps.current selectStart = Result.ok (.Ok (), checked) ∧
      selectedOps.pagination checked = Result.ok (.Ok metadata, paged) ∧
      selectedOps.project paged = Result.ok (.Ok selected, projected) ∧
      selectedOps.assemble projected selected metadata = Result.ok (reply, assembled) ∧
      selectedOps.check_safe assembled reply = Result.ok (.Ok (), selectDone)) ∧
    (submittedResult = .Ok () ∧ before.request.attempted = false ∧
      after.request.body = before.request.body ∧
      after.metadata = before.metadata ∧
      ∃ wire written,
        provider_io.Channel.into_parts bytes writerOps after =
          Result.ok (.Ok (after.writer, after.request, after.metadata)) ∧
        bytes.bytes before.request.body = Result.ok wire ∧
        writerOps.write_all before.writer wire = Result.ok (.Ok (), written) ∧
        writerOps.flush written = Result.ok (.Ok (), after.writer)) := by
  exact ⟨
    returned_success_requires_exact_append_delimiter_sync
      auditOps auditStart auditDone record auditReturned,
    every_successful_release_has_all_five_callbacks
      selectedOps selectStart selectDone reply selectReturned,
    actual_release_after_submit_has_exact_writer_origin
      bytes writerOps before after submittedResult submitReturned receiveReturned⟩

end aivm_secrets_garrett_core.production.AdapterRefinement
