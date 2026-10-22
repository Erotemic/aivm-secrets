import GarrettNR23Request
import GarrettNativeReadBoundary

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-2/3 fail-closed and uncertain-outcome branches of the *source-owned*
request/dispatch/provider controller. Actual transport delivery and every
native `Write` callback reachable from the process are not asserted.
-/
namespace aivm_secrets_garrett_core.nr23.Failures

open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.native_dispatch.ReadBoundary

private abbrev NativePending {W C B V M X O : Type} :=
  dispatch.Pending (current_admission.Bound W C (provider_io.Channel B V M X) O X)
    (provider_io.Channel B V M X) O X

private abbrev boundOps {W C B V M X O : Type}
    (work : dispatch.Work W (provider_io.Channel B V M X) O X)
    (checks : current_admission.Checks C X) :=
  current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks

private abbrev driver {W C B V M X O : Type}
    (work : dispatch.Work W (provider_io.Channel B V M X) O X)
    (checks : current_admission.Checks C X) :=
  dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider
    (boundOps work checks)

/-- A real returned setup/current-denial prefix has neither a new request-wide
    attempt receipt nor a stamp; its source-owned context stays fixed. This is
    *not* a statement that TLS handshake setup was network-silent. -/
theorem early_refusal_retains_exact_receipt_and_no_current_stamp
    {W C B V M X O : Type}
    (work : dispatch.Work W (provider_io.Channel B V M X) O X)
    (checks : current_admission.Checks C X)
    (initial final : NativePending (W := W) (C := C) (B := B)
      (V := V) (M := M) (X := X) (O := O))
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (driver work checks)
      initial ⟨phase, false⟩ = Result.ok (report, final))
    (refused : report.stage = .Setup ∨ report.stage = .Admission) :
    final.effects = initial.effects ∧
    final.work.context = initial.work.context ∧ report.current = none := by
  exact rejected_before_send_keeps_receipt work checks initial final
    phase report returned refused

/-- Auditing is a distinct gate. An acknowledged dispatch with no source-owned
    provider attempt cannot skip directly to completion. -/
theorem audited_but_unsent_cannot_complete
    (state : request_effects.RequestEffects) (phase : read_transition.Phase)
    (audited : state.progress = .Audited phase) :
    request_effects.RequestEffects.begin_completion state =
      Result.ok (false, {state with progress := .Halted}) := by
  exact request_effects.Proofs.audited_unsent_cannot_complete
    state phase audited

/-- A completion audit acknowledgement alone does not unlock a response. The
    second freshness check must complete and the core must reach `ValueReady`.
    This rules out equating an audit callback with release permission. -/
theorem completion_audit_acknowledgement_is_not_a_reply
    (state : request_effects.RequestEffects)
    (audited : state.progress = .CompletionAudited) :
    request_effects.RequestEffects.can_return_value state = Result.ok false := by
  exact completion_ack_is_not_return_permission state audited

/-- The *actual* post-audit begin-check transition preserves completion
    acknowledgement but has a closed return gate. If the native freshness
    primitive denies, this is the last returned receipt. -/
theorem late_postaudit_check_still_locks_guest_value
    (contexts : read_transition.Phase → Context)
    (before after : request_effects.RequestEffects)
    (reachable : Reachable before)
    (audited : before.progress = .CompletionAudited)
    (entered : request_effects.RequestEffects.begin_completion_check
      before .BeforeRelease = Result.ok (true, after)) :
    delta contexts before after = [] ∧
    after.completion.audit_acknowledged = true ∧
    request_effects.RequestEffects.can_return_value after = Result.ok false := by
  exact late_check_keeps_audit_without_reply contexts before after
    reachable audited entered

/-- Even a saved successful receipt must not survive an invalid extra native
    transition: the core's rejection closes the return gate without discarding
    evidence of earlier audit/provider attempts. -/
theorem invalid_extra_call_withdraws_permission_not_evidence
    (state : request_effects.RequestEffects) :
    request_effects.RequestEffects.reject state =
      Result.ok (false, {state with progress := .Halted}) ∧
    request_effects.RequestEffects.can_return_value
      {state with progress := .Halted} = Result.ok false ∧
    ({state with progress := .Halted} : request_effects.RequestEffects).completion =
      state.completion := by
  exact rejected_call_closes_return_gate state

/-- For a returned send failure, the *actual* source-owned channel consumes
    its one attempt; no `into_parts` response handoff and no callback retry
    occurs. Partial OS/TLS delivery is intentionally not called a clean
    no-send. -/
theorem returned_failed_read_send_blocks_parser_and_replay
    {W C B V M X O : Type}
    (work : dispatch.Work W (provider_io.Channel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (initial final : NativePending (W := W) (C := C) (B := B)
      (V := V) (M := M) (X := X) (O := O))
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (driver work checks)
      initial ⟨phase, false⟩ = Result.ok (report, final))
    (failed : report.stage = .Send)
    (constructed : SetupReturnsConstructed work checks bytes writer)
    (linked : SendsThroughChannel work checks bytes writer)
    (invalidCode : X)
    (invalid : writer.INVALID_TRANSITION = Result.ok invalidCode) :
    ∃ stamp before channel next error calls,
      report.current = some stamp ∧
      Issued (current_admission.Proofs.view initial.work.context) stamp ∧
      (driver work checks).send before channel =
        Result.ok (.Err error, final, next) ∧
      provider_io.Channel.submit bytes writer channel =
        Result.ok (.Err error, next) ∧
      channel.request.attempted = false ∧
      provider_io.NativeWriterEvents.Observed bytes writer
        channel.request channel.writer (.Err error)
        next.request next.writer calls ∧
      provider_io.NativeWriterEvents.projected phase
        (current_admission.Proofs.view initial.work.context) stamp calls =
        [attemptedEvent phase
          (current_admission.Proofs.view initial.work.context) stamp] ∧
      next.request.attempted = true ∧ next.ready = false ∧
      provider_io.Channel.into_parts bytes writer next =
        Result.ok (.Err invalidCode) ∧
      provider_io.Channel.submit bytes writer next =
        Result.ok (.Err invalidCode, {next with ready := false}) ∧
      provider_io.Channel.into_parts bytes writer {next with ready := false} =
        Result.ok (.Err invalidCode) := by
  exact returned_send_failure_is_spent_and_cannot_retry
    work checks bytes writer initial final phase report returned failed
    constructed linked invalidCode invalid

/-- After a returned successful send, a *response error* still has one
    acknowledged attempt and a successfully flushed captured wire; the
    upstream parser's error does not rewind/retry the channel. -/
theorem returned_response_error_has_prior_flushed_provider_request
    {W C B V M X O : Type}
    (work : dispatch.Work W (provider_io.Channel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (initial final : NativePending (W := W) (C := C) (B := B)
      (V := V) (M := M) (X := X) (O := O))
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (reachable : Reachable initial.effects)
    (returned : provider_exchange.exchange (driver work checks)
      initial ⟨phase, false⟩ = Result.ok (report, final))
    (responseFailed : report.stage = .Response)
    (constructed : SetupReturnsConstructed work checks bytes writer)
    (linked : SendsThroughChannel work checks bytes writer) :
    ∃ events,
      TraceSteps (fun _ => current_admission.Proofs.view initial.work.context)
        initial.effects final.effects events ∧
      confinement.Proofs.SoundTrace events ∧
      BoundTrace (current_admission.Proofs.view initial.work.context).binding events ∧
      final.work.context = initial.work.context ∧
      ∃ stamp before receiveBefore channel next received,
        report.current = some stamp ∧ report.result = received ∧
        Issued (current_admission.Proofs.view initial.work.context) stamp ∧
        (driver work checks).send before channel =
          Result.ok (.Ok (), receiveBefore, next) ∧
        (driver work checks).receive receiveBefore next =
          Result.ok (received, final) ∧
        next.ready = true ∧
        provider_io.Channel.into_parts bytes writer next =
          Result.ok (.Ok (next.writer, next.request, next.metadata)) ∧
        channel.request.attempted = false ∧ next.request.attempted = true ∧
        next.request.body = channel.request.body ∧
        next.metadata = channel.metadata ∧
        ∃ wire written,
          bytes.bytes channel.request.body = Result.ok wire ∧
          writer.write_all channel.writer wire = Result.ok (.Ok (), written) ∧
          writer.flush written = Result.ok (.Ok (), next.writer) := by
  exact returned_postsend_read_has_exact_flushed_wire work checks
    bytes writer initial final phase report reachable returned
    (Or.inl responseFailed) constructed linked

end aivm_secrets_garrett_core.nr23.Failures
