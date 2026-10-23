import GarrettProductionAssurance
import GarrettApproval
import GarrettDispatch

/-!
# OUT-4: the exact-write gate in front of the production controller

Source: `rust/crates/aivm-secrets-garrett-core/src/write_gate.rs`, extracted by
Aeneas. `custody/manifest_session.rs` computes the approval decision with the
extracted `approval::consume` (directly, or through the host approval state,
which calls the same function under its lock) and then calls
`write_gate::run_approved(decision, pending)`. That is the session's only
invocation of the production controller `read_transition::run_current`.

Proved here:

* `run_approved_ran`: the controller ran only if the decision was `Allowed`,
  and its result is exactly `run_current`'s;
* `run_approved_refusals`: a `Denied` or `Required` decision returns without
  invoking the controller, so no dispatch callback (and no provider attempt)
  can happen;
* `approve_mode_write_ran_consumed_its_approval`: in `approve` mode, a write
  whose controller ran had a matching, unexpired approval, and that approval
  is consumed (cannot be reused: `consumed_approval_cannot_be_reused`);
* `deny_mode_write_never_runs`: in `deny` mode a write never reaches the
  controller;
* `production_write_has_approval_and_authorized_attempts`: for the
  production request type, a returned request that passed the gate has an
  `Allowed` decision **and** every accounted provider attempt is currently
  authorized, audit-acknowledged and bound to its admission context
  (`production_denial_attempts_are_authorized_and_bound`, which holds for any
  operation, read or write).

Still assumed: that the native session feeds the gate the decision it
computed for this request's digest (`APPROVAL-RUST-01`), the host approval
store's locking, and the native premises of the production theorem
(`NATIVE-SINK-01`, `NATIVE-GLUE-01`).
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs

namespace aivm_secrets_garrett_core.write_gate.Proofs

open aivm_secrets_garrett_core.approval
open aivm_secrets_garrett_core.approval.Proofs

variable {R F E O X : Type}

/-- The controller ran only after an `Allowed` decision, with exactly
    `run_current`'s result. -/
theorem run_approved_ran (inst : read_transition.Request R F E O X) (decision : Decision)
    (adapter : R) (result : core.result.Result O X)
    (ran : write_gate.run_approved inst decision adapter = Result.ok (.Ran result)) :
    decision = .Allowed ∧ read_transition.run_current inst adapter = Result.ok result := by
  cases decision with
  | Allowed =>
    refine ⟨rfl, ?_⟩
    unfold write_gate.run_approved at ran
    cases h : read_transition.run_current inst adapter using Result.cases with
    | ret value => rw [h] at ran; simp at ran; rw [ran]
    | vis effect continuation => rw [h] at ran; simp at ran
    | div => rw [h] at ran; simp at ran
  | Denied => simp [write_gate.run_approved] at ran
  | Required => simp [write_gate.run_approved] at ran

/-- A refused decision returns at once: the controller (and with it every
    dispatch callback) is never invoked. -/
theorem run_approved_refusals (inst : read_transition.Request R F E O X) (adapter : R) :
    write_gate.run_approved inst .Denied adapter = Result.ok .Denied ∧
      write_gate.run_approved inst .Required adapter = Result.ok .Required := by
  exact ⟨rfl, rfl⟩

/-- In `approve` mode, a write whose controller ran consumed a matching,
    unexpired approval; the slot left behind is empty. -/
theorem approve_mode_write_ran_consumed_its_approval (inst : read_transition.Request R F E O X)
    (adapter : R) (wanted : alloc.vec.Vec U8) (now : I64) (prior remaining : Option Approval)
    (decided : consume .Approve true wanted now prior = Result.ok (decision, remaining))
    (result : core.result.Result O X)
    (ran : write_gate.run_approved inst decision adapter = Result.ok (.Ran result)) :
    Eligible prior wanted now ∧ remaining = none ∧
      consume .Approve true wanted now remaining = Result.ok (.Required, none) := by
  obtain ⟨allowed, _⟩ := run_approved_ran inst decision adapter result ran
  subst allowed
  obtain ⟨eligible, spent⟩ := admitted_approval_is_consumed wanted now prior remaining decided
  exact ⟨eligible, spent, consumed_approval_cannot_be_reused wanted now now prior remaining decided⟩

/-- In `deny` mode a write never reaches the controller. -/
theorem deny_mode_write_never_runs (inst : read_transition.Request R F E O X) (adapter : R)
    (wanted : alloc.vec.Vec U8) (now : I64) (prior remaining : Option Approval)
    (decided : consume .Deny true wanted now prior = Result.ok (decision, remaining)) :
    write_gate.run_approved inst decision adapter = Result.ok .Denied := by
  rw [deny_mode_refuses_write] at decided
  have same : decision = .Denied := by
    have := Result.ok_injective decided
    simp only [Prod.mk.injEq] at this
    exact this.1.symm
  subst same
  rfl

open aivm_secrets_garrett_core.production.Assurance
open aivm_secrets_garrett_core.request_context
open aivm_secrets_garrett_core.nr23.Effects
open aivm_secrets_garrett_core.nr23.ExactSinks
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement

/-- **A gated production request, read or write.** If the native session's
    `run_approved` returned a controller result for the production request
    type, the approval decision was `Allowed`, and every accounted provider
    attempt is currently authorized (which includes the session's write
    mode), audit-acknowledged and bound to the admission context passed to
    `ScopedRequest::new`; the attempt count equals the trace's source sends,
    so nothing is retried behind the trace. -/
theorem production_write_has_approval_and_authorized_attempts
    {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (decision : Decision) (out : core.result.Result (completion.Completed O) X)
    (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (gated : write_gate.run_approved
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) decision pending = Result.ok (.Ran out))
    (coverage : ExactNativeSinkCoverage (scopedOps work factory routes)
      (fun pending => pending.context) pending out attempts) :
    decision = .Allowed ∧
      (∀ attempt, attempt ∈ attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate = (current_admission.Proofs.view context).binding) ∧
      ∃ after events,
        read_transition.Proofs.RequestRun
          (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
            (scopedOps work factory routes)) pending out after ∧
        SoundTrace (withOutcome events out) ∧
        attempts.length = (sourceSends (withOutcome events out)).length := by
  obtain ⟨allowed, returned⟩ := run_approved_ran _ decision pending out gated
  obtain ⟨after, events, run, _, sound, _, _, authorized, count⟩ :=
    production_denial_attempts_are_authorized_and_bound work factory routes context native state
      pending out attempts created returned coverage
  exact ⟨allowed, authorized, after, events, run, sound, count⟩

theorem bind_ok_inv {A B : Type} {first : Result A} {next : A → Result B} {out : B}
    (h : (first >>= next) = Result.ok out) :
    ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp_all

/-- **A keyed write reserves before egress.** If the extracted dispatch
    returns success for a keyed (coordinated) write, then admission audit,
    configuration, the late check and the coordinator **reservation** all
    succeeded before the exchange, and the coordinator **finish** succeeded
    after it. (A failed finish is reported as `OUTCOME_UNKNOWN`, never
    retried: `dispatch.Proofs.coordinator_finish_refusal`.) -/
theorem keyed_success_reserved_and_finished {W C O X : Type} (ops : dispatch.Work W C O X)
    (pending : dispatch.Pending W C O X) (prepared : read_transition.Prepared)
    (value : O) (final : dispatch.Pending W C O X)
    (returned : dispatch.run ops pending prepared true = Result.ok (.Ok value, final)) :
    ∃ audited pendingA configured checked reserved exchanged,
      dispatch.audit ops pending prepared = Result.ok (.Ok audited, pendingA) ∧
      ops.configure pendingA.work true = Result.ok (.Ok (), configured) ∧
      ops.check configured = Result.ok (.Ok (), checked) ∧
      ops.reserve checked = Result.ok (.Ok (), reserved) ∧
      dispatch.exchange ops { pendingA with work := reserved } audited =
        Result.ok (.Ok value, exchanged) ∧
      dispatch.finish ops exchanged true = Result.ok (.Ok (), final) := by
  unfold dispatch.run at returned
  obtain ⟨⟨r, pendingA⟩, auditCall, after⟩ := bind_ok_inv returned
  cases r with
  | Err e => simp at after
  | Ok audited =>
    obtain ⟨⟨r1, configured⟩, configureCall, after⟩ := bind_ok_inv after
    cases r1 with
    | Err e => simp at after
    | Ok u =>
      obtain ⟨⟨r2, checked⟩, checkCall, after⟩ := bind_ok_inv after
      cases r2 with
      | Err e => simp at after
      | Ok u2 =>
        obtain ⟨⟨t2, reserved⟩, reserveCall, after⟩ := bind_ok_inv after
        simp only [↓reduceIte] at reserveCall
        obtain ⟨⟨reservedResult, t3⟩, reserveOps, reserveEq⟩ := bind_ok_inv reserveCall
        simp at reserveEq
        obtain ⟨hT2, hRes⟩ := reserveEq
        subst hT2 hRes
        cases reservedResult with
        | Err e => simp at after
        | Ok u3 =>
          obtain ⟨⟨r3, exchanged⟩, exchangeCall, after⟩ := bind_ok_inv after
          cases r3 with
          | Err e => simp at after
          | Ok v =>
            obtain ⟨⟨r4, finished⟩, finishCall, after⟩ := bind_ok_inv after
            cases r4 with
            | Err e => simp at after
            | Ok u4 =>
              simp at after
              obtain ⟨hv, hf⟩ := after
              subst hv hf
              cases u; cases u2; cases u3; cases u4
              exact ⟨audited, pendingA, configured, checked, t3, exchanged, auditCall,
                configureCall, checkCall, reserveOps, exchangeCall, finishCall⟩

end aivm_secrets_garrett_core.write_gate.Proofs
