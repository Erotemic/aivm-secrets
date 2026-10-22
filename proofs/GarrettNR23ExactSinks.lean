import GarrettNR23Assurance

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-3 strengthened native effect ledger. The earlier `AllNativeAttemptsAccounted`
asserted only membership: two native write attempts could cite the SAME
source event. This module adds a *sequence-preserving, multiplicity-sensitive*
contract. It is intentionally a native I/O obligation, not something derived
from the source event list itself.

The actual high-level channel writer is extracted; whether the deployed
binary has any other TLS/socket/diagnostic/drop sink is still external.
-/
namespace aivm_secrets_garrett_core.nr23.ExactSinks

open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.nr23.Effects
open aivm_secrets_garrett_core.request_adapter.TraceRefinement

/-- The projection is intentionally an ordered *list*, not a set. Audits,
    denials and result disclosures are not credential-bearing sends. -/
def isSend : Event → Bool
  | .providerSend _ _ _ => true
  | _ => false

def sourceSends (events : List Event) : List Event := events.filter isSend

def nativeSends (attempts : List NativeAttempt) : List Event :=
  attempts.map (fun a => .providerSend a.phase a.gate a.auditAck)

/-- This is a strictly stronger runtime correspondence requirement than
    membership accounting: native send observations must match every modeled
    source send in order and multiplicity. Distinct real sends cannot be
    justified by repeatedly citing one source event. -/
def ExactNativeSinkSequence (attempts : List NativeAttempt)
    (events : List Event) : Prop :=
  nativeSends attempts = sourceSends events

theorem exact_sequence_implies_event_coverage
    (attempts : List NativeAttempt) (events : List Event)
    (exact : ExactNativeSinkSequence attempts events) :
    AllNativeAttemptsAccounted attempts events := by
  intro attempt member
  have mapped : Event.providerSend attempt.phase attempt.gate attempt.auditAck ∈
      nativeSends attempts := by
    exact List.mem_map.mpr ⟨attempt, member, rfl⟩
  rw [exact] at mapped
  exact (List.mem_filter.mp mapped).1

theorem exact_sequence_has_no_extra_attempt_count
    (attempts : List NativeAttempt) (events : List Event)
    (exact : ExactNativeSinkSequence attempts events) :
    attempts.length = (sourceSends events).length := by
  have count := congrArg List.length exact
  simpa [nativeSends] using count

/-- A source return with zero modeled credential-bearing attempts cannot
    justify ANY native attempt under exact sink coverage, including duplicate
    or out-of-order attempts. This deliberately does not derive that the
    native process actually satisfies `ExactNativeSinkSequence`. -/
theorem no_modeled_send_has_no_native_attempt
    (attempts : List NativeAttempt) (events : List Event)
    (exact : ExactNativeSinkSequence attempts events)
    (noSend : sourceSends events = []) : attempts = [] := by
  cases attempts with
  | nil => rfl
  | cons a rest =>
      have impossible : nativeSends (a :: rest) = [] := by
        exact exact.trans noSend
      simp [nativeSends] at impossible

theorem exact_sequence_preserves_audit_and_binding
    (attempts : List NativeAttempt) (events : List Event)
    (binding : Binding) (sound : SoundTrace events)
    (bound : BoundTrace binding events)
    (exact : ExactNativeSinkSequence attempts events) :
    (∀ attempt, attempt ∈ attempts →
      attempt.gate.accepted ∧ attempt.auditAck = true ∧
      gateBinding attempt.gate = binding) ∧
    attempts.length = (sourceSends events).length := by
  exact ⟨accounted_native_attempts_have_current_bound_audit
    attempts events binding sound bound
    (exact_sequence_implies_event_coverage attempts events exact),
    exact_sequence_has_no_extra_attempt_count attempts events exact⟩

private abbrev boundAdapter {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H) :=
  request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error ops

/-- A native-process proof obligation covering *all* credential-bearing
    attempts (including non-returning callbacks once they have an externally
    specified observation). It is not automatically inhabited by any Lean
    trace; the live implementation must supply the equality. -/
def ExactNativeSinkCoverage {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (capture : W → current_admission.Context)
    (initial : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (attempts : List NativeAttempt) : Prop :=
  ∀ after events,
    read_transition.Proofs.RequestRun (boundAdapter ops) initial out after →
    TraceSteps (fun _ => current_admission.Proofs.view (capture initial.work))
      initial.effects after.adapter.effects events →
    ExactNativeSinkSequence attempts (withOutcome events out)

/-- A STRICTER top-level mediation result than `NativeSinkCoverage`:
    authorization/audit/binding is derived from the returned source run,
    while ordered one-for-one native/source accounting is separately required.
    In particular, a second native write cannot be attributed to one
    source-owned `providerSend` event. -/
theorem returned_request_has_exactly_accounted_authorized_native_sends
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (primitive : dispatch.Work D H F X)
    (checks : current_admission.Checks C X)
    (capture : W → current_admission.Context)
    (context : NativeContext ops primitive checks capture)
    (initial : W)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (attempts : List NativeAttempt)
    (created : request_adapter.Pending.new ops initial = Result.ok pending)
    (returned : read_transition.run_current (boundAdapter ops) pending =
      Result.ok out)
    (coverage : ExactNativeSinkCoverage ops capture pending out attempts) :
    ∃ after events,
      read_transition.Proofs.RequestRun (boundAdapter ops) pending out after ∧
      TraceSteps (fun _ => current_admission.Proofs.view (capture pending.work))
        pending.effects after.adapter.effects events ∧
      SoundTrace (withOutcome events out) ∧
      BoundTrace (current_admission.Proofs.view (capture pending.work)).binding
        (withOutcome events out) ∧
      ExactNativeSinkSequence attempts (withOutcome events out) ∧
      (∀ attempt, attempt ∈ attempts →
        attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate =
          (current_admission.Proofs.view (capture pending.work)).binding) ∧
      attempts.length = (sourceSends (withOutcome events out)).length := by
  obtain ⟨after, events, ran, _, trace, _, sound, bound, _⟩ :=
    aivm_secrets_garrett_core.nr23.Request.all_returned_request_events_are_authorized_and_bound
      ops primitive checks capture context initial pending out created returned
  have exact := coverage after events ran trace
  have secured := exact_sequence_preserves_audit_and_binding attempts
    (withOutcome events out)
    (current_admission.Proofs.view (capture pending.work)).binding
    sound bound exact
  exact ⟨after, events, ran, trace, sound, bound, exact,
    secured.1, secured.2⟩

/-- Multiplicity-sensitive coverage implies the earlier event-membership
    contract, so all previous NR-2/NR-3 top-level proofs remain reusable. -/
theorem strict_coverage_refines_original
    {W F E O X D C V H : Type}
    (ops : request_adapter.Work W F E O X
      (current_admission.Bound D C H F X) V H)
    (capture : W → current_admission.Context)
    (pending : request_adapter.Pending W F E O X
      (current_admission.Bound D C H F X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (attempts : List NativeAttempt)
    (exact : ExactNativeSinkCoverage ops capture pending out attempts) :
    aivm_secrets_garrett_core.nr23.Assurance.NativeSinkCoverage
      ops capture pending out attempts := by
  intro after events ran trace
  exact exact_sequence_implies_event_coverage attempts
    (withOutcome events out) (exact after events ran trace)

end aivm_secrets_garrett_core.nr23.ExactSinks
