import GarrettProtocol
import GarrettManifest
import GarrettDisclosure

open Aeneas Aeneas.Std
set_option maxHeartbeats 1000000

/-!
W4: conditional *source-controller* effects, not concrete socket traces.

`Gate.accepted` calls the Aeneas extraction of the Rust `manifest::authorize`.
`disclose` calls the extraction of `disclosure::project`.  The finite effect
interpreter below is a Lean specification of the W3 boundary, NOT extracted
from `custody/manifest_session.rs` or `tls.rs`. W6 must establish refinement
from those concrete interpreters to this trace model. In particular, the
adapter-supplied audit and provider acknowledgements are not verified here.

The event fields are internal proof witnesses. They are not an audit format and
must not be serialized to a guest. Source-level success does not prove that a
real HTTP adapter sends only the designated bytes or has no extra output path.
-/

namespace aivm_secrets_garrett_core.confinement.Proofs

open aivm_secrets_garrett_core.credential_use

/-- Snapshot used at one dispatch linearization point, not an admission made
    earlier in the request. The current grant may differ between phases. -/
structure Gate where
  claims : UseClaims
  grant : UseGrant
  requested : alloc.vec.Vec U8
  selected : alloc.vec.Vec U8
  write : Bool
  writesAllowed : Bool
  now : I64
  elapsed : I64

/-- Equality to the actual extracted Rust decision, not an arbitrary
    boolean supplied by the guest or the trace interpreter. -/
def Gate.accepted (g : Gate) : Prop :=
  aivm_secrets_garrett_core.manifest.authorize
    g.claims g.grant g.requested g.selected g.write g.writesAllowed
    g.now g.elapsed = Result.ok (.Ok ())

/-- An accepted dispatch implies freshness, exact operation selection, and
    host write permission as specified by the extracted Rust guard. -/
theorem accepted_implies_admission (g : Gate) (accepted : g.accepted) :
    aivm_secrets_garrett_core.manifest.Proofs.Admission
      g.claims g.grant g.requested g.selected g.write g.writesAllowed
      g.now g.elapsed := by
  obtain ⟨out, returned, property⟩ :=
    aivm_secrets_garrett_core.Proofs.returned_of_spec
      (aivm_secrets_garrett_core.manifest.Proofs.authorize_contract
        g.claims g.grant g.requested g.selected g.write g.writesAllowed
        g.now g.elapsed)
  have eq : Result.ok out = Result.ok (core.result.Result.Ok ()) := by
    rw [← returned]
    exact accepted
  cases out with
  | Err error => simp at eq
  | Ok resultUnit =>
    cases resultUnit
    exact property.mp rfl

/-- Revocation at the *new* dispatch check blocks the effect even if a
    previous check passed against an earlier grant snapshot. -/
theorem inactive_cannot_be_accepted (g : Gate)
    (inactive : g.grant.active = false) : ¬ g.accepted := by
  intro accepted
  have current := (accepted_implies_admission g accepted).1
  have active : g.grant.active = true := current.1
  simp [inactive] at active

inductive Phase where
  | preflight
  | final
  | completed

/-- Internal events preserve the snapshots that justify provider calls and
    projected replies. These witnesses must never be sent as public bytes. -/
inductive Event where
  | auditAttempt (phase : Phase)
  | providerSend (phase : Phase) (gate : Gate) (auditOK : Bool)
  | guestDenied
  | guestReply (raw : aivm_secrets_garrett_core.disclosure.Json)
      (schema : aivm_secrets_garrett_core.disclosure.Projection)
      (fuel budget : Usize)
      (selected : aivm_secrets_garrett_core.disclosure.Selection)

/-- A provider effect is backed by the extracted authorization decision.
    A public reply is backed by the extracted, schema-selected projection.
    Neither rule assumes the emitted event was already authorized. -/
def SoundEvent : Event → Prop
  | .providerSend _ gate auditOK => gate.accepted ∧ auditOK = true
  | .guestReply raw schema fuel budget selected =>
      aivm_secrets_garrett_core.disclosure.project raw schema fuel budget =
        Result.ok (.Ok selected)
  | _ => True

def SoundTrace (trace : List Event) : Prop :=
  ∀ event, event ∈ trace → SoundEvent event

/-- Abstract W3 dispatch phase: denied guard, refused durable audit, or
    audited credentialed provider call. `auditOK` is an *adapter result*;
    W6 must verify the actual durable-acknowledgement contract. -/
noncomputable def dispatch (phase : Phase) (gate : Gate) (auditOK : Bool) :
    List Event := by
  classical
  exact if gate.accepted then
    if auditOK then [.auditAttempt phase, .providerSend phase gate auditOK]
    else [.auditAttempt phase, .guestDenied]
  else [.guestDenied]

private theorem sound_append (left right : List Event)
    (hleft : SoundTrace left) (hright : SoundTrace right) :
    SoundTrace (left ++ right) := by
  intro event member
  rcases List.mem_append.mp member with inLeft | inRight
  · exact hleft event inLeft
  · exact hright event inRight

private theorem sound_denial : SoundTrace [Event.guestDenied] := by
  intro event member
  simp at member
  subst event
  trivial

private theorem sound_audit : SoundTrace [Event.auditAttempt .completed] := by
  intro event member
  simp at member
  subst event
  trivial

/-- TRACE-01 for one *modeled* phase; the predicate is checked on each actual
    emitted internal effect, not assumed about the whole trace. -/
theorem dispatch_sound (phase : Phase) (gate : Gate) (auditOK : Bool) :
    SoundTrace (dispatch phase gate auditOK) := by
  classical
  intro event member
  by_cases accepted : gate.accepted
  · cases auditOK with
    | false =>
      simp [dispatch, accepted] at member
      rcases member with rfl | rfl
      · trivial
      · trivial
    | true =>
      simp [dispatch, accepted] at member
      rcases member with rfl | rfl
      · trivial
      · exact ⟨accepted, rfl⟩
  · simp [dispatch, accepted] at member
    subst event
    trivial

/-- SINK-01 at the abstract provider-send point, sourced from the extracted
    Rust guard; audit acknowledgement is an explicitly named adapter result. -/
theorem provider_requires_admission (phase : Phase) (gate : Gate) (auditOK : Bool)
    (sent : Event.providerSend phase gate auditOK ∈ dispatch phase gate auditOK) :
    aivm_secrets_garrett_core.manifest.Proofs.Admission
      gate.claims gate.grant gate.requested gate.selected gate.write
      gate.writesAllowed gate.now gate.elapsed ∧ auditOK = true := by
  have sound : gate.accepted ∧ auditOK = true :=
    dispatch_sound phase gate auditOK (Event.providerSend phase gate auditOK) sent
  have accepted : gate.accepted := sound.1
  have ack : auditOK = true := sound.2
  exact ⟨accepted_implies_admission gate accepted, ack⟩

/-- Positive witness: an admitted operation with acknowledged audit really
    reaches a modeled provider send (the model is not deny-only). -/
theorem accepted_with_audit_dispatches (phase : Phase) (gate : Gate)
    (accepted : gate.accepted) :
    Event.providerSend phase gate true ∈ dispatch phase gate true := by
  classical
  simp [dispatch, accepted]

theorem rejected_has_no_provider (phase : Phase) (gate : Gate) (auditOK : Bool)
    (rejected : ¬ gate.accepted) :
    dispatch phase gate auditOK = [Event.guestDenied] := by
  classical
  simp [dispatch, rejected]

theorem audit_refusal_stops_dispatch (phase : Phase) (gate : Gate)
    (accepted : gate.accepted) :
    dispatch phase gate false = [.auditAttempt phase, .guestDenied] := by
  classical
  simp [dispatch, accepted]

theorem revoked_at_linearization_stops_dispatch (gate : Gate)
    (inactive : gate.grant.active = false) :
    dispatch .final gate true = [.guestDenied] := by
  exact rejected_has_no_provider .final gate true
    (inactive_cannot_be_accepted gate inactive)

/-- The only modeled public success event is constructed from the exact
    source-level disclosure projection. Failure (including a modeled panic)
    yields a denial, not raw provider data. -/
noncomputable def disclose
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) : List Event := by
  classical
  exact if h : ∃ selected : aivm_secrets_garrett_core.disclosure.Selection,
      aivm_secrets_garrett_core.disclosure.project raw schema fuel budget =
        Result.ok (.Ok selected)
    then [.guestReply raw schema fuel budget (Classical.choose h)]
    else [.guestDenied]

theorem disclose_sound
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) : SoundTrace (disclose raw schema fuel budget) := by
  classical
  intro event member
  by_cases success : ∃ selected : aivm_secrets_garrett_core.disclosure.Selection,
      aivm_secrets_garrett_core.disclosure.project raw schema fuel budget =
        Result.ok (.Ok selected)
  · simp [disclose, success] at member
    subst event
    exact Classical.choose_spec success
  · simp [disclose, success] at member
    subst event
    trivial

/-- A guest reply cannot be introduced by the trace interpreter without an
    actual successful extracted Rust projection. -/
theorem public_reply_origin
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize)
    (selected : aivm_secrets_garrett_core.disclosure.Selection)
    (observed : Event.guestReply raw schema fuel budget selected ∈
      disclose raw schema fuel budget) :
    aivm_secrets_garrett_core.disclosure.project raw schema fuel budget =
      Result.ok (.Ok selected) := by
  exact disclose_sound raw schema fuel budget _ observed

/-- A checked preflight fact is accepted by the extracted Rust manifest
    parameter rule, not by an unchecked fact supplied by the client. -/
structure CheckedFact where
  rule : aivm_secrets_garrett_core.manifest.Rule
  value : aivm_secrets_garrett_core.manifest.Scalar
  witness : Usize

def CheckedFact.accepted (fact : CheckedFact) : Prop :=
  aivm_secrets_garrett_core.manifest.parameter fact.rule fact.value fact.witness =
    Result.ok (.Ok ())

theorem accepted_fact_is_allowed (fact : CheckedFact) (accepted : fact.accepted) :
    aivm_secrets_garrett_core.manifest.Proofs.Allowed
      fact.rule fact.value fact.witness := by
  obtain ⟨out, returned, property⟩ :=
    aivm_secrets_garrett_core.Proofs.returned_of_spec
      (aivm_secrets_garrett_core.manifest.Proofs.parameter_contract
        fact.rule fact.value fact.witness)
  have eq : Result.ok out = Result.ok (core.result.Result.Ok ()) := by
    rw [← returned]
    exact accepted
  cases out with
  | Err error => simp at eq
  | Ok resultUnit =>
    cases resultUnit
    exact property.mp rfl

/-- The modeled two-phase request uses a fresh gate for each credentialed
    send. False preflight/provider acknowledgement aborts the continuation.
    No-preflight and checked-facts-only paths require W6 correspondence. -/
noncomputable def afterPreflight (pre : Gate) (auditOK providerOK : Bool)
    (continuation : List Event) : List Event := by
  classical
  let phaseEvents := dispatch .preflight pre auditOK
  exact if Event.providerSend .preflight pre auditOK ∈ phaseEvents then
    if providerOK then phaseEvents ++ continuation
    else phaseEvents ++ [.guestDenied]
  else phaseEvents

theorem denied_at_entry_stops (pre : Gate)
    (auditOK providerOK : Bool) (continuation : List Event)
    (denied : ¬ pre.accepted) :
    afterPreflight pre auditOK providerOK continuation = [.guestDenied] := by
  classical
  simp [afterPreflight, dispatch, denied]

/-- A failed preflight cannot be used as evidence authorizing a final send. -/
theorem failed_preflight_stops (pre : Gate) (accepted : pre.accepted)
    (continuation : List Event) :
    afterPreflight pre true false continuation =
      [.auditAttempt .preflight, .providerSend .preflight pre true, .guestDenied] := by
  classical
  simp [afterPreflight, dispatch, accepted]

/-- Audit failure is earlier than the preflight provider side effect. -/
theorem refused_preflight_audit_stops (pre : Gate) (accepted : pre.accepted)
    (providerOK : Bool) (continuation : List Event) :
    afterPreflight pre false providerOK continuation =
      [.auditAttempt .preflight, .guestDenied] := by
  classical
  simp [afterPreflight, dispatch, accepted]

/-- Fresh authorization and successful provider completion are necessary
    before projecting a guest response in this modeled final phase. -/
noncomputable def afterFinal
    (final : Gate) (auditOK providerOK completedAuditOK : Bool)
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) : List Event := by
  classical
  let phaseEvents := dispatch .final final auditOK
  exact if Event.providerSend .final final auditOK ∈ phaseEvents then
    if providerOK then
      if completedAuditOK then
        phaseEvents ++ ([.auditAttempt .completed] ++ disclose raw schema fuel budget)
      else phaseEvents ++ ([.auditAttempt .completed] ++ [.guestDenied])
    else phaseEvents ++ [.guestDenied]
  else phaseEvents

theorem final_provider_failure_stops_release (final : Gate)
    (accepted : final.accepted)
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) :
    afterFinal final true false true raw schema fuel budget =
      [.auditAttempt .final, .providerSend .final final true, .guestDenied] := by
  classical
  simp [afterFinal, dispatch, accepted]

theorem completion_audit_failure_stops_release (final : Gate)
    (accepted : final.accepted)
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) :
    afterFinal final true true false raw schema fuel budget =
      [.auditAttempt .final, .providerSend .final final true,
        .auditAttempt .completed, .guestDenied] := by
  classical
  simp [afterFinal, dispatch, accepted]

theorem revoked_after_preflight_stops_final (final : Gate)
    (revoked : final.grant.active = false)
    (auditOK providerOK completedAuditOK : Bool)
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) :
    afterFinal final auditOK providerOK completedAuditOK raw schema fuel budget =
      [.guestDenied] := by
  classical
  have denied := inactive_cannot_be_accepted final revoked
  simp [afterFinal, dispatch, denied]

theorem after_final_sound
    (final : Gate) (auditOK providerOK completedAuditOK : Bool)
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) :
    SoundTrace (afterFinal final auditOK providerOK completedAuditOK raw schema fuel budget) := by
  classical
  unfold afterFinal
  dsimp
  by_cases dispatched : Event.providerSend .final final auditOK ∈ dispatch .final final auditOK
  · simp only [dispatched, ↓reduceIte]
    cases providerOK with
    | false => exact sound_append _ _ (dispatch_sound .final final auditOK) sound_denial
    | true =>
      cases completedAuditOK with
      | false =>
        exact sound_append _ _ (dispatch_sound .final final auditOK)
          (sound_append _ _ sound_audit sound_denial)
      | true =>
        exact sound_append _ _ (dispatch_sound .final final auditOK)
          (sound_append _ _ sound_audit (disclose_sound raw schema fuel budget))
  · simpa only [dispatched, ↓reduceIte] using dispatch_sound .final final auditOK

/-- TRACE-01 for the abstract W3 preflight+final trace. It covers denied
    admission, failed audit, failed preflight, provider failure, revocation
    at either dispatch check, and schema-selected reply. It does NOT prove
    that native concrete TLS/file I/O refines this abstract construction. -/
noncomputable def requestTrace
    (pre final : Gate) (preAudit finalAudit preflightOK finalProviderOK completedAuditOK : Bool)
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) : List Event :=
  afterPreflight pre preAudit preflightOK
    (afterFinal final finalAudit finalProviderOK completedAuditOK raw schema fuel budget)

theorem request_trace_sound
    (pre final : Gate) (preAudit finalAudit preflightOK finalProviderOK completedAuditOK : Bool)
    (raw : aivm_secrets_garrett_core.disclosure.Json)
    (schema : aivm_secrets_garrett_core.disclosure.Projection)
    (fuel budget : Usize) :
    SoundTrace (requestTrace pre final preAudit finalAudit preflightOK finalProviderOK
      completedAuditOK raw schema fuel budget) := by
  classical
  unfold requestTrace afterPreflight
  dsimp
  by_cases sent : Event.providerSend .preflight pre preAudit ∈ dispatch .preflight pre preAudit
  · simp only [sent, ↓reduceIte]
    cases preflightOK with
    | false => exact sound_append _ _ (dispatch_sound .preflight pre preAudit) sound_denial
    | true => exact sound_append _ _ (dispatch_sound .preflight pre preAudit) (after_final_sound final finalAudit finalProviderOK completedAuditOK raw schema fuel budget)
  · simpa only [sent, ↓reduceIte] using dispatch_sound .preflight pre preAudit


end aivm_secrets_garrett_core.confinement.Proofs
