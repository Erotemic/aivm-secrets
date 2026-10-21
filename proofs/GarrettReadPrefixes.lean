import GarrettReadPaths

open Aeneas Aeneas.Std
set_option maxHeartbeats 1000000

/-!
Scoped W3/W4/W5 *abstract* read-history extension, not a native trace proof.
The existing extracted Rust admission guard appears in `Gate.accepted` and
its source-linked theorem. The extra `providerReached` bit is an UNPROVED
adapter-supplied fact: it must be matched to actual provider I/O by W6.
Unlike the original `dispatch` model, an admitted and audited attempt may be
stopped during TLS setup or fresh-authority checking without a provider send.
Arbitrary finite sequences of these attempts remain SoundTrace, and any
modeled send has the extracted admission witness. The final theorem composes
conditional W5 equivalence over arbitrary sequential *read* histories.
-/
namespace aivm_secrets_garrett_core.confinement.ReadPrefixes

open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.confinement.W5
open aivm_secrets_garrett_core.confinement.ReadPaths

private noncomputable instance (gate : Gate) : Decidable gate.accepted :=
  Classical.propDecidable _

structure Attempt where
  phase : Phase
  gate : Gate
  auditOK : Bool
  providerReached : Bool

/-- Both the durable audit acknowledgement and a later provider-reached
    decision are explicit adapter assumptions. No admitted send is inferred
    from the mere presence of an audit record. -/
noncomputable def attemptTrace (a : Attempt) : List Event :=
  if a.gate.accepted then
    if a.auditOK then
      if a.providerReached then
        [.auditAttempt a.phase, .providerSend a.phase a.gate true]
      else [.auditAttempt a.phase, .guestDenied]
    else [.auditAttempt a.phase, .guestDenied]
  else [.guestDenied]

/-- No provider event in an admitted-but-unsent modeled phase. -/
theorem blocked_has_no_provider (a : Attempt)
    (blocked : a.providerReached = false) (phase : Phase)
    (gate : Gate) (ack : Bool) :
    Event.providerSend phase gate ack ∉ attemptTrace a := by
  intro present
  by_cases accepted : a.gate.accepted
  · cases audited : a.auditOK <;>
      simp [attemptTrace, accepted, audited, blocked] at present
  · simp [attemptTrace, accepted] at present

/-- Every modeled provider send is backed by the actual extracted Rust
    authorization predicate and acknowledged audit. -/
theorem attempt_sound (a : Attempt) : SoundTrace (attemptTrace a) := by
  intro event member
  by_cases admitted : a.gate.accepted
  · cases audited : a.auditOK with
    | false =>
      simp [attemptTrace, admitted, audited] at member
      rcases member with rfl | rfl
      · trivial
      · trivial
    | true =>
      cases reached : a.providerReached with
      | false =>
        simp [attemptTrace, admitted, audited, reached] at member
        rcases member with rfl | rfl
        · trivial
        · trivial
      | true =>
        simp [attemptTrace, admitted, audited, reached] at member
        rcases member with rfl | rfl
        · trivial
        · exact ⟨admitted, rfl⟩
  · simp [attemptTrace, admitted] at member
    subst event
    trivial

theorem attempt_send_requires_admission (a : Attempt) (phase : Phase)
    (gate : Gate) (ack : Bool)
    (sent : Event.providerSend phase gate ack ∈ attemptTrace a) :
    aivm_secrets_garrett_core.manifest.Proofs.Admission
      gate.claims gate.grant gate.requested gate.selected gate.write
      gate.writesAllowed gate.now gate.elapsed ∧ ack = true := by
  have witness : gate.accepted ∧ ack = true := attempt_sound a _ sent
  exact ⟨accepted_implies_admission gate witness.1, witness.2⟩

/-- Source-level admission soundness composes over arbitrarily many abstract
    phases. The proof is independent of a test-selected maximum history size. -/
noncomputable def attemptHistory (attempts : List Attempt) : List Event :=
  attempts.flatMap attemptTrace

theorem history_sound (attempts : List Attempt) :
    SoundTrace (attemptHistory attempts) := by
  induction attempts with
  | nil =>
    intro event member
    simp [attemptHistory] at member
  | cons head tail ih =>
    intro event member
    change event ∈ attemptTrace head ++ attemptHistory tail at member
    rcases List.mem_append.mp member with first | rest
    · exact attempt_sound head event first
    · exact ih event rest

/-- Each component of a sequential read history has the same host-selected
    shape and agrees on the *explicitly declassified* W5 outcomes. -/
structure CoupledRead where
  kind : ReadPath
  left : RequestCase
  right : RequestCase
  agreement : DeclassificationAgreement left right

/-- General sequential W5 result for no-preflight, checked-only and two-phase
    reads. This does not claim equality of TLS timing or close behavior. -/
theorem coupled_history_noninterference (steps : List CoupledRead) :
    steps.map (fun x => observedRead x.kind x.left) =
    steps.map (fun x => observedRead x.kind x.right) := by
  -- Lift the already checked per-step equality without rewriting inside the
  -- large observation model while constructing the list induction proof.
  apply List.map_congr_left
  intro step _
  exact read_observation_noninterference step.kind step.left step.right
    step.agreement

end aivm_secrets_garrett_core.confinement.ReadPrefixes
