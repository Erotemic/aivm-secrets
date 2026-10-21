import GarrettNoninterference

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-!
W4/W5 optional-read-path extension. These are proofs about the extracted
manifest authorize/disclosure functions through the existing W4/W5 models,
NOT proofs that native TLS or audit files refine this trace interpreter.

The original W4 `requestTrace` requires two provider phases. Native
manifest-https-v1 also permits no-preflight and preflight-only fact returns.
This module gives those paths separate event interpreters and explicitly
conditional observational equivalence. W6 must still connect the actual Rust
I/O and guest frames to these events.
-/

namespace aivm_secrets_garrett_core.confinement.ReadPaths

open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.confinement.W5

-- Model-level admission is a proposition about the extracted Rust function.
-- Conditional branches in theorem *statements* require a decision instance.
private noncomputable instance (gate : Gate) : Decidable gate.accepted :=
  Classical.propDecidable _

inductive ReadPath where
  | noPreflight
  | checkedOnly
  | twoPhase
  deriving DecidableEq

/-- A request with no preflight still requires fresh final admission, an
    acknowledged final audit and an acknowledged completion audit. -/
noncomputable def finalOnly (r : RequestCase) : List Event :=
  afterFinal r.final r.finalAudit r.finalProviderOK r.completedAuditOK
    r.raw r.schema r.fuel r.budget

/-- Check-only operations have a preflight provider read but no final
    provider effect. A successful check returns a selected fact only after
    the completion audit. -/
noncomputable def checkOnly (r : RequestCase) : List Event :=
  afterPreflight r.pre r.preAudit r.preflightOK
    (if r.completedAuditOK then
      [.auditAttempt .completed] ++ disclose r.raw r.schema r.fuel r.budget
    else [.auditAttempt .completed, .guestDenied])

noncomputable def readTrace (kind : ReadPath) (r : RequestCase) : List Event :=
  match kind with
  | .noPreflight => finalOnly r
  | .checkedOnly => checkOnly r
  | .twoPhase => caseTrace r

private theorem append_sound (left right : List Event)
    (hl : SoundTrace left) (hr : SoundTrace right) :
    SoundTrace (left ++ right) := by
  intro event member
  rcases List.mem_append.mp member with first | second
  · exact hl event first
  · exact hr event second

private theorem denied_sound : SoundTrace [Event.guestDenied] := by
  intro event member
  simp at member
  subst event
  trivial

private theorem completed_sound : SoundTrace [Event.auditAttempt .completed] := by
  intro event member
  simp at member
  subst event
  trivial

private theorem check_release_sound (r : RequestCase) :
    SoundTrace (if r.completedAuditOK then
      [.auditAttempt .completed] ++ disclose r.raw r.schema r.fuel r.budget
    else [.auditAttempt .completed, .guestDenied]) := by
  cases h : r.completedAuditOK with
  | false =>
    simpa [h] using append_sound
      [Event.auditAttempt .completed] [Event.guestDenied]
      completed_sound denied_sound
  | true =>
    simpa [h] using append_sound
      [Event.auditAttempt .completed] (disclose r.raw r.schema r.fuel r.budget)
      completed_sound (disclose_sound r.raw r.schema r.fuel r.budget)

theorem final_only_sound (r : RequestCase) : SoundTrace (finalOnly r) := by
  exact after_final_sound r.final r.finalAudit r.finalProviderOK
    r.completedAuditOK r.raw r.schema r.fuel r.budget

-- Reuse the already verified dispatch rule for either preflight outcome.
-- Separating this lemma avoids reasoning about the nested Boolean branch
-- while the admitted provider-send decision is still in scope.
private theorem after_preflight_sound (pre : Gate)
    (auditOK providerOK : Bool) (continuation : List Event)
    (h : SoundTrace continuation) :
    SoundTrace (afterPreflight pre auditOK providerOK continuation) := by
  classical
  unfold afterPreflight
  dsimp
  by_cases sent : Event.providerSend .preflight pre auditOK ∈
      dispatch .preflight pre auditOK
  · simp only [sent, ↓reduceIte]
    cases providerOK with
    | false =>
      simpa using
        (append_sound _ _ (dispatch_sound .preflight pre auditOK) denied_sound)
    | true =>
      simpa using
        (append_sound _ _ (dispatch_sound .preflight pre auditOK) h)
  · simpa only [sent, ↓reduceIte] using
      (dispatch_sound .preflight pre auditOK)

theorem check_only_sound (r : RequestCase) : SoundTrace (checkOnly r) := by
  unfold checkOnly
  exact (after_preflight_sound r.pre r.preAudit r.preflightOK _
    (check_release_sound r))

theorem read_trace_sound (kind : ReadPath) (r : RequestCase) :
    SoundTrace (readTrace kind r) := by
  cases kind with
  | noPreflight => exact final_only_sound r
  | checkedOnly => exact check_only_sound r
  | twoPhase =>
    simpa only [readTrace, caseTrace] using
      (request_trace_sound r.pre r.final r.preAudit r.finalAudit
        r.preflightOK r.finalProviderOK r.completedAuditOK
        r.raw r.schema r.fuel r.budget)

/-- The no-preflight release still derives its selected fields from the
    extracted disclosure controller, with admission from the current gate. -/
theorem final_only_requires_admission (r : RequestCase)
    (auditOK : Bool)
    (sent : Event.providerSend .final r.final auditOK ∈ finalOnly r) :
    r.final.accepted ∧ auditOK = true := by
  exact (final_only_sound r _ sent)

/-- The W5 projected-value and declassification premises also suffice for a
    final-only read. Without equality of status, reflection decisions and
    metadata, full observation equality does not follow. -/
theorem final_only_noninterference (a b : RequestCase)
    (agree : DeclassificationAgreement a b) :
    observeTrace (finalOnly a) = observeTrace (finalOnly b) := by
  have projected : observeTrace (disclose a.raw a.schema a.fuel a.budget) =
      observeTrace (disclose b.raw b.schema b.fuel b.budget) := by
    rw [← agree.schema, ← agree.fuel, ← agree.budget]
    exact observe_disclose_noninterference a.raw b.raw a.schema a.fuel
      a.budget agree.projected
  simp only [finalOnly, observe_after_final,
    propext agree.finalAdmission, agree.finalAudit, agree.providerResult,
    agree.completedAudit, projected]

/-- The completion audit is not itself guest-visible, but the refusal to
    complete is visible as a public denial. -/
theorem observe_check_only (r : RequestCase) :
    observeTrace (checkOnly r) =
      if r.pre.accepted then
        if r.preAudit && r.preflightOK then
          if r.completedAuditOK then
            observeTrace (disclose r.raw r.schema r.fuel r.budget)
          else [.denied]
        else [.denied]
      else [.denied] := by
  classical
  -- The completion audit is erased from the guest observation in both
  -- branches. A failed completion audit releases only the fixed denial.
  have release_observation :
      observeTrace (if r.completedAuditOK then
        [Event.auditAttempt .completed] ++
          disclose r.raw r.schema r.fuel r.budget
      else [Event.auditAttempt .completed, Event.guestDenied]) =
      if r.completedAuditOK then
        observeTrace (disclose r.raw r.schema r.fuel r.budget)
      else [.denied] := by
    cases r.completedAuditOK <;> rfl
  unfold checkOnly
  rw [observe_after_preflight]
  rw [release_observation]

theorem check_only_noninterference (a b : RequestCase)
    (agree : DeclassificationAgreement a b) :
    observeTrace (checkOnly a) = observeTrace (checkOnly b) := by
  have projected : observeTrace (disclose a.raw a.schema a.fuel a.budget) =
      observeTrace (disclose b.raw b.schema b.fuel b.budget) := by
    rw [← agree.schema, ← agree.fuel, ← agree.budget]
    exact observe_disclose_noninterference a.raw b.raw a.schema a.fuel
      a.budget agree.projected
  simp only [observe_check_only,
    propext agree.preAdmission, agree.preAudit, agree.preflightResult,
    agree.completedAudit, projected]

noncomputable def observedRead (kind : ReadPath) (r : RequestCase) : ObservedStep :=
  { messages := (observeTrace (readTrace kind r)).map
      (reflectionView r.reflectionBlocked),
    metadata := r.metadata }

/-- Shape is chosen by the host policy. The shared shape, all permitted
    declassification outcomes and selected projection must agree before
    equality of guest observations follows. -/
theorem read_observation_noninterference (kind : ReadPath)
    (a b : RequestCase) (agree : DeclassificationAgreement a b) :
    observedRead kind a = observedRead kind b := by
  cases kind with
  | noPreflight =>
    have same := final_only_noninterference a b agree
    unfold observedRead
    simp only [readTrace]
    rw [same, agree.reflectionStatus, agree.metadata]
  | checkedOnly =>
    have same := check_only_noninterference a b agree
    unfold observedRead
    simp only [readTrace]
    rw [same, agree.reflectionStatus, agree.metadata]
  | twoPhase =>
    simpa [observedRead, readTrace, observed, caseTrace] using
      request_noninterference a b agree

end aivm_secrets_garrett_core.confinement.ReadPaths

-- Deliberately audited as a separate optional proof slice. Compilation and
-- axiom evidence are only authoritative when run with the pinned Lean toolchain.
