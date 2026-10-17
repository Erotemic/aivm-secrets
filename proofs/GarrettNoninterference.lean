import GarrettConfinement

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000
set_option linter.unusedSimpArgs false

/-!
W5: finite, adaptive *modeled-trace* noninterference, with explicit releases.

This imports the W4 source-linked authorization and recursive disclosure
lemmas. Guest observations erase internal provider/audit events and include
public denial/reply, a separately supplied metadata record, and the result of
an explicitly modeled literal-credential-reflection veto.

A two-run theorem requires agreement on source authorization decisions,
external adapter outcomes, the secret-dependent reflection veto and all
visible metadata. Those equalities are RELEASE CONDITIONS, not facts inferred
from equality of public requests. If the credential changes the rejection
status, strict confidentiality of that status is false. An additional theorem
below exhibits that distinguishing observation. W6 must show that concrete
Rust I/O (including metadata and close/error paths) refines this model.
-/

namespace aivm_secrets_garrett_core.confinement.W5

open aivm_secrets_garrett_core.confinement.Proofs

-- Admission is an extracted Rust decision represented as a proposition.
-- Make classical decidability explicit at the W5 model boundary, including
-- theorem statements whose `if` expressions elaborate before tactic scripts.
private noncomputable instance (gate : Gate) : Decidable gate.accepted :=
  Classical.propDecidable _

abbrev Json := aivm_secrets_garrett_core.disclosure.Json
abbrev Projection := aivm_secrets_garrett_core.disclosure.Projection
abbrev Selection := aivm_secrets_garrett_core.disclosure.Selection

inductive GuestMessage where
  | denied
  | released (selection : Selection)

/- Adapter-supplied observables are not checked by the source controller.
   This record must be refined at the actual guest-facing frame writer. -/
structure WireMetadata where
  statusCode : Nat
  frameLength : Nat
  possiblyMore : Bool
  connectionClosed : Bool

structure ObservedStep where
  messages : List GuestMessage
  metadata : WireMetadata

def observeEvent : Event -> Option GuestMessage
  | .guestDenied => some .denied
  | .guestReply _ _ _ _ selected => some (.released selected)
  | _ => none

def observeTrace (events : List Event) : List GuestMessage :=
  events.filterMap observeEvent

/- Reflection rejection occurs after the projection in this model. Unlike
   dropped provider fields, the decision can depend on credential bytes. -/
def reflectionView (blocked : Bool) : GuestMessage -> GuestMessage
  | .denied => .denied
  | .released selected => if blocked then .denied else .released selected

structure RequestCase where
  pre : Gate
  final : Gate
  preAudit : Bool
  finalAudit : Bool
  preflightOK : Bool
  finalProviderOK : Bool
  completedAuditOK : Bool
  raw : Json
  schema : Projection
  fuel : Usize
  budget : Usize
  reflectionBlocked : Bool
  metadata : WireMetadata

noncomputable def caseTrace (r : RequestCase) : List Event :=
  requestTrace r.pre r.final r.preAudit r.finalAudit r.preflightOK
    r.finalProviderOK r.completedAuditOK r.raw r.schema r.fuel r.budget

noncomputable def observed (r : RequestCase) : ObservedStep :=
  { messages := (observeTrace (caseTrace r)).map (reflectionView r.reflectionBlocked),
    metadata := r.metadata }

theorem observe_append (left right : List Event) :
    observeTrace (left ++ right) = observeTrace left ++ observeTrace right := by
  simp [observeTrace]

/- Internal audit and provider effects are erased from the guest observation.
   Keep these reductions separate from the phase-control simplifier, so the
   remaining goals describe only actual guest messages. -/
@[simp] private theorem observe_audit (phase : Phase) (tail : List Event) :
    observeTrace (.auditAttempt phase :: tail) = observeTrace tail := by
  rfl

@[simp] private theorem observe_provider (phase : Phase) (gate : Gate)
    (auditOK : Bool) (tail : List Event) :
    observeTrace (.providerSend phase gate auditOK :: tail) = observeTrace tail := by
  rfl

@[simp] private theorem observe_denial :
    observeTrace [.guestDenied] = [.denied] := by
  rfl

theorem observe_after_preflight (pre : Gate) (auditOK providerOK : Bool)
    (continuation : List Event) :
    observeTrace (afterPreflight pre auditOK providerOK continuation) =
      if pre.accepted then
        if auditOK && providerOK then observeTrace continuation else [.denied]
      else [.denied] := by
  classical
  by_cases accepted : pre.accepted
  · cases auditOK <;> cases providerOK <;>
      simp [afterPreflight, dispatch, accepted]
  · simp [afterPreflight, dispatch, accepted]

theorem observe_after_final (final : Gate)
    (auditOK providerOK completedAuditOK : Bool)
    (raw : Json) (schema : Projection) (fuel budget : Usize) :
    observeTrace (afterFinal final auditOK providerOK completedAuditOK
      raw schema fuel budget) =
      if final.accepted then
        if auditOK && providerOK && completedAuditOK then
          observeTrace (disclose raw schema fuel budget)
        else [.denied]
      else [.denied] := by
  classical
  by_cases accepted : final.accepted
  · cases auditOK <;> cases providerOK <;> cases completedAuditOK <;>
      simp [afterFinal, dispatch, accepted]
  · simp [afterFinal, dispatch, accepted]

theorem observe_case_normal_form (r : RequestCase) :
    observeTrace (caseTrace r) =
      if r.pre.accepted then
        if r.preAudit && r.preflightOK then
          if r.final.accepted then
            if r.finalAudit && r.finalProviderOK && r.completedAuditOK then
              observeTrace (disclose r.raw r.schema r.fuel r.budget)
            else [.denied]
          else [.denied]
        else [.denied]
      else [.denied] := by
  classical
  simp only [caseTrace, requestTrace, observe_after_preflight,
    observe_after_final]

/- W4 represents successful projection using a classical witness, including
   the raw input. Only the exact selected value is visible to the guest. -/
theorem observe_disclose_success (raw : Json) (schema : Projection)
    (fuel budget : Usize) (selected : Selection)
    (returned : aivm_secrets_garrett_core.disclosure.project raw schema fuel budget =
      Result.ok (core.result.Result.Ok selected)) :
    observeTrace (disclose raw schema fuel budget) = [.released selected] := by
  classical
  have success : Exists (fun value : Selection =>
      aivm_secrets_garrett_core.disclosure.project raw schema fuel budget =
        Result.ok (core.result.Result.Ok value)) := Exists.intro selected returned
  have chosen : Classical.choose success = selected := by
    have equalResults : Result.ok (core.result.Result.Ok (Classical.choose success)) =
        Result.ok (core.result.Result.Ok selected) :=
      (Classical.choose_spec success).symm.trans returned
    have inner := Result.ok_injective equalResults
    injection inner with equalValue
  simp [disclose, success, observeTrace, observeEvent, chosen]

theorem observe_disclose_congr (a b : Json) (schema : Projection)
    (fuel budget : Usize)
    (same : aivm_secrets_garrett_core.disclosure.project a schema fuel budget =
      aivm_secrets_garrett_core.disclosure.project b schema fuel budget) :
    observeTrace (disclose a schema fuel budget) =
      observeTrace (disclose b schema fuel budget) := by
  classical
  by_cases successA : Exists (fun selected : Selection =>
      aivm_secrets_garrett_core.disclosure.project a schema fuel budget =
        Result.ok (core.result.Result.Ok selected))
  · have successB : Exists (fun selected : Selection =>
        aivm_secrets_garrett_core.disclosure.project b schema fuel budget =
          Result.ok (core.result.Result.Ok selected)) := by
      obtain ⟨value, returned⟩ := successA
      exact Exists.intro value (same.symm.trans returned)
    have chosen : Classical.choose successA = Classical.choose successB := by
      have equalResults : Result.ok (core.result.Result.Ok (Classical.choose successA)) =
          Result.ok (core.result.Result.Ok (Classical.choose successB)) :=
        (Classical.choose_spec successA).symm.trans
          (same.trans (Classical.choose_spec successB))
      have inner := Result.ok_injective equalResults
      injection inner with equalValue
    simp [disclose, successA, successB, observeTrace, observeEvent, chosen]
  · have failureB : Not (Exists (fun selected : Selection =>
        aivm_secrets_garrett_core.disclosure.project b schema fuel budget =
          Result.ok (core.result.Result.Ok selected))) := by
      intro successB
      obtain ⟨value, returned⟩ := successB
      exact successA (Exists.intro value (same.trans returned))
    simp [disclose, successA, failureB, observeTrace, observeEvent]

/- Source-linked noninterference: the recursive extracted Rust projection
   ignores differences outside the reviewed schema, including its decision
   to deny, remaining budget, and selected values. -/
theorem observe_disclose_noninterference (a b : Json) (schema : Projection)
    (fuel budget : Usize)
    (agree : aivm_secrets_garrett_core.disclosure.Proofs.ProjectionAgreement
      fuel.val a b schema) :
    observeTrace (disclose a schema fuel budget) =
      observeTrace (disclose b schema fuel budget) := by
  apply observe_disclose_congr
  exact aivm_secrets_garrett_core.disclosure.Proofs.recursive_projection_noninterference
    a b schema fuel budget agree

/- This direct source-linked mutation lemma is stronger than postulating
   equality of public replies: ANY pair of JSON values placed in a leading
   unselected field produce the same modeled guest result. -/
theorem ignored_provider_field_noninterference
    (schema : Projection) (keyName hidden : alloc.vec.Vec U8)
    (different : hidden ≠ keyName) (pathTail : List (alloc.vec.Vec U8))
    (starts : schema.at.val = keyName :: pathTail) (left right : Json)
    (rest : List ((alloc.vec.Vec U8) × Json))
    (bound : rest.length + 1 ≤ Usize.max) (fuel budget : Usize) :
    observeTrace (disclose
      (.Object (alloc.vec.Vec.from ((hidden, left) :: rest) (by simpa using bound)))
      schema fuel budget) =
    observeTrace (disclose
      (.Object (alloc.vec.Vec.from ((hidden, right) :: rest) (by simpa using bound)))
      schema fuel budget) := by
  apply observe_disclose_congr
  exact aivm_secrets_garrett_core.disclosure.Proofs.ignored_input_field_noninterference
    schema keyName hidden different pathTail starts left right rest bound fuel budget

/- Every equality below is an *explicitly permitted observable release*.
   In particular, the status, metadata and reflection equalities may be
   secret-dependent in a deployed broker; none follows from equal requests.
   The ProjectionAgreement premise alone constrains only selected fields. -/
structure DeclassificationAgreement (a b : RequestCase) : Prop where
  preAdmission : a.pre.accepted <-> b.pre.accepted
  finalAdmission : a.final.accepted <-> b.final.accepted
  preAudit : a.preAudit = b.preAudit
  finalAudit : a.finalAudit = b.finalAudit
  preflightResult : a.preflightOK = b.preflightOK
  providerResult : a.finalProviderOK = b.finalProviderOK
  completedAudit : a.completedAuditOK = b.completedAuditOK
  schema : a.schema = b.schema
  fuel : a.fuel = b.fuel
  budget : a.budget = b.budget
  projected : aivm_secrets_garrett_core.disclosure.Proofs.ProjectionAgreement
    a.fuel.val a.raw b.raw a.schema
  reflectionStatus : a.reflectionBlocked = b.reflectionBlocked
  metadata : a.metadata = b.metadata

/- This proves that private differences outside approved projection paths
   cannot affect modeled guest-visible observations IF the separately
   declassified decisions and metadata are the same. -/
theorem request_noninterference (a b : RequestCase)
    (agree : DeclassificationAgreement a b) :
    observed a = observed b := by
  have selectedSame : observeTrace (disclose a.raw a.schema a.fuel a.budget) =
      observeTrace (disclose b.raw b.schema b.fuel b.budget) := by
    rw [← agree.schema, ← agree.fuel, ← agree.budget]
    exact observe_disclose_noninterference a.raw b.raw a.schema a.fuel a.budget
      agree.projected
  have traceSame : observeTrace (caseTrace a) = observeTrace (caseTrace b) := by
    simp only [observe_case_normal_form,
      propext agree.preAdmission, propext agree.finalAdmission,
      agree.preAudit, agree.finalAudit, agree.preflightResult,
      agree.providerResult, agree.completedAudit, selectedSame]
  unfold observed
  rw [traceSame, agree.reflectionStatus, agree.metadata]

/- A public attacker picks its next input from the entire observed history.
   The private state may change after each request. To lift the one-request
   theorem, the caller must show *step preservation* of a private-state
   relation and the per-request DeclassificationAgreement. That is a real
   transition-system obligation, not an axiom or a consequence of W4. -/
noncomputable def adaptiveRun {State Request : Type}
    (strategy : List ObservedStep -> Nat -> Request)
    (step : State -> Request -> RequestCase × State) :
    Nat -> State -> List ObservedStep -> List ObservedStep
  | 0, _, history => history
  | n + 1, state, history =>
      let result := step state (strategy history n)
      adaptiveRun strategy step n result.2 (history ++ [observed result.1])

theorem adaptive_noninterference {State Request : Type}
    (strategy : List ObservedStep -> Nat -> Request)
    (step : State -> Request -> RequestCase × State)
    (related : State -> State -> Prop)
    (step_preserves : forall a b request, related a b ->
      DeclassificationAgreement (step a request).1 (step b request).1 /\
      related (step a request).2 (step b request).2)
    (rounds : Nat) (a b : State) (history : List ObservedStep)
    (rel : related a b) :
    adaptiveRun strategy step rounds a history =
      adaptiveRun strategy step rounds b history := by
  induction rounds generalizing a b history with
  | zero => rfl
  | succ remaining ih =>
    let request := strategy history remaining
    have agree := (step_preserves a b request rel).1
    have nextRel := (step_preserves a b request rel).2
    have sameOutput := request_noninterference _ _ agree
    change adaptiveRun strategy step remaining (step a request).2
        (history ++ [observed (step a request).1]) =
      adaptiveRun strategy step remaining (step b request).2
        (history ++ [observed (step b request).1])
    rw [sameOutput]
    exact ih (step a request).2 (step b request).2
      (history ++ [observed (step b request).1]) nextRel

/- Success and denial are observably distinct; a conditional theorem must
   never silently collapse a reflection-triggered denial into a success. -/
theorem literal_reflection_is_observable (selected : Selection) :
    Not (reflectionView true (.released selected) =
      reflectionView false (.released selected)) := by
  simp [reflectionView]

theorem denied_request_witness (r : RequestCase)
    (denied : Not r.pre.accepted) :
    (observed r).messages = [.denied] := by
  classical
  simp [observed, observe_case_normal_form, denied, reflectionView]

theorem allowed_request_witness (r : RequestCase) (selected : Selection)
    (pre : r.pre.accepted) (final : r.final.accepted)
    (preAudit : r.preAudit = true) (finalAudit : r.finalAudit = true)
    (preflight : r.preflightOK = true) (provider : r.finalProviderOK = true)
    (completed : r.completedAuditOK = true)
    (clean : r.reflectionBlocked = false)
    (projection : aivm_secrets_garrett_core.disclosure.project r.raw r.schema
      r.fuel r.budget = Result.ok (core.result.Result.Ok selected)) :
    (observed r).messages = [.released selected] := by
  classical
  have released := observe_disclose_success r.raw r.schema r.fuel r.budget
    selected projection
  simp [observed, observe_case_normal_form, pre, final, preAudit, finalAudit,
    preflight, provider, completed, clean, released, reflectionView]

theorem boolean_projection_witness :
    observeTrace (disclose (.Boolean true)
      aivm_secrets_garrett_core.disclosure.Proofs.booleanSchema
      1#usize 5#usize) =
    [.released { value := .Boolean true, remaining := 0#usize }] := by
  exact observe_disclose_success _ _ _ _ _
    aivm_secrets_garrett_core.disclosure.Proofs.boolean_projection_positive_witness

/- A difference in concrete status/size/pagination/connection metadata
   is observable, regardless of payload noninterference. -/
theorem metadata_difference_is_observable (left right : WireMetadata)
    (different : Not (left = right)) (messages : List GuestMessage) :
    Not (ObservedStep.mk messages left = ObservedStep.mk messages right) := by
  intro equal
  exact different (congrArg ObservedStep.metadata equal)

end aivm_secrets_garrett_core.confinement.W5

