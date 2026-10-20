import GarrettCompletion
import GarrettRequestSimulation

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-! Compose the actual owned completion with the real request controller.
The native wrapper's report/copy-back equation remains an explicit source
correspondence obligation. It is narrower than assuming the complete callback
already preserves receipts or returns only authorized values. -/
namespace aivm_secrets_garrett_core.completion.Simulation
open read_transition request_effects request_effects.Proofs completion.Proofs

def SameOutcome {O N X : Type} (wrap : Completed O → N)
    (reported : core.result.Result (Completed O) X) (native : core.result.Result N X) : Prop :=
  match reported, native with
  | .Ok selected, .Ok value => value = wrap selected
  | .Err original, .Err error => error = original
  | _, _ => False

/-- The production native helper copies report.effects on success AND error,
    then maps only report.outcome through the private completed-value wrapper.
    Instantiating this equality for native Rc/JSON/closures remains a reviewed
    adapter obligation, not a whole-service or transitive I/O premise. -/
structure Link {P F E N X W O : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (primitives : Work W O X)
    (prepare : P → F → W) (wrap : Completed O → N) : Prop where
  returned : ∀ pending facts out after,
    request.complete pending facts = Result.ok (out, after) →
      ∃ report, completion.complete primitives (prepare pending facts) (observe pending) = Result.ok report ∧
        observe after = report.effects ∧ SameOutcome wrap report.outcome out

theorem linked_callback_receipts {P F E N X W O : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (primitives : Work W O X)
    (prepare : P → F → W) (wrap : Completed O → N)
    (link : Link request observe primitives prepare wrap) (pending after : P) (facts : F)
    (out : core.result.Result N X) (returned : request.complete pending facts = Result.ok (out, after)) :
    Steps (observe pending) (observe after) := by
  obtain ⟨report, ran, copied, _⟩ := link.returned pending facts out after returned
  rw [copied]
  exact (complete_receipts primitives (prepare pending facts) (observe pending) report ran).1

/-- Both prior whole-completion receipt hypotheses are supplied by the
    extracted body and the explicit native report equation. Dispatch and outer
    recheck correspondence remain independent, unresolved adapter contracts. -/
theorem request_contracts {P F E N X W O : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (primitives : Work W O X)
    (prepare : P → F → W) (wrap : Completed O → N)
    (link : Link request observe primitives prepare wrap)
    (dispatch : ∀ pending phase effect out after,
      request.dispatch pending phase effect = Result.ok (out, after) → Steps (observe pending) (observe after))
    (recheck : ∀ pending out after,
      request.recheck pending = Result.ok (out, after) → Steps (observe pending) (observe after)) :
    request_effects.Simulation.Contracts request observe := by
  refine ⟨dispatch, recheck, ?_, ?_⟩
  · intro pending facts out after returned
    exact linked_callback_receipts request observe primitives prepare wrap link pending after facts out returned
  · intro pending facts value after returned
    obtain ⟨report, ran, copied, same⟩ := link.returned pending facts (.Ok value) after returned
    rw [copied]
    cases reported : report.outcome with
    | Err error => simp [SameOutcome, reported] at same
    | Ok completed => exact ((complete_receipts primitives (prepare pending facts) (observe pending) report ran).2
        completed reported).2

theorem linked_native_success_origin {P F E N X W O : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (primitives : Work W O X)
    (prepare : P → F → W) (wrap : Completed O → N)
    (link : Link request observe primitives prepare wrap) (pending after : P) (facts : F) (value : N)
    (returned : request.complete pending facts = Result.ok (.Ok value, after)) :
    ∃ completed selected,
      primitives.select (prepare pending facts) = Result.ok (.Ok completed.value, selected) ∧
      value = wrap completed := by
  obtain ⟨report, ran, _, same⟩ := link.returned pending facts (.Ok value) after returned
  cases reported : report.outcome with
  | Err error => simp [SameOutcome, reported] at same
  | Ok completed =>
    obtain ⟨selected, origin⟩ := ((complete_receipts primitives (prepare pending facts) (observe pending) report ran).2
      completed reported).1
    exact ⟨completed, selected, origin, by simpa only [SameOutcome, reported] using same⟩

/-- The real request entry now consumes the proved completion contract rather
    than a free whole-completion Steps/success-gate premise. -/
theorem request_entry_with_owned_completion {P F E N X W O : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (primitives : Work W O X)
    (prepare : P → F → W) (wrap : Completed O → N)
    (link : Link request observe primitives prepare wrap)
    (dispatch : ∀ pending phase effect out after,
      request.dispatch pending phase effect = Result.ok (out, after) → Steps (observe pending) (observe after))
    (recheck : ∀ pending out after,
      request.recheck pending = Result.ok (out, after) → Steps (observe pending) (observe after))
    (pending : P) (out : core.result.Result N X)
    (start : RequestEffects.new = Result.ok (observe pending))
    (returned : run_current request pending = Result.ok out) :
    ∃ after, read_transition.Proofs.RequestRun request pending out after ∧ Reachable (observe after.adapter) := by
  exact request_effects.Simulation.returned_entry_has_reachable_receipt request observe
    (request_contracts request observe primitives prepare wrap link dispatch recheck) pending out start returned

end aivm_secrets_garrett_core.completion.Simulation
