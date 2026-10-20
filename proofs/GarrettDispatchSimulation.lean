import GarrettDispatch
import GarrettCompletionSimulation

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-! The native report/copy-back equations are explicit correspondence
obligations. Under those equations, both entire callback receipt hypotheses
are derived from the extracted production controllers. Primitive semantics,
outer rechecks, context capture and native I/O closure remain separate. -/
namespace aivm_secrets_garrett_core.dispatch.Simulation
open read_transition request_effects request_effects.Proofs

structure Plan (W X : Type) where
  work : W
  prepared : core.result.Result Prepared X
  keyed : Bool

structure Link {P F E N X W C : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (primitives : Work W C F X)
    (prepare : P → Phase → E → Plan W X) : Prop where
  returned : ∀ pending phase effect out after,
    request.dispatch pending phase effect = Result.ok (out, after) →
      ∃ report, dispatch.dispatch primitives (prepare pending phase effect).work
          (prepare pending phase effect).prepared (observe pending) (prepare pending phase effect).keyed = Result.ok report ∧
        observe after = report.effects ∧ out = report.outcome

theorem linked_callback_receipts {P F E N X W C : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (primitives : Work W C F X)
    (prepare : P → Phase → E → Plan W X) (link : Link request observe primitives prepare)
    (pending after : P) (phase : Phase) (effect : E) (out : core.result.Result F X)
    (returned : request.dispatch pending phase effect = Result.ok (out, after)) :
    Steps (observe pending) (observe after) := by
  obtain ⟨report, ran, copied, _⟩ := link.returned pending phase effect out after returned
  rw [copied]
  exact Proofs.dispatch_receipts primitives (prepare pending phase effect).work
    (prepare pending phase effect).prepared (observe pending) (prepare pending phase effect).keyed report ran

theorem request_contracts {P F E N X W C V O : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (dispatchOps : Work W C F X)
    (prepareDispatch : P → Phase → E → Plan W X)
    (dispatchLink : Link request observe dispatchOps prepareDispatch)
    (completionOps : completion.Work V O X) (prepareCompletion : P → F → V)
    (wrap : completion.Completed O → N)
    (completionLink : completion.Simulation.Link request observe completionOps prepareCompletion wrap)
    (recheck : ∀ pending out after,
      request.recheck pending = Result.ok (out, after) → Steps (observe pending) (observe after)) :
    request_effects.Simulation.Contracts request observe := by
  apply completion.Simulation.request_contracts request observe completionOps prepareCompletion wrap completionLink
  · intro pending phase effect out after returned
    exact linked_callback_receipts request observe dispatchOps prepareDispatch dispatchLink pending after phase effect out returned
  · exact recheck

/-- The real request entry consumes both owned controllers. This removes the
    earlier whole-dispatch and whole-completion Steps assumptions; it does not
    universally instantiate the native links or the primitive contracts. -/
theorem request_entry_with_owned_adapters {P F E N X W C V O : Type} (request : Request P F E N X)
    (observe : P → RequestEffects) (dispatchOps : Work W C F X)
    (prepareDispatch : P → Phase → E → Plan W X)
    (dispatchLink : Link request observe dispatchOps prepareDispatch)
    (completionOps : completion.Work V O X) (prepareCompletion : P → F → V)
    (wrap : completion.Completed O → N)
    (completionLink : completion.Simulation.Link request observe completionOps prepareCompletion wrap)
    (recheck : ∀ pending out after,
      request.recheck pending = Result.ok (out, after) → Steps (observe pending) (observe after))
    (pending : P) (out : core.result.Result N X)
    (start : RequestEffects.new = Result.ok (observe pending))
    (returned : run_current request pending = Result.ok out) :
    ∃ after, read_transition.Proofs.RequestRun request pending out after ∧ Reachable (observe after.adapter) := by
  exact request_effects.Simulation.returned_entry_has_reachable_receipt request observe
    (request_contracts request observe dispatchOps prepareDispatch dispatchLink completionOps prepareCompletion wrap completionLink recheck)
    pending out start returned

end aivm_secrets_garrett_core.dispatch.Simulation
