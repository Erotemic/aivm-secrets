import GarrettRequestEffects
import GarrettReadInvocations

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-!
Conditional simulation for the actual post-admission request entry. The native
adapter's plain receipt snapshot supplies `observe`. Local contracts relate
actual returned callback states to actual extracted receipt transitions; they
still require native adapter/primitive correspondence. No contract asserts the
whole-request conclusion or assumes an independent provider-reached flag.
-/
namespace aivm_secrets_garrett_core.request_effects.Simulation
open read_transition read_transition.Proofs request_effects.Proofs

/-- The native adapter copies its shared receipt after every effectful callback,
    on success and failure. Its successful complete callback also checks the
    actual `can_return_value` gate. These are explicit local adapter premises. -/
structure Contracts {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) : Prop where
  dispatch : ∀ pending phase effect out after,
    ops.dispatch pending phase effect = Result.ok (out, after) →
      Steps (observe pending) (observe after)
  recheck : ∀ pending out after,
    ops.recheck pending = Result.ok (out, after) → Steps (observe pending) (observe after)
  complete : ∀ pending facts out after,
    ops.complete pending facts = Result.ok (out, after) → Steps (observe pending) (observe after)
  completed : ∀ pending facts reply after,
    ops.complete pending facts = Result.ok (.Ok reply, after) →
      RequestEffects.can_return_value (observe after) = Result.ok true

private theorem steps_trans {first middle last : RequestEffects}
    (before : Steps first middle) (after : Steps middle last) : Steps first last := by
  induction after with
  | refl => exact before
  | next prior last continued => exact .next continued last

theorem facts_callback_steps {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (world : Contracts ops observe)
    (pending state : P) (preflight : Bool) (facts : F)
    (origin : FactsFrom ops pending preflight facts state) :
    Steps (observe pending) (observe state) := by
  cases preflight with
  | false =>
    obtain ⟨_, _, rfl⟩ := origin
    exact .refl
  | true =>
    obtain ⟨effect, _, sent⟩ := origin
    exact world.dispatch pending .Preflight effect (.Ok facts) state sent

theorem finishing_callback_steps {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (world : Contracts ops observe)
    (pending : P) (preflight : Bool) (facts : F) (reply : O) (after : invocation.Invocation P)
    (finished : FinishSuccess ops pending preflight facts reply after) :
    ∃ completed, after.adapter = completed ∧ Steps (observe pending) (observe completed) ∧
      RequestEffects.can_return_value (observe completed) = Result.ok true := by
  obtain ⟨checked, current, finish⟩ := finished
  have before := world.recheck pending (.Ok ()) checked current
  rcases finish with ⟨_, completed, completion, rfl⟩ |
    ⟨effect, write, raw, dispatched, completed, _, _, sent, completion, rfl⟩
  · exact ⟨completed, rfl, steps_trans before (world.complete checked facts (.Ok reply) completed completion),
      world.completed checked facts reply completed completion⟩
  · have sentSteps := world.dispatch checked .Final effect (.Ok raw) dispatched sent
    exact ⟨completed, rfl,
      steps_trans (steps_trans before sentSteps) (world.complete dispatched raw (.Ok reply) completed completion),
      world.completed dispatched raw reply completed completion⟩

/-- The output state of the actual mutable request kernel is related to the
    same receipt that began at the production constructor. -/
theorem request_forward_simulation {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (world : Contracts ops observe)
    (pending : P) (reply : O) (after : invocation.Invocation P)
    (start : RequestEffects.new = Result.ok (observe pending))
    (returned : request_current ops (initial pending) = Result.ok (.Ok reply, after)) :
    Reachable (observe after.adapter) ∧
      RequestEffects.can_return_value (observe after.adapter) = Result.ok true := by
  obtain ⟨facts, state, preflight, origin, finished⟩ :=
    (request_current_success_iff ops pending reply after).mp returned
  have first := facts_callback_steps ops observe world pending state preflight facts origin
  obtain ⟨completed, same, rest, ready⟩ :=
    finishing_callback_steps ops observe world state preflight facts reply after finished
  rw [same]
  exact ⟨⟨observe pending, start, steps_trans first rest⟩, ready⟩

/-- The consuming production entry cannot return a value without a reachable
    receipt that acknowledges completion and both freshness checks. This is
    conditional on local adapter correspondence, not a native I/O theorem. -/
theorem successful_entry_has_completed_receipt {P F E O X : Type} (ops : Request P F E O X)
    (observe : P → RequestEffects) (world : Contracts ops observe)
    (pending : P) (reply : O)
    (start : RequestEffects.new = Result.ok (observe pending))
    (returned : run_current ops pending = Result.ok (.Ok reply)) :
    ∃ completed, Reachable (observe completed) ∧
      (observe completed).completion.selected = true ∧
      (observe completed).completion.before_checked = true ∧
      (observe completed).completion.audit_attempted = true ∧
      (observe completed).completion.audit_acknowledged = true ∧
      (observe completed).completion.after_checked = true ∧
      (observe completed).completion.value_ready = true := by
  obtain ⟨facts, state, preflight, after, origin, finished⟩ :=
    (run_current_success_iff ops pending reply).mp returned
  have first := facts_callback_steps ops observe world pending state preflight facts origin
  obtain ⟨completed, _, rest, ready⟩ :=
    finishing_callback_steps ops observe world state preflight facts reply after finished
  have reachable : Reachable (observe completed) := ⟨observe pending, start, steps_trans first rest⟩
  exact ⟨completed, reachable, completed_value_requires_selection_checks_and_audit _ reachable ready⟩

end aivm_secrets_garrett_core.request_effects.Simulation
