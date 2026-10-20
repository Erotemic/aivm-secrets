import GarrettReadTransition

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-!
The actual extracted mutable invocation tracker and request controller.
States below name the concrete record contents at callback boundaries. They
are observation/relating functions, not a second Rust request interpreter.
The raw adapter remains an explicit external boundary; this module concerns
its invocations and results, not transitive native I/O inside a callback.
-/

namespace aivm_secrets_garrett_core.read_transition.Proofs

open invocation

def initial {P : Type} (pending : P) : Invocation P :=
  ⟨pending, .Empty, .Start⟩

def atState {P : Type} (pending : P) (trace : Trace) (progress : Progress) : Invocation P :=
  ⟨pending, trace, progress⟩

def factsState {P : Type} (pending : P) (preflight : Bool) : Invocation P :=
  atState pending (if preflight then .PreflightDispatch else .EmptyFacts) (.FinalPlan preflight)

def completeState {P : Type} (pending : P) (preflight finalEffect write : Bool) : Invocation P :=
  atState pending (if finalEffect then .FinalDispatch preflight else .Current preflight)
    (.Complete preflight finalEffect write)

def afterPreflight {P E X : Type} (pending : P) (out : core.result.Result (Option E) X) : Invocation P :=
  atState pending .PreflightPlan (match out with
    | .Err _ => .Halted
    | .Ok none => .Empty
    | .Ok (some _) => .Preflight)

def afterFinalPlan {P E X : Type} (pending : P) (preflight : Bool)
    (out : core.result.Result (Option E) X) : Invocation P :=
  atState pending (.FinalPlan preflight) (match out with
    | .Err _ => .Halted
    | .Ok selected => .Current preflight selected.isSome)

def afterComplete {P O X : Type} (pending : P) (preflight finalEffect write : Bool)
    (out : core.result.Result O X) : Invocation P :=
  atState pending (.Complete preflight finalEffect) (match out with
    | .Ok _ => .Finished
    | .Err _ => if write then .Uncertain preflight else .Halted)

private theorem bind_returns_iff {A B : Type} (first : Result A)
    (next : A → Result B) (result : B) :
    (first >>= next) = Result.ok result ↔
      ∃ value, first = Result.ok value ∧ next value = Result.ok result := by
  cases first using Result.cases with
  | ret value => simp
  | vis effect continuation => simp
  | div => simp

private theorem preflight_step {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (out : core.result.Result (Option E) X)
    (returned : ops.preflight pending = Result.ok out) :
    Invocation.preflight ops (initial pending) = Result.ok (out, afterPreflight pending out) := by
  cases out with
  | Err error => simp [Invocation.preflight, initial, afterPreflight, atState, returned]
  | Ok selected => cases selected <;>
      simp [Invocation.preflight, initial, afterPreflight, atState, returned]

private theorem empty_step {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (facts : F) (returned : ops.empty_facts pending = Result.ok facts) :
    Invocation.empty_facts ops (atState pending .PreflightPlan .Empty) =
      Result.ok (.Ok facts, factsState pending false) := by
  simp [Invocation.empty_facts, atState, factsState, returned]

private theorem preflight_dispatch_step {P F E O X : Type} (ops : Request P F E O X)
    (pending after : P) (effect : E) (out : core.result.Result F X)
    (returned : ops.dispatch pending .Preflight effect = Result.ok (out, after)) :
    Invocation.dispatch ops (atState pending .PreflightPlan .Preflight) .Preflight effect =
      Result.ok (out, match out with
        | .Ok _ => factsState after true
        | .Err _ => atState after .PreflightDispatch .Halted) := by
  cases out <;> simp [Invocation.dispatch, atState, factsState, returned]

private theorem final_plan_step {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight : Bool) (facts : F) (out : core.result.Result (Option E) X)
    (returned : ops.final_effect pending facts = Result.ok out) :
    Invocation.final_effect ops (factsState pending preflight) facts =
      Result.ok (out, afterFinalPlan pending preflight out) := by
  cases out with
  | Err error => simp [Invocation.final_effect, atState, factsState, afterFinalPlan, returned]
  | Ok selected => cases selected <;>
      simp [Invocation.final_effect, atState, factsState, afterFinalPlan, returned]

private theorem current_step {P F E O X : Type} (ops : Request P F E O X)
    (pending after : P) (preflight finalEffect : Bool) (out : core.result.Result Unit X)
    (returned : ops.recheck pending = Result.ok (out, after)) :
    Invocation.recheck ops (atState pending (.FinalPlan preflight) (.Current preflight finalEffect)) =
      Result.ok (out, match out with
        | .Err _ => atState after (.Current preflight) .Halted
        | .Ok _ => if finalEffect then atState after (.Current preflight) (.WriteKind preflight)
          else completeState after preflight false false) := by
  cases out with
  | Err error => simp [Invocation.recheck, atState, returned]
  | Ok u => cases u; cases finalEffect <;>
      simp [Invocation.recheck, atState, completeState, returned]

private theorem write_step {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight write : Bool) (effect : E)
    (returned : ops.effect_write pending effect = Result.ok write) :
    Invocation.effect_write ops (atState pending (.Current preflight) (.WriteKind preflight)) effect =
      Result.ok (.Ok write, atState pending (.WriteKind preflight) (.FinalDispatch preflight write)) := by
  simp [Invocation.effect_write, atState, returned]

private theorem final_dispatch_step {P F E O X : Type} (ops : Request P F E O X)
    (pending after : P) (preflight write : Bool) (effect : E) (out : core.result.Result F X)
    (returned : ops.dispatch pending .Final effect = Result.ok (out, after)) :
    Invocation.dispatch ops (atState pending (.WriteKind preflight) (.FinalDispatch preflight write))
      .Final effect = Result.ok (out, match out with
        | .Ok _ => completeState after preflight true write
        | .Err _ => atState after (.FinalDispatch preflight) .Halted) := by
  cases out <;> simp [Invocation.dispatch, atState, completeState, returned]

private theorem complete_step {P F E O X : Type} (ops : Request P F E O X)
    (pending after : P) (preflight finalEffect write : Bool) (raw : F) (out : core.result.Result O X)
    (returned : ops.complete pending raw = Result.ok (out, after)) :
    Invocation.complete ops (completeState pending preflight finalEffect write) raw =
      Result.ok (out, afterComplete after preflight finalEffect write out) := by
  cases out <;> cases write <;>
    simp [Invocation.complete, completeState, atState, afterComplete, returned]

private theorem uncertain_step {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight : Bool) (code : X)
    (returned : ops.outcome_unknown pending = Result.ok code) :
    Invocation.outcome_unknown ops (atState pending (.Complete preflight true) (.Uncertain preflight)) =
      Result.ok (code, atState pending (.Uncertain preflight) .Halted) := by
  simp [Invocation.outcome_unknown, atState, returned]

private theorem preflight_bind {P F E O X : Type} (ops : Request P F E O X) (pending : P) :
    Invocation.preflight ops (initial pending) = (do
      let out ← ops.preflight pending
      Result.ok (out, afterPreflight pending out)) := by
  simp [Invocation.preflight, initial]
  congr 1
  funext out
  cases out with
  | Err error => rfl
  | Ok selected => cases selected <;> rfl

private theorem empty_bind {P F E O X : Type} (ops : Request P F E O X) (pending : P) :
    Invocation.empty_facts ops (atState pending .PreflightPlan .Empty) = (do
      let facts ← ops.empty_facts pending
      Result.ok (.Ok facts, factsState pending false)) := by
  simp [Invocation.empty_facts, atState, factsState]

private theorem preflight_dispatch_bind {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (effect : E) :
    Invocation.dispatch ops (atState pending .PreflightPlan .Preflight) .Preflight effect = (do
      let (out, after) ← ops.dispatch pending .Preflight effect
      Result.ok (out, match out with
        | .Ok _ => factsState after true
        | .Err _ => atState after .PreflightDispatch .Halted)) := by
  simp [Invocation.dispatch, atState]
  congr 1
  funext pair
  rcases pair with ⟨out, after⟩
  cases out <;> rfl

private theorem final_plan_bind {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight : Bool) (facts : F) :
    Invocation.final_effect ops (factsState pending preflight) facts = (do
      let out ← ops.final_effect pending facts
      Result.ok (out, afterFinalPlan pending preflight out)) := by
  simp only [Invocation.final_effect, factsState, atState]
  congr 1
  funext out
  cases out with
  | Err error => rfl
  | Ok selected => cases selected <;> rfl

private theorem current_bind {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight finalEffect : Bool) :
    Invocation.recheck ops (atState pending (.FinalPlan preflight) (.Current preflight finalEffect)) = (do
      let (out, after) ← ops.recheck pending
      Result.ok (out, match out with
        | .Err _ => atState after (.Current preflight) .Halted
        | .Ok _ => if finalEffect then atState after (.Current preflight) (.WriteKind preflight)
          else completeState after preflight false false)) := by
  simp only [Invocation.recheck, atState]
  congr 1
  funext pair
  rcases pair with ⟨out, after⟩
  cases out with
  | Err error => rfl
  | Ok u => cases u; cases finalEffect <;> rfl

private theorem write_bind {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight : Bool) (effect : E) :
    Invocation.effect_write ops (atState pending (.Current preflight) (.WriteKind preflight)) effect = (do
      let write ← ops.effect_write pending effect
      Result.ok (.Ok write, atState pending (.WriteKind preflight) (.FinalDispatch preflight write))) := by
  rfl

private theorem final_dispatch_bind {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight write : Bool) (effect : E) :
    Invocation.dispatch ops (atState pending (.WriteKind preflight) (.FinalDispatch preflight write))
      .Final effect = (do
      let (out, after) ← ops.dispatch pending .Final effect
      Result.ok (out, match out with
        | .Ok _ => completeState after preflight true write
        | .Err _ => atState after (.FinalDispatch preflight) .Halted)) := by
  simp [Invocation.dispatch, atState]
  congr 1
  funext pair
  rcases pair with ⟨out, after⟩
  cases out <;> rfl

private theorem complete_bind {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight finalEffect write : Bool) (raw : F) :
    Invocation.complete ops (completeState pending preflight finalEffect write) raw = (do
      let (out, after) ← ops.complete pending raw
      Result.ok (out, afterComplete after preflight finalEffect write out)) := by
  simp only [Invocation.complete, completeState, atState]
  congr 1
  funext pair
  rcases pair with ⟨out, after⟩
  cases out with
  | Ok reply => rfl
  | Err error => cases write <;> rfl

private theorem uncertain_bind {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight : Bool) :
    Invocation.outcome_unknown ops (atState pending (.Complete preflight true) (.Uncertain preflight)) = (do
      let code ← ops.outcome_unknown pending
      Result.ok (code, atState pending (.Uncertain preflight) .Halted)) := by
  rfl


/-- Exact fact origin and returned mutable adapter state. -/
def FactsFrom {P F E O X : Type} (ops : Request P F E O X) (pending : P)
    (preflight : Bool) (facts : F) (after : P) : Prop :=
  if preflight then
    ∃ effect, ops.preflight pending = Result.ok (.Ok (some effect)) ∧
      ops.dispatch pending .Preflight effect = Result.ok (.Ok facts, after)
  else ops.preflight pending = Result.ok (.Ok none) ∧
    ops.empty_facts pending = Result.ok facts ∧ after = pending

theorem request_facts_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (facts : F) (after : Invocation P) :
    request_facts ops (initial pending) = Result.ok (.Ok facts, after) ↔
      ∃ state preflight, FactsFrom ops pending preflight facts state ∧ after = factsState state preflight := by
  unfold request_facts
  rw [preflight_bind]
  cases h : ops.preflight pending using Result.cases with
  | ret planned =>
    cases planned with
    | Err error => simp [h, FactsFrom, afterPreflight, atState]
    | Ok selected =>
      cases selected with
      | none =>
        simp [afterPreflight]
        rw [empty_bind]
        cases empty : ops.empty_facts pending using Result.cases <;>
          simp [empty, FactsFrom, h, eq_comm]
      | some effect =>
        simp [afterPreflight]
        rw [preflight_dispatch_bind]
        cases dispatched : ops.dispatch pending .Preflight effect using Result.cases with
        | ret pair => rcases pair with ⟨out, state⟩; cases out <;>
            simp [dispatched, FactsFrom, h, eq_comm]
        | vis event continuation => simp [dispatched, FactsFrom, h]
        | div => simp [dispatched, FactsFrom, h]
  | vis event continuation => simp [h, FactsFrom]
  | div => simp [h, FactsFrom]

def finishedState {P : Type} (pending : P) (preflight finalEffect : Bool) : Invocation P :=
  atState pending (.Complete preflight finalEffect) .Finished

/-- The current, dispatch and completion callbacks thread their actual states.
    Completion receives exactly the selected facts or final provider value. -/
def FinishSuccess {P F E O X : Type} (ops : Request P F E O X) (pending : P)
    (preflight : Bool) (facts : F) (reply : O) (after : Invocation P) : Prop :=
  ∃ checked, ops.recheck pending = Result.ok (.Ok (), checked) ∧
    ((ops.final_effect pending facts = Result.ok (.Ok none) ∧
      ∃ completed, ops.complete checked facts = Result.ok (.Ok reply, completed) ∧
      after = finishedState completed preflight false) ∨
     ∃ effect write raw dispatched completed,
       ops.final_effect pending facts = Result.ok (.Ok (some effect)) ∧
       ops.effect_write checked effect = Result.ok write ∧
       ops.dispatch checked .Final effect = Result.ok (.Ok raw, dispatched) ∧
       ops.complete dispatched raw = Result.ok (.Ok reply, completed) ∧
       after = finishedState completed preflight true)

private theorem complete_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight finalEffect write : Bool) (raw : F) (reply : O)
    (after : Invocation P) :
    Invocation.complete ops (completeState pending preflight finalEffect write) raw =
      Result.ok (.Ok reply, after) ↔
      ∃ completed, ops.complete pending raw = Result.ok (.Ok reply, completed) ∧
        after = finishedState completed preflight finalEffect := by
  rw [complete_bind]
  cases h : ops.complete pending raw using Result.cases with
  | ret pair => rcases pair with ⟨out, completed⟩; cases out <;>
      simp [afterComplete, finishedState, eq_comm]
  | vis event continuation => simp
  | div => simp

theorem finish_request_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight : Bool) (facts : F) (reply : O) (after : Invocation P) :
    finish_request ops (factsState pending preflight) facts = Result.ok (.Ok reply, after) ↔
      FinishSuccess ops pending preflight facts reply after := by
  constructor
  · intro success
    unfold finish_request at success
    rw [final_plan_bind] at success
    simp at success
    obtain ⟨planned, compiled, rest⟩ := (bind_returns_iff _ _ _).mp success
    cases planned with
    | Err error => simp at rest
    | Ok selected =>
      dsimp only [afterFinalPlan] at rest
      rw [current_bind] at rest
      simp at rest
      obtain ⟨⟨checked, state⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases checked with
      | Err error => simp at rest
      | Ok u =>
        cases u
        simp at rest
        cases selected with
        | none =>
          have last := (complete_success_iff ops state preflight false false facts reply after).mp (by simpa using rest)
          exact ⟨state, current, Or.inl ⟨compiled, last⟩⟩
        | some effect =>
          simp at rest
          rw [write_bind] at rest
          simp at rest
          obtain ⟨write, classified, rest⟩ := (bind_returns_iff _ _ _).mp rest
          rw [final_dispatch_bind] at rest
          simp at rest
          obtain ⟨⟨provider, dispatched⟩, sent, rest⟩ := (bind_returns_iff _ _ _).mp rest
          cases provider with
          | Err error => simp at rest
          | Ok raw =>
            simp at rest
            have last : ∃ completed, ops.complete dispatched raw = Result.ok (.Ok reply, completed) ∧
                after = finishedState completed preflight true := by
              cases write with
              | false => exact (complete_success_iff ops dispatched preflight true false raw reply after).mp (by simpa using rest)
              | true =>
                simp at rest
                rw [complete_bind] at rest
                simp at rest
                obtain ⟨⟨out, completed⟩, completion, rest⟩ := (bind_returns_iff _ _ _).mp rest
                cases out with
                | Ok value =>
                  have same : value = reply ∧ after = finishedState completed preflight true := by
                    simpa [afterComplete, finishedState, eq_comm] using rest
                  exact ⟨completed, by simpa [same.1] using completion, same.2⟩
                | Err error =>
                  simp [afterComplete] at rest
                  rw [uncertain_bind] at rest
                  simp at rest
                  obtain ⟨code, _, impossible⟩ := (bind_returns_iff _ _ _).mp rest
                  simp at impossible
            obtain ⟨completed, completion, same⟩ := last
            exact ⟨state, current, Or.inr ⟨effect, write, raw, dispatched, completed,
              compiled, classified, sent, completion, same⟩⟩
  · rintro ⟨state, current, ⟨compiled, completed, completion, rfl⟩ |
      ⟨effect, write, raw, dispatched, completed, compiled, classified, sent, completion, rfl⟩⟩
    · simp [finish_request, final_plan_step _ _ _ _ _ compiled, afterFinalPlan,
        current_step _ _ _ _ _ _ current, complete_step _ _ _ _ _ _ _ _ completion,
        afterComplete, finishedState]
    · cases write <;> simp [finish_request, final_plan_step _ _ _ _ _ compiled,
        afterFinalPlan, current_step _ _ _ _ _ _ current, write_step _ _ _ _ _ classified,
        final_dispatch_step _ _ _ _ _ _ _ sent, complete_step _ _ _ _ _ _ _ _ completion,
        afterComplete, finishedState]

theorem request_current_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (reply : O) (after : Invocation P) :
    request_current ops (initial pending) = Result.ok (.Ok reply, after) ↔
      ∃ facts state preflight, FactsFrom ops pending preflight facts state ∧
        FinishSuccess ops state preflight facts reply after := by
  constructor
  · intro success
    unfold request_current at success
    obtain ⟨⟨out, middle⟩, produced, rest⟩ := (bind_returns_iff _ _ _).mp success
    cases out with
    | Err error => simp at rest
    | Ok facts =>
      obtain ⟨state, preflight, origin, rfl⟩ := (request_facts_success_iff ops pending facts middle).mp produced
      exact ⟨facts, state, preflight, origin,
        (finish_request_success_iff ops state preflight facts reply after).mp rest⟩
  · rintro ⟨facts, state, preflight, origin, finish⟩
    have produced := (request_facts_success_iff ops pending facts (factsState state preflight)).mpr
      ⟨state, preflight, origin, rfl⟩
    simp [request_current, produced,
      (finish_request_success_iff ops state preflight facts reply after).mpr finish]

private theorem facts_return {P F E O X : Type} (ops : Request P F E O X)
    (pending state : P) (preflight : Bool) (facts : F) (origin : FactsFrom ops pending preflight facts state) :
    request_facts ops (initial pending) = Result.ok (.Ok facts, factsState state preflight) :=
  (request_facts_success_iff ops pending facts _).mpr ⟨state, preflight, origin, rfl⟩


theorem failed_preflight_compilation_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (error : X)
    (failed : ops.preflight pending = Result.ok (.Err error)) :
    request_current ops (initial pending) =
      Result.ok (.Err error, atState pending .PreflightPlan .Halted) := by
  simp [request_current, request_facts, preflight_step _ _ _ failed, afterPreflight]

theorem failed_preflight_provider_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending after : P) (effect : E) (error : X)
    (planned : ops.preflight pending = Result.ok (.Ok (some effect)))
    (failed : ops.dispatch pending .Preflight effect = Result.ok (.Err error, after)) :
    request_current ops (initial pending) =
      Result.ok (.Err error, atState after .PreflightDispatch .Halted) := by
  simp [request_current, request_facts, preflight_step _ _ _ planned, afterPreflight,
    preflight_dispatch_step _ _ _ _ _ failed]

theorem failed_final_compilation_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending state : P) (preflight : Bool) (facts : F) (error : X)
    (produced : FactsFrom ops pending preflight facts state)
    (failed : ops.final_effect state facts = Result.ok (.Err error)) :
    request_current ops (initial pending) =
      Result.ok (.Err error, atState state (.FinalPlan preflight) .Halted) := by
  simp [request_current, facts_return _ _ _ _ _ produced, finish_request,
    final_plan_step _ _ _ _ _ failed, afterFinalPlan]

theorem stale_after_preflight_stops {P F E O X : Type}
    (ops : Request P F E O X) (pending state after : P) (preflight : Bool) (facts : F)
    (selected : Option E) (error : X)
    (produced : FactsFrom ops pending preflight facts state)
    (compiled : ops.final_effect state facts = Result.ok (.Ok selected))
    (denied : ops.recheck state = Result.ok (.Err error, after)) :
    request_current ops (initial pending) =
      Result.ok (.Err error, atState after (.Current preflight) .Halted) := by
  simp [request_current, facts_return _ _ _ _ _ produced, finish_request,
    final_plan_step _ _ _ _ _ compiled, afterFinalPlan, current_step _ _ _ _ _ _ denied]

theorem final_provider_failure_stops_completion {P F E O X : Type}
    (ops : Request P F E O X) (pending state checked after : P) (preflight : Bool) (facts : F) (effect : E)
    (write : Bool) (error : X)
    (produced : FactsFrom ops pending preflight facts state)
    (compiled : ops.final_effect state facts = Result.ok (.Ok (some effect)))
    (current : ops.recheck state = Result.ok (.Ok (), checked))
    (classified : ops.effect_write checked effect = Result.ok write)
    (failed : ops.dispatch checked .Final effect = Result.ok (.Err error, after)) :
    request_current ops (initial pending) =
      Result.ok (.Err error, atState after (.FinalDispatch preflight) .Halted) := by
  simp [request_current, facts_return _ _ _ _ _ produced, finish_request,
    final_plan_step _ _ _ _ _ compiled, afterFinalPlan, current_step _ _ _ _ _ _ current,
    write_step _ _ _ _ _ classified, final_dispatch_step _ _ _ _ _ _ _ failed]

theorem final_read_continuation {P F E O X : Type}
    (ops : Request P F E O X) (pending state checked dispatched : P) (preflight : Bool) (facts raw : F) (effect : E)
    (produced : FactsFrom ops pending preflight facts state)
    (compiled : ops.final_effect state facts = Result.ok (.Ok (some effect)))
    (current : ops.recheck state = Result.ok (.Ok (), checked))
    (classified : ops.effect_write checked effect = Result.ok false)
    (sent : ops.dispatch checked .Final effect = Result.ok (.Ok raw, dispatched)) :
    request_current ops (initial pending) = (do
      let (out, completed) ← ops.complete dispatched raw
      Result.ok (out, afterComplete completed preflight true false out)) := by
  simp [request_current, facts_return _ _ _ _ _ produced, finish_request,
    final_plan_step _ _ _ _ _ compiled, afterFinalPlan, current_step _ _ _ _ _ _ current,
    write_step _ _ _ _ _ classified, final_dispatch_step _ _ _ _ _ _ _ sent, complete_bind]

theorem checked_only_continuation {P F E O X : Type}
    (ops : Request P F E O X) (pending state checked : P) (preflight : Bool) (facts : F)
    (produced : FactsFrom ops pending preflight facts state)
    (compiled : ops.final_effect state facts = Result.ok (.Ok none))
    (current : ops.recheck state = Result.ok (.Ok (), checked)) :
    request_current ops (initial pending) = (do
      let (out, completed) ← ops.complete checked facts
      Result.ok (out, afterComplete completed preflight false false out)) := by
  simp [request_current, facts_return _ _ _ _ _ produced, finish_request,
    final_plan_step _ _ _ _ _ compiled, afterFinalPlan, current_step _ _ _ _ _ _ current, complete_bind]

theorem sent_write_completion_failure_is_uncertain {P F E O X : Type}
    (ops : Request P F E O X) (pending state checked dispatched completed : P)
    (preflight : Bool) (facts raw : F) (effect : E) (error unknown : X)
    (produced : FactsFrom ops pending preflight facts state)
    (compiled : ops.final_effect state facts = Result.ok (.Ok (some effect)))
    (current : ops.recheck state = Result.ok (.Ok (), checked))
    (classified : ops.effect_write checked effect = Result.ok true)
    (sent : ops.dispatch checked .Final effect = Result.ok (.Ok raw, dispatched))
    (failed : ops.complete dispatched raw = Result.ok (.Err error, completed))
    (code : ops.outcome_unknown completed = Result.ok unknown) :
    request_current ops (initial pending) =
      Result.ok (.Err unknown, atState completed (.Uncertain preflight) .Halted) := by
  simp [request_current, facts_return _ _ _ _ _ produced, finish_request,
    final_plan_step _ _ _ _ _ compiled, afterFinalPlan, current_step _ _ _ _ _ _ current,
    write_step _ _ _ _ _ classified, final_dispatch_step _ _ _ _ _ _ _ sent,
    complete_step _ _ _ _ _ _ _ _ failed, afterComplete, uncertain_step _ _ _ _ code]

theorem two_phase_read_successful_witness {P F E O X : Type}
    (ops : Request P F E O X) (pending state checked dispatched completed : P)
    (preflight final : E) (facts raw : F) (reply : O)
    (preplanned : ops.preflight pending = Result.ok (.Ok (some preflight)))
    (prefetched : ops.dispatch pending .Preflight preflight = Result.ok (.Ok facts, state))
    (compiled : ops.final_effect state facts = Result.ok (.Ok (some final)))
    (current : ops.recheck state = Result.ok (.Ok (), checked))
    (classified : ops.effect_write checked final = Result.ok false)
    (sent : ops.dispatch checked .Final final = Result.ok (.Ok raw, dispatched))
    (completion : ops.complete dispatched raw = Result.ok (.Ok reply, completed)) :
    request_current ops (initial pending) =
      Result.ok (.Ok reply, finishedState completed true true) := by
  rw [final_read_continuation ops pending state checked dispatched true facts raw final
    (by exact ⟨preflight, preplanned, prefetched⟩) compiled current classified sent]
  simp [completion, afterComplete, finishedState]

private theorem into_result_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (state : Invocation P) (out : core.result.Result O X) (reply : O) :
    Invocation.into_result ops state out = Result.ok (.Ok reply) ↔
      out = .Ok reply ∧ state.progress = .Finished := by
  cases out with
  | Err error => simp [Invocation.into_result]
  | Ok value =>
    cases progress : state.progress <;>
      cases constant : ops.INVALID_TRANSITION using Result.cases <;>
        simp [Invocation.into_result, progress, constant]

private theorem finish_is_terminal {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight : Bool) (facts : F) (reply : O) (after : Invocation P)
    (success : FinishSuccess ops pending preflight facts reply after) :
    after.progress = .Finished := by
  rcases success with ⟨_, _, ⟨_, _, _, rfl⟩ | ⟨_, _, _, _, _, _, _, _, _, rfl⟩⟩ <;> rfl

theorem constructor_starts_empty {P F E O X : Type} (ops : Request P F E O X) (pending : P) :
    Invocation.new ops pending = Result.ok (initial pending) := by
  simp [Invocation.new, initial]

theorem run_current_success_iff {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (reply : O) :
    run_current ops pending = Result.ok (.Ok reply) ↔
      ∃ facts state preflight after, FactsFrom ops pending preflight facts state ∧
        FinishSuccess ops state preflight facts reply after := by
  constructor
  · intro success
    unfold run_current at success
    simp [constructor_starts_empty] at success
    obtain ⟨⟨out, after⟩, ran, gate⟩ := (bind_returns_iff _ _ _).mp success
    obtain ⟨rfl, _⟩ := (into_result_success_iff ops after out reply).mp gate
    obtain ⟨facts, state, preflight, origin, finish⟩ :=
      (request_current_success_iff ops pending reply after).mp ran
    exact ⟨facts, state, preflight, after, origin, finish⟩
  · rintro ⟨facts, state, preflight, after, origin, finish⟩
    have ran := (request_current_success_iff ops pending reply after).mpr
      ⟨facts, state, preflight, origin, finish⟩
    have gate := (into_result_success_iff ops after (.Ok reply) reply).mpr
      ⟨rfl, finish_is_terminal ops state preflight facts reply after finish⟩
    simp [run_current, constructor_starts_empty, ran, gate]

/-- Every successful controller run returns the concrete successful wrapper
    receipt. This does not count any transitive I/O inside the raw adapter. -/
theorem successful_request_receipt {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (reply : O) (after : Invocation P)
    (success : request_current ops (initial pending) = Result.ok (.Ok reply, after)) :
    ∃ state preflight finalEffect, after = finishedState state preflight finalEffect := by
  obtain ⟨facts, state, preflight, _, finish⟩ :=
    (request_current_success_iff ops pending reply after).mp success
  rcases finish with ⟨_, _, ⟨_, completed, _, same⟩ | ⟨_, _, _, _, completed, _, _, _, _, same⟩⟩
  · exact ⟨completed, preflight, false, same⟩
  · exact ⟨completed, preflight, true, same⟩

theorem finished_dispatch_is_rejected {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (preflight finalEffect : Bool) (phase : Phase) (effect : E) (error : X)
    (constant : ops.INVALID_TRANSITION = Result.ok error) :
    Invocation.dispatch ops (finishedState pending preflight finalEffect) phase effect =
      Result.ok (.Err error, atState pending (.Complete preflight finalEffect) .Halted) := by
  cases phase <;> simp [Invocation.dispatch, Invocation.reject, finishedState, atState, constant]

theorem invalid_progress_rejects_saved_success {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (trace : Trace) (progress : Progress) (reply : O) (error : X)
    (unfinished : progress ≠ .Finished) (constant : ops.INVALID_TRANSITION = Result.ok error) :
    Invocation.into_result ops (atState pending trace progress) (.Ok reply) =
      Result.ok (.Err error) := by
  cases progress <;> simp_all [Invocation.into_result, atState]

theorem ignored_extra_dispatch_rejects_saved_reply {P F E O X : Type}
    (ops : Request P F E O X) (pending : P) (preflight finalEffect : Bool)
    (phase : Phase) (effect : E) (reply : O) (error : X)
    (constant : ops.INVALID_TRANSITION = Result.ok error) :
    (do
      let (_, after) ← Invocation.dispatch ops (finishedState pending preflight finalEffect) phase effect
      Invocation.into_result ops after (.Ok reply)) = Result.ok (.Err error) := by
  rw [finished_dispatch_is_rejected ops pending preflight finalEffect phase effect error constant]
  simp [Invocation.into_result, atState, constant]


theorem halted_dispatch_is_rejected {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (trace : Trace) (phase : Phase) (effect : E) (error : X)
    (constant : ops.INVALID_TRANSITION = Result.ok error) :
    Invocation.dispatch ops (atState pending trace .Halted) phase effect =
      Result.ok (.Err error, atState pending trace .Halted) := by
  cases phase <;> simp [Invocation.dispatch, Invocation.reject, atState, constant]

theorem unfinished_value_is_not_public {P F E O X : Type} (ops : Request P F E O X)
    (pending : P) (trace : Trace) (value : O) (error : X)
    (constant : ops.INVALID_TRANSITION = Result.ok error) :
    Invocation.into_result ops (atState pending trace .Halted) (.Ok value) =
      Result.ok (.Err error) := by
  simp [Invocation.into_result, atState, constant]


end aivm_secrets_garrett_core.read_transition.Proofs
