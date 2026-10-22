import GarrettDisclosure

/-!
The Aeneas-extracted `disclosure.project` / `project_fields` implementations
feed the production-called `selected_conversion.render` traversal. The
extracted projection theorem already establishes `Fits` for each successful
selection. This module derives an *unbounded structural* invariant from that
bounded certificate: a successfully selected tree has no Opaque node at any
nesting depth.

This is an input-origin theorem, not a theorem about the generic builder's
callbacks or `serde_json`. In particular, it does not identify the bytes
captured by the native adapter with the output of the extracted renderer.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.disclosure (Json Projection Field Selection)

namespace aivm_secrets_garrett_core.selected_conversion.InputProofs

open aivm_secrets_garrett_core.Proofs (returned_of_spec)
open aivm_secrets_garrett_core.disclosure.Proofs

/-- An entire JSON tree is free of the provider-input-only `Opaque` variant.
Unlike `Fits`, this predicate is not parameterized by a proof fuel. -/
inductive OpaqueFree : Json → Prop where
  | null : OpaqueFree .Null
  | boolean (value : Bool) : OpaqueFree (.Boolean value)
  | integer (value : I64) : OpaqueFree (.Integer value)
  | text (value : alloc.vec.Vec U8) : OpaqueFree (.Text value)
  | array (values : alloc.vec.Vec Json)
      (children : ∀ child ∈ values.val, OpaqueFree child) :
      OpaqueFree (.Array values)
  | object (fields : alloc.vec.Vec ((alloc.vec.Vec U8) × Json))
      (children : ∀ field ∈ fields.val, OpaqueFree field.2) :
      OpaqueFree (.Object fields)

/-- The existing extracted projection's `Fits` postcondition excludes Opaque
recursively, not just at the top level of its selected reply. -/
theorem fits_excludes_opaque :
    ∀ depth (value : Json), Fits depth value → OpaqueFree value := by
  intro depth
  induction depth with
  | zero =>
    intro value fits
    exact False.elim fits
  | succ depth ih =>
    intro value fits
    cases value with
    | Null => exact .null
    | Boolean b => exact .boolean b
    | Integer n => exact .integer n
    | Text s => exact .text s
    | Array values =>
      exact .array values (by
        intro child member
        exact ih child (fits child member))
    | Object fields =>
      exact .object fields (by
        intro field member
        exact ih field.2 (fits field member))
    | Opaque => exact False.elim fits

/-- Every successful Aeneas-extracted recursive projection provides a value
whose complete tree excludes `Opaque` (including all array/object children). -/
theorem successful_project_is_opaque_free
    (source : Json) (schema : Projection) (fuel budget : Usize)
    (selected : Selection)
    (returned : disclosure.project source schema fuel budget =
      Result.ok (.Ok selected)) :
    OpaqueFree selected.value := by
  obtain ⟨result, actual, contract⟩ :=
    returned_of_spec (project_contract source schema fuel budget)
  have eq : result = .Ok selected :=
    Result.ok_injective (actual.symm.trans returned)
  rw [eq] at contract
  exact fits_excludes_opaque fuel.val selected.value contract.1

/-- The production `Disclosure::project` entry selects root fields with this
same extracted function. Successful root selection has the same invariant. -/
theorem successful_project_fields_is_opaque_free
    (source : Json) (fields : alloc.vec.Vec Field)
    (fuel budget : Usize) (selected : Selection)
    (returned : disclosure.project_fields source fields fuel budget =
      Result.ok (.Ok selected)) :
    OpaqueFree selected.value := by
  obtain ⟨result, actual, contract⟩ := returned_of_spec
    (project_fields_contract fuel
      (fun value schema remaining => project_contract value schema fuel remaining)
      source fields budget)
  have eq : result = .Ok selected :=
    Result.ok_injective (actual.symm.trans returned)
  rw [eq] at contract
  exact fits_excludes_opaque (fuel.val + 1) selected.value contract.1

/-- A successful list-spec selection retains the host field names exactly,
including their order and multiplicity. Selection cannot substitute names
from the provider document. -/
theorem fieldsWith_preserves_names
    (select : Projection → Nat → Option (PublicTree × Nat))
    (fields : List Field) (budget : Nat)
    (rendered : List ((alloc.vec.Vec U8) × PublicTree)) (remaining : Nat)
    (result : fieldsWith select fields budget = some (rendered, remaining)) :
    rendered.map Prod.fst = fields.map Field.name := by
  induction fields generalizing budget rendered remaining with
  | nil =>
    have pairEq : ([], budget) = (rendered, remaining) := by
      simpa [fieldsWith] using result
    have empty : rendered = [] := (Prod.mk.inj pairEq).1.symm
    subst rendered
    rfl
  | cons field rest ih =>
    by_cases tooLong : 64 < field.name.length
    · simp [fieldsWith, tooLong] at result
    · cases charged : takeBudget budget (6 * field.name.length + 4) with
      | none => simp [fieldsWith, tooLong, charged] at result
      | some available =>
        cases projected : select field.projection available with
        | none => simp [fieldsWith, tooLong, charged, projected] at result
        | some item =>
          rcases item with ⟨selectedTree, next⟩
          cases tail : fieldsWith select rest next with
          | none =>
            simp [fieldsWith, tooLong, charged, projected, tail] at result
          | some pair =>
            rcases pair with ⟨selectedTail, final⟩
            have pairEq : ((field.name, selectedTree) :: selectedTail, final) =
                (rendered, remaining) := by
              simpa [fieldsWith, tooLong, charged, projected, tail] using result
            have renderedEq : rendered = (field.name, selectedTree) :: selectedTail :=
              (Prod.mk.inj pairEq).1.symm
            subst rendered
            simp [ih next selectedTail final tail]

/-- The production-called extracted `project_fields` returns an object whose
root keys are *exactly* those in the host schema. This does not depend on the
raw provider object's keys or on a renderer/serde correspondence hypothesis. -/
theorem successful_project_fields_has_exact_root_keys
    (source : Json) (fields : alloc.vec.Vec Field)
    (fuel budget : Usize) (selected : Selection)
    (returned : disclosure.project_fields source fields fuel budget =
      Result.ok (.Ok selected)) :
    ∃ output : alloc.vec.Vec ((alloc.vec.Vec U8) × Json),
      selected.value = .Object output ∧
      output.val.map Prod.fst = fields.val.map Field.name := by
  obtain ⟨result, actual, contract⟩ := returned_of_spec
    (project_fields_contract fuel
      (fun value schema remaining => project_contract value schema fuel remaining)
      source fields budget)
  have eq : result = .Ok selected :=
    Result.ok_injective (actual.symm.trans returned)
  rw [eq] at contract
  obtain ⟨_, selectedSpec⟩ := contract
  by_cases invalid : fields.length = 0 ∨ 32 < fields.length
  · have impossible : refFields fuel.val source fields budget.val = none := by
      simp only [refFields, invalid, ↓reduceIte]
    rw [impossible] at selectedSpec
    cases selectedSpec
  · cases charged : takeBudget budget.val 2 with
    | none =>
      have impossible : refFields fuel.val source fields budget.val = none := by
        simp only [refFields, invalid, ↓reduceIte, charged,
          Option.bind_eq_bind]
        rfl
      rw [impossible] at selectedSpec
      cases selectedSpec
    | some available =>
      cases captured : fieldsWith
          (fun p b => refProject fuel.val source p b) fields.val available with
      | none =>
        have impossible : refFields fuel.val source fields budget.val = none := by
          simp only [refFields, invalid, ↓reduceIte, charged,
            Option.bind_eq_bind, Option.bind_some, captured]
          rfl
        rw [impossible] at selectedSpec
        cases selectedSpec
      | some pair =>
        rcases pair with ⟨publicFields, final⟩
        have valueSpec : some (PublicTree.object publicFields, final) =
            some (view (fuel.val + 1) selected.value, selected.remaining.val) := by
          simpa only [refFields, invalid, ↓reduceIte, charged,
            Option.bind_eq_bind, Option.bind_some, captured] using selectedSpec
        have selectedView : view (fuel.val + 1) selected.value =
            .object publicFields :=
          (congrArg Prod.fst (Option.some.inj valueSpec)).symm
        cases valueEq : selected.value with
        | Object output =>
          refine ⟨output, rfl, ?_⟩
          have objectEq : PublicTree.object
              (output.val.map (fun p => (p.1, view fuel.val p.2))) =
              PublicTree.object publicFields := by
            simpa only [valueEq, view] using selectedView
          have exactFields :
              output.val.map (fun p => (p.1, view fuel.val p.2)) = publicFields :=
            PublicTree.object.inj objectEq
          have exactNames : output.val.map Prod.fst = publicFields.map Prod.fst := by
            calc
              output.val.map Prod.fst =
                  (output.val.map (fun p => (p.1, view fuel.val p.2))).map Prod.fst := by
                    simp only [List.map_map]
                    rfl
              _ = publicFields.map Prod.fst :=
                congrArg (List.map Prod.fst) exactFields
          rw [exactNames]
          exact fieldsWith_preserves_names
            (fun p b => refProject fuel.val source p b)
            fields.val available publicFields final captured
        | Null => simp [valueEq, view] at selectedView
        | Boolean _ => simp [valueEq, view] at selectedView
        | Integer _ => simp [valueEq, view] at selectedView
        | Text _ => simp [valueEq, view] at selectedView
        | Array _ => simp [valueEq, view] at selectedView
        | Opaque => simp [valueEq, view] at selectedView

/-- The extracted source selects exactly the host's requested root names and
excludes opaque leaves recursively before calling the native renderer. -/
theorem successful_project_fields_has_public_shape
    (source : Json) (fields : alloc.vec.Vec Field)
    (fuel budget : Usize) (selected : Selection)
    (returned : disclosure.project_fields source fields fuel budget =
      Result.ok (.Ok selected)) :
    OpaqueFree selected.value ∧
    ∃ output : alloc.vec.Vec ((alloc.vec.Vec U8) × Json),
      selected.value = .Object output ∧
      output.val.map Prod.fst = fields.val.map Field.name := by
  exact ⟨successful_project_fields_is_opaque_free
    source fields fuel budget selected returned,
    successful_project_fields_has_exact_root_keys
    source fields fuel budget selected returned⟩

end aivm_secrets_garrett_core.selected_conversion.InputProofs
