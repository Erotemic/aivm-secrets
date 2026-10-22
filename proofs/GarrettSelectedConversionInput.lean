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

end aivm_secrets_garrett_core.selected_conversion.InputProofs
