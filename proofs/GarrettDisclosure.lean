import GarrettManifest

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.credential_use
open aivm_secrets_garrett_core.manifest.Proofs (index_exact)
set_option maxHeartbeats 4000000
noncomputable section
open aivm_secrets_garrett_core.oauth_login.Proofs (bytes_ne_exact)

namespace aivm_secrets_garrett_core.disclosure.Proofs

local instance : DecidableEq (alloc.vec.Vec U8) := Classical.decEq _

def findField (keyName : alloc.vec.Vec U8) : List ((alloc.vec.Vec U8) × Json) → core.result.Result Json UseDenial
  | [] => .Err .Denied
  | (key, value) :: rest => if key = keyName then .Ok value else findField keyName rest

theorem field_loop_contract (fields : alloc.vec.Vec ((alloc.vec.Vec U8) × Json))
    (keyName : alloc.vec.Vec U8) (index : Usize) :
    field_loop fields keyName index ⦃ out => out = findField keyName (fields.val.drop index.val) ⦄ := by
  classical
  suffices ∀ n (i : Usize), fields.length - i.val = n →
      field_loop fields keyName i ⦃ out => out = findField keyName (fields.val.drop i.val) ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [field_loop]
    split
    next inside =>
      have hb : i.val < fields.length := by scalar_tac
      have tail := List.drop_eq_getElem_cons hb
      rw [index_exact fields i hb]
      cases entry : fields.val[i.val] with
      | mk key value =>
        simp only [bind_ok, Aeneas.Std.uncurry]
        rw [bytes_ne_exact]
        simp only [bind_ok]
        by_cases same : key = keyName
        · simp [same, WP.spec_ok, tail, entry, findField]
        · simp only [same, ↓reduceIte]
          obtain ⟨next, returned, next_value⟩ := returned_of_spec (@Usize.add_spec i 1#usize (by scalar_tac))
          rw [returned]
          simp only [bind_ok]
          have recur := ih (fields.length - next.val) (by scalar_tac) next rfl
          apply WP.spec_mono recur
          intro out eq
          simpa [tail, entry, findField, same, next_value] using eq
    next outside =>
      have done : fields.val.length ≤ i.val := by scalar_tac
      simp [WP.spec_ok, List.drop_eq_nil_of_le done, findField]


theorem field_contract (fields : alloc.vec.Vec ((alloc.vec.Vec U8) × Json)) (keyName : alloc.vec.Vec U8) :
    field fields keyName = Result.ok (findField keyName fields.val) := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (field_loop_contract fields keyName 0#usize)
  simpa [field, property] using returned

theorem ignored_field_value_cannot_affect_lookup (keyName hidden : alloc.vec.Vec U8)
    (different : hidden ≠ keyName) (a b : Json) (rest : List ((alloc.vec.Vec U8) × Json))
    (bound : rest.length + 1 ≤ Usize.max) :
    field (alloc.vec.Vec.from ((hidden, a) :: rest) (by simpa using bound)) keyName =
      field (alloc.vec.Vec.from ((hidden, b) :: rest) (by simpa using bound)) keyName := by
  simp [field_contract, findField, different]

def lookupList : List (alloc.vec.Vec U8) → Json → core.result.Result Json UseDenial
  | [], value => .Ok value
  | keyName :: rest, .Object fields =>
      match findField keyName fields.val with
      | .Ok child => lookupList rest child
      | .Err error => .Err error
  | _ :: _, _ => .Err .Denied

theorem lookup_from_contract (value : Json) (path : alloc.vec.Vec (alloc.vec.Vec U8)) (index : Usize) :
    lookup_from value path index ⦃ out => out = lookupList (path.val.drop index.val) value ⦄ := by
  classical
  suffices ∀ n (i : Usize) (v : Json), path.length - i.val = n →
      lookup_from v path i ⦃ out => out = lookupList (path.val.drop i.val) v ⦄ from
    this _ index value rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i v measure
    by_cases done : path.length ≤ i.val
    · cases v <;> rw [lookup_from.eq_def] <;>
        simp [done, lookupList]
    · have hb : i.val < path.length := by scalar_tac
      have tail := List.drop_eq_getElem_cons hb
      have more : ¬ i ≥ path.len := by scalar_tac
      cases v
      case Object fields =>
        rw [lookup_from.eq_def]
        simp only [more, ↓reduceIte]
        rw [index_exact path i hb]
        simp only [bind_ok]
        rw [field_contract]
        simp only [bind_ok]
        cases found : findField path.val[i.val] fields.val with
        | Err error =>
          simp only [WP.spec_ok]
          rw [tail, lookupList, found]
        | Ok child =>
          simp only
          obtain ⟨next, returned, next_value⟩ := returned_of_spec (@Usize.add_spec i 1#usize (by scalar_tac))
          rw [returned]
          simp only [bind_ok]
          have recur := ih (path.length - next.val) (by scalar_tac) next child rfl
          apply WP.spec_mono recur
          intro out eq
          rw [tail, lookupList, found]
          have next_index : next.val = i.val + 1 := by scalar_tac
          simpa only [next_index] using eq
      all_goals
        rw [lookup_from.eq_def]
        simp only [more, ↓reduceIte, WP.spec_ok]
        rw [tail, lookupList]; simp

theorem lookup_contract (value : Json) (path : alloc.vec.Vec (alloc.vec.Vec U8)) :
    lookup value path ⦃ out => out = if 8 < path.length then .Err .Denied else lookupList path.val value ⦄ := by
  simp only [lookup]
  split
  · simp_all
  · apply WP.spec_mono (lookup_from_contract value path 0#usize)
    intro out property
    simp_all


def ChargeSpec (budget size : Nat) (out : core.result.Result Usize UseDenial) : Prop :=
  match out with
  | .Ok remaining => size ≤ budget ∧ remaining.val = budget - size
  | .Err .Denied => budget < size
  | .Err _ => False

theorem charge_contract (budget size : Usize) :
    charge budget size ⦃ out => ChargeSpec budget.val size.val out ⦄ := by
  unfold charge
  repeat' first
  | (solve | simp_all [ChargeSpec, WP.spec_ok]; all_goals scalar_tac)
  | split
  | step

def Nonzero (bytes : List U8) : Prop := ∀ b ∈ bytes, b.val ≠ 0

instance (bytes : List U8) : Decidable (Nonzero bytes) := by
  unfold Nonzero
  infer_instance

theorem nonzero_cons (b : U8) (rest : List U8) : Nonzero (b :: rest) ↔ b.val ≠ 0 ∧ Nonzero rest := by
  simp [Nonzero]

theorem text_safe_loop_contract (bytes : alloc.vec.Vec U8) (index : Usize) :
    text_safe_loop bytes index ⦃ out => out ↔ Nonzero (bytes.val.drop index.val) ⦄ := by
  suffices ∀ n (i : Usize), bytes.length - i.val = n →
      text_safe_loop bytes i ⦃ out => out ↔ Nonzero (bytes.val.drop i.val) ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [text_safe_loop]
    split
    next inside =>
      have hb : i.val < bytes.length := by scalar_tac
      have tail := List.drop_eq_getElem_cons hb
      rw [index_exact bytes i hb]
      simp only [bind_ok]
      split
      next zero => simp_all [WP.spec_ok, Nonzero]
      next nonzero =>
        obtain ⟨next, returned, next_value⟩ := returned_of_spec (@Usize.add_spec i 1#usize (by scalar_tac))
        rw [returned]
        simp only [bind_ok]
        apply WP.spec_mono (ih (bytes.length - next.val) (by scalar_tac) next rfl)
        intro out property
        rw [tail, nonzero_cons]
        have head_nonzero : bytes.val[i.val].val ≠ 0 := by scalar_tac
        have next_index : next.val = i.val + 1 := by scalar_tac
        constructor
        · intro holds
          refine ⟨head_nonzero, ?_⟩
          simpa only [next_index] using property.mp holds
        · intro pair
          apply property.mpr
          simpa only [next_index] using pair.2
    next done =>
      have hb : bytes.val.length ≤ i.val := by scalar_tac
      simp [WP.spec_ok, List.drop_eq_nil_of_le hb, Nonzero]

theorem text_safe_contract (bytes : alloc.vec.Vec U8) :
    text_safe bytes ⦃ out => out ↔ bytes.length ≤ 16384 ∧ Nonzero bytes.val ⦄ := by
  simp only [text_safe]
  split
  next too_long => simp_all [WP.spec_ok]
  next within =>
    apply WP.spec_mono (text_safe_loop_contract bytes 0#usize)
    intro out property
    simp_all


theorem bytes_clone_exact (bytes : alloc.vec.Vec U8) :
    alloc.vec.CloneVec.clone core.clone.CloneU8 bytes = Result.ok bytes := by
  unfold alloc.vec.CloneVec.clone
  obtain ⟨copied, returned, property⟩ := returned_of_spec
    (Slice.clone_spec (s := bytes.slice) (clone := core.clone.CloneU8.clone) (by intro x hx; rfl))
  rw [returned]
  simp only [bind_tc_ok, ← property]


/-- The public value model has no access to a provider's unselected fields. -/
inductive PublicTree where
  | cut
  | unsupported
  | null
  | boolean (value : Bool)
  | integer (value : I64)
  | text (value : alloc.vec.Vec U8)
  | array (values : List PublicTree)
  | object (values : List ((alloc.vec.Vec U8) × PublicTree))

def view : Nat → Json → PublicTree
  | 0, _ => .cut
  | _ + 1, .Null => .null
  | _ + 1, .Boolean value => .boolean value
  | _ + 1, .Integer value => .integer value
  | _ + 1, .Text value => .text value
  | fuel + 1, .Array values => .array (values.val.map (view fuel))
  | fuel + 1, .Object values => .object (values.val.map (fun p => (p.1, view fuel p.2)))
  | _ + 1, .Opaque => .unsupported

def Fits : Nat → Json → Prop
  | 0, _ => False
  | _ + 1, .Opaque => False
  | fuel + 1, .Array values => ∀ value ∈ values.val, Fits fuel value
  | fuel + 1, .Object values => ∀ pair ∈ values.val, Fits fuel pair.2
  | _ + 1, _ => True

def takeBudget (budget size : Nat) : Option Nat := if size ≤ budget then some (budget - size) else none

def fieldsWith (select : Projection → Nat → Option (PublicTree × Nat)) :
    List Field → Nat → Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat)
  | [], budget => some ([], budget)
  | item :: rest, budget => do
      if 64 < item.name.length then none else
        let remaining ← takeBudget budget (6 * item.name.length + 4)
        let (value, next) ← select item.projection remaining
        let (values, final) ← fieldsWith select rest next
        some ((item.name, value) :: values, final)

def itemsWith (select : Json → Nat → Option (PublicTree × Nat)) :
    List Json → Nat → Option (List PublicTree × Nat)
  | [], budget => some ([], budget)
  | item :: rest, budget => do
      let remaining ← takeBudget budget 1
      let (value, next) ← select item remaining
      let (values, final) ← itemsWith select rest next
      some (value :: values, final)

def boundedLookup (value : Json) (path : alloc.vec.Vec (alloc.vec.Vec U8)) : core.result.Result Json UseDenial :=
  if 8 < path.length then .Err .Denied else lookupList path.val value

/-- Independent list recursion specifies paths, public shape, types and cost.
It never invokes the extracted projection functions. -/
def refProject : Nat → Json → Projection → Nat → Option (PublicTree × Nat)
  | 0, _, _, _ => none
  | fuel + 1, value, schema, budget =>
      match boundedLookup value schema.at with
      | .Err _ => none
      | .Ok selected =>
        match schema.kind, selected with
        | .Integer, .Integer n => (takeBudget budget 21).map (fun rest => (.integer n, rest))
        | .Boolean, .Boolean b => (takeBudget budget 5).map (fun rest => (.boolean b, rest))
        | .Null, .Null => (takeBudget budget 4).map (fun rest => (.null, rest))
        | .Text, .Text s =>
            if s.length ≤ 16384 ∧ Nonzero s.val then
              (takeBudget budget (6 * s.length + 2)).map (fun rest => (.text s, rest))
            else none
        | .Object fields, .Object _ =>
            if fields.length = 0 ∨ 32 < fields.length then none else do
              let remaining ← takeBudget budget 2
              let (values, final) ← fieldsWith (fun p b => refProject fuel selected p b) fields.val remaining
              some (.object values, final)
        | .Array item maximum, .Array values =>
            if maximum.val < 1 ∨ 1000 < maximum.val ∨ maximum.val < values.length then none else do
              let remaining ← takeBudget budget 2
              let (values, final) ← itemsWith (fun v b => refProject fuel v item b) values.val remaining
              some (.array values, final)
        | _, _ => none

def refFields (fuel : Nat) (value : Json) (fields : alloc.vec.Vec Field) (budget : Nat) : Option (PublicTree × Nat) := do
  if fields.length = 0 ∨ 32 < fields.length then none else
    let remaining ← takeBudget budget 2
    let (values, final) ← fieldsWith (fun p b => refProject fuel value p b) fields.val remaining
    some (.object values, final)


theorem map_eq_of_fits {α β : Type} (P : α → Prop) (f : α → β)
    (injective : ∀ a b, P a → P b → f a = f b → a = b)
    (xs ys : List α) (fits_xs : ∀ x ∈ xs, P x) (fits_ys : ∀ y ∈ ys, P y)
    (same : xs.map f = ys.map f) : xs = ys := by
  induction xs generalizing ys with
  | nil => cases ys <;> simp_all
  | cons x xs ih =>
    cases ys with
    | nil => simp at same
    | cons y ys =>
      simp only [List.map_cons, List.cons.injEq] at same
      have head := injective x y (fits_xs x (by simp)) (fits_ys y (by simp)) same.1
      subst y
      congr 1
      apply ih ys (by intro z hz; exact fits_xs z (by simp [hz]))
        (by intro z hz; exact fits_ys z (by simp [hz])) same.2

theorem view_injective (fuel : Nat) (a b : Json) (fits_a : Fits fuel a) (fits_b : Fits fuel b)
    (same : view fuel a = view fuel b) : a = b := by
  induction fuel generalizing a b with
  | zero => cases fits_a
  | succ fuel ih =>
    cases a <;> cases b <;> simp only [Fits, view] at fits_a fits_b same
    all_goals try { contradiction }
    all_goals try { cases same; rfl }
    case Array.Array xs ys =>
      have maps := PublicTree.array.inj same
      apply congrArg Json.Array
      apply alloc.vec.Vec.ext
      exact map_eq_of_fits (Fits fuel) (view fuel) ih xs.val ys.val fits_a fits_b maps
    case Object.Object xs ys =>
      have maps := PublicTree.object.inj same
      apply congrArg Json.Object
      apply alloc.vec.Vec.ext
      apply map_eq_of_fits (fun pair => Fits fuel pair.2) (fun pair => (pair.1, view fuel pair.2))
        ?_ xs.val ys.val fits_a fits_b maps
      intro p q hp hq eq
      have keys := congrArg Prod.fst eq
      have values := congrArg Prod.snd eq
      exact Prod.ext keys (ih p.2 q.2 hp hq values)

def ResultMatches (depth : Nat) (expected : Option (PublicTree × Nat))
    (out : core.result.Result Selection UseDenial) : Prop :=
  match out with
  | .Ok selected => Fits depth selected.value ∧ expected = some (view depth selected.value, selected.remaining.val)
  | .Err .Denied => expected = none
  | .Err _ => False

def StateView (depth : Nat) (state : core.result.Result ((alloc.vec.Vec Json) × Usize) UseDenial) :
    Option (List PublicTree × Nat) :=
  match state with
  | .Ok (values, budget) => some (values.val.map (view depth), budget.val)
  | .Err _ => none

def StateFits (depth capacity : Nat) (state : core.result.Result ((alloc.vec.Vec Json) × Usize) UseDenial) : Prop :=
  match state with
  | .Ok (values, _) => (∀ value ∈ values.val, Fits depth value) ∧ values.length + capacity ≤ Usize.max
  | .Err .Denied => True
  | .Err _ => False

def runItems (select : Json → Nat → Option (PublicTree × Nat)) (todo : List Json)
    (state : Option (List PublicTree × Nat)) : Option (List PublicTree × Nat) := do
  let (accumulated, budget) ← state
  let (values, final) ← itemsWith select todo budget
  some (accumulated ++ values, final)

def stepItem (select : Json → Nat → Option (PublicTree × Nat)) (item : Json)
    (state : Option (List PublicTree × Nat)) : Option (List PublicTree × Nat) := do
  let (accumulated, budget) ← state
  let remaining ← takeBudget budget 1
  let (value, final) ← select item remaining
  some (accumulated ++ [value], final)

theorem runItems_cons (select : Json → Nat → Option (PublicTree × Nat)) (item : Json) (rest : List Json)
    (state : Option (List PublicTree × Nat)) :
    runItems select (item :: rest) state = runItems select rest (stepItem select item state) := by
  cases state with
  | none => rfl
  | some pair =>
    rcases pair with ⟨accumulated, budget⟩
    simp only [runItems, stepItem, itemsWith, Option.bind_eq_bind, Option.bind_some]
    cases available : takeBudget budget 1 <;> simp
    case some remaining =>
      cases selected : select item remaining <;> simp
      case some pair =>
        rcases pair with ⟨value, final⟩
        cases tail : itemsWith select rest final
        · simp
        · rename_i result
          rcases result with ⟨values, left⟩
          simp


attribute [local simp] core.result.Result.Insts.CoreOpsTry.branch
attribute [local simp] core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual
attribute [local simp] core.convert.FromSame

theorem array_step_contract (fuel : Usize)
    (recursive : ∀ value schema budget,
      project value schema fuel budget ⦃ out => ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄)
    (value : Json) (schema : Projection) (budget : Usize) (out : alloc.vec.Vec Json) (spare : Nat)
    (fits_out : ∀ item ∈ out.val, Fits fuel.val item) (capacity : out.length + spare < Usize.max) :
    array_step value schema fuel budget out ⦃ result => StateFits fuel.val spare result ∧
      StateView fuel.val result = stepItem (fun v b => refProject fuel.val v schema b) value
        (some (out.val.map (view fuel.val), budget.val)) ⦄ := by
  rw [array_step.eq_def]
  apply WP.spec_bind (charge_contract budget 1#usize)
  intro charged charge_property
  cases charged with
  | Err error =>
    cases error <;> simp_all [ChargeSpec, StateFits, StateView, stepItem, takeBudget]
  | Ok available =>
    have cut : takeBudget budget.val 1 = some available.val := by
      simp_all [ChargeSpec, takeBudget]
    simp
    apply WP.spec_bind (recursive value schema available)
    intro child property
    cases child with
    | Err error =>
      cases error <;> simp_all [ResultMatches, StateFits, StateView, stepItem]
    | Ok selected =>
      obtain ⟨child_fits, child_view⟩ := property
      dsimp only
      rw [bind_ok]
      apply WP.spec_bind (alloc.vec.Vec.push_spec out selected.value (by scalar_tac))
      intro values appended
      simp only [WP.spec_ok]
      constructor
      · constructor
        · intro item member
          rw [appended] at member
          rcases List.mem_append.mp member with old | new
          · exact fits_out item old
          · have eq : item = selected.value := by simpa using new
            simpa [eq] using child_fits
        · simp [appended, alloc.vec.Vec.length]
          scalar_tac
      · simp [StateView, stepItem, cut, child_view, appended, List.map_append]

end aivm_secrets_garrett_core.disclosure.Proofs

end
