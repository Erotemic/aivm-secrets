import GarrettManifest

/-!
Implementation refinement for the typed response filter extracted from Rust.
The list specification fixes selected paths, output names, types and failure
behavior independently of the Rust loops. Successful outputs fit the declared
proof depth, making the public view lossless. JSON decoding/rendering, transport,
reflection checks and provider semantics remain adapter assumptions.
-/

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

theorem runItems_nil (select : Json → Nat → Option (PublicTree × Nat))
    (state : Option (List PublicTree × Nat)) : runItems select [] state = state := by
  cases state with
  | none => rfl
  | some pair => cases pair; simp [runItems, itemsWith]

theorem array_from_loop_contract (fuel : Usize)
    (recursive : ∀ value schema budget,
      project value schema fuel budget ⦃ out => ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄)
    (values : alloc.vec.Vec Json) (schema : Projection) (index : Usize)
    (state : core.result.Result ((alloc.vec.Vec Json) × Usize) UseDenial)
    (initial : StateFits fuel.val (values.length - index.val) state) :
    array_from_loop values schema fuel index state ⦃ result => StateFits fuel.val 0 result ∧
      StateView fuel.val result = runItems (fun v b => refProject fuel.val v schema b)
        (values.val.drop index.val) (StateView fuel.val state) ⦄ := by
  suffices ∀ n (i : Usize) (s : core.result.Result ((alloc.vec.Vec Json) × Usize) UseDenial),
      values.length - i.val = n → StateFits fuel.val n s →
      array_from_loop values schema fuel i s ⦃ result => StateFits fuel.val 0 result ∧
        StateView fuel.val result = runItems (fun v b => refProject fuel.val v schema b)
          (values.val.drop i.val) (StateView fuel.val s) ⦄ from
    this _ index state rfl initial
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i s measure fits
    rw [array_from_loop.eq_def]
    by_cases inside : i < values.len
    · simp only [inside, ↓reduceIte]

      have hb : i.val < values.length := by scalar_tac
      have tail := List.drop_eq_getElem_cons hb
      obtain ⟨next, returned, next_value⟩ := returned_of_spec (@Usize.add_spec i 1#usize (by scalar_tac))
      cases s with
      | Err error =>
        cases error <;> simp only [StateFits] at fits
        simp only [bind_ok, returned]
        apply WP.spec_mono (ih (values.length - next.val) (by scalar_tac) next (.Err .Denied) rfl trivial)
        intro result property
        simpa [StateView, runItems] using property
      | Ok pair =>
        rcases pair with ⟨out, budget⟩
        obtain ⟨fits_out, capacity⟩ := fits
        rw [index_exact values i hb]
        simp only [bind_ok]
        apply WP.spec_bind (array_step_contract fuel recursive values.val[i.val] schema budget out
          (values.length - next.val) fits_out (by scalar_tac))
        intro stepped property
        rw [returned]
        simp only [bind_ok]
        apply WP.spec_mono (ih (values.length - next.val) (by scalar_tac) next stepped rfl property.1)
        intro result complete
        refine ⟨complete.1, ?_⟩
        rw [complete.2, property.2, tail, runItems_cons]
        simp [next_value, StateView]
    · simp only [inside, ↓reduceIte]

      have hb : values.val.length ≤ i.val := by scalar_tac
      simp only [WP.spec_ok]
      refine ⟨?_, ?_⟩
      · simpa [StateFits, ← measure, Nat.sub_eq_zero_of_le hb] using fits
      · rw [List.drop_eq_nil_of_le hb, runItems_nil]

theorem array_from_contract (fuel : Usize)
    (recursive : ∀ value schema budget,
      project value schema fuel budget ⦃ out => ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄)
    (values : alloc.vec.Vec Json) (schema : Projection) (budget index : Usize) (out : alloc.vec.Vec Json)
    (initial : StateFits fuel.val (values.length - index.val) (.Ok (out, budget))) :
    array_from values schema fuel budget index out ⦃ result =>
      ResultMatches (fuel.val + 1)
        ((runItems (fun v b => refProject fuel.val v schema b) (values.val.drop index.val)
          (some (out.val.map (view fuel.val), budget.val))).map (fun p => (PublicTree.array p.1, p.2))) result ⦄ := by
  rw [array_from.eq_def]
  apply WP.spec_bind (array_from_loop_contract fuel recursive values schema index (.Ok (out, budget)) initial)
  intro state property
  cases state with
  | Err error => cases error <;> simp_all [StateFits, StateView, ResultMatches]
  | Ok pair =>
    rcases pair with ⟨selected, remaining⟩
    apply (WP.spec_ok _).mpr
    change Fits (fuel.val + 1) (Json.Array selected) ∧ _
    constructor
    · exact property.1.1
    · have exact_run := property.2
      simp only [StateView] at exact_run
      rw [← exact_run]
      rfl

def FieldStateView (depth : Nat)
    (state : core.result.Result ((alloc.vec.Vec ((alloc.vec.Vec U8) × Json)) × Usize) UseDenial) :
    Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat) :=
  match state with
  | .Ok (values, budget) => some (values.val.map (fun p => (p.1, view depth p.2)), budget.val)
  | .Err _ => none

def FieldStateFits (depth capacity : Nat)
    (state : core.result.Result ((alloc.vec.Vec ((alloc.vec.Vec U8) × Json)) × Usize) UseDenial) : Prop :=
  match state with
  | .Ok (values, _) => (∀ pair ∈ values.val, Fits depth pair.2) ∧ values.length + capacity ≤ Usize.max
  | .Err .Denied => True
  | .Err _ => False

def runFields (select : Projection → Nat → Option (PublicTree × Nat)) (todo : List Field)
    (state : Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat)) :
    Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat) := do
  let (accumulated, budget) ← state
  let (values, final) ← fieldsWith select todo budget
  some (accumulated ++ values, final)

def stepField (select : Projection → Nat → Option (PublicTree × Nat)) (item : Field)
    (state : Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat)) :
    Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat) := do
  let (accumulated, budget) ← state
  if 64 < item.name.length then none else
    let remaining ← takeBudget budget (6 * item.name.length + 4)
    let (value, final) ← select item.projection remaining
    some (accumulated ++ [(item.name, value)], final)

theorem runFields_cons (select : Projection → Nat → Option (PublicTree × Nat)) (item : Field) (rest : List Field)
    (state : Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat)) :
    runFields select (item :: rest) state = runFields select rest (stepField select item state) := by
  cases state with
  | none => rfl
  | some pair =>
    rcases pair with ⟨accumulated, budget⟩
    simp only [runFields, stepField, fieldsWith, Option.bind_eq_bind, Option.bind_some]
    by_cases large : 64 < item.name.length
    · simp [large]
    · simp only [large, ↓reduceIte]
      cases available : takeBudget budget (6 * item.name.length + 4) <;> simp
      case some remaining =>
        cases selected : select item.projection remaining <;> simp
        case some pair =>
          rcases pair with ⟨value, final⟩
          cases tail : fieldsWith select rest final
          · simp
          · rename_i result
            rcases result with ⟨values, left⟩
            simp

theorem runFields_nil (select : Projection → Nat → Option (PublicTree × Nat))
    (state : Option (List ((alloc.vec.Vec U8) × PublicTree) × Nat)) : runFields select [] state = state := by
  cases state with
  | none => rfl
  | some pair => cases pair; simp [runFields, fieldsWith]

theorem field_step_contract (fuel : Usize)
    (recursive : ∀ value schema budget,
      project value schema fuel budget ⦃ out => ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄)
    (value : Json) (item : Field) (budget : Usize) (out : alloc.vec.Vec ((alloc.vec.Vec U8) × Json)) (spare : Nat)
    (fits_out : ∀ pair ∈ out.val, Fits fuel.val pair.2) (capacity : out.length + spare < Usize.max) :
    field_step value item fuel budget out ⦃ result => FieldStateFits fuel.val spare result ∧
      FieldStateView fuel.val result = stepField (fun p b => refProject fuel.val value p b) item
        (some (out.val.map (fun p => (p.1, view fuel.val p.2)), budget.val)) ⦄ := by
  rw [field_step.eq_def]
  by_cases large : item.name.len > 64#usize
  · have exceeds : 64 < item.name.length := by scalar_tac
    simp [large, FieldStateFits, FieldStateView, stepField, exceeds, WP.spec_ok]
  · have within : item.name.length ≤ 64 := by scalar_tac
    simp only [large, ↓reduceIte]
    obtain ⟨scaled, mul_return, mul_value⟩ := returned_of_spec
      (@Usize.mul_spec 6#usize item.name.len (by scalar_tac))
    rw [mul_return]
    simp only [bind_ok]
    obtain ⟨cost, add_return, add_value⟩ := returned_of_spec
      (@Usize.add_spec scaled 4#usize (by scalar_tac))
    rw [add_return]
    simp only [bind_ok]
    have cost_value : cost.val = 6 * item.name.length + 4 := by scalar_tac
    apply WP.spec_bind (charge_contract budget cost)
    intro charged charge_property
    cases charged with
    | Err error =>
      cases error with
      | InvalidCapability => exact False.elim charge_property
      | Upstream => exact False.elim charge_property
      | Denied =>
        have insufficient : ¬ 6 * item.name.length + 4 ≤ budget.val := by
          simp only [ChargeSpec] at charge_property
          omega
        simp [FieldStateFits, FieldStateView, stepField, takeBudget, insufficient]
    | Ok available =>
      have cut : takeBudget budget.val (6 * item.name.length + 4) = some available.val := by
        simp_all [ChargeSpec, takeBudget]
      simp
      apply WP.spec_bind (recursive value item.projection available)
      intro child property
      cases child with
      | Err error =>
        cases error <;> simp_all [ResultMatches, FieldStateFits, FieldStateView, stepField]
      | Ok selected =>
        obtain ⟨child_fits, child_view⟩ := property
        dsimp only
        rw [bind_ok, bytes_clone_exact]
        simp only [bind_ok]
        apply WP.spec_bind (alloc.vec.Vec.push_spec out (item.name, selected.value) (by scalar_tac))
        intro values appended
        simp only [WP.spec_ok]
        constructor
        · constructor
          · intro pair member
            rw [appended] at member
            rcases List.mem_append.mp member with old | new
            · exact fits_out pair old
            · have eq : pair = (item.name, selected.value) := by simpa using new
              simpa [eq] using child_fits
          · simp [appended, alloc.vec.Vec.length]
            scalar_tac
        · simp [FieldStateView, stepField, cut, child_view, appended, List.map_append, within]

theorem fields_from_loop_contract (fuel : Usize)
    (recursive : ∀ value schema budget,
      project value schema fuel budget ⦃ out => ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄)
    (value : Json) (fields : alloc.vec.Vec Field) (index : Usize)
    (state : core.result.Result ((alloc.vec.Vec ((alloc.vec.Vec U8) × Json)) × Usize) UseDenial)
    (initial : FieldStateFits fuel.val (fields.length - index.val) state) :
    fields_from_loop value fields fuel index state ⦃ result => FieldStateFits fuel.val 0 result ∧
      FieldStateView fuel.val result = runFields (fun p b => refProject fuel.val value p b)
        (fields.val.drop index.val) (FieldStateView fuel.val state) ⦄ := by
  suffices ∀ n (i : Usize) (s : core.result.Result ((alloc.vec.Vec ((alloc.vec.Vec U8) × Json)) × Usize) UseDenial),
      fields.length - i.val = n → FieldStateFits fuel.val n s →
      fields_from_loop value fields fuel i s ⦃ result => FieldStateFits fuel.val 0 result ∧
        FieldStateView fuel.val result = runFields (fun p b => refProject fuel.val value p b)
          (fields.val.drop i.val) (FieldStateView fuel.val s) ⦄ from
    this _ index state rfl initial
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i s measure fits
    rw [fields_from_loop.eq_def]
    by_cases inside : i < fields.len
    · simp only [inside, ↓reduceIte]

      have hb : i.val < fields.length := by scalar_tac
      have tail := List.drop_eq_getElem_cons hb
      obtain ⟨next, returned, next_value⟩ := returned_of_spec (@Usize.add_spec i 1#usize (by scalar_tac))
      cases s with
      | Err error =>
        cases error <;> simp only [FieldStateFits] at fits
        simp only [bind_ok, returned]
        apply WP.spec_mono (ih (fields.length - next.val) (by scalar_tac) next (.Err .Denied) rfl trivial)
        intro result property
        simpa [FieldStateView, runFields] using property
      | Ok pair =>
        rcases pair with ⟨out, budget⟩
        obtain ⟨fits_out, capacity⟩ := fits
        rw [index_exact fields i hb]
        simp only [bind_ok]
        apply WP.spec_bind (field_step_contract fuel recursive value fields.val[i.val] budget out
          (fields.length - next.val) fits_out (by scalar_tac))
        intro stepped property
        rw [returned]
        simp only [bind_ok]
        apply WP.spec_mono (ih (fields.length - next.val) (by scalar_tac) next stepped rfl property.1)
        intro result complete
        refine ⟨complete.1, ?_⟩
        rw [complete.2, property.2, tail, runFields_cons]
        simp [next_value, FieldStateView]
    · simp only [inside, ↓reduceIte]

      have hb : fields.val.length ≤ i.val := by scalar_tac
      simp only [WP.spec_ok]
      refine ⟨?_, ?_⟩
      · simpa [FieldStateFits, ← measure, Nat.sub_eq_zero_of_le hb] using fits
      · rw [List.drop_eq_nil_of_le hb, runFields_nil]

theorem fields_from_contract (fuel : Usize)
    (recursive : ∀ value schema budget,
      project value schema fuel budget ⦃ out => ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄)
    (value : Json) (fields : alloc.vec.Vec Field) (budget index : Usize) (out : alloc.vec.Vec ((alloc.vec.Vec U8) × Json))
    (initial : FieldStateFits fuel.val (fields.length - index.val) (.Ok (out, budget))) :
    fields_from value fields fuel budget index out ⦃ result =>
      ResultMatches (fuel.val + 1)
        ((runFields (fun p b => refProject fuel.val value p b) (fields.val.drop index.val)
          (some (out.val.map (fun p => (p.1, view fuel.val p.2)), budget.val))).map (fun p => (PublicTree.object p.1, p.2))) result ⦄ := by
  rw [fields_from.eq_def]
  apply WP.spec_bind (fields_from_loop_contract fuel recursive value fields index (.Ok (out, budget)) initial)
  intro state property
  cases state with
  | Err error => cases error <;> simp_all [FieldStateFits, FieldStateView, ResultMatches]
  | Ok pair =>
    rcases pair with ⟨selected, remaining⟩
    apply (WP.spec_ok _).mpr
    change Fits (fuel.val + 1) (Json.Object selected) ∧ _
    constructor
    · exact property.1.1
    · have exact_run := property.2
      simp only [FieldStateView] at exact_run
      rw [← exact_run]
      rfl

theorem project_fields_contract (fuel : Usize)
    (recursive : ∀ value schema budget,
      project value schema fuel budget ⦃ out => ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄)
    (value : Json) (fields : alloc.vec.Vec Field) (budget : Usize) :
    project_fields value fields fuel budget ⦃ result =>
      ResultMatches (fuel.val + 1) (refFields fuel.val value fields budget.val) result ⦄ := by
  rw [project_fields.eq_def]
  by_cases empty : fields.len = 0#usize
  · have zero : fields.length = 0 := by scalar_tac
    simp only [empty, ↓reduceIte, WP.spec_ok]
    simp [zero, refFields, ResultMatches]
  · simp only [empty, ↓reduceIte]
    by_cases large : fields.len > 32#usize
    · have exceeds : 32 < fields.length := by scalar_tac
      simp [large, exceeds, refFields, ResultMatches, WP.spec_ok]
    · have within : ¬ (fields.length = 0 ∨ 32 < fields.length) := by scalar_tac
      simp only [large, ↓reduceIte]
      apply WP.spec_bind (charge_contract budget 2#usize)
      intro charged property
      cases charged with
      | Err error =>
        cases error <;> simp_all [ChargeSpec, ResultMatches, refFields, takeBudget]
      | Ok available =>
        have cut : takeBudget budget.val 2 = some available.val := by
          simp_all [ChargeSpec, takeBudget]
        simp
        apply WP.spec_mono (fields_from_contract fuel recursive value fields available 0#usize
          (alloc.vec.Vec.new _) (by simp [FieldStateFits]))
        intro result contract
        have spec_eq : refFields fuel.val value fields budget.val =
            ((fieldsWith (fun p b => refProject fuel.val value p b) fields.val available.val).map
              (fun p => (PublicTree.object p.1, p.2))) := by
          simp only [refFields, within, ↓reduceIte, cut, Option.bind_eq_bind, Option.bind_some]
          cases fieldsWith (fun p b => refProject fuel.val value p b) fields.val available.val <;> rfl
        rw [spec_eq]
        simpa [runFields] using contract

theorem findField_denial (keyName : alloc.vec.Vec U8) (fields : List ((alloc.vec.Vec U8) × Json))
    (error : UseDenial) (denied : findField keyName fields = .Err error) : error = .Denied := by
  induction fields with
  | nil => simpa [findField] using denied.symm
  | cons pair rest ih =>
    rcases pair with ⟨key, value⟩
    by_cases same : key = keyName
    · simp [findField, same] at denied
    · exact ih (by simpa [findField, same] using denied)

theorem lookupList_denial (path : List (alloc.vec.Vec U8)) (value : Json)
    (error : UseDenial) (denied : lookupList path value = .Err error) : error = .Denied := by
  induction path generalizing value with
  | nil => simp [lookupList] at denied
  | cons key rest ih =>
    cases value <;> simp only [lookupList] at denied
    all_goals try { simpa using denied.symm }
    case Object fields =>
      cases found : findField key fields.val with
      | Err e =>
        have eq : error = e := by simpa [found] using denied.symm
        exact eq.trans (findField_denial key fields.val e found)
      | Ok child => exact ih child (by simpa [found] using denied)

theorem boundedLookup_denial (value : Json) (path : alloc.vec.Vec (alloc.vec.Vec U8))
    (error : UseDenial) (denied : boundedLookup value path = .Err error) : error = .Denied := by
  by_cases large : 8 < path.length
  · simpa [boundedLookup, large] using denied.symm
  · exact lookupList_denial path.val value error (by simpa [boundedLookup, large] using denied)

theorem project_contract (value : Json) (schema : Projection) (fuel budget : Usize) :
    project value schema fuel budget ⦃ result =>
      ResultMatches fuel.val (refProject fuel.val value schema budget.val) result ⦄ := by
  suffices ∀ n (f : Usize), f.val = n → ∀ value schema budget,
      project value schema f budget ⦃ result =>
        ResultMatches f.val (refProject f.val value schema budget.val) result ⦄ from
    this fuel.val fuel rfl value schema budget
  intro n
  induction n with
  | zero =>
    intro f eq value schema budget
    have zero : f = 0#usize := by scalar_tac
    rw [project.eq_def]
    simp [zero, ResultMatches, refProject, WP.spec_ok]
  | succ n ih =>
    intro f eq value schema budget
    have positive : f ≠ 0#usize := by scalar_tac
    obtain ⟨lower, lower_return, lower_value⟩ := returned_of_spec (@Usize.sub_spec f 1#usize (by scalar_tac))
    have lower_nat : lower.val = n := by scalar_tac
    have recursive : ∀ v p b, project v p lower b ⦃ out =>
        ResultMatches lower.val (refProject lower.val v p b.val) out ⦄ := ih lower lower_nat
    rw [project.eq_def]
    simp only [positive, ↓reduceIte]
    apply WP.spec_bind (lookup_contract value schema.at)
    intro selected lookup_property
    have matched : boundedLookup value schema.at = selected := lookup_property.symm
    cases selected with
    | Err error =>
      have denied := boundedLookup_denial value schema.at error matched
      subst error
      simp [eq, refProject, matched, ResultMatches, WP.spec_ok]
    | Ok child =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
      cases kind : schema.kind <;> cases child
      all_goals try { solve | simp [eq, refProject, matched, kind, ResultMatches, WP.spec_ok] }
      case Integer.Integer integer =>
        simp only [eq, refProject, matched, kind]
        apply WP.spec_bind (charge_contract budget 21#usize)
        intro charged property
        cases charged with
        | Err error => cases error <;> simp_all [ChargeSpec, ResultMatches, takeBudget]
        | Ok remaining =>
          simp_all [ChargeSpec, ResultMatches, Fits, view, takeBudget, WP.spec_ok]
      case Boolean.Boolean boolean =>
        simp only [eq, refProject, matched, kind]
        apply WP.spec_bind (charge_contract budget 5#usize)
        intro charged property
        cases charged with
        | Err error => cases error <;> simp_all [ChargeSpec, ResultMatches, takeBudget]
        | Ok remaining =>
          simp_all [ChargeSpec, ResultMatches, Fits, view, takeBudget, WP.spec_ok]
      case Null.Null =>
        simp only [eq, refProject, matched, kind]
        apply WP.spec_bind (charge_contract budget 4#usize)
        intro charged property
        cases charged with
        | Err error => cases error <;> simp_all [ChargeSpec, ResultMatches, takeBudget]
        | Ok remaining =>
          simp_all [ChargeSpec, ResultMatches, Fits, view, takeBudget, WP.spec_ok]
      case Text.Text bytes =>
        simp only [eq, refProject, matched, kind]
        apply WP.spec_bind (text_safe_contract bytes)
        intro safe safety
        cases safe with
        | false => simp_all [ResultMatches]
        | true =>
          have bound : bytes.length ≤ 16384 := safety.mp rfl |>.1
          simp only [↓reduceIte]
          rw [bytes_clone_exact]
          simp only [bind_ok]
          obtain ⟨scaled, mul_return, mul_value⟩ := returned_of_spec
            (@Usize.mul_spec 6#usize bytes.len (by scalar_tac))
          rw [mul_return]
          simp only [bind_ok]
          obtain ⟨cost, add_return, add_value⟩ := returned_of_spec
            (@Usize.add_spec scaled 2#usize (by scalar_tac))
          rw [add_return]
          simp only [bind_ok]
          have cost_value : cost.val = 6 * bytes.length + 2 := by scalar_tac
          apply WP.spec_bind (charge_contract budget cost)
          intro charged property
          cases charged with
          | Err error => cases error <;> simp_all [ChargeSpec, ResultMatches, takeBudget]
          | Ok remaining =>
            simp_all [ChargeSpec, ResultMatches, Fits, view, takeBudget, WP.spec_ok]
      case Object.Object fields members =>
        rw [lower_return]
        simp only [bind_ok]
        apply WP.spec_mono (project_fields_contract lower recursive (.Object members) fields budget)
        intro result property
        simpa [eq, refProject, matched, kind, refFields, lower_nat] using property
      case Array.Array item maximum values =>
        by_cases small : maximum < 1#usize
        · have invalid : maximum.val < 1 := by scalar_tac
          simp [small, eq, refProject, matched, kind, invalid, ResultMatches, WP.spec_ok]
        · simp only [small, ↓reduceIte]
          by_cases large : maximum > 1000#usize
          · have invalid : 1000 < maximum.val := by scalar_tac
            simp [large, eq, refProject, matched, kind, invalid, ResultMatches, WP.spec_ok]
          · simp only [large, ↓reduceIte]
            by_cases overflow : values.len > maximum
            · have invalid : maximum.val < values.length := by scalar_tac
              simp [overflow, eq, refProject, matched, kind, invalid, ResultMatches, WP.spec_ok]
            · have valid : ¬ (maximum.val < 1 ∨ 1000 < maximum.val ∨ maximum.val < values.length) := by scalar_tac
              simp only [overflow, ↓reduceIte]
              rw [lower_return]
              simp only [bind_ok]
              apply WP.spec_bind (charge_contract budget 2#usize)
              intro charged property
              cases charged with
              | Err error =>
                simp only [eq, refProject, matched, kind, valid, ↓reduceIte]
                cases error <;> simp_all [ChargeSpec, ResultMatches, takeBudget]
              | Ok available =>
                have cut : takeBudget budget.val 2 = some available.val := by
                  simp_all [ChargeSpec, takeBudget]
                simp
                apply WP.spec_mono (array_from_contract lower recursive values item available 0#usize
                  (alloc.vec.Vec.new _) (by simp [StateFits]))
                intro result property
                have spec_eq : refProject f.val value schema budget.val =
                    ((itemsWith (fun v b => refProject lower.val v item b) values.val available.val).map
                      (fun p => (PublicTree.array p.1, p.2))) := by
                  simp only [eq, refProject, matched, kind, valid, ↓reduceIte, cut,
                    Option.bind_eq_bind, Option.bind_some, lower_nat]
                  cases itemsWith (fun v b => refProject n v item b) values.val available.val <;> rfl
                rw [spec_eq]
                simpa [eq, lower_nat, runItems] using property

/-- The public view is lossless for successful outputs, including failure class
and the remaining construction budget. -/
theorem result_matches_unique (depth : Nat) (expected : Option (PublicTree × Nat))
    (a b : core.result.Result Selection UseDenial)
    (ha : ResultMatches depth expected a) (hb : ResultMatches depth expected b) : a = b := by
  cases a with
  | Err error =>
    cases error <;> simp only [ResultMatches] at ha
    cases b with
    | Err error => cases error <;> simp_all [ResultMatches]
    | Ok selected => simp [ResultMatches, ha] at hb
  | Ok selected =>
    cases b with
    | Err error => cases error <;> simp_all [ResultMatches]
    | Ok other =>
      obtain ⟨fits_a, same_a⟩ := ha
      obtain ⟨fits_b, same_b⟩ := hb
      have pair_eq := Option.some.inj (same_a.symm.trans same_b)
      have values_eq := view_injective depth selected.value other.value fits_a fits_b (congrArg Prod.fst pair_eq)
      have budget_eq : selected.remaining = other.remaining := by
        have numeric := congrArg Prod.snd pair_eq
        scalar_tac
      cases selected
      cases other
      simp_all

theorem refProject_lookup_congruence (depth : Nat) (schema : Projection) (a b : Json) (budget : Nat)
    (same : boundedLookup a schema.at = boundedLookup b schema.at) :
    refProject depth a schema budget = refProject depth b schema budget := by
  cases depth with
  | zero => rfl
  | succ depth => simp only [refProject, same]

/-- Equal selected inputs produce exactly equal owned outputs, even when the
provider documents differ outside the selected path. -/
theorem selected_path_noninterference (schema : Projection) (a b : Json) (fuel budget : Usize)
    (same : boundedLookup a schema.at = boundedLookup b schema.at) :
    project a schema fuel budget = project b schema fuel budget := by
  obtain ⟨left, left_return, left_matches⟩ := returned_of_spec (project_contract a schema fuel budget)
  obtain ⟨right, right_return, right_matches⟩ := returned_of_spec (project_contract b schema fuel budget)
  have spec_same := refProject_lookup_congruence fuel.val schema a b budget.val same
  rw [← spec_same] at right_matches
  rw [left_return, right_return, result_matches_unique fuel.val _ left right left_matches right_matches]

theorem fieldsWith_congruence (selectA selectB : Projection → Nat → Option (PublicTree × Nat))
    (fields : List Field) (budget : Nat)
    (same : ∀ field ∈ fields, ∀ b, selectA field.projection b = selectB field.projection b) :
    fieldsWith selectA fields budget = fieldsWith selectB fields budget := by
  induction fields generalizing budget with
  | nil => rfl
  | cons item rest ih =>
    simp only [fieldsWith]
    by_cases large : 64 < item.name.length
    · simp [large]
    · simp only [large, ↓reduceIte]
      cases cut : takeBudget budget (6 * item.name.length + 4) with
      | none => rfl
      | some remaining =>
        simp only [Option.bind_eq_bind, Option.bind_some, same item (by simp) remaining]
        cases selected : selectB item.projection remaining with
        | none => rfl
        | some pair =>
          rcases pair with ⟨value, next⟩
          simp only [Option.bind_some]
          rw [ih next (by intro field member b; exact same field (by simp [member]) b)]

/-- Root fields can change arbitrarily outside every schema-selected path.
The comparison includes successful outputs and denial behavior. -/
theorem root_fields_noninterference (a b : Json) (fields : alloc.vec.Vec Field) (fuel budget : Usize)
    (same : ∀ field ∈ fields.val,
      boundedLookup a field.projection.at = boundedLookup b field.projection.at) :
    project_fields a fields fuel budget = project_fields b fields fuel budget := by
  have recursive : ∀ value schema budget, project value schema fuel budget ⦃ out =>
      ResultMatches fuel.val (refProject fuel.val value schema budget.val) out ⦄ :=
    fun value schema budget => project_contract value schema fuel budget
  have spec_same : refFields fuel.val a fields budget.val = refFields fuel.val b fields budget.val := by
    unfold refFields
    by_cases invalid : fields.length = 0 ∨ 32 < fields.length
    · simp only [invalid, ↓reduceIte]
    · simp only [invalid, ↓reduceIte]
      cases cut : takeBudget budget.val 2 with
      | none => rfl
      | some remaining =>
        simp only [Option.bind_eq_bind, Option.bind_some]
        rw [fieldsWith_congruence (fun p bgt => refProject fuel.val a p bgt)
          (fun p bgt => refProject fuel.val b p bgt) fields.val remaining
          (by intro field member bgt; exact refProject_lookup_congruence _ _ _ _ _ (same field member))]
  obtain ⟨left, left_return, left_matches⟩ := returned_of_spec
    (project_fields_contract fuel recursive a fields budget)
  obtain ⟨right, right_return, right_matches⟩ := returned_of_spec
    (project_fields_contract fuel recursive b fields budget)
  rw [← spec_same] at right_matches
  rw [left_return, right_return,
    result_matches_unique (fuel.val + 1) _ left right left_matches right_matches]

/-- A provider's ignored leading field can contain arbitrary JSON. No bytes
from that value can change the selected projection or its denial outcome. -/
theorem ignored_input_field_noninterference (schema : Projection) (keyName hidden : alloc.vec.Vec U8)
    (different : hidden ≠ keyName) (pathTail : List (alloc.vec.Vec U8))
    (starts : schema.at.val = keyName :: pathTail) (a b : Json)
    (rest : List ((alloc.vec.Vec U8) × Json)) (bound : rest.length + 1 ≤ Usize.max)
    (fuel budget : Usize) :
    project (.Object (alloc.vec.Vec.from ((hidden, a) :: rest) (by simpa using bound))) schema fuel budget =
      project (.Object (alloc.vec.Vec.from ((hidden, b) :: rest) (by simpa using bound))) schema fuel budget := by
  apply selected_path_noninterference
  unfold boundedLookup
  simp [starts, lookupList, findField, different]

def booleanSchema : Projection := .mk (alloc.vec.Vec.new _) .Boolean

theorem boolean_projection_positive_witness :
    project (.Boolean true) booleanSchema 1#usize 5#usize =
      Result.ok (.Ok {value := .Boolean true, remaining := 0#usize}) := by
  obtain ⟨out, returned, matched_result⟩ := returned_of_spec
    (project_contract (.Boolean true) booleanSchema 1#usize 5#usize)
  have expected : refProject 1 (.Boolean true) booleanSchema 5 = some (.boolean true, 0) := by
    simp [refProject, booleanSchema, boundedLookup, lookupList, takeBudget]
  have witness : ResultMatches 1 (some (.boolean true, 0))
      (.Ok {value := .Boolean true, remaining := 0#usize}) := by
    simp [ResultMatches, Fits, view]
  change ResultMatches 1 (refProject 1 (.Boolean true) booleanSchema 5) out at matched_result
  rw [expected] at matched_result
  have eq := result_matches_unique 1 _ out _ matched_result witness
  simpa [eq] using returned

/-- Agreement follows the schema recursively. Provider fields outside its paths
are unconstrained, including inside selected objects and array elements. -/
def ProjectionAgreement : Nat → Json → Json → Projection → Prop
  | 0, _, _, _ => True
  | depth + 1, a, b, schema =>
      match boundedLookup a schema.at, boundedLookup b schema.at with
      | .Err _, .Err _ => True
      | .Ok left, .Ok right =>
          match schema.kind, left, right with
          | .Object fields, .Object _, .Object _ =>
              ∀ field ∈ fields.val, ProjectionAgreement depth left right field.projection
          | .Array item _, .Array xs, .Array ys =>
              List.Forall₂ (fun x y => ProjectionAgreement depth x y item) xs.val ys.val
          | _, _, _ => left = right
      | _, _ => False

theorem itemsWith_relational (select : Json → Nat → Option (PublicTree × Nat))
    (xs ys : List Json) (budget : Nat)
    (same : List.Forall₂ (fun x y => ∀ b, select x b = select y b) xs ys) :
    itemsWith select xs budget = itemsWith select ys budget := by
  induction same generalizing budget with
  | nil => rfl
  | cons head tail ih =>
    simp only [itemsWith]
    cases cut : takeBudget budget 1 with
    | none => rfl
    | some remaining =>
      simp only [Option.bind_eq_bind, Option.bind_some, head remaining]
      cases selected : select _ remaining with
      | none => rfl
      | some pair =>
        rcases pair with ⟨value, next⟩
        simp only [Option.bind_some]
        rw [ih next]

theorem refProject_agreement (depth : Nat) (a b : Json) (schema : Projection) (budget : Nat)
    (agree : ProjectionAgreement depth a b schema) :
    refProject depth a schema budget = refProject depth b schema budget := by
  induction depth generalizing a b schema budget with
  | zero => rfl
  | succ depth ih =>
    simp only [ProjectionAgreement] at agree
    simp only [refProject]
    cases lhs : boundedLookup a schema.at with
    | Err error =>
      cases rhs : boundedLookup b schema.at with
      | Err other => rfl
      | Ok right => simp [lhs, rhs] at agree
    | Ok left =>
      cases rhs : boundedLookup b schema.at with
      | Err other => simp [lhs, rhs] at agree
      | Ok right =>
        simp only [lhs, rhs] at agree ⊢
        cases kind : schema.kind <;> cases left <;> cases right
        all_goals simp only [kind] at agree ⊢
        all_goals try { contradiction }
        all_goals try { solve | cases agree; rfl }
        case Object.Object.Object fields left right =>
          have selected := fieldsWith_congruence
            (fun p n => refProject depth (.Object left) p n)
            (fun p n => refProject depth (.Object right) p n) fields.val
          by_cases invalid : fields.length = 0 ∨ 32 < fields.length
          · simp only [invalid, ↓reduceIte]
          · simp only [invalid, ↓reduceIte]
            cases cut : takeBudget budget 2 with
            | none => rfl
            | some remaining =>
              simp only [Option.bind_eq_bind, Option.bind_some]
              rw [selected remaining (by intro field member n; exact ih _ _ _ _ (agree field member))]
        case Array.Array.Array item maximum xs ys =>
          have lengths : xs.length = ys.length := agree.length_eq
          simp only [lengths]
          by_cases invalid : maximum.val < 1 ∨ 1000 < maximum.val ∨ maximum.val < ys.length
          · simp only [invalid, ↓reduceIte]
          · simp only [invalid, ↓reduceIte]
            cases cut : takeBudget budget 2 with
            | none => rfl
            | some remaining =>
              simp only [Option.bind_eq_bind, Option.bind_some]
              rw [itemsWith_relational (fun v n => refProject depth v item n) xs.val ys.val remaining
                (agree.imp (by intro x y property n; exact ih _ _ _ _ property))]

/-- Full recursive two-run noninterference of the extracted filter. This includes
successful owned output, remaining budget and denial, not just selected bytes. -/
theorem recursive_projection_noninterference (a b : Json) (schema : Projection) (fuel budget : Usize)
    (agree : ProjectionAgreement fuel.val a b schema) :
    project a schema fuel budget = project b schema fuel budget := by
  obtain ⟨left, left_return, left_matches⟩ := returned_of_spec (project_contract a schema fuel budget)
  obtain ⟨right, right_return, right_matches⟩ := returned_of_spec (project_contract b schema fuel budget)
  have spec_same := refProject_agreement fuel.val a b schema budget.val agree
  rw [← spec_same] at right_matches
  rw [left_return, right_return, result_matches_unique fuel.val _ left right left_matches right_matches]

end aivm_secrets_garrett_core.disclosure.Proofs

end
