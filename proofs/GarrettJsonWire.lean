import GarrettJsonString
import GarrettGuestFrame

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.json_wire.Proofs

private def TextValid (text : alloc.vec.Vec U32) : Prop := json_string.Proofs.ValidFrom text 0

def Series {α : Type} (bytes : α → List U8) (position : Nat) : List α → List U8
  | [] => []
  | value :: rest => (if 0 < position then [44#u8] else []) ++ bytes value ++ Series bytes (position + 1) rest

def SeriesBound {α : Type} (bound : α → Nat) : List α → Nat
  | [] => 0
  | value :: rest => 1 + bound value + SeriesBound bound rest

def Bytes : Nat → Value → List U8
  | 0, _ => []
  | _ + 1, .Null => [110#u8,117#u8,108#u8,108#u8]
  | _ + 1, .Boolean value => if value then [116#u8,114#u8,117#u8,101#u8] else [102#u8,97#u8,108#u8,115#u8,101#u8]
  | _ + 1, .Number token => token.val
  | _ + 1, .Text text => json_string.Proofs.StringBytes text.val
  | n + 1, .Array values => [91#u8] ++ Series (Bytes n) 0 values.val ++ [93#u8]
  | n + 1, .Object fields => [123#u8] ++ Series (fun field => json_string.Proofs.StringBytes field.1.val ++ [58#u8] ++ Bytes n field.2) 0 fields.val ++ [125#u8]

def Bound : Nat → Value → Nat
  | 0, _ => 0
  | _ + 1, .Null => 4
  | _ + 1, .Boolean value => if value then 4 else 5
  | _ + 1, .Number token => token.length
  | _ + 1, .Text text => 12 * text.length + 2
  | n + 1, .Array values => 2 + SeriesBound (Bound n) values.val
  | n + 1, .Object fields => 2 + SeriesBound (fun field => 12 * field.1.length + 3 + Bound n field.2) fields.val

def Valid : Nat → Value → Prop
  | 0, _ => False
  | _ + 1, .Text text => TextValid text
  | n + 1, .Array values => ∀ child ∈ values.val, Valid n child
  | n + 1, .Object fields => ∀ field ∈ fields.val, TextValid field.1 ∧ Valid n field.2
  | _ + 1, _ => True

private theorem series_length_bound {α : Type} (bytes : α → List U8) (bound : α → Nat)
    (values : List α) (position : Nat) (each : ∀ value ∈ values, (bytes value).length ≤ bound value) :
    (Series bytes position values).length ≤ SeriesBound bound values := by
  induction values generalizing position with
  | nil => simp [Series, SeriesBound]
  | cons value rest ih =>
    have first := each value (by simp)
    have tail := ih (position + 1) (by intro child member; exact each child (List.mem_cons_of_mem value member))
    simp only [Series, SeriesBound, List.length_append]
    split <;> simp only [List.length_singleton, List.length_nil, Nat.zero_add] <;> omega

theorem bytes_length_bound (fuel : Nat) (value : Value) : (Bytes fuel value).length ≤ Bound fuel value := by
  induction fuel generalizing value with
  | zero => simp [Bytes, Bound]
  | succ n ih =>
    cases value with
    | Null => simp [Bytes, Bound]
    | Boolean flag => cases flag <;> simp [Bytes, Bound]
    | Number token => simp [Bytes, Bound]
    | Text text =>
      have body := json_string.Proofs.body_length_bound text.val
      simp only [Bytes, Bound, json_string.Proofs.StringBytes, List.length_append, List.length_singleton]
      change 1 + (json_string.Proofs.BodyBytes text.val).length + 1 ≤ 12 * text.val.length + 2
      omega
    | Array values =>
      have series := series_length_bound (Bytes n) (Bound n) values.val 0 (by intro child _; exact ih child)
      simp only [Bytes, Bound, List.length_append, List.length_singleton]
      omega
    | Object fields =>
      have series := series_length_bound
        (fun field : alloc.vec.Vec U32 × Value => json_string.Proofs.StringBytes field.1.val ++ [58#u8] ++ Bytes n field.2)
        (fun field => 12 * field.1.length + 3 + Bound n field.2) fields.val 0 (by
          intro field _
          have body := json_string.Proofs.body_length_bound field.1.val
          have child := ih field.2
          simp only [json_string.Proofs.StringBytes, List.length_append, List.length_singleton]
          change 1 + (json_string.Proofs.BodyBytes field.1.val).length + 1 + 1 + (Bytes n field.2).length ≤ _
          change _ ≤ 12 * field.1.val.length + 3 + Bound n field.2
          omega)
      simp only [Bytes, Bound, List.length_append, List.length_singleton]
      omega

@[step] private theorem push_contract (output : alloc.vec.Vec U8) (byte : U8) (room : output.length < Usize.max) :
    alloc.vec.Vec.push output byte ⦃ out => out.val = output.val ++ [byte] ∧ out.length = output.length + 1 ⦄ := by
  apply WP.spec_mono (alloc.vec.Vec.push_spec output byte room)
  intro out equal
  refine ⟨equal, ?_⟩
  change out.val.length = output.val.length + 1
  simp [equal]

@[step] private theorem extend_contract (output : alloc.vec.Vec U8) (bytes : Slice U8)
    (room : output.length + bytes.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 output bytes ⦃ out =>
      out.val = output.val ++ bytes.val ∧ out.length = output.length + bytes.length ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  rw [dite_eq_left room]
  apply WP.spec_bind (List.clone_spec (clone := core.clone.CloneU8.clone)
    (l := bytes.val) (by intro x hx; simp))
  intro cloned exact_copy
  simp [exact_copy.1]

private theorem index_exact {α : Type} (values : alloc.vec.Vec α) (index : Usize) (inside : index.val < values.length) :
    alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) values index = Result.ok (values.val[index.val]) := by
  rw [alloc.vec.Vec.index_slice_index]
  obtain ⟨out, returned, same⟩ := returned_of_spec (alloc.vec.Vec.index_usize_spec values index inside)
  simpa only [same] using returned

private theorem comma_contract (output : alloc.vec.Vec U8) (index : Usize) (room : output.length < Usize.max) :
    (if index > 0#usize then alloc.vec.Vec.push output 44#u8 else Result.ok output) ⦃ out =>
      out.val = output.val ++ (if 0 < index.val then [44#u8] else []) ∧
      out.length = output.length + (if 0 < index.val then 1 else 0) ⦄ := by
  by_cases positive : index > 0#usize
  · have positive_nat : 0 < index.val := by scalar_tac
    simp only [positive, positive_nat, ↓reduceIte]
    exact push_contract output 44#u8 room
  · have zero_nat : ¬0 < index.val := by scalar_tac
    simp [positive, zero_nat]

private theorem array_loop_contract (fuel : Nat) (values : alloc.vec.Vec Value)
    (each : ∀ child ∈ values.val, ∀ output : alloc.vec.Vec U8,
      output.length + Bound fuel child ≤ Usize.max →
      append output child ⦃ out => out.1 = true ∧ out.2.val = output.val ++ Bytes fuel child ∧
        out.2.length = output.length + (Bytes fuel child).length ⦄)
    (output : alloc.vec.Vec U8) (index : Usize)
    (room : output.length + SeriesBound (Bound fuel) (values.val.drop index.val) + 1 ≤ Usize.max) :
    append_array_loop output values index ⦃ out => out.1 = true ∧
      out.2.val = output.val ++ Series (Bytes fuel) index.val (values.val.drop index.val) ++ [93#u8] ∧
      out.2.length = output.length + (Series (Bytes fuel) index.val (values.val.drop index.val)).length + 1 ⦄ := by
  suffices ∀ n (position : Usize) (leader : alloc.vec.Vec U8), values.length - position.val = n →
      leader.length + SeriesBound (Bound fuel) (values.val.drop position.val) + 1 ≤ Usize.max →
      append_array_loop leader values position ⦃ out => out.1 = true ∧
        out.2.val = leader.val ++ Series (Bytes fuel) position.val (values.val.drop position.val) ++ [93#u8] ∧
        out.2.length = leader.length + (Series (Bytes fuel) position.val (values.val.drop position.val)).length + 1 ⦄ from
    this _ index output rfl room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro position leader measure capacity
    rw [append_array_loop.eq_def]
    by_cases inside : position < values.len
    · have within : position.val < values.length := by scalar_tac
      have tail : values.val.drop position.val = values.val[position.val] :: values.val.drop (position.val + 1) :=
        List.drop_eq_getElem_cons within
      have split_bound : SeriesBound (Bound fuel) (values.val.drop position.val) =
          1 + Bound fuel values.val[position.val] + SeriesBound (Bound fuel) (values.val.drop (position.val + 1)) := by rw [tail]; rfl
      simp only [inside, ↓reduceIte]
      apply WP.spec_bind (comma_contract leader position (by omega))
      intro separated sep
      have sep_length := sep.2
      have comma_bound : (if 0 < position.val then 1 else 0) ≤ 1 := by split <;> omega
      rw [index_exact values position within]
      simp only [bind_ok]
      apply WP.spec_bind (each _ (List.getElem_mem within) separated (by omega))
      intro pair result
      rcases pair with ⟨accepted, encoded⟩
      rcases result with ⟨accepted_true, bytes, length⟩
      dsimp only at accepted_true bytes length ⊢
      change WP.spec (if accepted then (do
        let next ← position + 1#usize
        append_array_loop encoded values next) else Result.ok (false, encoded)) _
      rw [ite_eq_left accepted_true]
      have child_bound := bytes_length_bound fuel values.val[position.val]
      obtain ⟨next, increment, next_value⟩ := returned_of_spec (@Usize.add_spec position 1#usize (by scalar_tac))
      rw [increment]
      simp only [bind_ok]
      have next_nat : next.val = position.val + 1 := by scalar_tac
      apply WP.spec_mono (ih (values.length - next.val) (by omega) next encoded rfl (by rw [next_nat]; omega))
      intro out result
      rw [tail]
      simp only [Series, List.length_append]
      have comma_length : (if 0 < position.val then [44#u8] else []).length = (if 0 < position.val then 1 else 0) := by split <;> rfl
      simp only [next_nat] at result
      refine ⟨result.1, ?_, ?_⟩
      · simp only [result.2.1, bytes, sep.1, List.append_assoc]
      · rw [comma_length]
        omega
    · have past : values.length ≤ position.val := by scalar_tac
      have empty : values.val.drop position.val = [] := List.drop_eq_nil_of_le past
      simp only [inside, ↓reduceIte]
      have one : leader.length < Usize.max := by simp only [empty, SeriesBound] at capacity; omega
      apply WP.spec_bind (push_contract leader 93#u8 one)
      intro out post
      simp [WP.spec_ok, empty, Series, post]

def FieldBytes (fuel : Nat) (field : alloc.vec.Vec U32 × Value) : List U8 :=
  json_string.Proofs.StringBytes field.1.val ++ [58#u8] ++ Bytes fuel field.2

def FieldBound (fuel : Nat) (field : alloc.vec.Vec U32 × Value) : Nat :=
  12 * field.1.length + 3 + Bound fuel field.2

private theorem field_bytes_length (fuel : Nat) (field : alloc.vec.Vec U32 × Value) :
    (FieldBytes fuel field).length ≤ FieldBound fuel field := by
  have body := json_string.Proofs.body_length_bound field.1.val
  have child := bytes_length_bound fuel field.2
  simp only [FieldBytes, FieldBound, json_string.Proofs.StringBytes, List.length_append, List.length_singleton]
  change 1 + (json_string.Proofs.BodyBytes field.1.val).length + 1 + 1 + (Bytes fuel field.2).length ≤ 12 * field.1.val.length + 3 + Bound fuel field.2
  omega

private theorem field_contract (fuel : Nat) (field : alloc.vec.Vec U32 × Value)
    (valid : TextValid field.1)
    (each : ∀ output : alloc.vec.Vec U8, output.length + Bound fuel field.2 ≤ Usize.max →
      append output field.2 ⦃ out => out.1 = true ∧ out.2.val = output.val ++ Bytes fuel field.2 ∧
        out.2.length = output.length + (Bytes fuel field.2).length ⦄)
    (output : alloc.vec.Vec U8) (room : output.length + FieldBound fuel field ≤ Usize.max) :
    append_field output field ⦃ out => out.1 = true ∧ out.2.val = output.val ++ FieldBytes fuel field ∧
      out.2.length = output.length + (FieldBytes fuel field).length ⦄ := by
  rw [append_field.eq_def]
  apply WP.spec_bind (json_string.Proofs.accepted_quote_exact output field.1 valid (by unfold FieldBound at room; omega))
  intro pair property
  rcases pair with ⟨accepted, named⟩
  rcases property with ⟨accepted_true, bytes⟩
  dsimp only at accepted_true bytes
  change WP.spec (if accepted then (do
    let separated ← alloc.vec.Vec.push named 58#u8
    append separated field.2) else Result.ok (false, named)) _
  rw [ite_eq_left accepted_true]
  have named_length : named.length = output.length + (json_string.Proofs.StringBytes field.1.val).length := by
    change named.val.length = output.val.length + (json_string.Proofs.StringBytes field.1.val).length
    simp [bytes]
  have name_bound : (json_string.Proofs.StringBytes field.1.val).length ≤ 12 * field.1.length + 2 := by
    have body := json_string.Proofs.body_length_bound field.1.val
    simp only [json_string.Proofs.StringBytes, List.length_append, List.length_singleton]
    change 1 + (json_string.Proofs.BodyBytes field.1.val).length + 1 ≤ 12 * field.1.val.length + 2
    omega
  apply WP.spec_bind (push_contract named 58#u8 (by unfold FieldBound at room; omega))
  intro separated sep
  apply WP.spec_mono (each separated (by have len := sep.2; unfold FieldBound at room; omega))
  intro out result
  refine ⟨result.1, ?_, ?_⟩
  · simp only [result.2.1, sep.1, bytes, FieldBytes, List.append_assoc]
  · simp only [FieldBytes, List.length_append, List.length_singleton]
    have len := sep.2
    omega

private theorem fields_loop_contract (fuel : Nat) (fields : alloc.vec.Vec (alloc.vec.Vec U32 × Value))
    (each : ∀ child ∈ fields.val, ∀ output : alloc.vec.Vec U8,
      output.length + FieldBound fuel child ≤ Usize.max →
      append_field output child ⦃ out => out.1 = true ∧ out.2.val = output.val ++ FieldBytes fuel child ∧
        out.2.length = output.length + (FieldBytes fuel child).length ⦄)
    (output : alloc.vec.Vec U8) (index : Usize)
    (room : output.length + SeriesBound (FieldBound fuel) (fields.val.drop index.val) + 1 ≤ Usize.max) :
    append_fields_loop output fields index ⦃ out => out.1 = true ∧
      out.2.val = output.val ++ Series (FieldBytes fuel) index.val (fields.val.drop index.val) ++ [125#u8] ∧
      out.2.length = output.length + (Series (FieldBytes fuel) index.val (fields.val.drop index.val)).length + 1 ⦄ := by
  suffices ∀ n (position : Usize) (leader : alloc.vec.Vec U8), fields.length - position.val = n →
      leader.length + SeriesBound (FieldBound fuel) (fields.val.drop position.val) + 1 ≤ Usize.max →
      append_fields_loop leader fields position ⦃ out => out.1 = true ∧
        out.2.val = leader.val ++ Series (FieldBytes fuel) position.val (fields.val.drop position.val) ++ [125#u8] ∧
        out.2.length = leader.length + (Series (FieldBytes fuel) position.val (fields.val.drop position.val)).length + 1 ⦄ from
    this _ index output rfl room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro position leader measure capacity
    rw [append_fields_loop.eq_def]
    by_cases inside : position < fields.len
    · have within : position.val < fields.length := by scalar_tac
      have tail : fields.val.drop position.val = fields.val[position.val] :: fields.val.drop (position.val + 1) :=
        List.drop_eq_getElem_cons within
      have split_bound : SeriesBound (FieldBound fuel) (fields.val.drop position.val) =
          1 + FieldBound fuel fields.val[position.val] + SeriesBound (FieldBound fuel) (fields.val.drop (position.val + 1)) := by rw [tail]; rfl
      simp only [inside, ↓reduceIte]
      apply WP.spec_bind (comma_contract leader position (by omega))
      intro separated sep
      have sep_length := sep.2
      have comma_bound : (if 0 < position.val then 1 else 0) ≤ 1 := by split <;> omega
      rw [index_exact fields position within]
      simp only [bind_ok]
      apply WP.spec_bind (each _ (List.getElem_mem within) separated (by omega))
      intro pair result
      rcases pair with ⟨accepted, encoded⟩
      rcases result with ⟨accepted_true, bytes, length⟩
      dsimp only at accepted_true bytes length ⊢
      change WP.spec (if accepted then (do
        let next ← position + 1#usize
        append_fields_loop encoded fields next) else Result.ok (false, encoded)) _
      rw [ite_eq_left accepted_true]
      have child_bound := field_bytes_length fuel fields.val[position.val]
      obtain ⟨next, increment, next_value⟩ := returned_of_spec (@Usize.add_spec position 1#usize (by scalar_tac))
      rw [increment]
      simp only [bind_ok]
      have next_nat : next.val = position.val + 1 := by scalar_tac
      apply WP.spec_mono (ih (fields.length - next.val) (by omega) next encoded rfl (by rw [next_nat]; omega))
      intro out result
      rw [tail]
      simp only [Series, List.length_append]
      have comma_length : (if 0 < position.val then [44#u8] else []).length = (if 0 < position.val then 1 else 0) := by split <;> rfl
      simp only [next_nat] at result
      refine ⟨result.1, ?_, ?_⟩
      · simp only [result.2.1, bytes, sep.1, List.append_assoc]
      · rw [comma_length]
        omega
    · have past : fields.length ≤ position.val := by scalar_tac
      have empty : fields.val.drop position.val = [] := List.drop_eq_nil_of_le past
      simp only [inside, ↓reduceIte]
      have one : leader.length < Usize.max := by simp only [empty, SeriesBound] at capacity; omega
      apply WP.spec_bind (push_contract leader 125#u8 one)
      intro out post
      simp [WP.spec_ok, empty, Series, post]

/-- Actual recursive encoder; proof fuel bounds the tree depth and is not a
runtime parameter. Number tokens and object ordering are captured inputs. -/
@[step] theorem append_contract (fuel : Nat) (value : Value) (output : alloc.vec.Vec U8)
    (valid : Valid fuel value) (room : output.length + Bound fuel value ≤ Usize.max) :
    append output value ⦃ out => out.1 = true ∧ out.2.val = output.val ++ Bytes fuel value ∧
      out.2.length = output.length + (Bytes fuel value).length ⦄ := by
  have zero_value : (0#usize).val = 0 := by scalar_tac
  induction fuel generalizing value output with
  | zero => simp [Valid] at valid
  | succ n ih =>
    cases value with
    | Null =>
      rw [append.eq_def]
      simp only [lift, bind_ok]
      apply WP.spec_bind (extend_contract output _ (by simpa [Bound] using room))
      intro encoded property
      apply (WP.spec_ok _).mpr
      simpa [Bytes] using And.intro (Eq.refl true) property
    | Boolean flag =>
      cases flag
      all_goals
        rw [append.eq_def]
        simp only [Bool.false_eq_true, ↓reduceIte, lift, bind_ok]
        apply WP.spec_bind (extend_contract output _ (by simpa [Bound] using room))
        intro encoded property
        apply (WP.spec_ok _).mpr
        simpa [Bytes] using And.intro (Eq.refl true) property
    | Number token =>
      rw [append.eq_def]
      apply WP.spec_bind (extend_contract output (alloc.vec.Vec.deref token) (by simpa [Bound, alloc.vec.Vec.deref, Slice.length, Slice.from_val] using room))
      intro encoded property
      apply (WP.spec_ok _).mpr
      simpa [Bytes, alloc.vec.Vec.deref, Slice.from_val] using And.intro (Eq.refl true) property
    | Text text =>
      rw [append.eq_def]
      apply WP.spec_mono (json_string.Proofs.accepted_quote_exact output text valid (by simpa [Bound, Nat.add_assoc] using room))
      intro out property
      refine ⟨property.1, property.2, ?_⟩
      change out.2.val.length = output.val.length + (json_string.Proofs.StringBytes text.val).length
      simp [property.2]
    | Array values =>
      change output.length + (2 + SeriesBound (Bound n) values.val) ≤ Usize.max at room
      have children : ∀ child ∈ values.val, ∀ leader : alloc.vec.Vec U8,
          leader.length + Bound n child ≤ Usize.max →
          append leader child ⦃ out => out.1 = true ∧ out.2.val = leader.val ++ Bytes n child ∧
            out.2.length = leader.length + (Bytes n child).length ⦄ := by
        intro child member leader capacity
        exact ih child leader (valid child member) capacity
      rw [append.eq_def]
      change WP.spec (append_array output values) _
      rw [append_array.eq_def]
      apply WP.spec_bind (push_contract output 91#u8 (by omega))
      intro started start
      have start_length := start.2
      apply WP.spec_mono (array_loop_contract n values children started 0#usize (by simp only [zero_value, List.drop_zero]; omega))
      intro out result
      simp only [zero_value, List.drop_zero] at result
      refine ⟨result.1, ?_, ?_⟩
      · simpa only [start.1, Bytes, List.append_assoc] using result.2.1
      · simp only [Bytes, List.length_append, List.length_singleton]
        omega
    | Object fields =>
      change output.length + (2 + SeriesBound (FieldBound n) fields.val) ≤ Usize.max at room
      have children : ∀ field ∈ fields.val, ∀ leader : alloc.vec.Vec U8,
          leader.length + FieldBound n field ≤ Usize.max →
          append_field leader field ⦃ out => out.1 = true ∧ out.2.val = leader.val ++ FieldBytes n field ∧
            out.2.length = leader.length + (FieldBytes n field).length ⦄ := by
        intro field member leader capacity
        exact field_contract n field (valid field member).1
          (fun leader room => ih field.2 leader (valid field member).2 room) leader capacity
      rw [append.eq_def]
      change WP.spec (append_fields output fields) _
      rw [append_fields.eq_def]
      apply WP.spec_bind (push_contract output 123#u8 (by omega))
      intro started start
      have start_length := start.2
      apply WP.spec_mono (fields_loop_contract n fields children started 0#usize (by simp only [zero_value, List.drop_zero]; omega))
      intro out result
      simp only [zero_value, List.drop_zero] at result
      refine ⟨result.1, ?_, ?_⟩
      · change out.2.val = output.val ++ ([123#u8] ++ Series (FieldBytes n) 0 fields.val ++ [125#u8])
        simpa only [start.1, List.append_assoc] using result.2.1
      · simp only [Bytes, List.length_append, List.length_singleton]
        change out.2.length = output.length + (1 + (Series (FieldBytes n) 0 fields.val).length + 1)
        omega

@[step] theorem encode_contract (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) :
    encode value ⦃ out => ∃ bytes, out = .Ok bytes ∧ bytes.val = Bytes fuel value ⦄ := by
  unfold encode
  apply WP.spec_bind (append_contract fuel value (alloc.vec.Vec.new U8) valid (by simpa using room))
  intro pair property
  rcases pair with ⟨accepted, encoded⟩
  rcases property with ⟨accepted_true, bytes, length⟩
  dsimp only at accepted_true bytes
  change WP.spec (if accepted then Result.ok (core.result.Result.Ok encoded) else Result.ok (core.result.Result.Err EncodingDenial.InvalidText)) _
  rw [ite_eq_left accepted_true]
  apply (WP.spec_ok _).mpr
  exact ⟨encoded, rfl, by simpa using bytes⟩

theorem encoded_witness (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) :
    ∃ bytes, encode value = Result.ok (.Ok bytes) ∧ bytes.val = Bytes fuel value := by
  obtain ⟨out, returned, bytes, same, exact_bytes⟩ := returned_of_spec (encode_contract fuel value valid room)
  exact ⟨bytes, same ▸ returned, exact_bytes⟩

theorem returned_encoding_exact (fuel : Nat) (value : Value) (valid : Valid fuel value)
    (room : Bound fuel value ≤ Usize.max) (bytes : alloc.vec.Vec U8)
    (returned : encode value = Result.ok (.Ok bytes)) : bytes.val = Bytes fuel value := by
  have property := encode_contract fuel value valid room
  rw [returned] at property
  obtain ⟨actual, same, exact_bytes⟩ := (WP.spec_ok _).mp property
  cases same
  exact exact_bytes

end aivm_secrets_garrett_core.json_wire.Proofs
