import GarrettStatelessCodec

/-!
# `garrett-stateless-v1`: the field grammars, keys, header and segments

Source: `crates/garrett-stateless-core/src/stateless_token/` (`grammar.rs`, `keys.rs`, `payload.rs`, `opening.rs`)
(`plain`, `is_text`, `is_provider`, `is_kid`, `is_id`, `is_thumbprint`,
`is_scope`, `is_verifier`, `payload_valid`, `state_valid`, `select`,
`keys_valid`, `header_bytes`, `header_kid`, `ascii`, `dot_from`, `segments`,
`occurs`, `b64url`), extracted by Aeneas. Each validator is proved to compute
exactly a stated grammar, and every grammar excludes the JSON quote and
backslash, so a valid value is always a `Plain` string field.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.proxy_http.Base64Proofs (symNat sexNat enc encode_unpadded_spec sexNat_lt)
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.stateless_token.Proofs
open garrett_stateless_core.stateless_token.base64 garrett_stateless_core.stateless_token.grammar
  garrett_stateless_core.stateless_token.json garrett_stateless_core.stateless_token.payload
  garrett_stateless_core.stateless_token.keys garrett_stateless_core.stateless_token.opening
  garrett_stateless_core.stateless_token.sealing garrett_stateless_core.stateless_token.login_state

/-! ## Byte classes -/

theorem u8_bne (x y : U8) : (x != y) = decide (x.val ≠ y.val) := by
  have : x = y ↔ x.val = y.val := ⟨fun e => by rw [e], UScalar.eq_of_val_eq⟩
  rw [Bool.eq_iff_iff]; simp only [bne_iff_ne, ne_eq, decide_eq_true_eq, this]

abbrev PlainByte (x : U8) : Prop := 33 ≤ x.val ∧ x.val ≤ 126 ∧ x.val ≠ 34 ∧ x.val ≠ 92
abbrev LowerOrDigit (x : U8) : Prop := (97 ≤ x.val ∧ x.val ≤ 122) ∨ (48 ≤ x.val ∧ x.val ≤ 57)
abbrev Alphanumeric (x : U8) : Prop := (65 ≤ x.val ∧ x.val ≤ 90) ∨ LowerOrDigit x

theorem plain_eq (x : U8) : plain x = Result.ok (decide (PlainByte x)) := by
  unfold plain
  split_ifs <;> simp_all [u8_bne]

theorem lower_or_digit_eq (x : U8) : lower_or_digit x = Result.ok (decide (LowerOrDigit x)) := by
  unfold lower_or_digit
  split_ifs <;> simp_all

theorem alphanumeric_eq (x : U8) : alphanumeric x = Result.ok (decide (Alphanumeric x)) := by
  unfold alphanumeric
  split_ifs <;> simp_all [lower_or_digit_eq]

/-! ## The shape shared by every byte-class loop -/

theorem all_loop {loop : Slice U8 → Usize → Result Bool} (P : U8 → Prop) [DecidablePred P] (v : Slice U8)
    (step : ∀ (i : Usize) (inside : i.val < v.val.length),
      loop v i = if P (v.val[i.val]'inside) then (do let j ← i + 1#usize; loop v j) else Result.ok false)
    (stop : ∀ i : Usize, ¬ i.val < v.val.length → loop v i = Result.ok true) :
    ∀ i : Usize, i.val ≤ v.val.length → loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, P x)) := by
  have bound := v.property
  suffices ∀ n (i : Usize), v.val.length - i.val = n → i.val ≤ v.val.length →
      loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, P x)) from fun i h => this _ i rfl h
  intro n
  induction n with
  | zero =>
    intro i m _
    rw [stop i (by omega)]
    simp [show v.val.length ≤ i.val by omega]
  | succ n ih =>
    intro i m le
    have inside : i.val < v.val.length := by omega
    have hd : v.val.drop i.val = v.val[i.val] :: v.val.drop (i.val + 1) := (List.getElem_cons_drop inside).symm
    rw [step i inside]
    by_cases p : P (v.val[i.val]'inside)
    · obtain ⟨j, hj, jv⟩ := usize_succ i (by omega)
      simp only [p, ↓reduceIte, hj, bind_ok]
      rw [ih j (by omega) (by omega), jv]
      simp only [Result.ok.injEq, decide_eq_decide]
      refine ⟨fun h x mx => ?_, fun h x mx => h x (by rw [hd]; exact List.mem_cons_of_mem _ mx)⟩
      rw [hd] at mx
      rcases List.mem_cons.mp mx with e | mx
      · rw [e]; exact p
      · exact h x mx
    · simp only [p, ↓reduceIte, Result.ok.injEq]
      symm
      rw [decide_eq_false_iff_not]
      exact fun h => p (h _ (by rw [hd]; exact List.mem_cons_self))

abbrev ProviderByte (x : U8) : Prop := LowerOrDigit x ∨ x.val = 46 ∨ x.val = 95 ∨ x.val = 45
abbrev KidByte (x : U8) : Prop := Alphanumeric x ∨ x.val = 95 ∨ x.val = 45
abbrev IdByte (x : U8) : Prop := (48 ≤ x.val ∧ x.val ≤ 57) ∨ (97 ≤ x.val ∧ x.val ≤ 102)
abbrev VerifierByte (x : U8) : Prop := Alphanumeric x ∨ x.val = 45 ∨ x.val = 46 ∨ x.val = 95 ∨ x.val = 126

theorem is_text_loop_eq (v : Slice U8) : ∀ i : Usize, i.val ≤ v.val.length →
    is_text_loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, PlainByte x)) := by
  apply all_loop PlainByte v
  · intro i inside
    rw [is_text_loop.eq_def]
    have c : i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq v i inside, bind_ok, plain_eq, decide_eq_true_eq]
  · intro i out
    rw [is_text_loop.eq_def]
    have c : ¬ i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte]

theorem is_provider_loop_eq (v : Slice U8) : ∀ i : Usize, i.val ≤ v.val.length →
    is_provider_loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, ProviderByte x)) := by
  apply all_loop ProviderByte v
  · intro i inside
    rw [is_provider_loop.eq_def]
    have c : i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq v i inside, bind_ok, lower_or_digit_eq, decide_eq_true_eq, u8_bne]
    generalize v.val[i.val] = x
    by_cases a : LowerOrDigit x
    · simp [a]
    · by_cases b46 : x.val = 46 <;> by_cases b95 : x.val = 95 <;> by_cases b45 : x.val = 45 <;>
        simp [a, b46, b95, b45]
  · intro i out
    rw [is_provider_loop.eq_def]
    have c : ¬ i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte]

theorem is_kid_loop_eq (v : Slice U8) : ∀ i : Usize, i.val ≤ v.val.length →
    is_kid_loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, KidByte x)) := by
  apply all_loop KidByte v
  · intro i inside
    rw [is_kid_loop.eq_def]
    have c : i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq v i inside, bind_ok, alphanumeric_eq, decide_eq_true_eq, u8_bne]
    generalize v.val[i.val] = x
    by_cases a : Alphanumeric x
    · simp [a]
    · by_cases b95 : x.val = 95 <;> by_cases b45 : x.val = 45 <;> simp [a, b95, b45]
  · intro i out
    rw [is_kid_loop.eq_def]
    have c : ¬ i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte]

theorem is_verifier_loop_eq (v : Slice U8) : ∀ i : Usize, i.val ≤ v.val.length →
    is_verifier_loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, VerifierByte x)) := by
  apply all_loop VerifierByte v
  · intro i inside
    rw [is_verifier_loop.eq_def]
    have c : i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq v i inside, bind_ok, alphanumeric_eq, decide_eq_true_eq, u8_bne]
    generalize v.val[i.val] = x
    by_cases a : Alphanumeric x
    · simp [a]
    · by_cases b45 : x.val = 45 <;> by_cases b46 : x.val = 46 <;> by_cases b95 : x.val = 95 <;>
        by_cases b126 : x.val = 126 <;> simp [a, b45, b46, b95, b126]
  · intro i out
    rw [is_verifier_loop.eq_def]
    have c : ¬ i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte]

theorem is_id_loop_eq (v : Slice U8) : ∀ i : Usize, i.val ≤ v.val.length →
    is_id_loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, IdByte x)) := by
  apply all_loop IdByte v
  · intro i inside
    rw [is_id_loop.eq_def]
    have c : i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq v i inside, bind_ok]
    generalize v.val[i.val] = x
    by_cases a : IdByte x
    · simp only [a, ↓reduceIte]
      split_ifs <;> first | rfl | (exfalso; scalar_tac)
    · simp only [a, ↓reduceIte]
      split_ifs <;> first | rfl | (exfalso; scalar_tac)
  · intro i out
    rw [is_id_loop.eq_def]
    have c : ¬ i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte]

/-! ## The grammars -/

/-- 1-256 plain bytes. -/
def Text (l : List U8) : Prop := 1 ≤ l.length ∧ l.length ≤ 256 ∧ ∀ x ∈ l, PlainByte x
/-- `[a-z0-9][a-z0-9._-]{0,63}`. -/
def Provider (l : List U8) : Prop :=
  1 ≤ l.length ∧ l.length ≤ 64 ∧ (∀ h : 0 < l.length, LowerOrDigit (l[0]'h)) ∧ ∀ x ∈ l, ProviderByte x
/-- `[A-Za-z0-9][A-Za-z0-9_-]{0,31}`. -/
def Kid (l : List U8) : Prop :=
  1 ≤ l.length ∧ l.length ≤ 32 ∧ (∀ h : 0 < l.length, Alphanumeric (l[0]'h)) ∧ ∀ x ∈ l, KidByte x
/-- 32 lowercase hex digits. -/
def Id (l : List U8) : Prop := l.length = 32 ∧ ∀ x ∈ l, IdByte x
/-- An RFC 7636 code verifier: 43-128 unreserved bytes. -/
def Verifier (l : List U8) : Prop := 43 ≤ l.length ∧ l.length ≤ 128 ∧ ∀ x ∈ l, VerifierByte x
/-- The unpadded url encoding of a 32-byte SHA-256 thumbprint. -/
def Thumbprint (l : List U8) : Prop := l.length = 43 ∧ ∃ x : List U8, x.length = 32 ∧ l.map (·.val) = enc x true

instance : DecidablePred Text := fun l => by unfold Text; infer_instance
instance : DecidablePred Provider := fun l => by unfold Provider; infer_instance
instance : DecidablePred Kid := fun l => by unfold Kid; infer_instance
instance : DecidablePred Id := fun l => by unfold Id; infer_instance
instance : DecidablePred Verifier := fun l => by unfold Verifier; infer_instance

theorem ok_decide {P : Prop} [Decidable P] {b : Bool} (h : b = true ↔ P) :
    Result.ok b = Result.ok (decide P) := by
  rw [Result.ok.injEq]; cases b <;> simp_all

theorem usize_zero_val : (0#usize).val = 0 := by simp

theorem is_text_eq (v : Slice U8) : is_text v = Result.ok (decide (Text v.val)) := by
  unfold is_text
  simp only
  have loop := is_text_loop_eq v 0#usize (by simp)
  rw [usize_zero_val, List.drop_zero] at loop
  split_ifs with h1 h2
  · exact ok_decide (by unfold Text; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · exact ok_decide (by unfold Text; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · rw [loop]
    have : 1 ≤ v.val.length ∧ v.val.length ≤ 256 := by scalar_tac
    exact ok_decide (by unfold Text; simp [this])

theorem is_id_eq (v : Slice U8) : is_id v = Result.ok (decide (Id v.val)) := by
  unfold is_id
  simp only
  have loop := is_id_loop_eq v 0#usize (by simp)
  rw [usize_zero_val, List.drop_zero] at loop
  split_ifs with h1
  · exact ok_decide (by unfold Id; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · rw [loop]
    have : v.val.length = 32 := by scalar_tac
    exact ok_decide (by unfold Id; simp [this])

theorem is_verifier_eq (v : Slice U8) : is_verifier v = Result.ok (decide (Verifier v.val)) := by
  unfold is_verifier
  simp only
  have loop := is_verifier_loop_eq v 0#usize (by simp)
  rw [usize_zero_val, List.drop_zero] at loop
  split_ifs with h1 h2
  · exact ok_decide (by unfold Verifier; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · exact ok_decide (by unfold Verifier; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · rw [loop]
    have : 43 ≤ v.val.length ∧ v.val.length ≤ 128 := by scalar_tac
    exact ok_decide (by unfold Verifier; simp [this])

theorem is_provider_eq (v : Slice U8) : is_provider v = Result.ok (decide (Provider v.val)) := by
  unfold is_provider
  simp only
  have loop := is_provider_loop_eq v 0#usize (by simp)
  rw [usize_zero_val, List.drop_zero] at loop
  split_ifs with h1 h2
  · exact ok_decide (by unfold Provider; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · exact ok_decide (by unfold Provider; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · have inside : 0 < v.val.length := by scalar_tac
    have : 1 ≤ v.val.length ∧ v.val.length ≤ 64 := by scalar_tac
    rw [slice_index_eq v 0#usize (by simpa using inside)]
    simp only [bind_ok, lower_or_digit_eq]
    by_cases first : LowerOrDigit (v.val[0]'inside)
    · simp only [usize_zero_val, first, decide_true, ↓reduceIte, loop]
      exact ok_decide (by unfold Provider; simp [this, first])
    · simp only [usize_zero_val, first, decide_false, Bool.false_eq_true, ↓reduceIte]
      exact ok_decide (by unfold Provider; simp only [Bool.false_eq_true, false_iff]; exact fun h => first (h.2.2.1 inside))

theorem is_kid_eq (v : Slice U8) : is_kid v = Result.ok (decide (Kid v.val)) := by
  unfold is_kid
  simp only
  have loop := is_kid_loop_eq v 0#usize (by simp)
  rw [usize_zero_val, List.drop_zero] at loop
  split_ifs with h1 h2
  · exact ok_decide (by unfold Kid; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · exact ok_decide (by unfold Kid; simp only [Bool.false_eq_true, false_iff, not_and]; scalar_tac)
  · have inside : 0 < v.val.length := by scalar_tac
    have : 1 ≤ v.val.length ∧ v.val.length ≤ 32 := by scalar_tac
    rw [slice_index_eq v 0#usize (by simpa using inside)]
    simp only [bind_ok, alphanumeric_eq]
    by_cases first : Alphanumeric (v.val[0]'inside)
    · simp only [usize_zero_val, first, decide_true, ↓reduceIte, loop]
      exact ok_decide (by unfold Kid; simp [this, first])
    · simp only [usize_zero_val, first, decide_false, Bool.false_eq_true, ↓reduceIte]
      exact ok_decide (by unfold Kid; simp only [Bool.false_eq_true, false_iff]; exact fun h => first (h.2.2.1 inside))

/-! ## Scope: plain tokens separated by single spaces -/

/-- What `is_scope_loop` computes over the remaining bytes. -/
def scopeRun (valid after : Bool) : List U8 → Bool × Bool
  | [] => (valid, after)
  | x :: xs =>
    if x = 32#u8 then scopeRun (if after then false else valid) true xs
    else scopeRun (if PlainByte x then valid else false) false xs

theorem is_scope_loop_eq (v : Slice U8) : ∀ n (i : Usize) (valid after : Bool), v.val.length - i.val = n →
    i.val ≤ v.val.length → is_scope_loop v valid after i = Result.ok (scopeRun valid after (v.val.drop i.val)) := by
  have bound := v.property
  intro n
  induction n with
  | zero =>
    intro i valid after m le
    rw [is_scope_loop.eq_def]
    have c : ¬ i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte, show v.val.length ≤ i.val by omega, List.drop_eq_nil_of_le, scopeRun]
  | succ n ih =>
    intro i valid after m le
    have inside : i.val < v.val.length := by omega
    have hd : v.val.drop i.val = v.val[i.val] :: v.val.drop (i.val + 1) := (List.getElem_cons_drop inside).symm
    rw [is_scope_loop.eq_def]
    have c : i < Slice.len v := by scalar_tac
    obtain ⟨j, hj, jv⟩ := usize_succ i (by omega)
    simp only [c, ↓reduceIte, slice_index_eq v i inside, bind_ok, hd, scopeRun, plain_eq, decide_eq_true_eq]
    split_ifs <;> simp only [bind_ok, hj, Aeneas.Std.uncurry_apply_pair] <;>
      rw [ih j _ _ (by omega) (by omega), jv]

theorem pair_infix_cons (a b x : U8) (xs : List U8) :
    [a, b] <:+: x :: xs ↔ (x = a ∧ xs.head? = some b) ∨ [a, b] <:+: xs := by
  rw [List.infix_cons_iff, List.cons_prefix_cons]
  cases xs with
  | nil => simp
  | cons y ys =>
    simp only [List.cons_prefix_cons, List.nil_prefix, and_true, List.head?_cons, Option.some.injEq]
    constructor
    · rintro (⟨h1, h2⟩ | h)
      · exact Or.inl ⟨h1.symm, h2.symm⟩
      · exact Or.inr h
    · rintro (⟨h1, h2⟩ | h)
      · exact Or.inl ⟨h1.symm, h2.symm⟩
      · exact Or.inr h

theorem scopeRun_fst (l : List U8) : ∀ valid after : Bool,
    (scopeRun valid after l).1 = true ↔ valid = true ∧ (∀ x ∈ l, x = 32#u8 ∨ PlainByte x) ∧
      (after = true → l.head? ≠ some 32#u8) ∧ ¬ [32#u8, 32#u8] <:+: l := by
  induction l with
  | nil => intro valid after; simp [scopeRun]
  | cons x xs ih =>
    intro valid after
    rw [scopeRun, pair_infix_cons, List.forall_mem_cons, List.head?_cons]
    by_cases sp : x = 32#u8
    · simp only [sp, ↓reduceIte, ih]
      cases after <;> simp
    · simp only [sp, ↓reduceIte, ih]
      by_cases pl : PlainByte x
      · simp [pl, sp]
      · simp [pl, sp]

theorem scopeRun_snd (l : List U8) : ∀ valid after : Bool,
    (scopeRun valid after l).2 = l.getLast?.elim after (fun y => decide (y = 32#u8)) := by
  induction l with
  | nil => intro valid after; simp [scopeRun]
  | cons x xs ih =>
    intro valid after
    rw [scopeRun]
    cases xs with
    | nil => by_cases sp : x = 32#u8 <;> simp [sp, scopeRun]
    | cons y ys =>
      rw [List.getLast?_cons_cons]
      split_ifs <;> rw [ih] <;> simp [List.getLast?_cons]

/-- 0-1024 bytes of plain tokens, separated by single spaces: no leading,
    trailing or doubled space. -/
def Scope (l : List U8) : Prop :=
  l.length ≤ 1024 ∧ (∀ x ∈ l, x = 32#u8 ∨ PlainByte x) ∧ l.head? ≠ some 32#u8 ∧ l.getLast? ≠ some 32#u8 ∧
    ¬ [32#u8, 32#u8] <:+: l

theorem is_scope_true (v : Slice U8) : is_scope v = Result.ok true ↔ Scope v.val := by
  unfold is_scope Scope
  simp only
  have loop := is_scope_loop_eq v _ 0#usize true true rfl (by simp)
  rw [usize_zero_val, List.drop_zero] at loop
  rw [loop]
  simp only [bind_ok]
  have fst := scopeRun_fst v.val true true
  have snd := scopeRun_snd v.val true true
  generalize scopeRun true true v.val = r at fst snd
  obtain ⟨valid, after⟩ := r
  simp only [true_and, forall_const] at fst snd
  by_cases big : v.val.length > 1024
  · have : Slice.len v > 1024#usize := by scalar_tac
    simp only [this, ↓reduceIte, Result.ok.injEq, Bool.false_eq_true, false_iff, not_and]
    omega
  · have : ¬ Slice.len v > 1024#usize := by scalar_tac
    simp only [this, ↓reduceIte, Aeneas.Std.uncurry_apply_pair]
    cases valid
    · simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, false_iff]
      exact fun ⟨_, a, b, _, c⟩ => Bool.false_ne_true (fst.mpr ⟨a, b, c⟩)
    · obtain ⟨a, b, c⟩ := fst.mp rfl
      simp only [↓reduceIte]
      by_cases empty : v.val = []
      · have : Slice.len v = 0#usize := by scalar_tac
        simp [this, empty]
      · have : ¬ Slice.len v = 0#usize := by
          intro e; apply empty; apply List.eq_nil_of_length_eq_zero; scalar_tac
        obtain ⟨y, hy⟩ : ∃ y, v.val.getLast? = some y := by
          cases h : v.val.getLast? with
          | none => exact absurd (List.getLast?_eq_none_iff.mp h) empty
          | some y => exact ⟨y, rfl⟩
        rw [hy] at snd
        simp only [Option.elim_some] at snd
        simp [this, snd, hy, b, c, show v.val.length ≤ 1024 by omega]
        exact fun _ => a

/-! ## The url alphabet, encoding and thumbprints -/

/-- `[A-Za-z0-9_-]`, by value. -/
abbrev B64Byte (n : Nat) : Prop :=
  (65 ≤ n ∧ n ≤ 90) ∨ (97 ≤ n ∧ n ≤ 122) ∨ (48 ≤ n ∧ n ≤ 57) ∨ n = 45 ∨ n = 95

theorem symNat_url (v : Nat) (small : v < 64) : B64Byte (symNat v true) := by
  simp only [symNat, B64Byte, ↓reduceIte]
  split_ifs <;> omega

/-- Every byte of a url encoding is in the url alphabet. -/
theorem enc_alphabet {l x : List U8} (h : l.map (·.val) = enc x true) : ∀ y ∈ l, B64Byte y.val := by
  intro y my
  have : y.val ∈ enc x true := by rw [← h]; exact List.mem_map_of_mem my
  simp only [enc, List.mem_map, List.mem_range] at this
  obtain ⟨i, _, e⟩ := this
  rw [← e]
  exact symNat_url _ (sexNat_lt x i)

/-- The url alphabet has no quote, backslash, dot or non-ASCII byte. -/
theorem b64_byte_safe {n : Nat} (h : B64Byte n) : n ≠ 34 ∧ n ≠ 92 ∧ n ≠ 46 ∧ n ≤ 127 := by
  omega

theorem enc_plain {l x : List U8} (h : l.map (·.val) = enc x true) : Plain l :=
  fun y my => ⟨(b64_byte_safe (enc_alphabet h y my)).1, (b64_byte_safe (enc_alphabet h y my)).2.1⟩

/-- **What `b64url` returns**: exactly the unpadded url encoding. -/
theorem b64url_spec (x : Slice U8) (fits : 8 * x.val.length + 5 ≤ Usize.max) :
    ∃ w, b64url x = Result.ok w ∧ w.val.map (·.val) = enc x.val true := by
  unfold b64url
  exact returned_of_spec (encode_unpadded_spec x true fits)

theorem b64url_ok {x : Slice U8} {w : alloc.vec.Vec U8} (fits : 8 * x.val.length + 5 ≤ Usize.max)
    (h : b64url x = Result.ok w) :
    w.val.map (·.val) = enc x.val true ∧ Plain w.val ∧ (∀ y ∈ w.val, y.val ≠ 46 ∧ y.val ≤ 127) := by
  obtain ⟨w', h', e⟩ := b64url_spec x fits
  rw [h] at h'
  simp only [Result.ok.injEq] at h'
  subst h'
  exact ⟨e, enc_plain e, fun y my => ⟨(b64_byte_safe (enc_alphabet e y my)).2.2.1,
    (b64_byte_safe (enc_alphabet e y my)).2.2.2⟩⟩

theorem thumbprint_fits : 8 * 43 + 5 ≤ Usize.max := by
  have := usize_big; omega

theorem is_thumbprint_true (v : Slice U8) : is_thumbprint v = Result.ok true ↔ Thumbprint v.val := by
  unfold is_thumbprint Thumbprint
  simp only
  by_cases len : v.val.length = 43
  · have : ¬ (Slice.len v != 43#usize) = true := by
      simp only [bne_iff_ne, ne_eq, not_not]; scalar_tac
    simp only [this, Bool.false_eq_true, ↓reduceIte, len, true_and]
    constructor
    · intro h
      obtain ⟨o, ho, h⟩ := bind_ok_inv h
      cases o with
      | none => simp at h
      | some bytes =>
        simp only [Result.ok.injEq, decide_eq_true_eq] at h
        obtain ⟨e, _⟩ := from_b64url_sound (by rw [Slice.length, len]; exact thumbprint_fits) ho
        exact ⟨bytes.val, by scalar_tac, e⟩
    · rintro ⟨x, xl, e⟩
      have xb : x.length ≤ Usize.max := by have := usize_big; omega
      obtain ⟨out, ho, ov⟩ := from_b64url_complete (Slice.from x xb) v (by rw [Slice.from_val]; exact e)
        (by rw [len]; exact thumbprint_fits)
      rw [Slice.from_val] at ov
      rw [ho]
      simp only [bind_ok, Result.ok.injEq, decide_eq_true_eq]
      have : out.val.length = 32 := by rw [ov]; exact xl
      scalar_tac
  · have : (Slice.len v != 43#usize) = true := by
      simp only [bne_iff_ne, ne_eq]; intro e; apply len; scalar_tac
    simp only [this, ↓reduceIte, Result.ok.injEq, Bool.false_eq_true, false_iff, not_and]
    exact fun e => absurd e len

theorem thumbprint_plain {l : List U8} (h : Thumbprint l) : Plain l := by
  obtain ⟨_, x, _, e⟩ := h
  exact enc_plain e

/-! ## Totality: the validators never fail, so each returns exactly its grammar -/

theorem eq_decide_of_total {r : Result Bool} {P : Prop} [Decidable P] (total : ∃ b, r = Result.ok b)
    (h : r = Result.ok true ↔ P) : r = Result.ok (decide P) := by
  obtain ⟨b, hb⟩ := total
  rw [hb] at h ⊢
  cases b
  · have : ¬ P := fun p => by simpa using h.mpr p
    simp [this]
  · simp [h.mp rfl]

theorem from_b64url_total (text : Slice U8) (fits : 8 * text.val.length + 5 ≤ Usize.max) :
    ∃ o, from_b64url text = Result.ok o := by
  unfold from_b64url
  simp only
  obtain ⟨m, hm, _⟩ := returned_of_spec (Usize.rem_spec (x := Slice.len text) (y := 4#usize) (by simp))
  rw [hm]
  simp only [bind_ok]
  split_ifs
  · exact ⟨_, rfl⟩
  · have len := from_b64url_loop_length text (by simp only [Slice.length]; omega) _ (alloc.vec.Vec.new U8) true
      0#usize rfl (by simp) (by simp)
    obtain ⟨⟨out, valid⟩, hl, bound⟩ := returned_of_spec len
    rw [hl]
    simp only [bind_ok, Aeneas.Std.uncurry_apply_pair]
    split_ifs
    · obtain ⟨encoded, he, _⟩ := returned_of_spec (encode_unpadded_spec (alloc.vec.Vec.deref out) true
        (by simp only [Slice.length] at bound; simp [alloc.vec.Vec.deref]; omega))
      rw [he]
      simp only [bind_ok, slice_ne_eq]
      split_ifs <;> exact ⟨_, rfl⟩
    · exact ⟨_, rfl⟩

theorem is_thumbprint_total (v : Slice U8) : ∃ b, is_thumbprint v = Result.ok b := by
  unfold is_thumbprint
  simp only
  split_ifs with h
  · exact ⟨_, rfl⟩
  · have len : v.val.length = 43 := by simp only [bne_iff_ne, ne_eq, not_not] at h; scalar_tac
    obtain ⟨o, ho⟩ := from_b64url_total v (by rw [len]; exact thumbprint_fits)
    rw [ho]
    cases o <;> simp

noncomputable instance : DecidablePred Thumbprint := Classical.decPred _

theorem is_thumbprint_eq (v : Slice U8) : is_thumbprint v = Result.ok (decide (Thumbprint v.val)) :=
  eq_decide_of_total (is_thumbprint_total v) (is_thumbprint_true v)

instance : DecidablePred Scope := fun l => by unfold Scope; infer_instance

theorem is_scope_total (v : Slice U8) : ∃ b, is_scope v = Result.ok b := by
  unfold is_scope
  simp only
  have loop := is_scope_loop_eq v _ 0#usize true true rfl (by simp)
  rw [loop]
  simp only [bind_ok]
  obtain ⟨valid, after⟩ := scopeRun true true (List.drop (↑(0#usize)) v.val)
  simp only [Aeneas.Std.uncurry_apply_pair]
  split_ifs <;> exact ⟨_, rfl⟩

theorem is_scope_eq (v : Slice U8) : is_scope v = Result.ok (decide (Scope v.val)) :=
  eq_decide_of_total (is_scope_total v) (is_scope_true v)

/-! ## Every grammar is a plain JSON string -/

theorem text_plain {l : List U8} (h : Text l) : Plain l :=
  fun x m => by have := h.2.2 x m; simp only [PlainByte] at this; omega
theorem provider_plain {l : List U8} (h : Provider l) : Plain l :=
  fun x m => by have := h.2.2.2 x m; simp only [ProviderByte, LowerOrDigit] at this; omega
theorem kid_plain {l : List U8} (h : Kid l) : Plain l :=
  fun x m => by have := h.2.2.2 x m; simp only [KidByte, Alphanumeric, LowerOrDigit] at this; omega
theorem id_plain {l : List U8} (h : Id l) : Plain l :=
  fun x m => by have := h.2 x m; simp only [IdByte] at this; omega
theorem verifier_plain {l : List U8} (h : Verifier l) : Plain l :=
  fun x m => by have := h.2.2 x m; simp only [VerifierByte, Alphanumeric, LowerOrDigit] at this; omega
theorem scope_plain {l : List U8} (h : Scope l) : Plain l := by
  intro x m
  rcases h.2.1 x m with e | p
  · rw [e]; decide
  · simp only [PlainByte] at p; omega

/-- A `kid` is ASCII and has no `.`, quote or backslash. -/
theorem kid_safe {l : List U8} (h : Kid l) : ∀ x ∈ l, x.val ≠ 46 ∧ x.val ≤ 127 := by
  intro x m; have := h.2.2.2 x m; simp only [KidByte, Alphanumeric, LowerOrDigit] at this; omega

/-! ## Payload and login-state validity -/

theorem deref_val (x : alloc.vec.Vec U8) : (alloc.vec.Vec.deref x).val = x.val := by
  simp [alloc.vec.Vec.deref]

theorem i64_ge_zero (a : I64) : (a ≥ 0#i64) ↔ 0 ≤ a.val := by
  constructor <;> intro h <;> scalar_tac

theorem i64_le_max (a : I64) : (a ≤ MAX_INTEGER) ↔ a.val ≤ 9007199254740991 := by
  have := max_integer_val
  constructor <;> intro h <;> scalar_tac

/-- Every grammar a payload's members satisfy (`payload_valid`). -/
def PayloadValid (p : Payload) : Prop :=
  Text p.claims.issuer.val ∧ Text p.claims.audience.val ∧ Text p.claims.subject.val ∧
    Id p.claims.token_id.val ∧ Provider p.claims.provider.val ∧ Thumbprint p.claims.certificate.val ∧
    0 ≤ p.claims.issued_at.val ∧ p.claims.issued_at.val ≤ 9007199254740991 ∧
    0 ≤ p.claims.expires_at.val ∧ p.claims.expires_at.val ≤ 9007199254740991 ∧
    0 ≤ p.claims.renew_until.val ∧ p.claims.renew_until.val ≤ 9007199254740991 ∧
    (p.info.has_scope = true → Scope p.info.scope.val) ∧
    (p.info.has_upstream = true → upstream_object (alloc.vec.Vec.deref p.info.upstream) = Result.ok true)

theorem ite_ok_false (c : Prop) [Decidable c] (r : Result Bool) :
    ((if c then r else Result.ok false) = Result.ok true) ↔ c ∧ r = Result.ok true := by
  split_ifs with h <;> simp [h]

theorem payload_valid_true (p : Payload) : payload_valid p = Result.ok true ↔ PayloadValid p := by
  unfold payload_valid PayloadValid
  simp only [is_text_eq, is_id_eq, is_provider_eq, is_thumbprint_eq, is_scope_eq, deref_val, bind_ok,
    decide_eq_true_eq, i64_ge_zero, i64_le_max]
  cases p.info.has_scope <;> cases p.info.has_upstream <;>
    simp only [ite_ok_false, Bool.false_eq_true, ↓reduceIte, IsEmpty.forall_iff, forall_const, and_true,
      true_and]

/-- Every string member of a valid payload is a plain JSON string. -/
theorem payload_valid_plain {p : Payload} (h : PayloadValid p) :
    Plain p.claims.audience.val ∧ Plain p.claims.certificate.val ∧ Plain p.claims.issuer.val ∧
      Plain p.claims.token_id.val ∧ Plain p.claims.provider.val ∧ Plain p.claims.subject.val ∧
      (p.info.has_scope = true → Plain p.info.scope.val) := by
  obtain ⟨iss, aud, sub, jti, prv, cnf, _, _, _, _, _, _, scope, _⟩ := h
  exact ⟨text_plain aud, thumbprint_plain cnf, text_plain iss, id_plain jti, provider_plain prv, text_plain sub,
    fun hs => scope_plain (scope hs)⟩

/-- Every grammar a sealed login state's members satisfy (`state_valid`). -/
def StateValid (s : stateless_login.LoginState) : Prop :=
  Thumbprint s.certificate.val ∧ Id s.login.val ∧ Provider s.provider.val ∧ Kid s.replica.val ∧
    Scope s.scope.val ∧ Text s.subject.val ∧ Verifier s.verifier.val ∧
    0 ≤ s.certificate_expires.val ∧ s.certificate_expires.val ≤ 9007199254740991 ∧
    0 ≤ s.issued_at.val ∧ s.issued_at.val ≤ 9007199254740991 ∧
    0 ≤ s.expires_at.val ∧ s.expires_at.val ≤ 9007199254740991

theorem state_valid_true (s : stateless_login.LoginState) : state_valid s = Result.ok true ↔ StateValid s := by
  unfold state_valid StateValid
  simp only [is_text_eq, is_id_eq, is_provider_eq, is_kid_eq, is_verifier_eq, is_thumbprint_eq, is_scope_eq,
    deref_val, bind_ok, decide_eq_true_eq, i64_ge_zero, i64_le_max, ite_ok_false, Result.ok.injEq]

/-- Every string member of a valid login state is a plain JSON string. -/
theorem state_valid_plain {s : stateless_login.LoginState} (h : StateValid s) :
    Plain s.certificate.val ∧ Plain s.login.val ∧ Plain s.provider.val ∧ Plain s.replica.val ∧
      Plain s.scope.val ∧ Plain s.subject.val ∧ Plain s.verifier.val := by
  obtain ⟨cnf, login, prv, rep, scope, sub, ver, _⟩ := h
  exact ⟨thumbprint_plain cnf, id_plain login, provider_plain prv, kid_plain rep, scope_plain scope,
    text_plain sub, verifier_plain ver⟩

/-! ## Key selection -/

theorem named_eq {M : Type} (entry : KeyEntry M) (kid : Slice U8) :
    named entry kid = Result.ok (decide (entry.kid.val = kid.val)) := by
  unfold named
  rw [slice_eq_eq, deref_val]

theorem select_loop_spec {M : Type} (entries : Slice (KeyEntry M)) (kid : Slice U8) :
    ∀ n (index : Usize), entries.val.length - index.val = n → index.val ≤ entries.val.length →
      ∃ r : Usize, select_loop entries kid index = Result.ok r ∧ index.val ≤ r.val ∧
        r.val ≤ entries.val.length ∧
        (∀ j (h : j < entries.val.length), index.val ≤ j → j < r.val → (entries.val[j]'h).kid.val ≠ kid.val) ∧
        (∀ h : r.val < entries.val.length, (entries.val[r.val]'h).kid.val = kid.val) := by
  have bound := entries.property
  intro n
  induction n with
  | zero =>
    intro index m le
    refine ⟨index, ?_, le_refl _, le, fun j h a b => absurd b (by omega), fun h => absurd h (by omega)⟩
    rw [select_loop.eq_def]
    have c : ¬ index < Slice.len entries := by scalar_tac
    simp only [c, ↓reduceIte]
  | succ n ih =>
    intro index m le
    have inside : index.val < entries.val.length := by omega
    rw [select_loop.eq_def]
    have c : index < Slice.len entries := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq entries index inside, bind_ok, named_eq]
    by_cases hit : (entries.val[index.val]'inside).kid.val = kid.val
    · simp only [hit, decide_true, ↓reduceIte]
      exact ⟨index, rfl, le_refl _, le, fun j h a b => absurd b (by omega), fun _ => hit⟩
    · simp only [hit, decide_false, Bool.false_eq_true, ↓reduceIte]
      obtain ⟨j, hj, jv⟩ := usize_succ index (by omega)
      rw [hj]
      simp only [bind_ok]
      obtain ⟨r, hr, lo, hi, before, at_r⟩ := ih j (by omega) (by omega)
      refine ⟨r, hr, by omega, hi, fun k h a b => ?_, at_r⟩
      by_cases e : k = index.val
      · subst e; exact hit
      · exact before k h (by omega) b

/-- **`select` returns the first entry for `kid`**, or the length. -/
theorem select_spec {M : Type} (entries : Slice (KeyEntry M)) (kid : Slice U8) :
    ∃ r : Usize, select entries kid = Result.ok r ∧ r.val ≤ entries.val.length ∧
      (∀ j (h : j < entries.val.length), j < r.val → (entries.val[j]'h).kid.val ≠ kid.val) ∧
      (∀ h : r.val < entries.val.length, (entries.val[r.val]'h).kid.val = kid.val) := by
  unfold select
  obtain ⟨r, hr, _, hi, before, at_r⟩ := select_loop_spec entries kid _ 0#usize rfl (by simp)
  exact ⟨r, hr, hi, fun j h b => before j h (by simp) b, at_r⟩

/-- Entry `i` is the first one carrying its `kid`. -/
def FirstFor {M : Type} (l : List (KeyEntry M)) (i : Nat) (h : i < l.length) : Prop :=
  ∀ j (hj : j < i), (l[j]'(by omega)).kid.val ≠ (l[i]'h).kid.val

/-- What `entry_valid` checks. -/
def EntryValid {M : Type} (l : List (KeyEntry M)) (i : Nat) (h : i < l.length) : Prop :=
  Kid (l[i]'h).kid.val ∧ Text (l[i]'h).issuer.val ∧ FirstFor l i h

theorem entry_valid_true {M : Type} (entries : Slice (KeyEntry M)) (index : Usize)
    (inside : index.val < entries.val.length) :
    entry_valid entries index = Result.ok true ↔ EntryValid entries.val index.val inside := by
  unfold entry_valid EntryValid FirstFor
  simp only [slice_index_eq entries index inside, bind_ok, is_kid_eq, is_text_eq, deref_val, decide_eq_true_eq,
    ite_ok_false]
  obtain ⟨r, hr, hi, before, at_r⟩ := select_spec entries (alloc.vec.Vec.deref (entries.val[index.val]'inside).kid)
  simp only [deref_val] at before at_r
  rw [hr]
  simp only [bind_ok, Result.ok.injEq, decide_eq_true_eq]
  have first : r = index ↔ ∀ j (hj : j < index.val), (entries.val[j]'(by omega)).kid.val ≠
      (entries.val[index.val]'inside).kid.val := by
    constructor
    · intro e j hj; subst e; exact before j _ hj
    · intro h
      have rle : r.val ≤ index.val := by
        by_contra big
        exact before index.val inside (by omega) rfl
      have : ¬ r.val < index.val := fun lt => h r.val lt (at_r (by omega))
      exact UScalar.eq_of_val_eq (by omega)
  rw [first]

theorem entry_valid_total {M : Type} (entries : Slice (KeyEntry M)) (index : Usize)
    (inside : index.val < entries.val.length) : ∃ b, entry_valid entries index = Result.ok b := by
  unfold entry_valid
  simp only [slice_index_eq entries index inside, bind_ok, is_kid_eq, is_text_eq]
  obtain ⟨r, hr, _⟩ := select_spec entries (alloc.vec.Vec.deref (entries.val[index.val]'inside).kid)
  rw [hr]
  simp only [bind_ok]
  split_ifs <;> exact ⟨_, rfl⟩

theorem keys_valid_loop_spec {M : Type} (entries : Slice (KeyEntry M)) :
    ∀ n (valid : Bool) (index : Usize), entries.val.length - index.val = n → index.val ≤ entries.val.length →
      ∃ b, keys_valid_loop entries valid index = Result.ok b ∧
        (b = true ↔ valid = true ∧
          ∀ i (h : i < entries.val.length), index.val ≤ i → EntryValid entries.val i h) := by
  have bound := entries.property
  intro n
  induction n with
  | zero =>
    intro valid index m le
    refine ⟨valid, ?_, ⟨fun h => ⟨h, fun i h a => absurd h (by omega)⟩, fun h => h.1⟩⟩
    rw [keys_valid_loop.eq_def]
    have c : ¬ index < Slice.len entries := by scalar_tac
    simp only [c, ↓reduceIte]
  | succ n ih =>
    intro valid index m le
    have inside : index.val < entries.val.length := by omega
    rw [keys_valid_loop.eq_def]
    have c : index < Slice.len entries := by scalar_tac
    obtain ⟨b, hb⟩ := entry_valid_total entries index inside
    have ev := entry_valid_true entries index inside
    rw [hb] at ev
    obtain ⟨j, hj, jv⟩ := usize_succ index (by omega)
    simp only [c, ↓reduceIte, hb, bind_ok]
    obtain ⟨r, hr, rv⟩ := ih (if b = true then valid else false) j (by omega) (by omega)
    split_ifs at hr rv with hbt
    · simp only [hbt, ↓reduceIte, hj, bind_ok, hr]
      refine ⟨r, rfl, ?_⟩
      rw [rv]
      have here := ev.mp (by rw [hbt])
      constructor
      · rintro ⟨v, rest⟩
        refine ⟨v, fun i h a => ?_⟩
        by_cases e : i = index.val
        · subst e; exact here
        · exact rest i h (by omega)
      · rintro ⟨v, rest⟩
        exact ⟨v, fun i h a => rest i h (by omega)⟩
    · simp only [hbt, Bool.false_eq_true, ↓reduceIte, hj, bind_ok, hr]
      refine ⟨r, rfl, ?_⟩
      rw [rv]
      simp only [false_and, false_iff, not_and]
      intro _ rest
      exact hbt (by cases b <;> simp_all [Result.ok.injEq])

/-- What `keys_valid` accepts: 1 to 8 entries, each with a valid `kid` and
    issuer and the first entry for its `kid`. -/
def KeysValid {M : Type} (l : List (KeyEntry M)) : Prop :=
  1 ≤ l.length ∧ l.length ≤ 8 ∧ ∀ i (h : i < l.length), EntryValid l i h

theorem keys_valid_true {M : Type} (entries : Slice (KeyEntry M)) :
    keys_valid entries = Result.ok true ↔ KeysValid entries.val := by
  unfold keys_valid KeysValid
  simp only
  have := MAX_KEYS
  split_ifs with h1 h2
  · simp only [Result.ok.injEq, Bool.false_eq_true, false_iff, not_and]; scalar_tac
  · simp only [Result.ok.injEq, Bool.false_eq_true, false_iff, not_and]
    have : MAX_KEYS.val = 8 := by simp [MAX_KEYS]
    scalar_tac
  · obtain ⟨b, hb, bv⟩ := keys_valid_loop_spec entries _ true 0#usize rfl (by simp)
    rw [hb]
    have : MAX_KEYS.val = 8 := by simp [MAX_KEYS]
    have lens : 1 ≤ entries.val.length ∧ entries.val.length ≤ 8 := by scalar_tac
    simp only [Result.ok.injEq, bv, true_and, usize_zero_val, zero_le, forall_const, lens]

/-- **Key selection is unambiguous**: in a valid key set, no two entries share
    a `kid`, so `select` names the only entry for its `kid`, or none exists. -/
theorem keys_distinct {M : Type} {l : List (KeyEntry M)} (h : KeysValid l) :
    ∀ i j (hi : i < l.length) (hj : j < l.length), (l[i]'hi).kid.val = (l[j]'hj).kid.val → i = j := by
  intro i j hi hj e
  rcases Nat.lt_trichotomy i j with lt | eq | gt
  · exact absurd e ((h.2.2 j hj).2.2 i lt)
  · exact eq
  · exact absurd e.symm ((h.2.2 i hi).2.2 j gt)

/-- Conversely, 1 to 8 entries with valid names and distinct `kid`s are a
    valid key set. -/
theorem keys_valid_of {M : Type} {l : List (KeyEntry M)} (len : 1 ≤ l.length ∧ l.length ≤ 8)
    (names : ∀ i (h : i < l.length), Kid (l[i]'h).kid.val ∧ Text (l[i]'h).issuer.val)
    (distinct : ∀ i j (hi : i < l.length) (hj : j < l.length), (l[i]'hi).kid.val = (l[j]'hj).kid.val → i = j) :
    KeysValid l :=
  ⟨len.1, len.2, fun i h => ⟨(names i h).1, (names i h).2, fun j hj e => by
    have := distinct j i (by omega) h e; omega⟩⟩

theorem keys_nodup {M : Type} {l : List (KeyEntry M)} (h : KeysValid l) : (l.map (·.kid.val)).Nodup := by
  rw [List.Nodup, List.pairwise_iff_getElem]
  intro i j hi hj lt e
  simp only [List.getElem_map] at e
  have := keys_distinct h i j (by simpa using hi) (by simpa using hj) e
  omega

theorem select_unique {M : Type} (entries : Slice (KeyEntry M)) (kid : Slice U8) (valid : KeysValid entries.val) :
    ∃ r : Usize, select entries kid = Result.ok r ∧
      ((∃ h : r.val < entries.val.length, (entries.val[r.val]'h).kid.val = kid.val ∧
          ∀ j (hj : j < entries.val.length), (entries.val[j]'hj).kid.val = kid.val → j = r.val) ∨
        (r.val = entries.val.length ∧ ∀ j (hj : j < entries.val.length), (entries.val[j]'hj).kid.val ≠ kid.val)) := by
  obtain ⟨r, hr, hi, before, at_r⟩ := select_spec entries kid
  refine ⟨r, hr, ?_⟩
  by_cases lt : r.val < entries.val.length
  · exact Or.inl ⟨lt, at_r lt, fun j hj e => keys_distinct valid j r.val hj lt (by rw [e, at_r lt])⟩
  · exact Or.inr ⟨by omega, fun j hj => before j hj (by omega)⟩

/-! ## The version-1 header -/

/-- `{"alg":"EdDSA","kid":"` -/
def HS : List U8 := lit "{\"alg\":\"EdDSA\",\"kid\":\""
/-- `","typ":"garrett-stateless-v1+jwt"}` -/
def HE : List U8 := lit "\",\"typ\":\"garrett-stateless-v1+jwt\"}"

theorem header_start_val : HEADER_START.val = HS := by
  simp only [HEADER_START, array_slice_val]; rfl
theorem header_end_val : HEADER_END.val = HE := by
  simp only [HEADER_END, array_slice_val]; rfl
theorem hs_len : HS.length = 22 := by rfl
theorem he_len : HE.length = 35 := by rfl

/-- **The header writer**: exactly `HS ++ kid ++ HE`. -/
theorem header_bytes_ok {kid : Slice U8} {w : alloc.vec.Vec U8} (h : header_bytes kid = Result.ok w) :
    w.val = HS ++ kid.val ++ HE := by
  unfold header_bytes at h
  obtain ⟨o1, h1, h⟩ := bind_ok_inv h
  obtain ⟨o2, h2, h⟩ := bind_ok_inv h
  rw [append_ok h, append_ok h2, append_ok h1, header_start_val, header_end_val]
  simp

theorem header_bytes_spec (kid : Slice U8) (room : kid.val.length + 57 ≤ Usize.max) :
    ∃ w, header_bytes kid = Result.ok w ∧ w.val = HS ++ kid.val ++ HE := by
  unfold header_bytes
  have hl := hs_len; have el := he_len
  obtain ⟨o1, h1, v1⟩ := returned_of_spec (append_spec (alloc.vec.Vec.new U8) HEADER_START
    (by simp [header_start_val, hl]; omega))
  obtain ⟨o2, h2, v2⟩ := returned_of_spec (append_spec o1 kid (by rw [v1]; simp [header_start_val, hl]; omega))
  obtain ⟨o3, h3, v3⟩ := returned_of_spec (append_spec o2 HEADER_END
    (by rw [v2, v1]; simp [header_start_val, header_end_val, hl, el]; omega))
  refine ⟨o3, by rw [h1, bind_ok, h2, bind_ok, h3], ?_⟩
  rw [v3, v2, v1, header_start_val, header_end_val]
  simp

theorem slice_to_val {b : Slice U8} {hi : Usize} (inb : hi.val ≤ b.val.length) :
    core.slice.index.Slice.index (core.slice.index.SliceIndexRangeToUsizeSlice U8) b { «end» := hi } =
      Result.ok (Slice.from (b.val.take hi.val) (by have := b.property; simp only [List.length_take]; omega)) := by
  simp only [core.slice.index.Slice.index, core.slice.index.SliceIndexRangeToUsizeSlice.index]
  have : hi ≤ b.length := by scalar_tac
  simp only [this, ↓reduceIte, Result.ok.injEq, Slice.eq_iff, Slice.from_val]
  simp [List.slice]

theorem slice_from_val {b : Slice U8} {lo : Usize} (inb : lo.val ≤ b.val.length) :
    ∃ f, core.slice.index.Slice.index (core.slice.index.SliceIndexRangeFromUsizeSlice U8) b { start := lo } =
      Result.ok f ∧ f.val = b.val.drop lo.val := by
  obtain ⟨f, hf, fv, _⟩ := returned_of_spec
    (core.slice.index.SliceIndexRangeFromUsizeSlice.index.step_spec { start := lo } b (by simpa using inb))
  exact ⟨f, by simpa using hf, fv⟩

/-- The header shape a decomposition fixes: the prefix, suffix and middle. -/
theorem header_split {b k : List U8} (e : b = HS ++ k ++ HE) :
    b.take 22 = HS ∧ b.drop (b.length - 35) = HE ∧ (b.drop 22).take (b.length - 35 - 22) = k := by
  have hl := hs_len; have el := he_len
  subst e
  refine ⟨?_, ?_, ?_⟩
  · rw [List.append_assoc, List.take_append_of_le_length (by omega)]
    rw [← hl, List.take_length]
  · simp only [List.length_append, hl, el]
    rw [show 22 + k.length + 35 - 35 = (HS ++ k).length by simp [hl]]
    exact List.drop_left
  · simp only [List.length_append, hl, el, List.append_assoc]
    rw [show (22 : Nat) = HS.length from hl.symm, List.drop_left]
    rw [show HS.length + (k.length + 35) - 35 - HS.length = k.length by omega]
    exact List.take_left

/-- **`header_kid` accepts exactly the version-1 header.** It returns some
    `kid` only for `HS ++ kid ++ HE` with a valid `kid`, and none for every
    other byte string. -/
theorem header_kid_spec (b : Slice U8) :
    ∃ o, header_kid b = Result.ok o ∧
      (∀ v, o = some v → b.val = HS ++ v.val ++ HE ∧ Kid v.val) ∧
      (o = none → ¬ ∃ k, b.val = HS ++ k ++ HE ∧ Kid k) := by
  have hl := hs_len; have el := he_len
  have bound := b.property
  unfold header_kid
  simp only
  have sl : (Slice.len HEADER_START).val = 22 := by simp [header_start_val, hl]
  have el' : (Slice.len HEADER_END).val = 35 := by simp [header_end_val, el]
  obtain ⟨fixed, hf, fv⟩ := returned_of_spec (Usize.add_spec (x := Slice.len HEADER_START)
    (y := Slice.len HEADER_END) (by rw [sl, el']; have := usize_big; omega))
  rw [sl, el'] at fv
  rw [hf]
  simp only [bind_ok]
  by_cases short : b.val.length < 57
  · have : Slice.len b < fixed := by scalar_tac
    simp only [this, ↓reduceIte]
    refine ⟨none, rfl, fun v h => (by cases h), fun _ ⟨k, e, kid⟩ => ?_⟩
    have := congrArg List.length e
    simp only [List.length_append, hl, el] at this
    have := kid.1
    omega
  · have : ¬ Slice.len b < fixed := by scalar_tac
    simp only [this, ↓reduceIte]
    obtain ⟨tail, ht, tv⟩ := returned_of_spec (Usize.sub_spec (x := Slice.len b) (y := Slice.len HEADER_END)
      (by rw [el']; scalar_tac))
    rw [el'] at tv
    have tl : tail.val = b.val.length - 35 := by scalar_tac
    rw [ht]
    simp only [bind_ok]
    rw [slice_to_val (by rw [sl]; omega)]
    obtain ⟨ending, he, ev⟩ := slice_from_val (b := b) (lo := tail) (by scalar_tac)
    rw [he]
    simp only [bind_ok, slice_ne_eq, Slice.from_val, sl, header_start_val, header_end_val]
    by_cases start : b.val.take 22 = HS
    · simp only [start, ne_eq, not_true_eq_false, decide_false, Bool.false_eq_true, ↓reduceIte]
      by_cases ending_ok : ending.val = HE
      · simp only [ending_ok, not_true_eq_false, decide_false, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨mid, hm, mv⟩ := slice_range_val (b := b) (lo := Slice.len HEADER_START) (hi := tail)
          (by rw [sl]; omega) (by have : tail.val ≤ b.val.length := (by omega); exact this)
        rw [hm]
        simp only [bind_ok, is_kid_eq]
        rw [sl, tl] at mv
        have whole : b.val = HS ++ mid.val ++ HE := by
          have d : List.drop (b.val.length - 35 - 22) (List.drop 22 b.val) = List.drop tail.val b.val := by
            rw [List.drop_drop, tl]; congr 1; omega
          rw [mv, ← start, ← ending_ok, ev, ← d, List.append_assoc, List.take_append_drop, List.take_append_drop]
        by_cases kid : Kid mid.val
        · simp only [kid, decide_true, ↓reduceIte]
          obtain ⟨v, hv, vv⟩ := to_vec_val mid
          rw [hv]
          simp only [bind_ok]
          refine ⟨some v, rfl, fun w e => ?_, fun e => by cases e⟩
          simp only [Option.some.injEq] at e
          subst e
          rw [vv]; exact ⟨whole, kid⟩
        · simp only [kid, decide_false, Bool.false_eq_true, ↓reduceIte]
          refine ⟨none, rfl, fun v h => (by cases h), fun _ ⟨k, e, kk⟩ => kid ?_⟩
          have := (header_split e).2.2
          rw [(header_split whole).2.2] at this
          rw [this]; exact kk
      · simp only [ending_ok, not_false_eq_true, decide_true, ↓reduceIte]
        refine ⟨none, rfl, fun v h => (by cases h), fun _ ⟨k, e, _⟩ => ending_ok ?_⟩
        rw [ev, tl]; exact (header_split e).2.1
    · simp only [start, ne_eq, not_false_eq_true, decide_true, ↓reduceIte]
      exact ⟨none, rfl, fun v h => (by cases h), fun _ ⟨k, e, _⟩ => start (header_split e).1⟩

/-- The writer and the reader agree: `header_kid` of `header_bytes kid` is
    `kid` for every valid `kid`. -/
theorem header_kid_of {b : Slice U8} {k : List U8} (e : b.val = HS ++ k ++ HE) (kid : Kid k) :
    ∃ w, header_kid b = Result.ok (some w) ∧ w.val = k := by
  obtain ⟨o, ho, sound, complete⟩ := header_kid_spec b
  cases o with
  | none => exact absurd ⟨k, e, kid⟩ (complete rfl)
  | some w =>
    obtain ⟨e', _⟩ := sound w rfl
    refine ⟨w, ho, ?_⟩
    have := (header_split e').2.2
    rw [(header_split e).2.2] at this
    exact this.symm

/-! ## Three dot-separated segments -/

abbrev AsciiByte (x : U8) : Prop := x.val ≤ 127

theorem ascii_loop_eq (v : Slice U8) : ∀ i : Usize, i.val ≤ v.val.length →
    ascii_loop v i = Result.ok (decide (∀ x ∈ v.val.drop i.val, AsciiByte x)) := by
  apply all_loop AsciiByte v
  · intro i inside
    rw [ascii_loop.eq_def]
    have c : i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq v i inside, bind_ok]
    by_cases a : AsciiByte (v.val[i.val]'inside)
    · have : ¬ (v.val[i.val]'inside) > 127#u8 := by simp only [AsciiByte] at a; scalar_tac
      simp only [a, this, ↓reduceIte]
    · have : (v.val[i.val]'inside) > 127#u8 := by simp only [AsciiByte] at a; scalar_tac
      simp only [a, this, ↓reduceIte]
  · intro i out
    rw [ascii_loop.eq_def]
    have c : ¬ i < Slice.len v := by scalar_tac
    simp only [c, ↓reduceIte]

theorem ascii_eq (v : Slice U8) : opening.ascii v = Result.ok (decide (∀ x ∈ v.val, AsciiByte x)) := by
  unfold opening.ascii
  have := ascii_loop_eq v 0#usize (by simp)
  rw [usize_zero_val, List.drop_zero] at this
  exact this

/-- No `.` byte. -/
def NoDot (l : List U8) : Prop := ∀ x ∈ l, x.val ≠ 46

/-- The index of the first `.` (or the length). -/
def firstDot (l : List U8) : Nat := l.findIdx (fun x => decide (x.val = 46))

theorem firstDot_le (l : List U8) : firstDot l ≤ l.length := List.findIdx_le_length

theorem firstDot_none {l : List U8} (h : NoDot l) : firstDot l = l.length :=
  List.findIdx_eq_length.mpr (fun x m => by simpa using h x m)

theorem firstDot_none_iff {l : List U8} : firstDot l = l.length ↔ NoDot l := by
  unfold firstDot NoDot
  rw [List.findIdx_eq_length]
  simp

theorem firstDot_split {a r : List U8} (h : NoDot a) : firstDot (a ++ 46#u8 :: r) = a.length := by
  unfold firstDot
  rw [List.findIdx_append]
  have := firstDot_none h
  unfold firstDot at this
  rw [this]
  simp only [Nat.lt_irrefl, ↓reduceIte, List.findIdx_cons, show (46#u8 : U8).val = 46 from rfl, decide_true,
    Nat.zero_add]

/-- At the first `.` a list splits into a dot-free prefix, the dot, and the rest. -/
theorem split_first_dot {l : List U8} (lt : firstDot l < l.length) :
    l = l.take (firstDot l) ++ 46#u8 :: l.drop (firstDot l + 1) ∧ NoDot (l.take (firstDot l)) := by
  have dot : (l[firstDot l]'lt).val = 46 := by
    have := List.findIdx_getElem (p := fun x : U8 => decide (x.val = 46)) (xs := l) (w := lt)
    exact of_decide_eq_true this
  constructor
  · conv => lhs; rw [← List.take_append_drop (firstDot l) l]
    rw [List.drop_eq_getElem_cons lt]
    congr 2
    exact UScalar.eq_of_val_eq (by rw [dot]; rfl)
  · intro x m
    obtain ⟨j, hj, e⟩ := List.mem_take_iff_getElem.mp m
    unfold firstDot at hj
    have := List.not_of_lt_findIdx (p := fun x : U8 => decide (x.val = 46)) (xs := l) (i := j) (by omega)
    rw [← e]
    simpa using this

theorem dot_from_loop_eq (t : Slice U8) : ∀ n (index : Usize), t.val.length - index.val = n →
    index.val ≤ t.val.length →
    ∃ r : Usize, dot_from_loop t index = Result.ok r ∧ r.val = index.val + firstDot (t.val.drop index.val) := by
  have bound := t.property
  intro n
  induction n with
  | zero =>
    intro index m le
    refine ⟨index, ?_, by simp [show t.val.length ≤ index.val by omega, firstDot]⟩
    rw [dot_from_loop.eq_def]
    have c : ¬ index < Slice.len t := by scalar_tac
    simp only [c, ↓reduceIte]
  | succ n ih =>
    intro index m le
    have inside : index.val < t.val.length := by omega
    have hd : t.val.drop index.val = t.val[index.val] :: t.val.drop (index.val + 1) :=
      List.drop_eq_getElem_cons inside
    rw [dot_from_loop.eq_def]
    have c : index < Slice.len t := by scalar_tac
    simp only [c, ↓reduceIte, slice_index_eq t index inside, bind_ok, u8_bne]
    by_cases dot : (t.val[index.val]'inside).val = 46
    · have : ¬ (t.val[index.val]'inside).val ≠ (46#u8).val := by simp [dot]
      simp only [this, decide_false, Bool.false_eq_true, ↓reduceIte]
      refine ⟨index, rfl, ?_⟩
      rw [hd]
      simp only [firstDot, List.findIdx_cons, dot, decide_true, ↓reduceIte, Nat.add_zero]
    · have : (t.val[index.val]'inside).val ≠ (46#u8).val := by simpa using dot
      simp only [ne_eq, this, not_false_eq_true, decide_true, ↓reduceIte]
      obtain ⟨j, hj, jv⟩ := usize_succ index (by omega)
      rw [hj]
      simp only [bind_ok]
      obtain ⟨r, hr, rv⟩ := ih j (by omega) (by omega)
      refine ⟨r, hr, ?_⟩
      rw [rv, jv, hd]
      simp only [firstDot, List.findIdx_cons, dot, decide_false, Bool.false_eq_true, ↓reduceIte]
      omega

theorem dot_from_eq (t : Slice U8) (index : Usize) (le : index.val ≤ t.val.length) :
    ∃ r : Usize, dot_from t index = Result.ok r ∧ r.val = index.val + firstDot (t.val.drop index.val) := by
  unfold dot_from
  exact dot_from_loop_eq t _ index rfl le

theorem drop_dot (a r : List U8) : (a ++ 46#u8 :: r).drop (a.length + 1) = r := by
  induction a with
  | nil => rfl
  | cons x xs ih => simp

theorem ge_len {a : Usize} {t : Slice U8} (h : t.val.length ≤ a.val) : a ≥ Slice.len t := by scalar_tac
theorem not_ge_len {a : Usize} {t : Slice U8} (h : a.val < t.val.length) : ¬ a ≥ Slice.len t := by scalar_tac
theorem lt_len {a : Usize} {t : Slice U8} (h : a.val < t.val.length) : a < Slice.len t := by scalar_tac
theorem not_lt_len {a : Usize} {t : Slice U8} (h : t.val.length ≤ a.val) : ¬ a < Slice.len t := by scalar_tac

/-- `t` is three dot-free segments joined by two dots. -/
def Segments (t a b c : List U8) : Prop :=
  t = a ++ 46#u8 :: (b ++ 46#u8 :: c) ∧ NoDot a ∧ NoDot b ∧ NoDot c

/-- **`segments` accepts exactly the three-segment ASCII tokens** of at most
    16384 bytes, and returns the positions of their two dots. -/
theorem segments_spec (t : Slice U8) :
    ∃ o, segments t = Result.ok o ∧
      (∀ f s, o = some (f, s) → t.val.length ≤ 16384 ∧ (∀ x ∈ t.val, AsciiByte x) ∧
        ∃ a b c, Segments t.val a b c ∧ f.val = a.length ∧ s.val = a.length + 1 + b.length) ∧
      (∀ a b c, Segments t.val a b c → t.val.length ≤ 16384 → (∀ x ∈ t.val, AsciiByte x) →
        ∃ f s, o = some (f, s) ∧ f.val = a.length ∧ s.val = a.length + 1 + b.length) := by
  have bound := t.property
  have mt : MAX_TOKEN.val = 16384 := by simp [MAX_TOKEN]
  unfold segments
  simp only
  by_cases big : t.val.length > 16384
  · have : Slice.len t > MAX_TOKEN := by scalar_tac
    simp only [this, ↓reduceIte]
    exact ⟨none, rfl, fun f s h => (by cases h), fun a b c _ small _ => absurd small (by omega)⟩
  · have : ¬ Slice.len t > MAX_TOKEN := by scalar_tac
    simp only [this, ↓reduceIte]
    rw [ascii_eq, bind_ok]
    by_cases asc : ∀ x ∈ t.val, AsciiByte x
    · rw [decide_eq_true asc]
      simp only [↓reduceIte]
      obtain ⟨first, hf, fv⟩ := dot_from_eq t 0#usize (by simp)
      rw [usize_zero_val, List.drop_zero, Nat.zero_add] at fv
      rw [hf]
      simp only [bind_ok]
      by_cases noFirst : first.val ≥ t.val.length
      · have : first ≥ Slice.len t := by scalar_tac
        simp only [this, ↓reduceIte]
        refine ⟨none, rfl, fun f s h => (by cases h), fun a b c seg _ _ => ?_⟩
        obtain ⟨e, na, _, _⟩ := seg
        have := firstDot_split (r := b ++ 46#u8 :: c) na
        rw [← e] at this
        have : a.length < t.val.length := by rw [e]; simp
        omega
      · have : ¬ first ≥ Slice.len t := by scalar_tac
        simp only [this, ↓reduceIte]
        obtain ⟨i2, h2, i2v⟩ := usize_succ first (by omega)
        rw [h2]
        simp only [bind_ok]
        obtain ⟨second, hs, sv⟩ := dot_from_eq t i2 (by omega)
        rw [hs]
        simp only [bind_ok]
        have lt1 : firstDot t.val < t.val.length := by omega
        obtain ⟨split1, na⟩ := split_first_dot lt1
        rw [i2v, fv] at sv
        have r1len : (t.val.drop (firstDot t.val + 1)).length = t.val.length - (firstDot t.val + 1) :=
          List.length_drop
        generalize hR1 : t.val.drop (firstDot t.val + 1) = R1 at sv split1 r1len
        -- Any decomposition fixes the first dot and the rest after it.
        have first_of : ∀ a b c, Segments t.val a b c → firstDot t.val = a.length ∧ R1 = b ++ 46#u8 :: c := by
          intro a b c ⟨e, na', _, _⟩
          have fa : firstDot t.val = a.length := by rw [e]; exact firstDot_split na'
          refine ⟨fa, ?_⟩
          rw [← hR1, fa, e]
          exact drop_dot a _
        by_cases noSecond : second.val ≥ t.val.length
        · simp only [ge_len noSecond, ↓reduceIte]
          refine ⟨none, rfl, fun f s h => (by cases h), fun a b c seg _ _ => ?_⟩
          obtain ⟨fa, r1⟩ := first_of a b c seg
          have fb : firstDot R1 = b.length := by rw [r1]; exact firstDot_split seg.2.2.1
          have := congrArg List.length r1
          simp only [List.length_append, List.length_cons] at this
          omega
        · simp only [not_ge_len (by omega : second.val < t.val.length), ↓reduceIte]
          obtain ⟨i4, h4, i4v⟩ := usize_succ second (by omega)
          rw [h4]
          simp only [bind_ok]
          obtain ⟨third, h5, tv⟩ := dot_from_eq t i4 (by omega)
          rw [h5]
          simp only [bind_ok]
          have lt2 : firstDot R1 < R1.length := by omega
          obtain ⟨split2, nb⟩ := split_first_dot lt2
          have r2 : R1.drop (firstDot R1 + 1) = t.val.drop i4.val := by
            rw [i4v, sv, ← hR1, List.drop_drop]; congr 1
          have r2len : (t.val.drop i4.val).length = t.val.length - i4.val := List.length_drop
          rw [r2] at split2
          generalize hR2 : t.val.drop i4.val = R2 at split2 tv r2len
          have whole : t.val = t.val.take (firstDot t.val) ++ 46#u8 ::
              (R1.take (firstDot R1) ++ 46#u8 :: R2) := by
            rw [← split2]; exact split1
          have rest_of : ∀ a b c, Segments t.val a b c → firstDot R1 = b.length ∧ R2 = c := by
            intro a b c seg
            obtain ⟨_, r1⟩ := first_of a b c seg
            have fb : firstDot R1 = b.length := by rw [r1]; exact firstDot_split seg.2.2.1
            refine ⟨fb, ?_⟩
            rw [← hR2, ← r2, fb, r1]
            exact drop_dot b c
          have i4le : i4.val ≤ t.val.length := by omega
          by_cases third_dot : third.val < t.val.length
          · simp only [lt_len third_dot, ↓reduceIte]
            refine ⟨none, rfl, fun f s h => (by cases h), fun a b c seg _ _ => ?_⟩
            obtain ⟨_, r2c⟩ := rest_of a b c seg
            have := firstDot_none seg.2.2.2
            rw [← r2c] at this
            omega
          · simp only [not_lt_len (by omega : t.val.length ≤ third.val), ↓reduceIte]
            have nc : NoDot R2 := firstDot_none_iff.mp (by have := firstDot_le R2; omega)
            have flen : (t.val.take (firstDot t.val)).length = firstDot t.val := by
              rw [List.length_take]; omega
            have slen : (R1.take (firstDot R1)).length = firstDot R1 := by
              rw [List.length_take]; omega
            refine ⟨some (first, second), rfl, fun f s h => ?_, fun a b c seg _ _ => ?_⟩
            · simp only [Option.some.injEq, Prod.mk.injEq] at h
              obtain ⟨e1, e2⟩ := h
              subst e1 e2
              refine ⟨by omega, asc, _, _, _, ⟨whole, na, nb, nc⟩, by rw [flen, fv], ?_⟩
              rw [flen, slen, sv]
            · obtain ⟨fa, _⟩ := first_of a b c seg
              obtain ⟨fb, _⟩ := rest_of a b c seg
              exact ⟨first, second, rfl, by rw [fv, fa], by rw [sv, fa, fb]⟩
    · rw [decide_eq_false asc]
      simp only [Bool.false_eq_true, ↓reduceIte]
      exact ⟨none, rfl, fun f s h => (by cases h), fun a b c _ _ a' => absurd a' asc⟩

/-! ## Substring search -/

/-- `n` occurs in `h` at some position at or after `start`. -/
def OccursFrom (h n : List U8) (start : Nat) : Prop :=
  ∃ k, start ≤ k ∧ k + n.length ≤ h.length ∧ (h.drop k).take n.length = n

theorem occurs_loop_spec (h n : Slice U8) (room : h.val.length < Usize.max) (nonempty : 1 ≤ n.val.length) :
    ∀ m (start : Usize) (found : Bool), h.val.length + 1 - start.val = m →
      start.val + n.val.length ≤ h.val.length + 1 →
      ∃ b, occurs_loop h n found start = Result.ok b ∧
        (b = true ↔ found = true ∨ OccursFrom h.val n.val start.val) := by
  intro m
  induction m with
  | zero => intro start found meas fits; omega
  | succ m ih =>
    intro start found meas fits
    rw [occurs_loop.eq_def]
    cases found
    · simp only [Bool.false_eq_true, ↓reduceIte]
      obtain ⟨i1, h1, v1⟩ := returned_of_spec (Usize.add_spec (x := start) (y := Slice.len n) (by scalar_tac))
      rw [h1]
      simp only [bind_ok]
      by_cases within : start.val + n.val.length ≤ h.val.length
      · have : i1 ≤ Slice.len h := by scalar_tac
        simp only [this, ↓reduceIte]
        obtain ⟨window, hw, wv⟩ := slice_range_val (b := h) (lo := start) (hi := i1) (by scalar_tac)
          (by have : i1.val ≤ h.val.length := by scalar_tac
              exact this)
        rw [hw]
        simp only [bind_ok, slice_eq_eq]
        have wl : i1.val - start.val = n.val.length := by scalar_tac
        rw [wl] at wv
        obtain ⟨s1, hs1, sv1⟩ := usize_succ start (by omega)
        by_cases hit : window.val = n.val
        · simp only [hit, decide_true, ↓reduceIte, hs1, bind_ok]
          obtain ⟨b, hb, bv⟩ := ih s1 true (by omega) (by omega)
          refine ⟨b, hb, ?_⟩
          rw [bv]
          simp only [true_or, false_or, true_iff]
          exact ⟨start.val, le_refl _, within, by rw [← wv, hit]⟩
        · simp only [hit, decide_false, Bool.false_eq_true, ↓reduceIte, hs1, bind_ok]
          obtain ⟨b, hb, bv⟩ := ih s1 false (by omega) (by omega)
          refine ⟨b, hb, ?_⟩
          rw [bv, sv1]
          simp only [Bool.false_eq_true, false_or]
          constructor
          · rintro ⟨k, a, b, c⟩; exact ⟨k, by omega, b, c⟩
          · rintro ⟨k, a, b, c⟩
            refine ⟨k, ?_, b, c⟩
            by_contra lt
            have : k = start.val := by omega
            subst this
            exact hit (by rw [wv, c])
      · have : ¬ i1 ≤ Slice.len h := by scalar_tac
        simp only [this, ↓reduceIte]
        refine ⟨false, rfl, ?_⟩
        simp only [Bool.false_eq_true, false_or, false_iff]
        rintro ⟨k, a, b, _⟩
        omega
    · simp only [↓reduceIte]
      exact ⟨true, rfl, by simp⟩

theorem occurs_from_zero (h n : List U8) : OccursFrom h n 0 ↔ n <:+: h := by
  constructor
  · rintro ⟨k, _, fits, e⟩
    refine ⟨h.take k, h.drop (k + n.length), ?_⟩
    conv => rhs; rw [← List.take_append_drop k h]
    rw [List.append_assoc]
    congr 1
    conv => rhs; rw [← List.take_append_drop n.length (h.drop k)]
    rw [e, List.drop_drop]
  · rintro ⟨s, t, e⟩
    subst e
    refine ⟨s.length, Nat.zero_le _, by simp, ?_⟩
    simp [List.append_assoc]

/-- **`occurs` is substring search**, exactly. -/
theorem occurs_spec (h n : Slice U8) (room : h.val.length < Usize.max) :
    ∃ b, occurs h n = Result.ok b ∧ (b = true ↔ n.val <:+: h.val) := by
  unfold occurs
  simp only
  by_cases empty : n.val.length = 0
  · have : Slice.len n = 0#usize := by scalar_tac
    simp only [this, ↓reduceIte]
    refine ⟨true, rfl, ?_⟩
    simp [List.eq_nil_of_length_eq_zero empty]
  · have : ¬ Slice.len n = 0#usize := by scalar_tac
    simp only [this, ↓reduceIte]
    by_cases fits : n.val.length ≤ h.val.length + 1
    · obtain ⟨b, hb, bv⟩ := occurs_loop_spec h n room (by omega) _ 0#usize false rfl (by simp; omega)
      refine ⟨b, hb, ?_⟩
      rw [bv, usize_zero_val, occurs_from_zero]
      simp
    · -- The needle is longer than the haystack: the first bound check fails.
      rw [occurs_loop.eq_def]
      simp only [Bool.false_eq_true, ↓reduceIte]
      obtain ⟨i1, h1, v1⟩ := returned_of_spec (Usize.add_spec (x := 0#usize) (y := Slice.len n) (by scalar_tac))
      rw [h1]
      have : ¬ i1 ≤ Slice.len h := by scalar_tac
      simp only [bind_ok, this, ↓reduceIte]
      refine ⟨false, rfl, ?_⟩
      simp only [Bool.false_eq_true, false_iff]
      intro inf
      have := inf.length_le
      omega

end garrett_stateless_core.stateless_token.Proofs
