import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.json_string.Proofs

def Scalar (value : Nat) : Prop := value ≤ 1114111 ∧ (value < 55296 ∨ 57343 < value)

def Nibble (value : Nat) : U8 :=
  U8.ofNatCore (if value % 16 < 10 then 48 + value % 16 else 87 + value % 16) (by split <;> scalar_tac)

def Hex4 (value : Nat) : List U8 :=
  [Nibble (value / 4096), Nibble (value / 256), Nibble (value / 16), Nibble value]

def Wide (value : Nat) : List U8 :=
  if value ≤ 65535 then [92#u8, 117#u8] ++ Hex4 value
  else [92#u8, 117#u8] ++ Hex4 (55296 + (value - 65536) / 1024) ++
    [92#u8, 117#u8] ++ Hex4 (56320 + (value - 65536) % 1024)

def Escape (value : Nat) : List U8 :=
  if value = 34 then [92#u8, 34#u8]
  else if value = 92 then [92#u8, 92#u8]
  else if value = 8 then [92#u8, 98#u8]
  else if value = 12 then [92#u8, 102#u8]
  else if value = 10 then [92#u8, 110#u8]
  else if value = 13 then [92#u8, 114#u8]
  else if value = 9 then [92#u8, 116#u8]
  else if h : 32 ≤ value ∧ value ≤ 126 then [U8.ofNatCore value (by scalar_tac)]
  else Wide value

theorem nibble_value (value : Nat) :
    (Nibble value).val = if value % 16 < 10 then 48 + value % 16 else 87 + value % 16 := by simp [Nibble]

@[simp] theorem nibble_mod (value : Nat) : Nibble (value % 16) = Nibble value := by
  simp [Nibble]

theorem nibble_printable (value : Nat) : 48 ≤ (Nibble value).val ∧ (Nibble value).val ≤ 102 := by
  rw [nibble_value]
  split <;> omega

theorem surrogate_pair_exact (value : Nat) (low : 65536 ≤ value) (high : value ≤ 1114111) :
    let first := 55296 + (value - 65536) / 1024
    let second := 56320 + (value - 65536) % 1024
    55296 ≤ first ∧ first ≤ 56319 ∧ 56320 ≤ second ∧ second ≤ 57343 ∧
      65536 + (first - 55296) * 1024 + (second - 56320) = value := by
  dsimp
  omega

@[step] theorem valid_scalar_contract (value : U32) :
    valid_scalar value ⦃ out => out ↔ Scalar value.val ⦄ := by
  unfold valid_scalar
  split <;> try split
  all_goals (apply (WP.spec_ok _).mpr; simp_all [Scalar])

@[step] theorem hex_digit_contract (value : U32) (bound : value.val < 16) :
    hex_digit value ⦃ out => out = Nibble value.val ⦄ := by
  unfold hex_digit
  split
  · step
    step
    apply UScalar.eq_of_val_eq
    rw [nibble_value]
    split <;> scalar_tac
  · step
    step
    step
    apply UScalar.eq_of_val_eq
    rw [nibble_value]
    split <;> scalar_tac

@[step] private theorem extend_bytes_contract (output : alloc.vec.Vec U8) (bytes : Slice U8)
    (room : output.length + bytes.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 output bytes ⦃ out =>
      out.val = output.val ++ bytes.val ∧ out.length = output.length + bytes.length ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  rw [dite_eq_left room]
  apply WP.spec_bind (List.clone_spec (clone := core.clone.CloneU8.clone)
    (l := bytes.val) (by intro x hx; simp))
  intro cloned exact_copy
  simp [exact_copy.1]

@[step] private theorem push_byte_contract (output : alloc.vec.Vec U8) (byte : U8)
    (room : output.length < Usize.max) :
    alloc.vec.Vec.push output byte ⦃ out => out.val = output.val ++ [byte] ∧ out.length = output.length + 1 ⦄ := by
  apply WP.spec_mono (alloc.vec.Vec.push_spec output byte room)
  intro out equal
  refine ⟨equal, ?_⟩
  change out.val.length = output.val.length + 1
  simp [equal]

@[step] theorem append_hex_contract (output : alloc.vec.Vec U8) (value : U32)
    (room : output.length + 6 ≤ Usize.max) :
    append_hex output value ⦃ out => out.val = output.val ++ [92#u8, 117#u8] ++ Hex4 value.val ∧ out.length = output.length + 6 ⦄ := by
  unfold append_hex
  step
  have prefix_len : s.length = 2 := by rw [s_post]; rfl
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  step (config := {scalarTac := true, simpStar := true})
  simp_all [Hex4, List.append_assoc]

@[step] theorem append_wide_contract (output : alloc.vec.Vec U8) (value : U32)
    (valid : value.val ≤ 1114111) (room : output.length + 12 ≤ Usize.max) :
    append_wide output value ⦃ out => out.val = output.val ++ Wide value.val ∧
      out.length = output.length + (Wide value.val).length ⦄ := by
  unfold append_wide
  split
  · step (config := {scalarTac := true, simpStar := true})
    have low : value.val ≤ 65535 := by scalar_tac
    simp_all [Wide, Hex4, List.append_assoc]
  · step (config := {scalarTac := true, simpStar := true})
    step (config := {scalarTac := true, simpStar := true})
    step (config := {scalarTac := true, simpStar := true})
    step (config := {scalarTac := true, simpStar := true})
    step (config := {scalarTac := true, simpStar := true})
    step (config := {scalarTac := true, simpStar := true})
    step (config := {scalarTac := true, simpStar := true})
    have high : ¬value.val ≤ 65535 := by scalar_tac
    simp only [Wide, ite_eq_right high, Hex4]
    simp_all [Hex4, List.append_assoc]

theorem escape_length (value : Nat) : (Escape value).length ≤ 12 := by
  unfold Escape
  repeat' split
  all_goals simp [Wide, Hex4]
  all_goals (split <;> simp)

@[step] theorem append_scalar_contract (output : alloc.vec.Vec U8) (value : U32)
    (valid : Scalar value.val) (room : output.length + 12 ≤ Usize.max) :
    append_scalar output value ⦃ out => out.val = output.val ++ Escape value.val ∧
      out.length = output.length + (Escape value.val).length ⦄ := by
  by_cases code34 : value.val = 34
  · have same : value = 34#u32 := by apply UScalar.eq_of_val_eq; simpa using code34
    subst value
    simp only [append_scalar, ↓reduceIte]
    step
    have prefix_len : s.length = 2 := by rw [s_post]; rfl
    step (config := {scalarTac := true, simpStar := true})
    simp_all [Escape]
  · have neq34 : value ≠ 34#u32 := by scalar_tac
    by_cases code92 : value.val = 92
    · have same : value = 92#u32 := by apply UScalar.eq_of_val_eq; simpa using code92
      subst value
      simp only [append_scalar, neq34, ↓reduceIte]
      step
      have prefix_len : s.length = 2 := by rw [s_post]; rfl
      step (config := {scalarTac := true, simpStar := true})
      simp_all [Escape]
    · have neq92 : value ≠ 92#u32 := by scalar_tac
      by_cases code8 : value.val = 8
      · have same : value = 8#u32 := by apply UScalar.eq_of_val_eq; simpa using code8
        subst value
        simp only [append_scalar, neq34, neq92, ↓reduceIte]
        step
        have prefix_len : s.length = 2 := by rw [s_post]; rfl
        step (config := {scalarTac := true, simpStar := true})
        simp_all [Escape]
      · have neq8 : value ≠ 8#u32 := by scalar_tac
        by_cases code12 : value.val = 12
        · have same : value = 12#u32 := by apply UScalar.eq_of_val_eq; simpa using code12
          subst value
          simp only [append_scalar, neq34, neq92, neq8, ↓reduceIte]
          step
          have prefix_len : s.length = 2 := by rw [s_post]; rfl
          step (config := {scalarTac := true, simpStar := true})
          simp_all [Escape]
        · have neq12 : value ≠ 12#u32 := by scalar_tac
          by_cases code10 : value.val = 10
          · have same : value = 10#u32 := by apply UScalar.eq_of_val_eq; simpa using code10
            subst value
            simp only [append_scalar, neq34, neq92, neq8, neq12, ↓reduceIte]
            step
            have prefix_len : s.length = 2 := by rw [s_post]; rfl
            step (config := {scalarTac := true, simpStar := true})
            simp_all [Escape]
          · have neq10 : value ≠ 10#u32 := by scalar_tac
            by_cases code13 : value.val = 13
            · have same : value = 13#u32 := by apply UScalar.eq_of_val_eq; simpa using code13
              subst value
              simp only [append_scalar, neq34, neq92, neq8, neq12, neq10, ↓reduceIte]
              step
              have prefix_len : s.length = 2 := by rw [s_post]; rfl
              step (config := {scalarTac := true, simpStar := true})
              simp_all [Escape]
            · have neq13 : value ≠ 13#u32 := by scalar_tac
              by_cases code9 : value.val = 9
              · have same : value = 9#u32 := by apply UScalar.eq_of_val_eq; simpa using code9
                subst value
                simp only [append_scalar, neq34, neq92, neq8, neq12, neq10, neq13, ↓reduceIte]
                step
                have prefix_len : s.length = 2 := by rw [s_post]; rfl
                step (config := {scalarTac := true, simpStar := true})
                simp_all [Escape]
              · have neq9 : value ≠ 9#u32 := by scalar_tac
                unfold append_scalar
                simp only [neq34, neq92, neq8, neq12, neq10, neq13, neq9]
                by_cases low : 32#u32 ≤ value
                · by_cases high : value ≤ 126#u32
                  · simp only [low, high, ↓reduceIte]
                    step
                    step (config := {scalarTac := true, simpStar := true})
                    have ascii : 32 ≤ value.val ∧ value.val ≤ 126 := by scalar_tac
                    have bound : value.val < 2 ^ UScalarTy.U8.numBits := by scalar_tac
                    have byte_eq : i = U8.ofNatCore value.val bound := by
                      apply UScalar.eq_of_val_eq
                      scalar_tac
                    have escaped : Escape value.val = [U8.ofNatCore value.val bound] := by
                      simp [Escape, code34, code92, code8, code12, code10, code13, code9, ascii]
                    rw [escaped]
                    exact ⟨by simpa only [byte_eq] using out_post, by simpa using out_post1⟩
                  · simp only [low, high, ↓reduceIte]
                    step (config := {scalarTac := true, simpStar := true})
                    have ascii : ¬(32 ≤ value.val ∧ value.val ≤ 126) := by scalar_tac
                    have escaped : Escape value.val = Wide value.val := by simp [Escape, code34, code92, code8, code12, code10, code13, code9, ascii]
                    simpa only [escaped] using And.intro out_post out_post1
                · simp only [low, ↓reduceIte]
                  step (config := {scalarTac := true, simpStar := true})
                  have ascii : ¬(32 ≤ value.val ∧ value.val ≤ 126) := by scalar_tac
                  have escaped : Escape value.val = Wide value.val := by simp [Escape, code34, code92, code8, code12, code10, code13, code9, ascii]
                  simpa only [escaped] using And.intro out_post out_post1

def Printable (bytes : List U8) : Prop := ∀ byte ∈ bytes, 32 ≤ byte.val ∧ byte.val ≤ 126

theorem printable_append (first second : List U8) : Printable (first ++ second) ↔ Printable first ∧ Printable second := by
  constructor
  · intro valid
    exact ⟨fun byte member => valid byte (List.mem_append_left _ member),
      fun byte member => valid byte (List.mem_append_right _ member)⟩
  · rintro ⟨left, right⟩ byte member
    rcases List.mem_append.mp member with first | second
    · exact left byte first
    · exact right byte second

theorem hex4_printable (value : Nat) : Printable (Hex4 value) := by
  intro byte member
  simp only [Hex4, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with same | same | same | same
  all_goals subst byte
  · have bounds := nibble_printable (value / 4096); omega
  · have bounds := nibble_printable (value / 256); omega
  · have bounds := nibble_printable (value / 16); omega
  · have bounds := nibble_printable value; omega

theorem wide_printable (value : Nat) : Printable (Wide value) := by
  have leader : Printable [92#u8, 117#u8] := by simp [Printable]
  unfold Wide
  split
  · exact (printable_append _ _).mpr ⟨leader, hex4_printable value⟩
  · exact (printable_append _ _).mpr ⟨(printable_append _ _).mpr
      ⟨(printable_append _ _).mpr ⟨leader, hex4_printable _⟩, leader⟩, hex4_printable _⟩

theorem escape_printable (value : Nat) : Printable (Escape value) := by
  unfold Escape
  repeat' split
  all_goals first | exact wide_printable value | simp_all [Printable]

end aivm_secrets_garrett_core.json_string.Proofs
