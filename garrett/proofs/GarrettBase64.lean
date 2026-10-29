import GarrettStatelessCore
import GarrettFoundation

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
set_option maxHeartbeats 4000000

/-! The extracted unpadded base64 encoder is injective. The native broker's
`crypto::decode` accepts text only if re-encoding the decoded bytes gives the
same text, so with this encoder the accepted bytes are the unique preimage of
the text, whatever the decoding library returned. -/
namespace garrett_stateless_core.proxy_http.Base64Proofs

/-- The symbol for a 6-bit value, as a number. -/
def symNat (v : Nat) (url : Bool) : Nat :=
  if v < 26 then 65 + v
  else if v < 52 then 71 + v
  else if v < 62 then v - 4
  else if v = 62 then (if url then 45 else 43)
  else (if url then 95 else 47)

theorem symNat_injective (a b : Nat) (url : Bool) (ha : a < 64) (hb : b < 64)
    (same : symNat a url = symNat b url) : a = b := by
  unfold symNat at same
  cases url <;> split_ifs at same <;> omega

theorem symbol_spec (v : U8) (url : Bool) (small : v.val < 64) :
    base64_symbol v url ⦃ s => s.val = symNat v.val url ⦄ := by
  unfold base64_symbol symNat
  split
  · step*
  · split
    · step*
    · split
      · step*
      · split
        · cases url <;> simp_all [WP.spec_ok]
        · cases url <;> simp_all [WP.spec_ok] <;> split_ifs <;> omega

/-- Shift, or and mask on a byte pair are the arithmetic group extraction. -/
theorem pair_bits (h l k : Nat) (hh : h < 256) (hl : l < 256) :
    (((h <<< 8 % U16.size) ||| l) >>> k) &&& 63 = ((h * 256 + l) / 2 ^ k) % 64 := by
  have shifted : h <<< 8 % U16.size = h <<< 8 := by
    apply Nat.mod_eq_of_lt
    rw [Nat.shiftLeft_eq]; simp [U16.size, U16.numBits]; omega
  rw [shifted, ← Nat.shiftLeft_add_eq_or_of_lt (by omega : l < 2 ^ 8), Nat.shiftLeft_eq,
    Nat.shiftRight_eq_div_pow, show (63 : Nat) = 2 ^ 6 - 1 from rfl,
    Nat.and_two_pow_sub_one_eq_mod]

theorem u8_to_u16 (i : U8) : (UScalar.cast .U16 i).val = i.val := by
  have := UScalar.cast_val_mod_pow_greater_numBits_eq .U16 i (by decide)
  simpa [UScalar.cast_val_eq] using this

theorem u16_to_u8 (i : U16) (small : i.val < 256) : (UScalar.cast .U8 i).val = i.val := by
  have := UScalar.cast_val_mod_pow_of_inBounds_eq .U8 i (by simpa using small)
  simpa using this

/-- Group `i` of the bytes: bits `6i .. 6i+6`, zero past the end. -/
def sexNat (l : List U8) (i : Nat) : Nat :=
  (((l.getD (6 * i / 8) 0#u8).val * 256 + (l.getD (6 * i / 8 + 1) 0#u8).val) /
    2 ^ (10 - 6 * i % 8)) % 64

theorem sextet_spec (bytes : Slice U8) (index : Usize)
    (inside : 6 * index.val / 8 < bytes.length) (fits : 6 * index.val ≤ Usize.max) :
    sextet bytes index ⦃ s => s.val = sexNat bytes.val index.val ∧ s.val < 64 ⦄ := by
  unfold sextet
  step*
  split
  · step*
    have hi : i.val < 256 := by scalar_tac
    have hx : x.val < 256 := by scalar_tac
    have e6 : i6.val = ((i.val * 256 + x.val) / 2 ^ (10 - offset.val)) % 64 := by
      rw [i6_post, UScalar.val_and, i5_post, pair_post, UScalar.val_or, i3_post, high_post,
        u8_to_u16, u8_to_u16, ← i4_post]
      exact pair_bits _ _ _ hi hx
    have small : i6.val < 64 := by rw [e6]; omega
    rw [u16_to_u8 _ (by omega), e6]
    refine ⟨?_, by omega⟩
    unfold sexNat
    have inb : byte.val < bytes.val.length := by simp at inside; scalar_tac
    have inb1 : i1.val < bytes.val.length := by simpa [Slice.len] using ‹i1 < bytes.len›
    rw [List.getD_eq_getElem _ _ (by scalar_tac), List.getD_eq_getElem _ _ (by scalar_tac)]
    simp only [i_post, x_post, offset_post, byte_post, bit_post, i1_post]
    ring_nf
  · step*
    have hi : i.val < 256 := by scalar_tac
    have e6 : i6.val = ((i.val * 256 + 0) / 2 ^ (10 - offset.val)) % 64 := by
      rw [i6_post, UScalar.val_and, i5_post, pair_post, UScalar.val_or, i3_post, high_post,
        u8_to_u16, ← i4_post]
      exact pair_bits _ _ _ hi (by decide)
    rw [u16_to_u8 _ (by omega), e6]
    refine ⟨?_, by omega⟩
    unfold sexNat
    have outside : bytes.val.length ≤ i1.val := by
      have := ‹¬i1 < bytes.len›; simp [Slice.len] at this; scalar_tac
    rw [List.getD_eq_getElem _ _ (by scalar_tac), List.getD_eq_default _ _ (by scalar_tac)]
    simp only [i_post, offset_post, byte_post, bit_post]
    ring_nf
    simp


/-- The encoding as numbers: the symbol of every group `0 .. ceil(8n/6)`. -/
def enc (l : List U8) (url : Bool) : List Nat :=
  (List.range ((8 * l.length + 5) / 6)).map (fun i => symNat (sexNat l i) url)

theorem encode_loop_spec (bytes : Slice U8) (url : Bool) (stop : Usize)
    (out : alloc.vec.Vec U8) (index : Usize)
    (bound : stop.val = (8 * bytes.length + 5) / 6) (fits : 8 * bytes.length + 5 ≤ Usize.max)
    (below : index.val ≤ stop.val) (sized : out.length = index.val) :
    encode_unpadded_loop bytes url stop out index ⦃ r =>
      r.val.map (·.val) = out.val.map (·.val) ++
        (List.range' index.val (stop.val - index.val)).map
          (fun i => symNat (sexNat bytes.val i) url) ⦄ := by
  suffices ∀ n (index : Usize) (out : alloc.vec.Vec U8), stop.val - index.val = n →
      index.val ≤ stop.val → out.length = index.val →
      encode_unpadded_loop bytes url stop out index ⦃ r =>
        r.val.map (·.val) = out.val.map (·.val) ++
          (List.range' index.val (stop.val - index.val)).map
            (fun i => symNat (sexNat bytes.val i) url) ⦄ from this _ index out rfl below sized
  intro n
  induction n with
  | zero =>
    intro index out measure below sized
    rw [encode_unpadded_loop.eq_def]
    have stopped : ¬ index < stop := by scalar_tac
    simp only [stopped, ↓reduceIte, WP.spec_ok]
    simp [measure]
  | succ n ih =>
    intro index out measure below sized
    rw [encode_unpadded_loop.eq_def]
    have running : index < stop := by scalar_tac
    simp only [running, ↓reduceIte]
    have inside : 6 * index.val / 8 < bytes.length := by omega
    have small : 6 * index.val ≤ Usize.max := by omega
    apply WP.spec_bind (sextet_spec bytes index inside small)
    intro s ⟨sv, slt⟩
    apply WP.spec_bind (symbol_spec s url slt)
    intro c cv
    step*
    · simp_all [alloc.vec.Vec.length]
    · rw [r_post, out1_post]
      have split : stop.val - index.val = (stop.val - index1.val) + 1 := by scalar_tac
      rw [split, List.range'_succ]
      simp_all

/-- The extracted encoder computes `enc`. -/
theorem encode_unpadded_spec (bytes : Slice U8) (url : Bool)
    (fits : 8 * bytes.length + 5 ≤ Usize.max) :
    encode_unpadded bytes url ⦃ r => r.val.map (·.val) = enc bytes.val url ⦄ := by
  unfold encode_unpadded
  step*
  apply WP.spec_mono (encode_loop_spec bytes url «end» (alloc.vec.Vec.new U8) 0#usize
    (by scalar_tac) fits (by scalar_tac) (by simp))
  intro r hr
  rw [hr]
  have stop : «end».val = (8 * bytes.val.length + 5) / 6 := by scalar_tac
  simp [enc, List.range_eq_range', stop]

section injective

def g (l : List U8) (j : Nat) : Nat := (l.getD j 0#u8).val

theorem g_lt (l : List U8) (j : Nat) : g l j < 256 := by
  unfold g; scalar_tac

theorem s0 (l : List U8) (q : Nat) :
    sexNat l (4 * q) = (g l (3 * q) * 256 + g l (3 * q + 1)) / 1024 % 64 := by
  unfold sexNat g
  rw [show 6 * (4 * q) / 8 = 3 * q by omega, show 6 * (4 * q) % 8 = 0 by omega]
  norm_num
theorem s1 (l : List U8) (q : Nat) :
    sexNat l (4 * q + 1) = (g l (3 * q) * 256 + g l (3 * q + 1)) / 16 % 64 := by
  unfold sexNat g
  rw [show 6 * (4 * q + 1) / 8 = 3 * q by omega, show 6 * (4 * q + 1) % 8 = 6 by omega]
  norm_num
theorem s2 (l : List U8) (q : Nat) :
    sexNat l (4 * q + 2) = (g l (3 * q + 1) * 256 + g l (3 * q + 2)) / 64 % 64 := by
  unfold sexNat g
  rw [show 6 * (4 * q + 2) / 8 = 3 * q + 1 by omega, show 6 * (4 * q + 2) % 8 = 4 by omega]
  norm_num
theorem s3 (l : List U8) (q : Nat) :
    sexNat l (4 * q + 3) = (g l (3 * q + 2) * 256 + g l (3 * q + 3)) / 256 % 64 := by
  unfold sexNat g
  rw [show 6 * (4 * q + 3) / 8 = 3 * q + 2 by omega, show 6 * (4 * q + 3) % 8 = 2 by omega]
  norm_num

/-- Equal groups below `ceil(8n/6)` give equal bytes below `n`. -/
theorem bytes_of_groups (a b : List U8) (n : Nat)
    (same : ∀ i, i < (8 * n + 5) / 6 → sexNat a i = sexNat b i) (k : Nat) (hk : k < n) :
    g a k = g b k := by
  obtain ⟨q, r, hr, rfl⟩ : ∃ q r, r < 3 ∧ k = 3 * q + r := ⟨k / 3, k % 3, by omega, by omega⟩
  have ha := g_lt a (3 * q); have ha1 := g_lt a (3 * q + 1); have ha2 := g_lt a (3 * q + 2)
  have ha3 := g_lt a (3 * q + 3)
  have hb := g_lt b (3 * q); have hb1 := g_lt b (3 * q + 1); have hb2 := g_lt b (3 * q + 2)
  have hb3 := g_lt b (3 * q + 3)
  rcases (by omega : r = 0 ∨ r = 1 ∨ r = 2) with rfl | rfl | rfl
  · have e0 := same (4 * q) (by omega); have e1 := same (4 * q + 1) (by omega)
    rw [s0, s0] at e0; rw [s1, s1] at e1
    simp only [Nat.add_zero]; omega
  · have e1 := same (4 * q + 1) (by omega); have e2 := same (4 * q + 2) (by omega)
    rw [s1, s1] at e1; rw [s2, s2] at e2
    omega
  · have e2 := same (4 * q + 2) (by omega); have e3 := same (4 * q + 3) (by omega)
    rw [s2, s2] at e2; rw [s3, s3] at e3
    omega

theorem sexNat_lt (l : List U8) (i : Nat) : sexNat l i < 64 := by
  unfold sexNat; omega

/-- Different byte strings never have the same unpadded encoding. -/
theorem enc_injective (a b : List U8) (url : Bool) (same : enc a url = enc b url) : a = b := by
  have lengths := congrArg List.length same
  simp only [enc, List.length_map, List.length_range] at lengths
  have n_eq : a.length = b.length := by omega
  have groups : ∀ i, i < (8 * a.length + 5) / 6 → sexNat a i = sexNat b i := by
    intro i hi
    have hb : i < (8 * b.length + 5) / 6 := by omega
    have := congrArg (fun l => l[i]?) same
    simp only [enc, List.getElem?_map, List.getElem?_range hi, List.getElem?_range hb,
      Option.map_some, Option.some.injEq] at this
    exact symNat_injective _ _ url (sexNat_lt a i) (sexNat_lt b i) this
  apply List.ext_getElem n_eq
  intro k hka hkb
  have := bytes_of_groups a b a.length groups k hka
  unfold g at this
  rw [List.getD_eq_getElem _ _ hka, List.getD_eq_getElem _ _ hkb] at this
  exact UScalar.eq_of_val_eq this

end injective

end garrett_stateless_core.proxy_http.Base64Proofs
