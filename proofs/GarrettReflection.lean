import Garrett

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.reflection.Proofs

/-- Exact literal occurrence at an offset, with no decoder or alternate encoding. -/
def MatchesAt (value secret : Slice U8) (start : Nat) : Prop :=
  start + secret.length ≤ value.length ∧
    value.val.slice start (start + secret.length) = secret.val

theorem matches_at_contract (value secret : Slice U8) (start : Usize) :
    matches_at value secret start ⦃ out => out ↔ MatchesAt value secret start.val ⦄ := by
  rw [matches_at]
  by_cases after : start > value.len
  · simp only [after, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    constructor
    · intro impossible
      cases impossible
    · intro matching
      have fits := matching.1
      scalar_tac
  · have within : start.val ≤ value.length := by scalar_tac
    simp only [after, ↓reduceIte]
    obtain ⟨room, sub_return, room_value⟩ := returned_of_spec (@Usize.sub_spec value.len start (by scalar_tac))
    rw [sub_return]
    simp only [bind_ok]
    by_cases large : secret.len > room
    · simp only [large, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      constructor
      · intro impossible
        cases impossible
      · intro matching
        have fits := matching.1
        scalar_tac
    · have fits : start.val + secret.length ≤ value.length := by scalar_tac
      simp only [large, ↓reduceIte]
      obtain ⟨finish, add_return, finish_value⟩ := returned_of_spec
        (@Usize.add_spec start secret.len (by scalar_tac))
      rw [add_return]
      simp only [bind_ok]
      apply WP.spec_bind (core.slice.index.SliceIndexRangeUsizeSlice.index.step_spec
        (s := value) (r := {start := start, «end» := finish}) (by scalar_tac) (by scalar_tac))
      intro selected selected_property
      apply WP.spec_mono (core.slice.cmp.PartialEqSlice.eq_homo_spec
        core.cmp.PartialEqU8 selected secret (by intro x y; simp))
      intro out property
      simpa [MatchesAt, fits, Slice.eq_iff, selected_property.1, finish_value] using property

def ContainsFrom (value secret : Slice U8) (start last : Nat) : Prop :=
  ∃ index, start ≤ index ∧ index ≤ last ∧ MatchesAt value secret index

theorem contains_from_step (value secret : Slice U8) (start last : Nat) (inside : start ≤ last) :
    ContainsFrom value secret start last ↔
      MatchesAt value secret start ∨ ContainsFrom value secret (start + 1) last := by
  constructor
  · rintro ⟨index, after, before, matching⟩
    by_cases same : index = start
    · exact Or.inl (by simpa [same] using matching)
    · exact Or.inr ⟨index, by omega, before, matching⟩
  · rintro (matching | ⟨index, after, before, matching⟩)
    · exact ⟨start, Nat.le_refl _, inside, matching⟩
    · exact ⟨index, by omega, before, matching⟩

theorem contains_loop_contract (value secret : Slice U8) (last start : Usize)
    (room : last.val < Usize.max) :
    contains_loop value secret last start ⦃ out => out ↔ ContainsFrom value secret start.val last.val ⦄ := by
  suffices ∀ n (i : Usize), last.val + 1 - i.val = n →
      contains_loop value secret last i ⦃ out => out ↔ ContainsFrom value secret i.val last.val ⦄ from
    this _ start rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [contains_loop.eq_def]
    by_cases inside : i ≤ last
    · have bound : i.val ≤ last.val := by scalar_tac
      simp only [inside, ↓reduceIte]
      apply WP.spec_bind (matches_at_contract value secret i)
      intro found matching
      cases found with
      | true =>
        simp only [↓reduceIte]
        apply (WP.spec_ok _).mpr
        constructor
        · intro _
          exact ⟨i.val, Nat.le_refl _, bound, matching.mp rfl⟩
        · intro _
          rfl
      | false =>
        have absent : ¬ MatchesAt value secret i.val := by simpa using matching
        obtain ⟨next, advanced, next_value⟩ := returned_of_spec (@Usize.add_spec i 1#usize (by scalar_tac))
        rw [advanced]
        simp only [bind_ok]
        apply WP.spec_mono (ih (last.val + 1 - next.val) (by scalar_tac) next rfl)
        intro out property
        rw [contains_from_step value secret i.val last.val bound]
        simpa [absent, next_value] using property
    · have beyond : last.val < i.val := by scalar_tac
      simp only [inside, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      constructor
      · intro impossible
        cases impossible
      · rintro ⟨index, after, before, _⟩
        omega

/-- Empty credentials are not a reflection needle; acquisition validates them
separately. Every nonempty literal match, including the final offset, is found. -/
def LiteralOccurs (value secret : Slice U8) : Prop :=
  secret.length ≠ 0 ∧ ∃ start, MatchesAt value secret start

theorem contains_contract (value secret : Slice U8) :
    contains value secret ⦃ out => out ↔ LiteralOccurs value secret ⦄ := by
  rw [contains]
  by_cases empty : secret.len = 0#usize
  · have zero : secret.length = 0 := by scalar_tac
    simp only [empty, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    simp [LiteralOccurs, zero]
  · have nonempty : secret.length ≠ 0 := by scalar_tac
    simp only [empty, ↓reduceIte]
    by_cases large : secret.len > value.len
    · have longer : value.length < secret.length := by scalar_tac
      simp only [large, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      constructor
      · intro impossible
        cases impossible
      · rintro ⟨_, index, matching⟩
        have fits := matching.1
        scalar_tac
    · have fits : secret.length ≤ value.length := by scalar_tac
      simp only [large, ↓reduceIte]
      obtain ⟨last, returned, last_value⟩ := returned_of_spec (@Usize.sub_spec value.len secret.len (by scalar_tac))
      rw [returned]
      simp only [bind_ok]
      apply WP.spec_mono (contains_loop_contract value secret last 0#usize (by scalar_tac))
      intro out property
      apply property.trans
      constructor
      · rintro ⟨index, _, _, matching⟩
        exact ⟨nonempty, index, matching⟩
      · rintro ⟨_, index, matching⟩
        refine ⟨index, Nat.zero_le _, ?_, matching⟩
        have bound := matching.1
        scalar_tac

theorem reflected_credential_is_detected (value secret : Slice U8) (occurs : LiteralOccurs value secret) :
    contains value secret = Result.ok true := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (contains_contract value secret)
  have positive : out = true := property.mpr occurs
  simpa [positive] using returned

theorem false_search_excludes_literal (value secret : Slice U8)
    (returned : contains value secret = Result.ok false) : ¬ LiteralOccurs value secret := by
  intro occurs
  have detected := reflected_credential_is_detected value secret occurs
  rw [returned] at detected
  have impossible : (false : Bool) = true := Result.ok_injective detected
  cases impossible

theorem nonempty_self_is_detected (value : Slice U8) (nonempty : value.length ≠ 0) :
    contains value value = Result.ok true := by
  apply reflected_credential_is_detected
  refine ⟨nonempty, 0, ?_⟩
  simp [MatchesAt, List.slice, Slice.length]

end aivm_secrets_garrett_core.reflection.Proofs
