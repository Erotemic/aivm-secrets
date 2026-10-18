import GarrettHttpWireFormatting

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.http_auth.Proofs
open aivm_secrets_garrett_core.http_request.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.http_wire.Proofs

def ByteRangeFrom (bytes : Slice U8) (start low high : Nat) : Prop :=
  ∀ (i : Nat) (inside : i < bytes.length), start ≤ i →
    low ≤ (bytes.val[i]'inside).val ∧ (bytes.val[i]'inside).val ≤ high

theorem byte_range_step (bytes : Slice U8) (start low high : Nat)
    (inside : start < bytes.length) :
    ByteRangeFrom bytes start low high ↔
      (low ≤ (bytes.val[start]'inside).val ∧ (bytes.val[start]'inside).val ≤ high) ∧
        ByteRangeFrom bytes (start + 1) low high := by
  constructor
  · intro tail
    exact ⟨tail start inside (Nat.le_refl _), fun i hi after => tail i hi (by omega)⟩
  · rintro ⟨first, rest⟩ i hi after
    by_cases same : i = start
    · subst i; exact first
    · exact rest i hi (by omega)

/-- The two actual loops use the same equation with different lower bounds.
    Supplying the generated unfolding equation checks that correspondence. -/
theorem byte_range_loop_contract (loop : core.slice.iter.Iter U8 → Result Bool)
    (low high : U8)
    (equation : ∀ it, loop it = do
      let (value, next) ← core.slice.iter.IteratorSliceIter.next it
      match value with
      | none => Result.ok true
      | some byte =>
        if byte < low then Result.ok false
        else if byte > high then Result.ok false else loop next)
    (iter : core.slice.iter.Iter U8) :
    loop iter ⦃ out => out ↔ ByteRangeFrom iter.slice iter.i low.val high.val ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter U8), it.slice.length - it.i = n →
      loop it ⦃ out => out ↔ ByteRangeFrom it.slice it.i low.val high.val ⦄ from this _ iter rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [equation]
    by_cases inside : it.i < it.slice.length
    · have next : core.slice.iter.IteratorSliceIter.next it =
          Result.ok (some (it.slice.val[it.i]'inside), {it with i := it.i + 1}) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
        rfl
      rw [next]
      simp only [bind_ok]
      change (if (it.slice.val[it.i]'inside) < low then Result.ok false
        else if (it.slice.val[it.i]'inside) > high then Result.ok false
        else loop {it with i := it.i + 1})
        ⦃ out => out ↔ ByteRangeFrom it.slice it.i low.val high.val ⦄
      by_cases small : (it.slice.val[it.i]'inside) < low
      · simp only [small, ↓reduceIte]
        apply (WP.spec_ok _).mpr
        simp only [Bool.false_eq_true, false_iff]
        intro tail
        have first := tail it.i inside (Nat.le_refl _)
        scalar_tac
      · simp only [small, ↓reduceIte]
        by_cases large : (it.slice.val[it.i]'inside) > high
        · simp only [large, ↓reduceIte]
          apply (WP.spec_ok _).mpr
          simp only [Bool.false_eq_true, false_iff]
          intro tail
          have first := tail it.i inside (Nat.le_refl _)
          scalar_tac
        · simp only [large, ↓reduceIte]
          apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by omega)
            {it with i := it.i + 1} rfl)
          intro out tail
          rw [byte_range_step it.slice it.i low.val high.val inside]
          have first : low.val ≤ it.slice.val[it.i].val ∧ it.slice.val[it.i].val ≤ high.val := by
            scalar_tac
          simpa only [first, true_and] using tail
    · have next : core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
      rw [next]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      simp only [true_iff]
      intro i hi after
      omega

def HostChar (byte : U8) : Prop := AlphaNumeric byte ∨ byte = 46#u8 ∨ byte = 45#u8
def HostFrom (bytes : Slice U8) (start : Nat) : Prop :=
  ∀ (i : Nat) (hi : i < bytes.length), start ≤ i → HostChar (bytes.val[i]'hi)

theorem host_from_step (bytes : Slice U8) (start : Nat) (inside : start < bytes.length) :
    HostFrom bytes start ↔ HostChar (bytes.val[start]'inside) ∧ HostFrom bytes (start + 1) := by
  constructor
  · intro tail
    exact ⟨tail start inside (Nat.le_refl _), fun i hi after => tail i hi (by omega)⟩
  · rintro ⟨first, rest⟩ i hi after
    by_cases same : i = start
    · subst i; exact first
    · exact rest i hi (by omega)

@[step]
theorem valid_host_loop_sound (iter : core.slice.iter.Iter U8) :
    valid_host_loop iter ⦃ out => out = true → HostFrom iter.slice iter.i ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter U8), it.slice.length - it.i = n →
      valid_host_loop it ⦃ out => out = true → HostFrom it.slice it.i ⦄ from this _ iter rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [valid_host_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have next : core.slice.iter.IteratorSliceIter.next it =
          Result.ok (some it.slice[it.i], {it with i := it.i + 1}) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
        rfl
      rw [next]
      simp only [bind_ok]
      have recur (first : HostChar it.slice[it.i]) :
          valid_host_loop {it with i := it.i + 1} ⦃ out => out = true → HostFrom it.slice it.i ⦄ := by
        apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by omega)
          {it with i := it.i + 1} rfl)
        intro out tail accepted
        rw [host_from_step it.slice it.i inside]
        exact ⟨first, tail accepted⟩
      step
      cases found : out with
      | true =>
        simp only [↓reduceIte]
        apply recur
        exact Or.inl (out_post.mp found)
      | false =>
        simp only [Bool.false_eq_true, ↓reduceIte]
        by_cases dot : it.slice[it.i] = 46#u8
        · simp only [dot, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
          exact recur (Or.inr (Or.inl dot))
        · have not_dot : (it.slice[it.i] != 46#u8) = true := by simpa only [bne_iff_ne] using dot
          simp only [not_dot, ↓reduceIte]
          by_cases dash : it.slice[it.i] = 45#u8
          · simp only [dash, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
            exact recur (Or.inr (Or.inr dash))
          · have not_dash : (it.slice[it.i] != 45#u8) = true := by simpa only [bne_iff_ne] using dash
            simp [not_dash]
    · have next : core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
      rw [next]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      intro accepted i hi after
      omega

def ValidHost (host : Slice U8) : Prop :=
  0 < host.length ∧ host.length ≤ 253 ∧ HostFrom host 0

def ValidAccept (accept : Slice U8) : Prop :=
  0 < accept.length ∧ accept.length ≤ 96 ∧ ByteRangeFrom accept 0 33 126

@[step]
theorem valid_host_sound (host : Slice U8) :
    valid_host host ⦃ out => out = true → ValidHost host ⦄ := by
  unfold valid_host
  dsimp only
  split
  · simp
  · split
    · simp
    · simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
      apply WP.spec_mono (valid_host_loop_sound ⟨host, 0⟩)
      intro out tail accepted
      exact ⟨by scalar_tac, by scalar_tac, tail accepted⟩

@[step]
theorem valid_accept_contract (accept : Slice U8) :
    valid_accept accept ⦃ out => out ↔ ValidAccept accept ⦄ := by
  unfold valid_accept
  dsimp only
  split
  next empty =>
    apply (WP.spec_ok _).mpr
    simp only [Bool.false_eq_true, false_iff]
    intro valid
    have positive := valid.1
    scalar_tac
  next nonempty =>
    split
    next large =>
      apply (WP.spec_ok _).mpr
      simp only [Bool.false_eq_true, false_iff]
      intro valid
      have bound := valid.2.1
      scalar_tac
    next bounded =>
      simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
      apply WP.spec_mono (byte_range_loop_contract valid_accept_loop 33#u8 126#u8
        (by intro it; exact valid_accept_loop.eq_def it) ⟨accept, 0⟩)
      intro out bytes
      have positive : 0 < accept.length := by scalar_tac
      have bound : accept.length ≤ 96 := by scalar_tac
      simpa [ValidAccept, positive, bound] using bytes

@[step]
theorem max_body_contract : MAX_BODY ⦃ out => out.val = 2097152 ⦄ := by
  unfold MAX_BODY
  step
  step
  scalar_tac

theorem max_body_exact : MAX_BODY = Result.ok 2097152#usize := by
  obtain ⟨out, returned, exact_value⟩ := returned_of_spec max_body_contract
  have same : out = 2097152#usize := by apply UScalar.eq_of_val_eq; simpa using exact_value
  simpa only [same] using returned

@[step]
theorem valid_body_contract (body : Option (Slice U8)) :
    valid_body body ⦃ out => out ↔ match body with | none => True | some bytes => bytes.length ≤ 2097152 ⦄ := by
  cases body <;> simp [valid_body, max_body_exact]

theorem slice_index_exact {T : Type} (bytes : Slice T) (index : Usize)
    (inside : index.val < bytes.length) :
    Slice.index_usize bytes index = Result.ok (bytes.val[index.val]'inside) := by
  obtain ⟨value, returned, exact_value⟩ := returned_of_spec (Slice.index_usize_spec bytes index inside)
  simpa only [exact_value] using returned

def NameChar (byte : U8) (index : Nat) : Prop :=
  AlphaNumeric byte ∨ (0 < index ∧ byte = 45#u8)
def NameFrom (bytes : Slice U8) (start : Nat) : Prop :=
  ∀ (i : Nat) (inside : i < bytes.length), start ≤ i → NameChar (bytes.val[i]'inside) i

theorem name_from_step (bytes : Slice U8) (start : Nat) (inside : start < bytes.length) :
    NameFrom bytes start ↔ NameChar (bytes.val[start]'inside) start ∧ NameFrom bytes (start + 1) := by
  constructor
  · intro tail
    exact ⟨tail start inside (Nat.le_refl _), fun i hi after => tail i hi (by omega)⟩
  · rintro ⟨first, rest⟩ i hi after
    by_cases same : i = start
    · subst i; exact first
    · exact rest i hi (by omega)

@[step]
theorem valid_name_loop_sound (bytes : Slice U8) (index : Usize) :
    valid_name_loop bytes index ⦃ out => out = true →
      NameFrom bytes index.val ∧ ¬Reserved bytes ⦄ := by
  suffices ∀ n (i : Usize), bytes.length - i.val = n →
      valid_name_loop bytes i ⦃ out => out = true → NameFrom bytes i.val ∧ ¬Reserved bytes ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [valid_name_loop.eq_def]
    by_cases inside : i.val < bytes.length
    · have scalar_inside : i < Slice.len bytes := by scalar_tac
      simp only [scalar_inside, ↓reduceIte, slice_index_exact bytes i inside, bind_ok]
      let char := bytes.val[i.val]'inside
      have advance (first : NameChar char i.val) :
          (do let next ← i + 1#usize; valid_name_loop bytes next)
            ⦃ out => out = true → NameFrom bytes i.val ∧ ¬Reserved bytes ⦄ := by
        apply WP.spec_bind (@Usize.add_spec i 1#usize (by scalar_tac))
        intro next advanced
        apply WP.spec_mono (ih (bytes.length - next.val) (by scalar_tac) next rfl)
        intro out tail accepted
        obtain ⟨glyphs, unreserved⟩ := tail accepted
        refine ⟨?_, unreserved⟩
        rw [name_from_step bytes i.val inside]
        refine ⟨first, ?_⟩
        simpa [advanced] using glyphs
      obtain ⟨alpha, checked, membership⟩ := returned_of_spec (alphanumeric_contract char)
      rw [checked]
      simp only [bind_ok]
      change (if alpha then (do let next ← i + 1#usize; valid_name_loop bytes next)
        else if i = 0#usize then Result.ok false
        else if char != 45#u8 then Result.ok false
        else (do let next ← i + 1#usize; valid_name_loop bytes next))
        ⦃ out => out = true → NameFrom bytes i.val ∧ ¬Reserved bytes ⦄
      cases found : alpha with
      | true =>
        simp only [↓reduceIte]
        exact advance (Or.inl (membership.mp found))
      | false =>
        simp only [Bool.false_eq_true, ↓reduceIte]
        by_cases zero : i = 0#usize
        · simp [zero]
        · simp only [zero, ↓reduceIte]
          by_cases dash : char = 45#u8
          · simp only [dash, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
            exact advance (Or.inr ⟨by scalar_tac, dash⟩)
          · have different : (char != 45#u8) = true := by simpa only [bne_iff_ne] using dash
            simp [different]
    · have outside : ¬i < Slice.len bytes := by scalar_tac
      simp only [outside, ↓reduceIte]
      apply WP.spec_bind (reserved_name_contract bytes)
      intro reserved property
      cases found : reserved with
      | true => simp
      | false =>
        apply (WP.spec_ok _).mpr
        intro accepted
        refine ⟨?_, ?_⟩
        · intro j hj after; omega
        · intro forbidden
          have positive := property.mpr forbidden
          simp [found] at positive

def ValidName (bytes : Slice U8) : Prop :=
  0 < bytes.length ∧ bytes.length ≤ 64 ∧ NameFrom bytes 0 ∧ ¬Reserved bytes

@[step]
theorem valid_name_sound (bytes : Slice U8) :
    valid_name bytes ⦃ out => out = true → ValidName bytes ⦄ := by
  unfold valid_name
  dsimp only
  split
  · simp
  · split
    · simp
    · apply WP.spec_mono (valid_name_loop_sound bytes 0#usize)
      intro out tail accepted
      obtain ⟨glyphs, unreserved⟩ := tail accepted
      exact ⟨by scalar_tac, by scalar_tac, by simpa using glyphs, unreserved⟩

def ValueEdges (bytes : Slice U8) : Prop :=
  ∀ (i : Nat) (inside : i < bytes.length), i = 0 ∨ i + 1 = bytes.length →
    (bytes.val[i]'inside) ≠ 32#u8

def ValidValue (bytes : Slice U8) : Prop :=
  0 < bytes.length ∧ bytes.length ≤ 256 ∧ ValueEdges bytes ∧ ByteRangeFrom bytes 0 32 126

@[step]
theorem valid_value_sound (bytes : Slice U8) :
    valid_value bytes ⦃ out => out = true → ValidValue bytes ⦄ := by
  unfold valid_value
  dsimp only
  split
  · simp
  · split
    · simp
    · rw [slice_index_exact bytes 0#usize (by scalar_tac)]
      simp only [bind_ok]
      split
      · simp
      next not_first_space =>
        obtain ⟨last, subtraction, point⟩ := returned_of_spec
          (@Usize.sub_spec (Slice.len bytes) 1#usize (by scalar_tac))
        rw [subtraction]
        simp only [bind_ok]
        rw [slice_index_exact bytes last (by scalar_tac)]
        simp only [bind_ok]
        split
        · simp
        next not_last_space =>
          simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
          apply WP.spec_mono (byte_range_loop_contract valid_value_loop 32#u8 126#u8
            (by intro it; exact valid_value_loop.eq_def it) ⟨bytes, 0⟩)
          intro out characters accepted
          refine ⟨by scalar_tac, by scalar_tac, ?_, ?_⟩
          · intro i inside edge
            rcases edge with first | final
            · subst i
              simpa using not_first_space
            · have index : i = last.val := by scalar_tac
              subst i
              exact not_last_space
          · simpa using characters.mp accepted

def ValidHeader (header : Header) : Prop :=
  ValidName (alloc.vec.Vec.deref header.name) ∧ ValidValue (alloc.vec.Vec.deref header.value)

@[step]
theorem valid_header_sound (header : Header) :
    valid_header header ⦃ out => out = true → ValidHeader header ⦄ := by
  obtain ⟨admitted, checked, property⟩ := returned_of_spec
    (valid_name_sound (alloc.vec.Vec.deref header.name))
  unfold valid_header
  dsimp only
  rw [checked]
  simp only [bind_ok]
  cases accepted : admitted with
  | false => simp
  | true =>
    simp only [↓reduceIte]
    apply WP.spec_mono (valid_value_sound (alloc.vec.Vec.deref header.value))
    intro out valid success
    exact ⟨property accepted, valid success⟩

def UniqueFrom (headers : Slice Header) (candidate : Slice U8) (start stop : Nat) : Prop :=
  ∀ (j : Nat) (inside : j < headers.length), start ≤ j → j < stop →
    ¬FoldedEqual (alloc.vec.Vec.deref (headers.val[j]'inside).name) candidate

@[step]
theorem unique_before_loop_sound (headers : Slice Header) (stop : Usize)
    (candidate : Slice U8) (index : Usize) (bound : stop.val ≤ headers.length) :
    unique_before_loop headers stop candidate index ⦃ out => out = true →
      UniqueFrom headers candidate index.val stop.val ⦄ := by
  suffices ∀ n (j : Usize), stop.val - j.val = n →
      unique_before_loop headers stop candidate j ⦃ out => out = true →
        UniqueFrom headers candidate j.val stop.val ⦄ from this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro j measure
    rw [unique_before_loop.eq_def]
    by_cases inside : j < stop
    · simp only [inside, ↓reduceIte]
      have hi : j.val < headers.length := by scalar_tac
      rw [slice_index_exact headers j hi]
      simp only [bind_ok]
      let previous := headers.val[j.val]'hi
      obtain ⟨equal, compared, property⟩ := returned_of_spec
        (ascii_equal_contract (alloc.vec.Vec.deref previous.name) candidate)
      rw [compared]
      simp only [bind_ok]
      cases found : equal with
      | true => simp
      | false =>
        simp only [Bool.false_eq_true, ↓reduceIte]
        apply WP.spec_bind (@Usize.add_spec j 1#usize (by scalar_tac))
        intro next advanced
        apply WP.spec_mono (ih (stop.val - next.val) (by scalar_tac) next rfl)
        intro out tail accepted i ii after before
        by_cases same : i = j.val
        · subst i
          intro collision
          have impossible := property.mpr collision
          simp [found] at impossible
        · have later : next.val ≤ i := by scalar_tac
          exact tail accepted i ii later before
    · simp only [inside, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      intro accepted i ii after before
      scalar_tac

@[step]
theorem unique_before_sound (headers : Slice Header) (stop : Usize) (candidate : Slice U8) :
    unique_before headers stop candidate ⦃ out => out = true →
      stop.val ≤ headers.length ∧ UniqueFrom headers candidate 0 stop.val ⦄ := by
  unfold unique_before
  dsimp only
  split
  · simp
  · apply WP.spec_mono (unique_before_loop_sound headers stop candidate 0#usize (by scalar_tac))
    intro out tail accepted
    exact ⟨by scalar_tac, by simpa using tail accepted⟩

def HeadersFrom (headers : Slice Header) (start : Nat) : Prop :=
  ∀ (i : Nat) (inside : i < headers.length), start ≤ i →
    ValidHeader (headers.val[i]'inside) ∧
      UniqueFrom headers (alloc.vec.Vec.deref (headers.val[i]'inside).name) 0 i

@[step]
theorem valid_headers_loop_sound (headers : Slice Header) (index : Usize) :
    valid_headers_loop headers index ⦃ out => out = true → HeadersFrom headers index.val ⦄ := by
  suffices ∀ n (i : Usize), headers.length - i.val = n →
      valid_headers_loop headers i ⦃ out => out = true → HeadersFrom headers i.val ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro i measure
    rw [valid_headers_loop.eq_def]
    by_cases inside : i.val < headers.length
    · have scalar_inside : i < Slice.len headers := by scalar_tac
      simp only [scalar_inside, ↓reduceIte, slice_index_exact headers i inside, bind_ok]
      let entry := headers.val[i.val]'inside
      obtain ⟨valid, checked, header_property⟩ := returned_of_spec (valid_header_sound entry)
      rw [checked]
      simp only [bind_ok]
      cases found : valid with
      | false => simp
      | true =>
        simp only [↓reduceIte]
        obtain ⟨unique, scanned, unique_property⟩ := returned_of_spec
          (unique_before_sound headers i (alloc.vec.Vec.deref entry.name))
        rw [scanned]
        simp only [bind_ok]
        cases unique_found : unique with
        | false => simp
        | true =>
          simp only [↓reduceIte]
          apply WP.spec_bind (@Usize.add_spec i 1#usize (by scalar_tac))
          intro next advanced
          apply WP.spec_mono (ih (headers.length - next.val) (by scalar_tac) next rfl)
          intro out tail accepted j ji after
          by_cases same : j = i.val
          · subst j
            exact ⟨header_property found, (unique_property unique_found).2⟩
          · exact tail accepted j ji (by scalar_tac)
    · have outside : ¬i < Slice.len headers := by scalar_tac
      simp only [outside, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      intro accepted i ii after
      scalar_tac

def ValidHeaders (headers : Slice Header) : Prop := headers.length ≤ 9 ∧ HeadersFrom headers 0

@[step]
theorem valid_headers_sound (headers : Slice Header) :
    valid_headers headers ⦃ out => out = true → ValidHeaders headers ⦄ := by
  unfold valid_headers
  dsimp only
  split
  · simp
  · apply WP.spec_mono (valid_headers_loop_sound headers 0#usize)
    intro out tail accepted
    exact ⟨by scalar_tac, by simpa using tail accepted⟩

def ValidStart (head : Head) : Prop :=
  ValidHost (alloc.vec.Vec.deref head.host) ∧ head.port ≠ 0#u16 ∧
    ValidAccept (alloc.vec.Vec.deref head.accept) ∧
    ValidMethod (alloc.vec.Vec.deref head.method) ∧ ValidTarget (alloc.vec.Vec.deref head.target)

@[step]
theorem valid_start_sound (head : Head) :
    valid_start head ⦃ out => out = true → ValidStart head ⦄ := by
  unfold valid_start
  dsimp only
  obtain ⟨host, host_checked, host_property⟩ := returned_of_spec
    (valid_host_sound (alloc.vec.Vec.deref head.host))
  rw [host_checked]
  simp only [bind_ok]
  cases host_found : host with
  | false => simp
  | true =>
    simp only [↓reduceIte]
    by_cases port : head.port = 0#u16
    · simp [port]
    · have nonzero : (head.port != 0#u16) = true := by simpa only [bne_iff_ne] using port
      simp only [nonzero, ↓reduceIte]
      obtain ⟨accept, accept_checked, accept_property⟩ := returned_of_spec
        (valid_accept_contract (alloc.vec.Vec.deref head.accept))
      rw [accept_checked]
      simp only [bind_ok]
      cases accept_found : accept with
      | false => simp
      | true =>
        simp only [↓reduceIte]
        obtain ⟨method, method_checked, method_property⟩ := returned_of_spec
          (valid_method_contract (alloc.vec.Vec.deref head.method))
        rw [method_checked]
        simp only [bind_ok]
        cases method_found : method with
        | false => simp
        | true =>
          simp only [↓reduceIte]
          apply WP.spec_mono (valid_target_contract (alloc.vec.Vec.deref head.target))
          intro out target_property accepted
          exact ⟨host_property host_found, port, accept_property.mp accept_found,
            method_property.mp method_found, target_property.mp accepted⟩

end aivm_secrets_garrett_core.http_wire.Proofs
