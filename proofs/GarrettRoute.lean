import GarrettHttpWireHeaders
import GarrettProxyHttp

/-!
# The provider request target of a named operation

Source: `rust/crates/aivm-secrets-garrett-core/src/route.rs`, extracted by
Aeneas. The native manifest (`manifest.rs`, `Operation::effect`) parses the
policy's path and query templates and converts each argument to its scalar
text; `route::fill_target` then writes every byte of the target.

Proved here, for any templates and arguments:

* `fill_target_exact`: a returned target is exactly
  `PathBytes path ++ QueryBytes query`: `/value` per path part, then
  `?name=value` and `&name=value` per query entry, where each value is the
  literal or the **first** binding with the parameter's name;
* `fill_target_safe`: every byte of a returned target is unreserved
  (`A-Z a-z 0-9 - . _ ~`) or one of `/ ? = &`; path values contain only
  unreserved bytes and `/`, query names and values only unreserved bytes,
  so the only `?` is the query separator and no `#`, `%`, space, CR or LF
  can appear; the path is 2..1024 bytes and the target at most 8192.

What remains native: parsing the policy into templates and converting JSON
arguments to their text (integers in decimal), checked by the manifest
parity tests against the Python reference.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.http_wire.Proofs (AlphaNumeric alphanumeric_contract)
open aivm_secrets_garrett_core.proxy_http.Proofs (slice_eq_eq)
set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace aivm_secrets_garrett_core.route.Proofs

/-! ## Byte classes -/

def Unreserved (byte : U8) : Prop :=
  AlphaNumeric byte ∨ byte = 45#u8 ∨ byte = 46#u8 ∨ byte = 95#u8 ∨ byte = 126#u8

/-- One segment: non-empty, at most 128 bytes, not `.` or `..`, unreserved. -/
def Seg (value : List U8) : Prop :=
  value ≠ [] ∧ value.length ≤ 128 ∧ value ≠ [46#u8] ∧ value ≠ [46#u8, 46#u8] ∧
    ∀ byte ∈ value, Unreserved byte

/-- Path value bytes: unreserved or `/`. -/
def PathByte (byte : U8) : Prop := Unreserved byte ∨ byte = 47#u8

/-- Target bytes: unreserved or one of `/ ? = &`. -/
def TargetByte (byte : U8) : Prop :=
  Unreserved byte ∨ byte = 47#u8 ∨ byte = 63#u8 ∨ byte = 61#u8 ∨ byte = 38#u8

/-! ## Values and the specified target -/

/-- The value of the first binding named `name`. -/
def FirstValue : List Binding → List U8 → Option (List U8)
  | [], _ => none
  | binding :: rest, wanted =>
    if binding.name.val = wanted then some binding.value.val else FirstValue rest wanted

def PieceValue (bindings : List Binding) : Piece → Option (List U8)
  | .Literal text => some text.val
  | .Parameter label => FirstValue bindings label.val

def PathBytes (bindings : List Binding) : List Piece → List U8
  | [] => []
  | piece :: rest => 47#u8 :: (PieceValue bindings piece).getD [] ++ PathBytes bindings rest

def QueryBytes (bindings : List Binding) (first : Bool) : List QueryPiece → List U8
  | [] => []
  | entry :: rest =>
    (if first then 63#u8 else 38#u8) :: entry.name.val ++ 61#u8 ::
      (PieceValue bindings entry.piece).getD [] ++ QueryBytes bindings false rest

/-! ## Small functions -/

@[step]
theorem unreserved_contract (byte : U8) : unreserved byte ⦃ r => r ↔ Unreserved byte ⦄ := by
  unfold unreserved
  step as ⟨alpha, halpha⟩
  unfold Unreserved
  split
  · simp_all
  · repeat' split
    all_goals simp_all

theorem segment_ok_loop_contract (value : Slice U8) (index : Usize) :
    segment_ok_loop value index ⦃ r => r = true →
      ∀ k (hk : k < value.length), index.val ≤ k → Unreserved value.val[k] ⦄ := by
  suffices ∀ n (index : Usize), value.length - index.val = n →
      segment_ok_loop value index ⦃ r => r = true →
        ∀ k (hk : k < value.length), index.val ≤ k → Unreserved value.val[k] ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure
    rw [segment_ok_loop.eq_def]
    dsimp only
    split
    · step as ⟨byte, hbyte⟩
      step as ⟨good, hgood⟩
      split
      · step as ⟨next, hnext⟩
        refine WP.spec_mono (ih (value.length - next.val) (by scalar_tac) next rfl) ?_
        intro r hr ok k hk lo
        by_cases same : k = index.val
        · subst same
          rw [← hbyte]
          exact hgood.mp (by simp_all)
        · exact hr ok k hk (by scalar_tac)
      · simp
    · simp only [WP.spec_ok]
      intro _ k hk lo
      scalar_tac

@[step]
theorem segment_ok_contract (value : Slice U8) :
    segment_ok value ⦃ r => r = true → Seg value.val ⦄ := by
  unfold segment_ok
  simp only [core.slice.Slice.is_empty, bind_ok]
  split
  · simp
  · rename_i nonempty
    split
    · simp
    · rename_i bounded
      simp only [lift, Array.to_slice, Array.make, bind_ok, slice_eq_eq]
      split
      · simp
      · rename_i not_dot
        split
        · simp
        · rename_i not_dots
          refine WP.spec_mono (segment_ok_loop_contract value 0#usize) ?_
          intro r post yes
          refine ⟨?_, ?_, ?_, ?_, ?_⟩
          · intro empty
            apply nonempty
            simp [Slice.length, empty]
          · have : ¬ (value.len > MAX_SEGMENT) := bounded
            simp only [MAX_SEGMENT, gt_iff_lt, not_lt] at this
            scalar_tac
          · simpa using not_dot
          · simpa using not_dots
          · intro byte mem
            obtain ⟨k, hk, at_k⟩ := List.getElem_of_mem mem
            rw [← at_k]
            exact post yes k hk (by simp)

theorem mem_slice {l : List U8} {start stop k : Nat} (lo : start ≤ k) (hi : k < stop)
    (inside : stop ≤ l.length) : ∃ h : k < l.length, l[k] ∈ l.slice start stop := by
  refine ⟨by omega, ?_⟩
  have length : k - start < (l.slice start stop).length := by
    rw [List.slice_length]; omega
  have := List.getElem_mem length
  simp only [List.slice, List.getElem_take, List.getElem_drop] at this
  have same : start + (k - start) = k := by omega
  simp only [same] at this
  simpa [List.slice] using this

theorem segments_ok_loop_contract (value : Slice U8) (start index : Usize)
    (order : start.val ≤ index.val) (inside : index.val ≤ value.length) :
    segments_ok_loop value start index ⦃ r => r = true →
      ∀ k (hk : k < value.length), start.val ≤ k → PathByte value.val[k] ⦄ := by
  suffices ∀ n (start index : Usize), value.length - index.val = n → start.val ≤ index.val →
      index.val ≤ value.length →
      segments_ok_loop value start index ⦃ r => r = true →
        ∀ k (hk : k < value.length), start.val ≤ k → PathByte value.val[k] ⦄ from
    this _ start index rfl order inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro start index measure order inside
    rw [segments_ok_loop.eq_def]
    dsimp only
    split
    · step as ⟨byte, hbyte⟩
      split
      · rename_i slash
        step as ⟨piece, hpiece, _⟩
        step as ⟨good, hgood⟩
        split
        · step as ⟨next, hnext⟩
          refine WP.spec_mono (ih (value.length - next.val) (by scalar_tac) next next rfl
            (le_refl _) (by scalar_tac)) ?_
          intro r hr ok k hk lo
          by_cases before : k < index.val
          · obtain ⟨_, mem⟩ := mem_slice (l := value.val) lo before (by scalar_tac)
            rw [← hpiece] at mem
            exact Or.inl ((hgood (by simp_all)).2.2.2.2 _ mem)
          · by_cases here : k = index.val
            · subst here
              right
              rw [← hbyte]
              simpa using slash
            · exact hr ok k hk (by scalar_tac)
        · simp
      · step as ⟨next, hnext⟩
        exact ih (value.length - next.val) (by scalar_tac) start next rfl (by scalar_tac)
          (by scalar_tac)
    · step as ⟨rest, hrest, _⟩
      refine WP.spec_mono (segment_ok_contract rest) ?_
      intro good hgood ok k hk lo
      have hi : k < value.length := hk
      obtain ⟨_, mem⟩ := mem_slice (l := value.val) (stop := value.val.length) lo hi le_rfl
      have : value.val.slice start.val value.val.length = rest.val := by
        rw [hrest]; simp [List.slice]
      rw [this] at mem
      exact Or.inl ((hgood ok).2.2.2.2 _ mem)

@[step]
theorem segments_ok_contract (value : Slice U8) :
    segments_ok value ⦃ r => r = true → ∀ byte ∈ value.val, PathByte byte ⦄ := by
  unfold segments_ok
  refine WP.spec_mono (segments_ok_loop_contract value 0#usize 0#usize (le_refl _) (by simp)) ?_
  intro r post ok byte mem
  obtain ⟨k, hk, at_k⟩ := List.getElem_of_mem mem
  rw [← at_k]
  exact post ok k hk (by simp)

/-! ## Inversion helpers -/

theorem bind_ok_inv {A B : Type} {first : Result A} {next : A → Result B} {out : B}
    (h : (first >>= next) = Result.ok out) : ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp_all

theorem push_ok_val {α : Type} {v w : alloc.vec.Vec α} {x : α}
    (h : alloc.vec.Vec.push v x = Result.ok w) : w.val = v.val ++ [x] := by
  unfold alloc.vec.Vec.push at h
  dsimp only at h
  split at h
  · simp only [Result.ok.injEq] at h
    subst h
    simp
  · simp at h

theorem extend_ok_val {v w : alloc.vec.Vec U8} {bytes : Slice U8}
    (h : alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v bytes = Result.ok w) :
    w.val = v.val ++ bytes.val := by
  unfold alloc.vec.Vec.extend_from_slice at h
  split at h
  · obtain ⟨cloned, copied, h⟩ := bind_ok_inv h
    obtain ⟨c, hc, same⟩ := returned_of_spec (List.clone_spec (clone := core.clone.CloneU8.clone)
      (l := bytes.val) (by intro x _; rfl))
    rw [hc] at copied
    simp only [Result.ok.injEq] at copied h
    subst copied h
    simp [same]
  · simp at h

theorem index_usize_eq {α : Type} (s : Slice α) (i : Usize) (inside : i.val < s.length) :
    Slice.index_usize s i = Result.ok s.val[i.val] := by
  obtain ⟨y, hy, same⟩ := returned_of_spec (Slice.index_usize_spec s i inside)
  rw [hy, same]

theorem add_one_eq (a : Usize) (room : a.val + 1 ≤ Usize.max) :
    ∃ b : Usize, a + 1#usize = Result.ok b ∧ b.val = a.val + 1 := by
  obtain ⟨c, hc, value⟩ := returned_of_spec (Usize.add_spec (x := a) (y := 1#usize) (by simpa using room))
  exact ⟨c, hc, by simpa using value⟩

/-! ## Lookup -/

theorem lookup_loop_contract (bindings : Slice Binding) (wanted : Slice U8) (index : Usize) :
    lookup_loop bindings wanted index ⦃ r =>
      match r with
      | none => FirstValue (bindings.val.drop index.val) wanted.val = none
      | some i => ∃ h : i.val < bindings.length,
          FirstValue (bindings.val.drop index.val) wanted.val = some (bindings.val[i.val]).value.val ⦄ := by
  suffices ∀ n (index : Usize), bindings.length - index.val = n →
      lookup_loop bindings wanted index ⦃ r =>
        match r with
        | none => FirstValue (bindings.val.drop index.val) wanted.val = none
        | some i => ∃ h : i.val < bindings.length,
            FirstValue (bindings.val.drop index.val) wanted.val = some (bindings.val[i.val]).value.val ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure
    rw [lookup_loop.eq_def]
    dsimp only
    split
    · rename_i inside
      have cons : bindings.val.drop index.val =
          bindings.val[index.val] :: bindings.val.drop (index.val + 1) :=
        List.drop_eq_getElem_cons (by scalar_tac)
      step as ⟨b, hb⟩
      simp only [slice_eq_eq, bind_ok]
      split
      · rename_i same
        simp only [WP.spec_ok]
        refine ⟨by scalar_tac, ?_⟩
        rw [cons]
        subst hb
        simp only [decide_eq_true_eq, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] at same
        simp only [FirstValue]
        split
        · rfl
        · rename_i other
          exact absurd same other
      · rename_i differ
        step as ⟨next, hnext⟩
        refine WP.spec_mono (ih (bindings.length - next.val) (by scalar_tac) next rfl) ?_
        intro r hr
        have skip : FirstValue (bindings.val.drop index.val) wanted.val =
            FirstValue (bindings.val.drop next.val) wanted.val := by
          rw [cons]
          subst hb
          simp only [decide_eq_true_eq, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] at differ
          rw [hnext]
          simp only [FirstValue]
          split
          · rename_i other
            exact absurd other differ
          · rfl
        cases r with
        | none => simpa [skip] using hr
        | some i => simpa [skip] using hr
    · simp only [WP.spec_ok]
      have : bindings.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
      simp [this, FirstValue]

/-! ## Filling one part -/

theorem fill_piece_ok {out out' : alloc.vec.Vec U8} {piece : Piece} {bindings : Slice Binding}
    (h : fill_piece out piece bindings = Result.ok (.Ok (), out')) :
    ∃ value, PieceValue bindings.val piece = some value ∧ (∀ byte ∈ value, PathByte byte) ∧
      out'.val = out.val ++ value := by
  unfold fill_piece at h
  cases piece with
  | Literal text =>
    simp only at h
    obtain ⟨good, returned, post⟩ := returned_of_spec (segments_ok_contract (alloc.vec.Vec.deref text))
    rw [returned] at h
    simp only [bind_ok] at h
    split at h
    · rename_i yes
      obtain ⟨w, extended, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨_, same⟩ := h
      subst same
      refine ⟨text.val, rfl, ?_, ?_⟩
      · simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using post yes
      · simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using extend_ok_val extended
    · simp at h
  | Parameter label =>
    simp only at h
    obtain ⟨o, returned, post⟩ := returned_of_spec
      (lookup_loop_contract bindings (alloc.vec.Vec.deref label) 0#usize)
    unfold lookup at h
    rw [returned] at h
    simp only [bind_ok] at h
    cases o with
    | none => simp at h
    | some i =>
      simp only at h
      obtain ⟨inside, first⟩ := post
      rw [index_usize_eq bindings i inside] at h
      simp only [bind_ok] at h
      set b := bindings.val[i.val] with hb
      obtain ⟨good, returned2, post2⟩ := returned_of_spec
        (segments_ok_contract (alloc.vec.Vec.deref b.value))
      rw [returned2] at h
      simp only [bind_ok] at h
      split at h
      · rename_i yes
        obtain ⟨w, extended, h⟩ := bind_ok_inv h
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨_, same⟩ := h
        subst same
        refine ⟨b.value.val, ?_, ?_, ?_⟩
        · simp only [PieceValue]
          simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val, hb] using first
        · simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using post2 yes
        · simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using extend_ok_val extended
      · simp at h

/-- Every part has a value whose bytes are path bytes. -/
def Bound (bindings : List Binding) (pieces : List Piece) : Prop :=
  ∀ piece ∈ pieces, ∃ value, PieceValue bindings piece = some value ∧ ∀ byte ∈ value, PathByte byte

theorem fill_path_loop_stopped {out o : alloc.vec.Vec U8} {path : Slice Piece}
    {bindings : Slice Binding} {index : Usize} {done : Bool}
    (h : fill_path_loop out path bindings false index = Result.ok (o, done)) : done = false := by
  rw [fill_path_loop.eq_def] at h
  simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, Prod.mk.injEq] at h
  exact h.2.symm

theorem fill_path_loop_ok (path : Slice Piece) (bindings : Slice Binding) :
    ∀ n (out o : alloc.vec.Vec U8) (going : Bool) (index : Usize), path.length - index.val = n →
      fill_path_loop out path bindings going index = Result.ok (o, true) →
      Bound bindings.val (path.val.drop index.val) ∧
        o.val = out.val ++ PathBytes bindings.val (path.val.drop index.val) := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out o going index measure h
    rw [fill_path_loop.eq_def] at h
    dsimp only at h
    split at h
    · split at h
      · rename_i inside
        obtain ⟨out1, pushed, h⟩ := bind_ok_inv h
        obtain ⟨p, indexed, h⟩ := bind_ok_inv h
        rw [index_usize_eq path index (by scalar_tac)] at indexed
        simp only [Result.ok.injEq] at indexed
        have cons : path.val.drop index.val = p :: path.val.drop (index.val + 1) := by
          rw [← indexed]; exact List.drop_eq_getElem_cons (by scalar_tac)
        obtain ⟨⟨r, out2⟩, filled, h⟩ := bind_ok_inv h
        cases r with
        | Err e =>
          exact absurd (fill_path_loop_stopped h) (by simp)
        | Ok u =>
          cases u
          obtain ⟨next, added, value⟩ := add_one_eq index (by scalar_tac)
          simp only [added, bind_ok] at h
          obtain ⟨bound, bytes⟩ := ih (path.length - next.val) (by scalar_tac) out2 o going next rfl h
          obtain ⟨v, hv, safe, hout2⟩ := fill_piece_ok filled
          rw [value] at bound bytes
          refine ⟨?_, ?_⟩
          · rw [cons]
            intro piece mem
            rcases List.mem_cons.mp mem with here | rest
            · subst here; exact ⟨v, hv, safe⟩
            · exact bound piece rest
          · rw [bytes, hout2, push_ok_val pushed, cons]
            simp [PathBytes, hv]
      · simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨same, _⟩ := h
        subst same
        have : path.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
        simp [this, PathBytes, Bound]
    · simp_all

theorem fill_path_ok {out o : alloc.vec.Vec U8} {path : Slice Piece} {bindings : Slice Binding}
    (h : fill_path out path bindings = Result.ok (.Ok (), o)) :
    Bound bindings.val path.val ∧ o.val = out.val ++ PathBytes bindings.val path.val ∧
      2 ≤ o.length ∧ o.length ≤ 1024 := by
  unfold fill_path at h
  obtain ⟨⟨o1, going⟩, looped, h⟩ := bind_ok_inv h
  cases going with
  | false => simp at h
  | true =>
    change (if (true : Bool) = true then
        (if o1.len < 2#usize then Result.ok (core.result.Result.Err RouteDenial.Denied, o1)
         else if o1.len > MAX_PATH then Result.ok (core.result.Result.Err RouteDenial.Denied, o1)
         else Result.ok (core.result.Result.Ok (), o1))
      else Result.ok (core.result.Result.Err RouteDenial.Denied, o1)) = _ at h
    simp only [↓reduceIte] at h
    obtain ⟨bound, bytes⟩ := fill_path_loop_ok path bindings _ out o1 true 0#usize rfl looped
    split at h
    · simp at h
    · rename_i long_enough
      split at h
      · simp at h
      · rename_i short_enough
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨_, same⟩ := h
        subst same
        have z : (0#usize : Usize).val = 0 := by simp
        simp only [z, List.drop_zero] at bound bytes
        refine ⟨bound, bytes, ?_, ?_⟩
        · simp only [alloc.vec.Vec.len, not_lt] at long_enough; scalar_tac
        · simp only [alloc.vec.Vec.len, MAX_PATH, gt_iff_lt, not_lt] at short_enough; scalar_tac

/-! ## Query entries -/

/-- Every entry has a segment name and a segment value. -/
def QueryBound (bindings : List Binding) (entries : List QueryPiece) : Prop :=
  ∀ entry ∈ entries, Seg entry.name.val ∧
    ∃ value, PieceValue bindings entry.piece = some value ∧ Seg value

theorem fill_query_entry_ok {out o : alloc.vec.Vec U8} {entry : QueryPiece} {first : Bool}
    {bindings : Slice Binding}
    (h : fill_query_entry out entry first bindings = Result.ok (.Ok (), o)) :
    Seg entry.name.val ∧ ∃ value, PieceValue bindings.val entry.piece = some value ∧ Seg value ∧
      o.val = out.val ++ ((if first then 63#u8 else 38#u8) :: entry.name.val ++ 61#u8 :: value) := by
  unfold fill_query_entry at h
  dsimp only at h
  obtain ⟨good, returned, post⟩ := returned_of_spec (segment_ok_contract (alloc.vec.Vec.deref entry.name))
  rw [returned] at h
  simp only [bind_ok] at h
  split at h
  · rename_i named
    have name_seg : Seg entry.name.val := by
      simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using post named
    obtain ⟨out1, pushed, h⟩ := bind_ok_inv h
    have hout1 : out1.val = out.val ++ [if first then 63#u8 else 38#u8] := by
      cases first <;> simp only [Bool.false_eq_true, ↓reduceIte] at pushed <;>
        simp [push_ok_val pushed]
    obtain ⟨out2, extended, h⟩ := bind_ok_inv h
    obtain ⟨out3, pushed3, h⟩ := bind_ok_inv h
    obtain ⟨⟨r, out4⟩, filled, h⟩ := bind_ok_inv h
    cases r with
    | Err e => simp at h
    | Ok u =>
      cases u
      obtain ⟨v, hv, _, hout4⟩ := fill_piece_ok filled
      have h3 : out3.val = out2.val ++ [61#u8] := push_ok_val pushed3
      have h2 : out2.val = out1.val ++ entry.name.val := by
        simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using extend_ok_val extended
      change (do
          let s2 ← alloc.vec.Vec.index (core.slice.index.SliceIndexRangeFromUsizeSlice U8) out4
            { start := out3.len }
          let b1 ← segment_ok s2
          if b1 = true then Result.ok (core.result.Result.Ok (), out4)
          else Result.ok (core.result.Result.Err RouteDenial.Denied, out4)) = _ at h
      obtain ⟨tail, indexed, tail_val, _⟩ := returned_of_spec
        (alloc.vec.Vec.index_RangeFrom_spec out4 { start := alloc.vec.Vec.len out3 }
          (by simp only [alloc.vec.Vec.len, alloc.vec.Vec.length] ; rw [hout4]; simp))
      obtain ⟨s2, hs2, h⟩ := bind_ok_inv h
      rw [indexed] at hs2
      simp only [Result.ok.injEq] at hs2
      subst hs2
      have tail_is_v : tail.val = v := by
        rw [tail_val, hout4]
        simp [alloc.vec.Vec.len]
      obtain ⟨good2, returned2, post2⟩ := returned_of_spec (segment_ok_contract tail)
      obtain ⟨b1, hb1, h⟩ := bind_ok_inv h
      rw [returned2] at hb1
      simp only [Result.ok.injEq] at hb1
      subst hb1
      split at h
      · rename_i yes
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨_, same⟩ := h
        subst same
        refine ⟨name_seg, v, hv, tail_is_v ▸ post2 yes, ?_⟩
        rw [hout4, h3, h2, hout1]
        simp
      · simp at h
  · simp at h

theorem fill_target_loop_stopped {out o : alloc.vec.Vec U8} {query : Slice QueryPiece}
    {bindings : Slice Binding} {index : Usize} {done : Bool}
    (h : fill_target_loop query bindings out false index = Result.ok (o, done)) : done = false := by
  rw [fill_target_loop.eq_def] at h
  simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, Prod.mk.injEq] at h
  exact h.2.symm

theorem fill_target_loop_ok (query : Slice QueryPiece) (bindings : Slice Binding) :
    ∀ n (out o : alloc.vec.Vec U8) (going : Bool) (index : Usize), query.length - index.val = n →
      fill_target_loop query bindings out going index = Result.ok (o, true) →
      QueryBound bindings.val (query.val.drop index.val) ∧
        o.val = out.val ++ QueryBytes bindings.val (decide (index.val = 0)) (query.val.drop index.val) := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro out o going index measure h
    rw [fill_target_loop.eq_def] at h
    dsimp only at h
    split at h
    · split at h
      · rename_i inside
        obtain ⟨qp, indexed, h⟩ := bind_ok_inv h
        rw [index_usize_eq query index (by scalar_tac)] at indexed
        simp only [Result.ok.injEq] at indexed
        have cons : query.val.drop index.val = qp :: query.val.drop (index.val + 1) := by
          rw [← indexed]; exact List.drop_eq_getElem_cons (by scalar_tac)
        obtain ⟨⟨r, out1⟩, filled, h⟩ := bind_ok_inv h
        cases r with
        | Err e => exact absurd (fill_target_loop_stopped h) (by simp)
        | Ok u =>
          cases u
          obtain ⟨next, added, value⟩ := add_one_eq index (by scalar_tac)
          simp only [added, bind_ok] at h
          obtain ⟨bound, bytes⟩ := ih (query.length - next.val) (by scalar_tac) out1 o going next rfl h
          obtain ⟨name_seg, v, hv, vseg, hout1⟩ := fill_query_entry_ok filled
          rw [value] at bound bytes
          refine ⟨?_, ?_⟩
          · rw [cons]
            intro entry mem
            rcases List.mem_cons.mp mem with here | rest
            · subst here; exact ⟨name_seg, v, hv, vseg⟩
            · exact bound entry rest
          · rw [bytes, hout1, cons]
            have first_eq : (index = 0#usize) = (index.val = 0) := by
              simp [UScalar.eq_equiv]
            simp [QueryBytes, first_eq, hv]
      · simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨same, _⟩ := h
        subst same
        have : query.val.drop index.val = [] := List.drop_eq_nil_of_le (by scalar_tac)
        simp [this, QueryBytes, QueryBound]
    · simp_all

/-! ## The target -/

theorem len_le_target {o : alloc.vec.Vec U8} (short : ¬ o.len > MAX_TARGET) : o.length ≤ 8192 := by
  have : MAX_TARGET.val = 8192 := by unfold MAX_TARGET; rfl
  have lt := short
  rw [gt_iff_lt, UScalar.lt_equiv, not_lt, this] at lt
  simpa [alloc.vec.Vec.len, alloc.vec.Vec.length] using lt

/-- **The exact target.** A returned target is `PathBytes ++ QueryBytes`:
    `/value` per path part, then `?name=value` and `&name=value` per query
    entry, each value the literal or the first binding with that name. Every
    path part and query entry had a value. -/
theorem fill_target_exact {path : Slice Piece} {query : Slice QueryPiece} {bindings : Slice Binding}
    {target : alloc.vec.Vec U8}
    (h : fill_target path query bindings = Result.ok (.Ok target)) :
    target.val = PathBytes bindings.val path.val ++ QueryBytes bindings.val true query.val ∧
      Bound bindings.val path.val ∧ QueryBound bindings.val query.val ∧
      2 ≤ (PathBytes bindings.val path.val).length ∧ (PathBytes bindings.val path.val).length ≤ 1024 ∧
      target.length ≤ 8192 := by
  unfold fill_target at h
  obtain ⟨⟨r, out⟩, filled, h⟩ := bind_ok_inv h
  cases r with
  | Err e => simp at h
  | Ok u =>
    cases u
    obtain ⟨bound, path_bytes, lo, hi⟩ := fill_path_ok filled
    simp only at h
    obtain ⟨⟨o, going⟩, looped, h⟩ := bind_ok_inv h
    cases going with
    | false => simp at h
    | true =>
      obtain ⟨qbound, qbytes⟩ := fill_target_loop_ok query bindings _ out o true 0#usize rfl looped
      change (if (true : Bool) = true then
          (if o.len > MAX_TARGET then Result.ok (core.result.Result.Err RouteDenial.Denied)
           else Result.ok (core.result.Result.Ok o))
        else Result.ok (core.result.Result.Err RouteDenial.Denied)) = _ at h
      simp only [↓reduceIte] at h
      split at h
      · simp at h
      · rename_i short
        simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
        subst h
        have z : (0#usize : Usize).val = 0 := by simp
        simp only [z, List.drop_zero, decide_true] at qbound qbytes
        have out_val : out.val = PathBytes bindings.val path.val := by
          simpa [alloc.vec.Vec.new] using path_bytes
        refine ⟨by rw [qbytes, out_val], bound, qbound, ?_, ?_, ?_⟩
        · rw [← out_val]; exact lo
        · rw [← out_val]; exact hi
        · exact len_le_target short

theorem path_bytes_safe (bindings : List Binding) :
    ∀ pieces, Bound bindings pieces → ∀ byte ∈ PathBytes bindings pieces, PathByte byte := by
  intro pieces
  induction pieces with
  | nil => simp [PathBytes]
  | cons piece rest ih =>
    intro bound byte mem
    obtain ⟨v, hv, safe⟩ := bound piece (by simp)
    simp only [PathBytes, hv, Option.getD_some] at mem
    rcases List.mem_append.mp mem with head | later
    · rcases List.mem_cons.mp head with slash | inside
      · right; exact slash
      · exact safe byte inside
    · exact ih (fun p m => bound p (List.mem_cons_of_mem _ m)) byte later

theorem query_bytes_safe (bindings : List Binding) :
    ∀ entries first, QueryBound bindings entries →
      ∀ byte ∈ QueryBytes bindings first entries, TargetByte byte := by
  intro entries
  induction entries with
  | nil => simp [QueryBytes]
  | cons entry rest ih =>
    intro first bound byte mem
    obtain ⟨name_seg, v, hv, vseg⟩ := bound entry (by simp)
    simp only [QueryBytes, hv, Option.getD_some] at mem
    rcases List.mem_append.mp mem with head | later
    · rcases List.mem_append.mp head with front | back
      · rcases List.mem_cons.mp front with sep | in_name
        · unfold TargetByte; split at sep <;> simp_all
        · exact Or.inl (name_seg.2.2.2.2 byte in_name)
      · rcases List.mem_cons.mp back with eq | in_value
        · unfold TargetByte; simp_all
        · exact Or.inl (vseg.2.2.2.2 byte in_value)
    · exact ih false (fun e m => bound e (List.mem_cons_of_mem _ m)) byte later

/-- **Only safe bytes.** Every byte of a returned target is unreserved or one
    of `/ ? = &`; the path part contains only unreserved bytes and `/`, so
    the first `?` (if any) is the query separator. -/
theorem fill_target_safe {path : Slice Piece} {query : Slice QueryPiece} {bindings : Slice Binding}
    {target : alloc.vec.Vec U8}
    (h : fill_target path query bindings = Result.ok (.Ok target)) :
    (∀ byte ∈ target.val, TargetByte byte) ∧
      ∀ byte ∈ PathBytes bindings.val path.val, PathByte byte := by
  obtain ⟨bytes, bound, qbound, _⟩ := fill_target_exact h
  have path_safe := path_bytes_safe bindings.val path.val bound
  refine ⟨?_, path_safe⟩
  rw [bytes]
  intro byte mem
  rcases List.mem_append.mp mem with in_path | in_query
  · rcases path_safe byte in_path with u | slash
    · exact Or.inl u
    · exact Or.inr (Or.inl slash)
  · exact query_bytes_safe bindings.val query.val true qbound byte in_query

end aivm_secrets_garrett_core.route.Proofs
