import GarrettHttpWireHeaders

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.http_auth.Proofs
open aivm_secrets_garrett_core.http_request.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.http_wire.Proofs

@[simp, scalar_tac_simps]
theorem vec_deref_length {T : Type} (value : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref value).length = value.length := by simp [alloc.vec.Vec.deref]

@[simp, scalar_tac_simps]
theorem vec_deref_val {T : Type} (value : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref value).val = value.val := by simp [alloc.vec.Vec.deref]

def HeaderBytes (header : Header) : List U8 :=
  header.name.val ++ [58#u8, 32#u8] ++ header.value.val ++ [13#u8, 10#u8]

def HeadersBytes (headers : List Header) : List U8 := headers.flatMap HeaderBytes

@[step]
theorem append_headers_loop_contract (iter : core.slice.iter.Iter Header)
    (output : alloc.vec.Vec U8)
    (room : output.length + (HeadersBytes (iter.slice.val.drop iter.i)).length ≤ Usize.max) :
    append_headers_loop iter output ⦃ out =>
      out.val = output.val ++ HeadersBytes (iter.slice.val.drop iter.i) ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter Header), it.slice.length - it.i = n →
      ∀ (output : alloc.vec.Vec U8),
        output.length + (HeadersBytes (it.slice.val.drop it.i)).length ≤ Usize.max →
        append_headers_loop it output ⦃ out =>
          out.val = output.val ++ HeadersBytes (it.slice.val.drop it.i) ⦄ from
    this _ iter rfl output room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure output space
    rw [append_headers_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have next : core.slice.iter.IteratorSliceIter.next it =
          Result.ok (some it.slice[it.i], {it with i := it.i + 1}) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
        rfl
      rw [next]
      simp only [bind_ok]
      have bytes : HeadersBytes (it.slice.val.drop it.i) = HeaderBytes it.slice[it.i] ++
          HeadersBytes (it.slice.val.drop (it.i + 1)) := by
        rw [List.drop_eq_getElem_cons inside]
        rfl
      rw [bytes] at space
      simp only [HeaderBytes, List.length_append, List.length_cons, List.length_nil] at space
      have first_room : output.length + (alloc.vec.Vec.deref it.slice[it.i].name).length ≤ Usize.max := by
        simp only [vec_deref_length]
        scalar_tac
      step
      step
      step
      step
      step
      step
      have tail_room : output4.length + (HeadersBytes (it.slice.val.drop (it.i + 1))).length ≤ Usize.max := by
        simp only [s1_post, s3_post, Array.length_to_slice] at *
        scalar_tac
      apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by omega)
        {it with i := it.i + 1} rfl output4 tail_room)
      intro out exact_bytes
      simp_all [HeaderBytes, List.append_assoc]
    · have next : core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
      rw [next]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      simp [HeadersBytes, List.drop_eq_nil_of_le (Nat.le_of_not_gt inside)]

@[step]
theorem append_headers_exact (output : alloc.vec.Vec U8) (headers : Slice Header)
    (room : output.length + (HeadersBytes headers.val).length ≤ Usize.max) :
    append_headers output headers ⦃ out => out.val = output.val ++ HeadersBytes headers.val ⦄ := by
  unfold append_headers
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  apply WP.spec_mono (append_headers_loop_contract ⟨headers, 0⟩ output (by simpa using room))
  intro out exact_bytes
  simpa using exact_bytes

end aivm_secrets_garrett_core.http_wire.Proofs
