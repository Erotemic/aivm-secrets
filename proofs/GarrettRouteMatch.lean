import GarrettRoute

/-!
# Guest-side translation of a request target (HP-6)

Source: `rust/crates/aivm-secrets-garrett-core/src/route_match.rs`, extracted
by Aeneas. A guest-side constrained translator reads candidate arguments off
an HTTP request target and accepts them only if the host's own
`route::fill_target` writes the target back byte for byte.

Proved here:

* `translate_round_trip`: whenever `translate` returns arguments, the host
  encoder `fill_target` applied to the same templates and those arguments
  returns exactly the guest's target;
* `translate_exact`: so (by `fill_target_exact`, `fill_target_safe`) the
  accepted target is `PathBytes ++ QueryBytes` of those arguments, every
  byte is unreserved or one of `/ ? = &`, and every template part had a
  value.

How candidates are read off the target (`bind_path`, `bind_query`, and the
allowed texts that let one value span `/`) is not proved and need not be: it only decides which requests are translated. The
host bridge still authorizes the resulting named operation on its own
policy, so a guest whose route copy differs from the host's can only ask for
a different named operation, never widen authority.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.route.Proofs
open aivm_secrets_garrett_core.proxy_http.Proofs (slice_eq_eq)
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.route_match.Proofs

open aivm_secrets_garrett_core.route

/-- **Round trip.** Accepted arguments make the host's `fill_target`
    reproduce the guest's target exactly. -/
theorem translate_round_trip {path : Slice Piece} {query : Slice QueryPiece}
    {candidates : Slice Binding} {target : Slice U8}
    {bindings : alloc.vec.Vec Binding}
    (h : translate path query candidates target = Result.ok (some bindings)) :
    ∃ filled : alloc.vec.Vec U8,
      fill_target path query (alloc.vec.Vec.deref bindings) = Result.ok (.Ok filled) ∧
      filled.val = target.val := by
  unfold translate at h
  obtain ⟨stop, _, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  · obtain ⟨first, _, h⟩ := bind_ok_inv h
    split at h
    · simp at h
    · obtain ⟨b0, _, h⟩ := bind_ok_inv h
      obtain ⟨b1, _, h⟩ := bind_ok_inv h
      obtain ⟨r, filled_call, h⟩ := bind_ok_inv h
      cases r with
      | Err e => simp at h
      | Ok filled =>
        simp only [slice_eq_eq, bind_ok] at h
        split at h
        · rename_i same
          simp only [Result.ok.injEq, Option.some.injEq] at h
          subst h
          simp only [decide_eq_true_eq, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] at same
          exact ⟨filled, filled_call, same⟩
        · simp at h

/-- **What an accepted translation means.** The guest's target is exactly
    the host encoding of the accepted arguments, and contains only safe
    bytes. -/
theorem translate_exact {path : Slice Piece} {query : Slice QueryPiece}
    {candidates : Slice Binding} {target : Slice U8}
    {bindings : alloc.vec.Vec Binding}
    (h : translate path query candidates target = Result.ok (some bindings)) :
    target.val = PathBytes bindings.val path.val ++ QueryBytes bindings.val true query.val ∧
      Bound bindings.val path.val ∧ QueryBound bindings.val query.val ∧
      ∀ byte ∈ target.val, TargetByte byte := by
  obtain ⟨filled, call, same⟩ := translate_round_trip h
  obtain ⟨bytes, bound, qbound, _⟩ := fill_target_exact call
  obtain ⟨safe, _⟩ := fill_target_safe call
  simp only [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] at bytes bound qbound
  refine ⟨by rw [← same, bytes], bound, qbound, ?_⟩
  rw [← same]
  exact safe

end aivm_secrets_garrett_core.route_match.Proofs
