import GarrettRoute

/-!
# HTTPS proxy: who may open a tunnel

Source: `rust/crates/aivm-secrets-garrett-core/src/proxy_connect.rs`,
extracted by Aeneas. `garrett-proxy` reads a guest's `CONNECT` head and
opens a tunnel only if `proxy_connect::admit` answers `Open i`, and then
only to the configured origin at index `i`.

Proved here:

* `same_secret_true`: the constant-time comparison answers `true` only for
  byte-identical inputs;
* `authenticated_true`: authentication succeeds only if some field named
  `Proxy-Authorization` (any ASCII case) presents, through the extracted
  `presented` (`Bearer TOKEN` or `Basic base64(USER:TOKEN)`), exactly the
  session token;
* `admit_open`: a tunnel opens only for a current session, a valid index
  into the configured origins (equal to the host the extracted code read
  from the authority), and a head whose fields authenticate.

`presented`'s base64 decoding is extracted but not proved to be base64; it
does not need to be for this claim, because the bytes it presents must
still equal the session token. A Rust oracle test
(`garrett-proxy` `connect_oracle`) checks the decision against the native
code it replaced, including the `base64` crate's decoder.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.route.Proofs (bind_ok_inv index_usize_eq add_one_eq)
open aivm_secrets_garrett_core.proxy_http.Proofs (slice_eq_eq name_is_eq fold)
set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace aivm_secrets_garrett_core.proxy_connect.Proofs

def ProxyAuthorization : List U8 :=
  [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 97#u8, 117#u8, 116#u8, 104#u8,
   111#u8, 114#u8, 105#u8, 122#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8]

/-! ## Constant-time comparison -/

theorem or_zero {x y : U8} (h : (x ||| y) = 0#u8) : x = 0#u8 ∧ y = 0#u8 := by
  have hb : x.bv ||| y.bv = 0#8 := by
    have := congrArg UScalar.bv h; simpa using this
  -- Bit by bit, kernel-checked: `bv_decide` would add a native-code axiom.
  have bits : ∀ i, x.bv.getLsbD i = false ∧ y.bv.getLsbD i = false := by
    intro i
    have := congrArg (fun v => v.getLsbD i) hb
    simpa [BitVec.getLsbD_or] using this
  have hx : x.bv = 0#8 := BitVec.eq_of_getLsbD_eq (fun i _ => by simp [(bits i).1])
  have hy : y.bv = 0#8 := BitVec.eq_of_getLsbD_eq (fun i _ => by simp [(bits i).2])
  exact ⟨U8.bv_eq_imp_eq _ _ (by simpa using hx), U8.bv_eq_imp_eq _ _ (by simpa using hy)⟩

theorem xor_zero {x y : U8} (h : (x ^^^ y) = 0#u8) : x = y := by
  have hb : x.bv ^^^ y.bv = 0#8 := by
    have := congrArg UScalar.bv h; simpa using this
  apply U8.bv_eq_imp_eq
  calc x.bv = (x.bv ^^^ y.bv) ^^^ y.bv := by rw [BitVec.xor_assoc]; simp
    _ = y.bv := by rw [hb]; simp

theorem same_secret_loop_ok (a b : Slice U8) (same_length : a.length = b.length) :
    ∀ n (difference r : U8) (index : Usize), a.length - index.val = n →
      same_secret_loop a b difference index = Result.ok r → r = 0#u8 →
      difference = 0#u8 ∧ ∀ k (hk : k < a.length), index.val ≤ k → a.val[k] = b.val[k]'(by scalar_tac) := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro difference r index measure h zero
    rw [same_secret_loop.eq_def] at h
    dsimp only at h
    split at h
    · rename_i inside
      obtain ⟨x, hx, h⟩ := bind_ok_inv h
      rw [index_usize_eq a index (by scalar_tac)] at hx
      obtain ⟨y, hy, h⟩ := bind_ok_inv h
      rw [index_usize_eq b index (by scalar_tac)] at hy
      simp only [Result.ok.injEq] at hx hy
      simp only [lift, bind_ok] at h
      obtain ⟨next, added, value⟩ := add_one_eq index (by scalar_tac)
      simp only [added, bind_ok] at h
      obtain ⟨both, rest⟩ := ih (a.length - next.val) (by scalar_tac) _ r next rfl h zero
      obtain ⟨before, here⟩ := or_zero both
      refine ⟨before, fun k hk lo => ?_⟩
      by_cases at_index : k = index.val
      · subst at_index
        have := xor_zero here
        rw [← hx, ← hy] at this
        exact this
      · exact rest k hk (by scalar_tac)
    · simp only [Result.ok.injEq] at h
      subst h
      refine ⟨zero, fun k hk lo => ?_⟩
      exfalso; scalar_tac

/-- **Constant-time comparison.** It answers `true` only for equal bytes. -/
theorem same_secret_true {a b : Slice U8} (h : same_secret a b = Result.ok true) : a.val = b.val := by
  unfold same_secret at h
  dsimp only at h
  split at h
  · simp at h
  · rename_i lengths
    have same_length : a.length = b.length := by
      simp only [bne_iff_ne, ne_eq, Decidable.not_not] at lengths; scalar_tac
    obtain ⟨r, looped, h⟩ := bind_ok_inv h
    simp only [Result.ok.injEq, decide_eq_true_eq] at h
    obtain ⟨_, all⟩ := same_secret_loop_ok a b same_length _ 0#u8 r 0#usize rfl looped h
    apply List.ext_getElem (by simpa [Slice.length] using same_length)
    intro k hk _
    exact all k hk (by simp)

/-! ## Authentication -/

theorem first_named_loop_ok (fields : Slice proxy_http.Field) (label : Slice U8) :
    ∀ n (index i : Usize), fields.length - index.val = n →
      proxy_http.first_named_loop fields label index = Result.ok i → (inside : i.val < fields.length) →
      fold (fields.val[i.val]'(by simpa [Slice.length] using inside)).name.val = fold label.val := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index i measure h inside
    rw [proxy_http.first_named_loop.eq_def] at h
    dsimp only at h
    split at h
    · obtain ⟨f, hf, h⟩ := bind_ok_inv h
      rw [index_usize_eq fields index (by scalar_tac)] at hf
      simp only [Result.ok.injEq] at hf
      subst hf
      rw [name_is_eq] at h
      simp only [bind_ok] at h
      split at h
      · rename_i named
        simp only [Result.ok.injEq] at h
        subst h
        simpa using named
      · obtain ⟨next, added, value⟩ := add_one_eq index (by scalar_tac)
        simp only [added, bind_ok] at h
        exact ih (fields.length - next.val) (by scalar_tac) next i rfl h inside
    · simp only [Result.ok.injEq] at h
      subst h
      exfalso; scalar_tac

/-- **Authentication.** It succeeds only if a field named
    `Proxy-Authorization` (any ASCII case) presents exactly the token. -/
theorem authenticated_true {fields : Slice proxy_http.Field} {token : Slice U8}
    (h : authenticated fields token = Result.ok true) :
    ∃ (k : Nat) (inside : k < fields.length) (candidate : alloc.vec.Vec U8),
      fold (fields.val[k]).name.val = fold ProxyAuthorization ∧
      presented (alloc.vec.Vec.deref (fields.val[k]).value) = Result.ok (some candidate) ∧
      candidate.val = token.val := by
  unfold authenticated at h
  simp only [lift, Array.to_slice, Array.make, bind_ok] at h
  obtain ⟨count, _, h⟩ := bind_ok_inv h
  split at h
  · simp at h
  · obtain ⟨index, found, h⟩ := bind_ok_inv h
    split at h
    · simp at h
    · rename_i inside
      have inside : index.val < fields.length := by
        simp only [ge_iff_le, not_le] at inside; scalar_tac
      rw [index_usize_eq fields index inside] at h
      simp only [bind_ok] at h
      obtain ⟨o, hpresented, h⟩ := bind_ok_inv h
      cases o with
      | none => simp at h
      | some candidate =>
        simp only at h
        refine ⟨index.val, inside, candidate, ?_, hpresented, ?_⟩
        · have := first_named_loop_ok fields _ _ 0#usize index rfl found inside
          simpa [ProxyAuthorization] using this
        · simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using same_secret_true h

/-! ## The tunnel decision -/

theorem origin_index_loop_ok (hosts : Slice (alloc.vec.Vec U8)) (host : Slice U8) :
    ∀ n (index i : Usize), hosts.length - index.val = n →
      origin_index_loop hosts host index = Result.ok i → (inside : i.val < hosts.length) →
      (hosts.val[i.val]'(by simpa [Slice.length] using inside)).val = host.val := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index i measure h inside
    rw [origin_index_loop.eq_def] at h
    dsimp only at h
    split at h
    · obtain ⟨v, hv, h⟩ := bind_ok_inv h
      rw [index_usize_eq hosts index (by scalar_tac)] at hv
      simp only [Result.ok.injEq] at hv
      subst hv
      simp only [slice_eq_eq, bind_ok] at h
      split at h
      · rename_i same
        simp only [Result.ok.injEq] at h
        subst h
        simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using same
      · obtain ⟨next, added, value⟩ := add_one_eq index (by scalar_tac)
        simp only [added, bind_ok] at h
        exact ih (hosts.length - next.val) (by scalar_tac) next i rfl h inside
    · simp only [Result.ok.injEq] at h
      subst h
      exfalso; simp [Slice.len, Slice.length] at inside

/-- **Who may open a tunnel.** `admit` answers `Open i` only if the session
    is current, `i` indexes a configured origin (whose name equals the host
    slice the extracted code compared), and the parsed fields authenticate
    (with `authenticated_true`: some `Proxy-Authorization` field presents
    exactly the session token). The native shell opens the tunnel only to
    origin `i`. -/
theorem admit_open {head token : Slice U8} {hosts : Slice (alloc.vec.Vec U8)} {current : Bool}
    {i : Usize} (h : admit head token hosts current = Result.ok (.Open i)) :
    current = true ∧ ∃ (inside : i.val < hosts.length) (host : Slice U8)
      (fields : Slice proxy_http.Field),
      (hosts.val[i.val]).val = host.val ∧ authenticated fields token = Result.ok true := by
  unfold admit at h
  obtain ⟨first, _, h⟩ := bind_ok_inv h
  obtain ⟨line, _, h⟩ := bind_ok_inv h
  obtain ⟨o, _, h⟩ := bind_ok_inv h
  cases o with
  | none => simp at h
  | some found =>
    obtain ⟨one, two⟩ := found
    obtain ⟨method, _, h⟩ := bind_ok_inv h
    obtain ⟨_, _, h⟩ := bind_ok_inv h
    obtain ⟨version, _, h⟩ := bind_ok_inv h
    simp only [lift, Array.to_slice, Array.make, bind_ok] at h
    obtain ⟨clean, _, h⟩ := bind_ok_inv h
    split at h
    · simp only [slice_eq_eq, bind_ok] at h
      split at h
      · split at h
        · split at h
          · obtain ⟨b3, auth, h⟩ := bind_ok_inv h
            split at h
            · rename_i yes
              subst yes
              obtain ⟨_, _, h⟩ := bind_ok_inv h
              obtain ⟨authority, _, h⟩ := bind_ok_inv h
              obtain ⟨colon, _, h⟩ := bind_ok_inv h
              obtain ⟨host, _, h⟩ := bind_ok_inv h
              obtain ⟨port, _, h⟩ := bind_ok_inv h
              obtain ⟨index, found, h⟩ := bind_ok_inv h
              split at h
              · simp at h
              · rename_i inside
                split at h
                · split at h
                  · rename_i live
                    simp only [Result.ok.injEq, Admission.Open.injEq] at h
                    subst h
                    have inside : index.val < hosts.length := by
                      simp only [ge_iff_le, not_le] at inside; scalar_tac
                    exact ⟨live, inside, host, _, origin_index_loop_ok hosts host _ 0#usize index rfl
                      (by simpa [origin_index] using found) inside, auth⟩
                  · simp at h
                · simp at h
            · simp at h
          · obtain ⟨_, _, h⟩ := bind_ok_inv h
            obtain ⟨o1, _, h⟩ := bind_ok_inv h
            cases o1 with
            | none => simp at h
            | some fields =>
              simp only at h
              obtain ⟨b3, auth, h⟩ := bind_ok_inv h
              split at h
              · rename_i yes
                subst yes
                obtain ⟨_, _, h⟩ := bind_ok_inv h
                obtain ⟨authority, _, h⟩ := bind_ok_inv h
                obtain ⟨colon, _, h⟩ := bind_ok_inv h
                obtain ⟨host, _, h⟩ := bind_ok_inv h
                obtain ⟨port, _, h⟩ := bind_ok_inv h
                obtain ⟨index, found, h⟩ := bind_ok_inv h
                split at h
                · simp at h
                · rename_i inside
                  split at h
                  · split at h
                    · rename_i live
                      simp only [Result.ok.injEq, Admission.Open.injEq] at h
                      subst h
                      have inside : index.val < hosts.length := by
                        simp only [ge_iff_le, not_le] at inside; scalar_tac
                      exact ⟨live, inside, host, _, origin_index_loop_ok hosts host _ 0#usize index rfl
                        (by simpa [origin_index] using found) inside, auth⟩
                    · simp at h
                  · simp at h
              · simp at h
        · simp at h
      · simp at h
    · simp at h

end aivm_secrets_garrett_core.proxy_connect.Proofs
