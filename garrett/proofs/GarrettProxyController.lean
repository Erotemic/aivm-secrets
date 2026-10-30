import GarrettProxyResponse

/-!
# `garrett-stateless-v1`: the proxy's per-request helpers

Source: `crates/garrett-stateless-core/src/proxy_controller.rs`, extracted by
Aeneas. `stateless_proxy::serve` and `connection` use these to frame a
request off the connection and to answer it:

* `stopped_reply`: a stopped request carries exactly the fixed refusal for
  its code (`refusalText`);
* `release_reply`: a released request's reply is exactly what
  `guest_response` produced for the parsed provider response, or a fixed
  refusal;
* `frame_paths`: a request reaches `serve` only through the strict
  `parse_request` within the raw bound; past it, the refusal is `too_large`.

What the native shell does with the reply is outside these
(`STATELESS-NATIVE-01`).
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs

namespace garrett_stateless_core.proxy_controller.Proofs

open garrett_stateless_core.proxy_http.Proofs
open garrett_stateless_core.http_auth.Proofs (HeaderPrefix)

/-- A stopped request carries exactly the fixed refusal for its code. -/
theorem stopped_reply {code : proxy_http.refusal.Code} {stage : Stage} {served : Served}
    (h : stopped code stage = Result.ok served) :
    served.reply.val = ascii (refusalText code) ∧ served.stage = stage ∧ served.keep = false ∧
      served.code = code := by
  unfold stopped at h
  obtain ⟨out, returned, exact⟩ := returned_of_spec (refusal_exact code)
  rw [returned] at h
  simp only [bind_ok, Result.ok.injEq] at h
  subst h
  exact ⟨exact, rfl, rfl, rfl⟩

/-- **Release.** A released request's reply is exactly what `guest_response`
    appended to an empty buffer for the parsed provider response; any other
    outcome is a fixed refusal. -/
theorem release_reply (raw : Slice U8) (request : proxy_http.request.Request) (forms : Slice proxy_http.response.Form)
    (limit : Usize) (served : Served) (h : release raw request forms limit = Result.ok served) :
    (served.stage = .Completed ∧ ∃ head response,
      proxy_http.response.guest_response (alloc.vec.Vec.new U8) response forms request.keep_alive head =
        Result.ok (.Ok (), served.reply)) ∨
    (served.stage = .Failed ∧ served.reply.val = ascii (refusalText served.code)) := by
  unfold release at h
  obtain ⟨head, _, h⟩ := bind_ok_inv h
  obtain ⟨parsed, _, h⟩ := bind_ok_inv h
  cases parsed with
  | Ok response =>
    obtain ⟨⟨r1, out⟩, released, h⟩ := bind_ok_inv h
    cases r1 with
    | Ok u =>
      have h : Result.ok (Served.mk out request.keep_alive Stage.Completed
          proxy_http.refusal.Code.OutcomeUnknown response.status) = Result.ok served := h
      simp only [Result.ok.injEq] at h
      subst h
      cases u
      exact Or.inl ⟨rfl, head, response, released⟩
    | Err e =>
      have h : stopped proxy_http.refusal.Code.Reflected Stage.Failed = Result.ok served := h
      obtain ⟨reply, stage, _, code⟩ := stopped_reply h
      exact Or.inr ⟨stage, by rw [reply, code]⟩
  | Err refused =>
    cases refused <;> (
      obtain ⟨reply, stage, _, code⟩ := stopped_reply h
      exact Or.inr ⟨stage, by rw [reply, code]⟩)

variable {U : Type}

/-- **A request is framed only by the strict parser within the raw bound.**
    `frame` hands a request to `serve` only if the buffered bytes are within
    `raw_limit` and the extracted `parse_request` accepted them; it asks for
    more bytes only in the same two conditions; past the bound it refuses
    with `too_large` without parsing. -/
theorem frame_paths {buffer host : Slice U8} {limit : Usize} {out : Framed}
    (h : frame buffer host limit = Result.ok out) :
    ∃ bound, raw_limit limit = Result.ok bound ∧
      ((buffer.length > bound.val ∧ out = .Refuse .TooLarge) ∨
       (buffer.length ≤ bound.val ∧ ∃ parsed, proxy_http.request.parse_request buffer host limit = Result.ok parsed ∧
         match parsed with
         | .Ok none => out = .More
         | .Ok (some request) => out = .Request request
         | .Err refused => code_of refused = Result.ok (match out with
             | .Refuse code => code
             | _ => .InvalidRequest) ∧ ∃ code, out = .Refuse code)) := by
  unfold frame at h
  obtain ⟨bound, hbound, h⟩ := bind_ok_inv h
  refine ⟨bound, hbound, ?_⟩
  split at h
  · rename_i over
    simp only [Result.ok.injEq] at h
    exact Or.inl ⟨by scalar_tac, h.symm⟩
  · rename_i within
    right
    refine ⟨by scalar_tac, ?_⟩
    obtain ⟨parsed, hparsed, h⟩ := bind_ok_inv h
    refine ⟨parsed, hparsed, ?_⟩
    cases parsed with
    | Ok o =>
      cases o with
      | none => simp only [Result.ok.injEq] at h; exact h.symm
      | some request => simp only [Result.ok.injEq] at h; exact h.symm
    | Err refused =>
      obtain ⟨code, coded, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq] at h
      subst h
      exact ⟨coded, code, rfl⟩

end garrett_stateless_core.proxy_controller.Proofs
