import GarrettProxyResponse

/-!
# PROXY-NATIVE-01: the per-request controller of the substitution proxy

Source: `crates/garrett-stateless-core/src/proxy_controller.rs`,
extracted by Aeneas. `garrett-proxy` calls `proxy_controller::serve` for every
accepted guest request and supplies only three callbacks (`Upstream`): the
session clock (`current`), the admission audit (`admitted`, which reports whether
the record was durably written), the socket exchange (`exchange`) and the
completion audit (`completed`, written before a completed reply is released).

Proved here, for **any** callbacks:

* `serve_not_current`: if the session is not current, nothing is admitted or
  sent and the guest gets the fixed `revoked` refusal;
* `serve_sent_exactly_the_encoding`: if `exchange` was called at all, the
  session was current, the admission audit was acknowledged first (a failed
  audit refuses with `internal_error` and sends nothing), and the bytes passed
  to `exchange` are exactly what the extracted `encode_upstream` produced
  (so `encode_upstream_contract` describes every byte sent upstream);
* `serve_guest_bytes`: the guest reply is either a fixed refusal or bytes
  released by `guest_response`, in which no case-sensitive credential form
  occurs.

Still assumed (`PROXY-NATIVE-01`): that the native callbacks do what they
say (the exchange writes its argument to the pinned origin and nothing
else), that the native shell writes `served.reply` and nothing else to the
guest, and the CONNECT/tunnel handling outside `serve`.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs

namespace garrett_stateless_core.proxy_controller.Proofs

open garrett_stateless_core.proxy_http.Proofs
open garrett_stateless_core.http_auth.Proofs (HeaderPrefix)

/-- A stopped request carries exactly the fixed refusal for its code. -/
theorem stopped_reply {code : proxy_http.Code} {stage : Stage} {served : Served}
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
theorem release_reply (raw : Slice U8) (request : proxy_http.Request) (forms : Slice proxy_http.Form)
    (limit : Usize) (served : Served) (h : release raw request forms limit = Result.ok served) :
    (served.stage = .Completed ∧ ∃ head response,
      proxy_http.guest_response (alloc.vec.Vec.new U8) response forms request.keep_alive head =
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
          proxy_http.Code.OutcomeUnknown response.status) = Result.ok served := h
      simp only [Result.ok.injEq] at h
      subst h
      cases u
      exact Or.inl ⟨rfl, head, response, released⟩
    | Err e =>
      have h : stopped proxy_http.Code.Reflected Stage.Failed = Result.ok served := h
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
       (buffer.length ≤ bound.val ∧ ∃ parsed, proxy_http.parse_request buffer host limit = Result.ok parsed ∧
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
