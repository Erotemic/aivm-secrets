import GarrettProxyResponse

/-!
# PROXY-NATIVE-01: the per-request controller of the substitution proxy

Source: `rust/crates/aivm-secrets-garrett-core/src/proxy_controller.rs`,
extracted by Aeneas. `garrett-proxy` calls `proxy_controller::serve` for every
accepted guest request and supplies only three callbacks (`Upstream`): the
session clock (`current`), the admission audit (`admitted`) and the socket
exchange (`exchange`).

Proved here, for **any** callbacks:

* `serve_not_current`: if the session is not current, nothing is admitted or
  sent and the guest gets the fixed `revoked` refusal;
* `serve_sent_exactly_the_encoding`: if `exchange` was called at all, the
  session was current, the admission audit ran first, and the bytes passed
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
open aivm_secrets_garrett_core.Proofs

namespace aivm_secrets_garrett_core.proxy_controller.Proofs

open aivm_secrets_garrett_core.proxy_http.Proofs
open aivm_secrets_garrett_core.http_auth.Proofs (HeaderPrefix)

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

theorem code_of_ok (refused : proxy_http.Refusal) : ∃ code, code_of refused = Result.ok code := by
  cases refused <;> exact ⟨_, rfl⟩

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

/-- **The controller's only paths.** Every returned `serve` took exactly one
    of three paths:
    1. the session was not current: nothing admitted or sent, `revoked`;
    2. the encoder refused: nothing admitted or sent, a fixed refusal;
    3. the session was current, the encoder accepted and produced `wire`,
       the admission audit ran, and **`exchange` received exactly `wire`**;
       the reply is then `release` of the answer, or a fixed refusal. -/
theorem serve_paths (inst : Upstream U) (io : U) (request : proxy_http.Request) (host : Slice U8)
    (rules : Slice proxy_http.DenyRule) (secret : Slice U8)
    (authentication : credential_use.Authentication) (forms : Slice proxy_http.Form) (limit : Usize)
    (served : Served) (after : U)
    (h : serve inst io request host rules secret authentication forms limit = Result.ok (served, after)) :
    (∃ io1, inst.current io = Result.ok (false, io1) ∧ after = io1 ∧
      stopped .Revoked .Refused = Result.ok served) ∨
    (∃ io1 wire refused code, inst.current io = Result.ok (true, io1) ∧
      proxy_http.encode_upstream (alloc.vec.Vec.new U8) request host rules secret authentication =
        Result.ok (.Err refused, wire) ∧ code_of refused = Result.ok code ∧ after = io1 ∧
      stopped code .Refused = Result.ok served) ∨
    (∃ io1 wire io2 answer, inst.current io = Result.ok (true, io1) ∧
      proxy_http.encode_upstream (alloc.vec.Vec.new U8) request host rules secret authentication =
        Result.ok (.Ok (), wire) ∧
      inst.admitted io1 = Result.ok io2 ∧
      inst.exchange io2 (alloc.vec.Vec.deref wire) = Result.ok (answer, after) ∧
      (match answer with
       | .Ok raw => release (alloc.vec.Vec.deref raw) request forms limit = Result.ok served
       | .Err code => stopped code .Failed = Result.ok served)) := by
  unfold serve at h
  obtain ⟨⟨b, io1⟩, current, h⟩ := bind_ok_inv h
  cases b with
  | false =>
    obtain ⟨s, stop, h⟩ := bind_ok_inv h
    simp only [Result.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨hs, ha⟩ := h
    subst hs ha
    exact Or.inl ⟨io1, current, rfl, stop⟩
  | true =>
    obtain ⟨⟨r, wire⟩, encoded, h⟩ := bind_ok_inv h
    cases r with
    | Err refused =>
      obtain ⟨code, coded, h⟩ := bind_ok_inv h
      obtain ⟨s, stop, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨hs, ha⟩ := h
      subst hs ha
      exact Or.inr (Or.inl ⟨io1, wire, refused, code, current, encoded, coded, rfl, stop⟩)
    | Ok u =>
      obtain ⟨io2, admitted, h⟩ := bind_ok_inv h
      obtain ⟨⟨answer, io3⟩, exchanged, h⟩ := bind_ok_inv h
      cases u
      refine Or.inr (Or.inr ⟨io1, wire, io2, answer, current, encoded, admitted, ?_⟩)
      cases answer with
      | Ok raw =>
        obtain ⟨s, released, h⟩ := bind_ok_inv h
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨hs, ha⟩ := h
        subst hs ha
        exact ⟨exchanged, released⟩
      | Err code =>
        obtain ⟨s, stop, h⟩ := bind_ok_inv h
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨hs, ha⟩ := h
        subst hs ha
        exact ⟨exchanged, stop⟩

/-- **What goes upstream.** A request that was not refused before egress
    (`stage ≠ Refused`) passed through `exchange` exactly once, after the
    session was found current and the admission audit ran, and the bytes
    passed to `exchange` are exactly the encoder's output: for a request whose
    canonical encoding fits in memory, `UpstreamPrefix ++ HeaderPrefix ++
    secret ++ CRLF ++ UpstreamSuffix`, with a valid credential, a visible
    target and every forwarded guest field clean. A refused request reached
    neither `admitted` nor `exchange`. -/
theorem serve_upstream (inst : Upstream U) (io : U) (request : proxy_http.Request)
    (host : Slice U8) (rules : Slice proxy_http.DenyRule) (secret : Slice U8)
    (authentication : credential_use.Authentication) (forms : Slice proxy_http.Form) (limit : Usize)
    (served : Served) (after : U)
    (h : serve inst io request host rules secret authentication forms limit = Result.ok (served, after))
    (room : (UpstreamPrefix request host ++ HeaderPrefix authentication ++ secret.val ++ CRLF ++
      UpstreamSuffix request).length ≤ Usize.max) :
    (served.stage = .Refused ∧ ∃ current io1, inst.current io = Result.ok (current, io1) ∧ after = io1) ∨
    (served.stage ≠ .Refused ∧ ∃ io1 io2 wire answer,
      inst.current io = Result.ok (true, io1) ∧ inst.admitted io1 = Result.ok io2 ∧
      inst.exchange io2 (alloc.vec.Vec.deref wire) = Result.ok (answer, after) ∧
      wire.val = UpstreamPrefix request host ++ HeaderPrefix authentication ++ secret.val ++ CRLF ++
        UpstreamSuffix request ∧
      http_auth.Proofs.ValidCredential secret ∧ (∀ byte ∈ request.target.val, Visible byte) ∧
      (∀ field ∈ Forwarded request.fields.val, CleanField field)) := by
  rcases serve_paths inst io request host rules secret authentication forms limit served after h with
    ⟨io1, current, same, stop⟩ | ⟨io1, wire, refused, code, current, _, _, same, stop⟩ |
    ⟨io1, wire, io2, answer, current, encoded, admitted, exchanged, finish⟩
  · exact Or.inl ⟨(stopped_reply stop).2.1, false, io1, current, same⟩
  · exact Or.inl ⟨(stopped_reply stop).2.1, true, io1, current, same⟩
  · have stage : served.stage ≠ .Refused := by
      cases answer with
      | Ok raw =>
        rcases release_reply _ request forms limit served finish with ⟨done, _⟩ | ⟨failed, _⟩
        · rw [done]; simp
        · rw [failed]; simp
      | Err code => rw [(stopped_reply finish).2.1]; simp
    obtain ⟨value, returned, post⟩ := returned_of_spec
      (encode_upstream_contract (alloc.vec.Vec.new U8) request host rules secret authentication
        (by simpa [alloc.vec.Vec.new, alloc.vec.Vec.length] using room))
    rw [encoded] at returned
    simp only [Result.ok.injEq] at returned
    subst returned
    rcases post with ⟨_, valid, visible, clean, bytes⟩ | ⟨refused, _⟩
    · refine Or.inr ⟨stage, io1, io2, wire, answer, current, admitted, exchanged, ?_, valid, visible,
        clean⟩
      simpa [alloc.vec.Vec.new] using bytes
    · exact absurd rfl refused

/-- **What the guest receives.** The reply `serve` hands the native shell is
    either the fixed refusal for its code (`refusal_exact`: nothing but the
    code), or, for a completed request, exactly what `guest_response`
    released for the parsed provider response. For a response whose checked
    encoding fits in memory, no case-sensitive credential form occurs in it
    (`guest_response_contract`). -/
theorem serve_guest_reply (inst : Upstream U) (io : U) (request : proxy_http.Request)
    (host : Slice U8) (rules : Slice proxy_http.DenyRule) (secret : Slice U8)
    (authentication : credential_use.Authentication) (forms : Slice proxy_http.Form) (limit : Usize)
    (served : Served) (after : U)
    (h : serve inst io request host rules secret authentication forms limit = Result.ok (served, after)) :
    served.reply.val = ascii (refusalText served.code) ∨
    (served.stage = .Completed ∧ ∃ head response,
      proxy_http.guest_response (alloc.vec.Vec.new U8) response forms request.keep_alive head =
        Result.ok (.Ok (), served.reply) ∧
      ((ResponseBytes response response.fields.val request.keep_alive false).length ≤ Usize.max →
        ∀ form ∈ forms.val, form.folded = false → ¬ Occurs served.reply.val form.bytes.val)) := by
  have stopped_case : ∀ {code stage}, stopped code stage = Result.ok served →
      served.reply.val = ascii (refusalText served.code) := by
    intro code stage stop
    obtain ⟨reply, _, _, same⟩ := stopped_reply stop
    rw [reply, same]
  rcases serve_paths inst io request host rules secret authentication forms limit served after h with
    ⟨_, _, _, stop⟩ | ⟨_, _, _, _, _, _, _, _, stop⟩ | ⟨_, _, _, answer, _, _, _, _, finish⟩
  · exact Or.inl (stopped_case stop)
  · exact Or.inl (stopped_case stop)
  · cases answer with
    | Err code => exact Or.inl (stopped_case finish)
    | Ok raw =>
      rcases release_reply _ request forms limit served finish with
        ⟨done, head, response, released⟩ | ⟨_, refused⟩
      · refine Or.inr ⟨done, head, response, released, fun fits form mem plain => ?_⟩
        have contract := guest_response_contract (alloc.vec.Vec.new U8) response forms
          request.keep_alive head (by simpa [alloc.vec.Vec.new, alloc.vec.Vec.length] using fits)
        rw [released] at contract
        simp only [WP.spec_ok] at contract
        rcases contract with ⟨_, appended, bytes, none⟩ | ⟨wrong, _⟩
        · have : served.reply.val = appended := by simpa [alloc.vec.Vec.new] using bytes
          rw [this]
          exact none form mem plain
        · exact absurd rfl wrong
      · exact Or.inl refused

/-! ## Framing the guest's bytes -/

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

end aivm_secrets_garrett_core.proxy_controller.Proofs
