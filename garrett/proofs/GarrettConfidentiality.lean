import GarrettStatelessComposition
import GarrettStatelessProtocol

/-!
# `garrett-stateless-v1`: what the credential can influence

Source: `stateless_proxy.rs`, `proxy_controller.rs`, `proxy_http/`,
`stateless.rs` and `stateless_token/sealing.rs`, extracted by Aeneas.

`ClaimsHideCredential` says the credential is not a substring of any claim.
That is a statement about one output. This module states, as two-run
(relational) theorems, which outputs of the actual extracted code **can
depend on the credential at all**, and through what.

## The adversary

The agent is untrusted and fully controls its own requests: every byte of
every request, the surrogate it presents, how it frames them, when it sends
them. It holds a client certificate and its key, and every surrogate it was
issued. It observes everything the proxy and broker send it. It does **not**
hold the broker's or proxy's keys, cannot read the provider's traffic, and
does not control the provider's answers (a provider that the agent can
steer is discussed below).

## The observation and declassification boundary

The theorems compare two executions that differ **only in the protected
credential** and ask what the agent can observe differently.

* **Proxy** (`serve_declassified`). Fix the agent's request, the peer, the
  clock, the routes and both policies, and let the proxy's opener unseal
  either of two valid credentials (`SameButCredential`). Then the decision
  is the same up to the credential (`decide_declassified`: the same refusal,
  or a dispatch to the same route for the same claims), and if the network
  answered both runs alike, the agent receives the same reply, except that
  a provider answer reflecting one credential and not the other turns that
  run's reply into the fixed reflection refusal (`reply_declassified`).
* **Broker** (`issue_ciphertext_only`, `seal_token_ciphertext_only`). Two
  issuances with the same claims and sealer that both succeed, under
  primitives that sign alike and whose AEAD returned the same ciphertext
  for the two credentials, give the same surrogate: the credential reaches a
  surrogate only as AEAD ciphertext.

What is **declassified**, deliberately, and so may depend on the credential:

1. the dispatched bytes, which carry the credential **to the provider**
   (`AuthorizedEgress`, `SendsAreAuthorized` say where they go);
2. the provider's answer, which the agent receives after the reflection
   check (the theorems hold for every answer, but a provider whose answers
   depend on the credential — an echo endpoint that the reflection forms
   miss, an error that reveals a prefix — can reveal it; that is the
   provider's API semantics, not Garrett's);
3. one bit per request: whether the provider's answer reflected the
   credential in one of the checked encodings (`reflection_forms`);
4. at issuance, whether the credential is valid and whether it occurs in
   the header or the public claims (the broker refuses both); and
5. the AEAD ciphertext in the surrogate, which hides the credential only
   under the **cryptographic assumption** that AES-256-GCM is IND-CPA with
   unique nonces (`STATELESS-CRYPTO-01`). It is not proved here, and its
   length reveals the credential's length.

**Not covered**: timing, response sizes as seen on the network, error
timing, memory and side channels, the native shells' own behaviour (they are
trusted to pass only what the core returns, `STATELESS-NATIVE-01`), and a
whole-connection two-run theorem (the connection loop adds only framing
refusals, which do not involve the opener: `connection_step_paths`).
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.proxy_controller.Proofs

/-- **A release depends on the credential only through the reflection
    verdict.** `guest_response` uses the credential's forms only to decide
    whether the re-framed response reflects them; when it does not, its
    bytes are the same whatever the forms. -/
theorem guest_response_forms {output : alloc.vec.Vec U8} {response : proxy_http.response.Response}
    {f1 f2 : Slice proxy_http.response.Form} {keep head : Bool} {r1 r2 o1 o2}
    (h1 : proxy_http.response.guest_response output response f1 keep head = Result.ok (r1, o1))
    (h2 : proxy_http.response.guest_response output response f2 keep head = Result.ok (r2, o2)) :
    (r1 = .Ok () → r2 = .Ok () → o1 = o2) ∧
    (r1 ≠ .Ok () → r1 = .Err .Reflected) ∧ (r2 ≠ .Ok () → r2 = .Err .Reflected) := by
  unfold proxy_http.response.guest_response at h1 h2
  dsimp only at h1 h2
  obtain ⟨fields, hf, h1⟩ := bind_ok_inv h1
  rw [hf] at h2; simp only [bind_ok] at h2
  obtain ⟨full, hfull, h1⟩ := bind_ok_inv h1
  rw [hfull] at h2; simp only [bind_ok] at h2
  obtain ⟨b1, hb1, h1⟩ := bind_ok_inv h1
  obtain ⟨b2, hb2, h2⟩ := bind_ok_inv h2
  have side : ∀ {b : Bool} {r o}, (if b then Result.ok (core.result.Result.Err proxy_http.request.Refusal.Reflected, output)
      else do
        let output1 ← proxy_http.response.encode_response output response (alloc.vec.Vec.deref fields) keep head
        Result.ok (core.result.Result.Ok (), output1)) = Result.ok (r, o) →
      (b = true ∧ r = .Err .Reflected) ∨
      (b = false ∧ r = .Ok () ∧ proxy_http.response.encode_response output response
        (alloc.vec.Vec.deref fields) keep head = Result.ok o) := by
    intro b r o h
    cases b with
    | true =>
      simp only [↓reduceIte, Result.ok.injEq, Prod.mk.injEq] at h
      exact Or.inl ⟨rfl, h.1.symm⟩
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h
      obtain ⟨o', he, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨e1, e2⟩ := h
      subst e1 e2
      exact Or.inr ⟨rfl, rfl, he⟩
  rcases side h1 with ⟨_, e1⟩ | ⟨_, e1, enc1⟩ <;> rcases side h2 with ⟨_, e2⟩ | ⟨_, e2, enc2⟩ <;>
    subst e1 e2 <;> refine ⟨fun a b => ?_, fun n => ?_, fun n => ?_⟩ <;> simp_all

/-- **A released reply depends on the credential only through the
    reflection verdict.** Releasing the same provider answer for the same
    request against the forms of two different credentials gives the same
    reply, unless one of them is the fixed reflection refusal. -/
theorem release_declassified {raw : Slice U8} {request : proxy_http.request.Request}
    {f1 f2 : Slice proxy_http.response.Form} {limit : Usize} {s1 s2 : Served}
    (h1 : release raw request f1 limit = Result.ok s1) (h2 : release raw request f2 limit = Result.ok s2) :
    s1 = s2 ∨ ((stopped .Reflected .Failed = Result.ok s1) ∨ (stopped .Reflected .Failed = Result.ok s2)) := by
  unfold release at h1 h2
  dsimp only at h1 h2
  obtain ⟨head, hh, h1⟩ := bind_ok_inv h1
  rw [hh] at h2; simp only [bind_ok] at h2
  obtain ⟨parsed, hp, h1⟩ := bind_ok_inv h1
  rw [hp] at h2; simp only [bind_ok] at h2
  cases parsed with
  | Err e =>
    left
    rw [h1] at h2
    simpa using h2
  | Ok response =>
    obtain ⟨⟨r1, o1⟩, hg1, h1⟩ := bind_ok_inv h1
    obtain ⟨⟨r2, o2⟩, hg2, h2⟩ := bind_ok_inv h2
    obtain ⟨same, ref1, ref2⟩ := guest_response_forms hg1 hg2
    cases r1 with
    | Err e => exact Or.inr (Or.inl h1)
    | Ok u1 =>
      cases r2 with
      | Err e => exact Or.inr (Or.inr h2)
      | Ok u2 =>
        left
        cases u1; cases u2
        have eo := same rfl rfl
        subst eo
        simp only [Aeneas.Std.uncurry_apply_pair] at h1 h2
        rw [← Result.ok_injective h1, ← Result.ok_injective h2]

end garrett_stateless_core.proxy_controller.Proofs

namespace garrett_stateless_core.proxy_http.Proofs

/-- A valid credential's authentication line is always appended. -/
theorem append_header_valid {output : alloc.vec.Vec U8} {secret : Slice U8} {a : credential_use.Authentication}
    {r o} (valid : http_auth.Proofs.ValidCredential secret)
    (h : http_auth.append_header output secret a = Result.ok (r, o)) : r = .Ok () := by
  obtain ⟨accepted, checked, equivalent⟩ := returned_of_spec (http_auth.Proofs.valid_credential_contract secret)
  have yes : accepted = true := equivalent.mpr valid
  unfold http_auth.append_header at h
  rw [checked] at h
  simp only [bind_ok, yes, ↓reduceIte] at h
  repeat (obtain ⟨_, _, h⟩ := bind_ok_inv h)
  simp only [Result.ok.injEq, Prod.mk.injEq] at h
  exact h.1.symm

/-- **The encoder's verdict does not depend on which valid credential it
    carries.** Every refusal of `encode_upstream` comes from a check of the
    request and the deny rules made before the credential is read, or from
    the credential's validity; so for two valid credentials, everything else
    equal, it accepts both or refuses both with the same refusal. -/
theorem encode_upstream_verdict {output : alloc.vec.Vec U8} {request : proxy_http.request.Request}
    {host : Slice U8} {rules : Slice proxy_http.upstream.DenyRule} {s1 s2 : Slice U8}
    {a : credential_use.Authentication} {r1 r2}
    (v1 : http_auth.Proofs.ValidCredential s1) (v2 : http_auth.Proofs.ValidCredential s2)
    (h1 : proxy_http.upstream.encode_upstream output request host rules s1 a = Result.ok r1)
    (h2 : proxy_http.upstream.encode_upstream output request host rules s2 a = Result.ok r2) :
    r1.1 = r2.1 := by
  have yes : ∀ {s : Slice U8}, http_auth.Proofs.ValidCredential s → http_auth.valid_credential s = Result.ok true := by
    intro s v
    obtain ⟨accepted, checked, equivalent⟩ := returned_of_spec (http_auth.Proofs.valid_credential_contract s)
    rw [checked, equivalent.mpr v]
  unfold proxy_http.upstream.encode_upstream at h1 h2
  dsimp only at h1 h2
  obtain ⟨b, hb, h1⟩ := bind_ok_inv h1
  rw [hb] at h2; simp only [bind_ok] at h2
  cases b
  · simp only [Bool.false_eq_true, ↓reduceIte] at h1 h2
    rw [← Result.ok_injective h1, ← Result.ok_injective h2]
  simp only [↓reduceIte] at h1 h2
  obtain ⟨b1, hb1, h1⟩ := bind_ok_inv h1
  rw [hb1] at h2; simp only [bind_ok] at h2
  cases b1
  · simp only [Bool.false_eq_true, ↓reduceIte] at h1 h2
    rw [← Result.ok_injective h1, ← Result.ok_injective h2]
  simp only [↓reduceIte] at h1 h2
  obtain ⟨fields, hf, h1⟩ := bind_ok_inv h1
  rw [hf] at h2; simp only [bind_ok] at h2
  obtain ⟨b2, hb2, h1⟩ := bind_ok_inv h1
  rw [hb2] at h2; simp only [bind_ok] at h2
  cases b2
  · simp only [Bool.false_eq_true, ↓reduceIte] at h1 h2
    rw [← Result.ok_injective h1, ← Result.ok_injective h2]
  simp only [↓reduceIte] at h1 h2
  obtain ⟨e, he, h1⟩ := bind_ok_inv h1
  rw [he] at h2; simp only [bind_ok] at h2
  obtain ⟨t, ht, h1⟩ := bind_ok_inv h1
  rw [ht] at h2; simp only [bind_ok] at h2
  obtain ⟨b3, hb3, h1⟩ := bind_ok_inv h1
  rw [hb3] at h2; simp only [bind_ok] at h2
  cases b3
  swap
  · simp only [↓reduceIte] at h1 h2
    rw [← Result.ok_injective h1, ← Result.ok_injective h2]
  simp only [Bool.false_eq_true, ↓reduceIte, yes v1, yes v2, bind_ok] at h1 h2
  iterate 10 (obtain ⟨_, _, h1⟩ := bind_ok_inv h1)
  iterate 10 (obtain ⟨_, _, h2⟩ := bind_ok_inv h2)
  obtain ⟨⟨q1, o1⟩, ha1, h1⟩ := bind_ok_inv h1
  obtain ⟨⟨q2, o2⟩, ha2, h2⟩ := bind_ok_inv h2
  obtain rfl := append_header_valid v1 ha1
  obtain rfl := append_header_valid v2 ha2
  simp only [Aeneas.Std.uncurry_apply_pair] at h1 h2
  repeat (obtain ⟨_, _, h1⟩ := bind_ok_inv h1)
  repeat (obtain ⟨_, _, h2⟩ := bind_ok_inv h2)
  rw [← Result.ok_injective h1, ← Result.ok_injective h2]

end garrett_stateless_core.proxy_http.Proofs

namespace garrett_stateless_core.stateless_proxy.Proofs

variable {V P : Type}

/-- **Two openers that differ only in the credential.** They verify every
    token alike; for every verified envelope they unseal the same result, or
    each a valid credential (the protected secret). -/
def SameButCredential (ops1 ops2 : stateless.SurrogateOpener V) (opener : V) : Prop :=
  ops1.verify = ops2.verify ∧
  ∀ v r1 r2, ops1.«unseal» opener v = Result.ok r1 → ops2.«unseal» opener v = Result.ok r2 →
    r1 = r2 ∨ ∃ c1 c2, r1 = .Ok c1 ∧ r2 = .Ok c2 ∧
      http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref c1) ∧
      http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref c2)

/-- What a decision shows without its credential: the refusal, or the route
    and claims of a dispatch (not its bytes, which carry the credential). -/
inductive DecisionView where
  | unauthorized (rejection : Option stateless.Rejection)
  | refused (code : proxy_http.refusal.Code)
  | dispatch (index : Usize) (claims : stateless.SurrogateClaims)

def Decision.view : Decision → DecisionView
  | .unauthorized r => .unauthorized r
  | .refused code => .refused code
  | .dispatch index _ opened => .dispatch index opened.claims

/-- **The decision does not depend on the credential.** Two proxies whose
    openers differ only in the credential they unseal make the same decision
    for the same request — the same refusal, or a dispatch to the same route
    for the same claims; only the dispatched bytes differ, by the
    credential they carry. -/
theorem decide_declassified {ops1 ops2 : stateless.SurrogateOpener V} {pol : stateless_policy.OperationPolicy P}
    {opener : V} {policy : P} (same : SameButCredential ops1 ops2 opener)
    {request : proxy_http.request.Request} {routes : Slice Route} {a : stateless.Acceptance} {peer : Slice U8}
    {now : I64} {d1 d2 : Decision}
    (h1 : decide_request ops1 pol opener policy request routes a peer now = Result.ok d1)
    (h2 : decide_request ops2 pol opener policy request routes a peer now = Result.ok d2) :
    d1.view = d2.view := by
  have auth : ∀ t, stateless.authenticate ops2 opener t a peer now = stateless.authenticate ops1 opener t a peer now := by
    intro t; simp [stateless.authenticate, same.1]
  unfold decide_request at h1 h2
  obtain ⟨c1, hc1, h1⟩ := bind_ok_inv h1
  obtain ⟨c2, hc2, h2⟩ := bind_ok_inv h2
  rw [← Result.ok_injective h1, ← Result.ok_injective h2]
  clear h1 h2
  unfold stateless_proxy.decide at hc1 hc2
  dsimp only at hc1 hc2
  obtain ⟨o, ho, hc1⟩ := bind_ok_inv hc1
  rw [ho] at hc2; simp only [bind_ok] at hc2
  cases o with
  | none =>
    rw [← Result.ok_injective hc1, ← Result.ok_injective hc2]
  | some token =>
    dsimp only at hc1 hc2
    rw [auth] at hc2
    obtain ⟨r, hr, hc1⟩ := bind_ok_inv hc1
    rw [hr] at hc2; simp only [bind_ok] at hc2
    cases r with
    | Err e => rw [← Result.ok_injective hc1, ← Result.ok_injective hc2]
    | Ok v =>
      dsimp only at hc1 hc2
      obtain ⟨index, hi, hc1⟩ := bind_ok_inv hc1
      rw [hi] at hc2; simp only [bind_ok] at hc2
      split at hc1
      · rename_i out
        simp only [out, ↓reduceIte] at hc2
        rw [← Result.ok_injective hc1, ← Result.ok_injective hc2]
      · rename_i inside
        simp only [inside, ↓reduceIte] at hc2
        obtain ⟨op, hop, hc1⟩ := bind_ok_inv hc1
        rw [hop] at hc2; simp only [bind_ok] at hc2
        obtain ⟨b, hb, hc1⟩ := bind_ok_inv hc1
        rw [hb] at hc2; simp only [bind_ok] at hc2
        cases b
        · simp only [Bool.false_eq_true, ↓reduceIte] at hc1 hc2
          rw [← Result.ok_injective hc1, ← Result.ok_injective hc2]
        simp only [↓reduceIte] at hc1 hc2
        obtain ⟨r1, hd1, hc1⟩ := bind_ok_inv hc1
        obtain ⟨r2, hd2, hc2⟩ := bind_ok_inv hc2
        unfold stateless.decrypt at hd1 hd2
        obtain ⟨u1, hu1, hd1⟩ := bind_ok_inv hd1
        obtain ⟨u2, hu2, hd2⟩ := bind_ok_inv hd2
        rcases same.2 v u1 u2 hu1 hu2 with eu | ⟨k1, k2, e1, e2, valid1, valid2⟩
        · subst eu
          rw [hd1] at hd2
          have er := Result.ok_injective hd2
          subst er
          cases r1 with
          | Err e => rw [← Result.ok_injective hc1, ← Result.ok_injective hc2]
          | Ok opened =>
            dsimp only at hc1 hc2
            obtain ⟨route, hroute, hc1⟩ := bind_ok_inv hc1
            rw [hroute] at hc2; simp only [bind_ok] at hc2
            obtain ⟨enc, henc, hc1⟩ := bind_ok_inv hc1
            rw [henc] at hc2; simp only [bind_ok] at hc2
            rw [hc1] at hc2
            rw [Result.ok_injective hc2]
        · subst e1 e2
          have yes : ∀ {k : alloc.vec.Vec U8}, http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref k) →
              http_auth.valid_credential (alloc.vec.Vec.deref k) = Result.ok true := by
            intro k valid
            obtain ⟨accepted, checked, equivalent⟩ :=
              returned_of_spec (http_auth.Proofs.valid_credential_contract (alloc.vec.Vec.deref k))
            rw [checked, equivalent.mpr valid]
          simp only [yes valid1, yes valid2, bind_ok, ↓reduceIte] at hd1 hd2
          rw [← Result.ok_injective hd1] at hc1
          rw [← Result.ok_injective hd2] at hc2
          dsimp only at hc1 hc2
          obtain ⟨route, hroute, hc1⟩ := bind_ok_inv hc1
          rw [hroute] at hc2; simp only [bind_ok] at hc2
          obtain ⟨⟨q1, w1⟩, he1, hc1⟩ := bind_ok_inv hc1
          obtain ⟨⟨q2, w2⟩, he2, hc2⟩ := bind_ok_inv hc2
          have verdict := proxy_http.Proofs.encode_upstream_verdict valid1 valid2 he1 he2
          simp only at verdict
          subst verdict
          simp only [Aeneas.Std.uncurry_apply_pair] at hc1 hc2
          cases q1 with
          | Ok u =>
            rw [← Result.ok_injective hc1, ← Result.ok_injective hc2]
            rfl
          | Err refusal =>
            obtain ⟨code, hcode, hc1⟩ := bind_ok_inv hc1
            obtain ⟨code', hcode', hc2⟩ := bind_ok_inv hc2
            rw [hcode] at hcode'
            obtain rfl := Result.ok_injective hcode'

            rw [← Result.ok_injective hc1, ← Result.ok_injective hc2]
/-- The fixed refusal of a provider answer that reflected the credential. -/
def ReflectionRefusal (served : proxy_controller.Served) : Prop :=
  proxy_controller.stopped .Reflected .Failed = Result.ok served

/-- **The reply depends on the credential only through the reflection
    verdict.** For two decisions that look alike without their credentials,
    and the same answers from the network, the replies are equal, unless one
    of them is the fixed reflection refusal. -/
theorem reply_declassified {request : proxy_http.request.Request} {limit : Usize} {d1 d2 : Decision}
    {ans : Answered} {s1 s2 : proxy_controller.Served} (view : d1.view = d2.view)
    (h1 : reply request limit d1 ans = Result.ok s1) (h2 : reply request limit d2 ans = Result.ok s2) :
    s1 = s2 ∨ ReflectionRefusal s1 ∨ ReflectionRefusal s2 := by
  have same : ∀ {x : Result proxy_controller.Served}, x = Result.ok s1 → x = Result.ok s2 → s1 = s2 := by
    intro x e1 e2; rw [e1] at e2; exact Result.ok_injective e2
  cases d1 <;> cases d2 <;> simp only [Decision.view, reduceCtorEq, DecisionView.unauthorized.injEq,
    DecisionView.refused.injEq, DecisionView.dispatch.injEq] at view
  · subst view; exact Or.inl (same h1 h2)
  · subst view; exact Or.inl (same h1 h2)
  · rename_i index wire opened index' wire' opened'
    obtain ⟨ei, ec⟩ := view
    subst ei
    cases ans with
    | none => exact Or.inl (same h1 h2)
    | unadmitted => exact Or.inl (same h1 h2)
    | exchanged answer done =>
      simp only [reply] at h1 h2
      obtain ⟨f1, hf1, h1⟩ := bind_ok_inv h1
      obtain ⟨f2, hf2, h2⟩ := bind_ok_inv h2
      cases answer with
      | Err code => exact Or.inl (same h1 h2)
      | Ok raw =>
        dsimp only at h1 h2
        obtain ⟨r1, hr1, h1⟩ := bind_ok_inv h1
        obtain ⟨r2, hr2, h2⟩ := bind_ok_inv h2
        have failed : ∀ {r : proxy_controller.Served}, ReflectionRefusal r → r.stage = .Failed := by
          intro r stop
          exact (proxy_controller.Proofs.stopped_reply stop).2.1
        rcases proxy_controller.Proofs.release_declassified hr1 hr2 with e | stop | stop
        · subst e; exact Or.inl (same h1 h2)
        · refine Or.inr (Or.inl ?_)
          have st := failed stop
          split at h1
          · have c := ‹r1.stage = proxy_controller.Stage.Completed›
            rw [st] at c; cases c
          · rw [← Result.ok_injective h1]; exact stop
        · refine Or.inr (Or.inr ?_)
          have st := failed stop
          split at h2
          · have c := ‹r2.stage = proxy_controller.Stage.Completed›
            rw [st] at c; cases c
          · rw [← Result.ok_injective h2]; exact stop

/-- **What the agent receives does not depend on the credential, beyond
    what is declassified.** Run `serve` twice on the same request, peer,
    clock, routes and policies, with openers that differ only in the
    credential they unseal (`SameButCredential`), and any two origin
    adapters. Both runs make decisions that look alike without their
    credentials; and if the network answered both alike (admission,
    connection, write, the provider's answer and the completion record), the
    agent receives the same reply — unless exactly the provider's answer
    reflected one credential and not the other, when that run's reply is the
    fixed reflection refusal. -/
theorem serve_declassified {ops1 ops2 : stateless.SurrogateOpener V} {pol : stateless_policy.OperationPolicy P}
    {opener : V} {policy : P} (same : SameButCredential ops1 ops2 opener) {O1 O2 : Type}
    (inst1 : Origin O1) (io1 : O1) (inst2 : Origin O2) (io2 : O2)
    {request : proxy_http.request.Request} {routes : Slice Route} {a : stateless.Acceptance} {peer : Slice U8}
    {now : I64} {limit : Usize} {s1 s2 : proxy_controller.Served} {a1 : O1} {a2 : O2}
    (h1 : serve ops1 pol inst1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1))
    (h2 : serve ops2 pol inst2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2)) :
    ∃ d1 d2 ans1 ans2, decide_request ops1 pol opener policy request routes a peer now = Result.ok d1 ∧
      decide_request ops2 pol opener policy request routes a peer now = Result.ok d2 ∧ d1.view = d2.view ∧
      (d1.isDispatch = true → AnsweredBy inst1 io1 routes limit d1 ans1 a1) ∧
      (d2.isDispatch = true → AnsweredBy inst2 io2 routes limit d2 ans2 a2) ∧
      (ans1 = ans2 → s1 = s2 ∨ ReflectionRefusal s1 ∨ ReflectionRefusal s2) := by
  obtain ⟨d1, ans1, hd1, none1, by1, r1⟩ := serve_answered ops1 pol inst1 opener policy io1 request routes a peer
    now limit s1 a1 h1
  obtain ⟨d2, ans2, hd2, none2, by2, r2⟩ := serve_answered ops2 pol inst2 opener policy io2 request routes a peer
    now limit s2 a2 h2
  have view := decide_declassified same hd1 hd2
  refine ⟨d1, d2, ans1, ans2, hd1, hd2, view, by1, by2, fun e => ?_⟩
  subst e
  exact reply_declassified view r1 r2

end garrett_stateless_core.stateless_proxy.Proofs

namespace garrett_stateless_core.stateless_token.Proofs

set_option hygiene false in
/-- Step both runs through one bind that computes the same value. -/
local macro "shared" : tactic => `(tactic| (
  obtain ⟨x, hx, h1⟩ := bind_ok_inv h1
  rw [hx] at h2; simp only [bind_ok] at h2))

set_option hygiene false in
/-- Both runs take the same side of a shared test; the refusing side
    contradicts the issued token. -/
local macro "both" : tactic => `(tactic| (
  cases x <;> simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, reduceCtorEq] at h1 h2 ⊢))

/-- **A surrogate depends on its credential only through the ciphertext.**
    Two runs of the extracted `seal_token` with the same key entry,
    informational claims, claims and nonce, under primitives that sign alike,
    that both issue a token and whose AEAD `seal` returned the same
    ciphertext for their two credentials, issue the same token. Beyond the
    ciphertext, the credential reaches the token only through checks that
    refuse: it is valid, and it occurs in neither the header nor the public
    payload. -/
theorem seal_token_ciphertext_only {M : Type} {inst1 inst2 : keys.KeyMaterial M}
    (sign_same : inst1.sign = inst2.sign) {entry : keys.KeyEntry M} {info : payload.Informational}
    {claims : stateless.SurrogateClaims} {c1 c2 nonce : Slice U8} {t1 t2 : alloc.vec.Vec U8}
    (ciphertext : ∀ aad, inst1.«seal» entry.material nonce aad c1 = inst2.«seal» entry.material nonce aad c2)
    (h1 : sealing.seal_token inst1 entry info claims c1 nonce = Result.ok (.Ok t1))
    (h2 : sealing.seal_token inst2 entry info claims c2 nonce = Result.ok (.Ok t2)) : t1 = t2 := by
  unfold sealing.seal_token at h1 h2
  dsimp only at h1 h2
  obtain ⟨v1, hv1, h1⟩ := bind_ok_inv h1
  obtain ⟨v2, hv2, h2⟩ := bind_ok_inv h2
  cases v1 <;> cases v2 <;> simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, reduceCtorEq] at h1 h2
  shared; both
  split at h1
  · simp at h1
  · rename_i nonce_ok
    simp only [nonce_ok] at h2
    shared; shared; shared; shared; both
    shared
    obtain ⟨o1, ho1, h1⟩ := bind_ok_inv h1
    obtain ⟨o2, ho2, h2⟩ := bind_ok_inv h2
    cases o1 <;> cases o2 <;> simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, reduceCtorEq] at h1 h2
    obtain ⟨p1, hp1, h1⟩ := bind_ok_inv h1
    obtain ⟨p2, hp2, h2⟩ := bind_ok_inv h2
    cases p1 <;> cases p2 <;> simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, reduceCtorEq] at h1 h2
    shared
    rw [← ciphertext, ← sign_same] at h2
    rw [h1] at h2
    exact (core.result.Result.Ok.inj (Result.ok_injective h2))


/-- **An issued surrogate depends on its credential only through the
    ciphertext.** `stateless::issue` with two credentials, the same grant,
    policy, sealer and clock, both issuing, under primitives that sign alike
    and whose AEAD returned the same ciphertext for the two credentials:
    the same claims and the same surrogate. -/
theorem issue_ciphertext_only {M : Type} {inst1 inst2 : keys.KeyMaterial M} (sign_same : inst1.sign = inst2.sign)
    {sealer : sealing.TokenSealer M} {policy : stateless.IssuePolicy} {grant : stateless.Grant}
    {c1 c2 tid : Slice U8} {now lifetime : I64} {i1 i2 : stateless.Issued}
    (ciphertext : ∀ aad, inst1.«seal» sealer.entry.material (alloc.vec.Vec.deref sealer.nonce) aad c1 =
      inst2.«seal» sealer.entry.material (alloc.vec.Vec.deref sealer.nonce) aad c2)
    (h1 : stateless.issue (stateless_protocol.Sealing inst1) sealer policy grant c1 tid now lifetime =
      Result.ok (.Ok i1))
    (h2 : stateless.issue (stateless_protocol.Sealing inst2) sealer policy grant c2 tid now lifetime =
      Result.ok (.Ok i2)) : i1 = i2 := by
  unfold stateless.issue at h1 h2
  obtain ⟨v1, _, h1⟩ := bind_ok_inv h1
  obtain ⟨v2, _, h2⟩ := bind_ok_inv h2
  cases v1 <;> cases v2 <;> simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, reduceCtorEq] at h1 h2
  obtain ⟨r, hr, h1⟩ := bind_ok_inv h1
  rw [hr] at h2; simp only [bind_ok] at h2
  cases r with
  | Err e => simp at h1
  | Ok claims =>
    dsimp only at h1 h2
    obtain ⟨s1, hs1, h1⟩ := bind_ok_inv h1
    obtain ⟨s2, hs2, h2⟩ := bind_ok_inv h2
    cases s1 with
    | Err e => simp at h1
    | Ok t1 =>
      cases s2 with
      | Err e => simp at h2
      | Ok t2 =>
        have same := seal_token_ciphertext_only sign_same ciphertext
          (show sealing.seal_token inst1 sealer.entry sealer.info claims c1 (alloc.vec.Vec.deref sealer.nonce) =
            Result.ok (.Ok t1) from hs1)
          (show sealing.seal_token inst2 sealer.entry sealer.info claims c2 (alloc.vec.Vec.deref sealer.nonce) =
            Result.ok (.Ok t2) from hs2)
        subst same
        simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h1 h2
        rw [← h1, ← h2]

end garrett_stateless_core.stateless_token.Proofs
