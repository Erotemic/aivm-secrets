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
* **A whole connection** (`connection_declassified`). Two runs of the
  extracted connection loop, for every request on it, with an adaptive
  agent: the openers differ only in the credential, and the channels answer
  alike from related states (`ChannelsAgree`: the agent's bytes, deadlines
  and clock, and the network's answers, whatever credential-bearing bytes
  were written). The agent is sent the same byte strings — or the same up
  to one reply at which one run sent the fixed reflection refusal, after
  which the agent knows that bit and the runs may part
  (`DivergeAtReflection`). `channels_agree_self` shows the hypothesis is met
  by any channel whose provider side ignores the credential bytes.
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
trusted to pass only what the core returns, `STATELESS-NATIVE-01`), runs
that do not both return (the statements are termination-insensitive), and
the broker's issuance over a whole login (only one issuance is compared).
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


/-! ## Whole connections

`serve_declassified` compares one request. Here two runs of the extracted
`connection` loop, for every request of the connection, adaptively: the
agent's next bytes may depend on everything it has received so far. The two
runs differ in the credential their openers unseal (`SameButCredential`),
and their channels **agree** (`ChannelsAgree`): from related states, each
callback answers alike and leads to related states — the agent's reads and
deadlines and the clock alike, and the network's answers alike (the
admission and completion records, the connection, the write report and every
read of the provider's answer), whatever credential-bearing bytes were
written. That last clause is the declassification of the provider's answers:
the theorem says nothing about a provider whose answers depend on the
credential. -/

section connection
variable {C1 C2 : Type}

/-- Two callbacks agree from related states: the same answer, and related
    states after. -/
def Agree {α : Type} (R : C1 → C2 → Prop) (f1 : C1 → Result (α × C1)) (f2 : C2 → Result (α × C2)) : Prop :=
  ∀ s1 s2 x1 x2, R s1 s2 → f1 s1 = Result.ok x1 → f2 s2 = Result.ok x2 → x1.1 = x2.1 ∧ R x1.2 x2.2

/-- Two answerless callbacks keep related states related. -/
def Keeps (R : C1 → C2 → Prop) (f1 : C1 → Result C1) (f2 : C2 → Result C2) : Prop :=
  ∀ s1 s2 t1 t2, R s1 s2 → f1 s1 = Result.ok t1 → f2 s2 = Result.ok t2 → R t1 t2

/-- **Two origin adapters that answer alike.** In particular `transmit`
    answers alike for two egresses to the same destination whatever bytes
    they carry: the provider's behaviour does not depend on the credential
    (the declassification of its answers). -/
structure OriginsAgree (R : C1 → C2 → Prop) (o1 : Origin C1) (o2 : Origin C2) : Prop where
  rejected : ∀ r, Keeps R (o1.rejected · r) (o2.rejected · r)
  admitted : ∀ claims index, Agree R (o1.admitted · claims index) (o2.admitted · claims index)
  connect : ∀ D, Agree R (o1.connect · D) (o2.connect · D)
  transmit : ∀ e1 e2 : Egress, e1.destination = e2.destination → Agree R (o1.transmit · e1) (o2.transmit · e2)
  receive : Agree R o1.receive o2.receive
  completed : ∀ status, Agree R (o1.completed · status) (o2.completed · status)

/-- **Two channels that answer alike**: the origins, and the agent's side —
    its reads, the deadlines and the clock alike, and a write of the same
    bytes to it answered alike. -/
structure ChannelsAgree (R : C1 → C2 → Prop) (ch1 : Channel C1) (ch2 : Channel C2) : Prop where
  origin : OriginsAgree R ch1.OriginInst ch2.OriginInst
  overdue : Agree R ch1.overdue ch2.overdue
  read : Agree R ch1.read ch2.read
  send : ∀ bytes, Agree R (ch1.send · bytes) (ch2.send · bytes)
  refused : ∀ code, Keeps R (ch1.refused · code) (ch2.refused · code)
  stopped : ∀ code, Keeps R (ch1.stopped · code) (ch2.stopped · code)
  begin : ∀ request, Agree R (ch1.begin · request) (ch2.begin · request)
  restart : Keeps R ch1.restart ch2.restart

unseal Result in
theorem returns_mono {α : Type} {m : Result α} {Q₁ Q₂ : α → Prop} (r : Returns m Q₁) (h : ∀ v, Q₁ v → Q₂ v) :
    Returns m Q₂ := by
  unfold Returns at r ⊢
  exact Data.Coinductive.DWLP.mono r (fun v _ q => h v q)

/-- What `collect_loop` does after one read. -/
def collectRest {O : Type} (o : Origin O) (bound : Usize) (answer : alloc.vec.Vec U8) (x : Received) (t : O) :
    Result (Collected O) :=
  match x with
  | .Bytes bytes => do
    let grown ← alloc.vec.Vec.extend_from_slice core.clone.CloneU8 answer (alloc.vec.Vec.deref bytes)
    if alloc.vec.Vec.len grown > bound then Result.ok (core.result.Result.Err .TooLarge, t)
    else collect_loop o t bound grown
  | .End => Result.ok (core.result.Result.Ok answer, t)
  | .Failed => Result.ok (core.result.Result.Err .OutcomeUnknown, t)

theorem collect_loop_unfold {O : Type} (o : Origin O) (s : O) (bound : Usize) (answer : alloc.vec.Vec U8) :
    collect_loop o s bound answer = Std.bind (o.receive s) fun r => collectRest o bound answer r.1 r.2 := by
  rw [collect_loop]
  rfl

/-- The second run's first read answers alike, from related states. -/
theorem collect_second {R : C1 → C2 → Prop} {o1 : Origin C1} {o2 : Origin C2} (rcv : Agree R o1.receive o2.receive)
    {s1 : C1} {s2 : C2} (r : R s1 s2) {x : Received} {t1 : C1} (hr1 : o1.receive s1 = Result.ok (x, t1))
    {bound : Usize} {answer : alloc.vec.Vec U8} {r2 : Collected C2}
    (h2 : collect_loop o2 s2 bound answer = Result.ok r2) :
    ∃ t2, R t1 t2 ∧ collectRest o2 bound answer x t2 = Result.ok r2 := by
  rw [collect_loop_unfold] at h2
  obtain ⟨⟨x2, t2⟩, hr2, h2⟩ := bind_ok_inv h2
  obtain ⟨ex, rt⟩ := rcv s1 s2 _ _ r hr1 hr2
  simp only at ex rt
  subst ex
  exact ⟨t2, rt, h2⟩

theorem agree_self {C α : Type} (f : C → Result (α × C)) : Agree (fun s1 s2 : C => s1 = s2) f f := by
  intro s1 s2 x1 x2 e h1 h2
  subst e
  rw [h1] at h2
  obtain rfl := Result.ok_injective h2
  exact ⟨rfl, rfl⟩

theorem keeps_self {C : Type} (f : C → Result C) : Keeps (fun s1 s2 : C => s1 = s2) f f := by
  intro s1 s2 t1 t2 e h1 h2
  subst e
  rw [h1] at h2
  exact Result.ok_injective h2

/-- **The hypothesis is satisfiable.** A channel agrees with itself, state
    for state, whenever its provider side answers a write the same way for
    any two egresses to one destination — whatever credential they carry. -/
theorem channels_agree_self {C : Type} (ch : Channel C)
    (blind : ∀ s (e1 e2 : Egress), e1.destination = e2.destination →
      ch.OriginInst.transmit s e1 = ch.OriginInst.transmit s e2) :
    ChannelsAgree (fun s1 s2 : C => s1 = s2) ch ch where
  origin :=
    { rejected := fun r => keeps_self _
      admitted := fun claims index => agree_self _
      connect := fun D => agree_self _
      transmit := fun e1 e2 dest => by
        intro s1 s2 x1 x2 e h1 h2
        subst e
        simp only at h1 h2
        rw [blind s1 e1 e2 dest, h2] at h1
        obtain rfl := Result.ok_injective h1
        exact ⟨rfl, rfl⟩
      receive := agree_self _
      completed := fun status => agree_self _ }
  overdue := agree_self _
  read := agree_self _
  send := fun bytes => agree_self _
  refused := fun code => keeps_self _
  stopped := fun code => keeps_self _
  begin := fun request => agree_self _
  restart := keeps_self _

/-- Reading two answers alike gives the same answer. -/
theorem collect_loop_agree {R : C1 → C2 → Prop} {o1 : Origin C1} {o2 : Origin C2} (rcv : Agree R o1.receive o2.receive)
    (bound : Usize) (s1 : C1) (answer : alloc.vec.Vec U8) :
    Returns (collect_loop o1 s1 bound answer) (fun r1 => ∀ s2 r2, R s1 s2 →
      collect_loop o2 s2 bound answer = Result.ok r2 → r1.1 = r2.1 ∧ R r1.2 r2.2) := by
  revert s1 answer
  refine collect_loop.fixpoint_induct o1 bound
    (fun f => ∀ s1 answer, Returns (f s1 answer) (fun r1 => ∀ s2 r2, R s1 s2 →
      collect_loop o2 s2 bound answer = Result.ok r2 → r1.1 = r2.1 ∧ R r1.2 r2.2)) ?_ ?_
  · apply Lean.Order.admissible_pi; intro s1
    apply Lean.Order.admissible_pi; intro answer
    exact Lean.Order.admissible_apply (β := fun _ => alloc.vec.Vec U8 → Result (Collected C1))
      (fun _ (g : alloc.vec.Vec U8 → Result (Collected C1)) => Returns (g answer) (fun r1 => ∀ s2 r2, R s1 s2 →
        collect_loop o2 s2 bound answer = Result.ok r2 → r1.1 = r2.1 ∧ R r1.2 r2.2)) s1
      (returns_admissible answer _)
  · intro f ih s1 answer
    apply returns_bind (Q₁ := fun r => o1.receive s1 = Result.ok r) (returns_of_ok fun v h => h)
    rintro ⟨x, t1⟩ hr1
    simp only [Aeneas.Std.uncurry_apply_pair]
    cases x with
    | Bytes bytes =>
      apply returns_bind (Q₁ := fun g => alloc.vec.Vec.extend_from_slice core.clone.CloneU8 answer
        (alloc.vec.Vec.deref bytes) = Result.ok g) (returns_of_ok fun v h => h)
      intro grown hg
      split
      · rename_i over
        refine returns_of_ok fun v hv => ?_
        intro s2 r2 r h2
        obtain ⟨t2, rt, h2⟩ := collect_second rcv r hr1 h2
        simp only [collectRest, hg, bind_ok, over, ↓reduceIte, Result.ok.injEq] at h2 hv
        subst h2 hv
        exact ⟨rfl, rt⟩
      · rename_i under
        refine returns_mono (ih t1 grown) fun v q s2 r2 r h2 => ?_
        obtain ⟨t2, rt, h2⟩ := collect_second rcv r hr1 h2
        simp only [collectRest, hg, bind_ok, under, ↓reduceIte] at h2
        exact q t2 r2 rt h2
    | End =>
      refine returns_of_ok fun v hv => ?_
      intro s2 r2 r h2
      obtain ⟨t2, rt, h2⟩ := collect_second rcv r hr1 h2
      simp only [collectRest, Result.ok.injEq] at h2 hv
      subst h2 hv
      exact ⟨rfl, rt⟩
    | Failed =>
      refine returns_of_ok fun v hv => ?_
      intro s2 r2 r h2
      obtain ⟨t2, rt, h2⟩ := collect_second rcv r hr1 h2
      simp only [collectRest, Result.ok.injEq] at h2 hv
      subst h2 hv
      exact ⟨rfl, rt⟩

/-- **One exchange, twice.** Two egresses to the same destination, carrying
    any bytes, exchanged with agreeing origins: the same answer, related
    states. -/
theorem exchange_agree {R : C1 → C2 → Prop} {o1 : Origin C1} {o2 : Origin C2} (agree : OriginsAgree R o1 o2)
    {s1 : C1} {s2 : C2} (r : R s1 s2) {e1 e2 : Egress} (dest : e1.destination = e2.destination) {limit : Usize}
    {x1 x2} (h1 : exchange o1 s1 e1 limit = Result.ok x1) (h2 : exchange o2 s2 e2 limit = Result.ok x2) :
    x1.1 = x2.1 ∧ R x1.2 x2.2 := by
  unfold exchange at h1 h2
  simp only [egress_destination, bind_ok] at h1 h2
  obtain ⟨⟨b1, t1⟩, hc1, h1⟩ := bind_ok_inv h1
  obtain ⟨⟨b2, t2⟩, hc2, h2⟩ := bind_ok_inv h2
  rw [dest] at hc1
  obtain ⟨eb, rt⟩ := agree.connect _ s1 s2 _ _ r hc1 hc2
  simp only at eb rt
  subst eb
  simp only [Aeneas.Std.uncurry_apply_pair] at h1 h2
  cases b1 with
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte] at h1 h2
    rw [← Result.ok_injective h1, ← Result.ok_injective h2]
    exact ⟨rfl, rt⟩
  | true =>
    simp only [↓reduceIte] at h1 h2
    obtain ⟨⟨w1, u1⟩, ht1, h1⟩ := bind_ok_inv h1
    obtain ⟨⟨w2, u2⟩, ht2, h2⟩ := bind_ok_inv h2
    obtain ⟨ew, ru⟩ := agree.transmit e1 e2 dest t1 t2 _ _ rt ht1 ht2
    simp only at ew ru
    subst ew
    simp only [Aeneas.Std.uncurry_apply_pair] at h1 h2
    cases w1 with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h1 h2
      rw [← Result.ok_injective h1, ← Result.ok_injective h2]
      exact ⟨rfl, ru⟩
    | true =>
      simp only [↓reduceIte] at h1 h2
      obtain ⟨bound, hb, h1⟩ := bind_ok_inv h1
      rw [hb] at h2; simp only [bind_ok] at h2
      exact returns_ok (collect_loop_agree agree.receive bound u1 _) h1 u2 x2 ru h2

/-- **One request, twice.** Two runs of `serve` on the same request with
    openers that differ only in the credential and agreeing origins: the
    same reply and related states, unless the provider's answer reflected
    one credential and not the other, when that run's reply is the fixed
    reflection refusal. -/
theorem serve_agree {ops1 ops2 : stateless.SurrogateOpener V} {pol : stateless_policy.OperationPolicy P}
    {opener : V} {policy : P} (same : SameButCredential ops1 ops2 opener) {R : C1 → C2 → Prop}
    {o1 : Origin C1} {o2 : Origin C2} (agree : OriginsAgree R o1 o2) {io1 : C1} {io2 : C2} (r : R io1 io2)
    {request : proxy_http.request.Request} {routes : Slice Route} {a : stateless.Acceptance} {peer : Slice U8}
    {now : I64} {limit : Usize} {s1 s2 : proxy_controller.Served} {a1 : C1} {a2 : C2}
    (h1 : serve ops1 pol o1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1))
    (h2 : serve ops2 pol o2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2)) :
    (s1 = s2 ∧ R a1 a2) ∨ ReflectionRefusal s1 ∨ ReflectionRefusal s2 := by
  obtain ⟨d1, hd1, m1⟩ := serve_follows_decision ops1 pol o1 opener policy io1 request routes a peer now limit s1 a1 h1
  obtain ⟨d2, hd2, m2⟩ := serve_follows_decision ops2 pol o2 opener policy io2 request routes a peer now limit s2 a2 h2
  have view := decide_declassified same hd1 hd2
  have eq : ∀ {x : Result proxy_controller.Served} {u v : proxy_controller.Served}, x = Result.ok u →
      x = Result.ok v → u = v := fun e1 e2 => by rw [e1] at e2; exact Result.ok_injective e2
  cases d1 <;> cases d2 <;> simp only [Decision.view, reduceCtorEq, DecisionView.unauthorized.injEq,
    DecisionView.refused.injEq, DecisionView.dispatch.injEq] at view
  · subst view
    obtain ⟨u1, rj1⟩ := m1
    obtain ⟨u2, rj2⟩ := m2
    exact Or.inl ⟨eq u1 u2, agree.rejected _ _ _ _ _ r rj1 rj2⟩
  · subst view
    obtain ⟨u1, e1⟩ := m1
    obtain ⟨u2, e2⟩ := m2
    subst e1 e2
    exact Or.inl ⟨eq u1 u2, r⟩
  · rename_i index wire1 opened1 index' wire2 opened2
    obtain ⟨ei, ec⟩ := view
    subst ei
    rcases m1 with ⟨ad1, st1⟩ | ⟨j1, forms1, ans1, k1, ad1, _, ⟨in1, ex1⟩, rest1⟩ <;>
    rcases m2 with ⟨ad2, st2⟩ | ⟨j2, forms2, ans2, k2, ad2, _, ⟨in2, ex2⟩, rest2⟩ <;>
    rw [ec] at ad1 <;>
    obtain ⟨eb, rj⟩ := agree.admitted _ _ _ _ _ _ r ad1 ad2 <;>
    simp only [Bool.false_eq_true, Bool.true_eq_false] at eb rj
    · exact Or.inl ⟨eq st1 st2, rj⟩
    · obtain ⟨ea, rk⟩ := exchange_agree agree rj (e1 := egressTo routes index in1 wire1)
        (e2 := egressTo routes index in2 wire2) rfl ex1 ex2
      simp only at ea rk
      subst ea
      cases ans1 with
      | Err code =>
        obtain ⟨u1, e1⟩ := rest1
        obtain ⟨u2, e2⟩ := rest2
        subst e1 e2
        exact Or.inl ⟨eq u1 u2, rk⟩
      | Ok raw =>
        obtain ⟨rel1, hr1, c1⟩ := rest1
        obtain ⟨rel2, hr2, c2⟩ := rest2
        have failed : ∀ {s : proxy_controller.Served}, ReflectionRefusal s → s.stage = .Failed :=
          fun stop => (proxy_controller.Proofs.stopped_reply stop).2.1
        rcases proxy_controller.Proofs.release_declassified hr1 hr2 with e | stop | stop
        · subst e
          rcases c1 with ⟨n1, e1, f1⟩ | ⟨y1, b1, comp1, k1'⟩ <;>
          rcases c2 with ⟨n2, e2, f2⟩ | ⟨y2, b2, comp2, k2'⟩
          · subst e1 e2 f1 f2
            exact Or.inl ⟨rfl, rk⟩
          · exact absurd y2 n1
          · exact absurd y1 n2
          · obtain ⟨ebb, ra⟩ := agree.completed _ _ _ _ _ rk comp1 comp2
            simp only at ebb ra
            subst ebb
            refine Or.inl ⟨?_, ra⟩
            rcases k1' with ⟨_, e1⟩ | ⟨_, e1⟩ <;> rcases k2' with ⟨_, e2⟩ | ⟨_, e2⟩ <;> simp_all
        · refine Or.inr (Or.inl ?_)
          rcases c1 with ⟨_, e1, _⟩ | ⟨y1, _⟩
          · rw [e1]; exact stop
          · rw [failed stop] at y1; cases y1
        · refine Or.inr (Or.inr ?_)
          rcases c2 with ⟨_, e2, _⟩ | ⟨y2, _⟩
          · rw [e2]; exact stop
          · rw [failed stop] at y2; cases y2

/-- The bytes a log shows the agent. -/
def ProxyEvent.toAgent : ProxyEvent → Option (List U8)
  | .guestSent bytes => some bytes
  | _ => none

/-- **What the agent observes** of a logged connection: the byte strings it
    was sent, in order. -/
def agentView (log : List ProxyEvent) : List (List U8) := log.filterMap ProxyEvent.toAgent

theorem agentView_append (L1 L2 : List ProxyEvent) : agentView (L1 ++ L2) = agentView L1 ++ agentView L2 :=
  List.filterMap_append

/-- Related channel states whose logs showed the agent the same bytes. -/
def Seen (R : C1 → C2 → Prop) (x1 : C1 × List ProxyEvent) (x2 : C2 × List ProxyEvent) : Prop :=
  R x1.1 x2.1 ∧ agentView x1.2 = agentView x2.2

theorem agree_logged {α : Type} {R : C1 → C2 → Prop} {f1 : C1 → Result (α × C1)} {f2 : C2 → Result (α × C2)}
    (ag : Agree R f1 f2) (u1 u2 : List ProxyEvent → α → List ProxyEvent)
    (quiet : ∀ L1 L2 x, agentView L1 = agentView L2 → agentView (u1 L1 x) = agentView (u2 L2 x))
    {g1 : C1 × List ProxyEvent → Result (α × (C1 × List ProxyEvent))}
    {g2 : C2 × List ProxyEvent → Result (α × (C2 × List ProxyEvent))}
    (e1 : ∀ s, g1 s = Std.bind (f1 s.1) fun r => Result.ok (r.1, (r.2, u1 s.2 r.1)))
    (e2 : ∀ s, g2 s = Std.bind (f2 s.1) fun r => Result.ok (r.1, (r.2, u2 s.2 r.1))) :
    Agree (Seen R) g1 g2 := by
  rintro ⟨s1, L1⟩ ⟨s2, L2⟩ x1 x2 ⟨r, g⟩ h1 h2
  rw [e1] at h1
  rw [e2] at h2
  obtain ⟨y1, hy1, e1⟩ := bind_ok_inv h1
  obtain ⟨y2, hy2, e2⟩ := bind_ok_inv h2
  obtain ⟨ey, ry⟩ := ag s1 s2 y1 y2 r hy1 hy2
  rw [← Result.ok_injective e1, ← Result.ok_injective e2]
  refine ⟨ey, ry, ?_⟩
  rw [ey]
  exact quiet L1 L2 y2.1 g

theorem keeps_logged {R : C1 → C2 → Prop} {f1 : C1 → Result C1} {f2 : C2 → Result C2} (kp : Keeps R f1 f2)
    (u1 u2 : List ProxyEvent → List ProxyEvent) (quiet : ∀ L1 L2, agentView L1 = agentView L2 →
      agentView (u1 L1) = agentView (u2 L2))
    {g1 : C1 × List ProxyEvent → Result (C1 × List ProxyEvent)}
    {g2 : C2 × List ProxyEvent → Result (C2 × List ProxyEvent)}
    (e1 : ∀ s, g1 s = Std.bind (f1 s.1) fun c => Result.ok (c, u1 s.2))
    (e2 : ∀ s, g2 s = Std.bind (f2 s.1) fun c => Result.ok (c, u2 s.2)) :
    Keeps (Seen R) g1 g2 := by
  rintro ⟨s1, L1⟩ ⟨s2, L2⟩ t1 t2 ⟨r, g⟩ h1 h2
  rw [e1] at h1
  rw [e2] at h2
  obtain ⟨y1, hy1, e1⟩ := bind_ok_inv h1
  obtain ⟨y2, hy2, e2⟩ := bind_ok_inv h2
  rw [← Result.ok_injective e1, ← Result.ok_injective e2]
  exact ⟨kp s1 s2 y1 y2 r hy1 hy2, quiet L1 L2 g⟩

/-- A record the agent does not see. -/
theorem quiet_append {L1 L2 : List ProxyEvent} (g : agentView L1 = agentView L2) {e1 e2 : ProxyEvent}
    (q1 : e1.toAgent = none) (q2 : e2.toAgent = none) : agentView (L1 ++ [e1]) = agentView (L2 ++ [e2]) := by
  simp only [agentView_append, g]
  simp [agentView, q1, q2]

/-- **Logging keeps channels agreeing**, and records the same bytes to the
    agent. -/
theorem logged_agree {R : C1 → C2 → Prop} {ch1 : Channel C1} {ch2 : Channel C2} (agree : ChannelsAgree R ch1 ch2) :
    ChannelsAgree (Seen R) (logged ch1) (logged ch2) where
  origin :=
    { rejected := fun rj => keeps_logged (agree.origin.rejected rj) (· ++ [.rejected rj]) (· ++ [.rejected rj])
        (fun _ _ g => quiet_append g rfl rfl) (fun _ => rfl) (fun _ => rfl)
      admitted := fun claims index => agree_logged (agree.origin.admitted claims index)
        (fun L x => L ++ [.admitted claims index x]) (fun L x => L ++ [.admitted claims index x])
        (fun _ _ _ g => quiet_append g rfl rfl) (fun _ => rfl) (fun _ => rfl)
      connect := fun D => agree_logged (agree.origin.connect D) (fun L x => L ++ [.connected D x])
        (fun L x => L ++ [.connected D x]) (fun _ _ _ g => quiet_append g rfl rfl) (fun _ => rfl) (fun _ => rfl)
      transmit := fun e1 e2 dest => agree_logged (agree.origin.transmit e1 e2 dest)
        (fun L x => L ++ [.attempted e1.destination e1.wire x]) (fun L x => L ++ [.attempted e2.destination e2.wire x])
        (fun _ _ _ g => quiet_append g rfl rfl) (fun _ => rfl) (fun _ => rfl)
      receive := agree_logged agree.origin.receive (fun L _ => L) (fun L _ => L) (fun _ _ _ g => g)
        (fun _ => rfl) (fun _ => rfl)
      completed := fun status => agree_logged (agree.origin.completed status) (fun L x => L ++ [.completed status x])
        (fun L x => L ++ [.completed status x]) (fun _ _ _ g => quiet_append g rfl rfl) (fun _ => rfl)
        (fun _ => rfl) }
  overdue := agree_logged agree.overdue (fun L _ => L) (fun L _ => L) (fun _ _ _ g => g) (fun _ => rfl) (fun _ => rfl)
  read := agree_logged agree.read (fun L _ => L) (fun L _ => L) (fun _ _ _ g => g) (fun _ => rfl) (fun _ => rfl)
  send := fun bytes => agree_logged (agree.send bytes) (fun L _ => L ++ [.guestSent bytes.val])
    (fun L _ => L ++ [.guestSent bytes.val]) (fun _ _ _ g => by
      simp only [agentView_append, g]) (fun _ => rfl) (fun _ => rfl)
  refused := fun code => keeps_logged (agree.refused code) (· ++ [.refused code]) (· ++ [.refused code])
    (fun _ _ g => quiet_append g rfl rfl) (fun _ => rfl) (fun _ => rfl)
  stopped := fun code => keeps_logged (agree.stopped code) (· ++ [.stopped code]) (· ++ [.stopped code])
    (fun _ _ g => quiet_append g rfl rfl) (fun _ => rfl) (fun _ => rfl)
  begin := fun request => agree_logged (agree.begin request) (fun L _ => L ++ [.began request])
    (fun L _ => L ++ [.began request]) (fun _ _ _ g => quiet_append g rfl rfl) (fun _ => rfl) (fun _ => rfl)
  restart := keeps_logged agree.restart (fun L => L) (fun L => L) (fun _ _ g => g) (fun _ => rfl) (fun _ => rfl)

end connection

section run
variable {C C1 C2 : Type} {ops ops1 ops2 : stateless.SurrogateOpener V} {pol : stateless_policy.OperationPolicy P}
  {opener : V} {policy : P} {routes : Slice Route} {a : stateless.Acceptance} {authority peer : Slice U8}
  {limit : Usize}

/-- A byte string that is the fixed reflection refusal. -/
def Reflected (bytes : List U8) : Prop := ∃ s, ReflectionRefusal s ∧ bytes = s.reply.val

/-- Two agent views that are equal up to a reply at which one run sent the
    fixed reflection refusal; after it, the agent knows that bit and the runs
    may go apart. -/
def DivergeAtReflection (g1 g2 : List (List U8)) : Prop :=
  ∃ P b1 b2 X1 X2, g1 = P ++ b1 :: X1 ∧ g2 = P ++ b2 :: X2 ∧ (Reflected b1 ∨ Reflected b2)

/-- A request's log shows the agent nothing. -/
theorem serveLog_quiet {d : Decision} {E : List ProxyEvent} (slog : ServeLog routes d E) : agentView E = [] := by
  cases d with
  | unauthorized r => rw [slog]; rfl
  | refused c => rw [slog]; rfl
  | dispatch index wire opened =>
    rcases slog with e | ⟨_, _, e | e | e | ⟨_, _, e⟩⟩ <;> subst e <;> rfl

/-- What a served request adds to what the agent sees: exactly its reply. -/
theorem request_view (ch : Channel C) {x j k m n y : C × List ProxyEvent} {request : proxy_http.request.Request}
    {now : I64} {served : proxy_controller.Served} {sent : Bool}
    (bg : (logged ch).begin x request = Result.ok (now, j))
    (sv : serve ops pol (logged ch).OriginInst opener policy j request routes a peer now limit = Result.ok (served, k))
    (st : (served.stage = .Completed ∧ m = k) ∨
      (served.stage ≠ .Completed ∧ (logged ch).stopped k served.code = Result.ok m))
    (rs : (logged ch).restart m = Result.ok n)
    (sd : (logged ch).send n (alloc.vec.Vec.deref served.reply) = Result.ok (sent, y)) :
    agentView y.2 = agentView x.2 ++ [served.reply.val] := by
  obtain ⟨r1, _, e1⟩ := ok_map_inv bg
  have ej : j.2 = x.2 ++ [.began request] := by rw [(Prod.mk.inj e1).2]
  obtain ⟨d, E, _, lk, slog⟩ := serve_logged ops pol opener policy routes a peer limit ch.OriginInst j.1 j.2 request now
    served k sv
  obtain ⟨r4, _, e4⟩ := ok_map_inv rs
  have en : n.2 = m.2 := by rw [e4]
  obtain ⟨r5, _, e5⟩ := ok_map_inv sd
  have ey : y.2 = n.2 ++ [.guestSent (alloc.vec.Vec.deref served.reply).val] := by rw [(Prod.mk.inj e5).2]
  have vm : agentView m.2 = agentView k.2 := by
    rcases st with ⟨_, e⟩ | ⟨_, h⟩
    · rw [e]
    · obtain ⟨r3, _, e3⟩ := ok_map_inv h
      rw [e3]; simp [agentView, ProxyEvent.toAgent]
  rw [ey, agentView_append, en, vm, lk, agentView_append, serveLog_quiet slog, ej, agentView_append]
  simp [agentView, ProxyEvent.toAgent, vec_deref_val]

/-- **One step, twice**, past the deadline check. -/
theorem stepped_agree (same : SameButCredential ops1 ops2 opener) {R : C1 → C2 → Prop} {ch1 : Channel C1}
    {ch2 : Channel C2} (agree : ChannelsAgree R ch1 ch2) {x1 : C1 × List ProxyEvent} {x2 : C2 × List ProxyEvent}
    (r : Seen R x1 x2) {buffer : alloc.vec.Vec U8} {out1 out2 : proxy_controller.Tunnel} {y1 y2}
    (h1 : Stepped ops1 pol (logged ch1) opener policy routes a authority peer limit x1 buffer out1 y1)
    (h2 : Stepped ops2 pol (logged ch2) opener policy routes a authority peer limit x2 buffer out2 y2) :
    (out1 = out2 ∧ Seen R y1 y2) ∨ ∃ b1 b2, agentView y1.2 = agentView x1.2 ++ [b1] ∧
      agentView y2.2 = agentView x1.2 ++ [b2] ∧ (Reflected b1 ∨ Reflected b2) := by
  have lagree := logged_agree agree
  obtain ⟨f1, fr1, h1⟩ := h1
  obtain ⟨f2, fr2, h2⟩ := h2
  rw [fr1] at fr2
  obtain rfl := Result.ok_injective fr2
  cases f1 with
  | Refuse code =>
    obtain ⟨i1, bytes1, sent1, rf1, rb1, sd1, ob1, oo1⟩ := h1
    obtain ⟨i2, bytes2, sent2, rf2, rb2, sd2, ob2, oo2⟩ := h2
    rw [rb1] at rb2
    obtain rfl := Result.ok_injective rb2
    have ri := lagree.refused code x1 x2 i1 i2 r rf1 rf2
    obtain ⟨_, ry⟩ := lagree.send _ i1 i2 _ _ ri sd1 sd2
    refine Or.inl ⟨?_, ry⟩
    cases out1; cases out2; simp_all
  | More =>
    obtain ⟨g1, rd1, k1⟩ := h1
    obtain ⟨g2, rd2, k2⟩ := h2
    obtain ⟨eg, ry⟩ := lagree.read x1 x2 _ _ r rd1 rd2
    simp only at eg ry
    subst eg
    refine Or.inl ⟨?_, ry⟩
    cases g1 with
    | none => cases out1; cases out2; simp_all
    | some bytes =>
      rcases k1 with ⟨l1, b1, o1⟩ | ⟨l1, b1, o1⟩ <;> rcases k2 with ⟨l2, b2, o2⟩ | ⟨l2, b2, o2⟩
      · cases out1; cases out2; simp_all
      · exact absurd l1 l2
      · exact absurd l2 l1
      · have hb : out1.buffer = out2.buffer := alloc.vec.Vec.ext _ _ (b1.trans b2.symm)
        have ho : out1.open = out2.open := by rw [o1, o2]
        cases out1; cases out2
        simp only at hb ho
        subst hb ho
        rfl
  | Request parsed =>
    obtain ⟨now1, j1, s1, k1, m1, n1, sent1, bg1, sv1, st1, rs1, sd1, ob1, oo1⟩ := h1
    obtain ⟨now2, j2, s2, k2, m2, n2, sent2, bg2, sv2, st2, rs2, sd2, ob2, oo2⟩ := h2
    obtain ⟨en, rj⟩ := lagree.begin _ x1 x2 _ _ r bg1 bg2
    simp only at en rj
    subst en
    rcases serve_agree same lagree.origin rj sv1 sv2 with ⟨es, rk⟩ | stop | stop
    · subst es
      have rm : Seen R m1 m2 := by
        rcases st1 with ⟨c1, e1⟩ | ⟨c1, e1⟩ <;> rcases st2 with ⟨c2, e2⟩ | ⟨c2, e2⟩
        · subst e1 e2; exact rk
        · exact absurd c1 c2
        · exact absurd c2 c1
        · exact lagree.stopped _ _ _ _ _ rk e1 e2
      have rn := lagree.restart _ _ _ _ rm rs1 rs2
      obtain ⟨es, ry⟩ := lagree.send _ _ _ _ _ rn sd1 sd2
      simp only at es ry
      subst es
      refine Or.inl ⟨?_, ry⟩
      have hb : out1.buffer = out2.buffer := alloc.vec.Vec.ext _ _ (ob1.trans ob2.symm)
      have ho : out1.open = out2.open := by rw [oo1, oo2]
      cases out1; cases out2
      simp only at hb ho
      subst hb ho
      rfl
    all_goals
      right
      refine ⟨s1.reply.val, s2.reply.val, request_view ch1 bg1 sv1 st1 rs1 sd1, ?_, ?_⟩
      · rw [request_view ch2 bg2 sv2 st2 rs2 sd2, ← r.2]
      · first | exact Or.inl ⟨s1, stop, rfl⟩ | exact Or.inr ⟨s2, stop, rfl⟩

/-- **One step, twice.** -/
theorem step_agree (same : SameButCredential ops1 ops2 opener) {R : C1 → C2 → Prop} {ch1 : Channel C1}
    {ch2 : Channel C2} (agree : ChannelsAgree R ch1 ch2) {x1 : C1 × List ProxyEvent} {x2 : C2 × List ProxyEvent}
    (r : Seen R x1 x2) {buffer : alloc.vec.Vec U8} {out1 out2 : proxy_controller.Tunnel} {y1 y2}
    (h1 : connection_step ops1 pol (logged ch1) opener policy x1 buffer routes a authority peer limit =
      Result.ok (out1, y1))
    (h2 : connection_step ops2 pol (logged ch2) opener policy x2 buffer routes a authority peer limit =
      Result.ok (out2, y2)) :
    (out1 = out2 ∧ Seen R y1 y2) ∨ ∃ b1 b2, agentView y1.2 = agentView x1.2 ++ [b1] ∧
      agentView y2.2 = agentView x1.2 ++ [b2] ∧ (Reflected b1 ∨ Reflected b2) := by
  have lagree := logged_agree agree
  rcases connection_step_paths ops1 pol (logged ch1) opener policy routes a authority peer limit x1 buffer out1 y1 h1
    with ⟨l1, st1⟩ | ⟨l1, od1, ob1, oo1⟩ | ⟨l1, j1, od1, st1⟩ <;>
  rcases connection_step_paths ops2 pol (logged ch2) opener policy routes a authority peer limit x2 buffer out2 y2 h2
    with ⟨l2, st2⟩ | ⟨l2, od2, ob2, oo2⟩ | ⟨l2, j2, od2, st2⟩
  · exact stepped_agree same agree r st1 st2
  · exact absurd l1 l2
  · exact absurd l1 l2
  · exact absurd l2 l1
  · obtain ⟨_, ry⟩ := lagree.overdue x1 x2 _ _ r od1 od2
    refine Or.inl ⟨?_, ry⟩
    cases out1; cases out2; simp_all
  · obtain ⟨e, _⟩ := lagree.overdue x1 x2 _ _ r od1 od2
    cases e
  · exact absurd l2 l1
  · obtain ⟨e, _⟩ := lagree.overdue x1 x2 _ _ r od1 od2
    cases e
  · obtain ⟨_, rj⟩ := lagree.overdue x1 x2 _ _ r od1 od2
    have same1 : j1.2 = x1.2 := by
      obtain ⟨_, _, e⟩ := ok_map_inv od1
      simp only [Prod.mk.injEq] at e
      rw [e.2]
    rw [← same1]
    exact stepped_agree same agree rj st1 st2

/-- Two runs of the connection loop from related states and the same tunnel. -/
theorem runs_agree (same : SameButCredential ops1 ops2 opener) {R : C1 → C2 → Prop} {ch1 : Channel C1}
    {ch2 : Channel C2} (agree : ChannelsAgree R ch1 ch2) {x1 f1 : C1 × List ProxyEvent}
    {state : proxy_controller.Tunnel}
    (run1 : Runs ops1 pol (logged ch1) opener policy routes a authority peer limit x1 state f1) :
    ∀ {x2 f2 : C2 × List ProxyEvent}, Runs ops2 pol (logged ch2) opener policy routes a authority peer limit x2 state f2 →
      Seen R x1 x2 → Seen R f1 f2 ∨ DivergeAtReflection (agentView f1.2) (agentView f2.2) := by
  induction run1 with
  | closed shut =>
    intro x2 f2 run2 r
    cases run2 with
    | closed _ => exact Or.inl r
    | step running _ _ => rw [shut] at running; cases running
  | @step x1 state next y1 f1 running stepped1 rest1 ih =>
    intro x2 f2 run2 r
    cases run2 with
    | closed shut => rw [shut] at running; cases running
    | step _ stepped2 rest2 =>
      rcases step_agree same agree r stepped1 stepped2 with ⟨eo, ry⟩ | ⟨b1, b2, v1, v2, refl⟩
      · subst eo
        exact ih rest2 ry
      · right
        obtain ⟨segs1, l1, _⟩ := runs_logged ops1 pol opener policy routes a authority peer limit ch1 rest1
        obtain ⟨segs2, l2, _⟩ := runs_logged ops2 pol opener policy routes a authority peer limit ch2 rest2
        refine ⟨agentView x1.2, b1, b2, agentView segs1.flatten, agentView segs2.flatten, ?_, ?_, refl⟩
        · rw [l1, agentView_append, v1]; simp
        · rw [l2, agentView_append, v2]; simp

/-- **What the agent sees of a whole connection does not depend on the
    credential, beyond what is declassified.** Run the extracted connection
    loop twice, for the same peer, routes and policies, with openers that
    differ only in the valid credential they unseal, on any two channels that
    answer alike from related states (`ChannelsAgree`: the same agent bytes,
    deadlines and clock, adaptively, and the same network answers whatever
    credential-bearing bytes were written). Then the byte strings the agent is
    sent are the same, and the channels end related — or they are the same
    up to one reply at which one run sent the fixed reflection refusal (the
    provider's answer reflected that run's credential), after which the
    agent, knowing that bit, may act differently. -/
theorem connection_declassified (same : SameButCredential ops1 ops2 opener) {R : C1 → C2 → Prop}
    {ch1 : Channel C1} {ch2 : Channel C2} (agree : ChannelsAgree R ch1 ch2) {io1 : C1} {io2 : C2} (r : R io1 io2)
    {f1 : C1 × List ProxyEvent} {f2 : C2 × List ProxyEvent}
    (h1 : connection ops1 pol (logged ch1) opener policy (io1, []) routes a authority peer limit = Result.ok f1)
    (h2 : connection ops2 pol (logged ch2) opener policy (io2, []) routes a authority peer limit = Result.ok f2) :
    (agentView f1.2 = agentView f2.2 ∧ R f1.1 f2.1) ∨ DivergeAtReflection (agentView f1.2) (agentView f2.2) := by
  rcases runs_agree same agree (connection_runs ops1 pol (logged ch1) opener policy routes a authority peer limit _ _ h1)
    (connection_runs ops2 pol (logged ch2) opener policy routes a authority peer limit _ _ h2) ⟨r, rfl⟩ with
    ⟨rf, g⟩ | d
  · exact Or.inl ⟨g, rf⟩
  · exact Or.inr d

end run

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
