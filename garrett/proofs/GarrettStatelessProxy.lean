import GarrettProxyController
import GarrettStateless

/-!
# `garrett-stateless-v1`: the stateless mTLS proxy controller

Source: `crates/garrett-stateless-core/src/stateless_proxy.rs`,
extracted by Aeneas (`stateless_proxy.serve`). The `garrett-stateless`
proxy calls `serve` for every request on an authenticated connection with
the peer thumbprint of that connection's handshake; the native shell
supplies only `Origin` (a diagnostics callback, the admission record, the
socket exchange to a route's pinned destination, and the completion
record) and the key-set opener.

`Decision` / `decide_request` compose the extracted pieces `serve` runs
before any adapter state matters (`surrogate_of`, `stateless.authenticate`,
`route_of`, the operation policy's `permits`, `stateless.decrypt`,
`encode_upstream`). It is not a second implementation: it is literally the
prefix of `serve`, and `serve_follows_decision` proves `serve` acts on it. Its
arguments are the opener, the operation policy, the request, the routes, the
acceptance policy, the peer and the clock, and **no origin state**. Every
theorem here holds for any operation policy; `GarrettStatelessComposition`
gives the policies' contracts and the composed theorem.

Proved:

* `serve_follows_decision`: every run of `serve`, for any origin adapter,
  either refuses exactly as `decide_request` decided (with no exchange), or
  dispatches the decided route and bytes, after an acknowledged admission;
* `decide_dispatch_trace`, `dispatch_trace`: a dispatch decision means the
  request presented exactly one surrogate, it authenticated and then
  decrypted — together, it opened (`open_ok_trace`) — for this peer, the
  route is the first route of the token's authenticated provider, the policy
  permitted the operation in between, and the bytes are the extracted
  encoder's output for that route's host, rules and authentication, with the
  unsealed credential;
* `dispatch_permitted`: the policy answered `true` for the opened claims and
  the request's operation; `decide_unpermitted`: when it answers `false` the
  decision is the fixed `denied` refusal, whatever `unseal` would do;
* `serve_dispatch_exact`: the bytes handed to `exchange` are
  `UpstreamPrefix ++ HeaderPrefix ++ credential ++ CRLF ++ UpstreamSuffix`;
* `serve_rejected_never_sends`: a missing, malformed or refused surrogate gets
  the fixed `401` and the exchange is never called;
* `serve_guest_reply`: the guest reply is the fixed `401`, a fixed refusal, or
  a `guest_response` release in which the raw credential does not occur;
* `replicas_decide_alike`: two proxies with the same keys and configuration,
  whatever their own state, make the same refusal or dispatch decision for
  the same authenticated request.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.proxy_http.Proofs
open garrett_stateless_core.stateless.Proofs
open garrett_stateless_core.http_auth.Proofs (HeaderPrefix)
set_option maxHeartbeats 4000000

namespace garrett_stateless_core.stateless_proxy.Proofs

/-- What `serve` decides before any origin callback can matter. -/
inductive Decision where
  /-- No usable surrogate (`none`), or one the opener refused. -/
  | unauthorized (rejection : Option stateless.Rejection)
  /-- A fixed refusal before egress: no route, or the encoder refused. -/
  | refused (code : proxy_http.Code)
  /-- Send `wire` to route `index` for the opened surrogate. -/
  | dispatch (index : Usize) (wire : alloc.vec.Vec U8) (opened : stateless.Opened)

/-- The extracted decision, with the constructors named for these proofs. -/
def Decision.ofCore : stateless_proxy.Decision → Decision
  | .Unauthorized r => .unauthorized r
  | .Refused code => .refused code
  | .Dispatch d => .dispatch d.route d.wire d.opened

/-- The extracted pure decision `stateless_proxy::decide`. -/
def decide_request {V P : Type} (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (opener : V) (policy : P)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance)
    (peer : Slice U8) (now : I64) : Result Decision := do
  let c ← stateless_proxy.decide ops pol opener policy request routes a peer now
  Result.ok (Decision.ofCore c)

variable {V O P : Type}

/-- What happens after a dispatch decision, for one origin adapter. -/
def Dispatched (inst : Origin O) (io : O) (request : proxy_http.Request) (limit : Usize)
    (index : Usize) (wire : alloc.vec.Vec U8) (opened : stateless.Opened)
    (served : proxy_controller.Served) (after : O) : Prop :=
  (inst.admitted io opened.claims index = Result.ok (false, after) ∧
    proxy_controller.stopped .InternalError .Refused = Result.ok served) ∨
  (∃ io1 forms answer io2, inst.admitted io opened.claims index = Result.ok (true, io1) ∧
    proxy_http.reflection_forms (alloc.vec.Vec.deref opened.credential) = Result.ok forms ∧
    inst.exchange io1 { route := index, wire := wire } = Result.ok (answer, io2) ∧
    match answer with
    | .Ok raw => ∃ released, proxy_controller.release (alloc.vec.Vec.deref raw) request
          (alloc.vec.Vec.deref forms) limit = Result.ok released ∧
        ((released.stage ≠ .Completed ∧ served = released ∧ after = io2) ∨
         (released.stage = .Completed ∧ ∃ acked, inst.completed io2 released.status = Result.ok (acked, after) ∧
           ((acked = true ∧ served = released) ∨
            (acked = false ∧ proxy_controller.stopped .OutcomeUnknown .Failed = Result.ok served))))
    | .Err code => proxy_controller.stopped code .Failed = Result.ok served ∧ after = io2)

/-- **`serve` acts on `decide_request`.** For any origin adapter and any of
    its states, a run of `serve` computed the decision and then: for
    `unauthorized`, reported the rejection and returned the fixed `401`; for
    `refused`, returned that fixed refusal without touching the origin; for
    `dispatch`, recorded admission and, only if it was acknowledged,
    exchanged exactly the decided bytes with the decided route. -/
theorem serve_follows_decision (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (inst : Origin O)
    (opener : V) (policy : P) (io : O)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops pol inst opener policy io request routes a peer now limit = Result.ok (served, after)) :
    ∃ d, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
      match d with
      | .unauthorized r => unauthorized_served = Result.ok served ∧
          inst.rejected io (r.getD .Malformed) = Result.ok after
      | .refused code => proxy_controller.stopped code .Refused = Result.ok served ∧ after = io
      | .dispatch index wire opened => Dispatched inst io request limit index wire opened served after := by
  unfold serve at h
  obtain ⟨c, hc, h⟩ := bind_ok_inv h
  have hd : decide_request ops pol opener policy request routes a peer now = Result.ok (Decision.ofCore c) := by
    simp [decide_request, hc]
  refine ⟨Decision.ofCore c, hd, ?_⟩
  cases c with
  | Unauthorized r =>
    obtain ⟨io1, hr, h⟩ := bind_ok_inv h
    obtain ⟨s1, hs, h⟩ := bind_ok_inv h
    simp only [Result.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨e1, e2⟩ := h
    subst e1 e2
    refine ⟨hs, ?_⟩
    cases r <;> exact hr
  | Refused code =>
    obtain ⟨s1, hs, h⟩ := bind_ok_inv h
    simp only [Result.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨e1, e2⟩ := h
    subst e1 e2
    exact ⟨hs, rfl⟩
  | Dispatch dsp =>
    obtain ⟨⟨acked, io1⟩, hadm, h⟩ := bind_ok_inv h
    cases acked with
    | false =>
      obtain ⟨s6, hs6, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨e1, e2⟩ := h
      subst e1 e2
      exact Or.inl ⟨hadm, hs6⟩
    | true =>
      obtain ⟨forms, hforms, h⟩ := bind_ok_inv h
      obtain ⟨⟨answer, io2⟩, hex, h⟩ := bind_ok_inv h
      refine Or.inr ⟨io1, forms, answer, io2, hadm, hforms, hex, ?_⟩
      cases answer with
      | Ok raw =>
        obtain ⟨released, rel, h⟩ := bind_ok_inv h
        refine ⟨released, rel, ?_⟩
        cases hst : released.stage with
        | Refused =>
          rw [hst] at h
          simp only [Result.ok.injEq, Prod.mk.injEq] at h
          exact Or.inl ⟨by simp, h.1.symm, h.2.symm⟩
        | Failed =>
          rw [hst] at h
          simp only [Result.ok.injEq, Prod.mk.injEq] at h
          exact Or.inl ⟨by simp, h.1.symm, h.2.symm⟩
        | Completed =>
          rw [hst] at h
          obtain ⟨⟨acked, io3⟩, comp, h⟩ := bind_ok_inv h
          cases acked with
          | true =>
            have h' : Result.ok (released, io3) = Result.ok (served, after) := h
            simp only [Result.ok.injEq, Prod.mk.injEq] at h'
            obtain ⟨e1, e2⟩ := h'
            subst e2
            exact Or.inr ⟨rfl, true, comp, Or.inl ⟨rfl, e1.symm⟩⟩
          | false =>
            obtain ⟨s9, hs9, h⟩ := bind_ok_inv h
            simp only [Result.ok.injEq, Prod.mk.injEq] at h
            obtain ⟨e1, e2⟩ := h
            subst e1 e2
            exact Or.inr ⟨rfl, false, comp, Or.inr ⟨rfl, hs9⟩⟩
      | Err code =>
        obtain ⟨s7, hs7, h⟩ := bind_ok_inv h
        simp only [Result.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨e1, e2⟩ := h
        subst e1 e2
        exact ⟨hs7, rfl⟩

/-- **Replica equivalence.** Two proxies — any two origin adapters, in any
    states, sharing nothing — given the same opener (key set), request,
    routes, acceptance policy, peer and clock follow one and the same
    decision. -/
theorem replicas_decide_alike {O1 O2 : Type} (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (opener : V) (policy : P)
    (inst1 : Origin O1) (io1 : O1) (inst2 : Origin O2) (io2 : O2)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (s1 s2 : proxy_controller.Served) (a1 : O1) (a2 : O2)
    (h1 : serve ops pol inst1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1))
    (h2 : serve ops pol inst2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2)) :
    ∃ d, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
      (∀ code, d = .refused code → s1 = s2) ∧
      (∀ r, d = .unauthorized r → s1 = s2) := by
  obtain ⟨d1, hd1, m1⟩ := serve_follows_decision ops pol inst1 opener policy io1 request routes a peer now limit s1 a1 h1
  obtain ⟨d2, hd2, m2⟩ := serve_follows_decision ops pol inst2 opener policy io2 request routes a peer now limit s2 a2 h2
  rw [hd1] at hd2
  simp only [Result.ok.injEq] at hd2
  subst hd2
  refine ⟨d1, hd1, ?_, ?_⟩
  · intro code same
    subst same
    obtain ⟨x1, _⟩ := m1
    obtain ⟨x2, _⟩ := m2
    rw [x1] at x2
    simpa using x2
  · intro r same
    subst same
    obtain ⟨x1, _⟩ := m1
    obtain ⟨x2, _⟩ := m2
    rw [x1] at x2
    simpa using x2

/-- The reply `serve` returns, as a function of the decision and the three
    answers of its origin adapter: the admission acknowledgement, the
    exchange's answer and the completion acknowledgement. -/
def outcome (request : proxy_http.Request) (limit : Usize) (d : Decision) (acked : Bool)
    (answer : core.result.Result (alloc.vec.Vec U8) proxy_http.Code) (done : Bool) :
    Result proxy_controller.Served :=
  match d with
  | .unauthorized _ => unauthorized_served
  | .refused code => proxy_controller.stopped code .Refused
  | .dispatch _ _ opened =>
    if acked then do
      let forms ← proxy_http.reflection_forms (alloc.vec.Vec.deref opened.credential)
      match answer with
      | .Ok raw => do
        let released ← proxy_controller.release (alloc.vec.Vec.deref raw) request
          (alloc.vec.Vec.deref forms) limit
        match released.stage with
        | .Completed => if done then Result.ok released else proxy_controller.stopped .OutcomeUnknown .Failed
        | _ => Result.ok released
      | .Err code => proxy_controller.stopped code .Failed
    else proxy_controller.stopped .InternalError .Refused

/-- **The reply is the decision plus the adapter's answers.** Every run of
    `serve` returns `outcome` of the pure decision and of what its origin
    adapter answered; nothing else about the adapter's state reaches it. -/
theorem serve_outcome (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (inst : Origin O)
    (opener : V) (policy : P) (io : O)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops pol inst opener policy io request routes a peer now limit = Result.ok (served, after)) :
    ∃ d, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
      ∃ acked answer done, outcome request limit d acked answer done = Result.ok served := by
  obtain ⟨d, hd, m⟩ := serve_follows_decision ops pol inst opener policy io request routes a peer now limit served after h
  refine ⟨d, hd, ?_⟩
  cases d with
  | unauthorized r => exact ⟨true, .Err .InternalError, true, m.1⟩
  | refused code => exact ⟨true, .Err .InternalError, true, m.1⟩
  | dispatch index wire opened =>
    rcases m with ⟨_, stop⟩ | ⟨io1, forms, answer, io2, _, hforms, _, rest⟩
    · exact ⟨false, .Err .InternalError, true, by simpa [outcome] using stop⟩
    · cases answer with
      | Ok raw =>
        obtain ⟨released, rel, cases⟩ := rest
        rcases cases with ⟨stage, same, _⟩ | ⟨stage, acked, _, ⟨_, same⟩ | ⟨_, stop⟩⟩
        · refine ⟨true, .Ok raw, true, ?_⟩
          simp only [outcome, ↓reduceIte, hforms, bind_ok, rel]
          cases hst : released.stage <;> simp_all
        · refine ⟨true, .Ok raw, true, ?_⟩
          simp [outcome, hforms, rel, stage, same]
        · refine ⟨true, .Ok raw, false, ?_⟩
          simp [outcome, hforms, rel, stage, stop]
      | Err code =>
        exact ⟨true, .Err code, true, by simp [outcome, hforms, rest.1]⟩

/-- **Replicas: equal decisions, outcomes that differ only by the network.**
    Two proxies with the same keys, routes and acceptance policy — any two
    origin adapters, in any state — make the same decision for the same
    authenticated request (for a dispatch, the same route and bytes), and
    each reply is `outcome` of that decision and its own adapter's answers.
    Their replies can differ only because their upstream exchanges, or their
    admission and completion records, answered differently. -/
theorem replicas_differ_only_by_answers {O1 O2 : Type} (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (opener : V) (policy : P)
    (inst1 : Origin O1) (io1 : O1) (inst2 : Origin O2) (io2 : O2)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (s1 s2 : proxy_controller.Served) (a1 : O1) (a2 : O2)
    (h1 : serve ops pol inst1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1))
    (h2 : serve ops pol inst2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2)) :
    ∃ d, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
      (∃ acked answer done, outcome request limit d acked answer done = Result.ok s1) ∧
      (∃ acked answer done, outcome request limit d acked answer done = Result.ok s2) := by
  obtain ⟨d1, hd1, o1⟩ := serve_outcome ops pol inst1 opener policy io1 request routes a peer now limit s1 a1 h1
  obtain ⟨d2, hd2, o2⟩ := serve_outcome ops pol inst2 opener policy io2 request routes a peer now limit s2 a2 h2
  rw [hd1] at hd2
  simp only [Result.ok.injEq] at hd2
  subst hd2
  exact ⟨d1, hd1, o1, o2⟩

/-! ## Route selection -/

/-- The route the loop returns, when in range, serves exactly `provider`. -/
theorem route_of_loop_contract (routes : Slice Route) (provider : Slice U8) (index : Usize) :
    route_of_loop routes provider index ⦃ out => ∀ (inside : out.val < routes.length),
      (routes[out.val]'inside).provider.val = provider.val ⦄ := by
  suffices ∀ n (index : Usize), routes.length - index.val = n →
      route_of_loop routes provider index ⦃ out => ∀ (inside : out.val < routes.length),
        (routes[out.val]'inside).provider.val = provider.val ⦄ from this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure
    rw [route_of_loop.eq_def]
    by_cases inside : index.val < routes.length
    · have cond : index < Slice.len routes := by scalar_tac
      simp only [cond, ↓reduceIte]
      have get : Slice.index_usize routes index = Result.ok (routes[index.val]'inside) := by
        simp [Slice.index_usize, inside]
      rw [get]
      simp only [bind_ok, provides, slice_eq_eq]
      split
      · rename_i same
        apply (WP.spec_ok _).mpr
        intro _
        simpa [alloc.vec.Vec.deref] using same
      · obtain ⟨next, hnext, nval⟩ := returned_of_spec (@Usize.add_spec index 1#usize (by scalar_tac))
        rw [hnext]
        simp only [bind_ok]
        exact ih (routes.length - next.val) (by scalar_tac) next rfl
    · have cond : ¬ index < Slice.len routes := by scalar_tac
      simp only [cond, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      intro h
      exact absurd h inside

/-! ## What a dispatch decision means -/

/-- **The trace of a dispatch decision.** The request carried exactly one
    surrogate; `authenticate` verified it and admitted its claims for this
    peer, now; the route is in range and serves the authenticated provider;
    the operation policy permitted the request's operation for those claims;
    only then did `decrypt` unseal the credential; and the bytes are the
    extracted encoder's accepted output for that route with that credential. -/
theorem decide_dispatch_trace (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (opener : V) (policy : P) (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance)
    (peer : Slice U8) (now : I64) {dsp : stateless_proxy.Dispatch}
    (h : stateless_proxy.decide ops pol opener policy request routes a peer now = Result.ok (.Dispatch dsp)) :
    ∃ token v op, surrogate_of (alloc.vec.Vec.deref request.fields) = Result.ok (some token) ∧
      stateless.authenticate ops opener (alloc.vec.Vec.deref token) a peer now = Result.ok (.Ok v) ∧
      stateless_policy.operation_of request = Result.ok op ∧
      pol.permits policy v.claims op = Result.ok true ∧
      stateless.decrypt ops opener v = Result.ok (.Ok dsp.opened) ∧
      ∃ (inside : dsp.route.val < routes.length),
        (routes[dsp.route.val]'inside).provider.val = v.claims.provider.val ∧
        proxy_http.encode_upstream (alloc.vec.Vec.new U8) request
          (alloc.vec.Vec.deref (routes[dsp.route.val]'inside).host)
          (alloc.vec.Vec.deref (routes[dsp.route.val]'inside).rules)
          (alloc.vec.Vec.deref dsp.opened.credential) (routes[dsp.route.val]'inside).authentication =
          Result.ok (.Ok (), dsp.wire) := by
  unfold stateless_proxy.decide at h
  obtain ⟨o, ho, h⟩ := bind_ok_inv h
  cases o with
  | none => simp at h
  | some token =>
    dsimp only at h
    obtain ⟨r, hauth, h⟩ := bind_ok_inv h
    cases r with
    | Err e => simp at h
    | Ok v =>
      dsimp only at h
      obtain ⟨i, hi, h⟩ := bind_ok_inv h
      split at h
      · simp at h
      · rename_i inside
        have in' : i.val < routes.length := by scalar_tac
        obtain ⟨op, hop, h⟩ := bind_ok_inv h
        obtain ⟨b, hb, h⟩ := bind_ok_inv h
        split at h
        · rename_i yes
          obtain ⟨r1, hdec, h⟩ := bind_ok_inv h
          cases r1 with
          | Err e => simp at h
          | Ok o2 =>
            dsimp only at h
            have get : Slice.index_usize routes i = Result.ok (routes[i.val]'in') := by
              simp [Slice.index_usize, in']
            rw [get] at h
            simp only [bind_ok] at h
            obtain ⟨⟨r2, w⟩, henc, h⟩ := bind_ok_inv h
            cases r2 with
            | Err refusal =>
              obtain ⟨code, _, h⟩ := bind_ok_inv h
              simp at h
            | Ok u =>
              have same : stateless_proxy.Decision.Dispatch { route := i, wire := w, opened := o2 } =
                  .Dispatch dsp := by simpa using h
              cases same
              have route := route_of_loop_contract routes (alloc.vec.Vec.deref v.claims.provider) 0#usize
              simp only [route_of] at hi
              rw [hi] at route
              simp only [WP.spec_ok] at route
              refine ⟨token, v, op, ho, hauth, hop, by rw [hb, yes], hdec, in',
                by simpa [alloc.vec.Vec.deref] using route in', ?_⟩
              cases u
              exact henc
        · simp at h

/-- **Dispatch is authorized.** A dispatch decision means: the request
    carried exactly one surrogate; it opened for this peer, now, under this
    acceptance policy; the route is in range and serves the token's
    authenticated provider; and the decided bytes are the extracted encoder's
    accepted output for that route with the unsealed credential. -/
theorem dispatch_trace (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (opener : V)
    (policy : P) (request : proxy_http.Request)
    (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8) (now : I64)
    {index : Usize} {wire : alloc.vec.Vec U8} {opened : stateless.Opened}
    (h : decide_request ops pol opener policy request routes a peer now = Result.ok (.dispatch index wire opened)) :
    ∃ token, surrogate_of (alloc.vec.Vec.deref request.fields) = Result.ok (some token) ∧
      stateless.«open» ops opener (alloc.vec.Vec.deref token) a peer now = Result.ok (.Ok opened) ∧
      ∃ (inside : index.val < routes.length),
        (routes[index.val]'inside).provider.val = opened.claims.provider.val ∧
        proxy_http.encode_upstream (alloc.vec.Vec.new U8) request
          (alloc.vec.Vec.deref (routes[index.val]'inside).host) (alloc.vec.Vec.deref (routes[index.val]'inside).rules)
          (alloc.vec.Vec.deref opened.credential) (routes[index.val]'inside).authentication =
          Result.ok (.Ok (), wire) := by
  unfold decide_request at h
  obtain ⟨c, hc, h⟩ := bind_ok_inv h
  cases c with
  | Unauthorized r => simp [Decision.ofCore] at h
  | Refused code => simp [Decision.ofCore] at h
  | Dispatch dsp =>
    simp only [Decision.ofCore, Result.ok.injEq, Decision.dispatch.injEq] at h
    obtain ⟨e1, e2, e3⟩ := h
    subst e1 e2 e3
    obtain ⟨token, v, op, ho, hauth, _, _, hdec, inside, prov, henc⟩ :=
      decide_dispatch_trace ops pol opener policy request routes a peer now hc
    obtain ⟨_, same, _⟩ := stateless.Proofs.decrypt_ok_trace ops opener v dsp.opened hdec
    exact ⟨token, ho, stateless.Proofs.open_of_halves ops opener _ a peer now v dsp.opened hauth hdec, inside,
      by rw [same]; exact prov, henc⟩

/-- **Dispatch is permitted by the operation policy.** For a dispatch
    decision, the policy was asked about this request's operation and the
    opened surrogate's claims, and answered `true`. -/
theorem dispatch_permitted (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (opener : V) (policy : P) (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance)
    (peer : Slice U8) (now : I64) {index : Usize} {wire : alloc.vec.Vec U8} {opened : stateless.Opened}
    (h : decide_request ops pol opener policy request routes a peer now = Result.ok (.dispatch index wire opened)) :
    ∃ op, stateless_policy.operation_of request = Result.ok op ∧
      pol.permits policy opened.claims op = Result.ok true := by
  unfold decide_request at h
  obtain ⟨c, hc, h⟩ := bind_ok_inv h
  cases c with
  | Unauthorized r => simp [Decision.ofCore] at h
  | Refused code => simp [Decision.ofCore] at h
  | Dispatch dsp =>
    simp only [Decision.ofCore, Result.ok.injEq, Decision.dispatch.injEq] at h
    obtain ⟨e1, e2, e3⟩ := h
    subst e1 e2 e3
    obtain ⟨_, v, op, _, _, hop, hperm, hdec, _⟩ := decide_dispatch_trace ops pol opener policy request routes a peer now hc
    obtain ⟨_, same, _⟩ := stateless.Proofs.decrypt_ok_trace ops opener v dsp.opened hdec
    exact ⟨op, hop, by rw [same]; exact hperm⟩

/-- **A refused operation is refused before decryption.** If the surrogate
    authenticates, its provider has a route, and the policy refuses the
    operation, the decision is the fixed `denied` refusal — whatever the
    `unseal` adapter would do, so the credential is never decrypted. -/
theorem decide_unpermitted (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (opener : V) (policy : P) (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance)
    (peer : Slice U8) (now : I64) (token : alloc.vec.Vec U8) (v : stateless.Verified)
    (op : stateless_policy.Operation)
    (ho : surrogate_of (alloc.vec.Vec.deref request.fields) = Result.ok (some token))
    (hauth : stateless.authenticate ops opener (alloc.vec.Vec.deref token) a peer now = Result.ok (.Ok v))
    (routed : ∃ i, route_of routes (alloc.vec.Vec.deref v.claims.provider) = Result.ok i ∧ i.val < routes.length)
    (hop : stateless_policy.operation_of request = Result.ok op)
    (refused : pol.permits policy v.claims op = Result.ok false)
    (other : V → stateless.Verified → Result (core.result.Result (alloc.vec.Vec U8) stateless.Rejection)) :
    decide_request ops pol opener policy request routes a peer now = Result.ok (.refused .Denied) ∧
    decide_request {ops with «unseal» := other} pol opener policy request routes a peer now =
      Result.ok (.refused .Denied) := by
  obtain ⟨i, hi, inside⟩ := routed
  have hauth' : stateless.authenticate {ops with «unseal» := other} opener (alloc.vec.Vec.deref token) a peer now =
      Result.ok (.Ok v) := by
    rw [← hauth]; simp [stateless.authenticate]
  have notout : ¬ routes.val.length ≤ i.val := by scalar_tac
  constructor
  · simp [decide_request, stateless_proxy.decide, ho, hauth, hi, notout, hop, refused, Decision.ofCore]
  · simp [decide_request, stateless_proxy.decide, ho, hauth', hi, notout, hop, refused, Decision.ofCore]

/-- **Substitution correctness.** When `serve` exchanged bytes with a route,
    those bytes were exactly `UpstreamPrefix ++ HeaderPrefix ++ credential ++
    CRLF ++ UpstreamSuffix` for that route's host and authentication scheme
    and the credential the opener unsealed from a surrogate admitted for
    this peer; the route serves that surrogate's provider; and the admission
    record was acknowledged first. -/
theorem serve_dispatch_exact (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (inst : Origin O)
    (opener : V) (policy : P) (io : O)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops pol inst opener policy io request routes a peer now limit = Result.ok (served, after))
    (index : Usize) (wire : alloc.vec.Vec U8) (opened : stateless.Opened)
    (decided : decide_request ops pol opener policy request routes a peer now = Result.ok (.dispatch index wire opened))
    (room : ∀ (inside : index.val < routes.length),
      (UpstreamPrefix request (alloc.vec.Vec.deref (routes[index.val]'inside).host) ++
        HeaderPrefix (routes[index.val]'inside).authentication ++ opened.credential.val ++ CRLF ++
        UpstreamSuffix request).length ≤ Usize.max) :
    ∃ token v, surrogate_of (alloc.vec.Vec.deref request.fields) = Result.ok (some token) ∧
      ops.verify opener (alloc.vec.Vec.deref token) = Result.ok (.Ok v) ∧
      Admitted v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now ∧ opened.claims = v.claims ∧
      ops.«unseal» opener v = Result.ok (.Ok opened.credential) ∧
      ∃ (inside : index.val < routes.length),
        (routes[index.val]'inside).provider.val = v.claims.provider.val ∧
        wire.val = UpstreamPrefix request (alloc.vec.Vec.deref (routes[index.val]'inside).host) ++
          HeaderPrefix (routes[index.val]'inside).authentication ++ opened.credential.val ++ CRLF ++
          UpstreamSuffix request ∧
        Dispatched inst io request limit index wire opened served after := by
  obtain ⟨d, hd, m⟩ := serve_follows_decision ops pol inst opener policy io request routes a peer now limit served after h
  rw [decided] at hd
  simp only [Result.ok.injEq] at hd
  subst hd
  obtain ⟨token, ho, hopen, inside, provider, henc⟩ := dispatch_trace ops pol opener policy request routes a peer now decided
  obtain ⟨v, hv, adm, same, hun, _⟩ := open_ok_trace ops opener _ a peer now opened hopen
  refine ⟨token, v, ho, hv, adm, same, hun, inside, by rw [← same]; exact provider, ?_, m⟩
  obtain ⟨value, returned, post⟩ := returned_of_spec
    (encode_upstream_contract (alloc.vec.Vec.new U8) request
      (alloc.vec.Vec.deref (routes[index.val]'inside).host) (alloc.vec.Vec.deref (routes[index.val]'inside).rules)
      (alloc.vec.Vec.deref opened.credential) (routes[index.val]'inside).authentication
      (by rw [show (alloc.vec.Vec.new U8).length = 0 from rfl, Nat.zero_add]
          simpa [alloc.vec.Vec.deref] using room inside))
  rw [henc] at returned
  simp only [Result.ok.injEq] at returned
  subst returned
  rcases post with ⟨_, _, _, _, bytes⟩ | ⟨refused, _⟩
  · rw [bytes]
    simp [alloc.vec.Vec.new]
  · exact absurd rfl refused

/-- **No dispatch on rejection.** If the decision is not a dispatch — no or
    several surrogates, any opening failure (forged, expired, wrong
    certificate, audience, provider, undecryptable), no route, or an encoder
    refusal — then `serve`, for any origin, never calls `admitted` or
    `exchange`: the origin state after the request is the result of
    `rejected` alone, or untouched. -/
theorem serve_rejected_never_sends (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (inst : Origin O)
    (opener : V) (policy : P) (io : O)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops pol inst opener policy io request routes a peer now limit = Result.ok (served, after))
    (notDispatched : ∀ index wire opened,
      decide_request ops pol opener policy request routes a peer now ≠ Result.ok (.dispatch index wire opened)) :
    served.stage = .Refused ∧
      ((∃ r, inst.rejected io r = Result.ok after ∧ unauthorized_served = Result.ok served) ∨
       (after = io ∧ served.reply.val = ascii (refusalText served.code))) := by
  obtain ⟨d, hd, m⟩ := serve_follows_decision ops pol inst opener policy io request routes a peer now limit served after h
  cases d with
  | unauthorized r =>
    obtain ⟨hs, hr⟩ := m
    have stage : served.stage = .Refused := by
      simp only [unauthorized_served] at hs
      obtain ⟨v, _, hs⟩ := bind_ok_inv hs
      simp only [Result.ok.injEq] at hs
      rw [← hs]
    exact ⟨stage, Or.inl ⟨_, hr, hs⟩⟩
  | refused code =>
    obtain ⟨hs, ha⟩ := m
    obtain ⟨reply, stage, _, same⟩ := proxy_controller.Proofs.stopped_reply hs
    exact ⟨stage, Or.inr ⟨ha, by rw [reply, same]⟩⟩
  | dispatch index wire opened => exact absurd hd (notDispatched index wire opened)

/-! ## What the guest receives -/

/-- After a dispatch, the reply is a fixed refusal or a completed release of
    the provider's answer. -/
theorem dispatched_reply {inst : Origin O} {io : O} {request : proxy_http.Request} {limit : Usize}
    {index : Usize} {wire : alloc.vec.Vec U8} {opened : stateless.Opened}
    {served : proxy_controller.Served} {after : O}
    (m : Dispatched inst io request limit index wire opened served after) :
    served.reply.val = ascii (refusalText served.code) ∨
    ∃ forms raw, proxy_http.reflection_forms (alloc.vec.Vec.deref opened.credential) = Result.ok forms ∧
      proxy_controller.release (alloc.vec.Vec.deref raw) request (alloc.vec.Vec.deref forms) limit =
        Result.ok served ∧ served.stage = .Completed := by
  have stopped_case : ∀ {code stage}, proxy_controller.stopped code stage = Result.ok served →
      served.reply.val = ascii (refusalText served.code) := by
    intro code stage stop
    obtain ⟨reply, _, _, same⟩ := proxy_controller.Proofs.stopped_reply stop
    rw [reply, same]
  rcases m with ⟨_, stop⟩ | ⟨io1, forms, answer, io2, _, hforms, _, finish⟩
  · exact Or.inl (stopped_case stop)
  · cases answer with
    | Err code => exact Or.inl (stopped_case finish.1)
    | Ok raw =>
      obtain ⟨released, rel, cases⟩ := finish
      rcases cases with ⟨notdone, same, _⟩ | ⟨done, acked, _, ⟨_, same⟩ | ⟨_, stop⟩⟩
      · subst same
        rcases proxy_controller.Proofs.release_reply _ request _ limit served rel with ⟨isdone, _⟩ | ⟨_, refusal⟩
        · exact absurd isdone notdone
        · exact Or.inl refusal
      · subst same
        exact Or.inr ⟨forms, raw, hforms, rel, done⟩
      · exact Or.inl (stopped_case stop)

/-- **Credential confinement in replies.** The guest receives the fixed
    `401` (`unauthorized_served`, a closed term: it has no inputs), a fixed
    refusal (only its code, `refusal_exact`), or a completed release by
    `guest_response` of the provider's answer in which — for a response whose
    checked encoding fits in memory — the raw credential the proxy substituted
    does not occur (`reflection_forms_include_raw`, `guest_response_contract`).
    Other encodings of the credential are covered for the unfolded reflection
    forms only; a provider transformation outside them is not. -/
theorem serve_guest_reply (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (inst : Origin O)
    (opener : V) (policy : P) (io : O)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops pol inst opener policy io request routes a peer now limit = Result.ok (served, after)) :
    unauthorized_served = Result.ok served ∨
    served.reply.val = ascii (refusalText served.code) ∨
    (∃ index wire opened, decide_request ops pol opener policy request routes a peer now =
        Result.ok (.dispatch index wire opened) ∧ served.stage = .Completed ∧
      ∃ forms head response,
        proxy_http.reflection_forms (alloc.vec.Vec.deref opened.credential) = Result.ok forms ∧
        proxy_http.guest_response (alloc.vec.Vec.new U8) response (alloc.vec.Vec.deref forms)
          request.keep_alive head = Result.ok (.Ok (), served.reply) ∧
        ((ResponseBytes response response.fields.val request.keep_alive false).length ≤ Usize.max →
          ¬ Occurs served.reply.val opened.credential.val)) := by
  obtain ⟨d, hd, m⟩ := serve_follows_decision ops pol inst opener policy io request routes a peer now limit served after h
  cases d with
  | unauthorized r => exact Or.inl m.1
  | refused code =>
    obtain ⟨reply, _, _, same⟩ := proxy_controller.Proofs.stopped_reply m.1
    exact Or.inr (Or.inl (by rw [reply, same]))
  | dispatch index wire opened =>
    rcases dispatched_reply m with refusal | ⟨forms, raw, hforms, rel, done⟩
    · exact Or.inr (Or.inl refusal)
    · rcases proxy_controller.Proofs.release_reply _ request _ limit served rel with
        ⟨_, head, response, released⟩ | ⟨failed, _⟩
      · refine Or.inr (Or.inr ⟨index, wire, opened, hd, done, forms, head, response, hforms, released, ?_⟩)
        intro fits
        have contract := guest_response_contract (alloc.vec.Vec.new U8) response (alloc.vec.Vec.deref forms)
          request.keep_alive head (by simpa [alloc.vec.Vec.new, alloc.vec.Vec.length] using fits)
        rw [released] at contract
        simp only [WP.spec_ok] at contract
        rcases contract with ⟨_, appended, bytes, none⟩ | ⟨wrong, _⟩
        · obtain ⟨form, mem, plain, raw_bytes⟩ := reflection_forms_include_raw _ forms hforms
          have reply : served.reply.val = appended := by simpa [alloc.vec.Vec.new] using bytes
          have absent := none form (by simpa [alloc.vec.Vec.deref] using mem) plain
          rw [reply]
          have same : form.bytes.val = opened.credential.val := by simpa [alloc.vec.Vec.deref] using raw_bytes
          rwa [same] at absent
        · exact absurd rfl wrong
      · rw [done] at failed
        cases failed

end garrett_stateless_core.stateless_proxy.Proofs
