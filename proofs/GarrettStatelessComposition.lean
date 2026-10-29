import GarrettStatelessProxy

/-!
# `garrett-stateless-v1`: composable credential isolation

Source: `rust/crates/aivm-secrets-garrett-core/src/stateless_policy.rs` and
`stateless_proxy.rs`, extracted by Aeneas.

The proxy's request path is a composition of separately verified components,
each an extracted Rust function or trait instance:

| component | extracted code | contract |
| --- | --- | --- |
| identity verification | `stateless.authenticate` (verify, then admit) | `authenticate_ok_trace` |
| operation authorization | any `stateless_policy.OperationPolicy` instance | `Sound` |
| provider selection | `stateless_proxy.route_of` | `route_of_loop_contract` |
| credential release | `stateless.decrypt` | `decrypt_ok_trace` |
| exact request encoding | `proxy_http.encode_upstream` | `encode_upstream_contract` |
| controlled egress | `stateless_proxy.serve` with any `Origin` | `serve_follows_decision` |

`composed_egress` proves the composition once, for **any** operation-policy
component, from that component's contract `Sound pol policy Allowed`. It is
then instantiated, without repeating the proof, for the two policies the
`garrett-stateless` proxy runs — both actual extracted Rust trait instances:

* `Unrestricted` (Garrett's proxy), whose contract is `True`
  (`unrestricted_sound`), giving `garrett_egress`;
* `ReadOnly` (the constrained read-only proxy), whose contract
  `ReadOnlyAllowed` (`read_only_sound`, proved from the extracted
  `permits`, `any_allows` loop, `method_ok` and `path_matches`) restricts the
  method to `GET`/`HEAD`, the body to empty, and the provider and path to a
  configured resource, giving `read_only_egress` and `read_only_refuses`.

The policy sees the authenticated claims and the `Operation` (method, path,
body length) only — never the credential, the surrogate or upstream bytes —
and the proxy consults it before `decrypt` (`decide_unpermitted`).

Replicas: `serve_answered` refines `serve_outcome`: the reply is a function
`reply` of the pure decision and of exactly what the origin adapter answered —
`Answered.none` (never asked: no dispatch), `.unadmitted` (admission refused),
or `.exchanged answer done` (the provider exchange's result and, only when
the release completed, the completion acknowledgement).
`replicas_same_answers_same_reply` and `replica_replies_differ` hold for both
policies, since they are proved for any policy.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.proxy_http.Proofs
open aivm_secrets_garrett_core.stateless.Proofs
open aivm_secrets_garrett_core.http_auth.Proofs (HeaderPrefix)
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.stateless_policy.Proofs

/-! ## The operation-policy component and its contract -/

/-- **The contract of an operation-policy component.** `Allowed claims op`
    is what `permits` answering `true` guarantees. -/
def Sound {P : Type} (pol : OperationPolicy P) (policy : P)
    (Allowed : stateless.SurrogateClaims → Operation → Prop) : Prop :=
  ∀ claims op, pol.permits policy claims op ⦃ b => b = true → Allowed claims op ⦄

theorem clone_exact (bytes : alloc.vec.Vec U8) :
    alloc.vec.CloneVec.clone core.clone.CloneU8 bytes = Result.ok bytes := by
  unfold alloc.vec.CloneVec.clone
  obtain ⟨copied, returned, property⟩ := returned_of_spec
    (Slice.clone_spec (s := bytes.slice) (clone := core.clone.CloneU8.clone) (by intro x hx; rfl))
  rw [returned]
  simp only [bind_tc_ok, ← property]

/-- What a request's `Operation` is: its method, its target up to the
    position `path_end` finds (the path the encoder's deny rules check), and
    its body length. -/
theorem operation_of_spec (request : proxy_http.Request) :
    operation_of request ⦃ op => op.method.val = request.method.val ∧ op.body.val = request.body.length ∧
      ∃ e, proxy_http.path_end (alloc.vec.Vec.deref request.target) = Result.ok e ∧
        op.path.val = request.target.val.take e.val ⦄ := by
  unfold operation_of
  obtain ⟨e, he, ⟨le, _⟩⟩ := returned_of_spec (path_end_spec (alloc.vec.Vec.deref request.target))
  obtain ⟨s, hs, ⟨sv, _⟩⟩ := returned_of_spec (alloc.vec.Vec.index_RangeTo_spec request.target { «end» := e }
    (by simpa [alloc.vec.Vec.length] using le))
  simp only [he, clone_exact, hs, to_vec_eq, bind_ok, WP.spec_ok]
  refine ⟨trivial, by simp [alloc.vec.Vec.len, alloc.vec.Vec.length], e, rfl, ?_⟩
  rw [show (⟨s⟩ : alloc.vec.Vec U8).val = s.val from rfl, sv]
  exact slice_zero_eq_take _ _

/-! ## Garrett's policy: `Unrestricted` -/

/-- The extracted `impl OperationPolicy for Unrestricted`. -/
abbrev UnrestrictedPolicy : OperationPolicy Unrestricted :=
  Unrestricted.Insts.Aivm_secrets_garrett_coreStateless_policyOperationPolicy

/-- Garrett's proxy authorizes every operation by the surrogate alone. -/
theorem unrestricted_sound : Sound UnrestrictedPolicy () (fun _ _ => True) := by
  intro claims op
  simp [Unrestricted.Insts.Aivm_secrets_garrett_coreStateless_policyOperationPolicy.permits,
    WP.spec_ok]

/-! ## The constrained policy: `ReadOnly` -/

/-- The extracted `impl OperationPolicy for ReadOnly`. -/
abbrev ReadOnlyPolicy : OperationPolicy ReadOnly :=
  ReadOnly.Insts.Aivm_secrets_garrett_coreStateless_policyOperationPolicy

/-- `GET` or `HEAD`. -/
def ReadMethod (method : List U8) : Prop :=
  method = [71#u8, 69#u8, 84#u8] ∨ method = [72#u8, 69#u8, 65#u8, 68#u8]

instance (method : List U8) : Decidable (ReadMethod method) := by unfold ReadMethod; infer_instance

theorem read_method_eq (method : Slice U8) : read_method method = Result.ok (decide (ReadMethod method.val)) := by
  unfold read_method
  simp only [lifted_slice, bind_ok, slice_eq_eq, array_slice_val]
  by_cases g : method.val = [71#u8, 69#u8, 84#u8] <;>
    by_cases h : method.val = [72#u8, 69#u8, 65#u8, 68#u8] <;> simp_all [ReadMethod]

/-- One resource allows an operation at a provider: the same provider, a
    matching method (empty matches any) and a matching path. -/
def ResourceAllows (r : Resource) (provider : List U8) (op : Operation) : Prop :=
  r.provider.val = provider ∧ MethodMatches r.method.val op.method.val ∧ PathMatches r.path.val op.path.val

theorem resource_allows_spec (r : Resource) (provider : Slice U8) (op : Operation) :
    resource_allows r provider op ⦃ b => b = true ↔ ResourceAllows r provider.val op ⦄ := by
  unfold resource_allows
  simp only [slice_eq_eq, bind_ok]
  split
  · rename_i same
    apply WP.spec_bind (method_ok_spec _ _)
    intro b1 hb1
    split
    · rename_i yes
      refine WP.spec_mono (path_matches_spec _ _) ?_
      intro r hr
      simp_all [ResourceAllows, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]
    · rename_i no
      simp_all [WP.spec_ok, ResourceAllows, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]
  · rename_i differ
    simp_all [WP.spec_ok, ResourceAllows, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]

/-- The resources from `it.i` on. -/
def RemainingResources (it : core.slice.iter.Iter Resource) : List Resource := it.slice.val.drop it.i

theorem any_allows_loop_spec (it : core.slice.iter.Iter Resource) (provider : Slice U8) (op : Operation) :
    any_allows_loop it provider op ⦃ b =>
      b = true ↔ ∃ r ∈ RemainingResources it, ResourceAllows r provider.val op ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter Resource), it.slice.length - it.i = n →
      any_allows_loop it provider op ⦃ b =>
        b = true ↔ ∃ r ∈ RemainingResources it, ResourceAllows r provider.val op ⦄ from this _ it rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [any_allows_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · rw [iter_next_inside it inside]
      simp only [bind_ok]
      have cons : RemainingResources it = it.slice[it.i] :: RemainingResources { it with i := it.i + 1 } := by
        simp only [RemainingResources]
        exact List.drop_eq_getElem_cons (by simpa using inside)
      apply WP.spec_bind (resource_allows_spec _ provider op)
      intro b hb
      split
      · rename_i hit
        simp only [WP.spec_ok, true_iff]
        exact ⟨_, by rw [cons]; exact List.mem_cons_self, hb.mp hit⟩
      · rename_i miss
        refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac) { it with i := it.i + 1 } rfl) ?_
        intro r hr
        rw [hr, cons]
        constructor
        · rintro ⟨x, mem, allows⟩; exact ⟨x, List.mem_cons_of_mem _ mem, allows⟩
        · rintro ⟨x, mem, allows⟩
          rcases List.mem_cons.mp mem with same | rest
          · subst same; exact absurd (hb.mpr allows) miss
          · exact ⟨x, rest, allows⟩
    · rw [iter_next_done it inside]
      have empty : RemainingResources it = [] := by
        simp only [RemainingResources]; exact List.drop_eq_nil_of_le (by simpa using inside)
      simp [WP.spec_ok, empty]

theorem any_allows_spec (resources : Slice Resource) (provider : Slice U8) (op : Operation) :
    any_allows resources provider op ⦃ b =>
      b = true ↔ ∃ r ∈ resources.val, ResourceAllows r provider.val op ⦄ := by
  unfold any_allows
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  refine WP.spec_mono (any_allows_loop_spec _ provider op) ?_
  intro r hr
  simpa [RemainingResources] using hr

/-- **What the read-only policy permits**: a `GET` or `HEAD` operation with
    no body, allowed by a configured resource for the surrogate's
    authenticated provider. -/
def ReadOnlyAllowed (p : ReadOnly) (claims : stateless.SurrogateClaims) (op : Operation) : Prop :=
  ReadMethod op.method.val ∧ op.body.val = 0 ∧ ∃ r ∈ p.resources.val, ResourceAllows r claims.provider.val op

theorem read_only_permits_spec (p : ReadOnly) (claims : stateless.SurrogateClaims) (op : Operation) :
    ReadOnlyPolicy.permits p claims op ⦃ b => b = true ↔ ReadOnlyAllowed p claims op ⦄ := by
  simp only [ReadOnly.Insts.Aivm_secrets_garrett_coreStateless_policyOperationPolicy.permits,
    read_method_eq, bind_ok]
  split
  · rename_i read
    split
    · rename_i empty
      refine WP.spec_mono (any_allows_spec _ _ op) ?_
      intro r hr
      rw [hr]
      simp only [ReadOnlyAllowed, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]
      have : op.body.val = 0 := by scalar_tac
      simp_all
    · rename_i nonempty
      simp only [WP.spec_ok, ReadOnlyAllowed]
      have : op.body.val ≠ 0 := by scalar_tac
      simp_all
  · rename_i notread
    simp_all [WP.spec_ok, ReadOnlyAllowed, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]

/-- The read-only policy meets its contract, for every configuration `p`. -/
theorem read_only_sound (p : ReadOnly) : Sound ReadOnlyPolicy p (ReadOnlyAllowed p) := by
  intro claims op
  refine WP.spec_mono (read_only_permits_spec p claims op) ?_
  intro b hb yes
  exact hb.mp yes

end aivm_secrets_garrett_core.stateless_policy.Proofs


namespace aivm_secrets_garrett_core.stateless_proxy.Proofs

open stateless_policy.Proofs

variable {V O P : Type}

/-! ## The composition, for any operation-policy component -/

/-- The exact credential-bearing bytes of a dispatch on `route`. -/
def ExactWire (request : proxy_http.Request) (route : Route) (credential : alloc.vec.Vec U8) : List U8 :=
  UpstreamPrefix request (alloc.vec.Vec.deref route.host) ++ HeaderPrefix route.authentication ++
    credential.val ++ CRLF ++ UpstreamSuffix request

/-- What `composed_egress` guarantees about one run of `serve` that returned
    `served` with the origin at `after`, for an operation-policy contract
    `Allowed`. -/
def Isolated (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (inst : Origin O) (opener : V) (policy : P) (io : O)
    (Allowed : stateless.SurrogateClaims → stateless_policy.Operation → Prop)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O) : Prop :=
    ((∀ index wire opened,
        decide_request ops pol opener policy request routes a peer now ≠ Result.ok (.dispatch index wire opened)) ∧
      served.stage = .Refused ∧
      ((∃ r, inst.rejected io r = Result.ok after ∧ unauthorized_served = Result.ok served) ∨
       (after = io ∧ served.reply.val = ascii (refusalText served.code)))) ∨
    ∃ index wire opened, decide_request ops pol opener policy request routes a peer now =
        Result.ok (.dispatch index wire opened) ∧
      (∃ token v, surrogate_of (alloc.vec.Vec.deref request.fields) = Result.ok (some token) ∧
        ops.verify opener (alloc.vec.Vec.deref token) = Result.ok (.Ok v) ∧
        Admitted v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now ∧ opened.claims = v.claims ∧
        ops.«unseal» opener v = Result.ok (.Ok opened.credential)) ∧
      (∃ op, stateless_policy.operation_of request = Result.ok op ∧ Allowed opened.claims op) ∧
      (∃ (inside : index.val < routes.length),
        (routes[index.val]'inside).provider.val = opened.claims.provider.val ∧
        proxy_http.encode_upstream (alloc.vec.Vec.new U8) request
          (alloc.vec.Vec.deref (routes[index.val]'inside).host) (alloc.vec.Vec.deref (routes[index.val]'inside).rules)
          (alloc.vec.Vec.deref opened.credential) (routes[index.val]'inside).authentication =
          Result.ok (.Ok (), wire) ∧
        ((ExactWire request (routes[index.val]'inside) opened.credential).length ≤ Usize.max →
          wire.val = ExactWire request (routes[index.val]'inside) opened.credential)) ∧
      Dispatched inst io request limit index wire opened served after

/-- **Composable credential isolation.** For any operation-policy component
    meeting its contract `Allowed` (`Sound`), every run of the extracted
    `serve`, for any origin adapter and any key-set opener, is one of:

    * **no egress**: the decision is not a dispatch; the reply is the fixed
      `401` (after only the `rejected` diagnostic) or a fixed refusal, and the
      origin's `admitted` and `exchange` are never called; or
    * **one controlled, authorized, exact egress**, decided by
      `decide_request`, after which:
      - *identity*: the request carried exactly one surrogate, `verify`
        authenticated it and its claims were `Admitted` for this TLS peer, now;
      - *authorization*: the request's `Operation` is `Allowed` for those claims;
      - *provider selection*: the route serves the authenticated provider;
      - *credential*: the credential is `unseal` of that same surrogate;
      - *encoding*: the bytes are the extracted encoder's output for that
        route, and exactly `ExactWire` when they fit in memory;
      - *controlled egress*: the admission record was acknowledged before the
        one exchange of exactly those bytes with that route (`Dispatched`). -/
theorem composed_egress (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (inst : Origin O) (opener : V) (policy : P) (io : O)
    (Allowed : stateless.SurrogateClaims → stateless_policy.Operation → Prop) (sound : Sound pol policy Allowed)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops pol inst opener policy io request routes a peer now limit = Result.ok (served, after)) :
    Isolated ops pol inst opener policy io Allowed request routes a peer now limit served after := by
  unfold Isolated
  obtain ⟨d, hd, m⟩ := serve_follows_decision ops pol inst opener policy io request routes a peer now limit
    served after h
  cases d with
  | unauthorized r =>
    have none : ∀ index wire opened,
        decide_request ops pol opener policy request routes a peer now ≠ Result.ok (.dispatch index wire opened) := by
      intro index wire opened same; rw [hd] at same; simp at same
    exact Or.inl ⟨none, serve_rejected_never_sends ops pol inst opener policy io request routes a peer now limit
      served after h none⟩
  | refused code =>
    have none : ∀ index wire opened,
        decide_request ops pol opener policy request routes a peer now ≠ Result.ok (.dispatch index wire opened) := by
      intro index wire opened same; rw [hd] at same; simp at same
    exact Or.inl ⟨none, serve_rejected_never_sends ops pol inst opener policy io request routes a peer now limit
      served after h none⟩
  | dispatch index wire opened =>
    refine Or.inr ⟨index, wire, opened, hd, ?_, ?_, ?_, m⟩
    · obtain ⟨token, ho, hopen, _⟩ := dispatch_trace ops pol opener policy request routes a peer now hd
      obtain ⟨v, hv, adm, same, hun, _⟩ := open_ok_trace ops opener _ a peer now opened hopen
      exact ⟨token, v, ho, hv, adm, same, hun⟩
    · obtain ⟨op, hop, hperm⟩ := dispatch_permitted ops pol opener policy request routes a peer now hd
      have contract := sound opened.claims op
      rw [hperm] at contract
      exact ⟨op, hop, (WP.spec_ok _).mp contract rfl⟩
    · obtain ⟨_, _, _, inside, prov, henc⟩ := dispatch_trace ops pol opener policy request routes a peer now hd
      refine ⟨inside, prov, henc, fun room => ?_⟩
      obtain ⟨_, _, _, _, _, _, _, inside', _, bytes, _⟩ := serve_dispatch_exact ops pol inst opener policy io
        request routes a peer now limit served after h index wire opened hd (fun _ => room)
      exact bytes

/-! ## Instantiation 1: Garrett's proxy -/

/-- **Garrett's proxy** (`Unrestricted`): `composed_egress` with the
    trivial contract — identity, provider selection, exact encoding and
    controlled egress, with no restriction on the operation beyond the
    route's deny rules (inside the encoder). -/
theorem garrett_egress (ops : stateless.SurrogateOpener V) (inst : Origin O) (opener : V) (io : O)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops UnrestrictedPolicy inst opener () io request routes a peer now limit = Result.ok (served, after)) :
    Isolated ops UnrestrictedPolicy inst opener () io (fun _ _ => True) request routes a peer now limit served after :=
  composed_egress ops UnrestrictedPolicy inst opener () io (fun _ _ => True) unrestricted_sound request routes a
    peer now limit served after h

/-! ## Instantiation 2: the constrained read-only proxy -/

/-- **The read-only proxy** (`ReadOnly p`): `composed_egress` with the
    contract `ReadOnlyAllowed p`. -/
theorem read_only_egress (ops : stateless.SurrogateOpener V) (inst : Origin O) (opener : V) (p : stateless_policy.ReadOnly)
    (io : O) (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops ReadOnlyPolicy inst opener p io request routes a peer now limit = Result.ok (served, after)) :
    Isolated ops ReadOnlyPolicy inst opener p io (ReadOnlyAllowed p) request routes a peer now limit served after :=
  composed_egress ops ReadOnlyPolicy inst opener p io (ReadOnlyAllowed p) (read_only_sound p) request routes a
    peer now limit served after h

/-- **What the read-only proxy sends, in terms of the request.** Every
    credential-bearing egress of a read-only proxy is for a `GET` or `HEAD`
    request with an empty body, to the route of the surrogate's provider, on
    a path (the request target before any `?`, the path the encoder checks)
    that a configured resource for that provider allows. -/
theorem read_only_dispatch (ops : stateless.SurrogateOpener V) (opener : V) (p : stateless_policy.ReadOnly)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) {index : Usize} {wire : alloc.vec.Vec U8} {opened : stateless.Opened}
    (h : decide_request ops ReadOnlyPolicy opener p request routes a peer now =
      Result.ok (.dispatch index wire opened)) :
    ReadMethod request.method.val ∧ request.body.length = 0 ∧
      ∃ e r, proxy_http.path_end (alloc.vec.Vec.deref request.target) = Result.ok e ∧ r ∈ p.resources.val ∧
        r.provider.val = opened.claims.provider.val ∧ MethodMatches r.method.val request.method.val ∧
        PathMatches r.path.val (request.target.val.take e.val) := by
  obtain ⟨op, hop, hperm⟩ := dispatch_permitted ops ReadOnlyPolicy opener p request routes a peer now h
  have contract := read_only_permits_spec p opened.claims op
  rw [hperm] at contract
  obtain ⟨read, body, r, mem, prov, meth, path⟩ := ((WP.spec_ok _).mp contract).mp rfl
  have shape := operation_of_spec request
  rw [hop] at shape
  obtain ⟨m, b, e, he, pv⟩ := (WP.spec_ok _).mp shape
  refine ⟨by rwa [← m], by rw [← b]; exact body, e, r, he, mem, prov, by rwa [← m], by rwa [← pv]⟩

/-- **The read-only proxy refuses what Garrett's would forward, before any
    egress.** A read-only proxy never dispatches a request whose method is not
    `GET` or `HEAD`, or that has a body; so `serve` calls neither `admitted`
    nor `exchange` for it (`composed_egress`'s first case). -/
theorem read_only_refuses (ops : stateless.SurrogateOpener V) (opener : V) (p : stateless_policy.ReadOnly)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (write : ¬ ReadMethod request.method.val ∨ request.body.length ≠ 0) :
    ∀ index wire opened, decide_request ops ReadOnlyPolicy opener p request routes a peer now ≠
      Result.ok (.dispatch index wire opened) := by
  intro index wire opened h
  obtain ⟨read, body, _⟩ := read_only_dispatch ops opener p request routes a peer now h
  rcases write with w | w
  · exact w read
  · exact w body

/-! ## Replicas: decisions, admission, exchange and completion

`serve_outcome` shows a reply is a function of the decision and three adapter
answers. `Answered` names exactly which answers a run consulted, so replicas
can be compared answer by answer. -/

/-- A dispatch decision. -/
def Decision.isDispatch : Decision → Bool
  | .dispatch _ _ _ => true
  | _ => false

/-- What the origin adapter answered during one `serve`. -/
inductive Answered where
  /-- Not asked: the decision was not a dispatch. -/
  | none
  /-- The admission record was not acknowledged; nothing was sent. -/
  | unadmitted
  /-- Admitted; the provider exchange returned `answer`; `done` is the
      completion acknowledgement, asked (`some`) only for a completed release. -/
  | exchanged (answer : core.result.Result (alloc.vec.Vec U8) proxy_http.Code) (done : Option Bool)

/-- The reply, from the decision and the answers. -/
def reply (request : proxy_http.Request) (limit : Usize) : Decision → Answered → Result proxy_controller.Served
  | .unauthorized _, _ => unauthorized_served
  | .refused code, _ => proxy_controller.stopped code .Refused
  | .dispatch _ _ _, .none => proxy_controller.stopped .InternalError .Refused
  | .dispatch _ _ _, .unadmitted => proxy_controller.stopped .InternalError .Refused
  | .dispatch _ _ opened, .exchanged answer done => do
    let forms ← proxy_http.reflection_forms (alloc.vec.Vec.deref opened.credential)
    match answer with
    | .Ok raw => do
      let released ← proxy_controller.release (alloc.vec.Vec.deref raw) request (alloc.vec.Vec.deref forms) limit
      match released.stage, done with
      | .Completed, some false => proxy_controller.stopped .OutcomeUnknown .Failed
      | _, _ => Result.ok released
    | .Err code => proxy_controller.stopped code .Failed

/-- `ans` is exactly what `inst`, starting at `io`, answered for `d`. -/
def AnsweredBy (inst : Origin O) (io : O) (d : Decision) (ans : Answered) (after : O) : Prop :=
  match d, ans with
  | .dispatch index _ opened, .unadmitted => inst.admitted io opened.claims index = Result.ok (false, after)
  | .dispatch index wire opened, .exchanged answer done =>
    ∃ io1 io2, inst.admitted io opened.claims index = Result.ok (true, io1) ∧
      inst.exchange io1 { route := index, wire := wire } = Result.ok (answer, io2) ∧
      match done with
      | .none => after = io2
      | some b => ∃ status, inst.completed io2 status = Result.ok (b, after)
  | .dispatch _ _ _, .none => False
  | _, .none => True
  | _, _ => False

/-- **The reply is the decision and the answers.** Every run of `serve`
    computed the pure decision; the origin adapter's answers are `ans`
    (admission acknowledgement, provider exchange result, completion
    acknowledgement — only those it was asked); and the reply is
    `reply request limit d ans`. -/
theorem serve_answered (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (inst : Origin O) (opener : V) (policy : P) (io : O)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops pol inst opener policy io request routes a peer now limit = Result.ok (served, after)) :
    ∃ d ans, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
      (d.isDispatch = false → ans = .none) ∧ (d.isDispatch = true → AnsweredBy inst io d ans after) ∧
      reply request limit d ans = Result.ok served := by
  obtain ⟨d, hd, m⟩ := serve_follows_decision ops pol inst opener policy io request routes a peer now limit
    served after h
  have dispatched : ∀ {index wire opened}, (Decision.dispatch index wire opened).isDispatch = false → False := by
    intro _ _ _ e; simp [Decision.isDispatch] at e
  cases d with
  | unauthorized r =>
    exact ⟨_, .none, hd, fun _ => rfl, fun e => by simp [Decision.isDispatch] at e, m.1⟩
  | refused code =>
    exact ⟨_, .none, hd, fun _ => rfl, fun e => by simp [Decision.isDispatch] at e, m.1⟩
  | dispatch index wire opened =>
    rcases m with ⟨hadm, stop⟩ | ⟨io1, forms, answer, io2, hadm, hforms, hex, rest⟩
    · exact ⟨_, .unadmitted, hd, fun e => (dispatched e).elim, fun _ => hadm, stop⟩
    · cases answer with
      | Ok raw =>
        obtain ⟨released, rel, cases⟩ := rest
        rcases cases with ⟨stage, same, eafter⟩ | ⟨stage, acked, comp, ⟨eack, same⟩ | ⟨eack, stop⟩⟩
        · refine ⟨_, .exchanged (.Ok raw) none, hd, fun e => (dispatched e).elim,
            fun _ => ⟨io1, io2, hadm, hex, eafter⟩, ?_⟩
          simp only [reply, hforms, bind_ok, rel]
          cases hst : released.stage <;> simp_all
        · subst eack
          refine ⟨_, .exchanged (.Ok raw) (some true), hd, fun e => (dispatched e).elim,
            fun _ => ⟨io1, io2, hadm, hex, released.status, comp⟩, ?_⟩
          simp [reply, hforms, rel, same]
        · subst eack
          refine ⟨_, .exchanged (.Ok raw) (some false), hd, fun e => (dispatched e).elim,
            fun _ => ⟨io1, io2, hadm, hex, released.status, comp⟩, ?_⟩
          simp [reply, hforms, rel, stage, stop]
      | Err code =>
        refine ⟨_, .exchanged (.Err code) none, hd, fun e => (dispatched e).elim,
          fun _ => ⟨io1, io2, hadm, hex, rest.2⟩, ?_⟩
        simp [reply, hforms, rest.1]

/-- **Replicas with the same answers give the same reply.** Two proxies with
    the same keys, operation policy, routes and acceptance policy — any two
    origin adapters, in any state — make the same decision for the same
    authenticated request; and if their adapters answered alike (the same
    admission acknowledgement, provider exchange result and completion
    acknowledgement), their replies are identical. For a refusal no adapter
    is asked, so the replies are always identical. -/
theorem replicas_same_answers_same_reply {O1 O2 : Type} (ops : stateless.SurrogateOpener V)
    (pol : stateless_policy.OperationPolicy P) (opener : V) (policy : P)
    (inst1 : Origin O1) (io1 : O1) (inst2 : Origin O2) (io2 : O2)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (s1 s2 : proxy_controller.Served) (a1 : O1) (a2 : O2)
    (h1 : serve ops pol inst1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1))
    (h2 : serve ops pol inst2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2)) :
    ∃ d ans1 ans2, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
      (d.isDispatch = true → AnsweredBy inst1 io1 d ans1 a1 ∧ AnsweredBy inst2 io2 d ans2 a2) ∧
      (d.isDispatch = false → s1 = s2) ∧
      (ans1 = ans2 → s1 = s2) := by
  obtain ⟨d1, ans1, hd1, none1, by1, r1⟩ := serve_answered ops pol inst1 opener policy io1 request routes a peer
    now limit s1 a1 h1
  obtain ⟨d2, ans2, hd2, none2, by2, r2⟩ := serve_answered ops pol inst2 opener policy io2 request routes a peer
    now limit s2 a2 h2
  rw [hd1] at hd2
  simp only [Result.ok.injEq] at hd2
  subst hd2
  refine ⟨d1, ans1, ans2, hd1, fun e => ⟨by1 e, by2 e⟩, fun e => ?_, fun same => ?_⟩
  · rw [none1 e] at r1; rw [none2 e] at r2
    rw [r1] at r2; simpa using r2
  · subst same
    rw [r1] at r2; simpa using r2

/-- **Where replica replies can differ.** If two such replicas reply
    differently, the decision was a dispatch and their adapters answered
    differently: one acknowledged admission and the other did not, or their
    provider exchanges returned different results, or their completion
    acknowledgements differed. -/
theorem replica_replies_differ {O1 O2 : Type} (ops : stateless.SurrogateOpener V)
    (pol : stateless_policy.OperationPolicy P) (opener : V) (policy : P)
    (inst1 : Origin O1) (io1 : O1) (inst2 : Origin O2) (io2 : O2)
    (request : proxy_http.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (s1 s2 : proxy_controller.Served) (a1 : O1) (a2 : O2)
    (h1 : serve ops pol inst1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1))
    (h2 : serve ops pol inst2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2))
    (differ : s1 ≠ s2) :
    ∃ index wire opened ans1 ans2, decide_request ops pol opener policy request routes a peer now =
        Result.ok (.dispatch index wire opened) ∧
      AnsweredBy inst1 io1 (.dispatch index wire opened) ans1 a1 ∧
      AnsweredBy inst2 io2 (.dispatch index wire opened) ans2 a2 ∧ ans1 ≠ ans2 := by
  obtain ⟨d, ans1, ans2, hd, by12, same_refusal, same_answers⟩ :=
    replicas_same_answers_same_reply ops pol opener policy inst1 io1 inst2 io2 request routes a peer now limit
      s1 s2 a1 a2 h1 h2
  cases d with
  | unauthorized r => exact absurd (same_refusal rfl) differ
  | refused code => exact absurd (same_refusal rfl) differ
  | dispatch index wire opened =>
    obtain ⟨b1, b2⟩ := by12 rfl
    exact ⟨index, wire, opened, ans1, ans2, hd, b1, b2, fun e => differ (same_answers e)⟩

end aivm_secrets_garrett_core.stateless_proxy.Proofs
