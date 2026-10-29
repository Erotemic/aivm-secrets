import GarrettStatelessProxy
import GarrettProxyTunnel

/-!
# `garrett-stateless-v1`: the proxy's authenticated connection loop

Source: `rust/crates/aivm-secrets-garrett-core/src/stateless_proxy.rs`
(`connection`, `connection_step`, `serve`, `Egress`), extracted by Aeneas.
The native proxy completes the TLS handshake and calls `connection` with the
thumbprint of the certificate that handshake verified; it supplies only the
`Channel` callbacks (socket reads and writes, the clock, diagnostics, the
upstream sender). The upstream sender receives an `Egress`, which only `serve`
can build (private fields), and consumes it.

Proved here, for **any** opener and **any** channel, in any state:

* `connection_runs`: a connection that returns is a run (`Runs`) of
  `connection_step`s from an empty buffer, every one called with the peer the
  connection was started with;
* `connection_step_paths`: each step closes on an overdue partial request,
  refuses what `frame` refuses (audit, then only the fixed refusal), reads
  and appends exactly the bytes read, or serves exactly the parsed request by
  `serve` for that peer and the clock `begin` returned, audits `stopped`
  exactly when it did not complete, and writes exactly its reply;
* `logged` wraps any channel and records each callback in order.
  `serve_logged`, `step_logged`, `connection_logged`: the log is a sequence of
  per-step segments (`StepLog`);
* `connection_egress_authorized`: every `sent route wire` follows the
  acknowledged admission of the same request, whose decision was a dispatch
  of exactly that route and those bytes for a surrogate opened for this peer
  (`dispatch_trace`); `seg_sends_at_most_once`, `connection_sends_once_per_request`:
  at most one send per request, none for a request without a dispatch;
* `connection_guest_bytes`: the guest receives only fixed refusals, the fixed
  `401`, or `guest_response` releases in which the raw credential does not
  occur.

Partial correctness is stated with `Returns`, a liberal precondition in which
a failed callback satisfies every postcondition: these theorems say what holds
whenever the connection returns, whatever the callbacks return or fail with.
Still trusted (native boundary): that the channel's callbacks perform the
effect they name, that `send_upstream` writes the egress bytes once to its
route's pinned address, and that the peer thumbprint is the verified one.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.proxy_http.Proofs (bind_ok_inv)
open aivm_secrets_garrett_core.proxy_controller.Proofs (ite_ok_inv ok_pair_inv remainder_val)
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.stateless_proxy.Proofs

/-! ## Partial correctness that tolerates failing callbacks -/

unseal Result

/-- A weakest liberal precondition in which a failed computation satisfies
    every postcondition: it states only what holds of a returned value. -/
@[reducible] def lenientWP : Data.Coinductive.EffectWP RustEffect where
  State := Unit
  wp _ _ _ := True

instance : Data.Coinductive.EffectWP.Monotonic lenientWP where
  wp_monotonic := fun _ _ _ => trivial

instance : Data.Coinductive.EffectWP.Conjunctive lenientWP where
  wp_conj := fun _ _ _ => trivial

/-- Whatever `m` returns satisfies `Q`. -/
def Returns {α : Type} (m : Result α) (Q : α → Prop) : Prop :=
  Data.Coinductive.DWLP lenientWP m (fun v _ => Q v) ()

theorem returns_of_ok {α : Type} {m : Result α} {Q : α → Prop} (h : ∀ v, m = Result.ok v → Q v) :
    Returns m Q := by
  unfold Returns
  cases m using Result.cases with
  | ret v => exact Data.Coinductive.DWLP.ret_iff.mpr (h v rfl)
  | vis e k => exact Data.Coinductive.DWLP.vis trivial
  | div => exact Data.Coinductive.DWLP.div

theorem returns_ok {α : Type} {m : Result α} {Q : α → Prop} {v : α} (r : Returns m Q) (h : m = Result.ok v) :
    Q v := by
  subst h
  exact Data.Coinductive.DWLP.ret_iff.mp r

theorem returns_bind {α β : Type} {m : Result α} {k : α → Result β} {Q₁ : α → Prop} {Q₂ : β → Prop}
    (first : Returns m Q₁) (rest : ∀ v, Q₁ v → Returns (k v) Q₂) : Returns (Std.bind m k) Q₂ :=
  Data.Coinductive.DWLP.bind first (fun v _ hv => rest v hv)

theorem returns_admissible {α β : Type} (arg : α) (Q : β → Prop) :
    Lean.Order.admissible (fun f : α → Result β => Returns (f arg) Q) :=
  Lean.Order.admissible_apply (fun _ m => Returns m Q) arg
    (Data.Coinductive.DWLP.admissible lenientWP (fun v _ => Q v) ())

/-! ## Every run of a connection -/

variable {V C P : Type} (ops : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P) (inst : Channel C)
  (opener : V) (policy : P)
  (routes : Slice Route) (a : stateless.Acceptance) (authority peer : Slice U8) (limit : Usize)

/-- The steps a connection took from `state` with the channel at `io`,
    ending with the channel at `after`. Every step is `connection_step` with
    the connection's own `peer`. -/
inductive Runs : C → proxy_controller.Tunnel → C → Prop where
  | closed {io : C} {state : proxy_controller.Tunnel} (shut : state.open = false) : Runs io state io
  | step {io : C} {state next : proxy_controller.Tunnel} {io1 after : C} (running : state.open = true)
      (stepped : connection_step ops pol inst opener policy io state.buffer routes a authority peer limit = Result.ok (next, io1))
      (rest : Runs io1 next after) : Runs io state after

theorem connection_loop_runs (io : C) (state : proxy_controller.Tunnel) :
    Returns (connection_loop ops pol inst opener policy io routes a authority peer limit state)
      (fun after => Runs ops pol inst opener policy routes a authority peer limit io state after) := by
  revert io state
  apply connection_loop.fixpoint_induct ops pol inst opener policy routes a authority peer limit
    (motive := fun f => ∀ io state, Returns (f io state)
      (fun after => Runs ops pol inst opener policy routes a authority peer limit io state after))
  · apply Lean.Order.admissible_pi; intro io
    apply Lean.Order.admissible_pi; intro state
    exact Lean.Order.admissible_apply (β := fun _ => proxy_controller.Tunnel → Result C)
      (fun _ (g : proxy_controller.Tunnel → Result C) => Returns (g state)
        (fun after => Runs ops pol inst opener policy routes a authority peer limit io state after)) io
      (returns_admissible state _)
  · intro f ih io state
    simp only
    split
    · rename_i running
      apply returns_bind (Q₁ := fun r => connection_step ops pol inst opener policy io state.buffer routes a authority
        peer limit = Result.ok r) (returns_of_ok fun v h => h)
      rintro ⟨next, io1⟩ stepped
      simp only [Aeneas.Std.uncurry_apply_pair]
      have more := ih io1 next
      unfold Returns at more ⊢
      exact Data.Coinductive.DWLP.mono more (fun after _ r => Runs.step running stepped r)
    · rename_i shut
      apply returns_of_ok
      intro v h
      simp only [Result.ok.injEq] at h
      subst h
      exact Runs.closed (by simpa using shut)

/-- **Every connection starts with nothing buffered and is a run of steps
    for its own peer.** If `connection` returns, the channel went from `io` to
    `after` by `connection_step`s, each called with the `peer` the connection
    was started with, from an empty buffer. -/
theorem connection_runs (io after : C)
    (h : connection ops pol inst opener policy io routes a authority peer limit = Result.ok after) :
    Runs ops pol inst opener policy routes a authority peer limit io { buffer := alloc.vec.Vec.new U8, «open» := true } after :=
  returns_ok (connection_loop_runs ops pol inst opener policy routes a authority peer limit io _) h

/-! ## One step -/

/-- What a step does once its deadline check has passed (or was skipped
    because nothing is buffered): `io` is the channel at that point. -/
def Stepped (io : C) (buffer : alloc.vec.Vec U8) (out : proxy_controller.Tunnel) (after : C) : Prop :=
  ∃ framed, proxy_controller.frame (alloc.vec.Vec.deref buffer) authority limit = Result.ok framed ∧
  match framed with
  | .Refuse code =>
      ∃ io1 bytes sent, inst.refused io code = Result.ok io1 ∧
        proxy_http.refusal code = Result.ok bytes ∧
        inst.send io1 (alloc.vec.Vec.deref bytes) = Result.ok (sent, after) ∧
        out.buffer = buffer ∧ out.open = false
  | .More =>
      ∃ got, inst.read io = Result.ok (got, after) ∧
        match got with
        | none => out.buffer = buffer ∧ out.open = false
        | some bytes =>
            (bytes.length = 0 ∧ out.buffer = buffer ∧ out.open = false) ∨
            (bytes.length ≠ 0 ∧ out.buffer.val = buffer.val ++ bytes.val ∧ out.open = true)
  | .Request parsed =>
      ∃ now io1 served io2 io3 io4 sent, inst.begin io parsed.request = Result.ok (now, io1) ∧
        serve ops pol inst.OriginInst opener policy io1 parsed.request routes a peer now limit = Result.ok (served, io2) ∧
        ((served.stage = .Completed ∧ io3 = io2) ∨
          (served.stage ≠ .Completed ∧ inst.stopped io2 served.code = Result.ok io3)) ∧
        inst.restart io3 = Result.ok io4 ∧
        inst.send io4 (alloc.vec.Vec.deref served.reply) = Result.ok (sent, after) ∧
        out.buffer.val = buffer.val.drop parsed.used.val ∧ out.open = (sent && served.keep)

set_option hygiene false in
local macro "stepped_tail" : tactic => `(tactic| (
  obtain ⟨framed, fr, h⟩ := bind_ok_inv h
  refine ⟨framed, fr, ?_⟩
  cases framed with
  | More =>
    obtain ⟨⟨got, io2⟩, rd, h⟩ := bind_ok_inv h
    cases got with
    | none =>
      obtain ⟨hout, hafter⟩ := ok_pair_inv h
      subst hout hafter
      exact ⟨none, rd, rfl, rfl⟩
    | some bytes =>
      refine ⟨some bytes, ?_⟩
      rcases ite_ok_inv h with ⟨z, h⟩ | ⟨z, h⟩
      · obtain ⟨hout, hafter⟩ := ok_pair_inv h
        subst hout hafter
        exact ⟨rd, Or.inl ⟨by scalar_tac, rfl, rfl⟩⟩
      · obtain ⟨grown, extended, h⟩ := bind_ok_inv h
        obtain ⟨hout, hafter⟩ := ok_pair_inv h
        subst hout hafter
        refine ⟨rd, Or.inr ⟨by scalar_tac, ?_, rfl⟩⟩
        simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using
          aivm_secrets_garrett_core.route.Proofs.extend_ok_val extended
  | Refuse code =>
    obtain ⟨io2, rf, h⟩ := bind_ok_inv h
    obtain ⟨bytes, rb, h⟩ := bind_ok_inv h
    obtain ⟨⟨sent, io3⟩, sd, h⟩ := bind_ok_inv h
    obtain ⟨hout, hafter⟩ := ok_pair_inv h
    subst hout hafter
    exact ⟨io2, bytes, sent, rf, rb, sd, rfl, rfl⟩
  | Request parsed =>
    obtain ⟨rest, rem, h⟩ := bind_ok_inv h
    obtain ⟨⟨now, io2⟩, bg, h⟩ := bind_ok_inv h
    obtain ⟨⟨served, io3⟩, sv, h⟩ := bind_ok_inv h
    obtain ⟨io4, st, h⟩ := bind_ok_inv h
    obtain ⟨io5, rs, h⟩ := bind_ok_inv h
    obtain ⟨⟨sent, io6⟩, sd, h⟩ := bind_ok_inv h
    have kept := remainder_val _ _ _ rem
    have stage : (served.stage = .Completed ∧ io4 = io3) ∨
        (served.stage ≠ .Completed ∧ inst.stopped io3 served.code = Result.ok io4) := by
      revert st
      cases served.stage <;> simp [eq_comm]
    cases sent <;>
    · obtain ⟨hout, hafter⟩ := ok_pair_inv h
      subst hout hafter
      exact ⟨now, io2, served, io3, io4, io5, _, bg, sv, stage, rs, sd,
        by simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using kept, by simp⟩))

/-- **One connection step.** With nothing buffered the deadline is not
    consulted; otherwise an overdue partial request closes the connection and
    nothing else happens. Past the deadline check, `Stepped` says exactly which
    callbacks ran, with which arguments: a framing refusal is audited and only
    the fixed refusal is written; a read appends exactly the bytes read; a
    parsed request is served by the extracted `serve` for **this connection's
    `peer`** and the clock `begin` returned, `stopped` is audited exactly when
    it did not complete, and exactly its reply is written, keeping exactly the
    bytes after the request. -/
theorem connection_step_paths (io : C) (buffer : alloc.vec.Vec U8) (out : proxy_controller.Tunnel) (after : C)
    (h : connection_step ops pol inst opener policy io buffer routes a authority peer limit = Result.ok (out, after)) :
    (buffer.length = 0 ∧ Stepped ops pol inst opener policy routes a authority peer limit io buffer out after) ∨
    (buffer.length ≠ 0 ∧ inst.overdue io = Result.ok (true, after) ∧ out.buffer = buffer ∧ out.open = false) ∨
    (buffer.length ≠ 0 ∧ ∃ io1, inst.overdue io = Result.ok (false, io1) ∧
      Stepped ops pol inst opener policy routes a authority peer limit io1 buffer out after) := by
  unfold connection_step at h
  dsimp only at h
  split at h
  · rename_i nonempty
    obtain ⟨⟨late, io1⟩, od, h⟩ := bind_ok_inv h
    cases late with
    | true =>
      obtain ⟨hout, hafter⟩ := ok_pair_inv h
      subst hout hafter
      exact Or.inr (Or.inl ⟨by scalar_tac, od, rfl, rfl⟩)
    | false =>
      refine Or.inr (Or.inr ⟨by scalar_tac, io1, od, ?_⟩)
      stepped_tail
  · rename_i empty
    refine Or.inl ⟨by scalar_tac, ?_⟩
    stepped_tail

/-! ## The effects of a connection, as a log

`logged` wraps any channel and records each callback the extracted code
makes, in order, then delegates to the wrapped channel: the log is exactly the
sequence of native effects the connection loop requested. -/

/-- One native effect the connection loop requested. -/
inductive ProxyEvent where
  /-- A parsed request is about to be served. -/
  | began (request : proxy_http.Request)
  | rejected (rejection : stateless.Rejection)
  /-- The admission record was requested; `acked` is the native answer. -/
  | admitted (claims : stateless.SurrogateClaims) (route : Usize) (acked : Bool)
  /-- A credential-bearing upstream request was handed to the native sender. -/
  | sent (route : Usize) (wire : alloc.vec.Vec U8)
  | completed (status : U16) (acked : Bool)
  | refused (code : proxy_http.Code)
  | stopped (code : proxy_http.Code)
  /-- Bytes written to the guest. -/
  | guestSent (bytes : List U8)

def loggedOrigin (o : Origin C) : Origin (C × List ProxyEvent) where
  rejected s r := Std.bind (o.rejected s.1 r) fun c => Result.ok (c, s.2 ++ [.rejected r])
  admitted s claims route := Std.bind (o.admitted s.1 claims route) fun r =>
    Result.ok (r.1, (r.2, s.2 ++ [.admitted claims route r.1]))
  exchange s egress := Std.bind (o.exchange s.1 egress) fun r =>
    Result.ok (r.1, (r.2, s.2 ++ [.sent egress.route egress.wire]))
  completed s status := Std.bind (o.completed s.1 status) fun r =>
    Result.ok (r.1, (r.2, s.2 ++ [.completed status r.1]))

def logged (ch : Channel C) : Channel (C × List ProxyEvent) where
  OriginInst := loggedOrigin ch.OriginInst
  overdue s := Std.bind (ch.overdue s.1) fun r => Result.ok (r.1, (r.2, s.2))
  read s := Std.bind (ch.read s.1) fun r => Result.ok (r.1, (r.2, s.2))
  send s bytes := Std.bind (ch.send s.1 bytes) fun r => Result.ok (r.1, (r.2, s.2 ++ [.guestSent bytes.val]))
  refused s code := Std.bind (ch.refused s.1 code) fun c => Result.ok (c, s.2 ++ [.refused code])
  stopped s code := Std.bind (ch.stopped s.1 code) fun c => Result.ok (c, s.2 ++ [.stopped code])
  begin s request := Std.bind (ch.begin s.1 request) fun r => Result.ok (r.1, (r.2, s.2 ++ [.began request]))
  restart s := Std.bind (ch.restart s.1) fun c => Result.ok (c, s.2)

/-- What one `serve` call adds to the log, by its pre-egress decision. -/
def ServeLog (d : Decision) (E : List ProxyEvent) : Prop :=
  match d with
  | .unauthorized r => E = [.rejected (r.getD .Malformed)]
  | .refused _ => E = []
  | .dispatch index wire opened =>
      E = [.admitted opened.claims index false] ∨
      E = [.admitted opened.claims index true, .sent index wire] ∨
      ∃ status acked, E = [.admitted opened.claims index true, .sent index wire, .completed status acked]

/-- **The log of one request.** For any wrapped origin, a `serve` call
    records exactly what its decision allows: a refused surrogate one
    `rejected`; a pre-egress refusal nothing; a dispatch the admission request
    and — only if it was acknowledged — exactly one `sent` of the decided route
    and bytes, then at most a completion record. -/
theorem serve_logged (o : Origin C) (io : C) (L : List ProxyEvent) (request : proxy_http.Request) (now : I64)
    (served : proxy_controller.Served) (after : C × List ProxyEvent)
    (h : serve ops pol (loggedOrigin o) opener policy (io, L) request routes a peer now limit = Result.ok (served, after)) :
    ∃ d E, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧ after.2 = L ++ E ∧ ServeLog d E := by
  obtain ⟨d, hd, m⟩ := serve_follows_decision ops pol (loggedOrigin o) opener policy (io, L) request routes a peer now limit
    served after h
  refine ⟨d, ?_⟩
  cases d with
  | unauthorized r =>
    obtain ⟨_, rj⟩ := m
    obtain ⟨c, _, e⟩ := bind_ok_inv rj
    simp only [Result.ok.injEq] at e
    subst e
    exact ⟨_, hd, rfl, rfl⟩
  | refused code =>
    obtain ⟨_, e⟩ := m
    subst e
    exact ⟨[], hd, by simp, rfl⟩
  | dispatch index wire opened =>
    rcases m with ⟨adm, _⟩ | ⟨io1, forms, answer, io2, adm, _, ex, rest⟩
    · obtain ⟨r, _, e⟩ := bind_ok_inv adm
      simp only [Result.ok.injEq, Prod.mk.injEq] at e
      obtain ⟨e1, e2⟩ := e
      subst e2
      exact ⟨_, hd, rfl, Or.inl (by rw [e1])⟩
    · obtain ⟨r, _, e⟩ := bind_ok_inv adm
      simp only [Result.ok.injEq, Prod.mk.injEq] at e
      obtain ⟨e1, e2⟩ := e
      subst e2
      obtain ⟨r', _, e'⟩ := bind_ok_inv ex
      simp only [Result.ok.injEq, Prod.mk.injEq] at e'
      obtain ⟨_, e2'⟩ := e'
      subst e2'
      cases answer with
      | Err code =>
        obtain ⟨_, e⟩ := rest
        subst e
        exact ⟨[.admitted opened.claims index true, .sent index wire], hd, by simp [e1], Or.inr (Or.inl rfl)⟩
      | Ok raw =>
        obtain ⟨released, _, cases⟩ := rest
        rcases cases with ⟨_, _, e⟩ | ⟨_, acked, comp, _⟩
        · subst e
          exact ⟨[.admitted opened.claims index true, .sent index wire], hd, by simp [e1], Or.inr (Or.inl rfl)⟩
        · obtain ⟨r'', _, e''⟩ := bind_ok_inv comp
          simp only [Result.ok.injEq, Prod.mk.injEq] at e''
          obtain ⟨_, e2''⟩ := e''
          subst e2''
          exact ⟨[.admitted opened.claims index true, .sent index wire, .completed released.status r''.1], hd,
            by simp [e1], Or.inr (Or.inr ⟨_, _, rfl⟩)⟩

theorem ok_map_inv {α β : Type} {m : Result α} {f : α → β} {x : β}
    (h : Std.bind m (fun r => Result.ok (f r)) = Result.ok x) : ∃ r, m = Result.ok r ∧ x = f r := by
  obtain ⟨r, hm, e⟩ := bind_ok_inv h
  exact ⟨r, hm, (Result.ok_injective e).symm⟩

/-- The guarantee `serve_guest_reply` gives for the reply of one request. -/
def GuestReply (request : proxy_http.Request) (now : I64) (served : proxy_controller.Served) : Prop :=
  unauthorized_served = Result.ok served ∨
  served.reply.val = proxy_http.Proofs.ascii (proxy_http.Proofs.refusalText served.code) ∨
  (∃ index wire opened, decide_request ops pol opener policy request routes a peer now =
      Result.ok (.dispatch index wire opened) ∧ served.stage = .Completed ∧
    ∃ forms head response,
      proxy_http.reflection_forms (alloc.vec.Vec.deref opened.credential) = Result.ok forms ∧
      proxy_http.guest_response (alloc.vec.Vec.new U8) response (alloc.vec.Vec.deref forms)
        request.keep_alive head = Result.ok (.Ok (), served.reply) ∧
      ((proxy_http.Proofs.ResponseBytes response response.fields.val request.keep_alive false).length ≤
          Usize.max → ¬ proxy_http.Proofs.Occurs served.reply.val opened.credential.val))

/-- What one connection step adds to the log: nothing (a read, or a close);
    a framing refusal and its fixed bytes; or one request — `began`, exactly
    what `serve` recorded for its decision (`ServeLog`), the `stopped` audit
    exactly when it did not complete, and its reply. -/
def StepLog (seg : List ProxyEvent) : Prop :=
  seg = [] ∨
  (∃ code bytes, proxy_http.refusal code = Result.ok bytes ∧ seg = [.refused code, .guestSent bytes.val]) ∨
  (∃ request now d E served, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
    ServeLog d E ∧ GuestReply ops pol opener policy routes a peer request now served ∧
    ((served.stage = .Completed ∧ seg = [.began request] ++ E ++ [.guestSent served.reply.val]) ∨
     (served.stage ≠ .Completed ∧
        seg = [.began request] ++ E ++ [.stopped served.code, .guestSent served.reply.val])))

theorem stepped_logged (ch : Channel C) (io : C) (L : List ProxyEvent) (buffer : alloc.vec.Vec U8)
    (out : proxy_controller.Tunnel) (after : C × List ProxyEvent)
    (h : Stepped ops pol (logged ch) opener policy routes a authority peer limit (io, L) buffer out after) :
    ∃ seg, after.2 = L ++ seg ∧ StepLog ops pol opener policy routes a peer seg := by
  obtain ⟨framed, _, h⟩ := h
  cases framed with
  | Refuse code =>
    obtain ⟨io1, bytes, sent, rf, rb, sd, _⟩ := h
    obtain ⟨c, _, e1⟩ := ok_map_inv rf
    subst e1
    obtain ⟨r, _, e2⟩ := ok_map_inv sd
    simp only [Prod.mk.injEq] at e2
    obtain ⟨_, e2⟩ := e2
    subst e2
    exact ⟨_, by simp, Or.inr (Or.inl ⟨code, bytes, rb, rfl⟩)⟩
  | More =>
    obtain ⟨got, rd, _⟩ := h
    obtain ⟨r, _, e⟩ := ok_map_inv rd
    simp only [Prod.mk.injEq] at e
    obtain ⟨_, e⟩ := e
    subst e
    exact ⟨[], by simp, Or.inl rfl⟩
  | Request parsed =>
    obtain ⟨now, io1, served, io2, io3, io4, sent, bg, sv, stage, rs, sd, _⟩ := h
    obtain ⟨r1, _, e1⟩ := ok_map_inv bg
    simp only [Prod.mk.injEq] at e1
    obtain ⟨_, e1⟩ := e1
    subst e1
    have sv' : serve ops pol (loggedOrigin ch.OriginInst) opener policy (r1.2, L ++ [ProxyEvent.began parsed.request])
        parsed.request routes a peer now limit = Result.ok (served, io2) := sv
    obtain ⟨d, E, hd, log2, slog⟩ := serve_logged ops pol opener policy routes a peer limit ch.OriginInst r1.2
      (L ++ [.began parsed.request]) parsed.request now served io2 sv'
    have reply := serve_guest_reply ops pol (loggedOrigin ch.OriginInst) opener policy (r1.2, L ++ [.began parsed.request])
      parsed.request routes a peer now limit served io2 sv'
    obtain ⟨r4, _, e4⟩ := ok_map_inv rs
    obtain ⟨r6, _, e6⟩ := ok_map_inv sd
    simp only [Prod.mk.injEq] at e6
    obtain ⟨_, e6⟩ := e6
    subst e6 e4
    rcases stage with ⟨done, e3⟩ | ⟨notDone, st⟩
    · subst e3
      refine ⟨[.began parsed.request] ++ E ++ [.guestSent served.reply.val], ?_, Or.inr (Or.inr
        ⟨parsed.request, now, d, E, served, hd, slog, reply, Or.inl ⟨done, rfl⟩⟩)⟩
      simp [log2, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]
    · obtain ⟨r3, _, e3⟩ := ok_map_inv st
      subst e3
      refine ⟨[.began parsed.request] ++ E ++ [.stopped served.code, .guestSent served.reply.val], ?_,
        Or.inr (Or.inr ⟨parsed.request, now, d, E, served, hd, slog, reply, Or.inr ⟨notDone, rfl⟩⟩)⟩
      simp [log2, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]

/-- **One logged step** adds exactly one `StepLog` segment. -/
theorem step_logged (ch : Channel C) (io : C) (L : List ProxyEvent) (buffer : alloc.vec.Vec U8)
    (out : proxy_controller.Tunnel) (after : C × List ProxyEvent)
    (h : connection_step ops pol (logged ch) opener policy (io, L) buffer routes a authority peer limit = Result.ok (out, after)) :
    ∃ seg, after.2 = L ++ seg ∧ StepLog ops pol opener policy routes a peer seg := by
  rcases connection_step_paths ops pol (logged ch) opener policy routes a authority peer limit (io, L) buffer out after h with
    ⟨_, st⟩ | ⟨_, od, _⟩ | ⟨_, io1, od, st⟩
  · exact stepped_logged ops pol opener policy routes a authority peer limit ch io L buffer out after st
  · obtain ⟨r, _, e⟩ := ok_map_inv od
    simp only [Prod.mk.injEq] at e
    obtain ⟨_, e⟩ := e
    subst e
    exact ⟨[], by simp, Or.inl rfl⟩
  · obtain ⟨r, _, e⟩ := ok_map_inv od
    simp only [Prod.mk.injEq] at e
    obtain ⟨_, e⟩ := e
    subst e
    exact stepped_logged ops pol opener policy routes a authority peer limit ch r.2 L buffer out after st

theorem runs_logged (ch : Channel C) {io after : C × List ProxyEvent} {state : proxy_controller.Tunnel}
    (run : Runs ops pol (logged ch) opener policy routes a authority peer limit io state after) :
    ∃ segs : List (List ProxyEvent), after.2 = io.2 ++ segs.flatten ∧
      ∀ seg ∈ segs, StepLog ops pol opener policy routes a peer seg := by
  induction run with
  | closed _ => exact ⟨[], by simp, by simp⟩
  | @step io state next io1 after running stepped rest ih =>
    obtain ⟨seg, log1, ok1⟩ := step_logged ops pol opener policy routes a authority peer limit ch io.1 io.2 state.buffer
      next io1 stepped
    obtain ⟨segs, log2, ok2⟩ := ih
    refine ⟨seg :: segs, by rw [log2, log1]; simp, ?_⟩
    intro s m
    rcases List.mem_cons.mp m with e | m'
    · rw [e]; exact ok1
    · exact ok2 s m'

/-- **The log of a whole connection.** Run on any channel, wrapped by
    `logged` and starting with an empty log, a connection that returns has
    logged exactly a sequence of `StepLog` segments: framing refusals, reads,
    and one segment per served request, each decided for this connection's
    `peer`. -/
theorem connection_logged (ch : Channel C) (io : C) (after : C × List ProxyEvent)
    (h : connection ops pol (logged ch) opener policy (io, []) routes a authority peer limit = Result.ok after) :
    ∃ segs : List (List ProxyEvent), after.2 = segs.flatten ∧ ∀ seg ∈ segs, StepLog ops pol opener policy routes a peer seg := by
  obtain ⟨segs, log, ok⟩ := runs_logged ops pol opener policy routes a authority peer limit ch
    (connection_runs ops pol (logged ch) opener policy routes a authority peer limit _ _ h)
  exact ⟨segs, by simpa using log, ok⟩

/-- Within one segment, a `sent` event comes only from a dispatch decision,
    right after its acknowledged admission. -/
theorem seg_sent {seg : List ProxyEvent} (ok : StepLog ops pol opener policy routes a peer seg) {r : Usize}
    {w : alloc.vec.Vec U8} (m : ProxyEvent.sent r w ∈ seg) :
    ∃ request now opened, decide_request ops pol opener policy request routes a peer now = Result.ok (.dispatch r w opened) ∧
      ∃ A B, seg = A ++ [.admitted opened.claims r true, .sent r w] ++ B := by
  rcases ok with e | ⟨code, bytes, _, e⟩ | ⟨request, now, d, E, served, hd, slog, _, shape⟩
  · subst e; cases m
  · subst e; simp at m
  · have inE : ProxyEvent.sent r w ∈ E := by
      rcases shape with ⟨_, e⟩ | ⟨_, e⟩ <;> subst e <;> simpa using m
    cases d with
    | unauthorized _ => rw [slog] at inE; simp at inE
    | refused _ => rw [slog] at inE; simp at inE
    | dispatch index wire opened =>
      rcases slog with e | e | ⟨status, acked, e⟩
      · subst e; simp at inE
      · subst e
        simp only [List.mem_cons, ProxyEvent.sent.injEq, List.not_mem_nil, or_false, reduceCtorEq,
          false_or] at inE
        obtain ⟨rfl, rfl⟩ := inE
        refine ⟨request, now, opened, hd, ?_⟩
        rcases shape with ⟨_, e⟩ | ⟨_, e⟩ <;> subst e
        · exact ⟨[.began request], [.guestSent served.reply.val], by simp⟩
        · exact ⟨[.began request], [.stopped served.code, .guestSent served.reply.val], by simp⟩
      · subst e
        simp only [List.mem_cons, ProxyEvent.sent.injEq, List.not_mem_nil, or_false, reduceCtorEq,
          false_or] at inE
        obtain ⟨rfl, rfl⟩ := inE
        refine ⟨request, now, opened, hd, ?_⟩
        rcases shape with ⟨_, e⟩ | ⟨_, e⟩ <;> subst e
        · exact ⟨[.began request], [.completed status acked, .guestSent served.reply.val], by simp⟩
        · exact ⟨[.began request], [.completed status acked, .stopped served.code, .guestSent served.reply.val],
            by simp⟩

/-- Whether an event hands credential-bearing bytes to the native sender. -/
def ProxyEvent.isSent : ProxyEvent → Bool
  | .sent _ _ => true
  | _ => false

/-- **No duplicated egress.** A segment — one request — sends at most once:
    there is no retry path. -/
theorem seg_sends_at_most_once {seg : List ProxyEvent} (ok : StepLog ops pol opener policy routes a peer seg) :
    seg.countP ProxyEvent.isSent ≤ 1 := by
  rcases ok with e | ⟨code, bytes, _, e⟩ | ⟨request, now, d, E, served, _, slog, _, shape⟩
  · subst e; simp
  · subst e; simp [ProxyEvent.isSent]
  · have hE : E.countP ProxyEvent.isSent ≤ 1 := by
      cases d with
      | unauthorized _ => rw [slog]; simp [ProxyEvent.isSent]
      | refused _ => rw [slog]; simp
      | dispatch index wire opened =>
        rcases slog with e | e | ⟨_, _, e⟩ <;> subst e <;> simp [List.countP_cons, ProxyEvent.isSent]
    rcases shape with ⟨_, e⟩ | ⟨_, e⟩ <;> subst e <;> simp [List.countP_append, ProxyEvent.isSent] <;> omega

/-- **Every credential-bearing egress of a connection is authorized.** If a
    logged connection returns, every `sent route wire` in its log immediately
    follows the acknowledged `admitted` record of that same request, and that
    request's pre-egress decision was a dispatch of exactly `route` and
    `wire`: the request carried exactly one surrogate, it opened for **this
    connection's `peer`**, the route serves its authenticated provider, and
    `wire` is the extracted encoder's output with the unsealed credential
    (`dispatch_trace`). -/
theorem connection_egress_authorized (ch : Channel C) (io : C) (after : C × List ProxyEvent)
    (h : connection ops pol (logged ch) opener policy (io, []) routes a authority peer limit = Result.ok after)
    {r : Usize} {w : alloc.vec.Vec U8} (m : ProxyEvent.sent r w ∈ after.2) :
    ∃ request now opened, decide_request ops pol opener policy request routes a peer now = Result.ok (.dispatch r w opened) ∧
      (∃ A B, after.2 = A ++ [.admitted opened.claims r true, .sent r w] ++ B) ∧
      ∃ token, surrogate_of (alloc.vec.Vec.deref request.fields) = Result.ok (some token) ∧
        stateless.«open» ops opener (alloc.vec.Vec.deref token) a peer now = Result.ok (.Ok opened) ∧
        ∃ (inside : r.val < routes.length),
          (routes[r.val]'inside).provider.val = opened.claims.provider.val ∧
          proxy_http.encode_upstream (alloc.vec.Vec.new U8) request
            (alloc.vec.Vec.deref (routes[r.val]'inside).host) (alloc.vec.Vec.deref (routes[r.val]'inside).rules)
            (alloc.vec.Vec.deref opened.credential) (routes[r.val]'inside).authentication =
            Result.ok (.Ok (), w) := by
  obtain ⟨segs, log, ok⟩ := connection_logged ops pol opener policy routes a authority peer limit ch io after h
  rw [log] at m ⊢
  obtain ⟨seg, inSegs, inSeg⟩ := List.mem_flatten.mp m
  obtain ⟨request, now, opened, hd, A, B, e⟩ := seg_sent ops pol opener policy routes a peer (ok seg inSegs) inSeg
  obtain ⟨s1, s2, split⟩ := List.append_of_mem inSegs
  refine ⟨request, now, opened, hd, ⟨s1.flatten ++ A, B ++ s2.flatten, ?_⟩,
    dispatch_trace ops pol opener policy request routes a peer now hd⟩
  rw [split, e]
  simp

/-- **Requests without a dispatch decision never reach the provider.** A
    connection's log has no `sent` event for any request whose decision was
    not a dispatch: every `sent` belongs to a dispatched request (above), and
    each request sends at most once. -/
theorem connection_sends_once_per_request (ch : Channel C) (io : C) (after : C × List ProxyEvent)
    (h : connection ops pol (logged ch) opener policy (io, []) routes a authority peer limit = Result.ok after) :
    ∃ segs : List (List ProxyEvent), after.2 = segs.flatten ∧
      ∀ seg ∈ segs, StepLog ops pol opener policy routes a peer seg ∧ seg.countP ProxyEvent.isSent ≤ 1 := by
  obtain ⟨segs, log, ok⟩ := connection_logged ops pol opener policy routes a authority peer limit ch io after h
  exact ⟨segs, log, fun seg m => ⟨ok seg m, seg_sends_at_most_once ops pol opener policy routes a peer (ok seg m)⟩⟩

/-- **What the guest receives.** Every byte string a logged connection writes
    to the guest is a fixed framing refusal, or the reply of a request served
    for this connection's peer, which is the fixed `401`, a fixed refusal, or a
    `guest_response` release in which the raw credential does not occur
    (`serve_guest_reply`). -/
theorem connection_guest_bytes (ch : Channel C) (io : C) (after : C × List ProxyEvent)
    (h : connection ops pol (logged ch) opener policy (io, []) routes a authority peer limit = Result.ok after)
    {bytes : List U8} (m : ProxyEvent.guestSent bytes ∈ after.2) :
    (∃ code refusal, proxy_http.refusal code = Result.ok refusal ∧ bytes = refusal.val) ∨
    ∃ request now served, GuestReply ops pol opener policy routes a peer request now served ∧ bytes = served.reply.val := by
  obtain ⟨segs, log, ok⟩ := connection_logged ops pol opener policy routes a authority peer limit ch io after h
  rw [log] at m
  obtain ⟨seg, inSegs, inSeg⟩ := List.mem_flatten.mp m
  rcases ok seg inSegs with e | ⟨code, refusal, hr, e⟩ | ⟨request, now, d, E, served, _, slog, reply, shape⟩
  · subst e; cases inSeg
  · subst e
    simp only [List.mem_cons, reduceCtorEq, ProxyEvent.guestSent.injEq, List.not_mem_nil, or_false,
      false_or] at inSeg
    exact Or.inl ⟨code, refusal, hr, inSeg⟩
  · refine Or.inr ⟨request, now, served, reply, ?_⟩
    have noneE : ∀ b, ProxyEvent.guestSent b ∉ E := by
      intro b mb
      cases d with
      | unauthorized _ => rw [slog] at mb; simp at mb
      | refused _ => rw [slog] at mb; simp at mb
      | dispatch index wire opened =>
        rcases slog with e | e | ⟨_, _, e⟩ <;> subst e <;> simp at mb
    rcases shape with ⟨_, e⟩ | ⟨_, e⟩ <;> subst e <;>
      simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false, reduceCtorEq, false_or,
        ProxyEvent.guestSent.injEq] at inSeg <;>
      rcases inSeg with inE | same
    all_goals first | exact absurd inE (noneE _) | exact same

end aivm_secrets_garrett_core.stateless_proxy.Proofs
