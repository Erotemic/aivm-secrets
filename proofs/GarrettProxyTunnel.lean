import GarrettProxyController
import GarrettProxyParse

/-!
# PROXY-NATIVE-01: the guest tunnel loop of the substitution proxy

Source: `rust/crates/aivm-secrets-garrett-core/src/proxy_controller.rs`
(`step`, `tunnel`, `remainder`), extracted by Aeneas. After a CONNECT is
admitted, `garrett-proxy` runs `proxy_controller::tunnel` and supplies only
five callbacks (`Guest`): the request deadline (`overdue`), socket reads and
writes (`read`, `send`), the refusal audit (`refused`) and the per-request
server (`serve`, which calls the extracted `serve`).

Proved here, for **any** callbacks:

* `tunnel_starts_empty`, `tunnel_loop_closed`, `tunnel_loop_open`: a tunnel
  starts with no buffered bytes and runs `step` until a step closes it;
* `step_paths`: each step does exactly one of four things. It closes on an
  overdue partial request. It refuses what `frame` refuses (audit first, then
  only the fixed refusal is written). It appends exactly the bytes read. Or
  it serves **exactly** the request `frame` parsed, writes **exactly** that
  answer, and keeps exactly the bytes after the ones the request used;
* `step_request_fits`: on 64-bit-sized inputs, a served request used no more
  bytes than were buffered, so the kept bytes are a true suffix.

Together with `frame_paths` (only the strict parser's requests are served)
and `serve_guest_reply`, the guest receives only fixed refusals and
controller replies.

Still assumed (`PROXY-NATIVE-01`): that the callbacks do what they say (the
native `read` returns only bytes from this guest's TLS stream, `send` writes
its argument and nothing else, `serve` is the extracted `serve` with this
session's policy), TLS, sockets and the clock.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs

namespace aivm_secrets_garrett_core.proxy_controller.Proofs

open aivm_secrets_garrett_core.proxy_http.Proofs (bind_ok_inv)

/-- `remainder` keeps exactly the bytes from `used` on. -/
theorem remainder_val (buffer : Slice U8) (used : Usize) (rest : alloc.vec.Vec U8)
    (h : remainder buffer used = Result.ok rest) : rest.val = buffer.val.drop used.val := by
  unfold remainder at h
  dsimp only at h
  split at h
  · rename_i inside
    obtain ⟨piece, sliced, h⟩ := bind_ok_inv h
    have within : used.val ≤ buffer.length := by scalar_tac
    simp only [core.slice.index.Slice.index, core.slice.index.SliceIndexRangeFromUsizeSlice.index,
      within, ↓reduceIte,
      Result.ok.injEq] at sliced
    have := aivm_secrets_garrett_core.route.Proofs.extend_ok_val h
    rw [this, ← sliced]
    simp [alloc.vec.Vec.new]
  · rename_i past
    simp only [Result.ok.injEq] at h
    subst h
    have : buffer.val.length ≤ used.val := by scalar_tac
    simp [alloc.vec.Vec.new, List.drop_eq_nil_of_le this]

/-- What one step does once the deadline check has passed (or was skipped
    because nothing is buffered): `io` is the callback state at that point. -/
def Stepped {G : Type} (inst : Guest G) (io : G) (buffer : alloc.vec.Vec U8) (host : Slice U8) (limit : Usize)
    (out : Tunnel) (after : G) : Prop :=
  ∃ framed, frame (alloc.vec.Vec.deref buffer) host limit = Result.ok framed ∧
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
      ∃ answer io1 sent, inst.serve io parsed.request = Result.ok (answer, io1) ∧
        inst.send io1 (alloc.vec.Vec.deref answer.reply) = Result.ok (sent, after) ∧
        out.buffer.val = buffer.val.drop parsed.used.val ∧ out.open = (sent && answer.keep)

/-- An `if` that returned: which branch, and what it returned. Applied by
    unification, so it also sees through the pair bindings Aeneas emits. -/
theorem ite_ok_inv {α : Type} {c : Prop} [Decidable c] {a b : Result α} {x : α}
    (h : (if c then a else b) = Result.ok x) : (c ∧ a = Result.ok x) ∨ (¬ c ∧ b = Result.ok x) := by
  split at h
  · exact Or.inl ⟨‹_›, h⟩
  · exact Or.inr ⟨‹_›, h⟩

theorem ok_pair_inv {α β : Type} {a c : α} {b d : β}
    (h : (Result.ok (a, b) : Result (α × β)) = Result.ok (c, d)) : a = c ∧ b = d :=
  Prod.mk.inj (Result.ok_injective h)

-- The step after its deadline check, shared by both branches of `step`.
-- Every inversion is by unification (`bind_ok_inv`, `ite_ok_inv`,
-- `ok_pair_inv`), which reduces the pair bindings `simp` cannot.
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
    obtain ⟨⟨answer, io2⟩, sv, h⟩ := bind_ok_inv h
    obtain ⟨⟨sent, io3⟩, sd, h⟩ := bind_ok_inv h
    have kept := remainder_val _ _ _ rem
    refine ⟨answer, io2, sent, sv, ?_⟩
    cases sent <;>
    · obtain ⟨hout, hafter⟩ := ok_pair_inv h
      subst hout hafter
      refine ⟨sd, by simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using kept, ?_⟩
      simp))

/-- **One tunnel step.** With nothing buffered the deadline is not consulted;
    otherwise an overdue partial request closes the tunnel and nothing else
    happens. Past the deadline check, `Stepped` says exactly which callbacks
    ran, with which arguments. -/
theorem step_paths {G : Type} (inst : Guest G) (io : G) (buffer : alloc.vec.Vec U8) (host : Slice U8)
    (limit : Usize) (out : Tunnel) (after : G)
    (h : step inst io buffer host limit = Result.ok (out, after)) :
    (buffer.length = 0 ∧ Stepped inst io buffer host limit out after) ∨
    (buffer.length ≠ 0 ∧ inst.overdue io = Result.ok (true, after) ∧
      out.buffer = buffer ∧ out.open = false) ∨
    (buffer.length ≠ 0 ∧ ∃ io1, inst.overdue io = Result.ok (false, io1) ∧
      Stepped inst io1 buffer host limit out after) := by
  unfold step at h
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

/-- **A served request is a true prefix of the buffer.** When `frame` hands a
    request to `step`, it used no more bytes than were buffered (on inputs far
    from the `usize` bound), so `step` keeps exactly the bytes after it and
    nothing is lost or served twice; its body is within the request limit. -/
theorem step_request_fits {buffer : alloc.vec.Vec U8} {host : Slice U8} {limit : Usize}
    {parsed : proxy_http.Parsed}
    (small : buffer.length + 16 ^ 8 + 4 ≤ Usize.max) (bounded : limit.val + 16 ^ 8 ≤ Usize.max)
    (h : frame (alloc.vec.Vec.deref buffer) host limit = Result.ok (.Request parsed)) :
    parsed.used.val ≤ buffer.length ∧ parsed.request.body.length ≤ limit.val ∧
      (buffer.val.take parsed.used.val).length = parsed.used.val := by
  obtain ⟨bound, _, paths⟩ := frame_paths h
  rcases paths with ⟨_, refused⟩ | ⟨_, result, parsed_ok, shape⟩
  · cases refused
  · cases result with
    | Err refused =>
      obtain ⟨_, code, hcode⟩ := shape
      cases hcode
    | Ok o =>
      cases o with
      | none => cases shape
      | some request =>
        cases shape
        have := aivm_secrets_garrett_core.proxy_http.Proofs.parse_request_bounds
          (data := alloc.vec.Vec.deref buffer)
          (by simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using small) bounded parsed_ok
        refine ⟨by simpa using this.1, this.2, ?_⟩
        simp only [List.length_take]
        have : parsed.used.val ≤ buffer.val.length := by simpa using this.1
        omega

/-- A tunnel starts with nothing buffered. -/
theorem tunnel_starts_empty {G : Type} (inst : Guest G) (io : G) (host : Slice U8) (limit : Usize) :
    tunnel inst io host limit =
      tunnel_loop inst io host limit { buffer := alloc.vec.Vec.new U8, «open» := true } := rfl

/-- A closed tunnel does nothing more. -/
theorem tunnel_loop_closed {G : Type} (inst : Guest G) (io : G) (host : Slice U8) (limit : Usize)
    (state : Tunnel) (closed : state.open = false) :
    tunnel_loop inst io host limit state = Result.ok io := by
  rw [tunnel_loop.eq_def]
  simp [closed]

/-- An open tunnel runs one `step` on its buffer, then continues from there. -/
theorem tunnel_loop_open {G : Type} (inst : Guest G) (io : G) (host : Slice U8) (limit : Usize)
    (state : Tunnel) (opened : state.open = true) :
    tunnel_loop inst io host limit state =
      (step inst io state.buffer host limit >>= fun next =>
        tunnel_loop inst next.2 host limit next.1) := by
  rw [tunnel_loop.eq_def]
  simp only [opened, ↓reduceIte]
  rfl

end aivm_secrets_garrett_core.proxy_controller.Proofs
