import GarrettStatelessProtocol

/-!
# `garrett-stateless-v1`: the strict stateless profile

Garrett's architecture keeps no state but the keys. This profile has exactly
one piece of mutable process state, the broker's transient login mailbox
(`stateless_mailbox.rs`), and only the OAuth acquisition adapter uses it. A
**strict** broker configures no OAuth provider, so its login policy names no
provider (`garrett-stateless` builds `LoginPolicy.providers` from the OAuth
providers only, and a strict configuration refuses every OAuth provider).

Proved here, over every history of the extracted transitions:

* `no_providers_no_state`: when the login policy names no provider, every
  reachable mailbox is the empty one and the login history has no event —
  whatever the agents and browsers send, in any order;
* `strict_no_login_state`: the same for every reachable world of the whole
  protocol model, so in a strict deployment the broker's only inputs to a
  decision are its keys, its configuration, the request, the authenticated
  peer and the clock.

The proxy has no mutable state in the model at all: `Step.serve` takes no
part of the world, and `stateless_proxy.Proofs.replicas_differ_only_by_answers`
shows two proxies decide alike and differ only through their adapters'
answers.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.stateless_token
open garrett_stateless_core.stateless_token.base64 garrett_stateless_core.stateless_token.grammar
  garrett_stateless_core.stateless_token.json garrett_stateless_core.stateless_token.payload
  garrett_stateless_core.stateless_token.keys garrett_stateless_core.stateless_token.opening
  garrett_stateless_core.stateless_token.sealing garrett_stateless_core.stateless_token.login_state

namespace garrett_stateless_core.stateless_protocol

open stateless_mailbox.Proofs

theorem empty_of {mb : stateless_mailbox.Mailbox} (slots : mb.slots.val = []) (next : mb.next = 0#u64) :
    stateless_mailbox.empty = Result.ok mb := by
  obtain ⟨v, n⟩ := mb
  simp only at slots next
  subst next
  have : alloc.vec.Vec.new (Option stateless_mailbox.Slot) = v := alloc.vec.Vec.ext _ _ (by simpa using slots.symm)
  simp [stateless_mailbox.empty, this]

/-- **No login provider, no login state.** If the login policy names no
    provider, every reachable mailbox is empty and no login event happened. -/
theorem no_providers_no_state {S : Type} {ops : stateless.SurrogateSealer S}
    {policy : stateless_login.LoginPolicy} (none : policy.providers.val = [])
    {c : stateless_mailbox.Mailbox × List stateless_mailbox.Proofs.Event}
    (reach : stateless_mailbox.Proofs.Reachable ops policy c) :
    stateless_mailbox.empty = Result.ok c.1 ∧ c.2 = [] := by
  induction reach with
  | init made => exact ⟨made, rfl⟩
  | step _ move ih =>
    obtain ⟨e, h⟩ := ih
    cases move with
    | @start mb H provider peer subject ce login verifier scope now r mb' run =>
      simp only [stateless_mailbox.empty, Result.ok.injEq] at e
      simp only at h
      subst e h
      rcases start_effect run with ⟨next, slots, notOk⟩ | ⟨st, _, spec, _⟩
      · cases r with
        | Ok st => exact absurd rfl (notOk st)
        | Err _ =>
          refine ⟨empty_of ?_ next, by simp [startEvents]⟩
          rcases slots with s | s <;> simpa [alloc.vec.Vec.new] using s
      · obtain ⟨_, _, ⟨x, inSet, _⟩, _⟩ := spec
        simp [alloc.vec.Vec.deref, none] at inSet
    | pending run => exact ⟨e, h⟩
    | @accept mb H st rule issuer has denied now r mb' run =>
      simp only [stateless_mailbox.empty, Result.ok.injEq] at e
      simp only at h
      subst e h
      obtain ⟨next, rest⟩ := accept_effect run
      rcases rest with ⟨slots, notOk⟩ | ⟨k, hk, _⟩
      · cases r with
        | Ok p => exact absurd rfl (notOk p)
        | Err _ => exact ⟨empty_of (by simpa [alloc.vec.Vec.new] using slots) next, by simp [acceptEvents]⟩
      · simp [alloc.vec.Vec.new] at hk
    | exchange inst x held =>
      simp only at h
      subst h
      simp at held
    | finish held =>
      simp only at h
      subst h
      simp at held
    | @poll mb H peer login now r mb' run =>
      simp only [stateless_mailbox.empty, Result.ok.injEq] at e
      simp only at h
      subst e h
      obtain ⟨next, rest⟩ := poll_effect run
      rcases rest with ⟨slots, notReady⟩ | ⟨k, hk, _⟩
      · refine ⟨empty_of (by simpa [alloc.vec.Vec.new] using slots) next, ?_⟩
        cases r with
        | Ready t x n => exact absurd rfl (notReady t x n)
        | _ => simp [pollEvents]
      · simp [alloc.vec.Vec.new] at hk

/-- **A strict broker holds no login state.** In every reachable world of the
    protocol model whose login policy names no provider, the mailbox is the
    empty one and no login event happened: the renewals, mints and proxy
    connections of that world were decided from keys, configuration,
    request, peer and clock alone. -/
theorem strict_no_login_state {M : Type} {inst : KeyMaterial M} {Paired : M → M → Prop} {P : Type} {cfg : Config P}
    (none : cfg.login.providers.val = []) {W : World M} (reach : Reachable inst Paired cfg W) :
    stateless_mailbox.empty = Result.ok W.mb ∧ W.logins = [] :=
  no_providers_no_state none (mailbox_reachable reach)

end garrett_stateless_core.stateless_protocol
