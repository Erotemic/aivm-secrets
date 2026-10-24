import GarrettOAuth

/-! # OAuth and identity service history

A finite history model of one subject's durable state: the OAuth vault
record and the identity registry row. It covers OAuth enrollment, refresh and
revocation together with identity enrollment and revocation, and it includes
blocked dispatch, crashes and uncertain publication. Every dispatch is gated
by the extracted `oauth_state.require_current_lease`, the function the native
current-session path calls, not by a model of it.

What the model takes from the implementation (the adapter postconditions):

* Every event is one atomic durable write under the vault lock (`.vault.lock`
  serializes refresh, revoke, enrollment and dispatch admission), so
  concurrent operations are an interleaving of these events.
* A refresh is the extracted `refresh_once`: `refresh_order_contract` shows it
  writes `InDoubt` (`quarantine`) before any exchange and returns a successor
  only after `commit` wrote it as `Ready`. Here that is a `quarantine` event
  followed by `commit` or `settle`.
* A crash loses only volatile state: the in-flight refresh. Its durable
  `InDoubt` stays. Uncertain publication of a commit is a history with the
  `commit` event and a history without it; the theorems hold for both,
  because they hold for every history.
* A dispatch reads the durable record it is admitted against (the held
  `CurrentCredential` lock) and the registry row the identity verifier
  checks. The registry is modelled as active flag plus epoch; certificate
  validity and the cryptographic checks are the separate verifier proofs.

The theorems are about this model. They do not prove that the native
storage, locking or clock adapters meet the postconditions above.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core
open aivm_secrets_garrett_core.oauth_state
open aivm_secrets_garrett_core.oauth_state.Proofs

namespace Garrett.ServiceHistory

-- The extracted gate returns a `Result`, whose equality is not decidable
-- (it is coinductive); the model only needs it as a proposition.
noncomputable section
attribute [local instance] Classical.propDecidable

structure Vault where
  active : Bool
  state : RefreshState
  lease : LeaseMeta

structure Registry where
  active : Bool
  epoch : Nat

/-- Durable state plus the one volatile item: the prior state of a refresh
    whose `quarantine` landed but which has not committed or settled. -/
structure World where
  vault : Vault
  registry : Registry
  inflight : Option RefreshState

/-- What a guest session was started with. -/
structure Session where
  vaultEpoch : I64
  identityEpoch : Nat

inductive Event where
  /-- OAuth (re)enrollment; the vault refuses one that does not advance the epoch. -/
  | enroll (lease : LeaseMeta)
  | revoke
  /-- `refresh_once` reached its durable quarantine. -/
  | quarantine (retry : Bool)
  /-- The successor was written (`commit` succeeded). -/
  | commit (generation expires : I64)
  /-- A failure that `refresh_once` settles: not sent or rejected. -/
  | settle (failure : ExchangeFailure)
  | crash
  | identityEnroll
  | identityRevoke
  | dispatch (session : Session) (now : I64)

/-- One emitted provider request, with the state it was admitted against. -/
structure Emitted where
  world : World
  session : Session
  now : I64

/-- The extracted lease gate, as the dispatch admission runs it. -/
def leaseAdmits (v : Vault) (s : Session) (now : I64) : Prop :=
  require_current_lease v.active v.state v.lease s.vaultEpoch now = Result.ok (.Ok ())

def identityAdmits (r : Registry) (s : Session) : Prop :=
  r.active = true ∧ r.epoch = s.identityEpoch

/-- Which refreshes may start: the same condition `permit_refresh` checks
    (the generation bound is omitted; it only refuses more). -/
def mayQuarantine (v : Vault) (retry : Bool) : Bool :=
  v.active && (match v.state with
    | .Ready => true
    | .InDoubt => retry
    | .Reauthorize => false)

/-- The durable state `refresh_once` settles to, as `settled_failure` gives it. -/
def settledState (prior : RefreshState) : ExchangeFailure → RefreshState
  | .NotSent => prior
  | .Rejected => .Reauthorize
  | .Uncertain => .InDoubt

/-- One step. A refused operation changes nothing and emits nothing. -/
def step (w : World) : Event → World × Option Emitted
  | .enroll lease =>
    if w.vault.lease.epoch.val < lease.epoch.val then
      ({ w with vault := ⟨true, .Ready, lease⟩, inflight := none }, none)
    else (w, none)
  | .revoke => ({ w with vault := { w.vault with active := false }, inflight := none }, none)
  | .quarantine retry =>
    if w.inflight.isNone && mayQuarantine w.vault retry then
      ({ w with vault := { w.vault with state := .InDoubt }, inflight := some w.vault.state }, none)
    else (w, none)
  | .commit generation expires =>
    match w.inflight with
    | some _ =>
      ({ w with vault := { w.vault with state := .Ready,
                                        lease := { w.vault.lease with generation, expires_at := expires } },
                inflight := none }, none)
    | none => (w, none)
  | .settle failure =>
    match w.inflight with
    | some prior =>
      ({ w with vault := { w.vault with state := settledState prior failure }, inflight := none }, none)
    | none => (w, none)
  | .crash => ({ w with inflight := none }, none)
  | .identityEnroll => ({ w with registry := ⟨true, w.registry.epoch + 1⟩ }, none)
  | .identityRevoke => ({ w with registry := { w.registry with active := false } }, none)
  | .dispatch s now =>
    if leaseAdmits w.vault s now ∧ identityAdmits w.registry s then
      (w, some ⟨w, s, now⟩)
    else (w, none)

/-- Run a history; returns the final state and every emitted request in order. -/
def run (w : World) : List Event → World × List Emitted
  | [] => (w, [])
  | e :: rest =>
    let (w', out) := step w e
    let (final, emitted) := run w' rest
    (final, out.toList ++ emitted)

theorem lease_admits_iff (v : Vault) (s : Session) (now : I64) :
    leaseAdmits v s now ↔ CurrentLeaseAllowed v.active v.state v.lease s.vaultEpoch now := by
  obtain ⟨out, eq, post⟩ := aivm_secrets_garrett_core.Proofs.returned_of_spec
    (current_lease_contract v.active v.state v.lease s.vaultEpoch now)
  unfold leaseAdmits
  rw [eq, Result.ok.injEq]
  exact post

/-- What every emitted request had at the step it was emitted. -/
def Admitted (e : Emitted) : Prop :=
  e.world.vault.active = true ∧ e.world.vault.state = .Ready ∧
  e.world.vault.lease.epoch = e.session.vaultEpoch ∧
  0 ≤ e.now.val ∧ e.now.val < e.world.vault.lease.expires_at.val ∧
  e.world.registry.active = true ∧ e.world.registry.epoch = e.session.identityEpoch ∧
  e.world.inflight = none

/-- In the reachable worlds, an in-flight refresh always has `InDoubt` durably. -/
def Consistent (w : World) : Prop := w.inflight ≠ none → w.vault.state = .InDoubt

theorem step_consistent (w : World) (e : Event) (h : Consistent w) :
    Consistent (step w e).1 := by
  unfold Consistent at *
  cases e with
  | enroll lease => simp only [step]; split <;> simp_all
  | revoke => simp [step]
  | quarantine retry => simp only [step]; split <;> simp_all
  | commit g x => simp only [step]; split <;> simp_all
  | settle f => simp only [step]; split <;> simp_all
  | crash => simp [step]
  | identityEnroll => simpa [step] using h
  | identityRevoke => simpa [step] using h
  | dispatch s now => simp only [step]; split <;> simp_all

theorem step_emitted_admitted (w : World) (e : Event) (x : Emitted) (h : Consistent w)
    (out : (step w e).2 = some x) : Admitted x := by
  cases e with
  | dispatch s now =>
    simp only [step] at out
    split at out
    · rename_i gate
      cases out
      obtain ⟨lease, identity⟩ := gate
      obtain ⟨active, ready, epoch, lo, hi⟩ := (lease_admits_iff _ _ _).mp lease
      refine ⟨active, ready, epoch, lo, hi, identity.1, identity.2, ?_⟩
      by_contra pending
      exact absurd (h pending) (by simp [ready])
    · cases out
  | enroll lease => simp only [step] at out; split at out <;> cases out
  | revoke => simp [step] at out
  | quarantine r => simp only [step] at out; split at out <;> cases out
  | commit g x => simp only [step] at out; split at out <;> cases out
  | settle f => simp only [step] at out; split at out <;> cases out
  | crash => simp [step] at out
  | identityEnroll => simp [step] at out
  | identityRevoke => simp [step] at out

/-- **Every emitted request had a current admitted identity and a current
    credential lease at its own step**, in every history, from any consistent
    start: enrollment, re-enrollment, revocation, refresh, crashes and
    uncertain publication included. -/
theorem every_emission_admitted (w : World) (events : List Event) (h : Consistent w) :
    ∀ x ∈ (run w events).2, Admitted x := by
  induction events generalizing w with
  | nil => simp [run]
  | cons e rest ih =>
    intro x hx
    simp only [run] at hx
    rcases List.mem_append.mp hx with here | later
    · cases hout : (step w e).2 with
      | none => simp [hout] at here
      | some y =>
        simp [hout] at here
        subst here
        exact step_emitted_admitted w e _ h hout
    · exact ih _ (step_consistent w e h) x later

/-! ## Fencing across the history -/

/-- The vault epoch never decreases. -/
theorem step_epoch_monotone (w : World) (e : Event) :
    w.vault.lease.epoch.val ≤ (step w e).1.vault.lease.epoch.val := by
  cases e with
  | enroll lease => simp only [step]; split <;> simp_all; omega
  | revoke => simp [step]
  | quarantine r => simp only [step]; split <;> simp_all
  | commit g x => simp only [step]; split <;> simp_all
  | settle f => simp only [step]; split <;> simp_all
  | crash => simp [step]
  | identityEnroll => simp [step]
  | identityRevoke => simp [step]
  | dispatch s now => simp only [step]; split <;> simp_all

theorem step_identity_epoch_monotone (w : World) (e : Event) :
    w.registry.epoch ≤ (step w e).1.registry.epoch := by
  cases e <;> simp only [step] <;> (try split) <;> simp_all

/-- Revocation is terminal for a lease epoch: after the vault is inactive,
    it becomes active again only through an enrollment, which advances the
    epoch. So a session bound to the revoked epoch can never emit again. -/
def Fenced (w : World) (s : Session) : Prop :=
  w.vault.active = false ∧ w.vault.lease.epoch = s.vaultEpoch ∨
  s.vaultEpoch.val < w.vault.lease.epoch.val

theorem fenced_step (w : World) (e : Event) (s : Session) (h : Fenced w s) :
    Fenced (step w e).1 s := by
  unfold Fenced at *
  cases e with
  | enroll lease =>
    simp only [step]; split
    · rename_i advanced
      right; dsimp only
      rcases h with ⟨_, eq⟩ | lt
      · rw [← eq]; exact advanced
      · omega
    · exact h
  | revoke =>
    rcases h with ⟨_, eq⟩ | lt
    · left; simp [step, eq]
    · right; simpa [step] using lt
  | quarantine r => simp only [step]; split <;> simp_all
  | commit g x => simp only [step]; split <;> simp_all
  | settle f => simp only [step]; split <;> simp_all
  | crash => simpa [step] using h
  | identityEnroll => simpa [step] using h
  | identityRevoke => simpa [step] using h
  | dispatch s now => simp only [step]; split <;> simp_all

theorem fenced_never_emits (w : World) (e : Event) (s : Session) (h : Fenced w s) :
    ∀ x, (step w e).2 = some x → x.session ≠ s := by
  intro x out same
  cases e with
  | dispatch s' now =>
    simp only [step] at out
    split at out
    · rename_i gate
      cases out
      subst same
      obtain ⟨active, _, epoch, _⟩ := (lease_admits_iff _ _ _).mp gate.1
      rcases h with ⟨inactive, _⟩ | lt
      · simp_all
      · have := congrArg (fun i : I64 => i.val) epoch; simp only at this lt; omega
    · cases out
  | enroll l => simp only [step] at out; split at out <;> cases out
  | revoke => simp [step] at out
  | quarantine r => simp only [step] at out; split at out <;> cases out
  | commit g x => simp only [step] at out; split at out <;> cases out
  | settle f => simp only [step] at out; split at out <;> cases out
  | crash => simp [step] at out
  | identityEnroll => simp [step] at out
  | identityRevoke => simp [step] at out

/-- **Revocation fences forever:** once a session's lease epoch is revoked (or
    superseded by re-enrollment), no later step of any history emits a request
    for that session. -/
theorem fenced_session_never_emits (w : World) (events : List Event) (s : Session)
    (h : Fenced w s) : ∀ x ∈ (run w events).2, x.session ≠ s := by
  induction events generalizing w with
  | nil => simp [run]
  | cons e rest ih =>
    intro x hx
    simp only [run] at hx
    rcases List.mem_append.mp hx with here | later
    · cases hout : (step w e).2 with
      | none => simp [hout] at here
      | some y =>
        simp [hout] at here
        subst here
        exact fenced_never_emits w e s h _ hout
    · exact ih _ (fenced_step w e s h) x later

theorem revoke_fences (w : World) (s : Session) (bound : w.vault.lease.epoch = s.vaultEpoch) :
    Fenced (step w .revoke).1 s := by
  left; simp [step, bound]

/-- The same for identity: a session whose identity epoch was revoked or
    superseded never emits again. -/
def IdentityFenced (w : World) (s : Session) : Prop :=
  w.registry.active = false ∧ w.registry.epoch = s.identityEpoch ∨
  s.identityEpoch < w.registry.epoch

theorem identity_fenced_step (w : World) (e : Event) (s : Session) (h : IdentityFenced w s) :
    IdentityFenced (step w e).1 s := by
  unfold IdentityFenced at *
  cases e with
  | identityEnroll => right; simp [step]; omega
  | identityRevoke =>
    rcases h with ⟨_, eq⟩ | lt
    · left; simp [step, eq]
    · right; simpa [step] using lt
  | enroll l => simp only [step]; split <;> simp_all
  | revoke => simpa [step] using h
  | quarantine r => simp only [step]; split <;> simp_all
  | commit g x => simp only [step]; split <;> simp_all
  | settle f => simp only [step]; split <;> simp_all
  | crash => simpa [step] using h
  | dispatch s now => simp only [step]; split <;> simp_all

theorem identity_fenced_session_never_emits (w : World) (events : List Event) (s : Session)
    (h : IdentityFenced w s) : ∀ x ∈ (run w events).2, x.session ≠ s := by
  induction events generalizing w with
  | nil => simp [run]
  | cons e rest ih =>
    intro x hx
    simp only [run] at hx
    rcases List.mem_append.mp hx with here | later
    · cases hout : (step w e).2 with
      | none => simp [hout] at here
      | some y =>
        simp [hout] at here
        subst here
        intro same
        cases e with
        | dispatch s' now =>
          simp only [step] at hout
          split at hout
          · rename_i gate
            cases hout
            subst same
            rcases h with ⟨inactive, _⟩ | lt
            · simp_all [identityAdmits]
            · have := gate.2.2; simp only at lt; omega
          · cases hout
        | enroll l => simp only [step] at hout; split at hout <;> cases hout
        | revoke => simp [step] at hout
        | quarantine r => simp only [step] at hout; split at hout <;> cases hout
        | commit g x => simp only [step] at hout; split at hout <;> cases hout
        | settle f => simp only [step] at hout; split at hout <;> cases hout
        | crash => simp [step] at hout
        | identityEnroll => simp [step] at hout
        | identityRevoke => simp [step] at hout
    · exact ih _ (identity_fenced_step w e s h) x later

/-! ## Uncertain refresh -/

/-- Until a refresh settles, nothing is emitted: a quarantined refresh blocks
    dispatch, and after a crash the durable `InDoubt` keeps blocking. -/
theorem in_doubt_blocks (w : World) (s : Session) (now : I64)
    (h : w.vault.state = .InDoubt) : (step w (.dispatch s now)).2 = none := by
  simp only [step]
  split
  · rename_i gate
    have := ((lease_admits_iff _ _ _).mp gate.1).2.1
    simp_all
  · rfl

/-- After a crash, `InDoubt` is left only through an explicit retry
    (`quarantine true`) or a fresh enrollment: no plain refresh, settle or
    commit moves it. -/
theorem crash_leaves_in_doubt (w : World) (h : w.vault.state = .InDoubt) :
    let c := (step w .crash).1
    (step c (.quarantine false)).1.vault.state = .InDoubt ∧
    (∀ f, (step c (.settle f)).1.vault.state = .InDoubt) ∧
    (∀ g x, (step c (.commit g x)).1.vault.state = .InDoubt) := by
  simp [step, mayQuarantine, h]

/-- A rejected refresh needs reauthorization: no refresh can start and no
    dispatch is admitted until the vault is enrolled again. -/
theorem rejected_needs_reauthorization (w : World) (s : Session) (now : I64) (retry : Bool)
    (h : w.vault.state = .Reauthorize) :
    (step w (.dispatch s now)).2 = none ∧ (step w (.quarantine retry)).1 = w := by
  constructor
  · simp only [step]
    split
    · rename_i gate
      have := ((lease_admits_iff _ _ _).mp gate.1).2.1
      simp_all
    · rfl
  · simp [step, mayQuarantine, h]

/-! ## The model is not vacuous -/

def start : World :=
  ⟨⟨true, .Ready, ⟨1#i64, 0#i64, 4000#i64⟩⟩, ⟨true, 1⟩, none⟩

def session : Session := ⟨1#i64, 1⟩

/-- A refresh that commits keeps the session usable; a revoke then stops it. -/
theorem positive_and_fenced_witness :
    (run start [.dispatch session 1000#i64, .quarantine false, .dispatch session 1000#i64,
                .commit 1#i64 5000#i64, .dispatch session 4500#i64, .revoke,
                .dispatch session 4500#i64]).2.map (·.now) = [1000#i64, 4500#i64] := by
  simp [run, step, start, session, leaseAdmits, identityAdmits, mayQuarantine,
    require_current_lease, require_lease]

end

end Garrett.ServiceHistory
