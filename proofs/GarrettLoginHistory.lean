import GarrettLogin

/-! # OAuth login (acquisition) histories

One native `garrett-oauth login` run, as a finite history. The process holds
the pending authorization (state, PKCE verifier, window) and its stage in
memory, so a crash ends the login: a new one needs a new state value. Each
event runs the extracted decision the native driver calls
(`oauth_vault/login.rs`):

* a callback runs `claim` on the current stage;
* starting the token exchange runs `begin`;
* the exchange's end runs `finish` with whether the grant was installed.

In every history: at most one token exchange is ever started, it comes after a
callback bound to the pending state, issuer rule and window, and a grant is
installed at most once and only by that exchange. Nothing happens after a
crash.

Trusted, not proved: the loopback listener delivers parsed callbacks, the
token exchange and vault install are the TLS and storage adapters, and one
process runs one login.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core
open aivm_secrets_garrett_core.oauth_login
open aivm_secrets_garrett_core.oauth_login.Proofs
open aivm_secrets_garrett_core.Proofs

namespace Garrett.LoginHistory

noncomputable section
attribute [local instance] Classical.propDecidable

variable (p : Pending)

/-- The login's in-memory state; `none` once the process has crashed. -/
structure World where
  stage : Option Stage
  /-- The callback whose claim was accepted, kept for the theorems. -/
  claimed : Option (Callback × I64)

inductive Event where
  | callback (cb : Callback) (now : I64)
  | begin (now : I64)
  | finish (installed : Bool)
  | crash

/-- What leaves the host: the token exchange, and the vault install. -/
inductive Effect where
  | exchange (cb : Callback) (claimedAt now : I64)
  | install

/-- The next stage an extracted decision returns, if it returns one. -/
def next (r : Result (core.result.Result Stage LoginDenial)) : Option Stage :=
  if h : ∃ s, r = Result.ok (.Ok s) then some (Classical.choose h) else none

theorem next_eq (r : Result (core.result.Result Stage LoginDenial)) (s : Stage) :
    next r = some s ↔ r = Result.ok (.Ok s) := by
  unfold next
  constructor
  · intro h
    split at h
    · rename_i ex; cases h; exact Classical.choose_spec ex
    · cases h
  · intro h
    split
    · rename_i ex
      have e := (Classical.choose_spec ex).symm.trans h
      rw [Result.ok.injEq] at e
      simp only [core.result.Result.Ok.injEq] at e
      rw [e]
    · rename_i none_
      exact absurd ⟨s, h⟩ none_

def step (p : Pending) (w : World) : Event → World × Option Effect
  | .callback cb now =>
    match w.stage with
    | some stage =>
      match next (claim stage p cb now) with
      | some s => ({ stage := some s, claimed := some (cb, now) }, none)
      | none => (w, none)
    | none => (w, none)
  | .begin now =>
    match w.stage, w.claimed with
    | some stage, some (cb, at_) =>
      match next (oauth_login.begin stage p now) with
      | some s => ({ w with stage := some s }, some (.exchange cb at_ now))
      | none => (w, none)
    | _, _ => (w, none)
  | .finish installed =>
    match w.stage with
    | some stage =>
      match next (oauth_login.finish stage installed) with
      | some s => ({ w with stage := some s }, if installed then some .install else none)
      | none => (w, none)
    | none => (w, none)
  | .crash => ({ w with stage := none }, none)

def run (p : Pending) (w : World) : List Event → World × List Effect
  | [] => (w, [])
  | e :: rest =>
    let (w', out) := step p w e
    let (final, effects) := run p w' rest
    (final, out.toList ++ effects)

def initial : World := ⟨some .Pending, none⟩

def isExchange : Effect → Bool
  | .exchange .. => true
  | .install => false

def isInstall : Effect → Bool
  | .exchange .. => false
  | .install => true

theorem claim_from (stage : Stage) (cb : Callback) (now : I64) (s : Stage)
    (h : next (claim stage p cb now) = some s) :
    Bound stage p cb now ∧ s = (if cb.denied then .Denied else .Accepted) := by
  have h := (next_eq _ _).mp h
  obtain ⟨out, eq, post⟩ := returned_of_spec (claim_contract stage p cb now)
  rw [eq, Result.ok.injEq] at h
  subst h
  exact (post s).mp rfl

theorem begin_from (stage : Stage) (now : I64) (s : Stage)
    (h : next (oauth_login.begin stage p now) = some s) :
    stage = .Accepted ∧ Window p now ∧ s = .Exchanging := by
  have h := (next_eq _ _).mp h
  obtain ⟨c, returned, allowed⟩ := returned_of_spec (current_contract p now)
  cases stage <;> cases c <;> simp_all [oauth_login.begin, Result.ok.injEq]

theorem finish_from (stage : Stage) (installed : Bool) (s : Stage)
    (h : next (oauth_login.finish stage installed) = some s) :
    stage = .Exchanging ∧ s = (if installed then .Complete else .Uncertain) := by
  have h := (next_eq _ _).mp h
  obtain ⟨out, eq, post⟩ := returned_of_spec (finish_contract stage installed)
  rw [eq, Result.ok.injEq] at h
  subst h
  exact (post s).mp rfl

/-- Stage ordering: how far a login has progressed. `Accepted` is the only
    stage from which an exchange starts. -/
def rank : Option Stage → Nat
  | some .Pending => 0
  | some .Accepted => 1
  | some .Denied => 2
  | some .Exchanging => 2
  | some .Complete => 3
  | some .Uncertain => 3
  | none => 4

/-- The progress facts of one step: the stage never moves back, a callback
    moves only `Pending`, an exchange starts only from `Accepted` (with the
    window current) and leaves `Exchanging`, and an install happens only from
    `Exchanging`, leaving `Complete`. -/
theorem step_facts (w : World) (e : Event) :
    rank w.stage ≤ rank (step p w e).1.stage ∧
    (∀ cb a t, (step p w e).2 = some (.exchange cb a t) →
      w.stage = some .Accepted ∧ w.claimed = some (cb, a) ∧ Window p t ∧
      (step p w e).1.stage = some .Exchanging) ∧
    ((step p w e).2 = some .install →
      w.stage = some .Exchanging ∧ (step p w e).1.stage = some .Complete) ∧
    ((step p w e).1.claimed ≠ w.claimed → ∃ cb n,
      e = .callback cb n ∧ Bound .Pending p cb n ∧ w.stage = some .Pending ∧
      (step p w e).1.claimed = some (cb, n) ∧
      (step p w e).1.stage = some (if cb.denied then .Denied else .Accepted)) := by
  cases e with
  | callback cb n =>
    cases hs : w.stage with
    | none => simp [step, hs]
    | some stage =>
      cases hn : next (claim stage p cb n) with
      | none => simp [step, hs, hn]
      | some s =>
        obtain ⟨bound, result⟩ := claim_from p stage cb n s hn
        have pend : stage = .Pending := bound.1
        subst pend result
        refine ⟨?_, ?_, ?_, ?_⟩
        · cases cb.denied <;> simp [step, hs, hn, rank]
        · simp [step, hs, hn]
        · simp [step, hs, hn]
        · intro _; exact ⟨cb, n, rfl, bound, rfl, by simp [step, hs, hn], by simp [step, hs, hn]⟩
  | begin t =>
    cases hs : w.stage with
    | none => simp [step, hs]
    | some stage =>
      cases hc : w.claimed with
      | none => simp [step, hs, hc]
      | some c =>
        cases hn : next (oauth_login.begin stage p t) with
        | none => simp [step, hs, hc, hn]
        | some s =>
          obtain ⟨accepted, window, ex⟩ := begin_from p stage t s hn
          subst accepted ex
          refine ⟨by simp [step, hs, hc, hn, rank], ?_, by simp [step, hs, hc, hn],
                  by simp [step, hs, hc, hn]⟩
          intro cb a t' out
          simp [step, hs, hc, hn] at out
          obtain ⟨rfl, rfl, rfl⟩ := out
          exact ⟨rfl, by simp, window, by simp [step, hs, hc, hn]⟩
  | finish installed =>
    cases hs : w.stage with
    | none => simp [step, hs]
    | some stage =>
      cases hn : next (oauth_login.finish stage installed) with
      | none => simp [step, hs, hn]
      | some s =>
        obtain ⟨exchanging, result⟩ := finish_from stage installed s hn
        subst exchanging result
        cases installed <;> simp [step, hs, hn, rank]
  | crash =>
    cases hs : w.stage with
    | none => simp [step]
    | some stage => cases stage <;> simp [step, rank]

/-- A `Pending` or `Accepted` login has not exchanged yet; one past them
    never exchanges again. -/
theorem no_exchange_past_accepted (w : World) (events : List Event)
    (h : 2 ≤ rank w.stage) : ∀ x ∈ (run p w events).2, isExchange x = false := by
  induction events generalizing w with
  | nil => simp [run]
  | cons e rest ih =>
    intro x mem
    simp only [run] at mem
    obtain ⟨mono, exch, _, _⟩ := step_facts p w e
    rcases List.mem_append.mp mem with here | later
    · cases hout : (step p w e).2 with
      | none => simp [hout] at here
      | some y =>
        simp [hout] at here
        subst here
        cases x with
        | install => rfl
        | exchange cb a t =>
          have := (exch cb a t hout).1
          rw [this] at h; simp [rank] at h
    · exact ih _ (Nat.le_trans h mono) x later

/-- **At most one token exchange per login**, in every history. -/
theorem at_most_one_exchange (w : World) (events : List Event) :
    ((run p w events).2.filter isExchange).length ≤ 1 := by
  induction events generalizing w with
  | nil => simp [run]
  | cons e rest ih =>
    simp only [run, List.filter_append, List.length_append]
    cases hout : (step p w e).2 with
    | none => simpa using ih _
    | some x =>
      cases x with
      | install => simpa [isExchange] using ih _
      | exchange cb a t =>
        have moved := ((step_facts p w e).2.1 cb a t hout).2.2.2
        have quiet := no_exchange_past_accepted p _ rest (by rw [moved]; simp [rank])
        have : List.filter isExchange (run p (step p w e).1 rest).2 = [] :=
          List.filter_eq_nil_iff.mpr (fun y hy => by simp [quiet y hy])
        simp [List.filter, isExchange, this]

/-- An `Accepted` stage always holds the bound, non-denial callback that
    produced it. -/
def ClaimedBound (w : World) : Prop :=
  w.stage = some .Accepted → ∃ cb n, w.claimed = some (cb, n) ∧
    Bound .Pending p cb n ∧ cb.denied = false

theorem claimed_bound_step (w : World) (e : Event) (h : ClaimedBound p w) :
    ClaimedBound p (step p w e).1 := by
  intro accepted
  cases e with
  | callback cb n =>
    cases hs : w.stage with
    | none =>
      have same : (step p w (.callback cb n)).1 = w := by simp [step, hs]
      rw [same] at accepted ⊢; exact h accepted
    | some stage =>
      cases hn : next (claim stage p cb n) with
      | none =>
        have same : (step p w (.callback cb n)).1 = w := by simp [step, hs, hn]
        rw [same] at accepted ⊢; exact h accepted
      | some s =>
        obtain ⟨bound, result⟩ := claim_from p stage cb n s hn
        have pending : stage = .Pending := bound.1
        subst pending
        simp only [step, hs, hn] at accepted ⊢
        refine ⟨cb, n, rfl, bound, ?_⟩
        simp only [Option.some.injEq] at accepted
        subst accepted
        cases hd : cb.denied <;> simp_all
  | begin t =>
    cases hs : w.stage with
    | none =>
      have same : (step p w (.begin t)).1 = w := by simp [step, hs]
      rw [same] at accepted ⊢; exact h accepted
    | some stage =>
      cases hc : w.claimed with
      | none =>
        have same : (step p w (.begin t)).1 = w := by simp [step, hs, hc]
        rw [same] at accepted ⊢; exact h accepted
      | some c =>
        cases hn : next (oauth_login.begin stage p t) with
        | none =>
          have same : (step p w (.begin t)).1 = w := by simp [step, hs, hc, hn]
          rw [same] at accepted ⊢; exact h accepted
        | some s =>
          have ex := (begin_from p stage t s hn).2.2
          simp [step, hs, hc, hn, ex] at accepted
  | finish i =>
    cases hs : w.stage with
    | none =>
      have same : (step p w (.finish i)).1 = w := by simp [step, hs]
      rw [same] at accepted ⊢; exact h accepted
    | some stage =>
      cases hn : next (oauth_login.finish stage i) with
      | none =>
        have same : (step p w (.finish i)).1 = w := by simp [step, hs, hn]
        rw [same] at accepted ⊢; exact h accepted
      | some s =>
        have result := (finish_from stage i s hn).2
        cases i <;> simp [step, hs, hn, result] at accepted
  | crash => simp [step] at accepted

/-- **Every exchange follows a bound callback:** whenever a token exchange
    starts, the claimed callback carried the pending state, satisfied the
    issuer rule, arrived inside the window and was not a denial, and the
    exchange itself started inside the window. -/
theorem every_exchange_bound (w : World) (events : List Event) (h : ClaimedBound p w) :
    ∀ cb n t, .exchange cb n t ∈ (run p w events).2 →
      Bound .Pending p cb n ∧ cb.denied = false ∧ Window p t := by
  induction events generalizing w with
  | nil => simp [run]
  | cons e rest ih =>
    intro cb n t mem
    simp only [run] at mem
    rcases List.mem_append.mp mem with here | later
    · cases hout : (step p w e).2 with
      | none => simp [hout] at here
      | some y =>
        simp [hout] at here
        subst here
        obtain ⟨accepted, claimed, window, _⟩ := (step_facts p w e).2.1 cb n t hout
        obtain ⟨cb', n', hc, bound, denied⟩ := h accepted
        rw [claimed] at hc
        simp only [Option.some.injEq, Prod.mk.injEq] at hc
        obtain ⟨rfl, rfl⟩ := hc
        exact ⟨bound, denied, window⟩
    · exact ih _ (claimed_bound_step p w e h) cb n t later

theorem initial_claimed_bound : ClaimedBound p initial := by
  simp [ClaimedBound, initial]

/-- **A crash ends the login:** nothing leaves the host afterwards. -/
theorem crash_is_final (w : World) (events : List Event) :
    (run p w (.crash :: events)).2 = [] := by
  suffices quiet : ∀ (w : World), w.stage = none → (run p w events).2 = [] by
    simp only [run]
    simpa [step] using quiet _ rfl
  induction events with
  | nil => simp [run]
  | cons e rest ih =>
    intro w hs
    have stays : (step p w e).1.stage = none ∧ (step p w e).2 = none := by
      cases e <;> simp [step, hs]
    simp only [run, stays.2]
    simpa using ih _ stays.1

/-- An install happens only from an exchange in progress, and leaves the
    login `Complete`; so it happens at most once and only after the exchange. -/
theorem install_needs_exchange (w : World) (e : Event)
    (out : (step p w e).2 = some .install) :
    w.stage = some .Exchanging ∧ (step p w e).1.stage = some .Complete :=
  (step_facts p w e).2.2.1 out


/-! ## The model is not vacuous -/

/-- A login that claims a good callback, exchanges once and installs. -/
theorem successful_login_witness (state : alloc.vec.Vec U8) :
    let pending : Pending := ⟨state, .Absent, 1000#i64, 1200#i64⟩
    (run pending initial [.callback ⟨state, state, false, false⟩ 1100#i64, .begin 1100#i64,
                          .finish true]).2 =
      [.exchange ⟨state, state, false, false⟩ 1100#i64 1100#i64, .install] := by
  intro pending
  have h1 : next (claim .Pending pending ⟨state, state, false, false⟩ 1100#i64) = some .Accepted :=
    (next_eq _ _).mpr (successful_callback_witness state)
  have h2 : next (oauth_login.begin .Accepted pending 1100#i64) = some .Exchanging :=
    (next_eq _ _).mpr (successful_exchange_witness state)
  have h3 : next (oauth_login.finish .Exchanging true) = some .Complete :=
    (next_eq _ _).mpr rfl
  simp [run, step, initial, h1, h2, h3]

end

end Garrett.LoginHistory
