import GarrettDispatchTrace

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false

/-!
# The dispatch controller commutes with ghost erasure

`dispatch::dispatch` and `provider_exchange::exchange` are generic in the
dispatch primitive. This module proves they treat two primitives alike when
one *forward-simulates* the other along an erasure `e`: whenever the erased
primitive's callback returns, the full one's returns the same result, and its
next state erases to the erased one's. Then a returned dispatch over the
erased primitive has a returned dispatch over the full one with the same
outcome, receipts, send state, stage and stamp.

The use is ghost state. A primitive extended with a log the controller never
reads (`GarrettNativeSendLog.logged`) forward-simulates the primitive it
extends, so facts proved about the logged dispatch are facts about the
production dispatch it erases to.
-/
namespace aivm_secrets_garrett_core.dispatch.Erasure

theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

/-- Close a branch whose two sides return the same value from related states. -/
theorem finish_pair {V A B : Type} {e : A → B} (value out : V) (a : A) (b : B)
    (h : Result.ok (value, e a) = Result.ok (out, b)) :
    ∃ a', Result.ok (value, a) = Result.ok (out, a') ∧ e a' = b := by
  simp only [Result.ok.injEq, Prod.mk.injEq] at h
  exact ⟨a, by rw [h.1], h.2⟩

/-- The same, after one shared effect-free computation. -/
theorem finish_bind {V W A B : Type} {e : A → B} (m : Result W) (k : W → V) (out : V) (a : A) (b : B)
    (h : (do let x ← m; Result.ok (k x, e a)) = Result.ok (out, b)) :
    ∃ a', (do let x ← m; Result.ok (k x, a)) = Result.ok (out, a') ∧ e a' = b := by
  obtain ⟨x, hx, rest⟩ := (bind_returns_iff _ _ _).mp h
  rw [hx]
  simp only [bind_ok]
  exact finish_pair _ _ _ _ rest

/-- Run one shared step on the full side and continue. -/
theorem step {M V A B : Type} {e : A → B} (m : Result M) (value : M) (k : M → Result (V × A)) {out : V} {b : B}
    (hm : m = Result.ok value) (cont : ∃ a', k value = Result.ok (out, a') ∧ e a' = b) :
    ∃ a', Std.bind m k = Result.ok (out, a') ∧ e a' = b := by
  obtain ⟨a', hk, he⟩ := cont
  exact ⟨a', by rw [hm, bind_ok]; exact hk, he⟩

/-- The same three lemmas for callbacks that also return a channel. -/
theorem finish_triple {V A B C : Type} {e : A → B} (value out : V) (a : A) (b : B) (c next : C)
    (h : Result.ok (value, e a, c) = Result.ok (out, b, next)) :
    ∃ a', Result.ok (value, a, c) = Result.ok (out, a', next) ∧ e a' = b := by
  simp only [Result.ok.injEq, Prod.mk.injEq] at h
  exact ⟨a, by rw [h.1, h.2.2], h.2.1⟩

theorem finish_bind3 {V W A B C : Type} {e : A → B} (m : Result W) (k : W → V) (out : V) (a : A) (b : B)
    (c next : C) (h : (do let x ← m; Result.ok (k x, e a, c)) = Result.ok (out, b, next)) :
    ∃ a', (do let x ← m; Result.ok (k x, a, c)) = Result.ok (out, a', next) ∧ e a' = b := by
  obtain ⟨x, hx, rest⟩ := (bind_returns_iff _ _ _).mp h
  rw [hx]
  simp only [bind_ok]
  exact finish_triple _ _ _ _ _ _ rest

theorem step3 {M V A B C : Type} {e : A → B} (m : Result M) (value : M) (k : M → Result (V × A × C))
    {out : V} {b : B} {next : C}
    (hm : m = Result.ok value) (cont : ∃ a', k value = Result.ok (out, a', next) ∧ e a' = b) :
    ∃ a', Std.bind m k = Result.ok (out, a', next) ∧ e a' = b := by
  obtain ⟨a', hk, he⟩ := cont
  exact ⟨a', by rw [hm, bind_ok]; exact hk, he⟩

section provider
variable {A B C O X : Type}

/-- `PA` forward-simulates `PB` along `e`. -/
structure ProviderForward (PA : provider_exchange.Provider A C O X) (PB : provider_exchange.Provider B C O X)
    (e : A → B) : Prop where
  policy : PA.INVALID_POLICY = PB.INVALID_POLICY
  unknown : PA.OUTCOME_UNKNOWN = PB.OUTCOME_UNKNOWN
  setup : ∀ a r b, PB.setup (e a) = Result.ok (r, b) → ∃ a', PA.setup a = Result.ok (r, a') ∧ e a' = b
  recheck : ∀ a r b, PB.recheck (e a) = Result.ok (r, b) → ∃ a', PA.recheck a = Result.ok (r, a') ∧ e a' = b
  send : ∀ a ch r b next, PB.send (e a) ch = Result.ok (r, b, next) →
    ∃ a', PA.send a ch = Result.ok (r, a', next) ∧ e a' = b
  receive : ∀ a ch r b, PB.receive (e a) ch = Result.ok (r, b) →
    ∃ a', PA.receive a ch = Result.ok (r, a') ∧ e a' = b

set_option hygiene false in
/-- The common send-then-receive tail of both exchange branches. -/
local macro "send_tail" : tactic => `(tactic| (
  obtain ⟨⟨r3, b3, ch⟩, sendB, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨a3, sendA, rfl⟩ := fw.send _ _ _ _ _ sendB
  refine step _ _ _ sendA ?_
  cases r3 with
  | Err error =>
    first
    | exact finish_pair _ _ _ _ rest
    | (rw [fw.unknown]; exact finish_bind _ _ _ _ _ rest)
  | Ok _ =>
    obtain ⟨⟨r4, b4⟩, receiveB, rest⟩ := (bind_returns_iff _ _ _).mp rest
    obtain ⟨a4, receiveA, rfl⟩ := fw.receive _ _ _ _ receiveB
    refine step _ _ _ receiveA ?_
    cases r4 with
    | Ok value => exact finish_pair _ _ _ _ rest
    | Err error =>
      first
      | exact finish_pair _ _ _ _ rest
      | (rw [fw.unknown]; exact finish_bind _ _ _ _ _ rest)))

/-- **The provider driver commutes with erasure.** -/
theorem exchange_forward {PA : provider_exchange.Provider A C O X} {PB : provider_exchange.Provider B C O X}
    {e : A → B} (fw : ProviderForward PA PB e) (a : A) (audited : read_transition.Audited)
    (report : provider_exchange.Report O X) (b : B)
    (h : provider_exchange.exchange PB (e a) audited = Result.ok (report, b)) :
    ∃ a', provider_exchange.exchange PA a audited = Result.ok (report, a') ∧ e a' = b := by
  unfold provider_exchange.exchange at h ⊢
  simp only [read_transition.Audited.impl.phase, read_transition.Audited.is_write, bind_ok] at h ⊢
  obtain ⟨⟨r, b1⟩, setupB, h⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨a1, setupA, rfl⟩ := fw.setup _ _ _ setupB
  refine step _ _ _ setupA ?_
  cases r with
  | Err err => exact finish_pair _ _ _ _ h
  | Ok channel =>
    obtain ⟨⟨r, b2⟩, recheckB, h⟩ := (bind_returns_iff _ _ _).mp h
    obtain ⟨a2, recheckA, rfl⟩ := fw.recheck _ _ _ recheckB
    refine step _ _ _ recheckA ?_
    cases r with
    | Err err => exact finish_pair _ _ _ _ h
    | Ok stamp =>
      cases w : audited.write with
      | false =>
        simp only [w, Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair] at h ⊢
        send_tail
      | true =>
        simp only [w, ↓reduceIte, manifest.AdmissionStamp.impl.write, bind_ok, uncurry_apply_pair] at h ⊢
        cases allowed : stamp.write with
        | false =>
          simp only [allowed, Bool.false_eq_true, ↓reduceIte] at h ⊢
          rw [fw.policy]
          exact finish_bind _ _ _ _ _ h
        | true =>
          simp only [allowed, ↓reduceIte] at h ⊢
          send_tail

end provider

section work
variable {A B H O X : Type}

/-- `WA` forward-simulates `WB` along `e`: its provider callbacks do, its
    dispatch callbacks do, and it reports the same constants. -/
structure WorkForward (WA : dispatch.Work A H O X) (WB : dispatch.Work B H O X) (e : A → B) : Prop where
  provider : ProviderForward WA.provider_exchangeProviderInst WB.provider_exchangeProviderInst e
  invalid : WA.INVALID_TRANSITION = WB.INVALID_TRANSITION
  effect_write : ∀ a, WA.effect_write a = WB.effect_write (e a)
  prepare : ∀ a r b, WB.prepare (e a) = Result.ok (r, b) → ∃ a', WA.prepare a = Result.ok (r, a') ∧ e a' = b
  audit : ∀ a ph r b, WB.audit (e a) ph = Result.ok (r, b) → ∃ a', WA.audit a ph = Result.ok (r, a') ∧ e a' = b
  configure : ∀ a k r b, WB.configure (e a) k = Result.ok (r, b) →
    ∃ a', WA.configure a k = Result.ok (r, a') ∧ e a' = b
  check : ∀ a r b, WB.check (e a) = Result.ok (r, b) → ∃ a', WA.check a = Result.ok (r, a') ∧ e a' = b
  reserve : ∀ a r b, WB.reserve (e a) = Result.ok (r, b) → ∃ a', WA.reserve a = Result.ok (r, a') ∧ e a' = b
  finish : ∀ a r b, WB.finish (e a) = Result.ok (r, b) → ∃ a', WA.finish a = Result.ok (r, a') ∧ e a' = b

/-- Erase the primitive inside a dispatch's state; every other field stays. -/
def erasePending (e : A → B) (q : dispatch.Pending A H O X) : dispatch.Pending B H O X :=
  ⟨e q.work, q.effects, q.local, q.phase, q.write, q.provider_stage, q.current⟩

abbrev adapter (W : dispatch.Work A H O X) :=
  dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider W

/-- The dispatch's own provider adapter inherits forward simulation. -/
theorem adapter_forward {WA : dispatch.Work A H O X} {WB : dispatch.Work B H O X} {e : A → B}
    (fw : WorkForward WA WB e) : ProviderForward (adapter WA) (adapter WB) (erasePending e) where
  policy := by
    simp only [adapter, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider]
    unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.INVALID_POLICY
    exact fw.provider.policy
  unknown := by
    simp only [adapter, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider]
    unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.OUTCOME_UNKNOWN
    exact fw.provider.unknown
  setup := by
    intro q r b h
    simp only [adapter, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
    unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup at h ⊢
    obtain ⟨⟨r1, t⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
    obtain ⟨a1, callA, rfl⟩ := fw.provider.setup _ _ _ call
    refine step _ _ _ callA ?_
    simp only [uncurry_apply_pair] at h ⊢
    exact finish_pair (e := erasePending e) _ _ { q with work := a1 } _ h
  recheck := by
    intro q r b h
    simp only [adapter, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
    unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at h ⊢
    obtain ⟨⟨began, ss⟩, begin, h⟩ := (bind_returns_iff _ _ _).mp h
    refine step _ _ _ begin ?_
    cases began with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
      exact finish_bind (e := erasePending e) _ _ _ { q with «local» := ss } _ h
    | true =>
      simp only [↓reduceIte, uncurry_apply_pair] at h ⊢
      obtain ⟨⟨r1, t⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
      obtain ⟨a1, callA, rfl⟩ := fw.provider.recheck _ _ _ call
      refine step _ _ _ callA ?_
      cases r1 with
      | Err error =>
        simp only [uncurry_apply_pair] at h ⊢
        exact finish_pair (e := erasePending e) _ _ { q with work := a1, «local» := ss } _ h
      | Ok stamp =>
        obtain ⟨⟨finished, ss1⟩, done, h⟩ := (bind_returns_iff _ _ _).mp h
        refine step _ _ _ done ?_
        cases finished with
        | false =>
          simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
          exact finish_bind (e := erasePending e) _ _ _ { q with work := a1, «local» := ss1 } _ h
        | true =>
          simp only [↓reduceIte, uncurry_apply_pair] at h ⊢
          exact finish_pair (e := erasePending e) _ _ { q with work := a1, «local» := ss1 } _ h
  send := by
    intro q ch r b next h
    simp only [adapter, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
    unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at h ⊢
    obtain ⟨⟨began, re, ss⟩, begin, h⟩ := (bind_returns_iff _ _ _).mp h
    refine step3 _ _ _ begin ?_
    cases began with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
      exact finish_bind3 (e := erasePending e) _ _ _ { q with effects := re, «local» := ss } _ _ _ h
    | true =>
      simp only [↓reduceIte, uncurry_apply_pair] at h ⊢
      obtain ⟨⟨r1, t, c1⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
      obtain ⟨a1, callA, rfl⟩ := fw.provider.send _ _ _ _ _ call
      refine step3 _ _ _ callA ?_
      simp only [uncurry_apply_pair] at h ⊢
      exact finish_triple (e := erasePending e) _ _ { q with work := a1, effects := re, «local» := ss } _ _ _ h
  receive := by
    intro q ch r b h
    simp only [adapter, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
    unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive at h ⊢
    obtain ⟨⟨r1, t⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
    obtain ⟨a1, callA, rfl⟩ := fw.provider.receive _ _ _ _ call
    refine step _ _ _ callA ?_
    simp only [uncurry_apply_pair] at h ⊢
    exact finish_pair (e := erasePending e) _ _ { q with work := a1 } _ h

variable {WA : dispatch.Work A H O X} {WB : dispatch.Work B H O X} {e : A → B}

theorem audit_forward (fw : WorkForward WA WB e) (q : dispatch.Pending A H O X) (prepared : read_transition.Prepared)
    (out : core.result.Result read_transition.Audited X) (p : dispatch.Pending B H O X)
    (h : dispatch.audit WB (erasePending e q) prepared = Result.ok (out, p)) :
    ∃ q', dispatch.audit WA q prepared = Result.ok (out, q') ∧ erasePending e q' = p := by
  unfold dispatch.audit at h ⊢
  obtain ⟨⟨r, t⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨a1, callA, rfl⟩ := fw.prepare _ _ _ call
  refine step _ _ _ callA ?_
  simp only [uncurry_apply_pair] at h ⊢
  cases r with
  | Err error => exact finish_pair (e := erasePending e) _ _ { q with work := a1 } _ h
  | Ok u =>
    obtain ⟨⟨began, re⟩, begin, h⟩ := (bind_returns_iff _ _ _).mp h
    refine step _ _ _ begin ?_
    cases began with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
      exact finish_bind (e := erasePending e) _ _ _ { q with work := a1, effects := re } _ h
    | true =>
      simp only [↓reduceIte, uncurry_apply_pair, read_transition.Prepared.impl.phase, bind_ok] at h ⊢
      obtain ⟨⟨r1, t1⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
      obtain ⟨a2, callA, rfl⟩ := fw.audit _ _ _ _ call
      refine step _ _ _ callA ?_
      simp only [uncurry_apply_pair] at h ⊢
      cases r1 with
      | Err error => exact finish_pair (e := erasePending e) _ _ { q with work := a2, effects := re } _ h
      | Ok u =>
        obtain ⟨r2, ack, h⟩ := (bind_returns_iff _ _ _).mp h
        refine step _ _ _ ack ?_
        cases r2 with
        | Err error =>
          simp only [fw.invalid] at h ⊢
          exact finish_bind (e := erasePending e) _ _ _ { q with work := a2, effects := re } _ h
        | Ok audited =>
          obtain ⟨⟨b1, re1⟩, acked, h⟩ := (bind_returns_iff _ _ _).mp h
          refine step _ _ _ acked ?_
          cases b1 with
          | false =>
            simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
            exact finish_bind (e := erasePending e) _ _ _ { q with work := a2, effects := re1 } _ h
          | true =>
            simp only [↓reduceIte, uncurry_apply_pair] at h ⊢
            exact finish_pair (e := erasePending e) _ _ { q with work := a2, effects := re1 } _ h

theorem exchange_dispatch_forward (fw : WorkForward WA WB e) (q : dispatch.Pending A H O X)
    (audited : read_transition.Audited) (out : core.result.Result O X) (p : dispatch.Pending B H O X)
    (h : dispatch.exchange WB (erasePending e q) audited = Result.ok (out, p)) :
    ∃ q', dispatch.exchange WA q audited = Result.ok (out, q') ∧ erasePending e q' = p := by
  unfold dispatch.exchange at h ⊢
  simp only [read_transition.Audited.is_write, bind_ok] at h ⊢
  obtain ⟨w1, hw, h⟩ := (bind_returns_iff _ _ _).mp h
  have hwA : WA.effect_write q.work = Result.ok w1 := by rw [fw.effect_write]; exact hw
  rw [hwA, bind_ok]
  by_cases mismatch : (audited.write != w1) = true
  · simp only [mismatch, ↓reduceIte, fw.provider.policy] at h ⊢
    exact finish_bind (e := erasePending e) _ _ _ q _ h
  · simp only [mismatch, Bool.false_eq_true, ↓reduceIte] at h ⊢
    obtain ⟨⟨began, re⟩, begin, h⟩ := (bind_returns_iff _ _ _).mp h
    refine step _ _ _ begin ?_
    cases began with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
      exact finish_bind (e := erasePending e) _ _ _ { q with effects := re } _ h
    | true =>
      simp only [↓reduceIte, uncurry_apply_pair, read_transition.Audited.impl.phase, bind_ok] at h ⊢
      obtain ⟨⟨report, p1⟩, driver, h⟩ := (bind_returns_iff _ _ _).mp h
      obtain ⟨q1, driverA, rfl⟩ := exchange_forward (adapter_forward fw)
        { q with effects := re, phase := audited.phase, write := audited.write } audited report p1 driver
      refine step _ _ _ driverA ?_
      simp only [uncurry_apply_pair, provider_exchange.Report.impl.stage, provider_exchange.Report.impl.current,
        provider_exchange.Report.into_result, bind_ok] at h ⊢
      cases hr : report.result with
      | Err error =>
        simp only [hr] at h ⊢
        exact finish_pair (e := erasePending e) _ _
          { q1 with provider_stage := some report.stage, current := report.current } _ h
      | Ok value =>
        simp only [hr] at h ⊢
        obtain ⟨⟨b3, re1⟩, completed, h⟩ := (bind_returns_iff _ _ _).mp h
        refine step _ _ _ completed ?_
        cases b3 with
        | false =>
          simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
          exact finish_bind (e := erasePending e) _ _ _
            { q1 with effects := re1, provider_stage := some report.stage, current := report.current } _ h
        | true =>
          simp only [↓reduceIte, uncurry_apply_pair] at h ⊢
          exact finish_pair (e := erasePending e) _ _
            { q1 with effects := re1, provider_stage := some report.stage, current := report.current } _ h

theorem finish_forward (fw : WorkForward WA WB e) (q : dispatch.Pending A H O X) (keyed : Bool)
    (out : core.result.Result Unit X) (p : dispatch.Pending B H O X)
    (h : dispatch.finish WB (erasePending e q) keyed = Result.ok (out, p)) :
    ∃ q', dispatch.finish WA q keyed = Result.ok (out, q') ∧ erasePending e q' = p := by
  unfold dispatch.finish at h ⊢
  obtain ⟨⟨p1, finished⟩, framed, h⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨q1, framedA, rfl⟩ : ∃ q1, (if keyed = true then do
        let (finished1, t) ← WA.finish q.work
        Result.ok ({ q with work := t }, finished1)
      else Result.ok (q, core.result.Result.Ok ())) = Result.ok (q1, finished) ∧ erasePending e q1 = p1 := by
    cases keyed with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, Prod.mk.injEq] at framed ⊢
      exact ⟨q, ⟨rfl, framed.2⟩, framed.1⟩
    | true =>
      simp only [↓reduceIte] at framed ⊢
      obtain ⟨⟨f1, t⟩, call, back⟩ := (bind_returns_iff _ _ _).mp framed
      obtain ⟨a1, callA, rfl⟩ := fw.finish _ _ _ call
      simp only [uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at back
      refine ⟨{ q with work := a1 }, ?_, back.1⟩
      rw [callA, bind_ok]
      simp only [uncurry_apply_pair, back.2]
  rw [framedA, bind_ok]
  simp only [uncurry_apply_pair] at h ⊢
  cases finished with
  | Err error =>
    simp only [fw.provider.unknown] at h ⊢
    exact finish_bind (e := erasePending e) _ _ _ q1 _ h
  | Ok u =>
    obtain ⟨⟨b, re⟩, fin, h⟩ := (bind_returns_iff _ _ _).mp h
    refine step _ _ _ fin ?_
    cases b with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, uncurry_apply_pair, fw.invalid] at h ⊢
      exact finish_bind (e := erasePending e) _ _ _ { q1 with effects := re } _ h
    | true =>
      simp only [↓reduceIte, uncurry_apply_pair] at h ⊢
      exact finish_pair (e := erasePending e) _ _ { q1 with effects := re } _ h

theorem run_forward (fw : WorkForward WA WB e) (q : dispatch.Pending A H O X) (prepared : read_transition.Prepared)
    (keyed : Bool) (out : core.result.Result O X) (p : dispatch.Pending B H O X)
    (h : dispatch.run WB (erasePending e q) prepared keyed = Result.ok (out, p)) :
    ∃ q', dispatch.run WA q prepared keyed = Result.ok (out, q') ∧ erasePending e q' = p := by
  unfold dispatch.run at h ⊢
  obtain ⟨⟨audited, p1⟩, auditB, h⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨q1, auditA, rfl⟩ := audit_forward fw q prepared audited p1 auditB
  refine step _ _ _ auditA ?_
  simp only [uncurry_apply_pair] at h ⊢
  cases audited with
  | Err error => exact finish_pair (e := erasePending e) _ _ q1 _ h
  | Ok permit =>
    obtain ⟨⟨r1, t⟩, conf, h⟩ := (bind_returns_iff _ _ _).mp h
    obtain ⟨a1, confA, rfl⟩ := fw.configure _ _ _ _ conf
    refine step _ _ _ confA ?_
    simp only [uncurry_apply_pair] at h ⊢
    cases r1 with
    | Err error => exact finish_pair (e := erasePending e) _ _ { q1 with work := a1 } _ h
    | Ok u =>
      obtain ⟨⟨r2, t1⟩, chk, h⟩ := (bind_returns_iff _ _ _).mp h
      obtain ⟨a2, chkA, rfl⟩ := fw.check _ _ _ chk
      refine step _ _ _ chkA ?_
      simp only [uncurry_apply_pair] at h ⊢
      cases r2 with
      | Err error => exact finish_pair (e := erasePending e) _ _ { q1 with work := a2 } _ h
      | Ok u =>
        obtain ⟨⟨t2, reserved⟩, framed, h⟩ := (bind_returns_iff _ _ _).mp h
        obtain ⟨a3, framedA, rfl⟩ : ∃ a3, (if keyed = true then do
              let (reserved1, t3) ← WA.reserve a2
              Result.ok (t3, reserved1)
            else Result.ok (a2, core.result.Result.Ok ())) = Result.ok (a3, reserved) ∧ e a3 = t2 := by
          cases keyed with
          | false =>
            simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, Prod.mk.injEq] at framed ⊢
            exact ⟨a2, ⟨rfl, framed.2⟩, framed.1⟩
          | true =>
            simp only [↓reduceIte] at framed ⊢
            obtain ⟨⟨f1, t3⟩, call, back⟩ := (bind_returns_iff _ _ _).mp framed
            obtain ⟨a3, callA, rfl⟩ := fw.reserve _ _ _ call
            simp only [uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at back
            refine ⟨a3, ?_, back.1⟩
            rw [callA, bind_ok]
            simp only [uncurry_apply_pair, back.2]
        rw [framedA, bind_ok]
        simp only [uncurry_apply_pair] at h ⊢
        cases reserved with
        | Err error => exact finish_pair (e := erasePending e) _ _ { q1 with work := a3 } _ h
        | Ok u =>
          obtain ⟨⟨r3, p2⟩, exB, h⟩ := (bind_returns_iff _ _ _).mp h
          obtain ⟨q2, exA, rfl⟩ := exchange_dispatch_forward fw { q1 with work := a3 } permit r3 p2 exB
          refine step _ _ _ exA ?_
          simp only [uncurry_apply_pair] at h ⊢
          cases r3 with
          | Err error => exact finish_pair (e := erasePending e) _ _ q2 _ h
          | Ok value =>
            obtain ⟨⟨r4, p3⟩, finB, h⟩ := (bind_returns_iff _ _ _).mp h
            obtain ⟨q3, finA, rfl⟩ := finish_forward fw q2 keyed r4 p3 finB
            refine step _ _ _ finA ?_
            simp only [uncurry_apply_pair] at h ⊢
            cases r4 with
            | Ok u => exact finish_pair (e := erasePending e) _ _ q3 _ h
            | Err error => exact finish_pair (e := erasePending e) _ _ q3 _ h

/-- Erase the primitive inside a dispatch report. -/
def eraseReport (e : A → B) (r : dispatch.Report A H O X) : dispatch.Report B H O X :=
  ⟨r.outcome, e r.work, r.effects, r.local, r.provider_stage, r.current⟩

/-- **A dispatch commutes with erasure.** For any primitive `WA` that
    forward-simulates `WB` along `e`: if the extracted `dispatch::dispatch`
    returns over `WB` from `e a`, it returns over `WA` from `a`, with the
    same outcome, receipts, send state, provider stage and stamp, and a
    primitive state that erases to `WB`'s. -/
theorem dispatch_forward (fw : WorkForward WA WB e) (a : A)
    (prepared : core.result.Result read_transition.Prepared X) (before : request_effects.RequestEffects)
    (keyed : Bool) (report : dispatch.Report B H O X)
    (h : dispatch.dispatch WB (e a) prepared before keyed = Result.ok report) :
    ∃ report', dispatch.dispatch WA a prepared before keyed = Result.ok report' ∧ eraseReport e report' = report := by
  unfold dispatch.dispatch at h ⊢
  cases prepared with
  | Err error =>
    simp only [provider_exchange.SendState.new, bind_ok, Result.ok.injEq] at h ⊢
    exact ⟨_, rfl, h⟩
  | Ok prepared =>
    simp only [read_transition.Prepared.impl.phase, provider_exchange.SendState.new, bind_ok] at h ⊢
    obtain ⟨⟨outcome, p⟩, ran, h⟩ := (bind_returns_iff _ _ _).mp h
    obtain ⟨q, ranA, rfl⟩ := run_forward fw ⟨a, before, ⟨.Empty⟩, prepared.phase, false, none, none⟩
      prepared keyed outcome p ran
    rw [ranA, bind_ok]
    simp only [uncurry_apply_pair, Result.ok.injEq] at h ⊢
    exact ⟨_, rfl, h⟩

end work

end aivm_secrets_garrett_core.dispatch.Erasure
