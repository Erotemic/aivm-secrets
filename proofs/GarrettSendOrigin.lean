import GarrettNativeSendLog

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false

/-!
# Each recorded provider send, with its own phase, authorization and channel

`GarrettNativeSendLog` proves a returned request asks its dispatch primitive
for exactly as many sends as the source trace has `providerSend` events, and
then labels the sends in order. This module ties each send to its own
evidence instead:

* **Phase.** A dispatch marks an attempt only for its own phase; the other
  phase's attempt bit is unchanged (`dispatch_origin`). Per phase, a trace
  has exactly as many sends as that phase's bit was raised
  (`trace_phase_count`).
* **Channel.** Every channel the dispatch passes to its primitive's `send`
  is one its primitive's `setup` returned, from a state satisfying any
  invariant the primitive's callbacks preserve (`dispatch_origin`). For the
  production primitive that invariant is the captured route.
-/
namespace aivm_secrets_garrett_core.nr23.SendOrigin
open aivm_secrets_garrett_core.request_effects aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.nr23.ExactSinks
open aivm_secrets_garrett_core.nr23.SendLog
open aivm_secrets_garrett_core.provider_exchange.Simulation

/-! ## Per-phase accounting -/

/-- A phase's provider-attempt bit. -/
def bit : read_transition.Phase → RequestEffects → Bool
  | .Preflight, s => s.preflight.provider_attempted
  | .Final, s => s.final_effect.provider_attempted

def other : read_transition.Phase → read_transition.Phase
  | .Preflight => .Final
  | .Final => .Preflight

def ones (b : Bool) : Nat := if b then 1 else 0

/-- Is this a provider send of `phase`? -/
def sendOf : read_transition.Phase → confinement.Proofs.Event → Bool
  | .Preflight, .providerSend .preflight _ _ => true
  | .Final, .providerSend .final _ _ => true
  | _, _ => false

def samePhase : read_transition.Phase → read_transition.Phase → Bool
  | .Preflight, .Preflight => true
  | .Final, .Final => true
  | _, _ => false

def sendsOf (phase : read_transition.Phase) (events : List confinement.Proofs.Event) :
    List confinement.Proofs.Event :=
  events.filter (sendOf phase)

theorem bit_of_attempts {u v : RequestEffects} (same : Attempts v = Attempts u) (ph : read_transition.Phase) :
    bit ph v = bit ph u := by
  simp only [Attempts, Prod.mk.injEq] at same
  cases ph <;> simp [bit, same.1, same.2]

theorem records_attempts' {u v : RequestEffects} (same : Records v = Records u) : Attempts v = Attempts u := by
  simp only [Records, Prod.mk.injEq] at same
  simp [Attempts, same.1, same.2]

/-- One step's sends of a phase are that phase's newly marked attempt. -/
theorem sends_of_delta_phase (contexts : read_transition.Phase → Context) (u v : RequestEffects)
    (cp : v.preflight.provider_attempted = true → v.preflight.current.isSome = true)
    (cf : v.final_effect.provider_attempted = true → v.final_effect.current.isSome = true)
    (q : read_transition.Phase) :
    (sendsOf q (delta contexts u v)).length = ones (raised (bit q u) (bit q v)) := by
  have audit : ∀ ph a b, sendsOf q (auditDelta ph a b) = [] := by
    intro ph a b; unfold auditDelta; split <;> cases q <;> simp [sendsOf, sendOf]
  have provider : ∀ ph ctx (r r' : DispatchRecord),
      (r'.provider_attempted = true → r'.current.isSome = true) →
      (sendsOf q (providerDelta ph ctx r r')).length =
        (if samePhase ph q then ones (raised r.provider_attempted r'.provider_attempted) else 0) := by
    intro ph ctx r r' c
    unfold providerDelta
    cases hr : raised r.provider_attempted r'.provider_attempted
    · simp only [Bool.false_eq_true, ↓reduceIte]
      split <;> simp [ones, sendsOf]
    · have up : r'.provider_attempted = true := by
        cases a : r.provider_attempted <;> cases b : r'.provider_attempted <;> simp_all [raised]
      have some := c up
      cases hc : r'.current with
      | none => rw [hc] at some; cases some
      | some st =>
        cases ph <;> cases q <;> simp [sendsOf, sendOf, samePhase, ones, eventPhase, List.filter]
  simp only [delta, phaseDelta, sendsOf, List.filter_append, List.length_append]
  have a1 := audit (eventPhase .Preflight) u.preflight.audit_attempted v.preflight.audit_attempted
  have a2 := audit (eventPhase .Final) u.final_effect.audit_attempted v.final_effect.audit_attempted
  have a3 := audit .completed u.completion.audit_attempted v.completion.audit_attempted
  simp only [sendsOf] at a1 a2 a3 provider
  rw [a1, a2, a3, provider _ _ _ _ cp, provider _ _ _ _ cf]
  cases q <;> simp [bit, samePhase]

/-- A reachable step never clears an attempt bit, and raises a phase's bit
    exactly when it is that phase's accepted `begin_send`. -/
theorem step_phase_count (contexts : read_transition.Phase → Context) {u v : RequestEffects}
    (reach : Reachable u) (step : Step u v) (q : read_transition.Phase) :
    (sendsOf q (delta contexts u v)).length + ones (bit q u) = ones (bit q v) := by
  have reachV : Reachable v := by
    obtain ⟨i, m, st⟩ := reach
    exact ⟨i, m, .next st step⟩
  obtain ⟨cp, cf⟩ := attempted_has_stamp reachV
  rw [sends_of_delta_phase contexts u v cp cf q]
  have kept : Attempts v = Attempts u → ones (raised (bit q u) (bit q v)) + ones (bit q u) = ones (bit q v) := by
    intro same
    rw [bit_of_attempts same q]
    cases bit q u <;> simp [raised, ones]
  cases step with
  | begin_dispatch_audit acc p h => obtain ⟨ph, w⟩ := p; exact kept (begin_dispatch_audit_keeps h)
  | acknowledge_dispatch acc p h => obtain ⟨ph, w⟩ := p; exact kept (acknowledge_dispatch_keeps h)
  | begin_provider acc p h => obtain ⟨ph, w⟩ := p; exact kept (begin_provider_keeps h)
  | provider_completed acc ph h => exact kept (provider_completed_keeps h)
  | finish_dispatch acc ph h => exact kept (finish_dispatch_keeps h)
  | begin_completion acc h => exact kept (records_attempts' (begin_completion_records h))
  | selected acc h => exact kept (records_attempts' (selected_records h))
  | begin_completion_check acc ph h => exact kept (records_attempts' (begin_completion_check_records h))
  | finish_completion_check acc ph h => exact kept (records_attempts' (finish_completion_check_records h))
  | begin_completion_audit acc h => exact kept (records_attempts' (begin_completion_audit_records h))
  | acknowledge_completion_audit acc h => exact kept (records_attempts' (acknowledge_completion_audit_records h))
  | value_ready acc h => exact kept (records_attempts' (value_ready_records h))
  | begin_send acc ph l l' w h =>
    obtain ⟨refused, accepted⟩ := begin_send_marks h
    cases acc with
    | false => exact kept (refused rfl)
    | true =>
      obtain ⟨ready, marks⟩ := accepted rfl
      have prefixU := reachable_has_control_prefix u reach
      simp only [ControlPrefix, ready] at prefixU
      cases ph with
      | Preflight =>
        obtain ⟨vt, fe⟩ := marks
        simp only [PhasePrefix, DispatchPrefix] at prefixU
        have uf : u.preflight.provider_attempted = false := by simpa using prefixU.1.2.2.2.2.1
        cases q with
        | Preflight => simp [bit, raised, ones, vt, uf]
        | Final =>
          have hb : bit .Final v = bit .Final u := by simp [bit, fe]
          rw [hb]; cases bit .Final u <;> simp [raised, ones]
      | Final =>
        obtain ⟨vt, pe⟩ := marks
        simp only [PhasePrefix, DispatchPrefix] at prefixU
        have uf : u.final_effect.provider_attempted = false := by simpa using prefixU.2.1.2.2.2.2.1
        cases q with
        | Final => simp [bit, raised, ones, vt, uf]
        | Preflight =>
          have hb : bit .Preflight v = bit .Preflight u := by simp [bit, pe]
          rw [hb]; cases bit .Preflight u <;> simp [raised, ones]

/-- **Per phase, a trace's sends are exactly that phase's newly marked
    attempt.** -/
theorem trace_phase_count (contexts : read_transition.Phase → Context) {s t : RequestEffects}
    {events : List confinement.Proofs.Event} (reach : Reachable s) (trace : TraceSteps contexts s t events)
    (q : read_transition.Phase) :
    (sendsOf q events).length + ones (bit q s) = ones (bit q t) := by
  induction trace with
  | refl => simp [sendsOf]
  | @next u v evs prior step origin ih =>
    have reachU := (trace_steps_preserve_soundness _ _ _ _ reach prior).1
    have one := step_phase_count contexts reachU step q
    simp only [sendsOf, List.filter_append, List.length_append] at ih one ⊢
    omega

/-! ## Each send's channel and phase, within one dispatch -/
section dispatch
variable {D C H O X : Type} (work : dispatch.Work D H O X) (checks : current_admission.Checks C X)
  (Inv : D → Prop)

/-- `Inv` is preserved by every callback of the primitive that the bound
    dispatch can call on it. -/
structure Keeps : Prop where
  prepare : ∀ s r t, work.prepare s = Result.ok (r, t) → Inv s → Inv t
  audit : ∀ s ph r t, work.audit s ph = Result.ok (r, t) → Inv s → Inv t
  configure : ∀ s k r t, work.configure s k = Result.ok (r, t) → Inv s → Inv t
  check : ∀ s r t, work.check s = Result.ok (r, t) → Inv s → Inv t
  reserve : ∀ s r t, work.reserve s = Result.ok (r, t) → Inv s → Inv t
  finish : ∀ s r t, work.finish s = Result.ok (r, t) → Inv s → Inv t
  setup : ∀ s r t, work.provider_exchangeProviderInst.setup s = Result.ok (r, t) → Inv s → Inv t
  send : ∀ s c r t n, work.provider_exchangeProviderInst.send s c = Result.ok (r, t, n) → Inv s → Inv t
  receive : ∀ s c r t, work.provider_exchangeProviderInst.receive s c = Result.ok (r, t) → Inv s → Inv t

/-- `c` is a channel the primitive's own `setup` returned, from a state
    satisfying `Inv`. -/
def SetupFrom (c : H) : Prop :=
  ∃ d d', Inv d ∧ work.provider_exchangeProviderInst.setup d = Result.ok (.Ok c, d')

abbrev LPending (D C H O X : Type) := dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X

/-- From `before` to `after`: `Inv` is carried, every newly recorded send's
    channel came from a setup under `Inv`, and the attempt bit of the phase
    other than `ph` is unchanged. -/
def Track (ph : read_transition.Phase) (before after : LPending D C H O X) : Prop :=
  (Inv before.work.work.1 →
    Inv after.work.work.1 ∧ ∀ c, c ∈ calls after → c ∈ calls before ∨ SetupFrom work Inv c) ∧
  bit (other ph) after.effects = bit (other ph) before.effects

theorem track_refl (ph) (p : LPending D C H O X) : Track work Inv ph p p :=
  ⟨fun i => ⟨i, fun _ m => Or.inl m⟩, rfl⟩

theorem track_trans {ph} {a b c : LPending D C H O X} (l : Track work Inv ph a b) (r : Track work Inv ph b c) :
    Track work Inv ph a c := by
  refine ⟨fun i => ?_, r.2.trans l.2⟩
  obtain ⟨ib, mb⟩ := l.1 i
  obtain ⟨ic, mc⟩ := r.1 ib
  refine ⟨ic, fun x m => ?_⟩
  rcases mc x m with h | h
  · exact mb x h
  · exact Or.inr h

/-- A step that keeps the record list, the primitive state's invariant and
    both attempt bits. -/
theorem track_same {ph} {a b : LPending D C H O X} (log : calls b = calls a)
    (inv : Inv a.work.work.1 → Inv b.work.work.1) (bits : Attempts b.effects = Attempts a.effects) :
    Track work Inv ph a b :=
  ⟨fun i => ⟨inv i, fun _ m => Or.inl (log ▸ m)⟩, bit_of_attempts bits _⟩

set_option hygiene false in
/-- A forwarding callback of the bound logged primitive calls the base
    callback on the base state and keeps the log. -/
local macro "base_call " fn:ident : tactic => `(tactic| (
  simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
    current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold $fn:ident at h
  simp only [logged, loggedProvider] at h
  obtain ⟨⟨r1, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨⟨r2, d⟩, base, back⟩ := (bind_returns_iff _ _ _).mp inner
  have e1 := Result.ok_injective back
  have e2 := Result.ok_injective rest
  simp only [uncurry_apply_pair, Prod.mk.injEq] at e1 e2
  obtain ⟨rfl, rfl⟩ := e1
  obtain ⟨rfl, rfl⟩ := e2
  exact ⟨base, rfl⟩))

theorem base_prepare {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).prepare b = Result.ok (r, b')) :
    work.prepare b.work.1 = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.prepare

theorem base_audit {b b' : current_admission.Bound (D × List H) C H O X} {ph : read_transition.Phase}
    {r : core.result.Result Unit X} (h : (boundL work checks).audit b ph = Result.ok (r, b')) :
    work.audit b.work.1 ph = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.audit

theorem base_configure {b b' : current_admission.Bound (D × List H) C H O X} {k : Bool}
    {r : core.result.Result Unit X} (h : (boundL work checks).configure b k = Result.ok (r, b')) :
    work.configure b.work.1 k = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.configure

theorem base_check {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).check b = Result.ok (r, b')) :
    work.check b.work.1 = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.check

theorem base_reserve {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).reserve b = Result.ok (r, b')) :
    work.reserve b.work.1 = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.reserve

theorem base_finish {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).finish b = Result.ok (r, b')) :
    work.finish b.work.1 = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.finish

theorem base_setup {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result H X}
    (h : (boundL work checks).provider_exchangeProviderInst.setup b = Result.ok (r, b')) :
    work.provider_exchangeProviderInst.setup b.work.1 = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup

theorem base_receive {b b' : current_admission.Bound (D × List H) C H O X} {ch : H} {r : core.result.Result O X}
    (h : (boundL work checks).provider_exchangeProviderInst.receive b ch = Result.ok (r, b')) :
    work.provider_exchangeProviderInst.receive b.work.1 ch = Result.ok (r, b'.work.1) ∧ b'.work.2 = b.work.2 := by
  base_call current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive

theorem base_send {b b' : current_admission.Bound (D × List H) C H O X} {ch next : H} {r : core.result.Result Unit X}
    (h : (boundL work checks).provider_exchangeProviderInst.send b ch = Result.ok (r, b', next)) :
    work.provider_exchangeProviderInst.send b.work.1 ch = Result.ok (r, b'.work.1, next) ∧
      b'.work.2 = b.work.2 ++ [ch] := by
  simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
    current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at h
  simp only [logged, loggedProvider] at h
  obtain ⟨⟨r1, t, n1⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨⟨r2, d, n2⟩, base, back⟩ := (bind_returns_iff _ _ _).mp inner
  have e1 := Result.ok_injective back
  have e2 := Result.ok_injective rest
  simp only [uncurry_apply_pair, Prod.mk.injEq] at e1 e2
  obtain ⟨rfl, rfl, rfl⟩ := e1
  obtain ⟨rfl, rfl, rfl⟩ := e2
  exact ⟨base, rfl⟩

theorem setup_track {ph} (keeps : Keeps work Inv) {p after : LPending D C H O X} {out : core.result.Result H X}
    (h : (adapterL work checks).setup p = Result.ok (out, after)) :
    Track work Inv ph p after ∧ after.phase = p.phase ∧ after.effects = p.effects ∧
      (Inv p.work.work.1 → ∀ c, out = .Ok c → SetupFrom work Inv c) := by
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup at h
  obtain ⟨⟨r, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨base, log⟩ := base_setup work checks inner
  have e := Result.ok_injective rest
  simp only [uncurry_apply_pair, Prod.mk.injEq] at e
  obtain ⟨rfl, rfl⟩ := e
  refine ⟨track_same work Inv (by simp [calls, log]) (keeps.setup _ _ _ base) rfl, rfl, rfl, ?_⟩
  intro i c hc
  subst hc
  exact ⟨_, _, i, base⟩

theorem receive_track {ph} (keeps : Keeps work Inv) {p after : LPending D C H O X} {ch : H}
    {out : core.result.Result O X}
    (h : (adapterL work checks).receive p ch = Result.ok (out, after)) : Track work Inv ph p after := by
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive at h
  obtain ⟨⟨r, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨base, log⟩ := base_receive work checks inner
  have e := Result.ok_injective rest
  simp only [uncurry_apply_pair, Prod.mk.injEq] at e
  obtain ⟨rfl, rfl⟩ := e
  exact track_same work Inv (by simp [calls, log]) (keeps.receive _ _ _ _ base) rfl

theorem recheck_track {ph} {p after : LPending D C H O X} {out : core.result.Result manifest.AdmissionStamp X}
    (h : (adapterL work checks).recheck p = Result.ok (out, after)) :
    Track work Inv ph p after ∧ after.phase = p.phase ∧ after.effects = p.effects := by
  have grown := recheck_grew work checks h
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at h
  -- The bound recheck changes only the checks; every branch keeps work, phase and receipt.
  have shape : after.work.work = p.work.work ∧ after.phase = p.phase ∧ after.effects = p.effects := by
    obtain ⟨⟨b, ss⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp h
    cases b with
    | false =>
      obtain ⟨e, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have pair := Result.ok_injective rest
      simp only [Prod.mk.injEq] at pair
      obtain ⟨_, rfl⟩ := pair
      exact ⟨rfl, rfl, rfl⟩
    | true =>
      obtain ⟨⟨r, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have same := bound_recheck_log work checks inner
      cases r with
      | Err e =>
        have pair := Result.ok_injective rest
        simp only [Prod.mk.injEq] at pair
        obtain ⟨_, rfl⟩ := pair
        exact ⟨by simp [same], rfl, rfl⟩
      | Ok stamp =>
        obtain ⟨⟨b1, ss1⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
        cases b1 with
        | true =>
          have pair := Result.ok_injective rest
          simp only [Prod.mk.injEq] at pair
          obtain ⟨_, rfl⟩ := pair
          exact ⟨by simp [same], rfl, rfl⟩
        | false =>
          obtain ⟨e, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have pair := Result.ok_injective rest
          simp only [Prod.mk.injEq] at pair
          obtain ⟨_, rfl⟩ := pair
          exact ⟨by simp [same], rfl, rfl⟩
  obtain ⟨w, phs, eff⟩ := shape
  exact ⟨track_same work Inv (by simp [calls, w]) (by rw [w]; exact id) (by rw [eff]), phs, eff⟩

/-- An accepted composite send gate leaves the other phase's bit alone. -/
theorem marks_other {u v : RequestEffects} {ph : read_transition.Phase} {l l' : provider_exchange.SendState}
    {w : Bool} (h : RequestEffects.begin_send u ph l w = Result.ok (true, v, l')) :
    bit (other ph) v = bit (other ph) u := by
  obtain ⟨_, accepted⟩ := begin_send_marks h
  obtain ⟨_, marked⟩ := accepted rfl
  cases ph with
  | Preflight => simp [bit, other, marked.2]
  | Final => simp [bit, other, marked.2]

/-- A provider send, accepted or refused by the composite gate. The channel
    passed is recorded only if the gate accepted, and the gate marks only
    the pending phase. -/
theorem send_track (keeps : Keeps work Inv) {p after : LPending D C H O X} {ch next : H}
    {out : core.result.Result Unit X} (from_setup : Inv p.work.work.1 → SetupFrom work Inv ch)
    (h : (adapterL work checks).send p ch = Result.ok (out, after, next)) :
    Track work Inv p.phase p after ∧ after.phase = p.phase := by
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at h
  obtain ⟨⟨accepted, effects, localState⟩, gate, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨refused, marks⟩ := begin_send_marks gate
  cases accepted with
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte] at rest
    obtain ⟨e, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have pair := Result.ok_injective rest
    simp only [Prod.mk.injEq] at pair
    obtain ⟨_, rfl, _⟩ := pair
    exact ⟨track_same work Inv rfl id (refused rfl), rfl⟩
  | true =>
    simp only [↓reduceIte] at rest
    obtain ⟨⟨r, t, n⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp rest
    obtain ⟨base, log⟩ := base_send work checks inner
    have pair := Result.ok_injective rest
    simp only [Prod.mk.injEq] at pair
    obtain ⟨_, rfl, _⟩ := pair
    have other_kept := marks_other gate
    refine ⟨⟨fun i => ⟨keeps.send _ _ _ _ _ base i, fun c m => ?_⟩, ?_⟩, rfl⟩
    · simp only [calls, log, List.mem_append, List.mem_singleton] at m
      rcases m with m | rfl
      · exact Or.inl m
      · exact Or.inr (from_setup i)
    · exact other_kept

theorem inv_of {ph} {a b : LPending D C H O X} (t : Track work Inv ph a b) (i : Inv a.work.work.1) :
    Inv b.work.work.1 := (t.1 i).1

/-- **The provider driver, once.** Its only send is on the channel its own
    setup returned, and it marks only the pending phase. -/
theorem driver_track (keeps : Keeps work Inv) (pending after : LPending D C H O X)
    (audited : read_transition.Audited) (report : provider_exchange.Report O X)
    (i : Inv pending.work.work.1)
    (returned : provider_exchange.exchange (adapterL work checks) pending audited = Result.ok (report, after)) :
    Track work Inv pending.phase pending after := by
  unfold provider_exchange.exchange at returned
  simp [read_transition.Audited.impl.phase, read_transition.Audited.is_write] at returned
  obtain ⟨⟨initial, state1⟩, planned, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨first, ph1, _, origin⟩ := setup_track work checks Inv (ph := pending.phase) keeps planned
  cases initial with
  | Err error =>
    have same := returned_state (provider_exchange.Report.mk audited.phase .Setup none (.Err error)) report state1 after rest
    subst after
    exact first
  | Ok channel =>
    have chan := origin i channel rfl
    obtain ⟨⟨checked, second⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
    obtain ⟨rechecked, ph2, _⟩ := recheck_track work checks Inv (ph := pending.phase) current
    have prior := track_trans work Inv first rechecked
    cases checked with
    | Err error =>
      have same := returned_state (provider_exchange.Report.mk audited.phase .Admission none (.Err error)) report second after rest
      subst after
      exact prior
    | Ok stamp =>
      have finish : ∀ (third : LPending D C H O X) next sent,
          (adapterL work checks).send second channel = Result.ok (sent, third, next) →
          (∀ last received, (adapterL work checks).receive third next = Result.ok (received, last) →
            Track work Inv pending.phase pending last) ∧ Track work Inv pending.phase pending third := by
        intro third next sent sending
        obtain ⟨sent_track, _⟩ := send_track work checks Inv keeps (fun _ => chan) sending
        rw [ph2, ph1] at sent_track
        have upto := track_trans work Inv prior sent_track
        exact ⟨fun last received receiving => track_trans work Inv upto (receive_track work checks Inv keeps receiving), upto⟩
      cases writing : audited.write with
      | false =>
        simp [writing] at rest
        obtain ⟨⟨sent, third, next⟩, sending, rest⟩ := (bind_returns_iff _ _ _).mp rest
        obtain ⟨afterReceive, afterSend⟩ := finish third next sent sending
        cases sent with
        | Err error =>
          have same := returned_state (provider_exchange.Report.mk audited.phase .Send (some stamp) (.Err error)) report third after (by simpa using rest)
          subst after
          exact afterSend
        | Ok u =>
          cases u
          obtain ⟨⟨received, last⟩, receiving, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have same : after = last := by
            cases received with
            | Err error => exact returned_state (provider_exchange.Report.mk audited.phase .Response (some stamp) (.Err error)) report last after (by simpa using rest)
            | Ok value => exact returned_state (provider_exchange.Report.mk audited.phase .Complete (some stamp) (.Ok value)) report _ _ (by simpa using rest)
          subst after
          exact afterReceive last received receiving
      | true =>
        simp [writing, manifest.AdmissionStamp.impl.write] at rest
        cases allowed : stamp.write with
        | false =>
          have same := fixed_state (adapterL work checks).INVALID_POLICY
            (fun error => provider_exchange.Report.mk audited.phase .Admission (some stamp) (.Err error)) second after report (by simpa [allowed] using rest)
          subst after
          exact prior
        | true =>
          simp [allowed] at rest
          obtain ⟨⟨sent, third, next⟩, sending, rest⟩ := (bind_returns_iff _ _ _).mp rest
          obtain ⟨afterReceive, afterSend⟩ := finish third next sent sending
          cases sent with
          | Err error =>
            have same := fixed_state (adapterL work checks).OUTCOME_UNKNOWN (fun error => provider_exchange.Report.mk audited.phase .Send (some stamp) (.Err error)) third after report (by simpa using rest)
            subst after
            exact afterSend
          | Ok u =>
            cases u
            obtain ⟨⟨received, last⟩, receiving, rest⟩ := (bind_returns_iff _ _ _).mp rest
            have same : after = last := by
              cases received with
              | Err error => exact fixed_state (adapterL work checks).OUTCOME_UNKNOWN (fun error => provider_exchange.Report.mk audited.phase .Response (some stamp) (.Err error)) last after report (by simpa using rest)
              | Ok value => exact returned_state (provider_exchange.Report.mk audited.phase .Complete (some stamp) (.Ok value)) report _ _ (by simpa using rest)
            subst after
            exact afterReceive last received receiving

/-- A step on the base primitive that the bound dispatch forwards. -/
theorem track_base {ph} {a b : LPending D C H O X} (log : b.work.work.2 = a.work.work.2)
    (inv : Inv a.work.work.1 → Inv b.work.work.1) (bits : Attempts b.effects = Attempts a.effects) :
    Track work Inv ph a b := track_same work Inv (by simp [calls, log]) inv bits

theorem audit_track {ph} (keeps : Keeps work Inv) (pending after : LPending D C H O X)
    (prepared : read_transition.Prepared) (out : core.result.Result read_transition.Audited X)
    (returned : dispatch.audit (boundL work checks) pending prepared = Result.ok (out, after)) :
    Track work Inv ph pending after ∧ ∀ permit, out = .Ok permit → permit.phase = prepared.phase := by
  unfold dispatch.audit at returned
  obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨base1, log1⟩ := base_prepare work checks callback
  have prepared1 : Track work Inv ph pending {pending with work := native} :=
    track_base work Inv log1 (keeps.prepare _ _ _ base1) rfl
  cases result with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result read_transition.Audited X) out {pending with work := native} after (by simpa using rest)
    subst after
    refine ⟨prepared1, fun permit h => ?_⟩
    have pair : (core.result.Result.Err error : core.result.Result read_transition.Audited X) = out := by
      simpa using rest
    rw [h] at pair; cases pair
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have marked : Track work Inv ph {pending with work := native} {pending with work := native, effects := firstReceipt} := by
      obtain ⟨phx, w⟩ := prepared
      exact track_same work Inv rfl id (begin_dispatch_audit_keeps began)
    have prior := track_trans work Inv prepared1 marked
    cases accepted with
    | false =>
      have same := fixed_state (boundL work checks).INVALID_TRANSITION (fun error => (.Err error : core.result.Result read_transition.Audited X))
        {pending with work := native, effects := firstReceipt} after out (by simpa using rest)
      subst after
      refine ⟨prior, fun permit h => ?_⟩
      obtain ⟨e, _, back⟩ := (bind_returns_iff _ _ _).mp (by simpa using rest : (do let error ← (boundL work checks).INVALID_TRANSITION; Result.ok ((.Err error : core.result.Result read_transition.Audited X), ({pending with work := native, effects := firstReceipt} : LPending D C H O X))) = Result.ok (out, _))
      simp only [Result.ok.injEq, Prod.mk.injEq] at back
      rw [h] at back; cases back.1
    | true =>
      simp [read_transition.Prepared.impl.phase] at rest
      obtain ⟨⟨written, native2⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      obtain ⟨base2, log2⟩ := base_audit work checks auditCall
      have audited : Track work Inv ph {pending with work := native, effects := firstReceipt}
          {pending with work := native2, effects := firstReceipt} :=
        track_base work Inv log2 (keeps.audit _ _ _ _ base2) rfl
      have prior := track_trans work Inv prior audited
      cases written with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result read_transition.Audited X) out
          {pending with work := native2, effects := firstReceipt} after (by simpa using rest)
        subst after
        refine ⟨prior, fun permit h => ?_⟩
        have pair : (core.result.Result.Err error : core.result.Result read_transition.Audited X) = out := by
          simpa using rest
        rw [h] at pair; cases pair
      | Ok u =>
        cases u
        simp [read_transition.acknowledge] at rest
        obtain ⟨⟨accepted, last⟩, ack, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Track work Inv ph {pending with work := native2, effects := firstReceipt}
            {pending with work := native2, effects := last} := by
          exact track_same work Inv rfl id (acknowledge_dispatch_keeps ack)
        have same : after = {pending with work := native2, effects := last} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result read_transition.Audited X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok ⟨prepared.phase, prepared.write⟩ : core.result.Result read_transition.Audited X) out _ _ (by simpa using rest)
        subst after
        refine ⟨track_trans work Inv prior suffix, fun permit h => ?_⟩
        cases accepted with
        | false =>
          obtain ⟨e, _, back⟩ := (bind_returns_iff _ _ _).mp (by simpa using rest : (do let error ← (boundL work checks).INVALID_TRANSITION; Result.ok ((.Err error : core.result.Result read_transition.Audited X), ({pending with work := native2, effects := last} : LPending D C H O X))) = Result.ok (out, _))
          simp only [Result.ok.injEq, Prod.mk.injEq] at back
          rw [h] at back; cases back.1
        | true =>
          have pair : (core.result.Result.Ok ⟨prepared.phase, prepared.write⟩ : core.result.Result read_transition.Audited X) = out := by
            simpa using rest
          rw [h] at pair
          cases pair
          rfl

theorem exchange_track (keeps : Keeps work Inv) (pending after : LPending D C H O X)
    (audited : read_transition.Audited) (out : core.result.Result O X) (i : Inv pending.work.work.1)
    (returned : dispatch.exchange (boundL work checks) pending audited = Result.ok (out, after)) :
    Track work Inv audited.phase pending after := by
  unfold dispatch.exchange at returned
  simp [read_transition.Audited.is_write] at returned
  obtain ⟨effectWrite, policy, rest⟩ := (bind_returns_iff _ _ _).mp returned
  split at rest
  · obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have kept : Attempts firstReceipt = Attempts pending.effects := by
      obtain ⟨ph, w⟩ := audited
      exact begin_provider_keeps began
    have prior : Track work Inv audited.phase pending
        {pending with effects := firstReceipt, phase := audited.phase, write := audited.write} :=
      track_same work Inv rfl id kept
    cases accepted with
    | false =>
      have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) {pending with effects := firstReceipt} after out (by simpa using rest)
      subst after
      exact track_same work Inv rfl id kept
    | true =>
      simp [read_transition.Audited.impl.phase] at rest
      obtain ⟨⟨report, driverState⟩, driver, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have driven := driver_track work checks Inv keeps
        {pending with effects := firstReceipt, phase := audited.phase, write := audited.write}
        driverState audited report i driver
      have prefixTrack := track_trans work Inv prior driven
      simp [provider_exchange.Report.impl.stage, provider_exchange.Report.impl.current, provider_exchange.Report.into_result] at rest
      cases result : report.result with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {driverState with provider_stage := some report.stage, current := report.current} after (by simpa [result] using rest)
        subst after
        exact prefixTrack
      | Ok value =>
        simp only [result] at rest
        obtain ⟨⟨accepted, last⟩, completed, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Track work Inv audited.phase driverState {driverState with effects := last} :=
          track_same work Inv rfl id (provider_completed_keeps completed)
        have same : after = {driverState with effects := last, provider_stage := some report.stage, current := report.current} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result O X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
        subst after
        exact track_trans work Inv prefixTrack suffix
  · have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) pending after out rest
    subst after
    exact track_refl work Inv _ _

theorem finish_track {ph} (keeps : Keeps work Inv) (pending after : LPending D C H O X)
    (keyed : Bool) (out : core.result.Result Unit X)
    (returned : dispatch.finish (boundL work checks) pending keyed = Result.ok (out, after)) :
    Track work Inv ph pending after := by
  unfold dispatch.finish at returned
  obtain ⟨⟨nextState, finished⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have framed : Track work Inv ph pending nextState := by
    cases keyed with
    | false =>
      have pair := (Result.ok.injEq).mp finishCall
      have same : pending = nextState := congrArg Prod.fst pair
      rw [← same]
      exact track_refl work Inv _ _
    | true =>
      obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp finishCall
      have same : nextState = {pending with work := native} := by
        exact (by simpa using rest : {pending with work := native} = nextState ∧ result = finished).1.symm
      subst nextState
      obtain ⟨base, log⟩ := base_finish work checks callback
      exact track_base work Inv log (keeps.finish _ _ _ base) rfl
  cases finished with
  | Err error =>
    have same := fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) nextState after out rest
    subst after
    exact framed
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have suffix : Track work Inv ph nextState {nextState with effects := last} :=
      track_same work Inv rfl id (finish_dispatch_keeps finished)
    have same : after = {nextState with effects := last} := by
      cases accepted with
      | false => exact fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) _ _ _ (by simpa using rest)
      | true => exact returned_state (.Ok () : core.result.Result Unit X) out _ _ (by simpa using rest)
    subst after
    exact track_trans work Inv framed suffix

theorem run_track (keeps : Keeps work Inv) (pending after : LPending D C H O X)
    (prepared : read_transition.Prepared) (keyed : Bool) (out : core.result.Result O X)
    (i : Inv pending.work.work.1)
    (returned : dispatch.run (boundL work checks) pending prepared keyed = Result.ok (out, after)) :
    Track work Inv prepared.phase pending after := by
  unfold dispatch.run at returned
  obtain ⟨⟨audited, firstState⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  obtain ⟨prefixTrack, permitPhase⟩ := audit_track work checks Inv (ph := prepared.phase) keeps pending firstState prepared audited auditCall
  cases audited with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result O X) out firstState after (by simpa using rest)
    subst after
    exact prefixTrack
  | Ok permit =>
    have phaseEq := permitPhase permit rfl
    obtain ⟨⟨configured, native1⟩, configuredCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
    obtain ⟨baseC, logC⟩ := base_configure work checks configuredCall
    have prefixTrack := track_trans work Inv prefixTrack
      (track_base work Inv (b := {firstState with work := native1}) logC (keeps.configure _ _ _ _ baseC) rfl)
    cases configured with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := native1} after (by simpa using rest)
      subst after
      exact prefixTrack
    | Ok u =>
      cases u
      obtain ⟨⟨checked, work2⟩, checkCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      obtain ⟨baseK, logK⟩ := base_check work checks checkCall
      have prefixTrack := track_trans work Inv prefixTrack
        (track_base work Inv (a := {firstState with work := native1}) (b := {firstState with work := work2})
          logK (keeps.check _ _ _ baseK) rfl)
      cases checked with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work2} after (by simpa using rest)
        subst after
        exact prefixTrack
      | Ok u =>
        cases u
        obtain ⟨⟨work3, reserved⟩, reserveCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have reserveStep : work3.work.2 = work2.work.2 ∧ (Inv work2.work.1 → Inv work3.work.1) := by
          cases keyed with
          | false =>
            have pair : work2 = work3 ∧ (.Ok () : core.result.Result Unit X) = reserved := by simpa using reserveCall
            rw [← pair.1]
            exact ⟨rfl, id⟩
          | true =>
            obtain ⟨⟨result, native⟩, call, same⟩ := (bind_returns_iff _ _ _).mp reserveCall
            have pair : native = work3 ∧ result = reserved := by simpa using same
            rw [← pair.1]
            obtain ⟨baseR, logR⟩ := base_reserve work checks call
            exact ⟨logR, keeps.reserve _ _ _ baseR⟩
        have prefixTrack := track_trans work Inv prefixTrack
          (track_base work Inv (a := {firstState with work := work2}) (b := {firstState with work := work3})
            reserveStep.1 reserveStep.2 rfl)
        cases reserved with
        | Err error =>
          have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work3} after (by simpa using rest)
          subst after
          exact prefixTrack
        | Ok u =>
          cases u
          obtain ⟨⟨exchanged, secondState⟩, exchangeCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have exchangedTrack := exchange_track work checks Inv keeps {firstState with work := work3} secondState
            permit exchanged (inv_of work Inv prefixTrack i) exchangeCall
          rw [phaseEq] at exchangedTrack
          have prefixTrack := track_trans work Inv prefixTrack exchangedTrack
          cases exchanged with
          | Err error =>
            have same := returned_state (.Err error : core.result.Result O X) out secondState after (by simpa using rest)
            subst after
            exact prefixTrack
          | Ok value =>
            obtain ⟨⟨finished, lastState⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
            have prefixTrack := track_trans work Inv prefixTrack
              (finish_track work checks Inv keeps secondState lastState keyed finished finishCall)
            have same : after = lastState := by
              cases finished with
              | Err error => exact returned_state (.Err error : core.result.Result O X) out _ _ (by simpa using rest)
              | Ok u => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
            subst after
            exact prefixTrack

/-- **Within one logged dispatch, every recorded send's channel came from the
    primitive's own setup under `Inv`, and only the prepared phase's attempt
    bit can change.** -/
theorem dispatch_track (keeps : Keeps work Inv) (primitive : current_admission.Bound (D × List H) C H O X)
    (prepared : read_transition.Prepared) (before : RequestEffects) (keyed : Bool)
    (report : dispatch.Report (current_admission.Bound (D × List H) C H O X) H O X)
    (i : Inv primitive.work.1)
    (returned : dispatch.dispatch (boundL work checks) primitive (.Ok prepared) before keyed = Result.ok report) :
    (∀ c, c ∈ report.work.work.2 → c ∈ primitive.work.2 ∨ SetupFrom work Inv c) ∧
      bit (other prepared.phase) report.effects = bit (other prepared.phase) before := by
  simp [dispatch.dispatch, read_transition.Prepared.impl.phase, provider_exchange.SendState.new] at returned
  obtain ⟨⟨result, after⟩, ran, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have tracked := run_track work checks Inv keeps ⟨primitive, before, ⟨.Empty⟩, prepared.phase, false, none, none⟩ after
    prepared keyed result i ran
  have same : report = ⟨result, after.work, after.effects, after.«local», after.provider_stage, after.current⟩ := by
    simpa using rest.symm
  subst report
  exact ⟨(tracked.1 i).2, tracked.2⟩

theorem attCount_ones (s : RequestEffects) : attCount s = ones (bit .Preflight s) + ones (bit .Final s) := rfl

theorem sendsOf_sub (ph : read_transition.Phase) (events : List confinement.Proofs.Event) :
    sendsOf ph events = (sourceSends events).filter (sendOf ph) := by
  induction events with
  | nil => rfl
  | cons e rest ih =>
    cases e <;> cases ph <;> simp_all [sendsOf, sourceSends, sendOf, isSend, List.filter_cons]

theorem single_send_of_phase {ph : read_transition.Phase} {events : List confinement.Proofs.Event}
    {e : confinement.Proofs.Event} (single : sourceSends events = [e]) (one : (sendsOf ph events).length = 1) :
    ∃ g a, e = .providerSend (eventPhase ph) g a := by
  rw [sendsOf_sub, single] at one
  cases e with
  | providerSend p g a =>
    cases p <;> cases ph <;> simp_all [sendOf, List.filter, eventPhase]
  | _ => cases ph <;> simp_all [sendOf, List.filter]

/-- **One production-shaped dispatch, call by call.** A returned dispatch of
    the bound primitive from a reachable receipt, re-run with a send log
    (same report), and any chronological trace of it: either nothing was
    sent and the trace has no provider send, or exactly one channel was
    sent, the trace has exactly one provider send, of the dispatch's own
    phase, and the channel is one the primitive's own `setup` returned from
    a state satisfying `Inv`. -/
theorem dispatch_origin (keeps : Keeps work Inv) (primitive : current_admission.Bound D C H O X)
    (prepared : read_transition.Prepared) (before : RequestEffects) (keyed : Bool)
    (report : dispatch.Report (current_admission.Bound D C H O X) H O X)
    (reach : Reachable before) (i : Inv primitive.work)
    (returned : dispatch.dispatch (current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks)
      primitive (.Ok prepared) before keyed = Result.ok report)
    (contexts : read_transition.Phase → Context) {events : List confinement.Proofs.Event}
    (trace : TraceSteps contexts before report.effects events) :
    ∃ logged : dispatch.Report (current_admission.Bound (D × List H) C H O X) H O X,
      dispatch.dispatch (boundL work checks) (liftB primitive []) (.Ok prepared) before keyed = Result.ok logged ∧
      dispatch.Erasure.eraseReport eraseB logged = report ∧
      ((logged.work.work.2 = [] ∧ sourceSends events = []) ∨
       (∃ c g a, logged.work.work.2 = [c] ∧
          sourceSends events = [.providerSend (eventPhase prepared.phase) g a] ∧
          SetupFrom work Inv c)) := by
  obtain ⟨logged, ran, erased, count⟩ :=
    production_dispatch_sends work checks primitive (.Ok prepared) before keyed report reach returned
  have effects : logged.effects = report.effects := by rw [← erased]; rfl
  obtain ⟨origins, otherKept⟩ := dispatch_track work checks Inv keeps (liftB primitive []) prepared before keyed logged i ran
  rw [effects] at otherKept
  have total := trace_count contexts reach trace
  have otherCount := trace_phase_count contexts reach trace (other prepared.phase)
  have ownCount := trace_phase_count contexts reach trace prepared.phase
  rw [otherKept] at otherCount
  have noOther : (sendsOf (other prepared.phase) events).length = 0 := by omega
  refine ⟨logged, ran, erased, ?_⟩
  have origin : ∀ c, c ∈ logged.work.work.2 → SetupFrom work Inv c := by
    intro c m
    rcases origins c m with h | h
    · simp [liftB] at h
    · exact h
  have sum : ∀ s : RequestEffects, attCount s = ones (bit prepared.phase s) + ones (bit (other prepared.phase) s) := by
    intro s; cases prepared.phase <;> simp [attCount_ones, other]; omega
  rw [sum before, sum report.effects, otherKept] at count total
  have bound : ones (bit prepared.phase report.effects) ≤ 1 := by unfold ones; split <;> omega
  match hcs : logged.work.work.2, hsends : sourceSends events with
  | [], sends =>
    left
    refine ⟨rfl, ?_⟩
    rw [hcs] at count
    have : sends.length = 0 := by rw [← hsends]; simp at count; omega
    exact List.eq_nil_of_length_eq_zero this
  | [c], [] =>
    rw [hcs] at count; rw [hsends] at total; simp at count total; omega
  | [c], [e] =>
    right
    have one : (sendsOf prepared.phase events).length = 1 := by
      rw [hcs] at count; simp at count; omega
    obtain ⟨g, a, rfl⟩ := single_send_of_phase hsends one
    exact ⟨c, g, a, rfl, rfl, origin c (by rw [hcs]; simp)⟩
  | [c], _ :: _ :: _ =>
    rw [hcs] at count; rw [hsends] at total; simp at count total; omega
  | _ :: _ :: _, _ =>
    rw [hcs] at count; simp at count; omega

end dispatch

end aivm_secrets_garrett_core.nr23.SendOrigin
