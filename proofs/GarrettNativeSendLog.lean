import GarrettDispatchTrace
import GarrettDispatchErasure
import GarrettNR23ExactSinks

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false

namespace aivm_secrets_garrett_core.nr23.SendLog
open aivm_secrets_garrett_core.request_effects aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.nr23.ExactSinks
open aivm_secrets_garrett_core.provider_exchange.Simulation

/-- The provider-attempt bits of the two dispatch phases. -/
def Attempts (s : RequestEffects) : Bool × Bool :=
  (s.preflight.provider_attempted, s.final_effect.provider_attempted)

/-- A receipt change that keeps both attempt bits produces no provider send. -/
theorem quiet_delta (contexts : read_transition.Phase → Context) (s after : RequestEffects)
    (same : Attempts after = Attempts s) : sourceSends (delta contexts s after) = [] := by
  simp only [Attempts, Prod.mk.injEq] at same
  simp [sourceSends, delta, phaseDelta, auditDelta, providerDelta, raised, same.1, same.2, List.filter_append,
    isSend]
  refine ⟨fun a _ _ e => by subst e; rfl, fun a _ _ e => by subst e; rfl, fun a _ _ e => by subst e; rfl⟩

set_option hygiene false in
/-- Evaluate one receipt gate on every progress and phase: each branch either
    rejects (only the progress changes) or edits a record without touching
    its attempt bit. -/
local macro "keeps_bits " fn:ident : tactic => `(tactic| (
  obtain ⟨pre, fin, comp, prog⟩ := s
  cases prog <;> cases ph <;>
    simp [$fn:ident, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase,
      read_transition.Audited.impl.phase, read_transition.Prepared.impl.phase,
      read_transition.Phase.Insts.CoreCmpPartialEqPhase.eq, Attempts] at h ⊢ <;>
    (try split at h) <;> (try simp at h) <;>
    (try obtain ⟨_, rfl⟩ := h) <;> (try rfl) <;> (try simp_all)))

theorem begin_provider_keeps {s after : RequestEffects} {ph : read_transition.Phase} {w acc : Bool}
    (h : RequestEffects.begin_provider s ⟨ph, w⟩ = Result.ok (acc, after)) : Attempts after = Attempts s := by
  keeps_bits RequestEffects.begin_provider

theorem begin_dispatch_audit_keeps {s after : RequestEffects} {ph : read_transition.Phase} {w acc : Bool}
    (h : RequestEffects.begin_dispatch_audit s ⟨ph, w⟩ = Result.ok (acc, after)) : Attempts after = Attempts s := by
  keeps_bits RequestEffects.begin_dispatch_audit

theorem acknowledge_dispatch_keeps {s after : RequestEffects} {ph : read_transition.Phase} {w acc : Bool}
    (h : RequestEffects.acknowledge_dispatch s ⟨ph, w⟩ = Result.ok (acc, after)) : Attempts after = Attempts s := by
  keeps_bits RequestEffects.acknowledge_dispatch

theorem provider_completed_keeps {s after : RequestEffects} {ph : read_transition.Phase} {acc : Bool}
    (h : RequestEffects.provider_completed s ph = Result.ok (acc, after)) : Attempts after = Attempts s := by
  keeps_bits RequestEffects.provider_completed

theorem finish_dispatch_keeps {s after : RequestEffects} {ph : read_transition.Phase} {acc : Bool}
    (h : RequestEffects.finish_dispatch s ph = Result.ok (acc, after)) : Attempts after = Attempts s := by
  keeps_bits RequestEffects.finish_dispatch

/-- The two dispatch records, which completion never touches. -/
def Records (s : RequestEffects) : DispatchRecord × DispatchRecord := (s.preflight, s.final_effect)

set_option hygiene false in
local macro "keeps_records " fn:ident : tactic => `(tactic| (
  obtain ⟨pre, fin, comp, prog⟩ := s
  cases prog <;> (try cases ph) <;>
    simp [$fn:ident, RequestEffects.reject, Records] at h ⊢ <;>
    (try split at h) <;> (try simp at h) <;> (try split at h) <;> (try simp at h) <;>
    (try obtain ⟨_, rfl⟩ := h) <;> (try rfl) <;> (try simp_all)))

theorem begin_completion_records {s after : RequestEffects} {acc : Bool}
    (h : RequestEffects.begin_completion s = Result.ok (acc, after)) : Records after = Records s := by
  keeps_records RequestEffects.begin_completion

theorem selected_records {s after : RequestEffects} {acc : Bool}
    (h : RequestEffects.selected s = Result.ok (acc, after)) : Records after = Records s := by
  keeps_records RequestEffects.selected

theorem begin_completion_check_records {s after : RequestEffects} {ph : read_transition.CompletionPhase} {acc : Bool}
    (h : RequestEffects.begin_completion_check s ph = Result.ok (acc, after)) : Records after = Records s := by
  keeps_records RequestEffects.begin_completion_check

theorem finish_completion_check_records {s after : RequestEffects} {ph : read_transition.CompletionPhase} {acc : Bool}
    (h : RequestEffects.finish_completion_check s ph = Result.ok (acc, after)) : Records after = Records s := by
  keeps_records RequestEffects.finish_completion_check

theorem begin_completion_audit_records {s after : RequestEffects} {acc : Bool}
    (h : RequestEffects.begin_completion_audit s = Result.ok (acc, after)) : Records after = Records s := by
  keeps_records RequestEffects.begin_completion_audit

theorem acknowledge_completion_audit_records {s after : RequestEffects} {acc : Bool}
    (h : RequestEffects.acknowledge_completion_audit s = Result.ok (acc, after)) : Records after = Records s := by
  keeps_records RequestEffects.acknowledge_completion_audit

theorem value_ready_records {s after : RequestEffects} {acc : Bool}
    (h : RequestEffects.value_ready s = Result.ok (acc, after)) : Records after = Records s := by
  keeps_records RequestEffects.value_ready

/-- How many dispatch phases are marked attempted. -/
def attCount (s : RequestEffects) : Nat :=
  (if s.preflight.provider_attempted then 1 else 0) + (if s.final_effect.provider_attempted then 1 else 0)

/-- At a reachable receipt, a phase marked attempted carries its stamp. -/
theorem attempted_has_stamp {s : RequestEffects} (reach : Reachable s) :
    (s.preflight.provider_attempted = true → s.preflight.current.isSome = true) ∧
    (s.final_effect.provider_attempted = true → s.final_effect.current.isSome = true) := by
  obtain ⟨pre, fin, _, _⟩ := reachable_is_sound s reach
  exact ⟨fun a => (pre.2.2.1 a).2, fun a => (fin.2.2.1 a).2⟩

/-- One step's provider sends are its newly marked phases (each with its stamp). -/
theorem sends_of_delta (contexts : read_transition.Phase → Context) (u v : RequestEffects)
    (cp : v.preflight.provider_attempted = true → v.preflight.current.isSome = true)
    (cf : v.final_effect.provider_attempted = true → v.final_effect.current.isSome = true) :
    (sourceSends (delta contexts u v)).length =
      (if raised u.preflight.provider_attempted v.preflight.provider_attempted then 1 else 0) +
      (if raised u.final_effect.provider_attempted v.final_effect.provider_attempted then 1 else 0) := by
  have audit : ∀ ph a b, sourceSends (auditDelta ph a b) = [] := by
    intro ph a b; unfold auditDelta; split <;> rfl
  have provider : ∀ ph ctx (r r' : DispatchRecord),
      (r'.provider_attempted = true → r'.current.isSome = true) →
      (sourceSends (providerDelta ph ctx r r')).length =
        (if raised r.provider_attempted r'.provider_attempted then 1 else 0) := by
    intro ph ctx r r' c
    unfold providerDelta
    cases hr : raised r.provider_attempted r'.provider_attempted
    · rfl
    · have up : r'.provider_attempted = true := by
        cases a : r.provider_attempted <;> cases b : r'.provider_attempted <;> simp_all [raised]
      have some := c up
      cases hc : r'.current with
      | none => rw [hc] at some; cases some
      | some st => rfl
  simp only [delta, phaseDelta, sourceSends, List.filter_append, List.length_append]
  have a1 := audit (eventPhase .Preflight) u.preflight.audit_attempted v.preflight.audit_attempted
  have a2 := audit (eventPhase .Final) u.final_effect.audit_attempted v.final_effect.audit_attempted
  have a3 := audit .completed u.completion.audit_attempted v.completion.audit_attempted
  simp only [sourceSends] at a1 a2 a3 provider
  rw [a1, a2, a3, provider _ _ _ _ cp, provider _ _ _ _ cf]
  simp

/-- `begin_send` refused changes no attempt bit; accepted, it came from
    `ProviderReady` for the same phase, marks that phase and leaves the
    other phase's record alone. -/
theorem begin_send_marks {u v : RequestEffects} {ph : read_transition.Phase} {l l' : provider_exchange.SendState}
    {w acc : Bool} (h : RequestEffects.begin_send u ph l w = Result.ok (acc, v, l')) :
    (acc = false → Attempts v = Attempts u) ∧
    (acc = true → u.progress = .ProviderReady ph ∧
      match ph with
      | .Preflight => v.preflight.provider_attempted = true ∧ v.final_effect = u.final_effect
      | .Final => v.final_effect.provider_attempted = true ∧ v.preflight = u.preflight) := by
  obtain ⟨pre, fin, comp, prog⟩ := u
  obtain ⟨lp⟩ := l
  cases prog <;> cases ph <;> (try cases ‹read_transition.Phase›) <;>
    simp [RequestEffects.begin_send, RequestEffects.reject, RequestEffects.phase, RequestEffects.set_phase,
      read_transition.Phase.Insts.CoreCmpPartialEqPhase.eq, provider_exchange.SendState.begin_send,
      provider_exchange.SendState.stamp, manifest.AdmissionStamp.impl.write, Attempts] at h ⊢ <;>
    (try split at h) <;> (try simp at h) <;> (try split at h) <;> (try simp at h) <;>
    (try split at h) <;> (try simp at h) <;> (try split at h) <;> (try simp at h) <;>
    (try obtain ⟨rfl, rfl, rfl⟩ := h) <;> simp_all [read_transition.Phase.read_discriminant]

private theorem bits_count {u v : RequestEffects} (same : Attempts v = Attempts u) :
    (if raised u.preflight.provider_attempted v.preflight.provider_attempted then 1 else 0) +
      (if raised u.final_effect.provider_attempted v.final_effect.provider_attempted then 1 else 0) +
      attCount u = attCount v := by
  simp only [Attempts, Prod.mk.injEq] at same
  simp [attCount, raised, same.1, same.2]

private theorem records_attempts {u v : RequestEffects} (same : Records v = Records u) : Attempts v = Attempts u := by
  simp only [Records, Prod.mk.injEq] at same
  simp [Attempts, same.1, same.2]

/-- **One receipt step's provider sends are exactly its newly attempted
    phases.** Every step but an accepted `begin_send` keeps both attempt bits;
    an accepted `begin_send` marks the one phase that was provider-ready. -/
theorem step_count (contexts : read_transition.Phase → Context) {u v : RequestEffects} (reach : Reachable u)
    (step : Step u v) : (sourceSends (delta contexts u v)).length + attCount u = attCount v := by
  have reachV : Reachable v := by
    obtain ⟨i, m, st⟩ := reach
    exact ⟨i, m, .next st step⟩
  obtain ⟨cp, cf⟩ := attempted_has_stamp reachV
  rw [sends_of_delta contexts u v cp cf]
  cases step with
  | begin_dispatch_audit acc p h => obtain ⟨ph, w⟩ := p; exact bits_count (begin_dispatch_audit_keeps h)
  | acknowledge_dispatch acc p h => obtain ⟨ph, w⟩ := p; exact bits_count (acknowledge_dispatch_keeps h)
  | begin_provider acc p h => obtain ⟨ph, w⟩ := p; exact bits_count (begin_provider_keeps h)
  | provider_completed acc ph h => exact bits_count (provider_completed_keeps h)
  | finish_dispatch acc ph h => exact bits_count (finish_dispatch_keeps h)
  | begin_completion acc h => exact bits_count (records_attempts (begin_completion_records h))
  | selected acc h => exact bits_count (records_attempts (selected_records h))
  | begin_completion_check acc ph h => exact bits_count (records_attempts (begin_completion_check_records h))
  | finish_completion_check acc ph h => exact bits_count (records_attempts (finish_completion_check_records h))
  | begin_completion_audit acc h => exact bits_count (records_attempts (begin_completion_audit_records h))
  | acknowledge_completion_audit acc h =>
    exact bits_count (records_attempts (acknowledge_completion_audit_records h))
  | value_ready acc h => exact bits_count (records_attempts (value_ready_records h))
  | begin_send acc ph l l' w h =>
    obtain ⟨refused, accepted⟩ := begin_send_marks h
    cases acc with
    | false => exact bits_count (refused rfl)
    | true =>
      obtain ⟨ready, marks⟩ := accepted rfl
      have prefixU := reachable_has_control_prefix u reach
      simp only [ControlPrefix, ready] at prefixU
      cases ph with
      | Preflight =>
        obtain ⟨vt, fe⟩ := marks
        simp only [PhasePrefix, DispatchPrefix] at prefixU
        have uf : u.preflight.provider_attempted = false := by simpa using prefixU.1.2.2.2.2.1
        simp [attCount, raised, vt, fe, uf]
      | Final =>
        obtain ⟨vt, pe⟩ := marks
        simp only [PhasePrefix, DispatchPrefix] at prefixU
        have uf : u.final_effect.provider_attempted = false := by simpa using prefixU.2.1.2.2.2.2.1
        simp [attCount, raised, vt, pe, uf]
        omega

/-- **A trace's provider sends are exactly the phases it marked.** Along any
    chronological receipt trace from a reachable state, the number of source
    `providerSend` events is the number of attempt bits newly set. -/
theorem trace_count (contexts : read_transition.Phase → Context) {s t : RequestEffects}
    {events : List confinement.Proofs.Event} (reach : Reachable s) (trace : TraceSteps contexts s t events) :
    (sourceSends events).length + attCount s = attCount t := by
  induction trace with
  | refl => simp [sourceSends]
  | @next u v evs prior step origin ih =>
    have reachU := (trace_steps_preserve_soundness _ _ _ _ reach prior).1
    have one := step_count contexts reachU step
    simp only [sourceSends, List.filter_append, List.length_append] at ih one ⊢
    omega

/-! ## The dispatch primitive's provider sends, recorded

`logged work` is the dispatch primitive `work` with every provider `send` it
is asked to perform appended, with its channel, to a log kept beside its
state. Nothing else changes: every other callback forwards and keeps the
log. The extracted dispatch never sees the log; it is a ghost for stating
how many sends the controller asked the native primitive for. -/

/-- The provider callbacks, with each `send` recorded. -/
def loggedProvider {D H O X : Type} (p : provider_exchange.Provider D H O X) :
    provider_exchange.Provider (D × List H) H O X where
  INVALID_POLICY := p.INVALID_POLICY
  OUTCOME_UNKNOWN := p.OUTCOME_UNKNOWN
  setup s := do let (r, d) ← p.setup s.1; Result.ok (r, (d, s.2))
  recheck s := do let (r, d) ← p.recheck s.1; Result.ok (r, (d, s.2))
  send s channel := do
    let (r, d, next) ← p.send s.1 channel
    Result.ok (r, (d, s.2 ++ [channel]), next)
  receive s channel := do let (r, d) ← p.receive s.1 channel; Result.ok (r, (d, s.2))

/-- The dispatch primitive with its provider sends recorded. -/
def logged {D H O X : Type} (w : dispatch.Work D H O X) : dispatch.Work (D × List H) H O X where
  INVALID_TRANSITION := w.INVALID_TRANSITION
  provider_exchangeProviderInst := loggedProvider w.provider_exchangeProviderInst
  effect_write s := w.effect_write s.1
  prepare s := do let (r, d) ← w.prepare s.1; Result.ok (r, (d, s.2))
  audit s phase := do let (r, d) ← w.audit s.1 phase; Result.ok (r, (d, s.2))
  configure s keyed := do let (r, d) ← w.configure s.1 keyed; Result.ok (r, (d, s.2))
  check s := do let (r, d) ← w.check s.1; Result.ok (r, (d, s.2))
  reserve s := do let (r, d) ← w.reserve s.1; Result.ok (r, (d, s.2))
  finish s := do let (r, d) ← w.finish s.1; Result.ok (r, (d, s.2))

theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

section dispatch
variable {D C H O X : Type} (work : dispatch.Work D H O X) (checks : current_admission.Checks C X)

/-- The bound dispatch work over the logged primitive. -/
abbrev boundL := current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork (logged work) checks

/-- The dispatch's provider adapter over it. -/
abbrev adapterL :=
  dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider (boundL work checks)

/-- The sends recorded so far. -/
def calls (p : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X) : List H :=
  p.work.work.2

set_option hygiene false in
local macro "forwards " fn:ident : tactic => `(tactic| (
  simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
    current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold $fn:ident at h
  simp only [logged, loggedProvider] at h
  obtain ⟨⟨r1, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨⟨r2, d⟩, _, back⟩ := (bind_returns_iff _ _ _).mp inner
  have e1 := Result.ok_injective back
  have e2 := Result.ok_injective rest
  simp only [Prod.mk.injEq] at e1 e2
  obtain ⟨_, rfl⟩ := e1
  obtain ⟨_, rfl⟩ := e2
  rfl))

theorem bound_prepare_log {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).prepare b = Result.ok (r, b')) : b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.prepare

theorem bound_audit_log {b b' : current_admission.Bound (D × List H) C H O X} {phase : read_transition.Phase}
    {r : core.result.Result Unit X}
    (h : (boundL work checks).audit b phase = Result.ok (r, b')) : b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.audit

theorem bound_configure_log {b b' : current_admission.Bound (D × List H) C H O X} {keyed : Bool}
    {r : core.result.Result Unit X}
    (h : (boundL work checks).configure b keyed = Result.ok (r, b')) : b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.configure

theorem bound_check_log {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).check b = Result.ok (r, b')) : b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.check

theorem bound_reserve_log {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).reserve b = Result.ok (r, b')) : b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.reserve

theorem bound_finish_log {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result Unit X}
    (h : (boundL work checks).finish b = Result.ok (r, b')) : b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.finish

theorem bound_setup_log {b b' : current_admission.Bound (D × List H) C H O X} {r : core.result.Result H X}
    (h : (boundL work checks).provider_exchangeProviderInst.setup b = Result.ok (r, b')) : b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup

theorem bound_receive_log {b b' : current_admission.Bound (D × List H) C H O X} {channel : H}
    {r : core.result.Result O X}
    (h : (boundL work checks).provider_exchangeProviderInst.receive b channel = Result.ok (r, b')) :
    b'.work.2 = b.work.2 := by
  forwards current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive

theorem bound_recheck_log {b b' : current_admission.Bound (D × List H) C H O X}
    {r : core.result.Result manifest.AdmissionStamp X}
    (h : (boundL work checks).provider_exchangeProviderInst.recheck b = Result.ok (r, b')) :
    b'.work = b.work := by
  simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
    current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at h
  obtain ⟨⟨r1, t⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp h
  have e := Result.ok_injective rest
  simp only [Prod.mk.injEq] at e
  obtain ⟨_, rfl⟩ := e
  rfl

theorem bound_send_log {b b' : current_admission.Bound (D × List H) C H O X} {channel next : H}
    {r : core.result.Result Unit X}
    (h : (boundL work checks).provider_exchangeProviderInst.send b channel = Result.ok (r, b', next)) :
    b'.work.2 = b.work.2 ++ [channel] := by
  simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
    current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at h
  simp only [logged, loggedProvider] at h
  obtain ⟨⟨r1, t, n1⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  obtain ⟨⟨r2, d, n2⟩, _, back⟩ := (bind_returns_iff _ _ _).mp inner
  have e1 := Result.ok_injective back
  have e2 := Result.ok_injective rest
  simp only [Prod.mk.injEq] at e1 e2
  obtain ⟨_, rfl, _⟩ := e1
  obtain ⟨_, rfl, _⟩ := e2
  rfl

/-- The sends recorded grew by exactly as many as the phases newly marked
    attempted. -/
def Grew (before after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X) : Prop :=
  ∃ cs : List H, calls after = calls before ++ cs ∧ cs.length + attCount before.effects = attCount after.effects

theorem grew_refl (p : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X) : Grew p p :=
  ⟨[], by simp, by simp⟩

theorem grew_trans {a b c : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X}
    (left : Grew a b) (right : Grew b c) : Grew a c := by
  obtain ⟨x, hx, nx⟩ := left
  obtain ⟨y, hy, ny⟩ := right
  exact ⟨x ++ y, by rw [hy, hx, List.append_assoc], by simp only [List.length_append]; omega⟩

theorem grew_same {a b : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X}
    (log : calls b = calls a) (bits : attCount b.effects = attCount a.effects) : Grew a b :=
  ⟨[], by simp [log], by simp [bits]⟩

theorem attCount_of_attempts {u v : RequestEffects} (same : Attempts v = Attempts u) : attCount v = attCount u := by
  simp only [Attempts, Prod.mk.injEq] at same
  simp [attCount, same.1, same.2]

/-- `begin_send` from a reachable receipt adds one attempt exactly when it
    accepts. -/
theorem begin_send_count {u v : RequestEffects} {ph : read_transition.Phase} {l l' : provider_exchange.SendState}
    {w acc : Bool} (reach : Reachable u) (h : RequestEffects.begin_send u ph l w = Result.ok (acc, v, l')) :
    attCount v = attCount u + (if acc then 1 else 0) := by
  obtain ⟨refused, accepted⟩ := begin_send_marks h
  cases acc with
  | false => simpa using attCount_of_attempts (refused rfl)
  | true =>
    obtain ⟨ready, marks⟩ := accepted rfl
    have prefixU := reachable_has_control_prefix u reach
    simp only [ControlPrefix, ready] at prefixU
    cases ph with
    | Preflight =>
      obtain ⟨vt, fe⟩ := marks
      simp only [PhasePrefix, DispatchPrefix] at prefixU
      have uf : u.preflight.provider_attempted = false := by simpa using prefixU.1.2.2.2.2.1
      simp [attCount, vt, fe, uf]
      omega
    | Final =>
      obtain ⟨vt, pe⟩ := marks
      simp only [PhasePrefix, DispatchPrefix] at prefixU
      have uf : u.final_effect.provider_attempted = false := by simpa using prefixU.2.1.2.2.2.2.1
      simp [attCount, vt, pe, uf]

theorem setup_grew {p after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X}
    {out : core.result.Result H X}
    (h : (adapterL work checks).setup p = Result.ok (out, after)) : Grew p after := by
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup at h
  obtain ⟨⟨r, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  have log := bound_setup_log work checks inner
  have e := Result.ok_injective rest
  simp only [Prod.mk.injEq] at e
  obtain ⟨_, rfl⟩ := e
  exact grew_same (by simp [calls, log]) rfl

theorem receive_grew {p after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X}
    {channel : H} {out : core.result.Result O X}
    (h : (adapterL work checks).receive p channel = Result.ok (out, after)) : Grew p after := by
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive at h
  obtain ⟨⟨r, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp h
  have log := bound_receive_log work checks inner
  have e := Result.ok_injective rest
  simp only [Prod.mk.injEq] at e
  obtain ⟨_, rfl⟩ := e
  exact grew_same (by simp [calls, log]) rfl

theorem recheck_grew {p after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X}
    {out : core.result.Result manifest.AdmissionStamp X}
    (h : (adapterL work checks).recheck p = Result.ok (out, after)) : Grew p after := by
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at h
  obtain ⟨⟨b, ss⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp h
  cases b with
  | false =>
    try simp only [Bool.false_eq_true, ↓reduceIte] at rest
    obtain ⟨e, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have pair := Result.ok_injective rest
    simp only [Prod.mk.injEq] at pair
    obtain ⟨_, rfl⟩ := pair
    exact grew_same rfl rfl
  | true =>
    try simp only [↓reduceIte] at rest
    obtain ⟨⟨r, t⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have same := bound_recheck_log work checks inner
    have log : t.work.2 = p.work.work.2 := by rw [same]
    cases r with
    | Err e =>
      have pair := Result.ok_injective rest
      simp only [Prod.mk.injEq] at pair
      obtain ⟨_, rfl⟩ := pair
      exact grew_same (by simp [calls, log]) rfl
    | Ok stamp =>
      obtain ⟨⟨b1, ss1⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases b1 with
      | true =>
        have pair := Result.ok_injective rest
        simp only [Prod.mk.injEq] at pair
        obtain ⟨_, rfl⟩ := pair
        exact grew_same (by simp [calls, log]) rfl
      | false =>
        obtain ⟨e, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have pair := Result.ok_injective rest
        simp only [Prod.mk.injEq] at pair
        obtain ⟨_, rfl⟩ := pair
        exact grew_same (by simp [calls, log]) rfl

/-- **A provider send is recorded exactly when `begin_send` marks an
    attempt.** The dispatch asks its primitive to send only after the
    composite gate accepted, and then exactly once. -/
theorem send_grew {p after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X}
    {channel next : H} {out : core.result.Result Unit X} (reach : Reachable p.effects)
    (h : (adapterL work checks).send p channel = Result.ok (out, after, next)) : Grew p after := by
  dsimp only [adapterL, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at h
  obtain ⟨⟨accepted, effects, localState⟩, gate, rest⟩ := (bind_returns_iff _ _ _).mp h
  have count := begin_send_count reach gate
  cases accepted with
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte] at rest
    obtain ⟨e, _, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have pair := Result.ok_injective rest
    simp only [Prod.mk.injEq] at pair
    obtain ⟨_, rfl, _⟩ := pair
    exact grew_same rfl (by simpa using count)
  | true =>
    simp only [↓reduceIte] at rest
    obtain ⟨⟨r, t, n⟩, inner, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have log := bound_send_log work checks inner
    have pair := Result.ok_injective rest
    simp only [Prod.mk.injEq] at pair
    obtain ⟨_, rfl, _⟩ := pair
    refine ⟨[channel], by simp [calls, log], ?_⟩
    simp only [List.length_singleton, ↓reduceIte] at count ⊢
    omega

theorem returned_state {A P : Type} (value out : A) (state after : P)
    (returned : Result.ok (value, state) = Result.ok (out, after)) : after = state :=
  (congrArg Prod.snd ((Result.ok.injEq).mp returned)).symm

theorem fixed_state {A B P : Type} (first : Result A) (build : A → B) (state after : P) (out : B)
    (returned : (do let value ← first; Result.ok (build value, state)) = Result.ok (out, after)) : after = state := by
  obtain ⟨value, _, same⟩ := (bind_returns_iff _ _ _).mp returned
  exact returned_state _ _ _ _ same

/-- Reachability follows the existing source-derived histories. -/
theorem reach_of_related {p q : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X}
    (reach : Reachable p.effects) (rel : dispatch.TraceRefinement.Related p q) : Reachable q.effects := by
  obtain ⟨_, events, traced⟩ := rel
  exact (trace_steps_preserve_soundness _ _ _ _ reach traced).1

/-- **The provider driver, once.** One `provider_exchange::exchange` records
    a send exactly when it marks an attempt. -/
theorem driver_grew (pending after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X)
    (audited : read_transition.Audited) (report : provider_exchange.Report O X) (reach : Reachable pending.effects)
    (returned : provider_exchange.exchange (adapterL work checks) pending audited = Result.ok (report, after)) :
    Grew pending after := by
  unfold provider_exchange.exchange at returned
  simp [read_transition.Audited.impl.phase, read_transition.Audited.is_write] at returned
  obtain ⟨⟨initial, state1⟩, planned, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have first := setup_grew work checks planned
  have reach1 := reach_of_related reach
    (dispatch.TraceRefinement.setup_trace (logged work) checks pending state1 initial planned)
  cases initial with
  | Err error =>
    have same := returned_state (provider_exchange.Report.mk audited.phase .Setup none (.Err error)) report state1 after rest
    subst after
    exact first
  | Ok channel =>
    obtain ⟨⟨checked, second⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have prior := grew_trans first (recheck_grew work checks current)
    have reach2 := reach_of_related reach1
      (dispatch.TraceRefinement.current_trace (logged work) checks state1 second checked current)
    cases checked with
    | Err error =>
      have same := returned_state (provider_exchange.Report.mk audited.phase .Admission none (.Err error)) report second after rest
      subst after
      exact prior
    | Ok stamp =>
      have finish : ∀ (third : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X) next sent,
          (adapterL work checks).send second channel = Result.ok (sent, third, next) →
          (∀ last received, (adapterL work checks).receive third next = Result.ok (received, last) →
            Grew pending last) ∧ Grew pending third := by
        intro third next sent sending
        have upto := grew_trans prior (send_grew work checks reach2 sending)
        exact ⟨fun last received receiving => grew_trans upto (receive_grew work checks receiving), upto⟩
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

theorem audit_grew (pending after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X)
    (prepared : read_transition.Prepared) (out : core.result.Result read_transition.Audited X)
    (returned : dispatch.audit (boundL work checks) pending prepared = Result.ok (out, after)) : Grew pending after := by
  unfold dispatch.audit at returned
  obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have log1 := bound_prepare_log work checks callback
  have prepared1 : Grew pending {pending with work := native} := grew_same (by simp [calls, log1]) rfl
  cases result with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result read_transition.Audited X) out {pending with work := native} after (by simpa using rest)
    subst after
    exact prepared1
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have marked : Grew {pending with work := native} {pending with work := native, effects := firstReceipt} := by
      obtain ⟨ph, w⟩ := prepared
      exact grew_same rfl (attCount_of_attempts (begin_dispatch_audit_keeps began))
    have prior := grew_trans prepared1 marked
    cases accepted with
    | false =>
      have same := fixed_state (boundL work checks).INVALID_TRANSITION (fun error => (.Err error : core.result.Result read_transition.Audited X))
        {pending with work := native, effects := firstReceipt} after out (by simpa using rest)
      subst after
      exact prior
    | true =>
      simp [read_transition.Prepared.impl.phase] at rest
      obtain ⟨⟨written, native2⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have log2 := bound_audit_log work checks auditCall
      have audited : Grew {pending with work := native, effects := firstReceipt}
          {pending with work := native2, effects := firstReceipt} := grew_same (by simp [calls, log2]) rfl
      have prior := grew_trans prior audited
      cases written with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result read_transition.Audited X) out
          {pending with work := native2, effects := firstReceipt} after (by simpa using rest)
        subst after
        exact prior
      | Ok u =>
        cases u
        simp [read_transition.acknowledge] at rest
        obtain ⟨⟨accepted, last⟩, ack, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Grew {pending with work := native2, effects := firstReceipt} {pending with work := native2, effects := last} :=
          grew_same rfl (attCount_of_attempts (acknowledge_dispatch_keeps ack))
        have same : after = {pending with work := native2, effects := last} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result read_transition.Audited X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok ⟨prepared.phase, prepared.write⟩ : core.result.Result read_transition.Audited X) out _ _ (by simpa using rest)
        subst after
        exact grew_trans prior suffix

theorem exchange_grew (pending after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X)
    (audited : read_transition.Audited) (out : core.result.Result O X) (reach : Reachable pending.effects)
    (returned : dispatch.exchange (boundL work checks) pending audited = Result.ok (out, after)) : Grew pending after := by
  unfold dispatch.exchange at returned
  simp [read_transition.Audited.is_write] at returned
  obtain ⟨effectWrite, policy, rest⟩ := (bind_returns_iff _ _ _).mp returned
  split at rest
  · obtain ⟨⟨accepted, firstReceipt⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have kept : Attempts firstReceipt = Attempts pending.effects := by
      obtain ⟨ph, w⟩ := audited
      exact begin_provider_keeps began
    have prior : Grew pending {pending with effects := firstReceipt, phase := audited.phase, write := audited.write} :=
      grew_same rfl (attCount_of_attempts kept)
    have reach1 : Reachable firstReceipt := by
      obtain ⟨i, m, st⟩ := reach
      exact ⟨i, m, .next st (.begin_provider accepted audited began)⟩
    cases accepted with
    | false =>
      have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) {pending with effects := firstReceipt} after out (by simpa using rest)
      subst after
      exact grew_same rfl (attCount_of_attempts kept)
    | true =>
      simp [read_transition.Audited.impl.phase] at rest
      obtain ⟨⟨report, driverState⟩, driver, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have driven := driver_grew work checks {pending with effects := firstReceipt, phase := audited.phase, write := audited.write}
        driverState audited report reach1 driver
      have prefixGrew := grew_trans prior driven
      simp [provider_exchange.Report.impl.stage, provider_exchange.Report.impl.current, provider_exchange.Report.into_result] at rest
      cases result : report.result with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {driverState with provider_stage := some report.stage, current := report.current} after (by simpa [result] using rest)
        subst after
        exact prefixGrew
      | Ok value =>
        simp only [result] at rest
        obtain ⟨⟨accepted, last⟩, completed, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have suffix : Grew driverState {driverState with effects := last} :=
          grew_same rfl (attCount_of_attempts (provider_completed_keeps completed))
        have same : after = {driverState with effects := last, provider_stage := some report.stage, current := report.current} := by
          cases accepted with
          | false => exact fixed_state _ (fun error => (.Err error : core.result.Result O X)) _ _ _ (by simpa using rest)
          | true => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
        subst after
        exact grew_trans prefixGrew suffix
  · have same := fixed_state _ (fun error => (.Err error : core.result.Result O X)) pending after out rest
    subst after
    exact grew_refl _

theorem finish_grew (pending after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X)
    (keyed : Bool) (out : core.result.Result Unit X)
    (returned : dispatch.finish (boundL work checks) pending keyed = Result.ok (out, after)) : Grew pending after := by
  unfold dispatch.finish at returned
  obtain ⟨⟨nextState, finished⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have framed : Grew pending nextState := by
    cases keyed with
    | false =>
      have pair := (Result.ok.injEq).mp finishCall
      have same : pending = nextState := congrArg Prod.fst pair
      rw [← same]
      exact grew_refl _
    | true =>
      obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp finishCall
      have same : nextState = {pending with work := native} := by
        exact (by simpa using rest : {pending with work := native} = nextState ∧ result = finished).1.symm
      subst nextState
      exact grew_same (by simp [calls, bound_finish_log work checks callback]) rfl
  cases finished with
  | Err error =>
    have same := fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) nextState after out rest
    subst after
    exact framed
  | Ok u =>
    cases u
    obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have suffix : Grew nextState {nextState with effects := last} :=
      grew_same rfl (attCount_of_attempts (finish_dispatch_keeps finished))
    have same : after = {nextState with effects := last} := by
      cases accepted with
      | false => exact fixed_state _ (fun error => (.Err error : core.result.Result Unit X)) _ _ _ (by simpa using rest)
      | true => exact returned_state (.Ok () : core.result.Result Unit X) out _ _ (by simpa using rest)
    subst after
    exact grew_trans framed suffix

theorem run_grew (pending after : dispatch.Pending (current_admission.Bound (D × List H) C H O X) H O X)
    (prepared : read_transition.Prepared) (keyed : Bool) (out : core.result.Result O X)
    (reach : Reachable pending.effects)
    (returned : dispatch.run (boundL work checks) pending prepared keyed = Result.ok (out, after)) :
    Grew pending after := by
  unfold dispatch.run at returned
  obtain ⟨⟨audited, firstState⟩, auditCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have prefixGrew := audit_grew work checks pending firstState prepared audited auditCall
  have reach1 := reach_of_related reach
    (dispatch.TraceRefinement.audit_trace (logged work) checks pending firstState prepared audited auditCall)
  cases audited with
  | Err error =>
    have same := returned_state (.Err error : core.result.Result O X) out firstState after (by simpa using rest)
    subst after
    exact prefixGrew
  | Ok permit =>
    obtain ⟨⟨configured, native1⟩, configuredCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have prefixGrew := grew_trans prefixGrew
      (grew_same (b := {firstState with work := native1}) (by simp [calls, bound_configure_log work checks configuredCall]) rfl)
    cases configured with
    | Err error =>
      have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := native1} after (by simpa using rest)
      subst after
      exact prefixGrew
    | Ok u =>
      cases u
      obtain ⟨⟨checked, work2⟩, checkCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      have prefixGrew := grew_trans prefixGrew
        (grew_same (a := {firstState with work := native1}) (b := {firstState with work := work2})
          (by simp [calls, bound_check_log work checks checkCall]) rfl)
      cases checked with
      | Err error =>
        have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work2} after (by simpa using rest)
        subst after
        exact prefixGrew
      | Ok u =>
        cases u
        obtain ⟨⟨work3, reserved⟩, reserveCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have reserveLog : work3.work.2 = work2.work.2 := by
          cases keyed with
          | false =>
            have pair : work2 = work3 ∧ (.Ok () : core.result.Result Unit X) = reserved := by simpa using reserveCall
            rw [← pair.1]
          | true =>
            obtain ⟨⟨result, native⟩, call, same⟩ := (bind_returns_iff _ _ _).mp reserveCall
            have pair : native = work3 ∧ result = reserved := by simpa using same
            rw [← pair.1]
            exact bound_reserve_log work checks call
        have prefixGrew := grew_trans prefixGrew
          (grew_same (a := {firstState with work := work2}) (b := {firstState with work := work3})
            (by simp [calls, reserveLog]) rfl)
        cases reserved with
        | Err error =>
          have same := returned_state (.Err error : core.result.Result O X) out {firstState with work := work3} after (by simpa using rest)
          subst after
          exact prefixGrew
        | Ok u =>
          cases u
          obtain ⟨⟨exchanged, secondState⟩, exchangeCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
          have prefixGrew := grew_trans prefixGrew
            (exchange_grew work checks {firstState with work := work3} secondState permit exchanged reach1 exchangeCall)
          cases exchanged with
          | Err error =>
            have same := returned_state (.Err error : core.result.Result O X) out secondState after (by simpa using rest)
            subst after
            exact prefixGrew
          | Ok value =>
            obtain ⟨⟨finished, lastState⟩, finishCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
            have prefixGrew := grew_trans prefixGrew (finish_grew work checks secondState lastState keyed finished finishCall)
            have same : after = lastState := by
              cases finished with
              | Err error => exact returned_state (.Err error : core.result.Result O X) out _ _ (by simpa using rest)
              | Ok u => exact returned_state (.Ok value : core.result.Result O X) out _ _ (by simpa using rest)
            subst after
            exact prefixGrew

/-- **A dispatch asks its primitive for exactly as many provider sends as it
    marks attempts.** For any returned dispatch of the bound, logged
    primitive from a reachable receipt: the primitive's log grew by a list
    of channels whose length is the number of phases the dispatch newly
    marked attempted — and so, by `trace_count`, the number of source
    `providerSend` events of its chronological trace. -/
theorem dispatch_grew (primitive : current_admission.Bound (D × List H) C H O X)
    (prepared : core.result.Result read_transition.Prepared X) (before : RequestEffects) (keyed : Bool)
    (report : dispatch.Report (current_admission.Bound (D × List H) C H O X) H O X) (reach : Reachable before)
    (returned : dispatch.dispatch (boundL work checks) primitive prepared before keyed = Result.ok report) :
    ∃ cs : List H, report.work.work.2 = primitive.work.2 ++ cs ∧ cs.length + attCount before = attCount report.effects := by
  cases prepared with
  | Err error =>
    have same : report = ⟨.Err error, primitive, before, ⟨.Empty⟩, none, none⟩ := by
      simpa [dispatch.dispatch, provider_exchange.SendState.new] using returned.symm
    subst report
    exact ⟨[], by simp, by simp⟩
  | Ok prepared =>
    simp [dispatch.dispatch, read_transition.Prepared.impl.phase, provider_exchange.SendState.new] at returned
    obtain ⟨⟨result, after⟩, ran, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have grown := run_grew work checks ⟨primitive, before, ⟨.Empty⟩, prepared.phase, false, none, none⟩ after
      prepared keyed result reach ran
    have same : report = ⟨result, after.work, after.effects, after.«local», after.provider_stage, after.current⟩ := by
      simpa using rest.symm
    subst report
    obtain ⟨cs, log, count⟩ := grown
    exact ⟨cs, log, count⟩

end dispatch

/-! ## The log is a ghost

The logged primitive forward-simulates the primitive it logs: erasing the log
from a bound logged primitive gives the bound primitive, every callback
returns the same result, and `dispatch::dispatch` therefore returns the same
report (`Erasure.dispatch_forward`). So `dispatch_grew` is a statement about
the production dispatch, not about a different program. -/

/-- Forget the log. -/
def eraseB {D C H O X : Type} (b : current_admission.Bound (D × List H) C H O X) :
    current_admission.Bound D C H O X :=
  ⟨b.context, b.work.1, b.checks⟩

/-- Start a log beside a primitive. -/
def liftB {D C H O X : Type} (b : current_admission.Bound D C H O X) (log : List H) :
    current_admission.Bound (D × List H) C H O X :=
  ⟨b.context, (b.work, log), b.checks⟩

theorem erase_lift {D C H O X : Type} (b : current_admission.Bound D C H O X) (log : List H) :
    eraseB (liftB b log) = b := rfl

set_option hygiene false in
/-- A forwarding callback of the bound primitive, logged or not. -/
local macro "forward_bound " fn:ident : tactic => `(tactic| (
  unfold $fn:ident at h ⊢
  obtain ⟨⟨r1, t⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
  simp only [uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  refine ⟨{ b with work := (t, b.work.2) }, ?_, rfl⟩
  (try simp only [logged, loggedProvider])
  (try simp only [eraseB] at call)
  rw [call]
  simp))

/-- **The bound logged primitive forward-simulates the bound primitive.** -/
theorem logged_forward {D C H O X : Type} (work : dispatch.Work D H O X) (checks : current_admission.Checks C X) :
    dispatch.Erasure.WorkForward (boundL work checks)
      (current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks) eraseB where
  provider := {
    policy := by
      simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
        current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider]
      unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.INVALID_POLICY
      rfl
    unknown := by
      simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
        current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider]
      unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.OUTCOME_UNKNOWN
      rfl
    setup := by
      intro b r b' h
      simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
        current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
      forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup
    recheck := by
      intro b r b' h
      simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
        current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
      unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at h ⊢
      obtain ⟨⟨r1, t⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
      simp only [uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨{ b with checks := t }, ?_, rfl⟩
      (try simp only [eraseB] at call)
      rw [call]
      simp
    send := by
      intro b ch r b' next h
      simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
        current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
      unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at h ⊢
      obtain ⟨⟨r1, t, n⟩, call, h⟩ := (bind_returns_iff _ _ _).mp h
      simp only [uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      refine ⟨{ b with work := (t, b.work.2 ++ [ch]) }, ?_, rfl⟩
      (try simp only [logged, loggedProvider])
      (try simp only [eraseB] at call)
      rw [call]
      simp
    receive := by
      intro b ch r b' h
      simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork,
        current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at h ⊢
      forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive }
  invalid := by
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork]
    unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.INVALID_TRANSITION
    rfl
  effect_write := by
    intro b
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork]
    unfold current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.effect_write
    rfl
  prepare := by
    intro b r b' h
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork] at h ⊢
    forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.prepare
  audit := by
    intro b ph r b' h
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork] at h ⊢
    forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.audit
  configure := by
    intro b k r b' h
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork] at h ⊢
    forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.configure
  check := by
    intro b r b' h
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork] at h ⊢
    forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.check
  reserve := by
    intro b r b' h
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork] at h ⊢
    forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.reserve
  finish := by
    intro b r b' h
    simp only [boundL, current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork] at h ⊢
    forward_bound current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.finish

/-- **A production dispatch asks its primitive for exactly as many provider
    sends as it marks attempts.** For any returned `dispatch::dispatch` of a
    bound primitive from a reachable receipt, the same dispatch with a
    send log started beside the primitive returns the same report, and its
    log holds exactly the channels the primitive's `send` was called with:
    as many as the phases the dispatch newly marked attempted. -/
theorem production_dispatch_sends {D C H O X : Type} (work : dispatch.Work D H O X)
    (checks : current_admission.Checks C X) (primitive : current_admission.Bound D C H O X)
    (prepared : core.result.Result read_transition.Prepared X) (before : RequestEffects) (keyed : Bool)
    (report : dispatch.Report (current_admission.Bound D C H O X) H O X) (reach : Reachable before)
    (returned : dispatch.dispatch (current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks)
      primitive prepared before keyed = Result.ok report) :
    ∃ logged : dispatch.Report (current_admission.Bound (D × List H) C H O X) H O X,
      dispatch.dispatch (boundL work checks) (liftB primitive []) prepared before keyed = Result.ok logged ∧
      dispatch.Erasure.eraseReport eraseB logged = report ∧
      logged.work.work.2.length + attCount before = attCount report.effects := by
  obtain ⟨logged, ran, erased⟩ := dispatch.Erasure.dispatch_forward (logged_forward work checks)
    (liftB primitive []) prepared before keyed report returned
  obtain ⟨cs, log, count⟩ := dispatch_grew work checks (liftB primitive []) prepared before keyed logged reach ran
  have effects : logged.effects = report.effects := by rw [← erased]; rfl
  refine ⟨logged, ran, erased, ?_⟩
  rw [log, ← effects]
  simpa [liftB] using count

end aivm_secrets_garrett_core.nr23.SendLog
