import GarrettDispatch

open Aeneas Aeneas.Std
set_option maxHeartbeats 3000000

/-! Actual routed primitives and captured provider submission. Native buffer
view, DNS/TLS/Write and parser semantics remain explicit primitive contracts. -/
namespace aivm_secrets_garrett_core.provider_io.Proofs
open read_transition

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private abbrev provider {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X) :=
  Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider work routes

private abbrev routed_work {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X) :=
  Routed.Insts.Aivm_secrets_garrett_coreDispatchWork work routes

theorem context_route (context : current_admission.Context) :
    current_admission.Context.route context = Result.ok context.grant.route := rfl

theorem routed_constructor {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (route : credential_use.Route) (native : W) : Routed.new work routes route native = Result.ok ⟨route, native⟩ := rfl

/-- Actual setup takes the private captured route and retains the exact raw
    primitive post-state, including refusal after a partial TLS setup. -/
theorem routed_setup_iff {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X) (out : core.result.Result H X) :
    (provider work routes).setup pending = Result.ok (out, after) ↔
      ∃ native, routes.setup_route pending.work pending.route = Result.ok (out, native) ∧ after = {pending with work := native} := by
  constructor
  · intro returned
    dsimp only [provider, Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
    unfold Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup at returned
    obtain ⟨⟨result, native⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have pair : (result, {pending with work := native}) = (out, after) := by simpa using rest
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
    exact ⟨native, called, rfl⟩
  · rintro ⟨native, called, rfl⟩
    simp [Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup, called]

/-- Dispatch audit sees the same captured route as TLS/request setup. -/
theorem routed_audit_iff {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X) (phase : Phase) (out : core.result.Result Unit X) :
    (routed_work work routes).audit pending phase = Result.ok (out, after) ↔
      ∃ native, routes.audit_route pending.work pending.route phase = Result.ok (out, native) ∧ after = {pending with work := native} := by
  constructor
  · intro returned
    dsimp only [routed_work, Routed.Insts.Aivm_secrets_garrett_coreDispatchWork] at returned
    unfold Routed.Insts.Aivm_secrets_garrett_coreDispatchWork.audit at returned
    obtain ⟨⟨result, native⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have pair : (result, {pending with work := native}) = (out, after) := by simpa using rest
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
    exact ⟨native, called, rfl⟩
  · rintro ⟨native, called, rfl⟩
    simp [Routed.Insts.Aivm_secrets_garrett_coreDispatchWork.audit, called]

theorem setup_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X) (out : core.result.Result H X)
    (returned : (provider work routes).setup pending = Result.ok (out, after)) : after.route = pending.route := by
  obtain ⟨native, _, rfl⟩ := (routed_setup_iff work routes pending after out).mp returned
  rfl

theorem audit_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X) (phase : Phase) (out : core.result.Result Unit X)
    (returned : (routed_work work routes).audit pending phase = Result.ok (out, after)) : after.route = pending.route := by
  obtain ⟨native, _, rfl⟩ := (routed_audit_iff work routes pending after phase out).mp returned
  rfl

theorem recheck_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X)  (out : core.result.Result manifest.AdmissionStamp X)
    (returned : (provider work routes).recheck pending = Result.ok (out, after)) : after.route = pending.route := by
  dsimp only [provider, Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state⟩
  have equal : (result, {pending with work := state}) = (out, after) := by simpa using rest
  exact congrArg (fun pair => pair.2.route) equal.symm

theorem send_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X) (channel finalChannel : H) (out : core.result.Result Unit X)
    (returned : (provider work routes).send pending channel = Result.ok (out, after, finalChannel)) : after.route = pending.route := by
  dsimp only [provider, Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state, channel⟩
  have equal : (result, {pending with work := state}, channel) = (out, after, finalChannel) := by simpa using rest
  exact congrArg (fun pair => pair.2.1.route) equal.symm

theorem receive_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X) (channel : H) (out : core.result.Result O X)
    (returned : (provider work routes).receive pending channel = Result.ok (out, after)) : after.route = pending.route := by
  dsimp only [provider, Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state⟩
  have equal : (result, {pending with work := state}) = (out, after) := by simpa using rest
  exact congrArg (fun pair => pair.2.route) equal.symm

theorem prepare_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X)  (out : core.result.Result Unit X)
    (returned : (routed_work work routes).prepare pending = Result.ok (out, after)) : after.route = pending.route := by
  dsimp only [routed_work, Routed.Insts.Aivm_secrets_garrett_coreDispatchWork] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreDispatchWork.prepare at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state⟩
  have equal : (result, {pending with work := state}) = (out, after) := by simpa using rest
  exact congrArg (fun pair => pair.2.route) equal.symm

theorem configure_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X) (keyed : Bool) (out : core.result.Result Unit X)
    (returned : (routed_work work routes).configure pending keyed = Result.ok (out, after)) : after.route = pending.route := by
  dsimp only [routed_work, Routed.Insts.Aivm_secrets_garrett_coreDispatchWork] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreDispatchWork.configure at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state⟩
  have equal : (result, {pending with work := state}) = (out, after) := by simpa using rest
  exact congrArg (fun pair => pair.2.route) equal.symm

theorem check_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X)  (out : core.result.Result Unit X)
    (returned : (routed_work work routes).check pending = Result.ok (out, after)) : after.route = pending.route := by
  dsimp only [routed_work, Routed.Insts.Aivm_secrets_garrett_coreDispatchWork] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreDispatchWork.check at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state⟩
  have equal : (result, {pending with work := state}) = (out, after) := by simpa using rest
  exact congrArg (fun pair => pair.2.route) equal.symm

theorem reserve_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X)  (out : core.result.Result Unit X)
    (returned : (routed_work work routes).reserve pending = Result.ok (out, after)) : after.route = pending.route := by
  dsimp only [routed_work, Routed.Insts.Aivm_secrets_garrett_coreDispatchWork] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreDispatchWork.reserve at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state⟩
  have equal : (result, {pending with work := state}) = (out, after) := by simpa using rest
  exact congrArg (fun pair => pair.2.route) equal.symm

theorem finish_keeps_route {W H O X : Type} (work : dispatch.Work W H O X) (routes : RouteWork W H X)
    (pending after : Routed W H O X)  (out : core.result.Result Unit X)
    (returned : (routed_work work routes).finish pending = Result.ok (out, after)) : after.route = pending.route := by
  dsimp only [routed_work, Routed.Insts.Aivm_secrets_garrett_coreDispatchWork] at returned
  unfold Routed.Insts.Aivm_secrets_garrett_coreDispatchWork.finish at returned
  obtain ⟨called, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  rcases called with ⟨result, state⟩
  have equal : (result, {pending with work := state}) = (out, after) := by simpa using rest
  exact congrArg (fun pair => pair.2.route) equal.symm

theorem request_constructor {B : Type} (bytes : WireBytes B) (body : B) :
    Request.new bytes body = Result.ok ⟨body, false⟩ := rfl

/-- A raw write can partially accept before returning Err. These constructors
    name actual callback returns, never inferred provider arrival/delivery. -/
inductive SubmitRun {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request : Request B) (writer : W) : core.result.Result Unit X → Request B → W → Prop where
  | replay (error : X) (attempted : request.attempted = true) (invalid : ops.INVALID_TRANSITION = Result.ok error) :
      SubmitRun bytes ops request writer (.Err error) request writer
  | writeDenied (wire : alloc.vec.Vec U8) (after : W) (error : X)
      (fresh : request.attempted = false) (view : bytes.bytes request.body = Result.ok wire)
      (written : ops.write_all writer wire = Result.ok (.Err error, after)) :
      SubmitRun bytes ops request writer (.Err error) {request with attempted := true} after
  | flushed (wire : alloc.vec.Vec U8) (written after : W) (out : core.result.Result Unit X)
      (fresh : request.attempted = false) (view : bytes.bytes request.body = Result.ok wire)
      (writeCall : ops.write_all writer wire = Result.ok (.Ok (), written))
      (flushCall : ops.flush written = Result.ok (out, after)) :
      SubmitRun bytes ops request writer out {request with attempted := true} after

/-- All returned prefixes of the actual captured-buffer writer, including
    zero/partial write and flush errors, with exact buffer and mutable states. -/
theorem submit_run_iff {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request after : Request B) (writer final : W) (out : core.result.Result Unit X) :
    Request.submit bytes ops request writer = Result.ok (out, after, final) ↔ SubmitRun bytes ops request writer out after final := by
  constructor
  · intro returned
    unfold Request.submit at returned
    cases attempted : request.attempted with
    | true =>
      simp only [attempted, ↓reduceIte] at returned
      obtain ⟨error, invalid, rest⟩ := (bind_returns_iff _ _ _).mp returned
      have pair : ((.Err error : core.result.Result Unit X), request, writer) = (out, after, final) := by simpa using rest
      obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
      exact .replay error attempted invalid
    | false =>
      simp only [attempted, Bool.false_eq_true, ↓reduceIte] at returned
      obtain ⟨wire, viewed, rest⟩ := (bind_returns_iff _ _ _).mp returned
      obtain ⟨⟨written, state⟩, writeCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases written with
      | Err error =>
        have pair : ((.Err error : core.result.Result Unit X), {request with attempted := true}, state) = (out, after, final) := by simpa using rest
        obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
        exact .writeDenied wire state error attempted viewed writeCall
      | Ok u =>
        cases u
        obtain ⟨⟨result, last⟩, flushCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
        have pair : (result, {request with attempted := true}, last) = (out, after, final) := by simpa using rest
        obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
        exact .flushed wire state last result attempted viewed writeCall flushCall
  · intro run
    cases run with
    | replay error attempted invalid => simp [Request.submit, attempted, invalid]
    | writeDenied wire after error fresh view written => simp [Request.submit, fresh, view, written]
    | flushed wire written after out fresh view writeCall flushCall => simp [Request.submit, fresh, view, writeCall, flushCall]

theorem returned_body_is_captured {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request after : Request B) (writer final : W) (out : core.result.Result Unit X)
    (returned : Request.submit bytes ops request writer = Result.ok (out, after, final)) : after.body = request.body := by
  cases (submit_run_iff bytes ops request after writer final out).mp returned <;> rfl

theorem every_return_is_spent {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request after : Request B) (writer final : W) (out : core.result.Result Unit X)
    (returned : Request.submit bytes ops request writer = Result.ok (out, after, final)) : after.attempted = true := by
  cases (submit_run_iff bytes ops request after writer final out).mp returned with
  | replay error attempted invalid => exact attempted
  | writeDenied => rfl
  | flushed => rfl

theorem replay_calls_no_buffer_or_writer {B W X : Type} (bytes : WireBytes B) (ops : Writer W X)
    (request : Request B) (writer : W) (error : X) (spent : request.attempted = true)
    (invalid : ops.INVALID_TRANSITION = Result.ok error) :
    Request.submit bytes ops request writer = Result.ok (.Err error, request, writer) := by
  simp [Request.submit, spent, invalid]

end aivm_secrets_garrett_core.provider_io.Proofs
