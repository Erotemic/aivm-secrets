import GarrettProviderSimulation
import GarrettDispatch

open Aeneas Aeneas.Std
set_option maxHeartbeats 3000000

/-! Origin of the actual bound current check. Native primitive semantics and
input conversions remain explicit; the complete callback's admission result
or provider arrival is not assumed. -/
namespace aivm_secrets_garrett_core.current_admission.Proofs

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private theorem constant_not_success {X O P : Type} (constant : Result X) (state after : P) (value : O)
    (returned : (do let error ← constant; Result.ok ((.Err error : core.result.Result O X), state)) = Result.ok (.Ok value, after)) : False := by
  obtain ⟨error, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  simp at rest

/-- Projection of immutable source context, not an alternative interpreter. -/
def view (ctx : Context) : provider_exchange.Simulation.Context :=
  ⟨ctx.claims, ctx.grant, ctx.operation, ctx.operation, ctx.write, ctx.allowed⟩

theorem context_constructor (identity : Claims) (expected : Expectation) (peer : alloc.vec.Vec U8)
    (claims : credential_use.UseClaims) (grant : credential_use.UseGrant) (operation : alloc.vec.Vec U8)
    (write allowed : Bool) :
    Context.new identity expected peer claims grant operation write allowed =
      Result.ok ⟨identity, expected, peer, claims, grant, operation, write, allowed⟩ := rfl

/-- Successful returned current admission has the exact primitive order,
    post-states, sampled time and actual source validators. -/
theorem current_success_iff {C X : Type} (ops : Checks C X) (ctx : Context)
    (before after : C) (stamp : manifest.AdmissionStamp) :
    Context.current ops ctx before = Result.ok (.Ok stamp, after) ↔
      ∃ coordinated clocked controlled leased now elapsed,
        ops.coordination before = Result.ok (.Ok (), coordinated) ∧
        ops.clock coordinated = Result.ok (.Ok now, clocked) ∧
        ops.control clocked now = Result.ok (.Ok (), controlled) ∧
        ops.lease controlled now = Result.ok (.Ok (), leased) ∧
        present ctx.identity ctx.expected ctx.peer now = Result.ok (.Ok ()) ∧
        ops.elapsed leased = Result.ok (.Ok elapsed, after) ∧
        manifest.current ctx.claims ctx.grant ctx.operation ctx.operation ctx.write ctx.allowed now elapsed = Result.ok (.Ok stamp) := by
  constructor
  · intro returned
    unfold Context.current at returned
    obtain ⟨⟨coordinated, state1⟩, coordinateCall, rest⟩ := (bind_returns_iff _ _ _).mp returned
    cases coordinated with
    | Err error => simp at rest
    | Ok u =>
      cases u
      obtain ⟨⟨clocked, state2⟩, clockCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases clocked with
      | Err error => simp at rest
      | Ok now =>
        obtain ⟨⟨controlled, state3⟩, controlCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
        cases controlled with
        | Err error => simp at rest
        | Ok u =>
          cases u
          obtain ⟨⟨leased, state4⟩, leaseCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
          cases leased with
          | Err error => simp at rest
          | Ok u =>
            cases u
            obtain ⟨identity, presentCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
            cases identity with
            | Err denial => exact False.elim (constant_not_success ops.INVALID_CAPABILITY state4 after stamp (by simpa using rest))
            | Ok u =>
              cases u
              obtain ⟨⟨elapsedResult, state5⟩, elapsedCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
              cases elapsedResult with
              | Err error => simp at rest
              | Ok elapsed =>
                obtain ⟨result, authorizeCall, rest⟩ := (bind_returns_iff _ _ _).mp rest
                cases result with
                | Err denial => exact False.elim (constant_not_success (ops.use_error denial) state5 after stamp (by simpa using rest))
                | Ok actual =>
                  have pair : (.Ok actual, state5) = ((.Ok stamp : core.result.Result manifest.AdmissionStamp X), after) := by simpa using rest
                  have sameStamp : actual = stamp := by simpa using congrArg Prod.fst pair
                  have sameState : state5 = after := congrArg Prod.snd pair
                  subst actual; subst state5
                  exact ⟨state1, state2, state3, state4, now, elapsed, coordinateCall, clockCall, controlCall, leaseCall, presentCall, elapsedCall, authorizeCall⟩
  · rintro ⟨state1, state2, state3, state4, now, elapsed, coordinated, clocked, controlled, leased, identity, elapsedCall, authorized⟩
    simp [Context.current, coordinated, clocked, controlled, leased, identity, elapsedCall, authorized]

/-- Stamp origin is derived from the actual constructor at its actual sampled
    coordinates, rather than postulated for the native current callback. -/
theorem current_issued {C X : Type} (ops : Checks C X) (ctx : Context) (before after : C)
    (stamp : manifest.AdmissionStamp)
    (returned : Context.current ops ctx before = Result.ok (.Ok stamp, after)) :
    provider_exchange.Simulation.Issued (view ctx) stamp ∧
      present ctx.identity ctx.expected ctx.peer stamp.now = Result.ok (.Ok ()) := by
  obtain ⟨state1, state2, state3, state4, now, elapsed, _, _, _, _, identity, _, authorized⟩ :=
    (current_success_iff ops ctx before after stamp).mp returned
  have same := (manifest.StampProofs.current_success_iff ctx.claims ctx.grant ctx.operation ctx.operation ctx.write ctx.allowed now elapsed stamp).mp authorized |>.2
  subst stamp
  exact ⟨by simpa [provider_exchange.Simulation.Issued, view] using authorized, identity⟩

/-- **Every admission stamp had a current identity, control state and
    credential lease at its own time.** A returned current admission ran the
    control check and the credential-lease check (for OAuth sessions the
    native callback is the vault's `require_current`, over the extracted
    `require_current_lease`), both returning success at exactly the time
    recorded in the stamp, and the presented identity was current at that
    time too. Every provider send uses such a stamp (`dispatch_current_origin`,
    `owned_read_driver_stamp_origin`). -/
theorem admitted_stamp_had_current_lease {C X : Type} (ops : Checks C X) (ctx : Context)
    (before after : C) (stamp : manifest.AdmissionStamp)
    (returned : Context.current ops ctx before = Result.ok (.Ok stamp, after)) :
    ∃ clocked controlled leased,
      ops.control clocked stamp.now = Result.ok (.Ok (), controlled) ∧
      ops.lease controlled stamp.now = Result.ok (.Ok (), leased) ∧
      present ctx.identity ctx.expected ctx.peer stamp.now = Result.ok (.Ok ()) := by
  obtain ⟨_, clocked, controlled, leased, now, elapsed, _, _, control, lease, identity, _, authorized⟩ :=
    (current_success_iff ops ctx before after stamp).mp returned
  have same := (manifest.StampProofs.current_success_iff ctx.claims ctx.grant ctx.operation ctx.operation ctx.write ctx.allowed now elapsed stamp).mp authorized |>.2
  subst stamp
  exact ⟨clocked, controlled, leased, control, lease, identity⟩

theorem current_snapshot_accepted {C X : Type} (ops : Checks C X) (ctx : Context) (before after : C)
    (stamp : manifest.AdmissionStamp)
    (returned : Context.current ops ctx before = Result.ok (.Ok stamp, after)) :
    (provider_exchange.Simulation.snapshot (view ctx) stamp).accepted :=
  provider_exchange.Simulation.issued_snapshot_is_accepted (view ctx) stamp (current_issued ops ctx before after stamp returned).1

private abbrev bound_provider {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X) :=
  Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider work checks

private abbrev bound_work {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X) :=
  Bound.Insts.Aivm_secrets_garrett_coreDispatchWork work checks

private theorem forward_frame {W C H O X A : Type} (call : W → Result (A × W))
    (pending after : Bound W C H O X) (out : A)
    (returned : (do let (result, work) ← call pending.work; Result.ok (result, {pending with work})) = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  obtain ⟨⟨result, work⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have pair : (result, {pending with work}) = (out, after) := by simpa using rest
  have same : after = {pending with work} := (congrArg Prod.snd pair).symm
  subst after
  exact ⟨rfl, rfl⟩

theorem bound_constructor {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (ctx : Context) (primitive : W) (state : C) :
    Bound.new work checks ctx primitive state = Result.ok ⟨ctx, primitive, state⟩ := rfl

theorem bound_setup_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (out : core.result.Result H X)
    (returned : (bound_provider work checks).setup pending = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame work.provider_exchangeProviderInst.setup pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup] using returned

theorem bound_receive_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (channel : H) (out : core.result.Result O X)
    (returned : (bound_provider work checks).receive pending channel = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame (fun state => work.provider_exchangeProviderInst.receive state channel) pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive] using returned

theorem bound_send_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (channel next : H) (out : core.result.Result Unit X)
    (returned : (bound_provider work checks).send pending channel = Result.ok (out, after, next)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  dsimp only [bound_provider, Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at returned
  obtain ⟨⟨result, state, sent⟩, _, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have pair : (result, {pending with work := state}, sent) = (out, after, next) := by simpa using rest
  obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
  exact ⟨rfl, rfl⟩

/-- The bound recheck invokes the actual core validator, independently of any
    recheck implemented by its raw provider primitive. -/
theorem bound_recheck_iff {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (out : core.result.Result manifest.AdmissionStamp X) :
    (bound_provider work checks).recheck pending = Result.ok (out, after) ↔
      ∃ state, Context.current checks pending.context pending.checks = Result.ok (out, state) ∧ after = {pending with checks := state} := by
  constructor
  · intro returned
    dsimp only [bound_provider, Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
    unfold Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at returned
    obtain ⟨⟨result, state⟩, ran, rest⟩ := (bind_returns_iff _ _ _).mp returned
    have pair : (result, {pending with checks := state}) = (out, after) := by simpa using rest
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
    exact ⟨state, ran, rfl⟩
  · rintro ⟨state, ran, rfl⟩
    simp [Bound.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck, ran]

theorem bound_recheck_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (out : core.result.Result manifest.AdmissionStamp X)
    (returned : (bound_provider work checks).recheck pending = Result.ok (out, after)) :
    after.context = pending.context ∧ after.work = pending.work := by
  obtain ⟨state, _, rfl⟩ := (bound_recheck_iff work checks pending after out).mp returned
  exact ⟨rfl, rfl⟩

theorem bound_recheck_issued {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (stamp : manifest.AdmissionStamp)
    (returned : (bound_provider work checks).recheck pending = Result.ok (.Ok stamp, after)) :
    provider_exchange.Simulation.Issued (view pending.context) stamp ∧
      present pending.context.identity pending.context.expected pending.context.peer stamp.now = Result.ok (.Ok ()) := by
  obtain ⟨state, ran, _⟩ := (bound_recheck_iff work checks pending after (.Ok stamp)).mp returned
  exact current_issued checks pending.context pending.checks state stamp ran

/-- Every read-driver stamp, including failed/partial send and response errors,
    was issued by the same immutable context captured before TLS setup. -/
theorem read_driver_stamp_origin {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (bound_provider work checks) pending ⟨phase, false⟩ = Result.ok (report, after)) :
    after.context = pending.context ∧
      ∀ stamp, report.current = some stamp → provider_exchange.Simulation.Issued (view pending.context) stamp := by
  have run := (provider_exchange.Proofs.read_run_iff (bound_provider work checks) pending phase report after).mp returned
  cases run with
  | setupDenied after error setup =>
    refine ⟨(bound_setup_frame work checks pending after (.Err error) setup).1, ?_⟩
    intro stamp same
    simp [provider_exchange.Proofs.receipt] at same
  | admissionDenied channel state1 after error setup checked =>
    refine ⟨(bound_recheck_frame work checks state1 after (.Err error) checked).1.trans
      (bound_setup_frame work checks pending state1 (.Ok channel) setup).1, ?_⟩
    intro stamp same
    simp [provider_exchange.Proofs.receipt] at same
  | sendDenied channel next stamp state1 state2 after error setup checked sent =>
    have first := (bound_setup_frame work checks pending state1 (.Ok channel) setup).1
    have second := (bound_recheck_frame work checks state1 state2 (.Ok stamp) checked).1
    have last := (bound_send_frame work checks state2 after channel next (.Err error) sent).1
    refine ⟨last.trans (second.trans first), ?_⟩
    intro actual same
    have equal : stamp = actual := by simpa [provider_exchange.Proofs.receipt] using same
    subst actual
    simpa only [first] using (bound_recheck_issued work checks state1 state2 stamp checked).1
  | responseDenied channel next stamp state1 state2 state3 after error setup checked sent received =>
    have first := (bound_setup_frame work checks pending state1 (.Ok channel) setup).1
    have second := (bound_recheck_frame work checks state1 state2 (.Ok stamp) checked).1
    have third := (bound_send_frame work checks state2 state3 channel next (.Ok ()) sent).1
    have last := (bound_receive_frame work checks state3 after next (.Err error) received).1
    refine ⟨last.trans (third.trans (second.trans first)), ?_⟩
    intro actual same
    have equal : stamp = actual := by simpa [provider_exchange.Proofs.receipt] using same
    subst actual
    simpa only [first] using (bound_recheck_issued work checks state1 state2 stamp checked).1
  | complete channel next stamp state1 state2 state3 after value setup checked sent received =>
    have first := (bound_setup_frame work checks pending state1 (.Ok channel) setup).1
    have second := (bound_recheck_frame work checks state1 state2 (.Ok stamp) checked).1
    have third := (bound_send_frame work checks state2 state3 channel next (.Ok ()) sent).1
    have last := (bound_receive_frame work checks state3 after next (.Ok value) received).1
    refine ⟨last.trans (third.trans (second.trans first)), ?_⟩
    intro actual same
    have equal : stamp = actual := by simpa [provider_exchange.Proofs.receipt] using same
    subst actual
    simpa only [first] using (bound_recheck_issued work checks state1 state2 stamp checked).1

private abbrev outer_provider {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X) :=
  dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider (bound_work work checks)

private theorem returned_state {A P : Type} (value out : A) (state after : P)
    (returned : Result.ok (value, state) = Result.ok (out, after)) : after = state :=
  (congrArg Prod.snd ((Result.ok.injEq).mp returned)).symm

private theorem fixed_state {A B P : Type} (first : Result A) (build : A → B) (state after : P) (out : B)
    (returned : (do let value ← first; Result.ok (build value, state)) = Result.ok (out, after)) : after = state := by
  obtain ⟨value, _, same⟩ := (bind_returns_iff _ _ _).mp returned
  exact returned_state _ _ _ _ same

theorem dispatch_setup_context {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : dispatch.Pending (Bound W C H O X) H O X) (out : core.result.Result H X)
    (returned : (outer_provider work checks).setup pending = Result.ok (out, after)) :
    after.work.context = pending.work.context := by
  dsimp only [outer_provider, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.setup at returned
  obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have framed := (bound_setup_frame work checks pending.work native result callback).1
  have same := returned_state result out {pending with work := native} after (by simpa using rest)
  subst after
  exact framed

theorem dispatch_receive_context {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : dispatch.Pending (Bound W C H O X) H O X) (channel : H) (out : core.result.Result O X)
    (returned : (outer_provider work checks).receive pending channel = Result.ok (out, after)) :
    after.work.context = pending.work.context := by
  dsimp only [outer_provider, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.receive at returned
  obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp returned
  have framed := (bound_receive_frame work checks pending.work native channel result callback).1
  have same := returned_state result out {pending with work := native} after (by simpa using rest)
  subst after
  exact framed

theorem dispatch_send_context {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : dispatch.Pending (Bound W C H O X) H O X) (channel next : H) (out : core.result.Result Unit X)
    (returned : (outer_provider work checks).send pending channel = Result.ok (out, after, next)) :
    after.work.context = pending.work.context := by
  dsimp only [outer_provider, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send at returned
  obtain ⟨⟨accepted, effects, localState⟩, gate, rest⟩ := (bind_returns_iff _ _ _).mp returned
  cases accepted with
  | false =>
    obtain ⟨error, _, same⟩ := (bind_returns_iff _ _ _).mp rest
    have pair : (.Err error, {pending with effects, «local» := localState}, channel) = (out, after, next) := by simpa using same
    obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
    rfl
  | true =>
    obtain ⟨⟨result, native, sent⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have framed := (bound_send_frame work checks pending.work native channel sent result callback).1
    have pair : (result, {pending with work := native, effects := effects, «local» := localState}, sent) = (out, after, next) := by simpa using rest
    obtain ⟨rfl, rfl, rfl⟩ := (by simpa using pair)
    exact framed

/-- The local check gate can neither invent a successful stamp nor replace
    the bound context, including all returned denial prefixes. -/
theorem dispatch_current_origin {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : dispatch.Pending (Bound W C H O X) H O X) (out : core.result.Result manifest.AdmissionStamp X)
    (returned : (outer_provider work checks).recheck pending = Result.ok (out, after)) :
    after.work.context = pending.work.context ∧
      ∀ stamp, out = .Ok stamp → provider_exchange.Simulation.Issued (view pending.work.context) stamp := by
  dsimp only [outer_provider, dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider] at returned
  unfold dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.recheck at returned
  obtain ⟨⟨accepted, first⟩, began, rest⟩ := (bind_returns_iff _ _ _).mp returned
  cases accepted with
  | false =>
    have same := fixed_state (bound_work work checks).INVALID_TRANSITION
      (fun error => (.Err error : core.result.Result manifest.AdmissionStamp X)) {pending with «local» := first} after out (by simpa using rest)
    subst after
    refine ⟨rfl, ?_⟩
    intro stamp success
    subst out
    exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
  | true =>
    obtain ⟨⟨result, native⟩, callback, rest⟩ := (bind_returns_iff _ _ _).mp rest
    have framed := (bound_recheck_frame work checks pending.work native result callback).1
    cases result with
    | Err error =>
      have pair : ((.Err error : core.result.Result manifest.AdmissionStamp X), {pending with work := native, «local» := first}) = (out, after) := by simpa using rest
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
      exact ⟨framed, by intro stamp success; simp at success⟩
    | Ok current =>
      obtain ⟨⟨accepted, last⟩, finished, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases accepted with
      | false =>
        have same := fixed_state (bound_work work checks).INVALID_TRANSITION
          (fun error => (.Err error : core.result.Result manifest.AdmissionStamp X)) {pending with work := native, «local» := last} after out (by simpa using rest)
        subst after
        refine ⟨framed, ?_⟩
        intro stamp success
        subst out
        exact False.elim (constant_not_success _ _ _ _ (by simpa using rest))
      | true =>
        have pair : ((.Ok current : core.result.Result manifest.AdmissionStamp X), {pending with work := native, «local» := last}) = (out, after) := by simpa using rest
        obtain ⟨rfl, rfl⟩ := Prod.mk.inj pair
        refine ⟨framed, ?_⟩
        intro stamp success
        have same : current = stamp := by simpa using success
        subst stamp
        exact (bound_recheck_issued work checks pending.work native current callback).1

/-- This is the actual production driver's outer owned-send adapter over the
    bound provider. No native-current callback origin premise is supplied. -/
theorem owned_read_driver_stamp_origin {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : dispatch.Pending (Bound W C H O X) H O X) (phase : read_transition.Phase)
    (report : provider_exchange.Report O X)
    (returned : provider_exchange.exchange (outer_provider work checks) pending ⟨phase, false⟩ = Result.ok (report, after)) :
    after.work.context = pending.work.context ∧
      ∀ stamp, report.current = some stamp → provider_exchange.Simulation.Issued (view pending.work.context) stamp := by
  have run := (provider_exchange.Proofs.read_run_iff (outer_provider work checks) pending phase report after).mp returned
  cases run with
  | setupDenied after error setup =>
    refine ⟨dispatch_setup_context work checks pending after (.Err error) setup, ?_⟩
    intro stamp same
    simp [provider_exchange.Proofs.receipt] at same
  | admissionDenied channel state1 after error setup checked =>
    refine ⟨(dispatch_current_origin work checks state1 after (.Err error) checked).1.trans
      (dispatch_setup_context work checks pending state1 (.Ok channel) setup), ?_⟩
    intro stamp same
    simp [provider_exchange.Proofs.receipt] at same
  | sendDenied channel next stamp state1 state2 after error setup checked sent =>
    have first := dispatch_setup_context work checks pending state1 (.Ok channel) setup
    have second := dispatch_current_origin work checks state1 state2 (.Ok stamp) checked
    have last := dispatch_send_context work checks state2 after channel next (.Err error) sent
    refine ⟨last.trans (second.1.trans first), ?_⟩
    intro actual same
    have equal : stamp = actual := by simpa [provider_exchange.Proofs.receipt] using same
    subst actual
    simpa only [first] using second.2 stamp rfl
  | responseDenied channel next stamp state1 state2 state3 after error setup checked sent received =>
    have first := dispatch_setup_context work checks pending state1 (.Ok channel) setup
    have second := dispatch_current_origin work checks state1 state2 (.Ok stamp) checked
    have third := dispatch_send_context work checks state2 state3 channel next (.Ok ()) sent
    have last := dispatch_receive_context work checks state3 after next (.Err error) received
    refine ⟨last.trans (third.trans (second.1.trans first)), ?_⟩
    intro actual same
    have equal : stamp = actual := by simpa [provider_exchange.Proofs.receipt] using same
    subst actual
    simpa only [first] using second.2 stamp rfl
  | complete channel next stamp state1 state2 state3 after value setup checked sent received =>
    have first := dispatch_setup_context work checks pending state1 (.Ok channel) setup
    have second := dispatch_current_origin work checks state1 state2 (.Ok stamp) checked
    have third := dispatch_send_context work checks state2 state3 channel next (.Ok ()) sent
    have last := dispatch_receive_context work checks state3 after next (.Ok value) received
    refine ⟨last.trans (third.trans (second.1.trans first)), ?_⟩
    intro actual same
    have equal : stamp = actual := by simpa [provider_exchange.Proofs.receipt] using same
    subst actual
    simpa only [first] using second.2 stamp rfl


/-- Coordination refusal returns its exact state and error without sampling time. -/
theorem coordination_refusal {C X : Type} (ops : Checks C X) (ctx : Context)
    (before after : C) (error : X)
    (denied : ops.coordination before = Result.ok (.Err error, after)) :
    Context.current ops ctx before = Result.ok (.Err error, after) := by
  simp [Context.current, denied]

theorem bound_prepare_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (out : core.result.Result Unit X)
    (returned : (bound_work work checks).prepare pending = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame (fun state => work.prepare state) pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.prepare] using returned

theorem bound_audit_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (phase : read_transition.Phase) (out : core.result.Result Unit X)
    (returned : (bound_work work checks).audit pending phase = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame (fun state => work.audit state phase) pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.audit] using returned

theorem bound_configure_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (keyed : Bool) (out : core.result.Result Unit X)
    (returned : (bound_work work checks).configure pending keyed = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame (fun state => work.configure state keyed) pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.configure] using returned

theorem bound_check_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (out : core.result.Result Unit X)
    (returned : (bound_work work checks).check pending = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame (fun state => work.check state) pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.check] using returned

theorem bound_reserve_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (out : core.result.Result Unit X)
    (returned : (bound_work work checks).reserve pending = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame (fun state => work.reserve state) pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.reserve] using returned

theorem bound_finish_frame {W C H O X : Type} (work : dispatch.Work W H O X) (checks : Checks C X)
    (pending after : Bound W C H O X) (out : core.result.Result Unit X)
    (returned : (bound_work work checks).finish pending = Result.ok (out, after)) :
    after.context = pending.context ∧ after.checks = pending.checks := by
  apply forward_frame (fun state => work.finish state) pending after out
  simpa [Bound.Insts.Aivm_secrets_garrett_coreDispatchWork.finish] using returned

end aivm_secrets_garrett_core.current_admission.Proofs

namespace aivm_secrets_garrett_core.credential_use.Proofs

/-- A surrogate issued under a use grant is issued only while the grant is
active and current, and never outlives it: its lifetime is the requested one
capped at the grant's remaining time. -/
theorem nested_lifetime_spec (grant : UseGrant) (now lifetime : I64)
    (nonnegative : 0 ≤ grant.claims.issued_at.val) :
    nested_lifetime grant now lifetime ⦃ out =>
      (out = none ↔ ¬(grant.active = true ∧ grant.claims.issued_at.val ≤ now.val ∧
          now.val < grant.claims.expires_at.val)) ∧
      ∀ l, out = some l → l.val = min lifetime.val (grant.claims.expires_at.val - now.val) ⦄ := by
  unfold nested_lifetime
  cases grant.active <;> simp only [Bool.false_eq_true, ↓reduceIte]
  · apply (WP.spec_ok _).mpr; simp
  · split
    · apply (WP.spec_ok _).mpr; constructor
      · simp only [true_iff]; intro h; scalar_tac
      · simp
    · split
      · apply (WP.spec_ok _).mpr; constructor
        · simp only [true_iff]; intro h; scalar_tac
        · simp
      · step*

/-- **The window a session's grant starts with.** `grant_window` refuses
    unless `now` is in `[0, i64::MAX - 3600]` and the lifetime in
    `[1, 3600]`, and otherwise returns the expiry `now + lifetime`. These are
    exactly the bounds `Current` later requires of the grant's claims
    (`0 ≤ issued_at ≤ 9223372036854772207`, `issued_at < expires_at ≤
    issued_at + 3600`), so a grant started this way is one the request path
    can admit while it is current. -/
theorem grant_window_spec (now lifetime : I64) :
    grant_window now lifetime ⦃ out =>
      (out = none ↔ ¬(0 ≤ now.val ∧ now.val ≤ 9223372036854772207 ∧
          1 ≤ lifetime.val ∧ lifetime.val ≤ 3600)) ∧
      ∀ e, out = some e → e.val = now.val + lifetime.val ∧
        0 ≤ now.val ∧ now.val ≤ 9223372036854772207 ∧ now.val < e.val ∧
        e.val ≤ now.val + 3600 ⦄ := by
  unfold grant_window
  split
  · apply (WP.spec_ok _).mpr; constructor
    · simp only [true_iff]; intro h; scalar_tac
    · simp
  · split
    · apply (WP.spec_ok _).mpr; constructor
      · simp only [true_iff]; intro h; scalar_tac
      · simp
    · split
      · apply (WP.spec_ok _).mpr; constructor
        · simp only [true_iff]; intro h; scalar_tac
        · simp
      · split
        · apply (WP.spec_ok _).mpr; constructor
          · simp only [true_iff]; intro h; scalar_tac
          · simp
        · step*
          refine ⟨by simp; scalar_tac, ?_⟩
          intro e same
          simp only [Option.some.injEq] at same
          subst same
          refine ⟨i_post, ?_, ?_, ?_, ?_⟩ <;> scalar_tac

end aivm_secrets_garrett_core.credential_use.Proofs
