import GarrettProductionAssurance
import GarrettSendOrigin
import GarrettChannelWork

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000
set_option linter.unusedSimpArgs false

/-!
# The production request, call by call

`production_request_sends_are_the_logged_sends` counts a request's provider
sends and labels them in order. This module states, for the request type
production runs (`ScopedRequest` over `provider_io::Routed`), what each
individual send rests on:

* its own dispatch callback, with its own receipt-trace segment;
* exactly one `providerSend` event in that segment, of that dispatch's
  phase, whose gate the extracted `manifest::authorize` accepted, after an
  acknowledged audit, bound to the request's own identity, operation and
  route;
* a channel that the primitive's own `setup` built from a routed state whose
  route is the request's own captured route.

`production_calls_have_own_route_payload` specializes the primitive to the
core-owned `channel_work::Submitting` and adds what that setup built: the
extracted encoder's request for that route and the session's credential,
in a fresh, unsent channel, the one `Channel::submit` then writes once
(`GarrettChannelWork`). The native premise is unchanged (`NATIVE-SINK-01`):
that the native process's credential-bearing provider writes are those
`write_all` calls.
-/
namespace aivm_secrets_garrett_core.production.SendOrigin

open aivm_secrets_garrett_core.request_effects.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.nr23.ExactSinks
open aivm_secrets_garrett_core.nr23.SendLog
open aivm_secrets_garrett_core.nr23.SendOrigin
open aivm_secrets_garrett_core.production.Assurance
open aivm_secrets_garrett_core.request_context

/-- The routed primitive state still has the route of context `k`. -/
def RouteOf {D H O X : Type} (k : current_admission.Context) (d : provider_io.Routed D H O X) : Prop :=
  d.route = k.grant.route

/-- Every callback of a routed primitive keeps its route. -/
theorem routed_keeps {D H O X : Type} (work : dispatch.Work D H O X) (routes : provider_io.RouteWork D H X)
    (k : current_admission.Context) :
    Keeps (provider_io.Routed.Insts.Aivm_secrets_garrett_coreDispatchWork work routes) (RouteOf k) where
  prepare s r t h i := (provider_io.Proofs.prepare_keeps_route work routes s t r h).trans i
  audit s ph r t h i := (provider_io.Proofs.audit_keeps_route work routes s t ph r h).trans i
  configure s kw r t h i := (provider_io.Proofs.configure_keeps_route work routes s t kw r h).trans i
  check s r t h i := (provider_io.Proofs.check_keeps_route work routes s t r h).trans i
  reserve s r t h i := (provider_io.Proofs.reserve_keeps_route work routes s t r h).trans i
  finish s r t h i := (provider_io.Proofs.finish_keeps_route work routes s t r h).trans i
  setup s r t h i := (provider_io.Proofs.setup_keeps_route work routes s t r h).trans i
  send s c r t n h i := (provider_io.Proofs.send_keeps_route work routes s t c n r h).trans i
  receive s c r t h i := (provider_io.Proofs.receive_keeps_route work routes s t c r h).trans i

/-- What one dispatch segment shows, stated for the production request. -/
def CallEvidence {D H A X : Type} (work0 : dispatch.Work D H A X) (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (seg : Segment H) : Prop :=
  match seg.phase with
  | none => seg.calls = [] ∧ sourceSends seg.events = []
  | some ph => (seg.calls = [] ∧ sourceSends seg.events = []) ∨
      ∃ c g a, seg.calls = [c] ∧
        sourceSends seg.events = [.providerSend (eventPhase ph) g a] ∧
        g.accepted ∧ a = true ∧ gateBinding g = (current_admission.Proofs.view context).binding ∧
        ∃ d d', d.route = context.grant.route ∧
          (provider_io.Routed.Insts.Aivm_secrets_garrett_coreDispatchWork work0 routes).provider_exchangeProviderInst.setup d =
            Result.ok (.Ok c, d')

/-- **Production request, call by call.** For every returned outcome of the
    production request, the run is a chain of segments whose traces form a
    sound trace bound to the constructor context, and every dispatch
    segment either sent nothing and has no provider send, or sent one
    channel and has exactly one provider send, of its own phase, accepted by
    the extracted authorization, audit-acknowledged and bound to the
    context; that channel was built by the primitive's own setup from a
    routed state with the request's own route. -/
theorem production_calls_have_own_evidence
    {W F A E O X D V H C : Type}
    (work : request_adapter.Work W A E O X D V H) (factory : CheckFactory F X C)
    (routes : provider_io.RouteWork D H X)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending (ScopedRequest W F A E O X D V H C) A E O X
      (current_admission.Bound (provider_io.Routed D H A X) C H A X) V H)
    (out : core.result.Result (completion.Completed O) X)
    (created : request_adapter.Pending.new (scopedOps work factory routes)
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory routes)) pending = Result.ok out) :
    ∃ after segs,
      read_transition.Proofs.RequestRun
        (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
          (scopedOps work factory routes)) pending out after ∧
      Segs (scopedOps work factory routes) (routedPrimitive work routes) factory.current_admissionChecksInst
        context pending after.adapter segs ∧
      TraceSteps (ctxOf context) pending.effects after.adapter.effects (segs.flatMap Segment.events) ∧
      SoundTrace (withOutcome (segs.flatMap Segment.events) out) ∧
      BoundTrace (current_admission.Proofs.view context).binding (withOutcome (segs.flatMap Segment.events) out) ∧
      ∀ seg, seg ∈ segs → CallEvidence work.dispatchWorkInst routes context seg := by
  have initial := created_context work factory routes context native state pending created
  have contract := request_context.Proofs.native_context_contract work factory routes
  obtain ⟨after, ran⟩ := (read_transition.Proofs.run_current_returned_iff _ pending out).mp returned
  obtain ⟨segs, chain⟩ := run_segs (scopedOps work factory routes) (routedPrimitive work routes)
    factory.current_admissionChecksInst (fun pending => pending.context) contract pending out after ran
  rw [initial] at chain
  have reach : Reachable pending.effects :=
    ⟨pending.effects, (request_adapter.Proofs.initial_receipt _ _ pending created).1, .refl⟩
  have traced := segs_trace _ _ _ context chain
  obtain ⟨_, sound⟩ := trace_steps_preserve_soundness _ _ _ _ reach traced
  have bound := trace_steps_keep_binding (ctxOf context) (current_admission.Proofs.view context).binding
    (fun _ => rfl) _ _ _ traced
  have soundOut : SoundTrace (withOutcome (segs.flatMap Segment.events) out) := by
    cases out with
    | Ok _ => exact sound
    | Err _ =>
      intro e m
      rcases List.mem_append.mp m with m | m
      · exact sound e m
      · simp only [List.mem_singleton] at m; subst m; trivial
  have boundOut : BoundTrace (current_admission.Proofs.view context).binding
      (withOutcome (segs.flatMap Segment.events) out) := by
    cases out with
    | Ok _ => exact bound
    | Err _ =>
      intro phase gate ack m
      exact bound phase gate ack (by simpa [withOutcome] using m)
  obtain ⟨each, _⟩ := segs_each _ _ _ context (RouteOf (D := D) (H := H) (O := A) (X := X))
    (routed_keeps work.dispatchWorkInst routes) contract.dispatch_binding
    (fun w phase effect plan native planned =>
      (request_context.Proofs.dispatch_route work factory routes w native phase effect plan planned).2)
    chain reach
  refine ⟨after, segs, ran, chain, traced, soundOut, boundOut, fun seg m => ?_⟩
  have ok := each seg m
  unfold SegmentOK at ok
  unfold CallEvidence
  cases hph : seg.phase with
  | none => rw [hph] at ok; exact ok
  | some ph =>
    rw [hph] at ok
    rcases ok with none | ⟨c, g, a, hc, hs, d, d', inv, setup⟩
    · exact Or.inl none
    · have member : Event.providerSend (eventPhase ph) g a ∈ segs.flatMap Segment.events := by
        refine List.mem_flatMap.mpr ⟨seg, m, ?_⟩
        have : Event.providerSend (eventPhase ph) g a ∈ sourceSends seg.events := by rw [hs]; simp
        exact (List.mem_filter.mp this).1
      have authorized : g.accepted ∧ a = true := sound _ member
      exact Or.inr ⟨c, g, a, hc, hs, authorized.1, authorized.2, bound _ g a member, d, d', inv, setup⟩

section submitting
open aivm_secrets_garrett_core.channel_work.Proofs
variable {W0 B PW M A X : Type} (cw : channel_work.ChannelWork W0 B PW M A X)

/-- What the core-owned setup built for `route`: the extracted encoder's
    request over the native request fields and the session credential,
    wrapped, in a fresh, unsent, not-ready channel. -/
def BuiltFor (route : credential_use.Route) (c : provider_io.Channel B PW M X) : Prop :=
  ∃ s : channel_work.Submitting W0 B PW M A X, ∃ parts t encoded endpoint body t1 writer md s',
    cw.request_fields s.work = Result.ok (.Ok parts, t) ∧
    channel_work.encode (alloc.vec.Vec.new U8) route parts s.secret = Result.ok (.Ok endpoint, encoded) ∧
    cw.wrap_body t encoded = Result.ok (body, t1) ∧
    cw.connect t1 endpoint = Result.ok (.Ok (writer, md), s') ∧
    c = ⟨⟨body, false⟩, writer, md, false⟩

theorem routed_setup_built (d d' : provider_io.Routed (channel_work.Submitting W0 B PW M A X)
      (provider_io.Channel B PW M X) A X) (c : provider_io.Channel B PW M X)
    (h : (provider_io.Routed.Insts.Aivm_secrets_garrett_coreDispatchWork (submittingDispatch cw)
      (submittingRoutes cw)).provider_exchangeProviderInst.setup d = Result.ok (.Ok c, d')) :
    BuiltFor cw d.route c := by
  obtain ⟨native, called, _⟩ :=
    (provider_io.Proofs.routed_setup_iff (submittingDispatch cw) (submittingRoutes cw) d d' (.Ok c)).mp h
  obtain ⟨parts, t, encoded, endpoint, body, t1, writer, md, f, e, w, k, hc⟩ :=
    setup_route_constructs cw d.work native d.route c called
  exact ⟨d.work, parts, t, encoded, endpoint, body, t1, writer, md, native.work, f, e, w, k, hc⟩

/-- **Production request over the core-owned provider, call by call, with
    payload.** In addition to `production_calls_have_own_evidence`: every
    channel a dispatch sent was built, by that dispatch's own setup, from the
    extracted encoder's request for the request's own captured route. -/
theorem production_calls_have_own_route_payload
    {W F E O C V : Type}
    (work : request_adapter.Work W A E O X (channel_work.Submitting W0 B PW M A X) V (provider_io.Channel B PW M X))
    (factory : CheckFactory F X C)
    (binding : work.dispatchWorkInst = submittingDispatch cw)
    (context : current_admission.Context) (native : W) (state : F)
    (pending : request_adapter.Pending
      (ScopedRequest W F A E O X (channel_work.Submitting W0 B PW M A X) V (provider_io.Channel B PW M X) C) A E O X
      (current_admission.Bound (provider_io.Routed (channel_work.Submitting W0 B PW M A X)
        (provider_io.Channel B PW M X) A X) C (provider_io.Channel B PW M X) A X) V (provider_io.Channel B PW M X))
    (out : core.result.Result (completion.Completed O) X)
    (created : request_adapter.Pending.new (scopedOps work factory (submittingRoutes cw))
      ⟨context, native, state⟩ = Result.ok pending)
    (returned : read_transition.run_current
      (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
        (scopedOps work factory (submittingRoutes cw))) pending = Result.ok out) :
    ∃ after, ∃ segs : List (Segment (provider_io.Channel B PW M X)),
      read_transition.Proofs.RequestRun
        (request_adapter.Pending.Insts.Aivm_secrets_garrett_coreRead_transitionRequestClause0_FactsClause0_EffectCompletedClause0_Error
          (scopedOps work factory (submittingRoutes cw))) pending out after ∧
      SoundTrace (withOutcome (segs.flatMap Segment.events) out) ∧
      BoundTrace (current_admission.Proofs.view context).binding (withOutcome (segs.flatMap Segment.events) out) ∧
      ∀ seg, seg ∈ segs →
        CallEvidence work.dispatchWorkInst (submittingRoutes cw) context seg ∧
        ∀ c, c ∈ seg.calls → BuiltFor cw context.grant.route c := by
  obtain ⟨after, segs, ran, _, _, sound, bound, each⟩ :=
    production_calls_have_own_evidence work factory (submittingRoutes cw) context native state pending out
      created returned
  refine ⟨after, segs, ran, sound, bound, fun seg m => ⟨each seg m, fun c mc => ?_⟩⟩
  have ev := each seg m
  unfold CallEvidence at ev
  cases hph : seg.phase with
  | none => rw [hph] at ev; rw [ev.1] at mc; simp at mc
  | some ph =>
    rw [hph] at ev
    rcases ev with ⟨none, _⟩ | ⟨c', g, a, hc, _, _, _, _, d, d', route, setup⟩
    · rw [none] at mc; simp at mc
    · rw [hc] at mc
      simp only [List.mem_singleton] at mc
      subst mc
      rw [binding] at setup
      have built := routed_setup_built cw d d' _ setup
      rwa [route] at built

end submitting

end aivm_secrets_garrett_core.production.SendOrigin
