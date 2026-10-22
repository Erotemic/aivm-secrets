import GarrettNR23WriterOrigin
import GarrettProviderIO

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-2/NR-3 source-owned routing adapter. `Routed` is extracted from the
production core and forwards both provider setup and dispatch audit to the
SAME captured host route. These facts do not independently certify that the
unextracted `ManifestProvider` primitive honors the route argument; the
native source contract is separately reviewed/checked.
-/
namespace aivm_secrets_garrett_core.nr23.NativeRoute

open aivm_secrets_garrett_core.provider_io.Proofs

private abbrev routedProvider {W H O X : Type}
    (work : dispatch.Work W H O X)
    (routes : provider_io.RouteWork W H X) :=
  provider_io.Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider
    work routes

private abbrev routedDispatch {W H O X : Type}
    (work : dispatch.Work W H O X)
    (routes : provider_io.RouteWork W H X) :=
  provider_io.Routed.Insts.Aivm_secrets_garrett_coreDispatchWork
    work routes

/-- The very same captured route is submitted to the native audit primitive,
    while its returned mutable work state is kept exactly. There is no
    caller-controlled alternate audit destination in the extracted wrapper. -/
theorem dispatch_audit_uses_exact_host_captured_route
    {W H O X : Type}
    (work : dispatch.Work W H O X)
    (routes : provider_io.RouteWork W H X)
    (ctx : current_admission.Context)
    (pending after : provider_io.Routed W H O X)
    (phase : read_transition.Phase)
    (out : core.result.Result Unit X)
    (bound : pending.route = ctx.grant.route)
    (returned : (routedDispatch work routes).audit pending phase =
      Result.ok (out, after)) :
    after.route = ctx.grant.route ∧
    ∃ primitive,
      routes.audit_route pending.work ctx.grant.route phase =
        Result.ok (out, primitive) ∧
      after.work = primitive := by
  obtain ⟨primitive, called, exactly⟩ :=
    (routed_audit_iff work routes pending after phase out).mp returned
  subst after
  rw [bound] at called ⊢
  exact ⟨rfl, primitive, called, rfl⟩

/-- The setup continuation hands exactly the captured route to the native
    setup primitive, even when the primitive returns an error after opening
    a socket or running part of a TLS handshake. -/
theorem provider_setup_uses_exact_host_captured_route
    {W H O X : Type}
    (work : dispatch.Work W H O X)
    (routes : provider_io.RouteWork W H X)
    (ctx : current_admission.Context)
    (pending after : provider_io.Routed W H O X)
    (out : core.result.Result H X)
    (bound : pending.route = ctx.grant.route)
    (returned : (routedProvider work routes).setup pending =
      Result.ok (out, after)) :
    after.route = ctx.grant.route ∧
    ∃ primitive,
      routes.setup_route pending.work ctx.grant.route =
        Result.ok (out, primitive) ∧
      after.work = primitive := by
  obtain ⟨primitive, called, exactly⟩ :=
    (routed_setup_iff work routes pending after out).mp returned
  subst after
  rw [bound] at called ⊢
  exact ⟨rfl, primitive, called, rfl⟩

/-- Every returned current recheck, provider send or response callback
    preserves the source-owned route; in particular no mutable `work`
    replacement can change the wrapper's captured destination. -/
theorem provider_recheck_send_receive_cannot_replace_host_route
    {W H O X : Type}
    (work : dispatch.Work W H O X)
    (routes : provider_io.RouteWork W H X)
    (ctx : current_admission.Context)
    (first checked sent received : provider_io.Routed W H O X)
    (stamp : core.result.Result manifest.AdmissionStamp X)
    (channel next : H)
    (sendResult : core.result.Result Unit X)
    (answer : core.result.Result O X)
    (bound : first.route = ctx.grant.route)
    (rechecked : (routedProvider work routes).recheck first =
      Result.ok (stamp, checked))
    (sentCall : (routedProvider work routes).send checked channel =
      Result.ok (sendResult, sent, next))
    (receivedCall : (routedProvider work routes).receive sent next =
      Result.ok (answer, received)) :
    checked.route = ctx.grant.route ∧
    sent.route = ctx.grant.route ∧
    received.route = ctx.grant.route := by
  have h1 := recheck_keeps_route work routes first checked stamp rechecked
  have h2 := send_keeps_route work routes checked sent channel next
    sendResult sentCall
  have h3 := receive_keeps_route work routes sent received next answer
    receivedCall
  exact ⟨h1.trans bound, h2.trans (h1.trans bound),
    h3.trans (h2.trans (h1.trans bound))⟩

/-- The native call sites cannot substitute a new route through the extracted
    prepare/configure/check/reserve/finish callbacks either. These callbacks
    may still perform unreviewed filesystem/clock/network effects. -/
theorem all_configuration_callbacks_preserve_captured_route
    {W H O X : Type}
    (work : dispatch.Work W H O X)
    (routes : provider_io.RouteWork W H X)
    (ctx : current_admission.Context)
    (p a b c d e : provider_io.Routed W H O X)
    (configuredKeyed : Bool)
    (outA outB outC outD outE : core.result.Result Unit X)
    (bound : p.route = ctx.grant.route)
    (prepare : (routedDispatch work routes).prepare p = Result.ok (outA, a))
    (configure : (routedDispatch work routes).configure a configuredKeyed =
      Result.ok (outB, b))
    (check : (routedDispatch work routes).check b = Result.ok (outC, c))
    (reserve : (routedDispatch work routes).reserve c = Result.ok (outD, d))
    (finish : (routedDispatch work routes).finish d = Result.ok (outE, e)) :
    a.route = ctx.grant.route ∧ b.route = ctx.grant.route ∧
    c.route = ctx.grant.route ∧ d.route = ctx.grant.route ∧
    e.route = ctx.grant.route := by
  have hA := prepare_keeps_route work routes p a outA prepare
  have hB := configure_keeps_route work routes a b configuredKeyed outB configure
  have hC := check_keeps_route work routes b c outC check
  have hD := reserve_keeps_route work routes c d outD reserve
  have hE := finish_keeps_route work routes d e outE finish
  exact ⟨hA.trans bound, hB.trans (hA.trans bound),
    hC.trans (hB.trans (hA.trans bound)),
    hD.trans (hC.trans (hB.trans (hA.trans bound))),
    hE.trans (hD.trans (hC.trans (hB.trans (hA.trans bound))))⟩

end aivm_secrets_garrett_core.nr23.NativeRoute
