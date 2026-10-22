import GarrettNR23Request
import GarrettProviderWire

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

/-!
NR-3: the concrete provider encoder and source-owned Channel primitives.
The abstract request is not silently identified with a TLS syscall: the
last-mile native `ManifestWire`, `std::io::Write`, `StreamOwned`, `Drop`, and
socket reachability obligations remain explicitly external.
-/
namespace aivm_secrets_garrett_core.nr23.Effects

open aivm_secrets_garrett_core.provider_exchange.Simulation
open aivm_secrets_garrett_core.confinement.Proofs
open aivm_secrets_garrett_core.request_effects.TraceRefinement
open aivm_secrets_garrett_core.provider_wire.Proofs

/-- A useful source-level composition: a stamp that came from the real
    `manifest.current` constructor, the policy-chosen route, and a returned
    exact encoder/channel execution. It rules out *model-level* substitution
    of the destination or request bytes on this path.

    `routeIsCaptured` and `wrapped` are narrow Rust adapter obligations: the
    native request must pass the exact captured route and encoder buffer to
    the channel. TLS handshake and OS delivery are deliberately not inferred.
-/
theorem admitted_route_uses_exact_encoded_bytes_and_flushed_channel
    {B W M X : Type}
    (bytes : provider_io.WireBytes B) (writerOps : provider_io.Writer W X)
    (ctx : Context) (stamp : manifest.AdmissionStamp)
    (issued : Issued ctx stamp)
    (output buffer : alloc.vec.Vec U8) (route : credential_use.Route)
    (fields : provider_wire.Fields) (secret : Slice U8)
    (body : Option (Slice U8)) (endpoint : provider_wire.Endpoint)
    (native : B) (writer : W) (metadata : M)
    (pending after : provider_io.Channel B W M X)
    (out : core.result.Result Unit X)
    (parts : W × provider_io.Request B × M)
    (routeIsCaptured : route = ctx.grant.route)
    (encoded : provider_wire.append output route fields secret body =
      Result.ok (.Ok endpoint, buffer))
    (wrapped : bytes.bytes native = Result.ok buffer)
    (created : provider_io.Channel.new bytes writerOps native writer metadata =
      Result.ok pending)
    (submitted : provider_io.Channel.submit bytes writerOps pending =
      Result.ok (out, after))
    (released : provider_io.Channel.into_parts bytes writerOps after =
      Result.ok (.Ok parts))
    (room : output.length +
      (http_wire.Proofs.RequestBytes (ChosenHead route fields) secret
        route.authentication body).length + 22 ≤ Usize.max) :
    (snapshot ctx stamp).accepted ∧
    endpoint = ChosenEndpoint ctx.grant.route ∧
    buffer.val = output.val ++
      http_wire.Proofs.RequestBytes
        (ChosenHead ctx.grant.route fields) secret
        ctx.grant.route.authentication body ∧
    ∃ written,
      writerOps.write_all writer buffer = Result.ok (.Ok (), written) ∧
      writerOps.flush written = Result.ok (.Ok (), after.writer) ∧
      after.metadata = metadata ∧
      parts = (after.writer, after.request, metadata) := by
  have accepted := issued_snapshot_is_accepted ctx stamp issued
  obtain ⟨endpointOrigin, exact, written, writeCall, flushed, metadataKept, partsOrigin⟩ :=
    encoded_channel_write_origin bytes writerOps output buffer route fields
      secret body endpoint native writer metadata pending after out parts
      encoded wrapped created submitted released room
  subst route
  exact ⟨accepted, endpointOrigin, exact, written, writeCall,
    flushed, metadataKept, partsOrigin⟩

/-- A *native observation*, not an Aeneas-extracted Rust value. Each entry
    denotes a credential-bearing attempt actually observed at the scoped
    native writer/sink. The payload is intentionally carried for external
    exact-byte review; `ProviderSend` itself does not contain those bytes. -/
structure NativeAttempt where
  phase : confinement.Proofs.Phase
  gate : confinement.Proofs.Gate
  auditAck : Bool
  payload : List U8

/-- This is the NR-3 **sink-closure** obligation, not a conclusion. For the
    selected startup/configuration, a compiler-linked callback and its native
    effects must produce an event in the source-owned history for *every*
    credential-bearing attempt. Merely assuming `SoundTrace` cannot prove it.
    Storing this relation separately avoids disguising the hardest remaining
    reachability question as a Lean result. -/
def AllNativeAttemptsAccounted (native : List NativeAttempt)
    (events : List Event) : Prop :=
  ∀ attempt, attempt ∈ native →
    Event.providerSend attempt.phase attempt.gate attempt.auditAck ∈ events

/-- A covered native write is authorized, audit-acknowledged and has the exact
    captured identity/operation/destination binding. `AllNativeAttemptsAccounted`
    must still be discharged over the real transitive Rust call graph. -/
theorem accounted_native_attempts_have_current_bound_audit
    (native : List NativeAttempt) (events : List Event)
    (binding : Binding) (sound : SoundTrace events)
    (bound : BoundTrace binding events)
    (covered : AllNativeAttemptsAccounted native events) :
    ∀ attempt, attempt ∈ native →
      attempt.gate.accepted ∧ attempt.auditAck = true ∧
        gateBinding attempt.gate = binding := by
  intro attempt membership
  have event := covered attempt membership
  have authorization : attempt.gate.accepted ∧ attempt.auditAck = true :=
    sound _ event
  exact ⟨authorization.1, authorization.2,
    bound attempt.phase attempt.gate attempt.auditAck event⟩

/-- The acceptance of a high-level `write_all` does not imply delivery;
    its *existence* and request bytes can nevertheless be tied to the issued
    source stamp without trusting a provider-arrival bit. This is the read
    branch that NR-3 must connect to `ManifestProvider::send`. -/
theorem source_checked_read_has_native_callback_schedule
    {W C B V M X O : Type}
    (work : dispatch.Work W (provider_io.Channel B V M X) O X)
    (checks : current_admission.Checks C X)
    (bytes : provider_io.WireBytes B) (writer : provider_io.Writer V X)
    (start finish : dispatch.Pending
      (current_admission.Bound W C (provider_io.Channel B V M X) O X)
      (provider_io.Channel B V M X) O X)
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (reachable : request_effects.Proofs.Reachable start.effects)
    (returned : provider_exchange.exchange
      (dispatch.Pending.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider
        (current_admission.Bound.Insts.Aivm_secrets_garrett_coreDispatchWork
          work checks)) start ⟨phase, false⟩ = Result.ok (report, finish))
    (attempted : provider_exchange.Stage.attempted report.stage = Result.ok true)
    (constructed : native_dispatch.ReadBoundary.SetupReturnsConstructed
      work checks bytes writer)
    (linked : native_dispatch.ReadBoundary.SendsThroughChannel
      work checks bytes writer) :
    ∃ events,
      TraceSteps (fun _ => current_admission.Proofs.view start.work.context)
        start.effects finish.effects events ∧
      SoundTrace events ∧
      BoundTrace (current_admission.Proofs.view start.work.context).binding events ∧
      ∃ stamp, manifest.current
        (current_admission.Proofs.view start.work.context).claims
        (current_admission.Proofs.view start.work.context).grant
        (current_admission.Proofs.view start.work.context).requested
        (current_admission.Proofs.view start.work.context).selected
        (current_admission.Proofs.view start.work.context).write
        (current_admission.Proofs.view start.work.context).allowed
        stamp.now stamp.elapsed = Result.ok (.Ok stamp) := by
  have fresh := native_dispatch.ReadBoundary.constructed_setup_implies_fresh
    work checks bytes writer constructed
  obtain ⟨events, trace, sound, bound, _, stamp, before, after, channel,
    next, result, calls, _, issued, _, _, observed, projected, spent⟩ :=
    native_dispatch.ReadBoundary.returned_attempted_read_has_checked_writer
      work checks bytes writer start finish phase report reachable returned
      attempted fresh linked
  exact ⟨events, trace, sound, bound, stamp, issued⟩

end aivm_secrets_garrett_core.nr23.Effects
