import GarrettNR23WriterOrigin
import GarrettProviderExchange

/-!
# The provider channel lifecycle is core-owned

Source: `rust/crates/aivm-secrets-garrett-core/src/channel_work.rs`, extracted
by Aeneas. Production dispatch wraps the native `ManifestProvider` in
`channel_work::Submitting`, which holds the credential: the native provider has
no credential field. The core asks native code only for the host request
fields, encodes them with the extracted `channel_work::encode` (over
`provider_wire::append`) for the captured route, hands the encoded bytes to a
native zeroizing wrapper, connects to the encoder's endpoint, builds the
channel, sends with `Channel::submit` and mints the response-gate token before
the native parser runs. The target credential-reflection check also runs in
core (`selected_release::checked`).

* `setup_route_constructs`, `sent_bytes_are_setup_body`: the bytes handed to
  the native writer are the wrapped encoder output for this route.
* `sent_bytes_are_encoder_output`: under the two-line wrapper contract
  `WrapPreserves` (`ManifestWire` returns the vector it stores), the writer
  receives exactly the extracted encoder's output.
* `exchange_send_writes_route_body`: every read exchange reaching the send
  stage satisfies the above for its own captured route and credential.

Still native and trusted (`NATIVE-SINK-01`, `NATIVE-GLUE-01`): `request_fields`,
`wrap_body`, `connect` (TCP/TLS), `parse` (receives only the released token),
the writer's I/O, and that no other native code writes credential bytes.
-/

open Aeneas Aeneas.Std
namespace aivm_secrets_garrett_core.channel_work.Proofs
open aivm_secrets_garrett_core.provider_io.NativeWriterEvents

private theorem bind_returns_iff {A B : Type} (first : Result A)
    (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔
      ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

variable {W B PW M O X : Type} (cw : ChannelWork W B PW M O X)

abbrev submittingProvider :=
  Submitting.Insts.Aivm_secrets_garrett_coreProvider_exchangeProviderChannelClause0_OutputClause0_Error cw
abbrev submittingRoutes :=
  Submitting.Insts.Aivm_secrets_garrett_coreProvider_ioRouteWorkChannelClause0_Error cw

/-- The core-owned send is exactly the extracted `Channel::submit`. -/
theorem send_is_submit (s : Submitting W B PW M O X) (ch : provider_io.Channel B PW M X) :
    (submittingProvider cw).send s ch =
      (do let (r, ch₁) ← provider_io.Channel.submit cw.provider_ioWireBytesInst
            cw.provider_ioWriterInst ch
          Result.ok (r, s, ch₁)) := rfl

/-- A returned routed setup asked the native work only for host request
    fields, encoded them with the credential using the extracted
    `channel_work::encode` (over `provider_wire::append`) for the captured
    route, handed the encoded bytes to the native wrapper, *then* connected to
    the encoder's endpoint, and built a fresh, unsent, not-ready channel. -/
theorem setup_route_constructs (s s' : Submitting W B PW M O X) (route : credential_use.Route)
    (ch : provider_io.Channel B PW M X)
    (returned : (submittingRoutes cw).setup_route s route = Result.ok (.Ok ch, s')) :
    ∃ parts t encoded endpoint body t1 writer md,
      cw.request_fields s.work = Result.ok (.Ok parts, t) ∧
      channel_work.encode (alloc.vec.Vec.new U8) route parts s.secret =
        Result.ok (.Ok endpoint, encoded) ∧
      cw.wrap_body t encoded = Result.ok (body, t1) ∧
      cw.connect t1 endpoint = Result.ok (.Ok (writer, md), s'.work) ∧
      ch = ⟨⟨body, false⟩, writer, md, false⟩ := by
  simp only [
    Submitting.Insts.Aivm_secrets_garrett_coreProvider_ioRouteWorkChannelClause0_Error.setup_route] at returned
  obtain ⟨⟨r, t⟩, hfields, returned⟩ := (bind_returns_iff _ _ _).mp returned
  cases r with
  | Err e => simp at returned
  | Ok parts =>
    obtain ⟨⟨r1, encoded⟩, hencode, returned⟩ := (bind_returns_iff _ _ _).mp returned
    cases r1 with
    | Err d =>
      obtain ⟨⟨_, _⟩, _, returned⟩ := (bind_returns_iff _ _ _).mp returned
      simp at returned
    | Ok endpoint =>
      obtain ⟨⟨body, t1⟩, hwrap, returned⟩ := (bind_returns_iff _ _ _).mp returned
      obtain ⟨⟨r2, t2⟩, hconn, returned⟩ := (bind_returns_iff _ _ _).mp returned
      cases r2 with
      | Err e => simp at returned
      | Ok pair =>
        obtain ⟨writer, md⟩ := pair
        simp [provider_io.Channel.new, provider_io.Request.new] at returned
        obtain ⟨hch, hs⟩ := returned
        refine ⟨parts, t, encoded, endpoint, body, t1, writer, md, hfields, hencode, hwrap, ?_, hch.symm⟩
        rw [← hs]; exact hconn

/-- **Provider payload origin.** If the core-owned setup returned channel `ch`
    for `route` and the core-owned send then ran on `ch`, the native writer
    callback was invoked with exactly the bytes of the wrapped encoder output
    for that same route and this request's credential. This is the run-linked
    form of the former `PayloadCorresponds` premise. -/
theorem sent_bytes_are_setup_body (s s' s₂ s₃ : Submitting W B PW M O X)
    (route : credential_use.Route) (ch ch' : provider_io.Channel B PW M X)
    (out : core.result.Result Unit X)
    (setup : (submittingRoutes cw).setup_route s route = Result.ok (.Ok ch, s'))
    (sent : (submittingProvider cw).send s₂ ch = Result.ok (out, s₃, ch')) :
    ∃ parts t encoded endpoint body t1 calls wire,
      cw.request_fields s.work = Result.ok (.Ok parts, t) ∧
      channel_work.encode (alloc.vec.Vec.new U8) route parts s.secret =
        Result.ok (.Ok endpoint, encoded) ∧
      cw.wrap_body t encoded = Result.ok (body, t1) ∧
      ch.request.body = body ∧ ch.request.attempted = false ∧
      cw.provider_ioWireBytesInst.bytes body = Result.ok wire ∧
      Call.write wire ∈ calls ∧
      Observed cw.provider_ioWireBytesInst cw.provider_ioWriterInst ch.request ch.writer out
        ch'.request ch'.writer calls := by
  obtain ⟨parts, t, encoded, endpoint, body, t1, writer, md, hf, he, hw, _, rfl⟩ :=
    setup_route_constructs cw s s' route ch setup
  rw [send_is_submit] at sent
  obtain ⟨⟨r, ch₁⟩, submitted, sent⟩ := (bind_returns_iff _ _ _).mp sent
  simp at sent
  obtain ⟨rfl, -, rfl⟩ := sent
  obtain ⟨calls, wire, seen, hwire, hcall, -, -, -⟩ :=
    nr23.WriterOrigin.fresh_returned_channel_exposes_exact_writer_bytes
      cw.provider_ioWireBytesInst cw.provider_ioWriterInst _ ch₁ r rfl submitted
  exact ⟨parts, t, encoded, endpoint, body, t1, calls, wire, hf, he, hw, rfl, rfl, hwire, hcall, seen⟩

/-- The native wrapper contract (`NATIVE-GLUE-01`): the wrapped body's bytes
    are exactly the encoded bytes it was given. Production: `ManifestWire`
    stores the vector and `WireBytes::bytes` returns it. -/
def WrapPreserves : Prop :=
  ∀ s encoded body s', cw.wrap_body s encoded = Result.ok (body, s') →
    cw.provider_ioWireBytesInst.bytes body = Result.ok encoded

/-- Under the two-line wrapper contract, the bytes handed to the native writer
    are exactly the extracted encoder's output for the captured route, host
    fields and this request's credential. Properties of that output (the
    credential appears only in the authentication header) are the existing
    `provider_wire`/`http_wire` theorems. -/
theorem sent_bytes_are_encoder_output (wrap : WrapPreserves cw)
    (s s' s₂ s₃ : Submitting W B PW M O X)
    (route : credential_use.Route) (ch ch' : provider_io.Channel B PW M X)
    (out : core.result.Result Unit X)
    (setup : (submittingRoutes cw).setup_route s route = Result.ok (.Ok ch, s'))
    (sent : (submittingProvider cw).send s₂ ch = Result.ok (out, s₃, ch')) :
    ∃ parts endpoint encoded calls,
      channel_work.encode (alloc.vec.Vec.new U8) route parts s.secret =
        Result.ok (.Ok endpoint, encoded) ∧
      Call.write encoded ∈ calls ∧
      Observed cw.provider_ioWireBytesInst cw.provider_ioWriterInst ch.request ch.writer out
        ch'.request ch'.writer calls := by
  obtain ⟨parts, _, encoded, endpoint, body, _, calls, wire, _, he, hw, _, _, hwire, hcall, seen⟩ :=
    sent_bytes_are_setup_body cw s s' s₂ s₃ route ch ch' out setup sent
  have same : wire = encoded := by
    have := wrap _ _ _ _ hw
    rw [this] at hwire
    exact (Result.ok_injective hwire).symm
  subst same
  exact ⟨parts, endpoint, wire, calls, he, hcall, seen⟩

abbrev submittingDispatch :=
  Submitting.Insts.Aivm_secrets_garrett_coreDispatchWorkChannelClause0_OutputClause0_Error cw

/-- The production provider: `Routed` over the core-owned `Submitting` work. -/
abbrev routedProvider :=
  provider_io.Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider
    (submittingDispatch cw) (submittingRoutes cw)

theorem routed_send_is_submit (p : provider_io.Routed (Submitting W B PW M O X)
      (provider_io.Channel B PW M X) O X)
    (ch ch' : provider_io.Channel B PW M X) (out : core.result.Result Unit X)
    (p' : provider_io.Routed (Submitting W B PW M O X) (provider_io.Channel B PW M X) O X)
    (sent : (routedProvider cw).send p ch = Result.ok (out, p', ch')) :
    ∃ s', (submittingProvider cw).send p.work ch = Result.ok (out, s', ch') := by
  simp only [
    provider_io.Routed.Insts.Aivm_secrets_garrett_coreProvider_exchangeProvider.send] at sent
  obtain ⟨⟨r, s, c⟩, hs, rest⟩ := (bind_returns_iff _ _ _).mp sent
  simp at rest
  obtain ⟨rfl, -, rfl⟩ := rest
  exact ⟨s, hs⟩

/-- **Every production exchange that reaches the send stage wrote exactly its
    own route's encoded request.** For a read exchange over the routed
    core-owned provider that refused at send, refused at response, or
    completed, the native writer was called with the bytes of the wrapped
    output of the extracted encoder for the exchange's captured route and its
    own credential, on a fresh channel holding that body. -/
theorem exchange_send_writes_route_body
    (p after : provider_io.Routed (Submitting W B PW M O X) (provider_io.Channel B PW M X) O X)
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (run : provider_exchange.Proofs.ReadRun (routedProvider cw) p phase report after)
    (reached : report.stage = .Send ∨ report.stage = .Response ∨ report.stage = .Complete) :
    ∃ (channel : provider_io.Channel B PW M X) (parts : RequestParts) (t : W)
      (encoded : alloc.vec.Vec U8) (endpoint : provider_wire.Endpoint) (body : B) (t1 : W)
      (calls : List Call) (wire : alloc.vec.Vec U8) (out : core.result.Result Unit X)
      (ch' : provider_io.Channel B PW M X),
      cw.request_fields p.work.work = Result.ok (.Ok parts, t) ∧
      channel_work.encode (alloc.vec.Vec.new U8) p.route parts p.work.secret =
        Result.ok (.Ok endpoint, encoded) ∧
      cw.wrap_body t encoded = Result.ok (body, t1) ∧
      channel.request.body = body ∧ channel.request.attempted = false ∧
      cw.provider_ioWireBytesInst.bytes body = Result.ok wire ∧
      Call.write wire ∈ calls ∧
      Observed cw.provider_ioWireBytesInst cw.provider_ioWriterInst channel.request channel.writer out
        ch'.request ch'.writer calls := by
  have from_setup_send : ∀ (channel next : provider_io.Channel B PW M X)
      (s1 s2 s3 : provider_io.Routed (Submitting W B PW M O X) (provider_io.Channel B PW M X) O X)
      (out : core.result.Result Unit X),
      (routedProvider cw).setup p = Result.ok (.Ok channel, s1) →
      (routedProvider cw).send s2 channel = Result.ok (out, s3, next) →
      ∃ (channel : provider_io.Channel B PW M X) (parts : RequestParts) (t : W)
        (encoded : alloc.vec.Vec U8) (endpoint : provider_wire.Endpoint) (body : B) (t1 : W)
        (calls : List Call) (wire : alloc.vec.Vec U8) (out : core.result.Result Unit X)
        (ch' : provider_io.Channel B PW M X),
        cw.request_fields p.work.work = Result.ok (.Ok parts, t) ∧
        channel_work.encode (alloc.vec.Vec.new U8) p.route parts p.work.secret =
          Result.ok (.Ok endpoint, encoded) ∧
        cw.wrap_body t encoded = Result.ok (body, t1) ∧
        channel.request.body = body ∧ channel.request.attempted = false ∧
        cw.provider_ioWireBytesInst.bytes body = Result.ok wire ∧
        Call.write wire ∈ calls ∧
        Observed cw.provider_ioWireBytesInst cw.provider_ioWriterInst channel.request channel.writer out
          ch'.request ch'.writer calls := by
    intro channel next s1 s2 s3 out setup sent
    obtain ⟨native, routed, _⟩ := (provider_io.Proofs.routed_setup_iff (submittingDispatch cw)
      (submittingRoutes cw) p s1 (.Ok channel)).mp setup
    obtain ⟨s', hs⟩ := routed_send_is_submit cw s2 channel next out s3 sent
    obtain ⟨parts, t, encoded, endpoint, body, t1, calls, wire, hf, he, hw, hb, ha, hwire, hcall, seen⟩ :=
      sent_bytes_are_setup_body cw p.work native s2.work s' p.route channel next out routed hs
    exact ⟨channel, parts, t, encoded, endpoint, body, t1, calls, wire, out, next,
      hf, he, hw, hb, ha, hwire, hcall, seen⟩
  cases run with
  | setupDenied => simp [provider_exchange.Proofs.receipt] at reached
  | admissionDenied => simp [provider_exchange.Proofs.receipt] at reached
  | sendDenied channel next stamp s1 s2 _ error setup _ sent => exact from_setup_send _ _ _ _ _ _ setup sent
  | responseDenied channel next stamp s1 s2 s3 _ error setup _ sent _ => exact from_setup_send _ _ _ _ _ _ setup sent
  | complete channel next stamp s1 s2 s3 _ value setup _ sent _ => exact from_setup_send _ _ _ _ _ _ setup sent

end aivm_secrets_garrett_core.channel_work.Proofs
