import GarrettNR23WriterOrigin
import GarrettProviderExchange

/-!
# The provider channel lifecycle is core-owned

Source: `rust/crates/aivm-secrets-garrett-core/src/channel_work.rs`, extracted
by Aeneas. Production dispatch wraps the native `ManifestProvider` in
`channel_work::Submitting`, so the core builds the provider channel (encode the
request for the captured route, then connect), sends with `Channel::submit`,
and mints the response-gate token before the native parser runs.

`exchange_send_writes_route_body`: in every read exchange over the routed
production provider that reached the send stage (refused at send, refused at
response, or completed), the native writer callback was called with exactly the
encoded bytes of the request body produced for that exchange's own captured
route, on a fresh channel holding that body. This is the run-linked form of the
former `PayloadCorresponds` premise, which took the channel as an arbitrary
input.

Still native and trusted: `request_body` (a wrapper over the extracted
`provider_wire::append`, whose output is proved elsewhere), `connect` (TCP/TLS),
`parse` (receives only the released token), and the writer's I/O. That native
code makes no *other* credential-bearing write remains the narrowed
`ExactNativeSinkCoverage` premise, checked by the W3/W6 source guards.
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

/-- A returned routed setup built the channel from this route's encoded
    request body, *then* connected, and nothing else: a fresh, unsent,
    not-ready channel owning exactly that body. -/
theorem setup_route_constructs (s s' : Submitting W B PW M O X) (route : credential_use.Route)
    (ch : provider_io.Channel B PW M X)
    (returned : (submittingRoutes cw).setup_route s route = Result.ok (.Ok ch, s')) :
    ∃ body t writer md,
      cw.request_body s.work route = Result.ok (.Ok body, t) ∧
      cw.connect t route = Result.ok (.Ok (writer, md), s'.work) ∧
      ch = ⟨⟨body, false⟩, writer, md, false⟩ := by
  simp only [
    Submitting.Insts.Aivm_secrets_garrett_coreProvider_ioRouteWorkChannelClause0_Error.setup_route] at returned
  obtain ⟨⟨r, t⟩, hbody, returned⟩ := (bind_returns_iff _ _ _).mp returned
  cases r with
  | Err e => simp at returned
  | Ok body =>
    obtain ⟨⟨r1, t1⟩, hconn, returned⟩ := (bind_returns_iff _ _ _).mp returned
    cases r1 with
    | Err e => simp at returned
    | Ok parts =>
      obtain ⟨writer, md⟩ := parts
      simp [provider_io.Channel.new, provider_io.Request.new] at returned
      obtain ⟨hch, hs⟩ := returned
      refine ⟨body, t, writer, md, hbody, ?_, hch.symm⟩
      rw [← hs]; exact hconn

/-- **Provider payload origin.** If the core-owned setup returned channel `ch`
    for `route` and the core-owned send then ran on `ch`, the native writer
    callback was invoked with exactly the bytes of the request body that
    `request_body` produced for that same route (before `connect`). This is
    the run-linked form of the former `PayloadCorresponds` premise. -/
theorem sent_bytes_are_setup_body (s s' s₂ s₃ : Submitting W B PW M O X)
    (route : credential_use.Route) (ch ch' : provider_io.Channel B PW M X)
    (out : core.result.Result Unit X)
    (setup : (submittingRoutes cw).setup_route s route = Result.ok (.Ok ch, s'))
    (sent : (submittingProvider cw).send s₂ ch = Result.ok (out, s₃, ch')) :
    ∃ body t calls wire,
      cw.request_body s.work route = Result.ok (.Ok body, t) ∧
      ch.request.body = body ∧ ch.request.attempted = false ∧
      cw.provider_ioWireBytesInst.bytes body = Result.ok wire ∧
      Call.write wire ∈ calls ∧
      Observed cw.provider_ioWireBytesInst cw.provider_ioWriterInst ch.request ch.writer out
        ch'.request ch'.writer calls := by
  obtain ⟨body, t, writer, md, hbody, _, rfl⟩ := setup_route_constructs cw s s' route ch setup
  rw [send_is_submit] at sent
  obtain ⟨⟨r, ch₁⟩, submitted, sent⟩ := (bind_returns_iff _ _ _).mp sent
  simp at sent
  obtain ⟨rfl, -, rfl⟩ := sent
  obtain ⟨calls, wire, seen, hwire, hcall, -, -, -⟩ :=
    nr23.WriterOrigin.fresh_returned_channel_exposes_exact_writer_bytes
      cw.provider_ioWireBytesInst cw.provider_ioWriterInst _ ch₁ r rfl submitted
  exact ⟨body, t, calls, wire, hbody, rfl, rfl, hwire, hcall, seen⟩

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
    completed, the native writer was called with the bytes of the body that
    `request_body` produced for the exchange's captured route. -/
theorem exchange_send_writes_route_body
    (p after : provider_io.Routed (Submitting W B PW M O X) (provider_io.Channel B PW M X) O X)
    (phase : read_transition.Phase) (report : provider_exchange.Report O X)
    (run : provider_exchange.Proofs.ReadRun (routedProvider cw) p phase report after)
    (reached : report.stage = .Send ∨ report.stage = .Response ∨ report.stage = .Complete) :
    ∃ (channel : provider_io.Channel B PW M X) (body : B) (t : W) (calls : List Call)
      (wire : alloc.vec.Vec U8) (out : core.result.Result Unit X) (ch' : provider_io.Channel B PW M X),
      cw.request_body p.work.work p.route = Result.ok (.Ok body, t) ∧
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
      ∃ (channel : provider_io.Channel B PW M X) (body : B) (t : W) (calls : List Call)
        (wire : alloc.vec.Vec U8) (out : core.result.Result Unit X) (ch' : provider_io.Channel B PW M X),
        cw.request_body p.work.work p.route = Result.ok (.Ok body, t) ∧
        channel.request.body = body ∧ channel.request.attempted = false ∧
        cw.provider_ioWireBytesInst.bytes body = Result.ok wire ∧
        Call.write wire ∈ calls ∧
        Observed cw.provider_ioWireBytesInst cw.provider_ioWriterInst channel.request channel.writer out
          ch'.request ch'.writer calls := by
    intro channel next s1 s2 s3 out setup sent
    obtain ⟨native, routed, _⟩ := (provider_io.Proofs.routed_setup_iff (submittingDispatch cw)
      (submittingRoutes cw) p s1 (.Ok channel)).mp setup
    obtain ⟨s', hs⟩ := routed_send_is_submit cw s2 channel next out s3 sent
    obtain ⟨body, t, calls, wire, hbody, hb, ha, hwire, hcall, seen⟩ :=
      sent_bytes_are_setup_body cw p.work native s2.work s' p.route channel next out routed hs
    exact ⟨channel, body, t, calls, wire, out, next, hbody, hb, ha, hwire, hcall, seen⟩
  cases run with
  | setupDenied => simp [provider_exchange.Proofs.receipt] at reached
  | admissionDenied => simp [provider_exchange.Proofs.receipt] at reached
  | sendDenied channel next stamp s1 s2 _ error setup _ sent => exact from_setup_send _ _ _ _ _ _ setup sent
  | responseDenied channel next stamp s1 s2 s3 _ error setup _ sent _ => exact from_setup_send _ _ _ _ _ _ setup sent
  | complete channel next stamp s1 s2 s3 _ value setup _ sent _ => exact from_setup_send _ _ _ _ _ _ setup sent

end aivm_secrets_garrett_core.channel_work.Proofs
