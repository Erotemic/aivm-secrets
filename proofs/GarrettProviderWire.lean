import GarrettHttpWire
import GarrettProviderChannel

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

/-! Actual route-to-wire/endpoint producer. Native conversion, faithful
zeroizing buffer view, std/TLS/DNS and parser semantics remain contracts. -/
namespace aivm_secrets_garrett_core.provider_wire.Proofs

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

private theorem bytes_clone_exact (bytes : alloc.vec.Vec U8) :
    alloc.vec.CloneVec.clone core.clone.CloneU8 bytes = Result.ok bytes := by
  unfold alloc.vec.CloneVec.clone
  obtain ⟨copied, returned, property⟩ := returned_of_spec
    (Slice.clone_spec (s := bytes.slice) (clone := core.clone.CloneU8.clone) (by intro x hx; rfl))
  rw [returned]
  simp only [bind_tc_ok, ← property]

def PortGood (route : credential_use.Route) : Prop := 0 < route.port.val ∧ route.port.val ≤ 65535

def ChosenHead (route : credential_use.Route) (fields : Fields) : http_wire.Head :=
  ⟨fields.method, fields.target, route.host, IScalar.hcast .U16 route.port, fields.accept, fields.headers⟩

def ChosenEndpoint (route : credential_use.Route) : Endpoint :=
  ⟨route.host, IScalar.hcast .U16 route.port⟩

theorem endpoint_host (endpoint : Endpoint) : Endpoint.impl.host endpoint = Result.ok endpoint.host := rfl

theorem endpoint_port (endpoint : Endpoint) : Endpoint.impl.port endpoint = Result.ok endpoint.port := rfl

theorem port_cast_exact (route : credential_use.Route) (valid : PortGood route) :
    ((IScalar.hcast .U16 route.port).val : Int) = route.port.val := by
  have exact := IScalar.hcast_inBounds_spec .U16 route.port (by dsimp [PortGood] at valid; scalar_tac)
  simpa only [lift, WP.spec_ok] using exact

theorem head_refuses_invalid_port (route : credential_use.Route) (fields : Fields)
    (invalid : ¬PortGood route) : head route fields = Result.ok (.Err .InvalidRequest) := by
  by_cases low : route.port <= 0#i64
  · simp [head, low]
  · have high : route.port > 65535#i64 := by dsimp [PortGood] at invalid; scalar_tac
    simp [head, low, high]

theorem head_exact (route : credential_use.Route) (fields : Fields) (valid : PortGood route) :
    head route fields = Result.ok (.Ok (ChosenHead route fields)) := by
  have low : ¬route.port <= 0#i64 := by dsimp [PortGood] at valid; scalar_tac
  have high : ¬route.port > 65535#i64 := by dsimp [PortGood] at valid; scalar_tac
  simp [head, low, high, bytes_clone_exact, ChosenHead, lift]

theorem head_success_iff (route : credential_use.Route) (fields : Fields) (chosen : http_wire.Head) :
    head route fields = Result.ok (.Ok chosen) ↔ PortGood route ∧ chosen = ChosenHead route fields := by
  constructor
  · intro returned
    by_cases valid : PortGood route
    · rw [head_exact route fields valid] at returned
      exact ⟨valid, by simpa using returned.symm⟩
    · rw [head_refuses_invalid_port route fields valid] at returned
      simp at returned
  · rintro ⟨valid, rfl⟩
    exact head_exact route fields valid

/-- Actual head/credential/authentication/body argument forwarding and exact
post-buffer, including endpoint fields selected after encoder success. -/
theorem append_success_iff (output buffer : alloc.vec.Vec U8) (route : credential_use.Route)
    (fields : Fields) (secret : Slice U8) (body : Option (Slice U8)) (endpoint : Endpoint) :
    append output route fields secret body = Result.ok (.Ok endpoint, buffer) ↔
      PortGood route ∧ endpoint = ChosenEndpoint route ∧
        http_wire.append_request output (ChosenHead route fields) secret route.authentication body = Result.ok (.Ok (), buffer) := by
  constructor
  · intro returned
    unfold append at returned
    obtain ⟨selected, made, rest⟩ := (bind_returns_iff _ _ _).mp returned
    cases selected with
    | Err error => simp at rest
    | Ok chosen =>
      obtain ⟨valid, rfl⟩ := (head_success_iff route fields chosen).mp made
      obtain ⟨⟨encoded, after⟩, called, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases encoded with
      | Err error => simp at rest
      | Ok u =>
        cases u
        have pair : ((.Ok (ChosenEndpoint route) : core.result.Result Endpoint http_wire.EncodingDenial), after) = (.Ok endpoint, buffer) := by simpa [ChosenHead, ChosenEndpoint] using rest
        obtain ⟨same, rfl⟩ := Prod.mk.inj pair
        exact ⟨valid, by simpa using same.symm, called⟩
  · rintro ⟨valid, rfl, called⟩
    unfold append
    rw [head_exact route fields valid]
    simp only [bind_ok]
    rw [called]
    simp [ChosenHead, ChosenEndpoint]

theorem invalid_port_preserves_buffer (output : alloc.vec.Vec U8) (route : credential_use.Route)
    (fields : Fields) (secret : Slice U8) (body : Option (Slice U8)) (invalid : ¬PortGood route) :
    append output route fields secret body = Result.ok (.Err .InvalidRequest, output) := by
  simp [append, head_refuses_invalid_port route fields invalid]

theorem successful_endpoint_origin (output buffer : alloc.vec.Vec U8) (route : credential_use.Route)
    (fields : Fields) (secret : Slice U8) (body : Option (Slice U8)) (endpoint : Endpoint)
    (returned : append output route fields secret body = Result.ok (.Ok endpoint, buffer)) :
    PortGood route ∧ endpoint.host = route.host ∧ (endpoint.port.val : Int) = route.port.val ∧
      http_wire.Proofs.Admitted (ChosenHead route fields) secret body := by
  obtain ⟨valid, rfl, called⟩ := (append_success_iff output buffer route fields secret body endpoint).mp returned
  exact ⟨valid, rfl, port_cast_exact route valid,
    http_wire.Proofs.successful_request_requires_admission output buffer _ secret route.authentication body called⟩

/-- Exact complete bytes and an endpoint on actual successful execution, under
the same explicit finite-buffer bound as the existing complete encoder leaf. -/
theorem accepted_route_exact (output : alloc.vec.Vec U8) (route : credential_use.Route)
    (fields : Fields) (secret : Slice U8) (body : Option (Slice U8)) (valid : PortGood route)
    (admitted : http_wire.Proofs.Admitted (ChosenHead route fields) secret body)
    (room : output.length + (http_wire.Proofs.RequestBytes (ChosenHead route fields) secret route.authentication body).length + 22 ≤ Usize.max) :
    append output route fields secret body ⦃ out => out.1 = .Ok (ChosenEndpoint route) ∧
      out.2.val = output.val ++ http_wire.Proofs.RequestBytes (ChosenHead route fields) secret route.authentication body ⦄ := by
  unfold append
  rw [head_exact route fields valid]
  simp only [bind_ok]
  apply WP.spec_bind (http_wire.Proofs.accepted_request_exact output _ secret route.authentication body admitted room)
  intro pair property
  rcases pair with ⟨result, buffer⟩
  obtain ⟨rfl, wire⟩ := property
  apply (WP.spec_ok _).mpr
  exact ⟨rfl, wire⟩

theorem returned_route_bytes (output buffer : alloc.vec.Vec U8) (route : credential_use.Route)
    (fields : Fields) (secret : Slice U8) (body : Option (Slice U8)) (endpoint : Endpoint)
    (returned : append output route fields secret body = Result.ok (.Ok endpoint, buffer))
    (room : output.length + (http_wire.Proofs.RequestBytes (ChosenHead route fields) secret route.authentication body).length + 22 ≤ Usize.max) :
    endpoint = ChosenEndpoint route ∧ buffer.val = output.val ++
      http_wire.Proofs.RequestBytes (ChosenHead route fields) secret route.authentication body := by
  obtain ⟨valid, _, _, admitted⟩ := successful_endpoint_origin output buffer route fields secret body endpoint returned
  have exact := accepted_route_exact output route fields secret body valid admitted room
  rw [returned] at exact
  simp only [WP.spec_ok] at exact
  exact ⟨by simpa using exact.1, exact.2⟩

/-- The actual constructor/encoder/channel/release facts imply a write of the
encoded bytes, successful flush on its real post-state and the route endpoint.
Only the local native buffer view is supplied, not a callback-wide history. -/
theorem encoded_channel_write_origin {B W M X : Type} (bytes : provider_io.WireBytes B)
    (ops : provider_io.Writer W X) (output buffer : alloc.vec.Vec U8) (route : credential_use.Route)
    (fields : Fields) (secret : Slice U8) (body : Option (Slice U8)) (endpoint : Endpoint)
    (native : B) (writer : W) (metadata : M) (pending after : provider_io.Channel B W M X)
    (out : core.result.Result Unit X) (parts : W × provider_io.Request B × M)
    (encoded : append output route fields secret body = Result.ok (.Ok endpoint, buffer))
    (wrapped : bytes.bytes native = Result.ok buffer)
    (created : provider_io.Channel.new bytes ops native writer metadata = Result.ok pending)
    (submitted : provider_io.Channel.submit bytes ops pending = Result.ok (out, after))
    (released : provider_io.Channel.into_parts bytes ops after = Result.ok (.Ok parts))
    (room : output.length + (http_wire.Proofs.RequestBytes (ChosenHead route fields) secret route.authentication body).length + 22 ≤ Usize.max) :
    endpoint = ChosenEndpoint route ∧ buffer.val = output.val ++
      http_wire.Proofs.RequestBytes (ChosenHead route fields) secret route.authentication body ∧
      ∃ written, ops.write_all writer buffer = Result.ok (.Ok (), written) ∧
        ops.flush written = Result.ok (.Ok (), after.writer) ∧ after.metadata = metadata ∧
        parts = (after.writer, after.request, metadata) := by
  have initial : pending = ⟨⟨native, false⟩, writer, metadata, false⟩ := by
    simpa [provider_io.Channel.new, provider_io.Request.new] using created.symm
  subst pending
  obtain ⟨_, _, _, kept, same, wire, written, viewed, writeCall, flushCall⟩ :=
    provider_io.ChannelProofs.released_parts_require_exact_flushed_bytes bytes ops _ after out parts submitted released
  have equal : wire = buffer := by simpa [wrapped] using viewed.symm
  subst wire
  obtain ⟨endpoint, exact⟩ := returned_route_bytes output buffer route fields secret body endpoint encoded room
  exact ⟨endpoint, exact, written, writeCall, flushCall, kept, by simpa [kept] using same⟩

end aivm_secrets_garrett_core.provider_wire.Proofs
