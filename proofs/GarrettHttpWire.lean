import GarrettHttpWireValidation

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.http_auth.Proofs
open aivm_secrets_garrett_core.http_request.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.http_wire.Proofs

def VersionBytes : List U8 := [
  32#u8, 72#u8, 84#u8, 84#u8, 80#u8, 47#u8, 49#u8, 46#u8, 49#u8, 13#u8, 10#u8
]

def HostPrefix : List U8 := [
  72#u8, 111#u8, 115#u8, 116#u8, 58#u8, 32#u8
]

def AcceptPrefix : List U8 := [
  13#u8, 10#u8, 65#u8, 99#u8, 99#u8, 101#u8, 112#u8, 116#u8, 58#u8, 32#u8
]

def FixedHeaders : List U8 := [
  13#u8, 10#u8, 65#u8, 99#u8, 99#u8, 101#u8, 112#u8, 116#u8, 45#u8, 69#u8, 110#u8, 99#u8,
  111#u8, 100#u8, 105#u8, 110#u8, 103#u8, 58#u8, 32#u8, 105#u8, 100#u8, 101#u8, 110#u8, 116#u8,
  105#u8, 116#u8, 121#u8, 13#u8, 10#u8, 85#u8, 115#u8, 101#u8, 114#u8, 45#u8, 65#u8, 103#u8,
  101#u8, 110#u8, 116#u8, 58#u8, 32#u8, 97#u8, 105#u8, 118#u8, 109#u8, 45#u8, 115#u8, 101#u8,
  99#u8, 114#u8, 101#u8, 116#u8, 115#u8, 47#u8, 49#u8, 13#u8, 10#u8, 67#u8, 111#u8, 110#u8,
  110#u8, 101#u8, 99#u8, 116#u8, 105#u8, 111#u8, 110#u8, 58#u8, 32#u8, 99#u8, 108#u8, 111#u8,
  115#u8, 101#u8, 13#u8, 10#u8
]

def JsonLengthPrefix : List U8 := [
  67#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8, 84#u8, 121#u8, 112#u8, 101#u8,
  58#u8, 32#u8, 97#u8, 112#u8, 112#u8, 108#u8, 105#u8, 99#u8, 97#u8, 116#u8, 105#u8, 111#u8,
  110#u8, 47#u8, 106#u8, 115#u8, 111#u8, 110#u8, 13#u8, 10#u8, 67#u8, 111#u8, 110#u8, 116#u8,
  101#u8, 110#u8, 116#u8, 45#u8, 76#u8, 101#u8, 110#u8, 103#u8, 116#u8, 104#u8, 58#u8, 32#u8
]

def StartBytes (head : Head) : List U8 :=
  head.method.val ++ [32#u8] ++ head.target.val ++ VersionBytes ++
    HostPrefix ++ head.host.val ++ [58#u8] ++ Digits head.port.val ++
    AcceptPrefix ++ head.accept.val ++ FixedHeaders

def BodyHeaderBytes : Option (Slice U8) → List U8
  | none => []
  | some bytes => JsonLengthPrefix ++ Digits bytes.length ++ [13#u8, 10#u8]

def BodyBytes : Option (Slice U8) → List U8
  | none => []
  | some bytes => bytes.val

def RequestBytes (head : Head) (secret : Slice U8)
    (authentication : credential_use.Authentication) (body : Option (Slice U8)) : List U8 :=
  StartBytes head ++ HeadersBytes head.headers.val ++
    HeaderPrefix authentication ++ secret.val ++ [13#u8, 10#u8] ++
    BodyHeaderBytes body ++ [13#u8, 10#u8] ++ BodyBytes body

/-- These equalities name actual executed validators, rather than an assumed
    security conclusion. Their checked soundness gives the public grammar. -/
def Admitted (head : Head) (secret : Slice U8) (body : Option (Slice U8)) : Prop :=
  valid_start head = Result.ok true ∧ http_auth.valid_credential secret = Result.ok true ∧
    valid_body body = Result.ok true ∧ valid_headers (alloc.vec.Vec.deref head.headers) = Result.ok true

theorem admitted_grammar (head : Head) (secret : Slice U8) (body : Option (Slice U8))
    (accepted : Admitted head secret body) :
    ValidStart head ∧ ValidCredential secret ∧
      (∀ bytes, body = some bytes → bytes.length ≤ 2097152) ∧
      ValidHeaders (alloc.vec.Vec.deref head.headers) := by
  have start := valid_start_sound head
  rw [accepted.1] at start
  have credential := valid_credential_contract secret
  rw [accepted.2.1] at credential
  have body_valid := valid_body_contract body
  rw [accepted.2.2.1] at body_valid
  have headers := valid_headers_sound (alloc.vec.Vec.deref head.headers)
  rw [accepted.2.2.2] at headers
  refine ⟨(WP.spec_ok _).mp start rfl, ((WP.spec_ok _).mp credential).mp rfl,
    ?_, (WP.spec_ok _).mp headers rfl⟩
  intro bytes present
  subst body
  exact ((WP.spec_ok _).mp body_valid).mp rfl

@[step]
theorem decimal_wire_contract (output : alloc.vec.Vec U8) (value : Usize)
    (room : output.length + (Digits value.val).length ≤ Usize.max) :
    append_decimal output value ⦃ out => out.val = output.val ++ Digits value.val ∧
      out.length = output.length + (Digits value.val).length ⦄ := by
  apply WP.spec_mono (append_decimal_exact output value room)
  intro out exact_bytes
  exact ⟨exact_bytes, by simp [alloc.vec.Vec.length, exact_bytes]⟩

@[step]
theorem line_wire_contract (output : alloc.vec.Vec U8) (method target : Slice U8)
    (method_valid : ValidMethod method) (target_valid : ValidTarget target)
    (room : output.length + method.length + target.length + 12 ≤ Usize.max) :
    http_request.append_line output method target ⦃ out =>
      out.1 = .Ok () ∧ out.2.val = output.val ++ method.val ++ [32#u8] ++
        target.val ++ VersionBytes ∧
      out.2.length = output.length + method.length + target.length + 12 ⦄ := by
  apply WP.spec_mono (accepted_line_exact output method target method_valid target_valid (by omega))
  intro out exact_bytes
  refine ⟨exact_bytes.1, ?_, ?_⟩
  · simpa [VersionBytes, LineSuffix, List.append_assoc] using exact_bytes.2
  · simp [alloc.vec.Vec.length, exact_bytes.2, LineSuffix]
    omega

@[step]
theorem authentication_wire_contract (output : alloc.vec.Vec U8) (secret : Slice U8)
    (authentication : credential_use.Authentication) (valid : ValidCredential secret)
    (room : output.length + 22 + secret.length + 2 ≤ Usize.max) :
    http_auth.append_header output secret authentication ⦃ out => out.1 = .Ok () ∧
      out.2.val = output.val ++ HeaderPrefix authentication ++ secret.val ++ [13#u8, 10#u8] ∧
      out.2.length = output.length + (HeaderPrefix authentication).length + secret.length + 2 ⦄ := by
  apply WP.spec_mono (accepted_header_exact output secret authentication valid room)
  intro out exact_bytes
  exact ⟨exact_bytes.1, exact_bytes.2, by simp [alloc.vec.Vec.length, exact_bytes.2]; omega⟩

theorem refused_start_preserves_buffer (output : alloc.vec.Vec U8) (head : Head)
    (secret : Slice U8) (authentication : credential_use.Authentication) (body : Option (Slice U8))
    (refused : valid_start head = Result.ok false) :
    append_request output head secret authentication body = Result.ok (.Err .InvalidRequest, output) := by
  simp [append_request, refused]

theorem refused_credential_preserves_buffer (output : alloc.vec.Vec U8) (head : Head)
    (secret : Slice U8) (authentication : credential_use.Authentication) (body : Option (Slice U8))
    (start : valid_start head = Result.ok true)
    (refused : http_auth.valid_credential secret = Result.ok false) :
    append_request output head secret authentication body = Result.ok (.Err .InvalidCredential, output) := by
  simp [append_request, start, refused]

theorem refused_body_preserves_buffer (output : alloc.vec.Vec U8) (head : Head)
    (secret : Slice U8) (authentication : credential_use.Authentication) (body : Option (Slice U8))
    (start : valid_start head = Result.ok true)
    (credential : http_auth.valid_credential secret = Result.ok true)
    (refused : valid_body body = Result.ok false) :
    append_request output head secret authentication body = Result.ok (.Err .InvalidRequest, output) := by
  simp [append_request, start, credential, refused]

theorem refused_headers_preserve_buffer (output : alloc.vec.Vec U8) (head : Head)
    (secret : Slice U8) (authentication : credential_use.Authentication) (body : Option (Slice U8))
    (start : valid_start head = Result.ok true)
    (credential : http_auth.valid_credential secret = Result.ok true)
    (body_checked : valid_body body = Result.ok true)
    (refused : valid_headers (alloc.vec.Vec.deref head.headers) = Result.ok false) :
    append_request output head secret authentication body = Result.ok (.Err .InvalidRequest, output) := by
  simp [append_request, start, credential, body_checked, refused]

theorem rejected_request_preserves_buffer (output : alloc.vec.Vec U8) (head : Head)
    (secret : Slice U8) (authentication : credential_use.Authentication) (body : Option (Slice U8))
    (refused : ¬Admitted head secret body) :
    ∃ denial, append_request output head secret authentication body = Result.ok (.Err denial, output) := by
  obtain ⟨start, start_run, _⟩ := returned_of_spec (valid_start_sound head)
  cases start with
  | false => exact ⟨.InvalidRequest, refused_start_preserves_buffer output head secret authentication body start_run⟩
  | true =>
    obtain ⟨credential, credential_run, _⟩ := returned_of_spec (valid_credential_contract secret)
    cases credential with
    | false => exact ⟨.InvalidCredential, refused_credential_preserves_buffer output head secret authentication body start_run credential_run⟩
    | true =>
      obtain ⟨body_valid, body_run, _⟩ := returned_of_spec (valid_body_contract body)
      cases body_valid with
      | false => exact ⟨.InvalidRequest, refused_body_preserves_buffer output head secret authentication body start_run credential_run body_run⟩
      | true =>
        obtain ⟨headers, headers_run, _⟩ := returned_of_spec
          (valid_headers_sound (alloc.vec.Vec.deref head.headers))
        cases headers with
        | false => exact ⟨.InvalidRequest, refused_headers_preserve_buffer output head secret authentication body start_run credential_run body_run headers_run⟩
        | true => exact False.elim (refused ⟨start_run, credential_run, body_run, headers_run⟩)

theorem successful_request_requires_admission (output result : alloc.vec.Vec U8) (head : Head)
    (secret : Slice U8) (authentication : credential_use.Authentication) (body : Option (Slice U8))
    (success : append_request output head secret authentication body = Result.ok (.Ok (), result)) :
    Admitted head secret body := by
  by_contra refused
  obtain ⟨denial, failed⟩ := rejected_request_preserves_buffer output head secret authentication body refused
  rw [failed] at success
  have impossible := congrArg Prod.fst (Result.ok_injective success)
  cases impossible

/-- The unchecked suffix after credential admission; this is a proof-side
    decomposition of the extracted byte appender, not another runtime writer. -/
def Finish (with_auth : alloc.vec.Vec U8) (body : Option (Slice U8)) :
    Result ((core.result.Result Unit EncodingDenial) × alloc.vec.Vec U8) := do
  let with_body_headers : alloc.vec.Vec U8 ← match body with
    | none => Result.ok with_auth
    | some bytes => do
      let x ← alloc.vec.Vec.extend_from_slice core.clone.CloneU8 with_auth
        (Array.make 48#usize JsonLengthPrefix (by rfl)).to_slice
      let y ← append_decimal x bytes.len
      alloc.vec.Vec.extend_from_slice core.clone.CloneU8 y
        (Array.make 2#usize [13#u8, 10#u8] (by rfl)).to_slice
  let with_separator ← alloc.vec.Vec.extend_from_slice core.clone.CloneU8 with_body_headers
    (Array.make 2#usize [13#u8, 10#u8] (by rfl)).to_slice
  match body with
    | none => Result.ok (.Ok (), with_separator)
    | some bytes => do
      let finished ← alloc.vec.Vec.extend_from_slice core.clone.CloneU8 with_separator bytes
      Result.ok (.Ok (), finished)

/-- Exact bytes of the production full-message appender. The small additional
    room accounts for the authentication leaf's worst-case prefix bound. -/
theorem accepted_request_exact (output : alloc.vec.Vec U8) (head : Head)
    (secret : Slice U8) (authentication : credential_use.Authentication) (body : Option (Slice U8))
    (accepted : Admitted head secret body)
    (room : output.length + (RequestBytes head secret authentication body).length + 22 ≤ Usize.max) :
    append_request output head secret authentication body ⦃ out => out.1 = .Ok () ∧
      out.2.val = output.val ++ RequestBytes head secret authentication body ⦄ := by
  have grammar := admitted_grammar head secret body accepted
  obtain ⟨host_valid, port_valid, accept_valid, method_valid, target_valid⟩ := grammar.1
  have credential_valid := grammar.2.1
  obtain ⟨start, credential, body_checked, headers⟩ := accepted
  have capacity := room
  simp only [RequestBytes, StartBytes, VersionBytes, HostPrefix, AcceptPrefix, FixedHeaders,
    List.length_append, List.length_cons, List.length_nil] at capacity
  obtain ⟨pair, line_run, line⟩ := returned_of_spec (line_wire_contract output
    (alloc.vec.Vec.deref head.method) (alloc.vec.Vec.deref head.target)
    method_valid target_valid (by scalar_tac))
  rcases pair with ⟨result, buffer⟩
  obtain ⟨ack, line_bytes, line_length⟩ := line
  dsimp only at ack line_bytes line_length
  subst result
  let host_prefix : Slice U8 := (Array.make 6#usize HostPrefix (by rfl)).to_slice
  obtain ⟨with_prefix, prefix_run, prefix_bytes⟩ := returned_of_spec
    (extend_bytes_contract buffer host_prefix (by
      simp only [host_prefix, Array.length_to_slice]; scalar_tac))
  obtain ⟨with_host, host_run, host_bytes⟩ := returned_of_spec
    (extend_bytes_contract with_prefix (alloc.vec.Vec.deref head.host) (by scalar_tac))
  let colon : Slice U8 := (Array.make 1#usize [58#u8] (by rfl)).to_slice
  obtain ⟨with_colon, colon_run, colon_bytes⟩ := returned_of_spec
    (extend_bytes_contract with_host colon (by
      simp only [colon, Array.length_to_slice]; scalar_tac))
  let port : Usize := UScalar.cast .Usize head.port
  have port_value : port.val = head.port.val := by scalar_tac
  obtain ⟨with_port, port_run, port_bytes⟩ := returned_of_spec
    (decimal_wire_contract with_colon port (by rw [port_value]; scalar_tac))
  let accept_prefix : Slice U8 := (Array.make 10#usize AcceptPrefix (by rfl)).to_slice
  obtain ⟨with_accept_prefix, accept_prefix_run, accept_prefix_bytes⟩ := returned_of_spec
    (extend_bytes_contract with_port accept_prefix (by
      simp only [accept_prefix, Array.length_to_slice]; scalar_tac))
  obtain ⟨with_accept, accept_run, accept_bytes⟩ := returned_of_spec
    (extend_bytes_contract with_accept_prefix (alloc.vec.Vec.deref head.accept) (by scalar_tac))
  let fixed : Slice U8 := (Array.make 76#usize FixedHeaders (by rfl)).to_slice
  obtain ⟨with_fixed, fixed_run, fixed_bytes⟩ := returned_of_spec
    (extend_bytes_contract with_accept fixed (by
      simp only [fixed, Array.length_to_slice]; scalar_tac))
  obtain ⟨with_headers, header_run, header_bytes⟩ := returned_of_spec
    (append_headers_exact with_fixed (alloc.vec.Vec.deref head.headers) (by scalar_tac))
  have header_length : with_headers.length = with_fixed.length + (HeadersBytes head.headers.val).length := by
    simp [alloc.vec.Vec.length, header_bytes]
  obtain ⟨pair, auth_run, auth_result⟩ := returned_of_spec
    (authentication_wire_contract with_headers secret authentication credential_valid (by scalar_tac))
  rcases pair with ⟨result, with_auth⟩
  obtain ⟨ack, auth_bytes, auth_length⟩ := auth_result
  dsimp only at ack auth_bytes auth_length
  subst result
  dsimp only [host_prefix, HostPrefix] at prefix_run
  dsimp only [colon] at colon_run
  dsimp only [port] at port_run
  dsimp only [accept_prefix, AcceptPrefix] at accept_prefix_run
  dsimp only [fixed, FixedHeaders] at fixed_run
  -- Reduce generated tuple matchers explicitly; keep body cases out of this prefix calculation.
  have complete_prefix_run : append_request output head secret authentication body =
      Finish with_auth body := by
    simp only [append_request, start, credential, body_checked, headers, bind_ok, ↓reduceIte]
    rw [line_run]
    simp only [bind_ok]
    dsimp! only
    simp only [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
    rw [lifted_array_slice]
    simp only [bind_ok]
    rw [prefix_run]
    simp only [bind_ok]
    rw [host_run]
    simp only [bind_ok]
    rw [lifted_array_slice]
    simp only [bind_ok]
    rw [colon_run]
    simp only [bind_ok, lift]
    rw [port_run]
    simp only [bind_ok]
    rw [accept_prefix_run]
    simp only [bind_ok]
    rw [accept_run]
    simp only [bind_ok]
    rw [fixed_run]
    simp only [bind_ok]
    rw [header_run]
    simp only [bind_ok]
    rw [auth_run]
    simp only [bind_ok]
    dsimp! only
    simp only [bind_ok]
    rfl
  rw [complete_prefix_run]
  cases body with
  | none =>
    simp only [BodyHeaderBytes, BodyBytes, List.length_nil, Nat.add_zero] at capacity
    let crlf : Slice U8 := (Array.make 2#usize [13#u8, 10#u8] (by rfl)).to_slice
    obtain ⟨finished, final_run, final_bytes⟩ := returned_of_spec
      (extend_bytes_contract with_auth crlf (by
        simp only [crlf, Array.length_to_slice]; scalar_tac))
    have finish_run : Finish with_auth none = Result.ok (.Ok (), finished) := by
      simp (config := { zetaHave := true, zetaDelta := true, iota := true }) only [Finish, bind_ok, final_run]
    rw [finish_run]
    apply (WP.spec_ok _).mpr
    refine ⟨rfl, ?_⟩
    have host_prefix_val : host_prefix.val = HostPrefix := by
      rw [show host_prefix = (Array.make 6#usize HostPrefix (by rfl)).to_slice from rfl,
        Array.val_to_slice]
      exact Array.make_val _ _ _
    have accept_prefix_val : accept_prefix.val = AcceptPrefix := by
      rw [show accept_prefix = (Array.make 10#usize AcceptPrefix (by rfl)).to_slice from rfl,
        Array.val_to_slice]
      exact Array.make_val _ _ _
    have fixed_val : fixed.val = FixedHeaders := by
      rw [show fixed = (Array.make 76#usize FixedHeaders (by rfl)).to_slice from rfl,
        Array.val_to_slice]
      exact Array.make_val _ _ _
    simp only [final_bytes.1, auth_bytes, header_bytes, fixed_bytes.1, accept_bytes.1,
      accept_prefix_bytes.1, port_bytes.1, colon_bytes.1, host_bytes.1, prefix_bytes.1, line_bytes]
    simp only [RequestBytes, StartBytes, BodyHeaderBytes, BodyBytes, host_prefix_val,
      accept_prefix_val, fixed_val, colon, crlf, Array.val_to_slice, Array.make_val,
      vec_deref_val, port_value, List.append_assoc, List.append_nil]
  | some bytes =>
    simp only [BodyHeaderBytes, BodyBytes, List.length_append, List.length_cons,
      List.length_nil, JsonLengthPrefix] at capacity
    let json_prefix : Slice U8 := (Array.make 48#usize JsonLengthPrefix (by rfl)).to_slice
    obtain ⟨with_json, json_run, json_bytes⟩ := returned_of_spec
      (extend_bytes_contract with_auth json_prefix (by
        simp only [json_prefix, Array.length_to_slice]; scalar_tac))
    obtain ⟨with_length, length_run, length_bytes⟩ := returned_of_spec
      (decimal_wire_contract with_json bytes.len (by
        simp only [Slice.len_val]; scalar_tac))
    let crlf : Slice U8 := (Array.make 2#usize [13#u8, 10#u8] (by rfl)).to_slice
    obtain ⟨with_body_headers, body_header_run, body_header_bytes⟩ := returned_of_spec
      (extend_bytes_contract with_length crlf (by
        simp only [crlf, Array.length_to_slice]; scalar_tac))
    obtain ⟨with_separator, separator_run, separator_bytes⟩ := returned_of_spec
      (extend_bytes_contract with_body_headers crlf (by
        simp only [crlf, Array.length_to_slice]; scalar_tac))
    obtain ⟨finished, final_run, final_bytes⟩ := returned_of_spec
      (extend_bytes_contract with_separator bytes (by scalar_tac))
    have finish_run : Finish with_auth (some bytes) = Result.ok (.Ok (), finished) := by
      simp (config := { zetaHave := true, zetaDelta := true, iota := true }) only [Finish, json_run, length_run, body_header_run, separator_run, final_run, bind_ok]
    rw [finish_run]
    apply (WP.spec_ok _).mpr
    refine ⟨rfl, ?_⟩
    have host_prefix_val : host_prefix.val = HostPrefix := by
      rw [show host_prefix = (Array.make 6#usize HostPrefix (by rfl)).to_slice from rfl,
        Array.val_to_slice]
      exact Array.make_val _ _ _
    have accept_prefix_val : accept_prefix.val = AcceptPrefix := by
      rw [show accept_prefix = (Array.make 10#usize AcceptPrefix (by rfl)).to_slice from rfl,
        Array.val_to_slice]
      exact Array.make_val _ _ _
    have fixed_val : fixed.val = FixedHeaders := by
      rw [show fixed = (Array.make 76#usize FixedHeaders (by rfl)).to_slice from rfl,
        Array.val_to_slice]
      exact Array.make_val _ _ _
    simp only [final_bytes.1, separator_bytes.1, body_header_bytes.1, length_bytes.1,
      json_bytes.1, auth_bytes, header_bytes, fixed_bytes.1, accept_bytes.1,
      accept_prefix_bytes.1, port_bytes.1, colon_bytes.1, host_bytes.1, prefix_bytes.1, line_bytes]
    have json_val : json_prefix.val = JsonLengthPrefix := by
      rw [show json_prefix = (Array.make 48#usize JsonLengthPrefix (by rfl)).to_slice from rfl,
        Array.val_to_slice]
      exact Array.make_val _ _ _
    simp only [RequestBytes, StartBytes, BodyHeaderBytes, BodyBytes, host_prefix_val,
      accept_prefix_val, fixed_val, json_val, colon, crlf, Array.val_to_slice, Array.make_val,
      vec_deref_val, port_value, Slice.len_val, List.append_assoc]

end aivm_secrets_garrett_core.http_wire.Proofs
