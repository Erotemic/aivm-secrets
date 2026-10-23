import AivmSecretsGarrettCore
import GarrettFoundation
import GarrettHttpAuth
import GarrettHttpRequest
import GarrettHttpWireDecimal
import GarrettHttpWireFormatting

/-!
# HTTPS proxy, credential-substitution profile: where the credential goes

Source: `rust/crates/aivm-secrets-garrett-core/src/proxy_http.rs`, extracted
by Aeneas (HP-4/HP-5 in `docs/planning/aivm-secrets-http-proxy-profiles.md`).
The Python reference is `aivm_secrets/proxy/{http1,policy}.py`.

Proved here, for the extracted upstream encoder `encode_upstream`:

* `dropped_contract`: the extracted field filter drops exactly the fourteen
  names in `DroppedNames`, which include every credential-bearing guest field
  (`authorization`, `x-api-key`, `proxy-authorization`, `cookie`);
* `forwarded_contract`: the forwarded guest fields are the guest fields in
  order, minus those names;
* `append_fields_contract`: forwarded fields are written as
  `name ": " value CRLF`, nothing else;
* `encode_upstream_exact`: an accepted request writes exactly
  `Prefix ++ HeaderPrefix a ++ secret ++ CRLF ++ Suffix`, where `Prefix` and
  `Suffix` are functions of the request and host only. The credential's only
  position in the upstream bytes is the single verified authentication line
  (`http_auth.Proofs.accepted_header_exact`), after every guest field;
* `refusal_leaves_buffer`: a deny-listed request or an invalid credential
  writes nothing.

Not proved here: the parser (`parse_request`) and its agreement with the
provider's reading of the canonical bytes (`PROXY-PARSE-01`), the response
reflection check (`PROXY-REFLECT-01`), TLS and the session CA
(`PROXY-TLS-01`), and that the native proxy writes exactly these bytes.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace aivm_secrets_garrett_core.proxy_http.Proofs

open aivm_secrets_garrett_core.http_auth.Proofs (HeaderPrefix)
open aivm_secrets_garrett_core.http_request.Proofs (slice_bytes_equal)

/-- ASCII bytes of a literal. -/
def ascii (s : String) : List U8 := s.toList.map (fun c => ⟨BitVec.ofNat 8 c.toNat⟩)

/-- The guest fields the proxy never forwards. -/
def DroppedNames : List (List U8) :=
  ["authorization", "x-api-key", "proxy-authorization", "proxy-connection",
   "connection", "keep-alive", "transfer-encoding", "content-length", "te",
   "trailer", "upgrade", "host", "accept-encoding", "cookie"].map ascii

def Dropped (field : proxy_http.Field) : Prop := field.name.val ∈ DroppedNames

instance (field : proxy_http.Field) : Decidable (Dropped field) := by
  unfold Dropped; infer_instance

theorem lifted_slice {n : Usize} (bytes : Array U8 n) :
    lift (Array.to_slice bytes) = Result.ok (Array.to_slice bytes) := rfl

theorem name_is_eq (field : proxy_http.Field) (label : Slice U8) :
    name_is field label = Result.ok (decide (field.name.val = label.val)) := by
  unfold name_is
  obtain ⟨out, returned, h⟩ :=
    returned_of_spec (slice_bytes_equal (alloc.vec.Vec.deref field.name) label)
  rw [returned]
  congr 1
  by_cases e : field.name.val = label.val
  · simpa [e, alloc.vec.Vec.deref] using h
  · simp only [e, decide_false]
    cases out <;> simp_all [alloc.vec.Vec.deref]

/-- The same names as bytes, as the extracted code spells them. -/
theorem dropped_names_bytes : DroppedNames = [
   [97#u8, 117#u8, 116#u8, 104#u8, 111#u8, 114#u8, 105#u8, 122#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8],
   [120#u8, 45#u8, 97#u8, 112#u8, 105#u8, 45#u8, 107#u8, 101#u8, 121#u8],
   [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 97#u8, 117#u8, 116#u8, 104#u8, 111#u8, 114#u8, 105#u8, 122#u8, 97#u8, 116#u8, 105#u8, 111#u8, 110#u8],
   [112#u8, 114#u8, 111#u8, 120#u8, 121#u8, 45#u8, 99#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8, 105#u8, 111#u8, 110#u8],
   [99#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8, 105#u8, 111#u8, 110#u8],
   [107#u8, 101#u8, 101#u8, 112#u8, 45#u8, 97#u8, 108#u8, 105#u8, 118#u8, 101#u8],
   [116#u8, 114#u8, 97#u8, 110#u8, 115#u8, 102#u8, 101#u8, 114#u8, 45#u8, 101#u8, 110#u8, 99#u8, 111#u8, 100#u8, 105#u8, 110#u8, 103#u8],
   [99#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8, 108#u8, 101#u8, 110#u8, 103#u8, 116#u8, 104#u8],
   [116#u8, 101#u8],
   [116#u8, 114#u8, 97#u8, 105#u8, 108#u8, 101#u8, 114#u8],
   [117#u8, 112#u8, 103#u8, 114#u8, 97#u8, 100#u8, 101#u8],
   [104#u8, 111#u8, 115#u8, 116#u8],
   [97#u8, 99#u8, 99#u8, 101#u8, 112#u8, 116#u8, 45#u8, 101#u8, 110#u8, 99#u8, 111#u8, 100#u8, 105#u8, 110#u8, 103#u8],
   [99#u8, 111#u8, 111#u8, 107#u8, 105#u8, 101#u8]] := by rfl

theorem array_slice_val {k : Usize} (l : List U8) (h : l.length = k.val) :
    (Array.make k l h).to_slice.val = l := by
  simp [Array.to_slice, Slice.from_val]

/-- One link of an `if name = l then true else ...` chain is membership. -/
theorem chain_step (n l : List U8) (ls : List (List U8)) (r : Result Bool)
    (rest : r = Result.ok (decide (n ∈ ls))) :
    (if decide (n = l) = true then Result.ok true else r) =
      Result.ok (decide (n ∈ l :: ls)) := by
  by_cases h : n = l <;> simp [h, rest]

theorem dropped_eq (field : proxy_http.Field) :
    dropped field = Result.ok (decide (Dropped field)) := by
  unfold dropped
  simp only [Dropped, dropped_names_bytes, lifted_slice, bind_ok, name_is_eq, array_slice_val]
  generalize field.name.val = n
  repeat (refine chain_step _ _ _ _ ?_)
  simp

@[step]
theorem dropped_spec (field : proxy_http.Field) :
    dropped field ⦃ b => b = decide (Dropped field) ⦄ := by
  rw [dropped_eq]; simp

theorem bytes_clone_exact (bytes : alloc.vec.Vec U8) :
    alloc.vec.CloneVec.clone core.clone.CloneU8 bytes = Result.ok bytes := by
  unfold alloc.vec.CloneVec.clone
  obtain ⟨copied, returned, property⟩ := returned_of_spec
    (Slice.clone_spec (s := bytes.slice) (clone := core.clone.CloneU8.clone) (by intro x hx; rfl))
  rw [returned]
  simp only [bind_tc_ok, ← property]

/-- The guest fields that are forwarded, in order. -/
def Forwarded (fields : List proxy_http.Field) : List proxy_http.Field :=
  fields.filter (fun field => !decide (Dropped field))

theorem iter_next_inside {T : Type} (it : core.slice.iter.Iter T) (inside : it.i < it.slice.length) :
    core.slice.iter.IteratorSliceIter.next it =
      Result.ok (some it.slice[it.i], { it with i := it.i + 1 }) := by
  simp [core.slice.iter.IteratorSliceIter.next, inside]
  rfl

theorem iter_next_done {T : Type} (it : core.slice.iter.Iter T) (done : ¬ it.i < it.slice.length) :
    core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
  simp [core.slice.iter.IteratorSliceIter.next, done]

theorem forwarded_loop_contract (it : core.slice.iter.Iter proxy_http.Field)
    (out : alloc.vec.Vec proxy_http.Field)
    (room : out.length + (it.slice.length - it.i) ≤ Usize.max) :
    forwarded_loop it out ⦃ r => r.val = out.val ++ Forwarded (it.slice.val.drop it.i) ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter proxy_http.Field) (out : alloc.vec.Vec proxy_http.Field),
      it.slice.length - it.i = n → out.length + n ≤ Usize.max →
      forwarded_loop it out ⦃ r => r.val = out.val ++ Forwarded (it.slice.val.drop it.i) ⦄ from
    this _ it out rfl room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it out measure space
    rw [forwarded_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have split : it.slice.val.drop it.i = it.slice[it.i] :: it.slice.val.drop (it.i + 1) := by
        rw [List.drop_eq_getElem_cons (by scalar_tac : it.i < it.slice.val.length)]
        rfl
      rw [iter_next_inside it inside]
      simp only [bind_ok]
      step as ⟨b, hb⟩
      by_cases d : Dropped it.slice[it.i]
      · simp only [hb, d, decide_true, ↓reduceIte]
        refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
          { it with i := it.i + 1 } out rfl (by scalar_tac)) ?_
        intro r h
        rw [split]
        simpa [Forwarded, d] using h
      · simp only [hb, d, decide_false, Bool.false_eq_true, ↓reduceIte, bytes_clone_exact,
          bind_ok]
        have same : ({ «name» := it.slice[it.i].name, value := it.slice[it.i].value } :
            proxy_http.Field) = it.slice[it.i] := rfl
        rw [same]
        refine WP.spec_bind (alloc.vec.Vec.push_spec out it.slice[it.i] (by scalar_tac)) ?_
        intro pushed appended
        refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
          { it with i := it.i + 1 } pushed rfl
          (by simp [alloc.vec.Vec.length, appended]; scalar_tac)) ?_
        intro r h
        rw [split, h, appended]
        simp [Forwarded, d]
    · simp only [iter_next_done it inside, bind_ok]
      have : it.slice.val.drop it.i = [] := List.drop_eq_nil_of_le (by scalar_tac)
      simp [this, Forwarded]

@[step]
theorem forwarded_contract (fields : Slice proxy_http.Field) :
    forwarded fields ⦃ r => r.val = Forwarded fields.val ⦄ := by
  unfold forwarded
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  apply WP.spec_mono (forwarded_loop_contract ⟨fields, 0⟩ (alloc.vec.Vec.new proxy_http.Field)
    (by simp [alloc.vec.Vec.new, alloc.vec.Vec.length]))
  intro r h
  simpa [alloc.vec.Vec.new] using h

/-- No forwarded field is a credential field, or any other dropped field. -/
theorem forwarded_drops (fields : List proxy_http.Field) :
    ∀ field ∈ Forwarded fields, ¬ Dropped field := by
  intro field member
  simp only [Forwarded, List.mem_filter, Bool.not_eq_true', decide_eq_false_iff_not] at member
  exact member.2

@[step]
theorem path_end_loop_spec (target : Slice U8) (index : Usize) (inside : index.val ≤ target.length) :
    path_end_loop target index ⦃ e => e.val ≤ target.length ⦄ := by
  suffices ∀ n (index : Usize), target.length - index.val = n → index.val ≤ target.length →
      path_end_loop target index ⦃ e => e.val ≤ target.length ⦄ from this _ index rfl inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure inside
    rw [path_end_loop.eq_def]
    dsimp only
    split
    · step
      split
      · step
        exact ih (target.length - index1.val) (by scalar_tac) index1 rfl (by scalar_tac)
      · simp only [WP.spec_ok]; scalar_tac
    · simp only [WP.spec_ok]; scalar_tac

@[step]
theorem path_end_spec (target : Slice U8) :
    path_end target ⦃ e => e.val ≤ target.length ⦄ := by
  unfold path_end
  exact path_end_loop_spec target 0#usize (by scalar_tac)

@[step]
theorem rule_matches_spec (rule : proxy_http.DenyRule) (method path : Slice U8) :
    rule_matches rule method path ⦃ _ => True ⦄ := by
  unfold rule_matches
  step*

theorem denied_loop_spec (it : core.slice.iter.Iter proxy_http.DenyRule) (method path : Slice U8) :
    denied_loop it method path ⦃ _ => True ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter proxy_http.DenyRule), it.slice.length - it.i = n →
      denied_loop it method path ⦃ _ => True ⦄ from this _ it rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [denied_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · rw [iter_next_inside it inside]
      simp only [bind_ok]
      step as ⟨b⟩
      split
      · simp
      · exact ih (it.slice.length - (it.i + 1)) (by scalar_tac) { it with i := it.i + 1 } rfl
    · rw [iter_next_done it inside]
      simp

@[step]
theorem denied_spec (rules : Slice proxy_http.DenyRule) (method path : Slice U8) :
    denied rules method path ⦃ _ => True ⦄ := by
  unfold denied
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  exact denied_loop_spec _ method path

def CRLF : List U8 := [13#u8, 10#u8]

/-- One forwarded field on the wire. -/
def FieldBytes (field : proxy_http.Field) : List U8 :=
  field.name.val ++ [58#u8, 32#u8] ++ field.value.val ++ CRLF

def FieldsBytes : List proxy_http.Field → List U8
  | [] => []
  | field :: rest => FieldBytes field ++ FieldsBytes rest

theorem append_fields_loop_contract (iter : core.slice.iter.Iter proxy_http.Field)
    (output : alloc.vec.Vec U8)
    (room : output.length + (FieldsBytes (iter.slice.val.drop iter.i)).length ≤ Usize.max) :
    append_fields_loop iter output ⦃ out =>
      out.val = output.val ++ FieldsBytes (iter.slice.val.drop iter.i) ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter proxy_http.Field), it.slice.length - it.i = n →
      ∀ (output : alloc.vec.Vec U8),
        output.length + (FieldsBytes (it.slice.val.drop it.i)).length ≤ Usize.max →
        append_fields_loop it output ⦃ out =>
          out.val = output.val ++ FieldsBytes (it.slice.val.drop it.i) ⦄ from
    this _ iter rfl output room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure output space
    rw [append_fields_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · rw [iter_next_inside it inside]
      simp only [bind_ok]
      have bytes : FieldsBytes (it.slice.val.drop it.i) = FieldBytes it.slice[it.i] ++
          FieldsBytes (it.slice.val.drop (it.i + 1)) := by
        rw [List.drop_eq_getElem_cons inside]
        rfl
      rw [bytes] at space
      simp only [FieldBytes, CRLF, List.length_append, List.length_cons, List.length_nil] at space
      have first_room : output.length + (alloc.vec.Vec.deref it.slice[it.i].name).length ≤
          Usize.max := by
        simp only [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_length]
        scalar_tac
      step
      step
      step
      step
      step
      step
      have tail_room : output4.length + (FieldsBytes (it.slice.val.drop (it.i + 1))).length ≤
          Usize.max := by
        simp only [s1_post, s3_post, Array.length_to_slice] at *
        scalar_tac
      apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by omega)
        {it with i := it.i + 1} rfl output4 tail_room)
      intro out exact_bytes
      rw [bytes]
      simp_all [FieldBytes, CRLF, List.append_assoc]
    · rw [iter_next_done it inside]
      simp only [bind_ok]
      have : it.slice.val.drop it.i = [] := List.drop_eq_nil_of_le (by scalar_tac)
      simp [this, FieldsBytes]

@[step]
theorem append_fields_contract (output : alloc.vec.Vec U8) (fields : Slice proxy_http.Field)
    (room : output.length + (FieldsBytes fields.val).length ≤ Usize.max) :
    append_fields output fields ⦃ out => out.val = output.val ++ FieldsBytes fields.val ⦄ := by
  unfold append_fields
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  exact append_fields_loop_contract ⟨fields, 0⟩ output (by simpa using room)

theorem slice_eq_eq (a b : Slice U8) :
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b = Result.ok (decide (a.val = b.val)) := by
  obtain ⟨out, returned, h⟩ := returned_of_spec (slice_bytes_equal a b)
  rw [returned]
  congr 1
  by_cases e : a.val = b.val
  · simpa [e] using h
  · simp only [e, decide_false]
    cases out <;> simp_all

/-- Methods that always carry an explicit `Content-Length`. -/
def BodyMethods : List (List U8) := [ascii "POST", ascii "PUT", ascii "PATCH"]

theorem body_methods_bytes : BodyMethods =
    [[80#u8, 79#u8, 83#u8, 84#u8], [80#u8, 85#u8, 84#u8], [80#u8, 65#u8, 84#u8, 67#u8, 72#u8]] := by
  rfl

def NeedsLength (request : proxy_http.Request) : Prop :=
  0 < request.body.length ∨ request.method.val ∈ BodyMethods

instance (request : proxy_http.Request) : Decidable (NeedsLength request) := by
  unfold NeedsLength; infer_instance

theorem needs_length_eq (request : proxy_http.Request) :
    needs_length request = Result.ok (decide (NeedsLength request)) := by
  unfold needs_length
  simp only [NeedsLength, body_methods_bytes, lifted_slice, bind_ok, slice_eq_eq, array_slice_val]
  by_cases body : 0 < request.body.length
  · have : alloc.vec.Vec.len request.body > 0#usize := by scalar_tac
    simp [this, body]
  · have : ¬ alloc.vec.Vec.len request.body > 0#usize := by scalar_tac
    simp only [this, body, ↓reduceIte, false_or]
    rw [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]
    generalize request.method.val = m
    by_cases a : m = [80#u8, 79#u8, 83#u8, 84#u8] <;>
      by_cases b : m = [80#u8, 85#u8, 84#u8] <;>
      by_cases c : m = [80#u8, 65#u8, 84#u8, 67#u8, 72#u8] <;> simp_all

open aivm_secrets_garrett_core.http_wire.Proofs (Digits)

/-- Everything written before the credential line: request line, `Host`, and
    the forwarded guest fields. A function of the request and host only. -/
def UpstreamPrefix (request : proxy_http.Request) (host : Slice U8) : List U8 :=
  request.method.val ++ [32#u8] ++ request.target.val ++ ascii " HTTP/1.1\r\nHost: " ++
    host.val ++ CRLF ++ FieldsBytes (Forwarded request.fields.val)

/-- Everything written after the credential line. A function of the request only. -/
def UpstreamSuffix (request : proxy_http.Request) : List U8 :=
  ascii "Accept-Encoding: identity\r\nConnection: close\r\n" ++
    (if NeedsLength request then ascii "Content-Length: " ++ Digits request.body.length ++ CRLF
     else []) ++ CRLF ++ request.body.val

theorem request_line_bytes : ascii " HTTP/1.1\r\nHost: " =
    [32#u8, 72#u8, 84#u8, 84#u8, 80#u8, 47#u8, 49#u8, 46#u8, 49#u8,
     13#u8, 10#u8, 72#u8, 111#u8, 115#u8, 116#u8, 58#u8, 32#u8] := by rfl

theorem fixed_tail_bytes : ascii "Accept-Encoding: identity\r\nConnection: close\r\n" =
    [65#u8, 99#u8, 99#u8, 101#u8, 112#u8, 116#u8, 45#u8, 69#u8,
     110#u8, 99#u8, 111#u8, 100#u8, 105#u8, 110#u8, 103#u8, 58#u8,
     32#u8, 105#u8, 100#u8, 101#u8, 110#u8, 116#u8, 105#u8, 116#u8,
     121#u8, 13#u8, 10#u8, 67#u8, 111#u8, 110#u8, 110#u8, 101#u8,
     99#u8, 116#u8, 105#u8, 111#u8, 110#u8, 58#u8, 32#u8, 99#u8,
     108#u8, 111#u8, 115#u8, 101#u8, 13#u8, 10#u8] := by rfl

theorem length_field_bytes : ascii "Content-Length: " =
    [67#u8, 111#u8, 110#u8, 116#u8, 101#u8, 110#u8, 116#u8, 45#u8,
     76#u8, 101#u8, 110#u8, 103#u8, 116#u8, 104#u8, 58#u8, 32#u8] := by rfl

attribute [local scalar_tac_simps] Array.length_to_slice
attribute [local step] aivm_secrets_garrett_core.http_wire.Proofs.append_decimal_exact

@[step]
theorem needs_length_spec (request : proxy_http.Request) :
    needs_length request ⦃ b => b = decide (NeedsLength request) ⦄ := by
  rw [needs_length_eq]; simp

theorem header_prefix_length (authentication : credential_use.Authentication) :
    (HeaderPrefix authentication).length ≤ 22 := by
  cases authentication <;> simp [HeaderPrefix]

/-- **Where the credential goes.** For every guest request, credential, host
    and deny list, `encode_upstream` either refuses and leaves the buffer as
    it was, or accepts a valid credential and appends exactly
    `UpstreamPrefix ++ HeaderPrefix a ++ secret ++ CRLF ++ UpstreamSuffix`.
    Neither `UpstreamPrefix` nor `UpstreamSuffix` depends on the secret, and
    every guest field in the prefix passed the filter (`forwarded_drops`),
    so no guest `Authorization`, `X-Api-Key`, `Proxy-Authorization` or
    `Cookie` field is forwarded. -/
theorem encode_upstream_contract (output : alloc.vec.Vec U8) (request : proxy_http.Request)
    (host : Slice U8) (rules : Slice proxy_http.DenyRule) (secret : Slice U8)
    (authentication : credential_use.Authentication)
    (room : output.length + (UpstreamPrefix request host ++ HeaderPrefix authentication ++
      secret.val ++ CRLF ++ UpstreamSuffix request).length ≤ Usize.max) :
    encode_upstream output request host rules secret authentication ⦃ r =>
      (r.1 = .Ok () ∧ http_auth.Proofs.ValidCredential secret ∧
        r.2.val = output.val ++ UpstreamPrefix request host ++ HeaderPrefix authentication ++
          secret.val ++ CRLF ++ UpstreamSuffix request) ∨
      (r.1 ≠ .Ok () ∧ r.2 = output) ⦄ := by
  have lengths := room
  simp only [UpstreamPrefix, UpstreamSuffix, CRLF, request_line_bytes, fixed_tail_bytes,
    length_field_bytes, List.length_append, List.length_cons, List.length_nil] at lengths
  have prefix_length := header_prefix_length authentication
  unfold encode_upstream
  step*
  · obtain ⟨accepted, checked, equivalent⟩ :=
      returned_of_spec (http_auth.Proofs.valid_credential_contract secret)
    rw [checked]
    simp only [bind_ok]
    by_cases valid : http_auth.Proofs.ValidCredential secret
    · have yes : accepted = true := equivalent.mpr valid
      simp only [yes, ↓reduceIte, lifted_slice, bind_ok]
      step*
      obtain ⟨pair, header, exact⟩ := returned_of_spec
        (http_auth.Proofs.accepted_header_exact output7 secret authentication valid (by scalar_tac))
      rw [header]
      rcases pair with ⟨outcome, output8⟩
      obtain ⟨accepted_ok, output8_post⟩ := exact
      simp only at accepted_ok output8_post
      subst accepted_ok
      have output8_length : output8.length =
          output7.length + (HeaderPrefix authentication).length + secret.length + 2 := by
        simp only [alloc.vec.Vec.length, output8_post, List.length_append, List.length_cons,
          List.length_nil]
      simp only [bind_ok]
      step*
      have body_len : (alloc.vec.Vec.len request.body).val = request.body.length := by scalar_tac
      by_cases need : NeedsLength request
      · have yes : b2 = true := by simp [b2_post, need]
        simp only [yes, ↓reduceIte]
        simp only [need, ↓reduceIte, List.length_append] at lengths
        rw [← body_len] at lengths
        step*
        all_goals first
          | (left
             refine ⟨valid, ?_⟩
             simp_all [UpstreamPrefix, UpstreamSuffix, CRLF, request_line_bytes, fixed_tail_bytes,
               length_field_bytes, List.append_assoc])
          | (simp_all [alloc.vec.Vec.length, List.length_append]
             scalar_tac)
      · have no : b2 = false := by simp [b2_post, need]
        simp only [no, Bool.false_eq_true, ↓reduceIte, bind_ok]
        simp only [need, ↓reduceIte, List.length_nil] at lengths
        step*
        left
        refine ⟨valid, ?_⟩
        simp_all [UpstreamPrefix, UpstreamSuffix, CRLF, request_line_bytes, fixed_tail_bytes,
          List.append_assoc]
    · have no : accepted = false := by cases accepted <;> simp_all
      simp only [no, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
      right
      simp

end aivm_secrets_garrett_core.proxy_http.Proofs
