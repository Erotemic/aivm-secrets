import AivmSecretsGarrettCore
import GarrettFoundation
import GarrettHttpAuth
import GarrettHttpRequest
import GarrettHttpWireDecimal
import GarrettHttpWireFormatting
import GarrettHttpWireHeaders

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
open aivm_secrets_garrett_core.http_wire.Proofs (CaseFold FoldedEqual PrefixTail)

/-- ASCII bytes of a literal. -/
def ascii (s : String) : List U8 := s.toList.map (fun c => ⟨BitVec.ofNat 8 c.toNat⟩)

/-- The guest fields the proxy never forwards. -/
def DroppedNames : List (List U8) :=
  ["authorization", "x-api-key", "proxy-authorization", "proxy-connection",
   "connection", "keep-alive", "transfer-encoding", "content-length", "te",
   "trailer", "upgrade", "host", "accept-encoding", "cookie"].map ascii

/-- Bytes compared without regard to ASCII case. -/
def fold (bytes : List U8) : List Nat := bytes.map (fun b => CaseFold b.val)

/-- A dropped field: its name equals one of `DroppedNames` ignoring ASCII case,
    so the filter does not depend on the parser lowercasing names. -/
def Dropped (field : proxy_http.Field) : Prop := fold field.name.val ∈ DroppedNames.map fold

instance (field : proxy_http.Field) : Decidable (Dropped field) := by
  unfold Dropped; infer_instance

theorem lifted_slice {n : Usize} (bytes : Array U8 n) :
    lift (Array.to_slice bytes) = Result.ok (Array.to_slice bytes) := rfl

theorem folded_equal_iff (a b : Slice U8) : FoldedEqual a b ↔ fold a.val = fold b.val := by
  constructor
  · rintro ⟨len, tail⟩
    apply List.ext_getElem
    · simp [fold]; scalar_tac
    · intro i h1 h2
      simp only [fold, List.getElem_map]
      exact tail i (by simpa [fold] using h1) (by simp [fold] at h2; scalar_tac) (Nat.zero_le _)
  · intro same
    have len : a.length = b.length := by
      have := congrArg List.length same
      simp [fold] at this; scalar_tac
    refine ⟨len, fun i hn hp _ => ?_⟩
    have := congrArg (fun l => l[i]?) same
    simpa [fold, List.getElem?_map, List.getElem?_eq_getElem hn,
      List.getElem?_eq_getElem hp] using this

theorem name_is_eq (field : proxy_http.Field) (label : Slice U8) :
    name_is field label = Result.ok (decide (fold field.name.val = fold label.val)) := by
  unfold name_is
  rw [aivm_secrets_garrett_core.http_wire.Proofs.ascii_equal_exact]
  simp [folded_equal_iff, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]

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
theorem chain_step {α : Type} [DecidableEq α] (n l : α) (ls : List α) (r : Result Bool)
    (rest : r = Result.ok (decide (n ∈ ls))) :
    (if decide (n = l) = true then Result.ok true else r) =
      Result.ok (decide (n ∈ l :: ls)) := by
  by_cases h : n = l <;> simp [h, rest]

theorem chain_step_prop {α : Type} [DecidableEq α] (n l : α) (ls : List α) (r : Result Bool)
    (rest : r = Result.ok (decide (n ∈ ls))) :
    (if n = l then Result.ok true else r) = Result.ok (decide (n ∈ l :: ls)) := by
  by_cases h : n = l <;> simp [h, rest]

theorem chain_step_or {α : Type} [DecidableEq α] (n l : α) (b : Bool) (r : Result Bool)
    (rest : r = Result.ok b) :
    (if n = l then Result.ok true else r) = Result.ok (decide (n = l) || b) := by
  by_cases h : n = l <;> simp [h, rest]

theorem chain_fold (n : List Nat) (l : List U8) (ls : List (List U8)) (r : Result Bool)
    (rest : r = Result.ok (decide (n ∈ ls.map fold))) :
    (if n = fold l then Result.ok true else r) = Result.ok (decide (n ∈ (l :: ls).map fold)) := by
  by_cases h : n = fold l <;> simp [h, rest]

theorem dropped_eq (field : proxy_http.Field) :
    dropped field = Result.ok (decide (Dropped field)) := by
  unfold dropped
  simp only [lifted_slice, bind_ok, name_is_eq, array_slice_val, decide_eq_true_eq]
  change _ = Result.ok (decide (fold field.name.val ∈ DroppedNames.map fold))
  rw [dropped_names_bytes]
  generalize fold field.name.val = n
  repeat (refine chain_fold _ _ _ _ ?_)
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
    path_end_loop target index ⦃ e => index.val ≤ e.val ∧ e.val ≤ target.length ∧
      ∀ (h : e.val < target.length), target.val[e.val] = 63#u8 ⦄ := by
  suffices ∀ n (index : Usize), target.length - index.val = n → index.val ≤ target.length →
      path_end_loop target index ⦃ e => index.val ≤ e.val ∧ e.val ≤ target.length ∧
        ∀ (h : e.val < target.length), target.val[e.val] = 63#u8 ⦄ from this _ index rfl inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure inside
    rw [path_end_loop.eq_def]
    dsimp only
    split
    · step as ⟨byte, hbyte⟩
      split
      · step as ⟨next, hnext⟩
        refine WP.spec_mono (ih (target.length - next.val) (by scalar_tac) next rfl (by scalar_tac)) ?_
        intro e ⟨lo, hi, at_q⟩
        exact ⟨by scalar_tac, hi, at_q⟩
      · rename_i stop
        simp only [WP.spec_ok]
        refine ⟨le_refl _, by scalar_tac, fun _ => ?_⟩
        simp only [bne_iff_ne, ne_eq, Decidable.not_not] at stop
        simpa [hbyte] using stop
    · simp only [WP.spec_ok]
      refine ⟨le_refl _, by scalar_tac, fun h => ?_⟩
      exfalso; scalar_tac

@[step]
theorem path_end_spec (target : Slice U8) :
    path_end target ⦃ e => e.val ≤ target.length ∧
      ∀ (h : e.val < target.length), target.val[e.val] = 63#u8 ⦄ := by
  unfold path_end
  refine WP.spec_mono (path_end_loop_spec target 0#usize (by scalar_tac)) ?_
  intro e ⟨_, hi, at_q⟩
  exact ⟨hi, at_q⟩

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

/-! ## The encoder's own framing checks -/

def Visible (byte : U8) : Prop := 33 ≤ byte.val ∧ byte.val ≤ 126

instance (byte : U8) : Decidable (Visible byte) := by unfold Visible; infer_instance

/-- A byte allowed in a field value: visible ASCII, SP or HTAB. Never CR or LF. -/
def Clean (byte : U8) : Prop := Visible byte ∨ byte.val = 32 ∨ byte.val = 9

/-- A field that is exactly one header line. -/
def CleanField (field : proxy_http.Field) : Prop :=
  field.name.val ≠ [] ∧ (∀ byte ∈ field.name.val, Visible byte) ∧
    ∀ byte ∈ field.value.val, Clean byte

theorem visible_eq (byte : U8) : visible byte = Result.ok (decide (Visible byte)) := by
  unfold visible Visible
  split <;> simp_all

theorem blank_eq (byte : U8) : blank byte = Result.ok (decide (byte.val = 32 ∨ byte.val = 9)) := by
  unfold blank
  by_cases h32 : byte = 32#u8
  · subst h32; simp
  · have n32 : byte.val ≠ 32 := fun e => h32 (UScalar.eq_of_val_eq (by simpa using e))
    simp only [h32, ↓reduceIte, Result.ok.injEq]
    by_cases h9 : byte = 9#u8
    · subst h9; simp
    · have n9 : byte.val ≠ 9 := fun e => h9 (UScalar.eq_of_val_eq (by simpa using e))
      simp [h9, n32, n9]

@[step]
theorem token_byte_spec (byte : U8) : token_byte byte ⦃ _ => True ⦄ := by
  unfold token_byte
  step*

theorem all_token_loop_spec (line : Slice U8) (stop index : Usize) (h : stop.val ≤ line.length) :
    all_token_loop line stop index ⦃ t => t = true →
      ∀ k (hk : k < line.length), index.val ≤ k → k < stop.val → Visible line.val[k] ⦄ := by
  suffices ∀ n (index : Usize), stop.val - index.val = n →
      all_token_loop line stop index ⦃ t => t = true →
        ∀ k (hk : k < line.length), index.val ≤ k → k < stop.val → Visible line.val[k] ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure
    rw [all_token_loop.eq_def]
    split
    · step as ⟨byte, hbyte⟩
      rw [visible_eq]
      simp only [bind_ok]
      split
      · rename_i seen
        step as ⟨t⟩
        split
        · step as ⟨next, hnext⟩
          refine WP.spec_mono (ih (stop.val - next.val) (by scalar_tac) next rfl) ?_
          intro r hr ok k hk lo hi
          by_cases same : k = index.val
          · subst same
            simp only [decide_eq_true_eq] at seen
            simpa [hbyte] using seen
          · exact hr ok k hk (by scalar_tac) hi
        · simp
      · simp
    · simp only [WP.spec_ok]
      intro _ k hk lo hi
      scalar_tac

theorem all_value_loop_spec (line : Slice U8) (last check : Usize) (h : last.val ≤ line.length) :
    all_value_loop line last check ⦃ t => t = true →
      ∀ k (hk : k < line.length), check.val ≤ k → k < last.val → Clean line.val[k] ⦄ := by
  suffices ∀ n (check : Usize), last.val - check.val = n →
      all_value_loop line last check ⦃ t => t = true →
        ∀ k (hk : k < line.length), check.val ≤ k → k < last.val → Clean line.val[k] ⦄ from
    this _ check rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro check measure
    rw [all_value_loop.eq_def]
    split
    · step as ⟨byte, hbyte⟩
      rw [visible_eq]
      simp only [bind_ok]
      split
      · rename_i seen
        step as ⟨next, hnext⟩
        refine WP.spec_mono (ih (last.val - next.val) (by scalar_tac) next rfl) ?_
        intro r hr ok k hk lo hi
        by_cases same : k = check.val
        · subst same
          left
          simp only [decide_eq_true_eq] at seen
          simpa [hbyte] using seen
        · exact hr ok k hk (by scalar_tac) hi
      · rw [blank_eq]
        simp only [bind_ok]
        split
        · rename_i seen
          step as ⟨next, hnext⟩
          refine WP.spec_mono (ih (last.val - next.val) (by scalar_tac) next rfl) ?_
          intro r hr ok k hk lo hi
          by_cases same : k = check.val
          · subst same
            right
            simp only [decide_eq_true_eq] at seen
            simpa [hbyte] using seen
          · exact hr ok k hk (by scalar_tac) hi
        · simp
    · simp only [WP.spec_ok]
      intro _ k hk lo hi
      scalar_tac

theorem mem_all {P : U8 → Prop} (bytes : List U8)
    (all : ∀ k (hk : k < bytes.length), P bytes[k]) : ∀ b ∈ bytes, P b := by
  intro b mem
  obtain ⟨k, hk, rfl⟩ := List.getElem_of_mem mem
  exact all k hk

@[step]
theorem clean_field_spec (field : proxy_http.Field) :
    clean_field field ⦃ t => t = true → CleanField field ⦄ := by
  unfold clean_field
  dsimp only
  split
  · rename_i nonempty
    simp only [all_token]
    refine WP.spec_bind (all_token_loop_spec _ _ 0#usize (by simp)) ?_
    intro t ht
    split
    · simp only [all_value]
      refine WP.spec_mono (all_value_loop_spec _ _ 0#usize (by simp)) ?_
      intro r hr ok
      refine ⟨?_, ?_, ?_⟩
      · intro empty
        have zero : alloc.vec.Vec.len field.name = 0#usize :=
          UScalar.eq_of_val_eq (by simp [alloc.vec.Vec.len, empty])
        simp [zero] at nonempty
      · apply mem_all
        intro k hk
        have := ht (by simp_all) k (by simpa using hk) (Nat.zero_le _) (by simpa using hk)
        simpa using this
      · apply mem_all
        intro k hk
        have := hr ok k (by simpa using hk) (Nat.zero_le _) (by simpa using hk)
        simpa using this
    · simp
  · simp

theorem clean_fields_loop_spec (it : core.slice.iter.Iter proxy_http.Field) :
    clean_fields_loop it ⦃ t => t = true → ∀ field ∈ it.slice.val.drop it.i, CleanField field ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter proxy_http.Field), it.slice.length - it.i = n →
      clean_fields_loop it ⦃ t => t = true → ∀ field ∈ it.slice.val.drop it.i, CleanField field ⦄ from
    this _ it rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [clean_fields_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have split : it.slice.val.drop it.i = it.slice[it.i] :: it.slice.val.drop (it.i + 1) := by
        rw [List.drop_eq_getElem_cons (by scalar_tac : it.i < it.slice.val.length)]
        rfl
      rw [iter_next_inside it inside]
      simp only [bind_ok]
      step as ⟨t, ht⟩
      split
      · refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
          { it with i := it.i + 1 } rfl) ?_
        intro r hr ok field mem
        rw [split] at mem
        rcases List.mem_cons.mp mem with same | rest
        · subst same; exact ht (by simp_all)
        · exact hr ok field rest
      · simp
    · rw [iter_next_done it inside]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      intro _ field mem
      have : it.slice.val.drop it.i = [] := List.drop_eq_nil_of_le (by scalar_tac)
      rw [this] at mem
      cases mem

@[step]
theorem clean_fields_spec (fields : Slice proxy_http.Field) :
    clean_fields fields ⦃ t => t = true → ∀ field ∈ fields.val, CleanField field ⦄ := by
  unfold clean_fields
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  refine WP.spec_mono (clean_fields_loop_spec ⟨fields, 0⟩) ?_
  intro t h ok
  simpa using h ok

@[step]
theorem escape_at_spec (value : Slice U8) (start : Usize) (a b : U8) :
    escape_at value start a b ⦃ _ => True ⦄ := by
  unfold escape_at
  step*

@[step]
theorem forbidden_escape_at_spec (value : Slice U8) (start : Usize) :
    forbidden_escape_at value start ⦃ _ => True ⦄ := by
  unfold forbidden_escape_at
  step*

theorem plain_target_bytes_loop_spec (target : Slice U8) (index : Usize) :
    plain_target_bytes_loop target index ⦃ t => t = true →
      ∀ k (hk : k < target.length), index.val ≤ k → Visible target.val[k] ⦄ := by
  suffices ∀ n (index : Usize), target.length - index.val = n →
      plain_target_bytes_loop target index ⦃ t => t = true →
        ∀ k (hk : k < target.length), index.val ≤ k → Visible target.val[k] ⦄ from
    this _ index rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro index measure
    rw [plain_target_bytes_loop.eq_def]
    dsimp only
    split
    · step as ⟨byte, hbyte⟩
      rw [visible_eq]
      simp only [bind_ok]
      split
      · rename_i seen
        split
        · simp
        · split
          · simp
          · step as ⟨escaped⟩
            split
            · simp
            · step as ⟨next, hnext⟩
              refine WP.spec_mono (ih (target.length - next.val) (by scalar_tac) next rfl) ?_
              intro r hr ok k hk lo
              by_cases same : k = index.val
              · subst same
                simp only [decide_eq_true_eq] at seen
                simpa [hbyte] using seen
              · exact hr ok k hk (by scalar_tac)
      · simp
    · simp only [WP.spec_ok]
      intro _ k hk lo
      scalar_tac

@[step]
theorem segment_ok_spec (path : Slice U8) (start stop : Usize) (last : Bool)
    (order : start.val ≤ stop.val) (inside : stop.val ≤ path.length) :
    segment_ok path start stop last ⦃ _ => True ⦄ := by
  unfold segment_ok
  repeat (first | step | split | simp)

theorem segments_ok_loop_spec (path : Slice U8) (start index : Usize)
    (order : start.val ≤ index.val) (inside : index.val ≤ path.length) :
    segments_ok_loop path start index ⦃ _ => True ⦄ := by
  suffices ∀ n (start index : Usize), path.length - index.val = n → start.val ≤ index.val →
      index.val ≤ path.length → segments_ok_loop path start index ⦃ _ => True ⦄ from
    this _ start index rfl order inside
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro start index measure order inside
    rw [segments_ok_loop.eq_def]
    dsimp only
    split
    · step as ⟨byte⟩
      split
      · step as ⟨ok⟩
        split
        · step as ⟨next, hnext⟩
          exact ih (path.length - next.val) (by scalar_tac) next next rfl (le_refl _) (by scalar_tac)
        · simp
      · step as ⟨next, hnext⟩
        exact ih (path.length - next.val) (by scalar_tac) start next rfl (by scalar_tac) (by scalar_tac)
    · step*

/-- An accepted target is visible ASCII only: no SP, CR, LF or NUL. -/
@[step]
theorem check_target_spec (target : Slice U8) :
    check_target target ⦃ t => t = true → ∀ byte ∈ target.val, Visible byte ⦄ := by
  unfold check_target
  dsimp only
  split
  · simp
  · split
    · simp
    · step as ⟨first, hfirst⟩
      split
      · simp
      · rename_i slash
        refine WP.spec_bind (plain_target_bytes_loop_spec target 0#usize) ?_
        intro plain hplain
        split
        · rename_i accepted
          step as ⟨stop, hstop, at_q⟩
          step as ⟨path, hpath, hpath_len⟩
          have one : 1 ≤ stop.val := by
            by_contra zero
            have z : stop.val = 0 := by omega
            have q := at_q (by scalar_tac)
            simp only [z] at q
            simp only [bne_iff_ne, ne_eq, Decidable.not_not] at slash
            have f47 : first = 47#u8 := slash
            rw [hfirst] at f47
            rw [f47] at q
            exact absurd q (by decide)
          refine WP.spec_mono (segments_ok_loop_spec path 1#usize 1#usize (le_refl _)
            (by scalar_tac)) ?_
          intro _ _ _
          apply mem_all
          intro k hk
          exact hplain accepted k hk (Nat.zero_le _)
        · simp

@[step]
theorem valid_method_spec (method : Slice U8) : valid_method method ⦃ _ => True ⦄ := by
  unfold valid_method
  step*

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
attribute [step] aivm_secrets_garrett_core.http_wire.Proofs.append_decimal_exact

@[step]
theorem needs_length_spec (request : proxy_http.Request) :
    needs_length request ⦃ b => b = decide (NeedsLength request) ⦄ := by
  rw [needs_length_eq]; simp

theorem header_prefix_length (authentication : credential_use.Authentication) :
    (HeaderPrefix authentication).length ≤ 22 := by
  cases authentication <;> simp [HeaderPrefix]

/-- A clean field or visible target holds no CR (13) or LF (10): each guest
    field the encoder writes is exactly one line. -/
theorem clean_field_single_line (field : proxy_http.Field) (clean : CleanField field) :
    ∀ byte ∈ field.name.val ++ field.value.val, byte.val ≠ 13 ∧ byte.val ≠ 10 := by
  intro byte mem
  rcases List.mem_append.mp mem with in_name | in_value
  · have := clean.2.1 byte in_name
    simp only [Visible] at this; omega
  · rcases clean.2.2 byte in_value with v | sp | tab
    · simp only [Visible] at v; omega
    · omega
    · omega

theorem visible_single_line (byte : U8) (visible : Visible byte) :
    byte.val ≠ 13 ∧ byte.val ≠ 10 := by
  simp only [Visible] at visible; omega

/-- **Where the credential goes.** For every guest request, credential, host
    and deny list, `encode_upstream` either refuses and leaves the buffer as
    it was, or it has checked that the credential is valid, the target is
    visible ASCII, and every forwarded field is a single clean header line,
    and appends exactly
    `UpstreamPrefix ++ HeaderPrefix a ++ secret ++ CRLF ++ UpstreamSuffix`.
    Neither `UpstreamPrefix` nor `UpstreamSuffix` depends on the secret; no
    forwarded field is named `Authorization`, `X-Api-Key`,
    `Proxy-Authorization` or `Cookie` in any ASCII case (`forwarded_drops`);
    and since no forwarded name, value or target contains CR or LF, a guest
    cannot add a header line. These checks are the encoder's own, so the
    framing does not depend on the parser. -/
theorem encode_upstream_contract (output : alloc.vec.Vec U8) (request : proxy_http.Request)
    (host : Slice U8) (rules : Slice proxy_http.DenyRule) (secret : Slice U8)
    (authentication : credential_use.Authentication)
    (room : output.length + (UpstreamPrefix request host ++ HeaderPrefix authentication ++
      secret.val ++ CRLF ++ UpstreamSuffix request).length ≤ Usize.max) :
    encode_upstream output request host rules secret authentication ⦃ r =>
      (r.1 = .Ok () ∧ http_auth.Proofs.ValidCredential secret ∧
        (∀ byte ∈ request.target.val, Visible byte) ∧
        (∀ field ∈ Forwarded request.fields.val, CleanField field) ∧
        r.2.val = output.val ++ UpstreamPrefix request host ++ HeaderPrefix authentication ++
          secret.val ++ CRLF ++ UpstreamSuffix request) ∨
      (r.1 ≠ .Ok () ∧ r.2 = output) ⦄ := by
  have lengths := room
  simp only [UpstreamPrefix, UpstreamSuffix, CRLF, request_line_bytes, fixed_tail_bytes,
    length_field_bytes, List.length_append, List.length_cons, List.length_nil] at lengths
  have prefix_length := header_prefix_length authentication
  unfold encode_upstream
  step*
  have target_visible : ∀ byte ∈ request.target.val, Visible byte := by
    simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using b1_post (by assumption)
  have fields_clean : ∀ field ∈ Forwarded request.fields.val, CleanField field := by
    have := b2_post (by assumption)
    simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val, fields_post] using this
  obtain ⟨accepted, checked, equivalent⟩ :=
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
    · have yes : b5 = true := by simp [b5_post, need]
      simp only [yes, ↓reduceIte]
      simp only [need, ↓reduceIte, List.length_append] at lengths
      rw [← body_len] at lengths
      step*
      left
      refine ⟨valid, target_visible, fields_clean, ?_⟩
      simp_all [UpstreamPrefix, UpstreamSuffix, CRLF, request_line_bytes, fixed_tail_bytes,
        length_field_bytes, List.append_assoc]
    · have no : b5 = false := by simp [b5_post, need]
      simp only [no, Bool.false_eq_true, ↓reduceIte, bind_ok]
      simp only [need, ↓reduceIte, List.length_nil] at lengths
      step*
      left
      refine ⟨valid, target_visible, fields_clean, ?_⟩
      simp_all [UpstreamPrefix, UpstreamSuffix, CRLF, request_line_bytes, fixed_tail_bytes,
        List.append_assoc]
  · have no : accepted = false := by cases accepted <;> simp_all
    simp only [no, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
    right
    simp

end aivm_secrets_garrett_core.proxy_http.Proofs
