import GarrettProxyHttp
import GarrettReflection

/-!
# HTTPS proxy, credential-substitution profile: what the guest may receive

Source: the response side of `rust/crates/aivm-secrets-garrett-core/src/proxy_http.rs`
(`guest_response`, `reflects`, `encode_response`), extracted by Aeneas.
Python reference: `aivm_secrets/proxy/policy.py` (`guest_response`).

Proved here (HP-5(c) in `docs/planning/aivm-secrets-http-proxy-profiles.md`):

* `reflects_spec`: when the extracted check answers `false`, no
  case-sensitive form occurs anywhere in the checked bytes;
* `guest_response_contract`: an accepted response appends bytes to the guest
  buffer in which **no case-sensitive form occurs**, including for `HEAD`,
  whose bytes are a prefix of the checked ones; a refused response appends
  nothing.

With `reflection_forms`, whose first form is the raw credential, this means a
released response never contains the credential's exact bytes. Encodings
the forms do not list (partial, transformed or freshly minted credentials)
are not covered: `PROXY-REFLECT-01`, `PROXY-AUTHORITY-01`.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000
set_option maxRecDepth 100000

namespace aivm_secrets_garrett_core.proxy_http.Proofs

open aivm_secrets_garrett_core.reflection.Proofs (LiteralOccurs MatchesAt contains_contract)

/-- `needle` occurs as contiguous bytes in `bytes`. -/
def Occurs (bytes needle : List U8) : Prop :=
  needle ≠ [] ∧ ∃ start, start + needle.length ≤ bytes.length ∧
    bytes.slice start (start + needle.length) = needle

theorem literal_occurs_iff (value secret : Slice U8) :
    LiteralOccurs value secret ↔ Occurs value.val secret.val := by
  unfold LiteralOccurs Occurs MatchesAt
  constructor
  · rintro ⟨nonempty, start, fits, same⟩
    exact ⟨by intro e; apply nonempty; simp [Slice.length, e], start, by simpa using fits, same⟩
  · rintro ⟨nonempty, start, fits, same⟩
    exact ⟨by intro e; apply nonempty; simpa [Slice.length] using e, start,
      by simpa using fits, same⟩

/-- An occurrence in a prefix is an occurrence in the whole. -/
theorem occurs_append (front back needle : List U8) (inside : Occurs front needle) :
    Occurs (front ++ back) needle := by
  obtain ⟨nonempty, start, fits, same⟩ := inside
  refine ⟨nonempty, start, by simp; omega, ?_⟩
  simp only [List.slice] at same ⊢
  rw [List.drop_append_of_le_length (by omega), List.take_append_of_le_length (by simp; omega)]
  exact same

theorem lowered_loop_spec (it : core.slice.iter.Iter U8) (out : alloc.vec.Vec U8)
    (room : out.length + (it.slice.length - it.i) ≤ Usize.max) :
    lowered_loop it out ⦃ r => r.length = out.length + (it.slice.length - it.i) ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter U8) (out : alloc.vec.Vec U8),
      it.slice.length - it.i = n → out.length + n ≤ Usize.max →
      lowered_loop it out ⦃ r => r.length = out.length + n ⦄ from this _ it out rfl room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it out measure space
    rw [lowered_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · rw [iter_next_inside it inside]
      simp only [bind_ok]
      step as ⟨low⟩
      step as ⟨pushed, hpushed⟩
      have pushed_length : pushed.length = out.length + 1 := by
        simp [alloc.vec.Vec.length, hpushed]
      refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
        { it with i := it.i + 1 } pushed rfl (by scalar_tac)) ?_
      intro r hr
      omega
    · simp only [iter_next_done it inside, bind_ok]
      change (Result.ok out : Result (alloc.vec.Vec U8)) ⦃ r => r.length = out.length + n ⦄
      simp only [WP.spec_ok]
      omega

@[step]
theorem lowered_spec (bytes : Slice U8) : lowered bytes ⦃ r => r.length = bytes.length ⦄ := by
  unfold lowered
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  refine WP.spec_mono (lowered_loop_spec ⟨bytes, 0⟩ (alloc.vec.Vec.new U8)
    (by simp [alloc.vec.Vec.new, alloc.vec.Vec.length])) ?_
  intro r h
  simpa [alloc.vec.Vec.new, alloc.vec.Vec.length] using h

@[step]
theorem form_present_spec (data folded : Slice U8) (form : proxy_http.Form) :
    form_present data folded form ⦃ b => b = false → form.folded = false →
      ¬ Occurs data.val form.bytes.val ⦄ := by
  unfold form_present
  split
  · obtain ⟨found, returned, _⟩ := returned_of_spec
      (contains_contract folded (alloc.vec.Vec.deref form.bytes))
    rw [returned]
    apply (WP.spec_ok _).mpr
    intro _ plain
    simp_all
  · rename_i plain_form
    obtain ⟨found, returned, iff⟩ := returned_of_spec
      (contains_contract data (alloc.vec.Vec.deref form.bytes))
    rw [returned]
    apply (WP.spec_ok _).mpr
    intro absent _ occurs
    have : LiteralOccurs data (alloc.vec.Vec.deref form.bytes) := by
      rw [literal_occurs_iff]
      simpa [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using occurs
    simp_all

theorem reflects_loop_spec (it : core.slice.iter.Iter proxy_http.Form) (data : Slice U8)
    (folded : alloc.vec.Vec U8) :
    reflects_loop it data folded ⦃ b => b = false →
      ∀ form ∈ it.slice.val.drop it.i, form.folded = false → ¬ Occurs data.val form.bytes.val ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter proxy_http.Form), it.slice.length - it.i = n →
      reflects_loop it data folded ⦃ b => b = false →
        ∀ form ∈ it.slice.val.drop it.i, form.folded = false → ¬ Occurs data.val form.bytes.val ⦄ from
    this _ it rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [reflects_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have split_list : it.slice.val.drop it.i = it.slice[it.i] :: it.slice.val.drop (it.i + 1) := by
        rw [List.drop_eq_getElem_cons (by scalar_tac : it.i < it.slice.val.length)]
        rfl
      rw [iter_next_inside it inside]
      simp only [bind_ok]
      step as ⟨present, hpresent⟩
      split
      · simp
      · refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
          { it with i := it.i + 1 } rfl) ?_
        intro b hb no form mem plain
        rw [split_list] at mem
        rcases List.mem_cons.mp mem with same | rest
        · subst same; exact hpresent (by simp_all) plain
        · exact hb no form rest plain
    · simp only [iter_next_done it inside, bind_ok]
      apply (WP.spec_ok _).mpr
      intro _ form mem
      have : it.slice.val.drop it.i = [] := List.drop_eq_nil_of_le (by scalar_tac)
      rw [this] at mem
      cases mem

/-- **The extracted reflection check.** If it answers `false`, no
    case-sensitive form occurs anywhere in `data`. -/
@[step]
theorem reflects_spec (data : Slice U8) (forms : Slice proxy_http.Form) :
    reflects data forms ⦃ b => b = false →
      ∀ form ∈ forms.val, form.folded = false → ¬ Occurs data.val form.bytes.val ⦄ := by
  unfold reflects
  step as ⟨folded⟩
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  refine WP.spec_mono (reflects_loop_spec ⟨forms, 0⟩ data folded) ?_
  intro b h no
  simpa using h no

theorem dropped_response_ok (field : proxy_http.Field) : ∃ b, dropped_response field = Result.ok b := by
  unfold dropped_response
  simp only [lifted_slice, bind_ok, name_is_eq]
  split_ifs <;> simp

@[step]
theorem dropped_response_spec (field : proxy_http.Field) :
    dropped_response field ⦃ _ => True ⦄ := by
  obtain ⟨b, h⟩ := dropped_response_ok field
  rw [h]; simp

theorem returned_fields_loop_spec (it : core.slice.iter.Iter proxy_http.Field)
    (out : alloc.vec.Vec proxy_http.Field)
    (room : out.length + (it.slice.length - it.i) ≤ Usize.max) :
    returned_fields_loop it out ⦃ r => ∃ kept, r.val = out.val ++ kept ∧
      kept.Sublist (it.slice.val.drop it.i) ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter proxy_http.Field) (out : alloc.vec.Vec proxy_http.Field),
      it.slice.length - it.i = n → out.length + n ≤ Usize.max →
      returned_fields_loop it out ⦃ r => ∃ kept, r.val = out.val ++ kept ∧
        kept.Sublist (it.slice.val.drop it.i) ⦄ from this _ it out rfl room
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it out measure space
    rw [returned_fields_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have split_list : it.slice.val.drop it.i = it.slice[it.i] :: it.slice.val.drop (it.i + 1) := by
        rw [List.drop_eq_getElem_cons (by scalar_tac : it.i < it.slice.val.length)]
        rfl
      rw [iter_next_inside it inside]
      simp only [bind_ok]
      step as ⟨d⟩
      split
      · refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
          { it with i := it.i + 1 } out rfl (by scalar_tac)) ?_
        rintro r ⟨kept, hr, sub⟩
        refine ⟨kept, hr, ?_⟩
        rw [split_list]
        exact sub.cons _
      · simp only [bytes_clone_exact, bind_ok]
        have same : ({ «name» := it.slice[it.i].name, value := it.slice[it.i].value } :
            proxy_http.Field) = it.slice[it.i] := rfl
        rw [same]
        refine WP.spec_bind (alloc.vec.Vec.push_spec out it.slice[it.i] (by scalar_tac)) ?_
        intro pushed appended
        refine WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by scalar_tac)
          { it with i := it.i + 1 } pushed rfl
          (by simp [alloc.vec.Vec.length, appended]; scalar_tac)) ?_
        rintro r ⟨kept, hr, sub⟩
        refine ⟨it.slice[it.i] :: kept, by simp [hr, appended], ?_⟩
        rw [split_list]
        exact sub.cons_cons _
    · simp only [iter_next_done it inside, bind_ok]
      change (Result.ok out : Result (alloc.vec.Vec proxy_http.Field)) ⦃ r => ∃ kept,
        r.val = out.val ++ kept ∧ kept.Sublist (it.slice.val.drop it.i) ⦄
      simp only [WP.spec_ok]
      exact ⟨[], by simp, List.nil_sublist _⟩

@[step]
theorem returned_fields_spec (fields : Slice proxy_http.Field) :
    returned_fields fields ⦃ r => r.val.Sublist fields.val ⦄ := by
  unfold returned_fields
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  refine WP.spec_mono (returned_fields_loop_spec ⟨fields, 0⟩ (alloc.vec.Vec.new proxy_http.Field)
    (by simp [alloc.vec.Vec.new, alloc.vec.Vec.length])) ?_
  rintro r ⟨kept, hr, sub⟩
  simpa [alloc.vec.Vec.new, hr] using sub

theorem fields_bytes_sublist {a b : List proxy_http.Field} (sub : a.Sublist b) :
    (FieldsBytes a).length ≤ (FieldsBytes b).length := by
  induction sub with
  | slnil => simp
  | cons x _ ih => simp only [FieldsBytes, List.length_append]; omega
  | cons_cons x _ ih => simp only [FieldsBytes, List.length_append]; omega

open aivm_secrets_garrett_core.http_wire.Proofs (Digits)

/-- The bytes `encode_response` writes. -/
def ResponseBytes (response : proxy_http.Response) (fields : List proxy_http.Field)
    (keep head : Bool) : List U8 :=
  ascii "HTTP/1.1 " ++ Digits response.status.val ++ [32#u8] ++ response.reason.val ++ CRLF ++
    FieldsBytes fields ++ ascii "Content-Length: " ++ Digits response.body.length ++
    (if keep then ascii "\r\nConnection: keep-alive\r\n\r\n" else ascii "\r\nConnection: close\r\n\r\n") ++
    (if head then [] else response.body.val)

theorem status_prefix_bytes : ascii "HTTP/1.1 " =
    [72#u8, 84#u8, 84#u8, 80#u8, 47#u8, 49#u8, 46#u8, 49#u8, 32#u8] := by rfl

theorem keep_alive_bytes : ascii "\r\nConnection: keep-alive\r\n\r\n" =
    [13#u8, 10#u8, 67#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8,
     105#u8, 111#u8, 110#u8, 58#u8, 32#u8, 107#u8, 101#u8, 101#u8,
     112#u8, 45#u8, 97#u8, 108#u8, 105#u8, 118#u8, 101#u8, 13#u8, 10#u8,
     13#u8, 10#u8] := by rfl

theorem close_bytes : ascii "\r\nConnection: close\r\n\r\n" =
    [13#u8, 10#u8, 67#u8, 111#u8, 110#u8, 110#u8, 101#u8, 99#u8, 116#u8,
     105#u8, 111#u8, 110#u8, 58#u8, 32#u8, 99#u8, 108#u8, 111#u8,
     115#u8, 101#u8, 13#u8, 10#u8, 13#u8, 10#u8] := by rfl

/-- The `HEAD` encoding is a prefix of the full one: only the body differs. -/
theorem response_head_prefix (response : proxy_http.Response) (fields : List proxy_http.Field)
    (keep : Bool) :
    ResponseBytes response fields keep false = ResponseBytes response fields keep true ++
      response.body.val := by
  simp [ResponseBytes, List.append_assoc]

attribute [local scalar_tac_simps] Array.length_to_slice

theorem encode_response_contract (output : alloc.vec.Vec U8) (response : proxy_http.Response)
    (fields : Slice proxy_http.Field) (keep head : Bool)
    (room : output.length + (ResponseBytes response fields.val keep false).length ≤ Usize.max) :
    encode_response output response fields keep head ⦃ r =>
      r.val = output.val ++ ResponseBytes response fields.val keep head ⦄ := by
  have lengths := room
  simp only [ResponseBytes, CRLF, status_prefix_bytes, length_field_bytes, keep_alive_bytes,
    close_bytes, List.length_append, List.length_cons, List.length_nil] at lengths
  have status_val : (UScalar.cast .Usize response.status).val = response.status.val := by
    simp only [UScalar.cast_val_eq]
    apply Nat.mod_eq_of_lt
    have bound := response.status.hBounds
    have bits : 16 ≤ System.Platform.numBits := by
      rcases System.Platform.numBits_eq with h | h <;> omega
    calc response.status.val < 2 ^ 16 := by simpa using bound
      _ ≤ 2 ^ System.Platform.numBits := Nat.pow_le_pow_right (by decide) bits
  unfold encode_response
  simp only [lifted_slice, bind_ok]
  step*
  have output8_length :
      output8.length = output7.length + (Digits (alloc.vec.Vec.len response.body).val).length := by
    simp [alloc.vec.Vec.length, output8_post]
  have output6_length : output6.length = output5.length + (FieldsBytes fields.val).length := by
    simp [alloc.vec.Vec.length, output6_post]
  have output2_length : output2.length = output1.length + (Digits i.val).length := by
    simp [alloc.vec.Vec.length, output2_post]
  have body_len : (alloc.vec.Vec.len response.body).val = response.body.length := by scalar_tac
  cases keep <;> cases head <;>
    simp only [Bool.false_eq_true, ↓reduceIte] at lengths ⊢ <;>
    step* <;>
    simp_all [ResponseBytes, CRLF, status_prefix_bytes, length_field_bytes, keep_alive_bytes,
      close_bytes, List.append_assoc]

theorem response_bytes_length_mono (response : proxy_http.Response)
    {a b : List proxy_http.Field} (keep head : Bool)
    (shorter : (FieldsBytes a).length ≤ (FieldsBytes b).length) :
    (ResponseBytes response a keep head).length ≤ (ResponseBytes response b keep head).length := by
  simp only [ResponseBytes, List.length_append]
  omega

/-- **What the guest may receive.** For any upstream response and forms,
    `guest_response` either refuses (`Reflected`) and appends nothing, or
    appends bytes in which no case-sensitive form occurs. For `HEAD` the
    appended bytes are a prefix of the checked ones, so the same holds. -/
theorem guest_response_contract (output : alloc.vec.Vec U8) (response : proxy_http.Response)
    (forms : Slice proxy_http.Form) (keep head : Bool)
    (room : output.length + (ResponseBytes response response.fields.val keep false).length ≤
      Usize.max) :
    guest_response output response forms keep head ⦃ r =>
      (r.1 = .Ok () ∧ ∃ appended, r.2.val = output.val ++ appended ∧
        ∀ form ∈ forms.val, form.folded = false → ¬ Occurs appended form.bytes.val) ∨
      (r.1 ≠ .Ok () ∧ r.2 = output) ⦄ := by
  unfold guest_response
  step as ⟨fields, sub⟩
  simp only [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] at sub
  have fits : (ResponseBytes response fields.val keep false).length ≤
      (ResponseBytes response response.fields.val keep false).length :=
    response_bytes_length_mono response keep false (fields_bytes_sublist sub)
  refine WP.spec_bind (encode_response_contract (alloc.vec.Vec.new U8) response
    (alloc.vec.Vec.deref fields) keep false (by
      simp only [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]
      simp [alloc.vec.Vec.new, alloc.vec.Vec.length]; omega)) ?_
  intro full hfull
  have full_bytes : full.val = ResponseBytes response fields.val keep false := by
    simpa [alloc.vec.Vec.new, aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] using hfull
  step as ⟨found, hfound⟩
  split
  · simp
  · rename_i absent
    refine WP.spec_bind (encode_response_contract output response (alloc.vec.Vec.deref fields)
      keep head (by simp only [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val]; omega)) ?_
    intro written hwritten
    simp only [WP.spec_ok]
    left
    refine ⟨trivial, _, hwritten, ?_⟩
    intro form mem plain occurs
    have none := hfound (by simpa using absent) form mem plain
    apply none
    rw [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val, full_bytes]
    simp only [aivm_secrets_garrett_core.http_wire.Proofs.vec_deref_val] at occurs
    cases head
    · exact occurs
    · rw [response_head_prefix]
      exact occurs_append _ _ _ occurs

theorem bind_ok_inv {A B : Type} {first : Result A} {next : A → Result B} {out : B}
    (h : (first >>= next) = Result.ok out) : ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp_all

theorem push_ok_val {α : Type} {v w : alloc.vec.Vec α} {x : α}
    (h : alloc.vec.Vec.push v x = Result.ok w) : w.val = v.val ++ [x] := by
  unfold alloc.vec.Vec.push at h
  dsimp only at h
  split at h
  · simp only [Result.ok.injEq] at h
    subst h
    simp
  · simp at h

theorem push_or_keep {α : Type} {c : Prop} [Decidable c] {v w : alloc.vec.Vec α} {x : α}
    (h : (if c then alloc.vec.Vec.push v x else Result.ok v) = Result.ok w) :
    ∃ rest, w.val = v.val ++ rest := by
  split at h
  · exact ⟨[x], push_ok_val h⟩
  · simp only [Result.ok.injEq] at h; subst h; exact ⟨[], by simp⟩

/-- The search loop only appends forms. -/
theorem reflection_forms_loop_prefix (secret : Slice U8) :
    ∀ n (forms out : alloc.vec.Vec proxy_http.Form) (shift : Usize), 3 - shift.val = n →
      reflection_forms_loop secret forms shift = Result.ok out → ∃ rest, out.val = forms.val ++ rest := by
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro forms out shift measure returned
    rw [reflection_forms_loop.eq_def] at returned
    split at returned
    · obtain ⟨standard, _, after⟩ := bind_ok_inv returned
      obtain ⟨forms1, pushed1, after⟩ := bind_ok_inv after
      obtain ⟨url, _, after⟩ := bind_ok_inv after
      obtain ⟨forms2, pushed2, after⟩ := bind_ok_inv after
      obtain ⟨shift1, next, after⟩ := bind_ok_inv after
      obtain ⟨rest1, h1⟩ := push_or_keep pushed1
      obtain ⟨rest2, h2⟩ := push_or_keep pushed2
      have bound : shift1.val = shift.val + 1 := by
        have := (Usize.add_spec (x := shift) (y := 1#usize) (by scalar_tac))
        obtain ⟨z, hz, zv⟩ := returned_of_spec this
        rw [hz] at next
        simp only [Result.ok.injEq] at next
        subst next; scalar_tac
      obtain ⟨rest3, h3⟩ := ih (3 - shift1.val) (by scalar_tac) forms2 out shift1 rfl after
      exact ⟨rest1 ++ rest2 ++ rest3, by simp [h3, h2, h1, List.append_assoc]⟩
    · simp only [Result.ok.injEq] at returned
      subst returned
      exact ⟨[], by simp⟩

/-- **The raw credential is always a checked form.** If `reflection_forms`
    returns, its list contains the credential's exact bytes as a
    case-sensitive form, so `guest_response_contract` applies to them. -/
theorem reflection_forms_include_raw (secret : Slice U8) (forms : alloc.vec.Vec proxy_http.Form)
    (returned : reflection_forms secret = Result.ok forms) :
    ∃ form ∈ forms.val, form.folded = false ∧ form.bytes.val = secret.val := by
  unfold reflection_forms at returned
  obtain ⟨v, copied, after⟩ := bind_ok_inv returned
  obtain ⟨forms0, pushed0, after⟩ := bind_ok_inv after
  obtain ⟨_, _, after⟩ := bind_ok_inv after
  obtain ⟨forms1, pushed1, after⟩ := bind_ok_inv after
  obtain ⟨_, _, after⟩ := bind_ok_inv after
  obtain ⟨forms2, pushed2, after⟩ := bind_ok_inv after
  obtain ⟨rest, final⟩ := reflection_forms_loop_prefix secret _ forms2 forms 0#usize rfl after
  have same : v.slice = secret := by
    obtain ⟨w, hw, eq⟩ := returned_of_spec (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 secret
      (by intro x _; rfl))
    rw [hw] at copied
    simp only [Result.ok.injEq] at copied
    subst copied
    exact eq.symm
  refine ⟨{ bytes := v, folded := false }, ?_, rfl, ?_⟩
  · rw [final, push_ok_val pushed2, push_ok_val pushed1, push_ok_val pushed0]
    simp
  · simp [alloc.vec.Vec.val, ← same]

end aivm_secrets_garrett_core.proxy_http.Proofs
