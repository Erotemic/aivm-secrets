import GarrettNR4ManifestRelease
import GarrettJsonReflection
import GarrettJsonFrame

/-!
# The production successful read frame

Source: `selected_release.rs` (`select`, `Manifest`, `checked`) and
`json_wire.rs` (`encode`, `prepare`), extracted by Aeneas. The bridge frames a
released read reply with `json_wire::prepare` on the extracted wire value
(`json::Reply::Released` -> `Captured::prepare`).

`production_read_frame` states what a successful read sends: the frame is the
JSON encoding of the reply assembled from the extracted projection of the
request's own provider document (plus extracted pagination metadata) and one
newline, and the credential occurs in neither the encoding nor any decoded key
or string. This replaces the NR-2/3 success theorem's `toCapturedJson`,
`Valid` and `Bound` premises for the production path.

Still trusted: the native parse of the provider body into the document, the
two-line native glue (`Reply::Released` framing via `Captured::prepare`,
checked by the W3 guard), and the guest writer's I/O.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
namespace aivm_secrets_garrett_core.selected_release.FrameProofs
open aivm_secrets_garrett_core.disclosure (Json)

private theorem bind_returns_iff {A B : Type} (first : Result A)
    (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔
      ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

/-- A released value passed both reflection checks: no decoded key or string
    of the reply contains the credential, and neither does its encoding. -/
theorem checked_success (reply : Json) (secret : alloc.vec.Vec U8) (wire : json_wire.Value)
    (h : selected_release.checked reply secret = Result.ok (.Ok wire)) :
    ¬ json_reflection.Proofs.Occurs (alloc.vec.Vec.deref secret) reply ∧
    selected_conversion.render_wire reply = Result.ok (.Ok wire) ∧
    ∃ bytes, json_wire.encode wire = Result.ok (.Ok bytes) ∧
      ¬ reflection.Proofs.LiteralOccurs (alloc.vec.Vec.deref bytes) (alloc.vec.Vec.deref secret) := by
  unfold selected_release.checked at h
  obtain ⟨safe, hsafe, h⟩ := (bind_returns_iff _ _ _).mp h
  cases safe with
  | false => simp at h
  | true =>
    simp only [↓reduceIte] at h
    obtain ⟨rendered, hrender, h⟩ := (bind_returns_iff _ _ _).mp h
    cases rendered with
    | Err _ => simp at h
    | Ok w =>
      simp only at h
      obtain ⟨encoded, henc, h⟩ := (bind_returns_iff _ _ _).mp h
      cases encoded with
      | Err _ => simp at h
      | Ok bytes =>
        simp only at h
        obtain ⟨found, hfound, h⟩ := (bind_returns_iff _ _ _).mp h
        cases found with
        | true => simp at h
        | false =>
          simp only [Bool.false_eq_true, ↓reduceIte, Result.ok.injEq, core.result.Result.Ok.injEq] at h
          subst h
          exact ⟨json_reflection.Proofs.accepted_excludes_literal _ _ _ hsafe, hrender,
            bytes, henc, reflection.Proofs.false_search_excludes_literal _ _ hfound⟩

/-- Framing a released value frames exactly its encoding and one newline. -/
theorem prepared_is_encoding (wire : json_wire.Value) (bytes : alloc.vec.Vec U8) (limit : Usize)
    (frame : guest_frame.Frame)
    (encoded : json_wire.encode wire = Result.ok (.Ok bytes))
    (prepared : json_wire.prepare wire limit = Result.ok (.Ok frame)) :
    frame.wire.val = bytes.val ++ [10#u8] ∧ frame.wire.val.length ≤ limit.val := by
  have framed : guest_frame.prepare bytes limit = Result.ok (.Ok frame) := by
    simpa [json_wire.prepare, encoded] using prepared
  have line := guest_frame.Proofs.prepared_wire_is_bounded_single_line bytes limit frame framed
  exact ⟨line.1, line.2.1⟩

open aivm_secrets_garrett_core.selected_release.Relational (manifestOps)

/-- The pagination metadata a successful release used: none without a page
    policy, otherwise exactly `metadata document page`. -/
def MetadataOf (document : Json) : Option selected_release.Page → Option Json → Prop
  | none, md => md = none
  | some page, md => ∃ m, selected_release.metadata document page = Result.ok (.Ok m) ∧ md = some m

/-- Every successful production release came from the extracted projection
    of the provider document, the extracted pagination metadata, the fixed
    reply envelope and a passing reflection check, all over the request's own
    document, schema, page policy and credential. -/
theorem successful_release_origin {C X : Type} (cur : selected_release.Current C X)
    (s done : selected_release.Manifest C X) (wire : json_wire.Value)
    (returned : selected_release.select (manifestOps cur) s = Result.ok (.Ok wire, done)) :
    ∃ fields budget selected md reply,
      s.fields = some fields ∧
      disclosure.project_fields s.document fields 9#usize budget = Result.ok (.Ok selected) ∧
      MetadataOf s.document s.page md ∧
      selected_release.assemble selected.value md = Result.ok reply ∧
      selected_release.checked reply s.secret = Result.ok (.Ok wire) := by
  obtain ⟨checked, paged, projected, assembled, md, sel, reply, hc, hp, hj, ha, hs⟩ :=
    selected_release.Proofs.every_successful_release_has_all_five_callbacks
      (manifestOps cur) s done wire returned
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.current] at hc
  obtain ⟨⟨r0, t0⟩, hcur, hc⟩ := (bind_returns_iff _ _ _).mp hc
  simp at hc
  obtain ⟨rfl, rfl⟩ := hc
  -- pagination
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.pagination] at hp
  have meta_of : MetadataOf s.document s.page md ∧
      paged = { current := t0, document := s.document, fields := s.fields, page := s.page, secret := s.secret } := by
    cases hpage : s.page with
    | none =>
      simp only [hpage] at hp
      simp only [Result.ok.injEq, Prod.mk.injEq, core.result.Result.Ok.injEq] at hp
      exact ⟨by simp [MetadataOf, hp.1], hp.2.symm⟩
    | some page =>
      simp only [hpage] at hp
      obtain ⟨r, hmeta, hp⟩ := (bind_returns_iff _ _ _).mp hp
      cases r with
      | Err denial =>
        obtain ⟨⟨_, _⟩, _, hp⟩ := (bind_returns_iff _ _ _).mp hp
        simp at hp
      | Ok m =>
        simp only [Result.ok.injEq, Prod.mk.injEq, core.result.Result.Ok.injEq] at hp
        exact ⟨⟨m, hmeta, hp.1.symm⟩, hp.2.symm⟩
  obtain ⟨hmd, rfl⟩ := meta_of
  -- projection
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.project] at hj
  cases hfields : s.fields with
  | none =>
    simp only [hfields] at hj
    obtain ⟨⟨_, _⟩, _, hj⟩ := (bind_returns_iff _ _ _).mp hj
    simp at hj
  | some fs =>
    simp only [hfields] at hj
    obtain ⟨i, _, hj⟩ := (bind_returns_iff _ _ _).mp hj
    obtain ⟨i1, _, hj⟩ := (bind_returns_iff _ _ _).mp hj
    obtain ⟨budget, _, hj⟩ := (bind_returns_iff _ _ _).mp hj
    obtain ⟨r, hproj, hj⟩ := (bind_returns_iff _ _ _).mp hj
    cases r with
    | Err _ =>
      obtain ⟨⟨_, _⟩, _, hj⟩ := (bind_returns_iff _ _ _).mp hj
      simp at hj
    | Ok selected =>
      simp only [Result.ok.injEq, Prod.mk.injEq, core.result.Result.Ok.injEq] at hj
      obtain ⟨rfl, rfl⟩ := hj
      -- assembly and check
      simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.assemble] at ha
      obtain ⟨j, hasm, ha⟩ := (bind_returns_iff _ _ _).mp ha
      simp only [Result.ok.injEq, Prod.mk.injEq] at ha
      obtain ⟨rfl, rfl⟩ := ha
      simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.check_safe] at hs
      obtain ⟨r, hchk, hs⟩ := (bind_returns_iff _ _ _).mp hs
      cases r with
      | Err _ =>
        obtain ⟨⟨_, _⟩, _, hs⟩ := (bind_returns_iff _ _ _).mp hs
        simp at hs
      | Ok w =>
        simp only [Result.ok.injEq, Prod.mk.injEq, core.result.Result.Ok.injEq] at hs
        obtain ⟨rfl, _⟩ := hs
        exact ⟨fs, budget, selected, md, j, rfl, hproj, hmd, hasm, hchk⟩

/-- **The production successful read frame, end to end.** When the extracted
    release returns `wire` and the bridge frames it, the bytes handed to the
    guest writer are exactly `bytes ++ "\n"`, where `bytes` is the JSON
    encoding of `wire`, `wire` is the rendering of the reply assembled from
    the extracted projection of *this request's* provider document under
    *this request's* host schema and pagination policy, and the credential
    occurs neither in `bytes` nor in any decoded key or string of the reply.
    No conversion function, validity or bound premise is assumed. -/
theorem production_read_frame {C X : Type} (cur : selected_release.Current C X)
    (s done : selected_release.Manifest C X) (wire : json_wire.Value)
    (limit : Usize) (frame : guest_frame.Frame)
    (returned : selected_release.select (manifestOps cur) s = Result.ok (.Ok wire, done))
    (prepared : json_wire.prepare wire limit = Result.ok (.Ok frame)) :
    ∃ fields budget selected md reply bytes,
      s.fields = some fields ∧
      disclosure.project_fields s.document fields 9#usize budget = Result.ok (.Ok selected) ∧
      MetadataOf s.document s.page md ∧
      selected_release.assemble selected.value md = Result.ok reply ∧
      selected_conversion.render_wire reply = Result.ok (.Ok wire) ∧
      json_wire.encode wire = Result.ok (.Ok bytes) ∧
      frame.wire.val = bytes.val ++ [10#u8] ∧ frame.wire.val.length ≤ limit.val ∧
      ¬ json_reflection.Proofs.Occurs (alloc.vec.Vec.deref s.secret) reply ∧
      ¬ reflection.Proofs.LiteralOccurs (alloc.vec.Vec.deref bytes) (alloc.vec.Vec.deref s.secret) := by
  obtain ⟨fields, budget, selected, md, reply, hf, hproj, hmd, hasm, hchk⟩ :=
    successful_release_origin cur s done wire returned
  obtain ⟨decoded, rendered, bytes, encoded, literal⟩ := checked_success reply s.secret wire hchk
  obtain ⟨wireBytes, bound⟩ := prepared_is_encoding wire bytes limit frame encoded prepared
  exact ⟨fields, budget, selected, md, reply, bytes, hf, hproj, hmd, hasm, rendered, encoded,
    wireBytes, bound, decoded, literal⟩

end aivm_secrets_garrett_core.selected_release.FrameProofs
