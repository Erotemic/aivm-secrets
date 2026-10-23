import GarrettProductionSelectedRelease
import GarrettDisclosure

/-!
# NR-4: the production read release depends only on declassified data

Source: `rust/crates/aivm-secrets-garrett-core/src/selected_release.rs`
(`select`, `Manifest`, `metadata`, `rows_at`, `assemble`, `checked`), extracted
by Aeneas. The native manifest session builds `Manifest` from the parsed
provider document and calls `select`; the bridge frames the released wire
value directly (`json::Reply::Released`).

`manifest_release_noninterference` proves: for any native current-control
callback, two runs whose provider documents satisfy `DocumentsAgree` (the same
JSON at every host-selected path, and the same row count at the pagination
path) release the same wire value or refuse with the same error. Everything
else in the provider response is invisible to the guest through this path.

What this replaces: the earlier NR-4 statements needed a native conversion
`toJson`, a `SelectedConversion` premise linking it to the selection, and
selections not tied to the run. Those were native gaps; this theorem is about
the extracted function the bridge actually calls. It also exposes the
pagination channel (row count) that those premises hid.

Still outside this theorem: the native parse of the provider body into the
`Json` document, the native current-control callback's own behaviour (any
behaviour is allowed, but both runs must use the same one), the credential
(both runs use the same `secret`; reflection refusals are a separate,
documented declassification), and the TLS/guest writer I/O.
-/

open Aeneas Aeneas.Std
namespace aivm_secrets_garrett_core.selected_release.Relational

/-- Two stateful computations return the same value whenever either returns,
    with related final states. Failures and divergence are matched in that
    neither side can return while the other does not. -/
def Lift {W α : Type} (rel : W → W → Prop) (x y : Result (α × W)) : Prop :=
  (∀ r a, x = Result.ok (r, a) → ∃ b, y = Result.ok (r, b) ∧ rel a b) ∧
  (∀ r b, y = Result.ok (r, b) → ∃ a, x = Result.ok (r, a) ∧ rel a b)

private theorem bind_returns_iff {A B : Type} (first : Result A)
    (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔
      ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

theorem lift_bind {W α β : Type} {rel : W → W → Prop}
    (x y : Result (α × W)) (k₁ k₂ : α × W → Result (β × W))
    (hx : Lift rel x y) (hk : ∀ r a b, rel a b → Lift rel (k₁ (r, a)) (k₂ (r, b))) :
    Lift rel (x >>= k₁) (y >>= k₂) := by
  constructor
  · intro r a h
    obtain ⟨⟨v, s⟩, hx1, hk1⟩ := (bind_returns_iff _ _ _).mp h
    obtain ⟨t, hy, rel1⟩ := hx.1 v s hx1
    obtain ⟨b, hk2, rel2⟩ := (hk v s t rel1).1 r a hk1
    exact ⟨b, (bind_returns_iff _ _ _).mpr ⟨(v, t), hy, hk2⟩, rel2⟩
  · intro r b h
    obtain ⟨⟨v, t⟩, hy1, hk1⟩ := (bind_returns_iff _ _ _).mp h
    obtain ⟨s, hx, rel1⟩ := hx.2 v t hy1
    obtain ⟨a, hk2, rel2⟩ := (hk v s t rel1).2 r b hk1
    exact ⟨a, (bind_returns_iff _ _ _).mpr ⟨(v, s), hx, hk2⟩, rel2⟩

theorem lift_ok {W α : Type} {rel : W → W → Prop} (r : α) (a b : W) (h : rel a b) :
    Lift rel (Result.ok (r, a)) (Result.ok (r, b)) :=
  ⟨fun r' a' e => by
      simp only [Result.ok.injEq, Prod.mk.injEq] at e
      obtain ⟨rfl, rfl⟩ := e; exact ⟨b, rfl, h⟩,
   fun r' b' e => by
      simp only [Result.ok.injEq, Prod.mk.injEq] at e
      obtain ⟨rfl, rfl⟩ := e; exact ⟨a, rfl, h⟩⟩

attribute [local simp] core.result.Result.Insts.CoreOpsTry.branch
attribute [local simp] core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual
attribute [local simp] core.convert.FromSame

/-- `lift_bind` for the `let (r, w) ← x` pattern Aeneas emits. -/
theorem lift_bind_pair {W α β : Type} {rel : W → W → Prop}
    (x y : Result (α × W)) (k₁ k₂ : α → W → Result (β × W))
    (hx : Lift rel x y) (hk : ∀ r a b, rel a b → Lift rel (k₁ r a) (k₂ r b)) :
    Lift rel (do let (r, w) ← x; k₁ r w) (do let (r, w) ← y; k₂ r w) :=
  lift_bind x y (fun p => k₁ p.1 p.2) (fun p => k₂ p.1 p.2) hx (fun r a b h => hk r a b h)

/-- If every callback maps related states to the same result and related
    states, so does the extracted five-step `select` controller. -/
theorem select_lift {W M S R L X : Type} (ops : selected_release.Work W M S R L X)
    (rel : W → W → Prop)
    (current : ∀ a b, rel a b → Lift rel (ops.current a) (ops.current b))
    (pagination : ∀ a b, rel a b → Lift rel (ops.pagination a) (ops.pagination b))
    (project : ∀ a b, rel a b → Lift rel (ops.project a) (ops.project b))
    (assemble : ∀ a b selected metadata, rel a b →
      Lift rel (ops.assemble a selected metadata) (ops.assemble b selected metadata))
    (check : ∀ a b reply, rel a b → Lift rel (ops.check_safe a reply) (ops.check_safe b reply))
    (a b : W) (related : rel a b) :
    Lift rel (selected_release.select ops a) (selected_release.select ops b) := by
  unfold selected_release.select
  apply lift_bind_pair _ _ _ _ (current a b related)
  intro r a1 b1 h1
  cases r with
  | Err e => simpa using lift_ok _ _ _ h1
  | Ok u =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
    apply lift_bind_pair _ _ _ _ (pagination a1 b1 h1)
    intro r a2 b2 h2
    cases r with
    | Err e => simpa using lift_ok _ _ _ h2
    | Ok md =>
      simp only [bind_ok]
      apply lift_bind_pair _ _ _ _ (project a2 b2 h2)
      intro r a3 b3 h3
      cases r with
      | Err e => simpa using lift_ok _ _ _ h3
      | Ok sel =>
        simp only [bind_ok]
        apply lift_bind_pair _ _ _ _ (assemble a3 b3 sel md h3)
        intro reply a4 b4 h4
        exact check a4 b4 reply h4

/-- Running one shared computation and building related states from its
    result preserves `Lift`. -/
theorem lift_value_same {W α β : Type} {rel : W → W → Prop}
    (x : Result α) (k₁ k₂ : α → Result (β × W)) (h : ∀ v, Lift rel (k₁ v) (k₂ v)) :
    Lift rel (x >>= k₁) (x >>= k₂) := by
  constructor
  · intro r a e
    obtain ⟨v, hx, hk⟩ := (bind_returns_iff _ _ _).mp e
    obtain ⟨b, hb, rel1⟩ := (h v).1 r a hk
    exact ⟨b, (bind_returns_iff _ _ _).mpr ⟨v, hx, hb⟩, rel1⟩
  · intro r b e
    obtain ⟨v, hx, hk⟩ := (bind_returns_iff _ _ _).mp e
    obtain ⟨a, ha, rel1⟩ := (h v).2 r b hk
    exact ⟨a, (bind_returns_iff _ _ _).mpr ⟨v, hx, ha⟩, rel1⟩

open aivm_secrets_garrett_core.disclosure (Json Field)
open aivm_secrets_garrett_core.disclosure.Proofs (boundedLookup)

/-- **The declassification.** Two provider documents are indistinguishable to
    the read release when every host-selected path looks up the same JSON and
    the pagination row array has the same length. Nothing else about the
    documents is constrained. -/
def DocumentsAgree (d₁ d₂ : Json) (fields : Option (alloc.vec.Vec Field))
    (page : Option selected_release.Page) : Prop :=
  (∀ fs, fields = some fs → ∀ f ∈ fs.val,
    boundedLookup d₁ f.projection.at = boundedLookup d₂ f.projection.at) ∧
  (∀ p, page = some p → selected_release.rows_at d₁ p.at 0#usize =
    selected_release.rows_at d₂ p.at 0#usize)

/-- Release states that differ only in an agreeing provider document. -/
def Related {C X : Type} (s₁ s₂ : selected_release.Manifest C X) : Prop :=
  s₁.current = s₂.current ∧ s₁.fields = s₂.fields ∧ s₁.page = s₂.page ∧
    s₁.secret = s₂.secret ∧ DocumentsAgree s₁.document s₂.document s₁.fields s₁.page

theorem related_current {C X : Type} {s₁ s₂ : selected_release.Manifest C X}
    (h : Related s₁ s₂) (t : C) :
    Related (X := X) { s₁ with current := t } { s₂ with current := t } :=
  ⟨rfl, h.2.1, h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩

/-- Pagination metadata depends on the document only through `rows_at`. -/
theorem metadata_congr (d₁ d₂ : Json) (p : selected_release.Page)
    (rows : selected_release.rows_at d₁ p.at 0#usize = selected_release.rows_at d₂ p.at 0#usize) :
    selected_release.metadata d₁ p = selected_release.metadata d₂ p := by
  unfold selected_release.metadata
  rw [rows]

abbrev manifestOps {C X : Type} (cur : selected_release.Current C X) :=
  selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error cur

theorem current_lift {C X : Type} (cur : selected_release.Current C X)
    (s₁ s₂ : selected_release.Manifest C X) (h : Related s₁ s₂) :
    Lift Related ((manifestOps cur).current s₁) ((manifestOps cur).current s₂) := by
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.current]
  rw [h.1]
  exact lift_value_same _ _ _ (fun v => lift_ok _ _ _ (related_current h v.2))

theorem pagination_lift {C X : Type} (cur : selected_release.Current C X)
    (s₁ s₂ : selected_release.Manifest C X) (h : Related s₁ s₂) :
    Lift Related ((manifestOps cur).pagination s₁) ((manifestOps cur).pagination s₂) := by
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.pagination]
  have ⟨cur_eq, _, page_eq, _, _, rows⟩ := h
  rw [← page_eq]
  cases hp : s₁.page with
  | none => exact lift_ok _ _ _ h
  | some p =>
    simp only []
    rw [metadata_congr _ _ p (rows p hp)]
    apply lift_value_same
    intro r
    cases r with
    | Ok md => exact lift_ok _ _ _ h
    | Err denial =>
      rw [cur_eq]
      refine lift_value_same _ _ _ (fun v => lift_ok _ _ _ ?_)
      have kept := related_current h v.2
      rw [hp, ← page_eq, hp] at kept
      exact kept

theorem project_lift {C X : Type} (cur : selected_release.Current C X)
    (s₁ s₂ : selected_release.Manifest C X) (h : Related s₁ s₂) :
    Lift Related ((manifestOps cur).project s₁) ((manifestOps cur).project s₂) := by
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.project]
  have ⟨cur_eq, fields_eq, _, _, lookups, _⟩ := h
  rw [← fields_eq]
  cases hf : s₁.fields with
  | none =>
    simp only []
    rw [cur_eq]
    refine lift_value_same _ _ _ (fun v => lift_ok _ _ _ ?_)
    have kept := related_current h v.2
    rw [hf, ← fields_eq, hf] at kept
    exact kept
  | some fs =>
    simp only []
    apply lift_value_same; intro i
    apply lift_value_same; intro i1
    apply lift_value_same; intro i2
    rw [disclosure.Proofs.root_fields_noninterference s₁.document s₂.document fs 9#usize i2
      (lookups fs hf)]
    apply lift_value_same
    intro r
    cases r with
    | Ok selected => exact lift_ok _ _ _ h
    | Err _ =>
      rw [cur_eq]
      refine lift_value_same _ _ _ (fun v => lift_ok _ _ _ ?_)
      have kept := related_current h v.2
      rw [hf, ← fields_eq, hf] at kept
      exact kept

theorem assemble_lift {C X : Type} (cur : selected_release.Current C X)
    (s₁ s₂ : selected_release.Manifest C X) (selected : Json) (md : Option Json)
    (h : Related s₁ s₂) :
    Lift Related ((manifestOps cur).assemble s₁ selected md)
      ((manifestOps cur).assemble s₂ selected md) := by
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.assemble]
  exact lift_value_same _ _ _ (fun j => lift_ok _ _ _ h)

theorem check_lift {C X : Type} (cur : selected_release.Current C X)
    (s₁ s₂ : selected_release.Manifest C X) (reply : Json) (h : Related s₁ s₂) :
    Lift Related ((manifestOps cur).check_safe s₁ reply)
      ((manifestOps cur).check_safe s₂ reply) := by
  simp only [selected_release.Manifest.Insts.Aivm_secrets_garrett_coreSelected_releaseWorkJsonJsonJsonValueClause0_Error.check_safe]
  have ⟨cur_eq, _, _, secret_eq, _⟩ := h
  rw [secret_eq]
  apply lift_value_same
  intro r
  cases r with
  | Ok wire => exact lift_ok _ _ _ h
  | Err denial =>
    rw [cur_eq]
    refine lift_value_same _ _ _ (fun v => lift_ok _ _ _ ?_)
    have kept := related_current h v.2
    rw [secret_eq] at kept
    exact kept

/-- **Read-release noninterference (NR-4, production pipeline).**
    The production read release (`selected_release::select` over
    `selected_release::Manifest`, the exact Rust the bridge calls) gives the
    same outcome (the same released wire value, or the same refusal) for any
    two provider documents that agree on `DocumentsAgree`: the JSON at the
    host-selected paths and the pagination row count. Every other byte of the
    provider response, including credential reflections outside the selected
    paths, cannot influence what is released. The native `Current` callback
    is arbitrary; the theorem holds for every implementation of it. -/
theorem manifest_release_noninterference {C X : Type} (cur : selected_release.Current C X)
    (s₁ s₂ : selected_release.Manifest C X) (h : Related s₁ s₂) :
    Lift Related (selected_release.select (manifestOps cur) s₁)
      (selected_release.select (manifestOps cur) s₂) :=
  select_lift (manifestOps cur) Related (current_lift cur) (pagination_lift cur)
    (project_lift cur) (assemble_lift cur) (check_lift cur) s₁ s₂ h

/-- The same statement as an equation on the released outcome. -/
theorem manifest_release_same_outcome {C X : Type} (cur : selected_release.Current C X)
    (s₁ s₂ : selected_release.Manifest C X) (h : Related s₁ s₂)
    (out : core.result.Result json_wire.Value X) (done : selected_release.Manifest C X)
    (released : selected_release.select (manifestOps cur) s₁ = Result.ok (out, done)) :
    ∃ done₂, selected_release.select (manifestOps cur) s₂ = Result.ok (out, done₂) := by
  obtain ⟨b, hb, _⟩ := (manifest_release_noninterference cur s₁ s₂ h).1 out done released
  exact ⟨b, hb⟩

end aivm_secrets_garrett_core.selected_release.Relational
