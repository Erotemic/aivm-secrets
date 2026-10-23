import GarrettProductionAuditRecord

open Aeneas Aeneas.Std
set_option maxHeartbeats 6500000

/-!
Aeneas-extracted actual selected-result controller called by
`ManifestSelection` from `PendingCompletion.select`. Unlike the old opaque
native closure, the core owns *the entire five-callback release schedule*.
Callback implementations (current authority, pagination, native JSON
projection/assembly and reflection predicate) remain independent obligations.
-/
namespace aivm_secrets_garrett_core.selected_release.Proofs

private theorem bind_returns_iff {A B : Type} (first : Result A)
    (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔
      ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

-- Aeneas translates each Rust `?` into these explicit ControlFlow primitives.
-- Reduce them when proving the returned callback prefixes.
attribute [local simp] core.result.Result.Insts.CoreOpsTry.branch
attribute [local simp] core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual
attribute [local simp] core.convert.FromSame

/-- Current-control failure refuses before metadata, projection, assembly,
    or reflection callbacks. -/
theorem stale_current_control_refuses_release
    {W M S R L X : Type} (ops : selected_release.Work W M S R L X)
    (start after : W) (error : X)
    (rejected : ops.current start = Result.ok (.Err error, after)) :
    selected_release.select ops start = Result.ok (.Err error, after) := by
  simp [selected_release.select, rejected]

/-- A failed pagination callback is terminal: the projection has not been
    called and there is no selected public reply. -/
theorem pagination_denial_stops_before_projection
    {W M S R L X : Type} (ops : selected_release.Work W M S R L X)
    (start checked failed : W) (error : X)
    (fresh : ops.current start = Result.ok (.Ok (), checked))
    (denied : ops.pagination checked = Result.ok (.Err error, failed)) :
    selected_release.select ops start = Result.ok (.Err error, failed) := by
  simp [selected_release.select, fresh, denied]

/-- Failure in the actual native projection is terminal before any JSON
    assembly or reflected-secret check. -/
theorem failed_projection_refuses_release
    {W M S R L X : Type} (ops : selected_release.Work W M S R L X)
    (start checked paged refused : W) (metadata : Option M) (error : X)
    (fresh : ops.current start = Result.ok (.Ok (), checked))
    (page : ops.pagination checked = Result.ok (.Ok metadata, paged))
    (denied : ops.project paged = Result.ok (.Err error, refused)) :
    selected_release.select ops start = Result.ok (.Err error, refused) := by
  simp [selected_release.select, fresh, page, denied]

/-- A reflection rejection cannot be converted into a successful public
    release after the reply has been assembled. -/
theorem rejected_reflection_refuses_assembled_reply
    {W M S R L X : Type} (ops : selected_release.Work W M S R L X)
    (start checked paged projected assembled rejected : W)
    (metadata : Option M) (selected : S) (reply : R) (error : X)
    (fresh : ops.current start = Result.ok (.Ok (), checked))
    (page : ops.pagination checked = Result.ok (.Ok metadata, paged))
    (project : ops.project paged = Result.ok (.Ok selected, projected))
    (assemble : ops.assemble projected selected metadata = Result.ok (reply, assembled))
    (reflectionDenied : ops.check_safe assembled reply = Result.ok (.Err error, rejected)) :
    selected_release.select ops start = Result.ok (.Err error, rejected) := by
  simp [selected_release.select, fresh, page, project, assemble, reflectionDenied]

/-- Positive witness for exactly the *real extracted* five callbacks. The
    successful controller yields only the value released by `check_safe` from
    the assembled reply; nothing else can be returned. -/
theorem five_accepted_callbacks_release_only_checked_reply
    {W M S R L X : Type} (ops : selected_release.Work W M S R L X)
    (start checked paged projected assembled done : W)
    (metadata : Option M) (selected : S) (reply : R) (released : L)
    (fresh : ops.current start = Result.ok (.Ok (), checked))
    (page : ops.pagination checked = Result.ok (.Ok metadata, paged))
    (project : ops.project paged = Result.ok (.Ok selected, projected))
    (assemble : ops.assemble projected selected metadata = Result.ok (reply, assembled))
    (safe : ops.check_safe assembled reply = Result.ok (.Ok released, done)) :
    selected_release.select ops start = Result.ok (.Ok released, done) := by
  simp [selected_release.select, fresh, page, project, assemble, safe]

/-- Reverse direction: a successful *actual returned* release necessarily
    has a current check, accepted pagination, projection, an assembled reply,
    and a successful reflection check that released the returned value from
    that exact reply, in order.
    These callback witnesses are not chosen by the theorem caller. -/
theorem every_successful_release_has_all_five_callbacks
    {W M S R L X : Type} (ops : selected_release.Work W M S R L X)
    (start done : W) (released : L)
    (returned : selected_release.select ops start = Result.ok (.Ok released, done)) :
    ∃ checked paged projected assembled : W, ∃ metadata : Option M, ∃ selected : S,
      ∃ reply : R,
      ops.current start = Result.ok (.Ok (), checked) ∧
      ops.pagination checked = Result.ok (.Ok metadata, paged) ∧
      ops.project paged = Result.ok (.Ok selected, projected) ∧
      ops.assemble projected selected metadata = Result.ok (reply, assembled) ∧
      ops.check_safe assembled reply = Result.ok (.Ok released, done) := by
  unfold selected_release.select at returned
  obtain ⟨⟨currentResult, checked⟩, first, rest⟩ :=
    (bind_returns_iff _ _ _).mp returned
  cases currentResult with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at rest
  | Ok u =>
    cases u
    obtain ⟨flowCurrent, currentFlowCall, rest⟩ :=
      (bind_returns_iff _ _ _).mp rest
    have currentContinues : flowCurrent = .Continue () := by
      simpa [core.result.Result.Insts.CoreOpsTry.branch] using
        currentFlowCall.symm
    subst flowCurrent
    dsimp only at rest
    obtain ⟨⟨paginationResult, paged⟩, second, rest⟩ :=
      (bind_returns_iff _ _ _).mp rest
    cases paginationResult with
    | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at rest
    | Ok metadata =>
      obtain ⟨flowPagination, paginationFlowCall, rest⟩ :=
        (bind_returns_iff _ _ _).mp rest
      have paginationContinues : flowPagination = .Continue metadata := by
        simpa [core.result.Result.Insts.CoreOpsTry.branch] using
          paginationFlowCall.symm
      subst flowPagination
      dsimp only at rest
      obtain ⟨⟨projectResult, projected⟩, third, rest⟩ :=
        (bind_returns_iff _ _ _).mp rest
      cases projectResult with
      | Err error =>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at rest
      | Ok selected =>
        obtain ⟨flowProject, projectFlowCall, rest⟩ :=
          (bind_returns_iff _ _ _).mp rest
        have projectContinues : flowProject = .Continue selected := by
          simpa [core.result.Result.Insts.CoreOpsTry.branch] using
            projectFlowCall.symm
        subst flowProject
        dsimp only at rest
        obtain ⟨⟨assembledReply, assembled⟩, fourth, last⟩ :=
          (bind_returns_iff _ _ _).mp rest
        exact ⟨checked, paged, projected, assembled, metadata, selected,
          assembledReply, first, second, third, fourth, last⟩

end aivm_secrets_garrett_core.selected_release.Proofs
