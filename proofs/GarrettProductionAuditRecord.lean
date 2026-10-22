import GarrettNR4Assurance

open Aeneas Aeneas.Std
set_option maxHeartbeats 6000000

/-!
The *actual Aeneas-extracted* durable audit record controller. The native
`Audit::write_record` now calls this controller while holding its mutex.
The first external append and the delimiter append are distinct effects,
followed by a sync callback; an error leaves the modeled attempt poisoned.

This is not a proof that `File::sync_all` is honest, that kernel writes are
atomic, or that panic/unwinding is represented by the returned-result model.
-/
namespace aivm_secrets_garrett_core.audit_record.Proofs

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

/-- A previously failed record cannot trigger even the first append callback.
    The state and the recorder are returned unchanged. -/
theorem poisoned_record_refuses_before_any_callback
    {S X : Type} (ops : audit_record.Sink S X) (sink : S)
    (bytes : alloc.vec.Vec U8) (error : X)
    (poisoned : ops.POISONED = Result.ok error) :
    audit_record.append_durable_record ops sink true bytes =
      Result.ok (.Err error, sink, true) := by
  simp [audit_record.append_durable_record, poisoned]

/-- Failure of the payload append consumes the audit attempt, even if the
    external writer has partially modified the file. No delimiter or sync
    callback is reached by this returned path. -/
theorem failed_payload_append_is_poisoned
    {S X : Type} (ops : audit_record.Sink S X)
    (sink after : S) (bytes : alloc.vec.Vec U8) (error : X)
    (failed : ops.append sink bytes = Result.ok (.Err error, after)) :
    audit_record.append_durable_record ops sink false bytes =
      Result.ok (.Err error, after, true) := by
  simp [audit_record.append_durable_record, failed]

/-- The source-owned record delimiter is precisely one LF byte. Its
    extraction is checked with the same Rust-generated definition as the
    production append controller. -/
theorem source_delimiter_is_exact_lf :
    ∃ delimiter : alloc.vec.Vec U8,
      audit_record.record_delimiter = Result.ok delimiter ∧
      delimiter.val = [10#u8] := by
  -- `Array.make` is Aeneas's *fixed-size* array, not Lean's ordinary
  -- `_root_.Array`. Let its type be inferred from its length index.
  let sourceArray := Array.make 1#usize [10#u8] (by rfl)
  let sourceVec : alloc.vec.Vec U8 :=
    alloc.slice.Slice.into_vec sourceArray.to_slice
  refine ⟨sourceVec, ?_, ?_⟩
  · -- The actual extracted body is `lift array.to_slice >>= into_vec`.
    simp only [audit_record.record_delimiter, lift, bind_ok,
      sourceVec, sourceArray]
  · -- `into_vec` preserves the slice list, and `make` has its given list.
    change sourceArray.val = [10#u8]
    exact Array.make_val _ _ _

/-- An actual successful returned record must have invoked all three
    callbacks in order, with the *same* captured payload and the exact LF
    delimiter, and can only clear the poison bit after the sync callback.
    Unlike an abstract `AuditAcknowledged` predicate, these witnesses are
    extracted from this particular successful source execution. -/
theorem returned_success_requires_exact_append_delimiter_sync
    {S X : Type} (ops : audit_record.Sink S X)
    (sink final : S) (bytes : alloc.vec.Vec U8)
    (returned : audit_record.append_durable_record ops sink false bytes =
      Result.ok (.Ok (), final, false)) :
    ∃ first second : S, ∃ delimiter : alloc.vec.Vec U8,
      audit_record.record_delimiter = Result.ok delimiter ∧
      delimiter.val = [10#u8] ∧
      ops.append sink bytes = Result.ok (.Ok (), first) ∧
      ops.append first delimiter = Result.ok (.Ok (), second) ∧
      ops.sync_record second = Result.ok (.Ok (), final) := by
  unfold audit_record.append_durable_record at returned
  obtain ⟨⟨payloadOut, first⟩, payloadCall, rest⟩ :=
    (bind_returns_iff _ _ _).mp returned
  cases payloadOut with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at rest
  | Ok u =>
    cases u
    -- Rust `?` binds the ControlFlow *first*.  It is not yet the call
    -- to `record_delimiter`, so eliminate this branch before peeling a
    -- second monadic bind.
    obtain ⟨flowPayload, payloadFlowCall, rest⟩ :=
      (bind_returns_iff _ _ _).mp rest
    have payloadContinues : flowPayload = .Continue () := by
      simpa [core.result.Result.Insts.CoreOpsTry.branch] using
        payloadFlowCall.symm
    subst flowPayload
    dsimp only at rest
    obtain ⟨delimiter, delimiterCall, rest⟩ :=
      (bind_returns_iff _ _ _).mp rest
    obtain ⟨⟨delimOut, second⟩, delimiterAppend, rest⟩ :=
      (bind_returns_iff _ _ _).mp rest
    cases delimOut with
    | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at rest
    | Ok u =>
      cases u
      obtain ⟨flowDelimiter, delimiterFlowCall, rest⟩ :=
        (bind_returns_iff _ _ _).mp rest
      have delimiterContinues : flowDelimiter = .Continue () := by
        simpa [core.result.Result.Insts.CoreOpsTry.branch] using
          delimiterFlowCall.symm
      subst flowDelimiter
      dsimp only at rest
      obtain ⟨⟨syncOut, afterSync⟩, synced, rest⟩ :=
        (bind_returns_iff _ _ _).mp rest
      cases syncOut with
      | Err error =>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at rest
      | Ok u =>
        cases u
        obtain ⟨flowSync, syncFlowCall, last⟩ :=
          (bind_returns_iff _ _ _).mp rest
        have syncContinues : flowSync = .Continue () := by
          simpa [core.result.Result.Insts.CoreOpsTry.branch] using
            syncFlowCall.symm
        subst flowSync
        dsimp only at last
        have same : afterSync = final := by simpa using last
        subst afterSync
        obtain ⟨lf, lfExact⟩ := source_delimiter_is_exact_lf
        have exactLine : delimiter = lf := by
          have okEqual : Result.ok delimiter = Result.ok lf :=
            delimiterCall.symm.trans lfExact.1
          simpa only [Result.ok.injEq] using okEqual
        subst delimiter
        exact ⟨first, second, lf, delimiterCall, lfExact.2,
          payloadCall, delimiterAppend, synced⟩

/-- A successful returned recorder invocation *cannot* skip the native
    payload append. Its exact argument is the captured byte vector. -/
theorem successful_record_has_payload_origin
    {S X : Type} (ops : audit_record.Sink S X)
    (sink final : S) (bytes : alloc.vec.Vec U8)
    (returned : audit_record.append_durable_record ops sink false bytes =
      Result.ok (.Ok (), final, false)) :
    ∃ after, ops.append sink bytes = Result.ok (.Ok (), after) := by
  unfold audit_record.append_durable_record at returned
  obtain ⟨⟨result, after⟩, appended, rest⟩ :=
    (bind_returns_iff _ _ _).mp returned
  cases result with
  | Err error => simp at rest
  | Ok u =>
    cases u
    exact ⟨after, appended⟩

/-- The fail-stop property is a concrete source consequence, not a caller-
    supplied audit sequencing axiom. This lemma targets the fully returned
    callback result and does not equate that result to physical disk receipt. -/
theorem returned_failure_does_not_leave_a_fresh_attempt
    {S X : Type} (ops : audit_record.Sink S X)
    (sink final : S) (bytes : alloc.vec.Vec U8) (error : X)
    (_returned : audit_record.append_durable_record ops sink false bytes =
      Result.ok (.Err error, final, true))
    (poisonedCode : ops.POISONED = Result.ok error) :
    audit_record.append_durable_record ops final true bytes =
      Result.ok (.Err error, final, true) := by
  exact poisoned_record_refuses_before_any_callback ops final bytes error poisonedCode

end aivm_secrets_garrett_core.audit_record.Proofs
