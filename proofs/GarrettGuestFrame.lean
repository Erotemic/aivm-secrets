import GarrettLineFrame

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 2000000

/-! Actual outbound framing and returning send decisions. JSON selection,
serialization, TLS delivery and non-returning I/O remain adapter obligations. -/
namespace aivm_secrets_garrett_core.guest_frame.Proofs

def Admitted (payload : alloc.vec.Vec U8) (limit : Usize) : Prop :=
  payload.val.length < limit.val ∧ 10#u8 ∉ payload.val

private theorem appended_line (payload : List U8) :
    line_frame.Proofs.CompleteLine (payload ++ [10#u8]) ↔ 10#u8 ∉ payload := by
  constructor
  · rintro ⟨before, same, absent⟩
    have equal : payload = before := List.append_cancel_right same
    simpa [equal] using absent
  · intro absent
    exact ⟨payload, rfl, absent⟩

@[step] theorem prepare_contract (payload : alloc.vec.Vec U8) (limit : Usize) :
    prepare payload limit ⦃ out => match out with
      | .Err _ => ¬Admitted payload limit
      | .Ok frame => Admitted payload limit ∧ frame.wire.val = payload.val ++ [10#u8] ∧ frame.attempted = false ⦄ := by
  unfold prepare
  by_cases large : alloc.vec.Vec.len payload >= limit
  · simp only [large, ↓reduceIte]
    apply (WP.spec_ok _).mpr
    intro valid
    have inside := valid.1
    scalar_tac
  · simp only [large, ↓reduceIte]
    apply WP.spec_bind (alloc.vec.Vec.push_spec payload 10#u8 (by scalar_tac))
    intro extended appended
    step
    apply WP.spec_bind (line_frame.Proofs.complete_contract (alloc.vec.Vec.deref extended) s1 limit)
    intro accepted contract
    cases accepted with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      apply (WP.spec_ok _).mpr
      intro admitted
      have line : line_frame.Proofs.Admitted (alloc.vec.Vec.deref extended) s1 limit := by
        refine ⟨?_, ?_, ?_⟩
        · simp only [alloc.vec.Vec.deref, Slice.length, Slice.from_val]
          rw [appended]
          simp only [List.length_append, List.length_singleton]
          scalar_tac
        · simp_all
        · simp only [alloc.vec.Vec.deref, Slice.from_val, appended, appended_line]
          exact admitted.2
      exact Bool.noConfusion (contract.mpr line)
    | true =>
      simp only [↓reduceIte]
      apply (WP.spec_ok _).mpr
      have valid := contract.mp rfl
      refine ⟨⟨by scalar_tac, ?_⟩, appended, rfl⟩
      have line : line_frame.Proofs.CompleteLine extended.val := by
        simpa only [alloc.vec.Vec.deref, Slice.from_val] using valid.2.2
      exact (appended_line payload.val).mp (appended ▸ line)

private theorem bind_returns_iff {A B : Type} (first : Result A) (next : A → Result B) (out : B) :
    (first >>= next) = Result.ok out ↔ ∃ value, first = Result.ok value ∧ next value = Result.ok out := by
  cases first using Result.cases <;> simp

/-- Returning attempts pass exactly the protected wire to the actual writer,
    preserving the callback error and both returned states. -/
theorem returning_send_iff {W X : Type} (ops : Writer W X) (frame after : Frame)
    (writer next : W) (out : core.result.Result Unit X) (ready : frame.attempted = false) :
    Frame.send ops frame writer = Result.ok (out, after, next) ↔
      ops.write_frame writer (alloc.vec.Vec.deref frame.wire) = Result.ok (out, next) ∧
        after = {frame with attempted := true} := by
  simp only [Frame.send, ready, Bool.false_eq_true, ↓reduceIte]
  constructor
  · intro returned
    obtain ⟨⟨actual, state⟩, callback, same⟩ := (bind_returns_iff _ _ _).mp returned
    simp at same
    obtain ⟨rfl, rfl, rfl⟩ := same
    exact ⟨callback, rfl⟩
  · rintro ⟨callback, rfl⟩
    simp [callback]

theorem attempted_frame_rejects_repeat {W X : Type} (ops : Writer W X) (frame : Frame)
    (writer : W) (code : X) (attempted : frame.attempted = true)
    (constant : ops.ALREADY_ATTEMPTED = Result.ok code) :
    Frame.send ops frame writer = Result.ok (.Err code, frame, writer) := by
  simp [Frame.send, attempted, constant]

theorem send_failure_keeps_attempt_and_wire {W X : Type} (ops : Writer W X) (frame after : Frame)
    (writer next : W) (error : X) (ready : frame.attempted = false)
    (returned : Frame.send ops frame writer = Result.ok (.Err error, after, next)) :
    after.attempted = true ∧ after.wire = frame.wire := by
  obtain ⟨_, rfl⟩ := (returning_send_iff ops frame after writer next (.Err error) ready).mp returned
  exact ⟨rfl, rfl⟩

/-- The encoder is total for every modeled vector and admits exactly bounded,
    newline-free opaque payloads. Successful encoding is not JSON validation. -/
theorem prepare_admitted_iff (payload : alloc.vec.Vec U8) (limit : Usize) :
    (∃ frame, prepare payload limit = Result.ok (.Ok frame)) ↔ Admitted payload limit := by
  obtain ⟨out, returned, contract⟩ := returned_of_spec (prepare_contract payload limit)
  cases out with
  | Err reason =>
    simp only [returned, Result.ok.injEq, reduceCtorEq, exists_false, false_iff]
    exact contract
  | Ok frame =>
    constructor
    · intro _; exact contract.1
    · intro _; exact ⟨frame, returned⟩

theorem prepared_wire_is_bounded_single_line (payload : alloc.vec.Vec U8) (limit : Usize)
    (frame : Frame) (returned : prepare payload limit = Result.ok (.Ok frame)) :
    frame.wire.val = payload.val ++ [10#u8] ∧ frame.wire.val.length ≤ limit.val ∧
      line_frame.Proofs.CompleteLine frame.wire.val ∧ frame.attempted = false := by
  have contract := prepare_contract payload limit
  rw [returned] at contract
  have valid := (WP.spec_ok _).mp contract
  refine ⟨valid.2.1, ?_, ?_, valid.2.2⟩
  · rw [valid.2.1]
    simp only [List.length_append, List.length_singleton]
    have fits := valid.1.1
    omega
  · rw [valid.2.1, appended_line]
    exact valid.1.2

/-- The preparation and actual writer call compose without re-encoding or
    substituting the selected payload, including returned writer errors. -/
theorem prepared_send_exact {W X : Type} (ops : Writer W X)
    (payload : alloc.vec.Vec U8) (limit : Usize) (frame after : Frame)
    (writer next : W) (out : core.result.Result Unit X)
    (prepared : prepare payload limit = Result.ok (.Ok frame))
    (sent : Frame.send ops frame writer = Result.ok (out, after, next)) :
    ops.write_frame writer (alloc.vec.Vec.deref frame.wire) = Result.ok (out, next) ∧
      frame.wire.val = payload.val ++ [10#u8] ∧ after.attempted = true ∧ after.wire = frame.wire := by
  have valid := prepared_wire_is_bounded_single_line payload limit frame prepared
  obtain ⟨callback, rfl⟩ := (returning_send_iff ops frame after writer next out valid.2.2.2).mp sent
  exact ⟨callback, valid.1, rfl, rfl⟩

/-- Even a returned error closes the send gate without touching the writer a
    second time. It says nothing about how many bytes the primitive delivered. -/
theorem failed_send_cannot_retry {W X : Type} (ops : Writer W X) (frame after : Frame)
    (writer next : W) (error refusal : X) (ready : frame.attempted = false)
    (returned : Frame.send ops frame writer = Result.ok (.Err error, after, next))
    (constant : ops.ALREADY_ATTEMPTED = Result.ok refusal) :
    Frame.send ops after next = Result.ok (.Err refusal, after, next) := by
  exact attempted_frame_rejects_repeat ops after next refusal
    (send_failure_keeps_attempt_and_wire ops frame after writer next error ready returned).1 constant

theorem prepared_positive_witness :
    ∃ (payload : alloc.vec.Vec U8) (frame : Frame),
      prepare payload 3#usize = Result.ok (.Ok frame) ∧ frame.wire.val = [123#u8, 125#u8, 10#u8] := by
  let payload := alloc.vec.Vec.from [123#u8, 125#u8] (by scalar_tac)
  have admitted : Admitted payload 3#usize := by
    constructor
    · simp [payload]
    · simp [payload]
  obtain ⟨frame, prepared⟩ := (prepare_admitted_iff payload 3#usize).mpr admitted
  exact ⟨payload, frame, prepared, by simpa [payload] using
    (prepared_wire_is_bounded_single_line payload 3#usize frame prepared).1⟩

end aivm_secrets_garrett_core.guest_frame.Proofs
