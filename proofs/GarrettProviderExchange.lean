import GarrettReadTransition
import GarrettManifest

open Aeneas Aeneas.Std
set_option maxHeartbeats 2000000

/-!
The production provider driver, including mutable adapter/channel state.
`ReadRun` relates its actual callback returns to its returned report; there
is no separate executable request interpreter. Native TLS/Write/parser
implementations still require their explicit primitive contracts.
-/
namespace aivm_secrets_garrett_core.manifest.StampProofs

theorem current_success_iff (claims : credential_use.UseClaims) (grant : credential_use.UseGrant)
    (requested selected : alloc.vec.Vec U8) (write allowed : Bool) (now elapsed : I64)
    (stamp : AdmissionStamp) :
    current claims grant requested selected write allowed now elapsed = Result.ok (.Ok stamp) ↔
      authorize claims grant requested selected write allowed now elapsed = Result.ok (.Ok ()) ∧
      stamp = ⟨now, elapsed, write⟩ := by
  cases checked : authorize claims grant requested selected write allowed now elapsed using Result.cases with
  | ret out => cases out with
    | Err error => simp [current, checked]
    | Ok u => cases u; simp [current, checked, eq_comm]
  | vis effect continuation => simp [current, checked]
  | div => simp [current, checked]

theorem denied_current_preserves_error (claims : credential_use.UseClaims) (grant : credential_use.UseGrant)
    (requested selected : alloc.vec.Vec U8) (write allowed : Bool) (now elapsed : I64)
    (error : credential_use.UseDenial)
    (denied : authorize claims grant requested selected write allowed now elapsed = Result.ok (.Err error)) :
    current claims grant requested selected write allowed now elapsed = Result.ok (.Err error) := by
  simp [current, denied]

end aivm_secrets_garrett_core.manifest.StampProofs

namespace aivm_secrets_garrett_core.provider_exchange.Proofs

private theorem bind_returns_iff {A B : Type} (first : Result A)
    (next : A → Result B) (result : B) :
    (first >>= next) = Result.ok result ↔
      ∃ value, first = Result.ok value ∧ next value = Result.ok result := by
  cases first using Result.cases with
  | ret value => simp
  | vis effect continuation => simp
  | div => simp

def receipt {O X : Type} (phase : read_transition.Phase) (stage : Stage)
    (stamp : Option manifest.AdmissionStamp) (out : core.result.Result O X) : Report O X :=
  ⟨phase, stage, stamp, out⟩

/-- A relating predicate for returned runs of the extracted read driver. Each
    premise names an actual callback, exact input state/channel and returned
    state/channel. Failures are terminal prefixes; later callbacks are unused. -/
inductive ReadRun {P C O X : Type} (ops : Provider P C O X) (pending : P)
    (phase : read_transition.Phase) : Report O X → P → Prop where
  | setupDenied (after : P) (error : X)
      (setup : ops.setup pending = Result.ok (.Err error, after)) :
      ReadRun ops pending phase (receipt phase .Setup none (.Err error)) after
  | admissionDenied (channel : C) (s1 after : P) (error : X)
      (setup : ops.setup pending = Result.ok (.Ok channel, s1))
      (checked : ops.recheck s1 = Result.ok (.Err error, after)) :
      ReadRun ops pending phase (receipt phase .Admission none (.Err error)) after
  | sendDenied (channel nextChannel : C) (stamp : manifest.AdmissionStamp) (s1 s2 after : P) (error : X)
      (setup : ops.setup pending = Result.ok (.Ok channel, s1))
      (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
      (sent : ops.send s2 channel = Result.ok (.Err error, after, nextChannel)) :
      ReadRun ops pending phase (receipt phase .Send (some stamp) (.Err error)) after
  | responseDenied (channel nextChannel : C) (stamp : manifest.AdmissionStamp) (s1 s2 s3 after : P) (error : X)
      (setup : ops.setup pending = Result.ok (.Ok channel, s1))
      (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
      (sent : ops.send s2 channel = Result.ok (.Ok (), s3, nextChannel))
      (received : ops.receive s3 nextChannel = Result.ok (.Err error, after)) :
      ReadRun ops pending phase (receipt phase .Response (some stamp) (.Err error)) after
  | complete (channel nextChannel : C) (stamp : manifest.AdmissionStamp) (s1 s2 s3 after : P) (value : O)
      (setup : ops.setup pending = Result.ok (.Ok channel, s1))
      (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
      (sent : ops.send s2 channel = Result.ok (.Ok (), s3, nextChannel))
      (received : ops.receive s3 nextChannel = Result.ok (.Ok value, after)) :
      ReadRun ops pending phase (receipt phase .Complete (some stamp) (.Ok value)) after

theorem read_run_iff {P C O X : Type} (ops : Provider P C O X) (pending : P)
    (phase : read_transition.Phase) (report : Report O X) (after : P) :
    exchange ops pending ⟨phase, false⟩ = Result.ok (report, after) ↔
      ReadRun ops pending phase report after := by
  constructor
  · intro returned
    simp [exchange, read_transition.Audited.impl.phase, read_transition.Audited.is_write] at returned
    obtain ⟨⟨planned, s1⟩, setup, rest⟩ := (bind_returns_iff _ _ _).mp returned
    cases planned with
    | Err error =>
      have same : (receipt phase .Setup none (.Err error), s1) = (report, after) := by
        simpa [receipt] using rest
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
      exact .setupDenied _ _ setup
    | Ok channel =>
      obtain ⟨⟨checked, s2⟩, current, rest⟩ := (bind_returns_iff _ _ _).mp rest
      cases checked with
      | Err error =>
        have same : (receipt phase .Admission none (.Err error), s2) = (report, after) := by
          simpa [receipt] using rest
        obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
        exact .admissionDenied _ _ _ _ setup current
      | Ok stamp =>
        obtain ⟨⟨sent, s3, nextChannel⟩, sending, rest⟩ := (bind_returns_iff _ _ _).mp rest
        cases sent with
        | Err error =>
          have same : (receipt phase .Send (some stamp) (.Err error), s3) = (report, after) := by
            simpa [receipt] using rest
          obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
          exact .sendDenied _ _ _ _ _ _ _ setup current sending
        | Ok u =>
          cases u
          obtain ⟨⟨received, s4⟩, response, rest⟩ := (bind_returns_iff _ _ _).mp rest
          cases received with
          | Err error =>
            have same : (receipt phase .Response (some stamp) (.Err error), s4) = (report, after) := by
              simpa [receipt] using rest
            obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
            exact .responseDenied _ _ _ _ _ _ _ _ setup current sending response
          | Ok value =>
            have same : (receipt phase .Complete (some stamp) (.Ok value), s4) = (report, after) := by
              simpa [receipt] using rest
            obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
            exact .complete _ _ _ _ _ _ _ _ setup current sending response
  · intro run
    cases run <;> simp_all [exchange, read_transition.Audited.impl.phase,
      read_transition.Audited.is_write, receipt]


theorem returned_phase_is_input_phase {P C O X : Type} (ops : Provider P C O X)
    (pending after : P) (phase : read_transition.Phase) (report : Report O X)
    (returned : exchange ops pending ⟨phase, false⟩ = Result.ok (report, after)) :
    report.phase = phase := by
  cases (read_run_iff ops pending phase report after).mp returned <;> rfl

theorem attempted_read_has_actual_current_origin {P C O X : Type} (ops : Provider P C O X)
    (pending after : P) (phase : read_transition.Phase) (report : Report O X)
    (returned : exchange ops pending ⟨phase, false⟩ = Result.ok (report, after))
    (attempted : Stage.attempted report.stage = Result.ok true) :
    ∃ channel s1 s2 stamp, ops.setup pending = Result.ok (.Ok channel, s1) ∧
      ops.recheck s1 = Result.ok (.Ok stamp, s2) ∧ report.current = some stamp := by
  cases (read_run_iff ops pending phase report after).mp returned with
  | setupDenied => simp [receipt, Stage.attempted] at attempted
  | admissionDenied => simp [receipt, Stage.attempted] at attempted
  | sendDenied channel nextChannel stamp s1 s2 after error setup checked sent =>
      exact ⟨channel, s1, s2, stamp, setup, checked, rfl⟩
  | responseDenied channel nextChannel stamp s1 s2 s3 after error setup checked sent received =>
      exact ⟨channel, s1, s2, stamp, setup, checked, rfl⟩
  | complete channel nextChannel stamp s1 s2 s3 after value setup checked sent received =>
      exact ⟨channel, s1, s2, stamp, setup, checked, rfl⟩

theorem setup_failure_is_unsent {P C O X : Type} (ops : Provider P C O X)
    (pending after : P) (phase : read_transition.Phase) (error : X)
    (setup : ops.setup pending = Result.ok (.Err error, after)) :
    exchange ops pending ⟨phase, false⟩ =
      Result.ok (receipt phase .Setup none (.Err error), after) :=
  (read_run_iff ops pending phase _ after).mpr (.setupDenied _ _ setup)

theorem denied_current_is_unsent {P C O X : Type} (ops : Provider P C O X)
    (pending s1 after : P) (phase : read_transition.Phase) (channel : C) (error : X)
    (setup : ops.setup pending = Result.ok (.Ok channel, s1))
    (checked : ops.recheck s1 = Result.ok (.Err error, after)) :
    exchange ops pending ⟨phase, false⟩ =
      Result.ok (receipt phase .Admission none (.Err error), after) :=
  (read_run_iff ops pending phase _ after).mpr (.admissionDenied _ _ _ _ setup checked)

theorem read_send_failure_is_attempted {P C O X : Type} (ops : Provider P C O X)
    (pending s1 s2 after : P) (phase : read_transition.Phase) (channel nextChannel : C)
    (stamp : manifest.AdmissionStamp) (error : X)
    (setup : ops.setup pending = Result.ok (.Ok channel, s1))
    (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
    (sent : ops.send s2 channel = Result.ok (.Err error, after, nextChannel)) :
    exchange ops pending ⟨phase, false⟩ =
      Result.ok (receipt phase .Send (some stamp) (.Err error), after) :=
  (read_run_iff ops pending phase _ after).mpr (.sendDenied _ _ _ _ _ _ _ setup checked sent)

theorem read_response_failure_is_attempted {P C O X : Type} (ops : Provider P C O X)
    (pending s1 s2 s3 after : P) (phase : read_transition.Phase) (channel nextChannel : C)
    (stamp : manifest.AdmissionStamp) (error : X)
    (setup : ops.setup pending = Result.ok (.Ok channel, s1))
    (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
    (sent : ops.send s2 channel = Result.ok (.Ok (), s3, nextChannel))
    (received : ops.receive s3 nextChannel = Result.ok (.Err error, after)) :
    exchange ops pending ⟨phase, false⟩ =
      Result.ok (receipt phase .Response (some stamp) (.Err error), after) :=
  (read_run_iff ops pending phase _ after).mpr (.responseDenied _ _ _ _ _ _ _ _ setup checked sent received)

/-- Positive witness also retains the updated channel, exact sampled stamp
    and final adapter state. It is independent of unused callback outcomes. -/
theorem completed_read_witness {P C O X : Type} (ops : Provider P C O X)
    (pending s1 s2 s3 after : P) (phase : read_transition.Phase) (channel nextChannel : C)
    (stamp : manifest.AdmissionStamp) (value : O)
    (setup : ops.setup pending = Result.ok (.Ok channel, s1))
    (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
    (sent : ops.send s2 channel = Result.ok (.Ok (), s3, nextChannel))
    (received : ops.receive s3 nextChannel = Result.ok (.Ok value, after)) :
    exchange ops pending ⟨phase, false⟩ =
      Result.ok (receipt phase .Complete (some stamp) (.Ok value), after) :=
  (read_run_iff ops pending phase _ after).mpr (.complete _ _ _ _ _ _ _ _ setup checked sent received)

theorem read_stamp_cannot_authorize_writing_effect {P C O X : Type} (ops : Provider P C O X)
    (pending s1 after : P) (phase : read_transition.Phase) (channel : C)
    (stamp : manifest.AdmissionStamp) (error : X)
    (setup : ops.setup pending = Result.ok (.Ok channel, s1))
    (checked : ops.recheck s1 = Result.ok (.Ok stamp, after))
    (readOnly : stamp.write = false) (constant : ops.INVALID_POLICY = Result.ok error) :
    exchange ops pending ⟨phase, true⟩ =
      Result.ok (receipt phase .Admission (some stamp) (.Err error), after) := by
  simp [exchange, read_transition.Audited.impl.phase, read_transition.Audited.is_write,
    setup, checked, manifest.AdmissionStamp.impl.write, readOnly, constant, receipt]

theorem writing_send_failure_is_uncertain {P C O X : Type} (ops : Provider P C O X)
    (pending s1 s2 after : P) (phase : read_transition.Phase) (channel nextChannel : C)
    (stamp : manifest.AdmissionStamp) (error unknown : X)
    (setup : ops.setup pending = Result.ok (.Ok channel, s1))
    (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
    (sent : ops.send s2 channel = Result.ok (.Err error, after, nextChannel))
    (writing : stamp.write = true) (constant : ops.OUTCOME_UNKNOWN = Result.ok unknown) :
    exchange ops pending ⟨phase, true⟩ =
      Result.ok (receipt phase .Send (some stamp) (.Err unknown), after) := by
  simp [exchange, read_transition.Audited.impl.phase, read_transition.Audited.is_write,
    setup, checked, manifest.AdmissionStamp.impl.write, writing, sent, constant, receipt]

theorem writing_response_failure_is_uncertain {P C O X : Type} (ops : Provider P C O X)
    (pending s1 s2 s3 after : P) (phase : read_transition.Phase) (channel nextChannel : C)
    (stamp : manifest.AdmissionStamp) (error unknown : X)
    (setup : ops.setup pending = Result.ok (.Ok channel, s1))
    (checked : ops.recheck s1 = Result.ok (.Ok stamp, s2))
    (sent : ops.send s2 channel = Result.ok (.Ok (), s3, nextChannel))
    (received : ops.receive s3 nextChannel = Result.ok (.Err error, after))
    (writing : stamp.write = true) (constant : ops.OUTCOME_UNKNOWN = Result.ok unknown) :
    exchange ops pending ⟨phase, true⟩ =
      Result.ok (receipt phase .Response (some stamp) (.Err unknown), after) := by
  simp [exchange, read_transition.Audited.impl.phase, read_transition.Audited.is_write,
    setup, checked, manifest.AdmissionStamp.impl.write, writing, sent, received, constant, receipt]


theorem new_send_state_is_empty : SendState.new = Result.ok ⟨.Empty⟩ := rfl

theorem checking_is_required_to_record_stamp (state after : SendState)
    (stamp : manifest.AdmissionStamp) :
    SendState.finish_check state stamp = Result.ok (true, after) ↔
      state.progress = .Checking ∧ after = ⟨.Checked stamp⟩ := by
  cases state with
  | mk progress => cases progress <;> simp [SendState.finish_check, eq_comm]

theorem empty_is_required_to_begin_check (state after : SendState) :
    SendState.begin_check state = Result.ok (true, after) ↔
      state.progress = .Empty ∧ after = ⟨.Checking⟩ := by
  cases state with
  | mk progress => cases progress <;> simp [SendState.begin_check, eq_comm]

theorem successful_send_gate_iff (state after : SendState) (write : Bool) :
    SendState.begin_send state write = Result.ok (true, after) ↔
      ∃ stamp, state.progress = .Checked stamp ∧
        (write = true → stamp.write = true) ∧ after = ⟨.Attempted stamp⟩ := by
  cases state with
  | mk progress =>
    cases progress with
    | Empty => simp [SendState.begin_send]
    | Checking => simp [SendState.begin_send]
    | Halted => simp [SendState.begin_send]
    | Attempted stamp => simp [SendState.begin_send]
    | Checked stamp =>
      cases stamp with
      | mk now elapsed approved => cases write <;> cases approved <;>
          simp [SendState.begin_send, manifest.AdmissionStamp.impl.write] <;> exact eq_comm

theorem attempted_cannot_check_again (stamp : manifest.AdmissionStamp) :
    SendState.begin_check ⟨.Attempted stamp⟩ = Result.ok (false, ⟨.Attempted stamp⟩) := rfl

theorem attempted_cannot_replace_stamp (stamp other : manifest.AdmissionStamp) :
    SendState.finish_check ⟨.Attempted stamp⟩ other = Result.ok (false, ⟨.Attempted stamp⟩) := rfl

theorem attempted_cannot_send_again (stamp : manifest.AdmissionStamp) (write : Bool) :
    SendState.begin_send ⟨.Attempted stamp⟩ write = Result.ok (false, ⟨.Attempted stamp⟩) := rfl

theorem halted_cannot_send (write : Bool) :
    SendState.begin_send ⟨.Halted⟩ write = Result.ok (false, ⟨.Halted⟩) := rfl

theorem attempted_retains_exact_stamp (stamp : manifest.AdmissionStamp) :
    SendState.stamp ⟨.Attempted stamp⟩ = Result.ok (some stamp) ∧
      SendState.attempted ⟨.Attempted stamp⟩ = Result.ok true := ⟨rfl, rfl⟩

end aivm_secrets_garrett_core.provider_exchange.Proofs
