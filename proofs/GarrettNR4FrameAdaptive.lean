import GarrettNR4ExchangeAdaptive
import GarrettPublicError

/-!
# NR-4: adaptive noninterference over the guest's frames

`adaptive_exchange_noninterference` compares raw outcomes, so a transport
failure in the two worlds had to be the *same native error*. The guest never
sees a native error: the bridge (`GuestFrame::from_answer`) frames every
failure with the extracted `public_error::denial_frame` of its public code and
every success with the extracted `json_wire.prepare`. This module states the
theorem at that boundary.

The guest's strategy now chooses each request from the earlier *frames*, and
two worlds need only agree on the public code (`pub`) of a transport failure,
not on the native error. With `denial_frame_exact`, a failure frame is one of
the 17 fixed lines, so per failed request the guest learns at most which of
17 codes the native mapping chose: that is the declassification, stated
explicitly, in place of the assumption that native errors carry no
provider-private data.

Trusted here: the bridge applies exactly `productionFrame` (pinned by the
NR-4 edge guard, `NATIVE-GLUE-01`), and `pub` is the native `From<Error>` for
`PublicError`, which may be any function.
-/

open Aeneas Aeneas.Std

namespace aivm_secrets_garrett_core.selected_release.FrameBoundary
open aivm_secrets_garrett_core.selected_release.Relational
open aivm_secrets_garrett_core.selected_release.Adaptive
open aivm_secrets_garrett_core.selected_release.Transport
open aivm_secrets_garrett_core.disclosure (Json)

variable {C X Q O P : Type}

/-- An adaptive guest that observes frames: `frame` turns each outcome into
    what the guest reads, and `strategy` picks the next request from those. -/
structure FrameSession (C X Q O : Type) where
  cur : selected_release.Current C X
  host : Q → Json → selected_release.Manifest C X
  strategy : List O → Q
  frame : core.result.Result json_wire.Value X → O

/-- The host side of one request `q` (a step does not consult the strategy). -/
def FrameSession.at (s : FrameSession C X Q O) (q : Q) : Session C X Q :=
  ⟨s.cur, fun _ => q, s.host⟩

/-- A full adaptive session, observed as frames. -/
inductive Frames (s : FrameSession C X Q O) (statusError : provider_status.StatusDenial → X)
    (provider : Q → Answer X) : List O → Prop where
  | nil : Frames s statusError provider []
  | step (h : List O) (out : core.result.Result json_wire.Value X)
      (prior : Frames s statusError provider h)
      (observed : StepOutcome (s.at (s.strategy h)) statusError (s.strategy h)
        (provider (s.strategy h)) out) :
      Frames s statusError provider (h ++ [s.frame out])

/-- **The declassification at the frame boundary.** Two transport failures
    agree when their public codes agree; responses agree as in
    `AnswersAgree` (same status class, and agreeing documents when admitted). -/
def FrameAgree (s : FrameSession C X Q O) (pub : X → P) (q : Q) : Answer X → Answer X → Prop
  | .transport e₁, .transport e₂ => pub e₁ = pub e₂
  | .transport _, .response _ _ => False
  | .response st₁ d₁, a₂ => AnswersAgree (s.at q) q (.response st₁ d₁) a₂

/-- A frame that depends on a failure only through its public code. -/
def FailureByCode (s : FrameSession C X Q O) (pub : X → P) : Prop :=
  ∀ e₁ e₂, pub e₁ = pub e₂ → s.frame (.Err e₁) = s.frame (.Err e₂)

theorem frame_step_transfer (s : FrameSession C X Q O)
    (statusError : provider_status.StatusDenial → X) (pub : X → P) (byCode : FailureByCode s pub)
    (q : Q) (a₁ a₂ : Answer X) (agree : FrameAgree s pub q a₁ a₂)
    (out : core.result.Result json_wire.Value X)
    (seen : StepOutcome (s.at q) statusError q a₁ out) :
    ∃ out', StepOutcome (s.at q) statusError q a₂ out' ∧ s.frame out' = s.frame out := by
  cases a₁ with
  | transport e₁ =>
    cases a₂ with
    | transport e₂ =>
      cases seen
      exact ⟨.Err e₂, .transport e₂, byCode _ _ agree.symm⟩
    | response => exact absurd agree (by simp [FrameAgree])
  | response st₁ d₁ =>
    exact ⟨out, step_transfer (s.at q) statusError q _ a₂ agree out seen, rfl⟩

/-- **Adaptive noninterference over guest frames.** A guest choosing each
    request from the frames it has read sees the same frame histories in two
    worlds whose answers agree request by request on `FrameAgree`: the public
    code of a transport failure, or the status class and the selected data. -/
theorem adaptive_frame_noninterference (s : FrameSession C X Q O)
    (statusError : provider_status.StatusDenial → X) (pub : X → P) (byCode : FailureByCode s pub)
    (p₁ p₂ : Q → Answer X) (agree : ∀ q, FrameAgree s pub q (p₁ q) (p₂ q))
    (h : List O) (seen : Frames s statusError p₁ h) : Frames s statusError p₂ h := by
  induction seen with
  | nil => exact .nil
  | step h out _ observed ih =>
    obtain ⟨out', observed', same⟩ :=
      frame_step_transfer s statusError pub byCode _ _ _ (agree _) out observed
    rw [← same]
    exact .step h out' ih observed'

/-- What the bridge frames for an outcome (`GuestFrame::from_answer`): the
    extracted encoding of a released value, or the extracted fixed denial
    frame of a failure's public code. -/
def productionFrame (pub : X → public_error.PublicError) (limit : Usize) :
    core.result.Result json_wire.Value X →
      Result (core.result.Result guest_frame.Frame guest_frame.FrameDenial)
  | .Ok value => json_wire.prepare value limit
  | .Err error => public_error.denial_frame (pub error) limit

theorem production_failure_by_code (cur : selected_release.Current C X)
    (host : Q → Json → selected_release.Manifest C X)
    (strategy : List (Result (core.result.Result guest_frame.Frame guest_frame.FrameDenial)) → Q)
    (pub : X → public_error.PublicError) (limit : Usize) :
    FailureByCode ⟨cur, host, strategy, productionFrame pub limit⟩ pub := by
  intro e₁ e₂ same
  simp [productionFrame, same]

/-- **The production frame instance.** With the bridge's framing, the guest's
    frame histories agree whenever answers agree on `FrameAgree pub`; every
    failure frame is the fixed `denialText` line of its public code
    (`public_error.Proofs.denial_frame_exact`), so a failed request reveals
    one of 17 codes and nothing of the native error behind it. -/
theorem production_frame_noninterference (cur : selected_release.Current C X)
    (host : Q → Json → selected_release.Manifest C X)
    (strategy : List (Result (core.result.Result guest_frame.Frame guest_frame.FrameDenial)) → Q)
    (pub : X → public_error.PublicError) (limit : Usize)
    (statusError : provider_status.StatusDenial → X)
    (p₁ p₂ : Q → Answer X)
    (agree : ∀ q, FrameAgree ⟨cur, host, strategy, productionFrame pub limit⟩ pub q (p₁ q) (p₂ q))
    (h : List (Result (core.result.Result guest_frame.Frame guest_frame.FrameDenial)))
    (seen : Frames ⟨cur, host, strategy, productionFrame pub limit⟩ statusError p₁ h) :
    Frames ⟨cur, host, strategy, productionFrame pub limit⟩ statusError p₂ h :=
  adaptive_frame_noninterference _ statusError pub
    (production_failure_by_code cur host strategy pub limit) p₁ p₂ agree h seen

/-- Every failure frame the guest can read is the fixed line of a public code. -/
theorem production_failure_frame (pub : X → public_error.PublicError) (limit : Usize)
    (large : 200 ≤ limit.val) (error : X) :
    ∃ frame, productionFrame pub limit (.Err error) = Result.ok (.Ok frame) ∧
      frame.wire.val =
        public_error.Proofs.ascii (public_error.Proofs.denialText (pub error)) ++ [10#u8] :=
  let ⟨frame, built, wire, _⟩ := public_error.Proofs.denial_frame_exact (pub error) limit large
  ⟨frame, built, wire⟩

end aivm_secrets_garrett_core.selected_release.FrameBoundary
