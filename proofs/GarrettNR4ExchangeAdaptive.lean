import GarrettNR4AdaptiveRelease

/-!
# NR-4: the whole provider exchange, transport and status included

Source: `rust/crates/aivm-secrets-garrett-core/src/provider_status.rs`
(`parse`, `manifest`) and `selected_release.rs`, extracted by Aeneas. Native
`manifest_response` calls `provider_status::parse` on the status line and
`provider_status::manifest` on the code; a refusal becomes a fixed public error.

`manifest_classes` states the exact public class of every status code: 4xx is
`Rejected`, any other non-2xx is `Failed`, 206 is `Partial`, the rest proceed.

`adaptive_exchange_noninterference` extends the adaptive release theorem to
steps that end in a transport failure, a refused status, or a release: two
worlds whose answers agree request by request on `AnswersAgree` (same
transport failure, or same status class and agreeing documents) give the guest
the same observable histories. The exact status code, headers and unselected
body bytes are not observable through these outcomes.

Modelled rather than extracted: the `Answer` abstraction (which native error a
transport failure maps to, and the body parse into the document), and the
native `statusError` table, which may be any function. Admission outcomes
depend on host authority state, which `Session.host` and the shared
current-control callback hold equal in both worlds.
-/

open Aeneas Aeneas.Std
namespace aivm_secrets_garrett_core.provider_status.Proofs

/-- The public class of every provider status code, as the guest learns it. -/
theorem manifest_classes (status : U16) :
    provider_status.manifest status =
      Result.ok (if 400 ≤ status.val ∧ status.val < 500 then .Err .Rejected
        else if status.val < 200 ∨ 300 ≤ status.val then .Err .Failed
        else if status.val = 206 then .Err .Partial
        else .Ok ()) := by
  unfold provider_status.manifest
  have h := status.hBounds
  split_ifs <;> first | rfl | (exfalso; scalar_tac)

end aivm_secrets_garrett_core.provider_status.Proofs

namespace aivm_secrets_garrett_core.selected_release.Transport
open aivm_secrets_garrett_core.selected_release.Relational
open aivm_secrets_garrett_core.selected_release.Adaptive
open aivm_secrets_garrett_core.disclosure (Json)

variable {C X Q : Type}

/-- What the provider exchange produced for one request: a transport failure
    (connect, TLS, write, framing; already mapped to a public error), or a
    response with a status code and, if the body parsed, a document. -/
inductive Answer (X : Type) where
  | transport (error : X)
  | response (status : U16) (document : Json)

/-- One step's guest-visible outcome for answer `a` to request `q`: the
    transport error; or the extracted status refusal, mapped by the native
    `statusError`; or the extracted read release over the document. -/
inductive StepOutcome (s : Session C X Q) (statusError : provider_status.StatusDenial → X)
    (q : Q) : Answer X → core.result.Result json_wire.Value X → Prop where
  | transport (e : X) : StepOutcome s statusError q (.transport e) (.Err e)
  | refused (st : U16) (d : Json) (c : provider_status.StatusDenial)
      (classified : provider_status.manifest st = Result.ok (.Err c)) :
      StepOutcome s statusError q (.response st d) (.Err (statusError c))
  | released (st : U16) (d : Json) (out : core.result.Result json_wire.Value X)
      (done : selected_release.Manifest C X)
      (admitted : provider_status.manifest st = Result.ok (.Ok ()))
      (release : selected_release.select (manifestOps s.cur) (s.host q d) = Result.ok (out, done)) :
      StepOutcome s statusError q (.response st d) out

/-- A full adaptive session whose provider exchanges may fail. -/
inductive Produces (s : Session C X Q) (statusError : provider_status.StatusDenial → X)
    (provider : Q → Answer X) : List (core.result.Result json_wire.Value X) → Prop where
  | nil : Produces s statusError provider []
  | step (h : List (core.result.Result json_wire.Value X)) (out : core.result.Result json_wire.Value X)
      (prior : Produces s statusError provider h)
      (observed : StepOutcome s statusError (s.strategy h) (provider (s.strategy h)) out) :
      Produces s statusError provider (h ++ [out])

/-- **The declassification for a whole provider exchange.** The two answers
    are the same transport failure, or responses whose statuses fall in the
    same public class (`provider_status.manifest`) and, when admitted, whose
    documents agree on the selected JSON and pagination row count. The exact
    status code, headers and every unselected byte stay private. -/
def AnswersAgree (s : Session C X Q) (q : Q) : Answer X → Answer X → Prop
  | .transport e₁, .transport e₂ => e₁ = e₂
  | .response st₁ d₁, .response st₂ d₂ =>
      provider_status.manifest st₁ = provider_status.manifest st₂ ∧
      (provider_status.manifest st₁ = Result.ok (.Ok ()) →
        Related (s.host q d₁) (s.host q d₂))
  | _, _ => False

theorem step_transfer (s : Session C X Q) (statusError : provider_status.StatusDenial → X)
    (q : Q) (a₁ a₂ : Answer X) (agree : AnswersAgree s q a₁ a₂)
    (out : core.result.Result json_wire.Value X)
    (seen : StepOutcome s statusError q a₁ out) : StepOutcome s statusError q a₂ out := by
  cases seen with
  | transport e =>
    cases a₂ with
    | transport e₂ => simp only [AnswersAgree] at agree; subst agree; exact .transport e
    | response => simp [AnswersAgree] at agree
  | refused st d c classified =>
    cases a₂ with
    | transport => simp [AnswersAgree] at agree
    | response st₂ d₂ =>
      exact .refused st₂ d₂ c (agree.1 ▸ classified)
  | released st d out done admitted release =>
    cases a₂ with
    | transport => simp [AnswersAgree] at agree
    | response st₂ d₂ =>
      obtain ⟨b, hb, _⟩ :=
        (manifest_release_noninterference s.cur _ _ (agree.2 admitted)).1 out done release
      exact .released st₂ d₂ out b (agree.1 ▸ admitted) hb

/-- **Adaptive noninterference across the whole provider exchange.** A guest
    choosing each request from all earlier outcomes observes the same histories
    in two worlds whose answers agree request by request (`AnswersAgree`):
    same transport failure, or same status class and agreeing documents. -/
theorem adaptive_exchange_noninterference (s : Session C X Q)
    (statusError : provider_status.StatusDenial → X) (p₁ p₂ : Q → Answer X)
    (agree : ∀ q, AnswersAgree s q (p₁ q) (p₂ q))
    (h : List (core.result.Result json_wire.Value X)) (seen : Produces s statusError p₁ h) :
    Produces s statusError p₂ h := by
  induction seen with
  | nil => exact .nil
  | step h out _ observed ih =>
    exact .step h out ih (step_transfer s statusError _ _ _ (agree _) out observed)

end aivm_secrets_garrett_core.selected_release.Transport
