import GarrettNR4ExchangeAdaptive
import GarrettProductionReadFrame

/-!
# NR-4: complete requests, and independence from the body parser

`adaptive_request_noninterference` adds the admission stage to the adaptive
guest model. Admission is the extracted `manifest::authorize` over host-held
authority state and the guest's request, so both worlds compute the same
admission and only provider-dependent stages need `AnswersAgree`. A step's
outcome is then: admission refusal, transport failure, status refusal, or the
read release.

`read_confinement_for_every_document` states that read confinement holds for
every provider document, hence for any body parser: the framed bytes never
contain the credential and no decoded key or string of the released reply
does. The native serde body parse is therefore not an assumption of the
confinement result; it only determines *which* agreeing documents the
noninterference premise compares.
-/

open Aeneas Aeneas.Std

namespace aivm_secrets_garrett_core.selected_release.Admission
open aivm_secrets_garrett_core.selected_release.Adaptive
open aivm_secrets_garrett_core.selected_release.Transport

variable {C X Q : Type}

/-- The host's admission inputs for a request: the presented use claims, the
    host grant, the requested and selected operation, the write flags and the
    host clock. These are host-held state and the guest's request; they never
    include provider data. -/
structure Admit (Q : Type) where
  claims : Q → credential_use.UseClaims
  grant : credential_use.UseGrant
  requested : Q → alloc.vec.Vec U8
  selected : Q → alloc.vec.Vec U8
  write : Q → Bool
  writesAllowed : Bool
  now : Q → I64
  elapsed : Q → I64

/-- One request's guest-visible outcome, including the admission stage: the
    extracted `manifest::authorize` refuses (mapped by the native `useError`),
    or the request proceeds to the provider exchange. -/
inductive FullOutcome (s : Session C X Q) (statusError : provider_status.StatusDenial → X)
    (admit : Admit Q) (useError : credential_use.UseDenial → X) (q : Q) :
    Answer X → core.result.Result json_wire.Value X → Prop where
  | refused (a : Answer X) (d : credential_use.UseDenial)
      (denied : manifest.authorize (admit.claims q) admit.grant (admit.requested q)
        (admit.selected q) (admit.write q) admit.writesAllowed (admit.now q) (admit.elapsed q) =
        Result.ok (.Err d)) :
      FullOutcome s statusError admit useError q a (.Err (useError d))
  | admitted (a : Answer X) (out : core.result.Result json_wire.Value X)
      (accepted : manifest.authorize (admit.claims q) admit.grant (admit.requested q)
        (admit.selected q) (admit.write q) admit.writesAllowed (admit.now q) (admit.elapsed q) =
        Result.ok (.Ok ()))
      (exchanged : StepOutcome s statusError q a out) :
      FullOutcome s statusError admit useError q a out

inductive Produces (s : Session C X Q) (statusError : provider_status.StatusDenial → X)
    (admit : Admit Q) (useError : credential_use.UseDenial → X) (provider : Q → Answer X) :
    List (core.result.Result json_wire.Value X) → Prop where
  | nil : Produces s statusError admit useError provider []
  | step (h : List (core.result.Result json_wire.Value X)) (out : core.result.Result json_wire.Value X)
      (prior : Produces s statusError admit useError provider h)
      (observed : FullOutcome s statusError admit useError (s.strategy h) (provider (s.strategy h)) out) :
      Produces s statusError admit useError provider (h ++ [out])

/-- **Adaptive noninterference for complete requests.** Admission (the
    extracted `manifest::authorize` over host state and the request), the
    provider exchange (transport failure or status class) and the read
    release are all included. Two worlds that agree request by request on
    `AnswersAgree` give the guest the same observable histories. -/
theorem adaptive_request_noninterference (s : Session C X Q)
    (statusError : provider_status.StatusDenial → X) (admit : Admit Q)
    (useError : credential_use.UseDenial → X) (p₁ p₂ : Q → Answer X)
    (agree : ∀ q, AnswersAgree s q (p₁ q) (p₂ q))
    (h : List (core.result.Result json_wire.Value X))
    (seen : Produces s statusError admit useError p₁ h) :
    Produces s statusError admit useError p₂ h := by
  induction seen with
  | nil => exact .nil
  | step h out _ observed ih =>
    refine .step h out ih ?_
    cases observed with
    | refused d denied => exact .refused _ d denied
    | admitted _ accepted exchanged =>
      exact .admitted _ out accepted (step_transfer s statusError _ _ _ (agree _) out exchanged)

end aivm_secrets_garrett_core.selected_release.Admission

namespace aivm_secrets_garrett_core.selected_release.ParseIndependence
open aivm_secrets_garrett_core.selected_release.Relational (manifestOps)

/-- **Read confinement does not depend on how the provider body was parsed.**
    For every document whatsoever (so for any parser, correct or not), a
    successful release frames bytes in which the credential does not occur,
    and no decoded key or string of the released reply contains it. -/
theorem read_confinement_for_every_document {C X : Type} (cur : selected_release.Current C X)
    (s done : selected_release.Manifest C X) (document : disclosure.Json)
    (wire : json_wire.Value) (limit : Usize) (frame : guest_frame.Frame)
    (returned : selected_release.select (manifestOps cur) { s with document } =
      Result.ok (.Ok wire, done))
    (prepared : json_wire.prepare wire limit = Result.ok (.Ok frame)) :
    ∃ bytes reply,
      frame.wire.val = bytes.val ++ [10#u8] ∧
      ¬ reflection.Proofs.LiteralOccurs (alloc.vec.Vec.deref bytes) (alloc.vec.Vec.deref s.secret) ∧
      ¬ json_reflection.Proofs.Occurs (alloc.vec.Vec.deref s.secret) reply := by
  obtain ⟨_, _, _, _, reply, bytes, _, _, _, _, _, _, wireBytes, _, decoded, literal⟩ :=
    selected_release.FrameProofs.production_read_frame cur _ done wire limit frame returned prepared
  exact ⟨bytes, reply, wireBytes, literal, decoded⟩

end aivm_secrets_garrett_core.selected_release.ParseIndependence
