import GarrettNR4ManifestRelease

/-!
# NR-4: adaptive guest sessions over the production read release

A malicious guest issues requests one after another and may choose each one
from every outcome it has already seen. `adaptive_release_same_histories`
proves that two worlds whose provider responses agree, request by request, on
the declassified data (`Related`: selected JSON, pagination row count, same
host policy/credential/current state) give the guest exactly the same set of
observable release histories.

This is the release-stage instance of the earlier
`GarrettNoninterference.adaptive_noninterference`. That theorem needed a
`step_preserves`/`PairedStepCertificate` premise asserting each paired step was
already indistinguishable; here the per-step fact is *proved* from the
extracted code (`manifest_release_noninterference`), and the only premise is
about the inputs.

Scope: each step's observation is the outcome of the extracted release (the
released value, or the refusal error, which the bridge turns into one of the
fixed denial frames proved in `GarrettPublicError`). Outcomes decided earlier in
a request (admission, revocation, provider transport errors) depend on host
and network state and are not part of this step model.
-/

open Aeneas Aeneas.Std
namespace aivm_secrets_garrett_core.selected_release.Adaptive
open aivm_secrets_garrett_core.selected_release.Relational
open aivm_secrets_garrett_core.disclosure (Json)

variable {C X Q : Type}

/-- An adaptive guest session. The guest chooses each request `q` from the
    outcomes it has seen so far (`strategy`); the host turns the request and
    the provider's response document into the release state (`host`); the
    provider may answer each request differently (`provider`). -/
structure Session (C X Q : Type) where
  cur : selected_release.Current C X
  strategy : List (core.result.Result json_wire.Value X) → Q
  host : Q → Json → selected_release.Manifest C X

/-- `Produces s provider h`: interacting with `provider`, the guest observes
    exactly the release outcomes `h`, in order. -/
inductive Produces (s : Session C X Q) (provider : Q → Json) :
    List (core.result.Result json_wire.Value X) → Prop where
  | nil : Produces s provider []
  | step (h : List (core.result.Result json_wire.Value X))
      (out : core.result.Result json_wire.Value X) (done : selected_release.Manifest C X)
      (prior : Produces s provider h)
      (released : selected_release.select (manifestOps s.cur)
        (s.host (s.strategy h) (provider (s.strategy h ))) = Result.ok (out, done)) :
      Produces s provider (h ++ [out])

/-- **Adaptive read noninterference.** If, for every request the guest could
    make, the two providers' responses agree on the declassified data (the
    selected JSON and the pagination row count, with the same host policy,
    credential and current-control state), then every history of release
    outcomes the guest can observe against one provider it also observes
    against the other. The guest may choose each request from all earlier
    outcomes. -/
theorem adaptive_release_noninterference (s : Session C X Q) (p₁ p₂ : Q → Json)
    (agree : ∀ q, Related (s.host q (p₁ q)) (s.host q (p₂ q)))
    (h : List (core.result.Result json_wire.Value X)) (seen : Produces s p₁ h) :
    Produces s p₂ h := by
  induction seen with
  | nil => exact .nil
  | step h out done _ released ih =>
    obtain ⟨b, hb, _⟩ :=
      (manifest_release_noninterference s.cur _ _ (agree (s.strategy h))).1 out done released
    exact .step h out b ih hb

/-- Symmetric form: the two worlds produce exactly the same histories. -/
theorem adaptive_release_same_histories (s : Session C X Q) (p₁ p₂ : Q → Json)
    (agree : ∀ q, Related (s.host q (p₁ q)) (s.host q (p₂ q)))
    (h : List (core.result.Result json_wire.Value X)) :
    Produces s p₁ h ↔ Produces s p₂ h := by
  have symm : ∀ q, Related (s.host q (p₂ q)) (s.host q (p₁ q)) := by
    intro q
    have ⟨c, f, pg, sc, ⟨lookups, rows⟩⟩ := agree q
    refine ⟨c.symm, f.symm, pg.symm, sc.symm, ?_, ?_⟩
    · intro fs hf field mem
      exact (lookups fs (f.trans hf) field mem).symm
    · intro p hp
      exact (rows p (pg.trans hp)).symm
  exact ⟨adaptive_release_noninterference s p₁ p₂ agree h,
    adaptive_release_noninterference s p₂ p₁ symm h⟩

end aivm_secrets_garrett_core.selected_release.Adaptive
