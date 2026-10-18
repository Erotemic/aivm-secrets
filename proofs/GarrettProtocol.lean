import Garrett

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.credential_use
open aivm_secrets_garrett_core.credential_use.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.protocol.Proofs

variable {V O A E C S : Type}
variable (vops : EnvelopeVerifier V C) (iops : CredentialOpener O C S)
variable (aops : DispatchObserver A) (eops : CredentialExecutor E S)
variable (verifier : V) (opener : O) (observer : A) (executor : E)
variable (token : alloc.vec.Vec U8) (g : UseGrant) (op : alloc.vec.Vec U8) (p : Presentation)

/-- Evidence already holds before execution, including when the provider later
    returns an error. Crypto and inner opening are named adapter contracts. -/
def PreparedOrigin (Authentic : alloc.vec.Vec U8 → AuthenticatedEnvelope → Prop)
    (Unsealed : AuthenticatedEnvelope → C → Prop) (InnerOf : C → UseClaims → S → Prop)
    (ready : Prepared S) : Prop :=
  ∃ envelope capability, Authentic token envelope ∧
    Bound envelope.claims p.expected p.peer p.now.val ∧ ready.identity = envelope.claims ∧
    Unsealed envelope capability ∧ InnerOf capability ready.claims ready.credential ∧
    Current ready.claims g p.now.val p.elapsed.val ∧ op = g.operation

theorem prepared_contract
    (Authentic : alloc.vec.Vec U8 → AuthenticatedEnvelope → Prop)
    (Unsealed : AuthenticatedEnvelope → C → Prop) (InnerOf : C → UseClaims → S → Prop)
    (verify_contract : vops.verify verifier token ⦃ out =>
      match out with | .Ok envelope => Authentic token envelope | .Err _ => True ⦄)
    (unseal_contract : ∀ envelope, vops.«unseal» verifier envelope ⦃ out =>
      match out with | .Ok capability => Unsealed envelope capability | .Err _ => True ⦄)
    (inner_contract : ∀ capability, iops.«open» opener capability ⦃ out =>
      match out with | .Ok inner => InnerOf capability inner.claims inner.credential | .Err _ => True ⦄) :
    prepare vops iops verifier opener token g op p ⦃ out =>
      match out with
      | .Ok ready => PreparedOrigin token g op p Authentic Unsealed InnerOf ready
      | .Err _ => True ⦄ := by
  unfold prepare
  apply WP.spec_bind (open_surrogate_contract vops verifier token p.expected p.peer p.now
    Authentic Unsealed verify_contract unseal_contract)
  intro opened authenticated
  cases opened with
  | Err error => simp
  | Ok outer =>
    dsimp only at authenticated ⊢
    apply WP.spec_bind (inner_contract outer.secret)
    intro decoded inner_origin
    cases decoded with
    | Err error => simp
    | Ok inner =>
      dsimp only at inner_origin ⊢
      apply WP.spec_bind (authorize_use_contract inner.claims g op p.now p.elapsed)
      intro checked authorized
      cases checked with
      | Err error => simp
      | Ok value =>
        dsimp only [UseSpec] at authorized
        rcases authenticated with ⟨envelope, authentic, bound, identity, unsealed⟩
        simpa only [WP.spec_ok, PreparedOrigin] using
          (show ∃ e cap, Authentic token e ∧ Bound e.claims p.expected p.peer p.now.val ∧
            outer.claims = e.claims ∧ Unsealed e cap ∧ InnerOf cap inner.claims inner.credential ∧
            Current inner.claims g p.now.val p.elapsed.val ∧ op = g.operation from
            ⟨envelope, outer.secret, authentic, bound, identity, unsealed, inner_origin, authorized⟩)

/-- A fresh recheck discards opened material, but retains the same exact
    identity, grant, operation and lifetime guarantees as request preparation. -/
theorem recheck_contract
    (Authentic : alloc.vec.Vec U8 → AuthenticatedEnvelope → Prop)
    (Unsealed : AuthenticatedEnvelope → C → Prop) (InnerOf : C → UseClaims → S → Prop)
    (verify_contract : vops.verify verifier token ⦃ out =>
      match out with | .Ok envelope => Authentic token envelope | .Err _ => True ⦄)
    (unseal_contract : ∀ envelope, vops.«unseal» verifier envelope ⦃ out =>
      match out with | .Ok capability => Unsealed envelope capability | .Err _ => True ⦄)
    (inner_contract : ∀ capability, iops.«open» opener capability ⦃ out =>
      match out with | .Ok inner => InnerOf capability inner.claims inner.credential | .Err _ => True ⦄) :
    recheck vops iops verifier opener token g op p ⦃ out =>
      match out with
      | .Ok _ => ∃ ready, PreparedOrigin token g op p Authentic Unsealed InnerOf ready
      | .Err _ => True ⦄ := by
  unfold recheck
  apply WP.spec_bind (prepared_contract vops iops verifier opener token g op p
    Authentic Unsealed InnerOf verify_contract unseal_contract inner_contract)
  intro checked origin
  cases checked with
  | Err error => simp
  | Ok ready => simpa only [WP.spec_ok] using Exists.intro ready origin

theorem recheck_rejection (error : UseDenial)
    (denied : prepare vops iops verifier opener token g op p = Result.ok (.Err error)) :
    recheck vops iops verifier opener token g op p = Result.ok (.Err error) := by
  simp [recheck, denied]

theorem recheck_successful_witness (ready : Prepared S)
    (admitted : prepare vops iops verifier opener token g op p = Result.ok (.Ok ready)) :
    recheck vops iops verifier opener token g op p = Result.ok (.Ok ()) := by
  simp [recheck, admitted]

theorem finish_contract (route : Route) (secret : S)
    (Executed : Route → S → ProviderReply → Prop)
    (execute_contract : eops.execute executor route secret ⦃ out =>
      match out with | .Ok response => Executed route secret response | .Err _ => True ⦄) :
    finish_use eops executor secret route ⦃ out =>
      match out with
      | .Ok released => ∃ response, Executed route secret response ∧
          released.account_id = response.account_id ∧ released.active = response.active
      | .Err _ => True ⦄ := by
  unfold finish_use
  apply WP.spec_bind execute_contract
  intro result executed
  cases result with
  | Err error => simp
  | Ok response =>
    apply WP.spec_bind (show release_reply response ⦃ released =>
      released.account_id = response.account_id ∧ released.active = response.active ⦄ from by
        simp [release_reply])
    intro released projection
    simpa only [WP.spec_ok] using (show ∃ r, Executed route secret r ∧
      released.account_id = r.account_id ∧ released.active = r.active from ⟨response, executed, projection⟩)

theorem perform_contract
    (Authentic : alloc.vec.Vec U8 → AuthenticatedEnvelope → Prop)
    (Unsealed : AuthenticatedEnvelope → C → Prop) (InnerOf : C → UseClaims → S → Prop)
    (Recorded : Claims → UseClaims → Route → alloc.vec.Vec U8 → Prop)
    (Executed : Route → S → ProviderReply → Prop)
    (verify_contract : vops.verify verifier token ⦃ out =>
      match out with | .Ok envelope => Authentic token envelope | .Err _ => True ⦄)
    (unseal_contract : ∀ envelope, vops.«unseal» verifier envelope ⦃ out =>
      match out with | .Ok capability => Unsealed envelope capability | .Err _ => True ⦄)
    (inner_contract : ∀ capability, iops.«open» opener capability ⦃ out =>
      match out with | .Ok inner => InnerOf capability inner.claims inner.credential | .Err _ => True ⦄)
    (record_contract : ∀ identity claims, aops.record observer identity claims g.route op ⦃ out =>
      match out with | .Ok _ => Recorded identity claims g.route op | .Err _ => True ⦄)
    (execute_contract : ∀ secret, eops.execute executor g.route secret ⦃ out =>
      match out with | .Ok response => Executed g.route secret response | .Err _ => True ⦄) :
    perform vops iops aops eops verifier opener observer executor token g op p ⦃ out =>
      match out with
      | .Ok released => ∃ ready response,
          PreparedOrigin token g op p Authentic Unsealed InnerOf ready ∧
          Recorded ready.identity ready.claims g.route op ∧
          Executed g.route ready.credential response ∧
          released.account_id = response.account_id ∧ released.active = response.active
      | .Err _ => True ⦄ := by
  unfold perform
  apply WP.spec_bind (prepared_contract vops iops verifier opener token g op p
    Authentic Unsealed InnerOf verify_contract unseal_contract inner_contract)
  intro prepared origin
  cases prepared with
  | Err error => simp
  | Ok ready =>
    dsimp only at origin ⊢
    apply WP.spec_bind (record_contract ready.identity ready.claims)
    intro observed recorded
    cases observed with
    | Err error => simp
    | Ok value =>
      dsimp only at recorded ⊢
      apply WP.spec_mono (finish_contract eops executor g.route ready.credential Executed
        (execute_contract ready.credential))
      intro result projection
      cases result with
      | Err error => trivial
      | Ok released =>
        rcases projection with ⟨response, executed, id, active⟩
        exact ⟨ready, response, origin, recorded, executed, id, active⟩


theorem perform_outer_failure
    (failed : open_surrogate vops verifier token p.expected p.peer p.now =
      Result.ok (core.result.Result.Err Denial.InvalidCapability)) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      Result.ok (core.result.Result.Err UseDenial.InvalidCapability) := by
  simp [perform, prepare, failed]

theorem perform_stolen_surrogate (envelope : AuthenticatedEnvelope)
    (canAuthenticate : alloc.vec.Vec U8 → Prop)
    (verified : vops.verify verifier token = Result.ok (core.result.Result.Ok envelope))
    (outsider : ¬ canAuthenticate envelope.claims.certificate)
    (actual_peer : canAuthenticate p.peer) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      Result.ok (core.result.Result.Err UseDenial.InvalidCapability) := by
  apply perform_outer_failure
  exact open_stolen_surrogate_rejected vops verifier token p.expected p.peer p.now
    envelope canAuthenticate verified outsider actual_peer

theorem perform_inner_failure (outer : OpenedSurrogate C) (error : UseDenial)
    (authenticated : open_surrogate vops verifier token p.expected p.peer p.now =
      Result.ok (core.result.Result.Ok outer))
    (failed : iops.«open» opener outer.secret = Result.ok (core.result.Result.Err error)) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      Result.ok (core.result.Result.Err error) := by
  simp [perform, prepare, authenticated, failed]

theorem perform_unauthorized_operation (outer : OpenedSurrogate C) (inner : OpenedCredential S)
    (authenticated : open_surrogate vops verifier token p.expected p.peer p.now =
      Result.ok (core.result.Result.Ok outer))
    (decoded : iops.«open» opener outer.secret = Result.ok (core.result.Result.Ok inner))
    (current : Current inner.claims g p.now.val p.elapsed.val) (wrong : op ≠ g.operation) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      Result.ok (core.result.Result.Err UseDenial.Denied) := by
  simp [perform, prepare, authenticated, decoded, authorize_use_exact, current, wrong]

/-- This equality describes every provider outcome, including failure/divergence:
    the only execution continuation follows acknowledgement of the exact record. -/
theorem perform_after_prepared (ready : Prepared S)
    (accepted : prepare vops iops verifier opener token g op p =
      Result.ok (core.result.Result.Ok ready)) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      (do
        let observed ← aops.record observer ready.identity ready.claims g.route op
        match observed with
        | .Ok _ => finish_use eops executor ready.credential g.route
        | .Err error => Result.ok (core.result.Result.Err error)) := by
  unfold perform
  rw [accepted, bind_ok]
  rfl

theorem perform_observer_failure (ready : Prepared S) (error : UseDenial)
    (accepted : prepare vops iops verifier opener token g op p =
      Result.ok (core.result.Result.Ok ready))
    (failed : aops.record observer ready.identity ready.claims g.route op =
      Result.ok (core.result.Result.Err error)) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      Result.ok (core.result.Result.Err error) := by
  simp [perform, accepted, failed]

theorem prepare_successful (envelope : AuthenticatedEnvelope) (capability : C)
    (inner : OpenedCredential S)
    (verified : vops.verify verifier token = Result.ok (core.result.Result.Ok envelope))
    (bound : Bound envelope.claims p.expected p.peer p.now.val)
    (unsealed : vops.«unseal» verifier envelope = Result.ok (core.result.Result.Ok capability))
    (decoded : iops.«open» opener capability = Result.ok (core.result.Result.Ok inner))
    (current : Current inner.claims g p.now.val p.elapsed.val) (allowed : op = g.operation) :
    prepare vops iops verifier opener token g op p =
      Result.ok (core.result.Result.Ok (Prepared.mk envelope.claims inner.claims inner.credential)) := by
  have authenticated := open_successful_use vops verifier token p.expected p.peer p.now
    envelope capability verified bound unsealed
  simp [prepare, authenticated, decoded, authorize_use_exact, current, allowed]

theorem perform_successful (ready : Prepared S) (response : ProviderReply)
    (accepted : prepare vops iops verifier opener token g op p =
      Result.ok (core.result.Result.Ok ready))
    (recorded : aops.record observer ready.identity ready.claims g.route op =
      Result.ok (core.result.Result.Ok ()))
    (executed : eops.execute executor g.route ready.credential =
      Result.ok (core.result.Result.Ok response)) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      Result.ok (core.result.Result.Ok (PublicReply.mk response.account_id response.active)) := by
  simp [perform, accepted, recorded, finish_use, executed, release_reply]

/-- Reply-only, conditional noninterference across the whole controller.
    Ciphertext lengths, public metadata and malicious-provider channels are not
    erased by this statement: the approved public response fields must agree. -/
theorem perform_projection_noninterference (token_b : alloc.vec.Vec U8)
    (a b : Prepared S) (response_a response_b : ProviderReply)
    (accepted_a : prepare vops iops verifier opener token g op p = Result.ok (core.result.Result.Ok a))
    (accepted_b : prepare vops iops verifier opener token_b g op p = Result.ok (core.result.Result.Ok b))
    (recorded_a : aops.record observer a.identity a.claims g.route op = Result.ok (core.result.Result.Ok ()))
    (recorded_b : aops.record observer b.identity b.claims g.route op = Result.ok (core.result.Result.Ok ()))
    (executed_a : eops.execute executor g.route a.credential = Result.ok (core.result.Result.Ok response_a))
    (executed_b : eops.execute executor g.route b.credential = Result.ok (core.result.Result.Ok response_b))
    (same_id : response_a.account_id = response_b.account_id)
    (same_active : response_a.active = response_b.active) :
    perform vops iops aops eops verifier opener observer executor token g op p =
    perform vops iops aops eops verifier opener observer executor token_b g op p := by
  rw [perform_successful vops iops aops eops verifier opener observer executor token g op p
    a response_a accepted_a recorded_a executed_a]
  rw [perform_successful vops iops aops eops verifier opener observer executor token_b g op p
    b response_b accepted_b recorded_b executed_b]
  simp [same_id, same_active]

end aivm_secrets_garrett_core.protocol.Proofs
