import AivmSecretsGarrettCore
import GarrettFoundation

open Aeneas Aeneas.Std
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.Proofs

def IssueAllowed (active : Bool) (epoch expiry now lifetime : Int) : Prop :=
  active = true ∧ 0 ≤ epoch ∧ epoch ≤ 2147483647 ∧ 0 ≤ expiry ∧
    0 ≤ now ∧ now ≤ 9223372036854772207 ∧ 1 ≤ lifetime ∧ lifetime ≤ 3600 ∧ now < expiry

def IssueSpec (active : Bool) (epoch expiry now lifetime : Int)
    (out : core.result.Result IssueWindow Denial) : Prop :=
  match out with
  | .Err .InvalidCapability => ¬ IssueAllowed active epoch expiry now lifetime
  | .Ok window => IssueAllowed active epoch expiry now lifetime ∧
      window.issued_at.val = now ∧ window.epoch.val = epoch ∧
      window.expires_at.val = min (now + lifetime) expiry

theorem issue_contract (active : Bool) (epoch expiry now lifetime : I64) :
    issue_window active epoch expiry now lifetime
      ⦃ out => IssueSpec active epoch.val expiry.val now.val lifetime.val out ⦄ := by
  unfold issue_window
  repeat' first
  | (solve | simp_all [WP.spec_ok, IssueSpec, IssueAllowed, min_def]; all_goals scalar_tac)
  | split
  | step

def Bound (c : Claims) (e : Expectation) (peer : alloc.vec.Vec U8) (now : Int) : Prop :=
  c.issuer = e.issuer ∧ c.audience = e.audience ∧ c.subject = e.subject ∧
    c.certificate = peer ∧ 0 ≤ c.epoch.val ∧ c.epoch.val ≤ 2147483647 ∧
    c.epoch = e.epoch ∧ 0 ≤ c.issued_at.val ∧ c.issued_at.val ≤ 9223372036854772207 ∧
    c.issued_at.val < c.expires_at.val ∧ c.expires_at.val ≤ c.issued_at.val + 3600 ∧
    c.issued_at.val ≤ now ∧ now < c.expires_at.val

instance (c : Claims) (e : Expectation) (peer : alloc.vec.Vec U8) (now : Int) :
    Decidable (Bound c e peer now) := by unfold Bound; infer_instance

theorem present_contract (c : Claims) (e : Expectation) (peer : alloc.vec.Vec U8) (now : I64) :
    present c e peer now ⦃ out =>
      match out with
      | .Ok _ => Bound c e peer now.val
      | .Err .InvalidCapability => ¬ Bound c e peer now.val ⦄ := by
  unfold present
  apply WP.spec_bind (bytes_ne_spec c.issuer e.issuer)
  intro different0 neq0
  by_cases h0 : different0 = true
  · simp_all [WP.spec_ok, Bound]
  · simp only [h0]
    apply WP.spec_bind (bytes_ne_spec c.audience e.audience)
    intro different1 neq1
    by_cases h1 : different1 = true
    · simp_all [WP.spec_ok, Bound]
    · simp only [h1]
      apply WP.spec_bind (bytes_ne_spec c.subject e.subject)
      intro different2 neq2
      by_cases h2 : different2 = true
      · simp_all [WP.spec_ok, Bound]
      · simp only [h2]
        apply WP.spec_bind (bytes_ne_spec c.certificate peer)
        intro different3 neq3
        by_cases h3 : different3 = true
        · simp_all [WP.spec_ok, Bound]
        · simp only [h3]
          repeat' first
          | (solve | simp_all [WP.spec_ok, Bound]; all_goals scalar_tac)
          | split
          | step


theorem present_exact (c : Claims) (e : Expectation) (peer : alloc.vec.Vec U8) (now : I64) :
    present c e peer now = Result.ok (if Bound c e peer now.val then
      core.result.Result.Ok () else core.result.Result.Err Denial.InvalidCapability) := by
  obtain ⟨value, returned, property⟩ := returned_of_spec (present_contract c e peer now)
  cases value with
  | Ok value => cases value; simpa [property] using returned
  | Err denial => cases denial; simpa [property] using returned

theorem present_accepted_iff (c : Claims) (e : Expectation) (peer : alloc.vec.Vec U8) (now : I64) :
    present c e peer now = Result.ok (core.result.Result.Ok ()) ↔ Bound c e peer now.val := by
  rw [present_exact]
  split_ifs <;> simp_all

theorem stolen_surrogate_wrong_peer (c : Claims) (e : Expectation) (peer : alloc.vec.Vec U8) (now : I64)
    (different : c.certificate ≠ peer) :
    present c e peer now = Result.ok (core.result.Result.Err Denial.InvalidCapability) := by
  rw [present_exact]
  simp [Bound, different]

/-- The TLS contract supplies this predicate. The adversary lacks the victim's
    signing operation, not merely the ability to export its private key bytes. -/
def IndependentUse (canAuthenticate : alloc.vec.Vec U8 → Prop) (c : Claims) : Prop :=
  ∃ peer expected now, canAuthenticate peer ∧
    present c expected peer now = Result.ok (core.result.Result.Ok ())

theorem stolen_surrogate_cannot_be_used
    (canAuthenticate : alloc.vec.Vec U8 → Prop) (c : Claims)
    (no_signing_oracle : ¬ canAuthenticate c.certificate) :
    ¬ IndependentUse canAuthenticate c := by
  rintro ⟨peer, expected, now, authenticated, accepted⟩
  have bound := (present_accepted_iff c expected peer now).mp accepted
  exact no_signing_oracle (bound.2.2.2.1.symm ▸ authenticated)

theorem issuance_cannot_outlive_enrollment (active : Bool) (epoch expiry now lifetime : I64)
    (window : IssueWindow)
    (issued : issue_window active epoch expiry now lifetime = Result.ok (core.result.Result.Ok window)) :
    window.expires_at.val ≤ expiry.val ∧ now.val < window.expires_at.val ∧
      window.epoch = epoch := by
  have contract := issue_contract active epoch expiry now lifetime
  rw [issued] at contract
  simp only [WP.spec_ok, IssueSpec] at contract
  have facts := contract.1
  have window_eq := contract.2.2.2
  have epoch_eq : window.epoch = epoch := by scalar_tac
  simp only [IssueAllowed] at facts
  rw [window_eq]
  exact ⟨min_le_right _ _, lt_min (by omega) facts.2.2.2.2.2.2.2.2, epoch_eq⟩

def witnessBytes (n : Nat) (byte : U8) (h : n ≤ Usize.max) : alloc.vec.Vec U8 :=
  alloc.vec.Vec.from (List.replicate n byte) (by simpa using h)

def witnessClaims : Claims := {
  issuer := witnessBytes 1 97#u8 (by scalar_tac)
  audience := witnessBytes 1 98#u8 (by scalar_tac)
  subject := witnessBytes 1 99#u8 (by scalar_tac)
  token_id := witnessBytes 32 48#u8 (by scalar_tac)
  certificate := witnessBytes 43 65#u8 (by scalar_tac)
  epoch := 0#i64, issued_at := 100#i64, expires_at := 200#i64 }

theorem authorized_use_positive_witness :
    present witnessClaims
      ⟨witnessClaims.issuer, witnessClaims.audience, witnessClaims.subject, 0#i64⟩
      witnessClaims.certificate 150#i64 = Result.ok (core.result.Result.Ok ()) := by
  rw [present_exact]
  norm_num [Bound, witnessClaims]


/-- Composition over the exact controller used by the Rust crypto adapter.
    Authenticity and authenticated-decryption semantics are explicit contracts,
    rather than booleans supplied by a client or project security axioms. -/
theorem open_surrogate_contract {V S : Type} (ops : EnvelopeVerifier V S) (verifier : V)
    (token : alloc.vec.Vec U8) (expected : Expectation) (peer : alloc.vec.Vec U8) (now : I64)
    (Authentic : alloc.vec.Vec U8 → AuthenticatedEnvelope → Prop)
    (Unsealed : AuthenticatedEnvelope → S → Prop)
    (verify_contract : ops.verify verifier token ⦃ out =>
      match out with | .Ok envelope => Authentic token envelope | .Err _ => True ⦄)
    (unseal_contract : ∀ envelope, ops.«unseal» verifier envelope ⦃ out =>
      match out with | .Ok secret => Unsealed envelope secret | .Err _ => True ⦄) :
    open_surrogate ops verifier token expected peer now ⦃ out =>
      match out with
      | .Ok opened => ∃ envelope, Authentic token envelope ∧
          Bound envelope.claims expected peer now.val ∧
          opened.claims = envelope.claims ∧ Unsealed envelope opened.secret
      | .Err _ => True ⦄ := by
  unfold open_surrogate
  apply WP.spec_bind verify_contract
  intro verified authentic
  cases verified with
  | Err denial => simp
  | Ok envelope =>
    dsimp only at authentic ⊢
    rw [present_exact]
    split_ifs with bound
    · simp only [bind_ok]
      apply WP.spec_bind (unseal_contract envelope)
      intro unsealed related
      cases unsealed with
      | Err denial => simp
      | Ok secret => simpa only [WP.spec_ok] using (show ∃ e, Authentic token e ∧ Bound e.claims expected peer now.val ∧ envelope.claims = e.claims ∧ Unsealed e secret from ⟨envelope, authentic, bound, rfl, related⟩)
    · simp

theorem open_rejects_unbound_before_unsealing {V S : Type} (ops : EnvelopeVerifier V S)
    (verifier : V) (token : alloc.vec.Vec U8) (expected : Expectation)
    (peer : alloc.vec.Vec U8) (now : I64) (envelope : AuthenticatedEnvelope)
    (verified : ops.verify verifier token = Result.ok (core.result.Result.Ok envelope))
    (unbound : ¬ Bound envelope.claims expected peer now.val) :
    open_surrogate ops verifier token expected peer now =
      Result.ok (core.result.Result.Err Denial.InvalidCapability) := by
  simp [open_surrogate, verified, present_exact, unbound]

theorem open_stolen_surrogate_rejected {V S : Type} (ops : EnvelopeVerifier V S)
    (verifier : V) (token : alloc.vec.Vec U8) (expected : Expectation)
    (peer : alloc.vec.Vec U8) (now : I64) (envelope : AuthenticatedEnvelope)
    (canAuthenticate : alloc.vec.Vec U8 → Prop)
    (verified : ops.verify verifier token = Result.ok (core.result.Result.Ok envelope))
    (outsider : ¬ canAuthenticate envelope.claims.certificate)
    (actual_peer : canAuthenticate peer) :
    open_surrogate ops verifier token expected peer now =
      Result.ok (core.result.Result.Err Denial.InvalidCapability) := by
  apply open_rejects_unbound_before_unsealing ops verifier token expected peer now envelope verified
  intro bound
  exact outsider (bound.2.2.2.1.symm ▸ actual_peer)

theorem open_successful_use {V S : Type} (ops : EnvelopeVerifier V S)
    (verifier : V) (token : alloc.vec.Vec U8) (expected : Expectation)
    (peer : alloc.vec.Vec U8) (now : I64) (envelope : AuthenticatedEnvelope) (secret : S)
    (verified : ops.verify verifier token = Result.ok (core.result.Result.Ok envelope))
    (bound : Bound envelope.claims expected peer now.val)
    (unsealed : ops.«unseal» verifier envelope = Result.ok (core.result.Result.Ok secret)) :
    open_surrogate ops verifier token expected peer now =
      Result.ok (core.result.Result.Ok ⟨envelope.claims, secret⟩) := by
  simp [open_surrogate, verified, present_exact, bound, unsealed]


def Prepared (input : IssueInputs) (now lifetime : Int) (claims : Claims) : Prop :=
  IssueAllowed input.active input.epoch.val input.not_after.val now lifetime ∧
    claims.issuer = input.issuer ∧ claims.audience = input.audience ∧
    claims.subject = input.subject ∧ claims.token_id = input.token_id ∧
    claims.certificate = input.certificate ∧ claims.epoch.val = input.epoch.val ∧
    claims.issued_at.val = now ∧ claims.expires_at.val = min (now + lifetime) input.not_after.val

def PrepareSpec (input : IssueInputs) (now lifetime : Int) (out : core.result.Result Claims Denial) : Prop :=
  match out with
  | .Ok claims => Prepared input now lifetime claims
  | .Err .InvalidCapability => ¬ IssueAllowed input.active input.epoch.val input.not_after.val now lifetime

theorem prepare_issue_contract (input : IssueInputs) (now lifetime : I64) :
    prepare_issue input now lifetime ⦃ out => PrepareSpec input now.val lifetime.val out ⦄ := by
  unfold prepare_issue
  apply WP.spec_bind (issue_contract input.active input.epoch input.not_after now lifetime)
  intro result property
  cases result with
  | Err denial => cases denial; simpa only [WP.spec_ok, PrepareSpec, IssueSpec] using property
  | Ok window =>
    dsimp only [IssueSpec] at property
    simp only [WP.spec_ok, PrepareSpec, Prepared]
    exact ⟨property.1, True.intro, True.intro, True.intro, True.intro, True.intro, property.2.2.1, property.2.1, property.2.2.2⟩

theorem issue_surrogate_contract {I S : Type} (ops : EnvelopeIssuer I S) (issuer : I)
    (input : IssueInputs) (now lifetime : I64) (secret : S)
    (Sealed : Claims → S → alloc.vec.Vec U8 → Prop)
    (seal_contract : ∀ claims, ops.«seal» issuer claims secret ⦃ out =>
      match out with | .Ok token => Sealed claims secret token | .Err _ => True ⦄) :
    issue_surrogate ops issuer input now lifetime secret ⦃ out =>
      match out with
      | .Ok issued => Prepared input now.val lifetime.val issued.claims ∧
          Sealed issued.claims secret issued.token
      | .Err _ => True ⦄ := by
  unfold issue_surrogate
  apply WP.spec_bind (prepare_issue_contract input now lifetime)
  intro result property
  cases result with
  | Err denial => simp
  | Ok claims =>
    dsimp only [PrepareSpec] at property
    dsimp only
    apply WP.spec_bind (seal_contract claims)
    intro sealed related
    cases sealed with
    | Err denial => simp
    | Ok token => simpa only [WP.spec_ok] using And.intro property related

theorem inactive_enrollment_never_sealed {I S : Type} (ops : EnvelopeIssuer I S) (issuer : I)
    (input : IssueInputs) (now lifetime : I64) (secret : S) (inactive : input.active = false) :
    issue_surrogate ops issuer input now lifetime secret =
      Result.ok (core.result.Result.Err Denial.InvalidCapability) := by
  obtain ⟨result, returned, property⟩ := returned_of_spec (prepare_issue_contract input now lifetime)
  cases result with
  | Ok claims => simp [PrepareSpec, Prepared, IssueAllowed, inactive] at property
  | Err denial => cases denial; simp [issue_surrogate, returned]

end aivm_secrets_garrett_core.Proofs

namespace aivm_secrets_garrett_core.credential_use.Proofs
open aivm_secrets_garrett_core.Proofs

def Current (c : UseClaims) (g : UseGrant) (now elapsed : Int) : Prop :=
  g.active = true ∧ c.binding = g.claims.binding ∧ c.policy = g.claims.policy ∧
  c.grant = g.claims.grant ∧ c.issued_at = g.claims.issued_at ∧
  c.expires_at = g.claims.expires_at ∧ 0 ≤ c.issued_at.val ∧
  c.issued_at.val ≤ 9223372036854772207 ∧ c.issued_at.val < c.expires_at.val ∧
  c.expires_at.val ≤ c.issued_at.val + 3600 ∧ c.issued_at.val ≤ now ∧
  now < c.expires_at.val ∧ 0 ≤ elapsed ∧ elapsed < c.expires_at.val - c.issued_at.val

instance (c : UseClaims) (g : UseGrant) (now elapsed : Int) :
    Decidable (Current c g now elapsed) := by unfold Current; infer_instance

def UseSpec (c : UseClaims) (g : UseGrant) (op : alloc.vec.Vec U8) (now elapsed : Int)
    (out : core.result.Result Unit UseDenial) : Prop :=
  match out with
  | .Ok _ => Current c g now elapsed ∧ op = g.operation
  | .Err .InvalidCapability => ¬ Current c g now elapsed
  | .Err .Denied => Current c g now elapsed ∧ op ≠ g.operation
  | .Err .Upstream => False

theorem require_use_current_contract (c : UseClaims) (g : UseGrant) (now elapsed : I64) :
    require_use_current c g now elapsed ⦃ out =>
      match out with
      | .Ok _ => Current c g now.val elapsed.val
      | .Err .InvalidCapability => ¬ Current c g now.val elapsed.val
      | .Err _ => False ⦄ := by
  unfold require_use_current
  by_cases active : g.active = true
  · simp only [active, ↓reduceIte]
    apply WP.spec_bind (bytes_ne_spec c.binding g.claims.binding)
    intro different0 neq0
    by_cases h0 : different0 = true
    · simp_all [WP.spec_ok, Current]
    · simp only [h0]
      apply WP.spec_bind (bytes_ne_spec c.policy g.claims.policy)
      intro different1 neq1
      by_cases h1 : different1 = true
      · simp_all [WP.spec_ok, Current]
      · simp only [h1]
        apply WP.spec_bind (bytes_ne_spec c.grant g.claims.grant)
        intro different2 neq2
        by_cases h2 : different2 = true
        · simp_all [WP.spec_ok, Current]
        · simp only [h2]
          repeat' first
          | (solve | simp_all [WP.spec_ok, Current]; all_goals scalar_tac)
          | split
          | step
  · simp_all [WP.spec_ok, Current]

theorem authorize_use_contract (c : UseClaims) (g : UseGrant) (op : alloc.vec.Vec U8) (now elapsed : I64) :
    authorize_use c g op now elapsed ⦃ out => UseSpec c g op now.val elapsed.val out ⦄ := by
  unfold authorize_use
  apply WP.spec_bind (require_use_current_contract c g now elapsed)
  intro checked property
  cases checked with
  | Err error => cases error <;> simp_all [UseSpec]
  | Ok value =>
    dsimp only at property
    dsimp only
    apply WP.spec_bind (bytes_ne_spec op g.operation)
    intro different neq
    by_cases h : different = true <;> simp_all [WP.spec_ok, UseSpec]

theorem release_reply_exact (response : ProviderReply) :
    release_reply response = Result.ok (PublicReply.mk response.account_id response.active) := by
  rfl

/-- Two-run noninterference of the actual release function: arbitrary discarded
    provider bytes do not change any field of the public result. -/
theorem release_noninterference (a b : ProviderReply)
    (same_id : a.account_id = b.account_id) (same_active : a.active = b.active) :
    release_reply a = release_reply b := by
  simp [release_reply, same_id, same_active]

end aivm_secrets_garrett_core.credential_use.Proofs


namespace aivm_secrets_garrett_core.credential_use.Proofs
open aivm_secrets_garrett_core.Proofs

theorem authorize_use_exact (c : UseClaims) (g : UseGrant) (op : alloc.vec.Vec U8) (now elapsed : I64) :
    authorize_use c g op now elapsed = Result.ok
      (if Current c g now.val elapsed.val then
        if op = g.operation then core.result.Result.Ok () else core.result.Result.Err UseDenial.Denied
       else core.result.Result.Err UseDenial.InvalidCapability) := by
  obtain ⟨out, returned, property⟩ := returned_of_spec (authorize_use_contract c g op now elapsed)
  cases out with
  | Ok value =>
      cases value
      dsimp only [UseSpec] at property
      simpa [property.1, property.2] using returned
  | Err error =>
      cases error with
      | InvalidCapability =>
          dsimp only [UseSpec] at property
          simpa [property] using returned
      | Denied =>
          dsimp only [UseSpec] at property
          simpa [property.1, property.2] using returned
      | Upstream => exact False.elim property

/-- Composition over the actual executor call. The only credential-bearing
    operation receives the selected route and precisely the opened credential. -/
theorem credential_use_contract {E S : Type} (ops : CredentialExecutor E S) (executor : E)
    (secret : S) (c : UseClaims) (g : UseGrant) (op : alloc.vec.Vec U8) (now elapsed : I64)
    (Executed : Route → S → ProviderReply → Prop)
    (execute_contract : ops.execute executor g.route secret ⦃ out =>
      match out with | .Ok response => Executed g.route secret response | .Err _ => True ⦄) :
    use_credential ops executor secret c g op now elapsed ⦃ out =>
      match out with
      | .Ok released => Current c g now.val elapsed.val ∧ op = g.operation ∧
          ∃ response, Executed g.route secret response ∧
            released.account_id = response.account_id ∧ released.active = response.active
      | .Err _ => True ⦄ := by
  unfold use_credential finish_use
  apply WP.spec_bind (authorize_use_contract c g op now elapsed)
  intro checked authorized
  cases checked with
  | Err error => simp
  | Ok value =>
    dsimp only [UseSpec] at authorized
    dsimp only
    apply WP.spec_bind execute_contract
    intro result executed
    cases result with
    | Err error => simp
    | Ok response =>
      apply WP.spec_bind (show release_reply response ⦃ released =>
        released.account_id = response.account_id ∧ released.active = response.active ⦄ from by
          simp [release_reply])
      intro released projection
      simpa only [WP.spec_ok] using
        And.intro authorized.1 (And.intro authorized.2 ⟨response, executed, projection⟩)

theorem inactive_grant_never_executes {E S : Type} (ops : CredentialExecutor E S) (executor : E)
    (secret : S) (c : UseClaims) (g : UseGrant) (op : alloc.vec.Vec U8) (now elapsed : I64)
    (inactive : g.active = false) :
    use_credential ops executor secret c g op now elapsed =
      Result.ok (core.result.Result.Err UseDenial.InvalidCapability) := by
  simp [use_credential, finish_use, authorize_use_exact, Current, inactive]

theorem unauthorized_operation_never_executes {E S : Type} (ops : CredentialExecutor E S) (executor : E)
    (secret : S) (c : UseClaims) (g : UseGrant) (op : alloc.vec.Vec U8) (now elapsed : I64)
    (current : Current c g now.val elapsed.val) (wrong : op ≠ g.operation) :
    use_credential ops executor secret c g op now elapsed =
      Result.ok (core.result.Result.Err UseDenial.Denied) := by
  simp [use_credential, finish_use, authorize_use_exact, current, wrong]

theorem credential_use_successful {E S : Type} (ops : CredentialExecutor E S) (executor : E)
    (secret : S) (c : UseClaims) (g : UseGrant) (now elapsed : I64) (response : ProviderReply)
    (current : Current c g now.val elapsed.val)
    (executed : ops.execute executor g.route secret = Result.ok (core.result.Result.Ok response)) :
    use_credential ops executor secret c g g.operation now elapsed =
      Result.ok (core.result.Result.Ok (PublicReply.mk response.account_id response.active)) := by
  simp [use_credential, finish_use, authorize_use_exact, current, executed, release_reply]

/-- Changing the credential and arbitrary private response content leaves the
    released result identical when the provider's declared public result agrees.
    This is not a claim about malicious providers encoding secrets in public data. -/
theorem credential_use_noninterference {E S : Type} (ops : CredentialExecutor E S) (executor : E)
    (secret_a secret_b : S) (c : UseClaims) (g : UseGrant) (op : alloc.vec.Vec U8) (now elapsed : I64)
    (a b : ProviderReply)
    (execute_a : ops.execute executor g.route secret_a = Result.ok (core.result.Result.Ok a))
    (execute_b : ops.execute executor g.route secret_b = Result.ok (core.result.Result.Ok b))
    (same_id : a.account_id = b.account_id) (same_active : a.active = b.active) :
    use_credential ops executor secret_a c g op now elapsed =
    use_credential ops executor secret_b c g op now elapsed := by
  simp only [use_credential, finish_use, authorize_use_exact]
  split_ifs <;> simp [execute_a, execute_b, release_reply, same_id, same_active]

end aivm_secrets_garrett_core.credential_use.Proofs
