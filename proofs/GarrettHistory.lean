import GarrettProtocol
import GarrettSecrecy

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core
open aivm_secrets_garrett_core.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.protocol.Proofs

theorem recorded_issuance_contract {I A C : Type}
    (iops : EnvelopeIssuer I C) (aops : IssuanceObserver A) (issuer : I) (observer : A)
    (input : IssueInputs) (now lifetime : I64) (secret : C)
    (Sealed : Claims → C → alloc.vec.Vec U8 → Prop) (Recorded : Claims → Prop)
    (seal_contract : ∀ claims, iops.«seal» issuer claims secret ⦃ out =>
      match out with | .Ok token => Sealed claims secret token | .Err _ => True ⦄)
    (record_contract : ∀ claims, aops.issued observer claims ⦃ out =>
      match out with | .Ok _ => Recorded claims | .Err _ => True ⦄) :
    issue_recorded iops aops issuer observer input now lifetime secret ⦃ out =>
      match out with
      | .Ok issued => aivm_secrets_garrett_core.Proofs.Prepared input now.val lifetime.val issued.claims ∧
          Sealed issued.claims secret issued.token ∧ Recorded issued.claims
      | .Err _ => True ⦄ := by
  unfold issue_recorded
  apply WP.spec_bind (issue_surrogate_contract iops issuer input now lifetime secret Sealed seal_contract)
  intro result origin
  cases result with
  | Err error => simp
  | Ok issued =>
    dsimp only at origin ⊢
    apply WP.spec_bind (record_contract issued.claims)
    intro acknowledged recorded
    cases acknowledged with
    | Err error => simp
    | Ok value => simpa only [WP.spec_ok] using And.intro origin.1 (And.intro origin.2 recorded)

theorem recorded_issuance_failure {I A C : Type}
    (iops : EnvelopeIssuer I C) (aops : IssuanceObserver A) (issuer : I) (observer : A)
    (input : IssueInputs) (now lifetime : I64) (secret : C) (issued : IssuedSurrogate)
    (sealed : issue_surrogate iops issuer input now lifetime secret = Result.ok (.Ok issued))
    (failed : aops.issued observer issued.claims = Result.ok (.Err Denial.InvalidCapability)) :
    issue_recorded iops aops issuer observer input now lifetime secret =
      Result.ok (.Err Denial.InvalidCapability) := by
  simp [issue_recorded, sealed, failed]

theorem recorded_issuance_success {I A C : Type}
    (iops : EnvelopeIssuer I C) (aops : IssuanceObserver A) (issuer : I) (observer : A)
    (input : IssueInputs) (now lifetime : I64) (secret : C) (issued : IssuedSurrogate)
    (sealed : issue_surrogate iops issuer input now lifetime secret = Result.ok (.Ok issued))
    (recorded : aops.issued observer issued.claims = Result.ok (.Ok ())) :
    issue_recorded iops aops issuer observer input now lifetime secret =
      Result.ok (.Ok issued) := by
  simp [issue_recorded, sealed, recorded]

end aivm_secrets_garrett_core.protocol.Proofs

namespace Garrett.ControllerHistory
open aivm_secrets_garrett_core.protocol
open aivm_secrets_garrett_core.protocol.Proofs
open aivm_secrets_garrett_core.credential_use
open aivm_secrets_garrett_core.credential_use.Proofs

/-- A projection of the private service history. Prepared credentials stay in
    the mathematical witness, never in the public audit representation. -/
inductive Event (S : Type) where
  | issued (token : alloc.vec.Vec U8) (identity : Claims)
  | dispatch (token : alloc.vec.Vec U8) (ready : Prepared S)
      (grant : UseGrant) (operation : alloc.vec.Vec U8) (presentation : Presentation)

def Authentic {S : Type} (past : List (Event S))
    (token : alloc.vec.Vec U8) (envelope : AuthenticatedEnvelope) : Prop :=
  Event.issued token envelope.claims ∈ past

/-- The model records successful source-level issuance and the acknowledged
    dispatch boundary. Verification's origin contract is a crypto assumption,
    not an assumption that presentation or authorization succeeds. -/
inductive Run {I A V O C S : Type}
    (issueOps : EnvelopeIssuer I C) (issueAudit : IssuanceObserver A)
    (verifyOps : EnvelopeVerifier V C) (innerOps : CredentialOpener O C S)
    (auditOps : DispatchObserver A) (issuer : I) (observer : A) (verifier : V) (opener : O) :
    List (Event S) → Prop where
  | empty : Run issueOps issueAudit verifyOps innerOps auditOps issuer observer verifier opener []
  | issue {past} (previous : Run issueOps issueAudit verifyOps innerOps auditOps issuer observer verifier opener past)
      (input : IssueInputs) (now lifetime : I64) (secret : C) (issued : IssuedSurrogate)
      (released : issue_recorded issueOps issueAudit issuer observer input now lifetime secret = Result.ok (.Ok issued)) :
      Run issueOps issueAudit verifyOps innerOps auditOps issuer observer verifier opener
        (.issued issued.token issued.claims :: past)
  | dispatch {past} (previous : Run issueOps issueAudit verifyOps innerOps auditOps issuer observer verifier opener past)
      (token : alloc.vec.Vec U8) (ready : Prepared S) (g : UseGrant)
      (op : alloc.vec.Vec U8) (p : Presentation)
      (verify_contract : verifyOps.verify verifier token ⦃ out =>
        match out with | .Ok env => Authentic past token env | .Err _ => True ⦄)
      (unseal_contract : ∀ env, verifyOps.«unseal» verifier env ⦃ _ => True ⦄)
      (inner_contract : ∀ cap, innerOps.«open» opener cap ⦃ _ => True ⦄)
      (prepared : prepare verifyOps innerOps verifier opener token g op p = Result.ok (.Ok ready))
      (recorded : auditOps.record observer ready.identity ready.claims g.route op = Result.ok (.Ok ())) :
      Run issueOps issueAudit verifyOps innerOps auditOps issuer observer verifier opener
        (.dispatch token ready g op p :: past)

/-- Each dispatch's witness must occur in its strictly older suffix. Tokens
    are reusable: distinct dispatches may refer to the same issuance. -/
def Corresponds {S : Type} : List (Event S) → Prop
  | [] => True
  | event :: past => Corresponds past ∧ match event with
      | .issued _ _ => True
      | .dispatch token ready g op p =>
          Event.issued token ready.identity ∈ past ∧
          Bound ready.identity p.expected p.peer p.now.val ∧
          Current ready.claims g p.now.val p.elapsed.val ∧ op = g.operation

theorem all_histories_correspond {I A V O C S : Type}
    (issueOps : EnvelopeIssuer I C) (issueAudit : IssuanceObserver A)
    (verifyOps : EnvelopeVerifier V C) (innerOps : CredentialOpener O C S)
    (auditOps : DispatchObserver A) (issuer : I) (observer : A) (verifier : V) (opener : O)
    {past : List (Event S)}
    (run : Run issueOps issueAudit verifyOps innerOps auditOps issuer observer verifier opener past) :
    Corresponds past := by
  induction run with
  | empty => trivial
  | issue _ _ _ _ _ _ _ ih => exact ⟨ih, True.intro⟩
  | dispatch _ token ready g op p verification unsealing opening accepted _ ih =>
    have origin := prepared_contract verifyOps innerOps verifier opener token g op p
      (Authentic _) (fun _ _ => True) (fun _ _ _ => True)
      verification
      (by intro env; apply WP.spec_mono (unsealing env); intro out _; cases out <;> trivial)
      (by intro cap; apply WP.spec_mono (opening cap); intro out _; cases out <;> trivial)
    rw [accepted] at origin
    simp only [WP.spec_ok] at origin
    rcases origin with ⟨envelope, cap, issued, bound, identity, _, _, current, operation⟩
    exact ⟨ih, by simpa [Authentic, identity] using issued, by simpa [identity] using bound, current, operation⟩

/-- Connect the modeled acknowledged boundary to the actual source controller's
    execution continuation, independently of provider success, error or divergence. -/
theorem dispatch_continuation {V O A E C S : Type}
    (vops : EnvelopeVerifier V C) (iops : CredentialOpener O C S)
    (aops : DispatchObserver A) (eops : CredentialExecutor E S)
    (verifier : V) (opener : O) (observer : A) (executor : E)
    (token : alloc.vec.Vec U8) (g : UseGrant) (op : alloc.vec.Vec U8) (p : Presentation)
    (ready : Prepared S)
    (prepared : prepare vops iops verifier opener token g op p = Result.ok (.Ok ready))
    (recorded : aops.record observer ready.identity ready.claims g.route op = Result.ok (.Ok ())) :
    perform vops iops aops eops verifier opener observer executor token g op p =
      finish_use eops executor ready.credential g.route := by
  simp [perform, prepared, recorded]

end Garrett.ControllerHistory

namespace Garrett.History
open Garrett.Protocol

/-- A readable protected signature must originate in the issuer's output set.
    The predicate traverses ciphertext too; deduction never invents a signature
    even if an attacker can subsequently open or wrap its enclosing message. -/
def SignatureOrigin (signing : Nat) (issued : List Message) : Message → Prop
  | .pair a b => SignatureOrigin signing issued a ∧ SignatureOrigin signing issued b
  | .sealed _ _ m => SignatureOrigin signing issued m
  | .signed k m => (k = signing → .signed k m ∈ issued) ∧ SignatureOrigin signing issued m
  | _ => True

theorem signature_origin_monotone (signing : Nat) (a b : List Message)
    (subset : ∀ m ∈ a, m ∈ b) (m : Message)
    (origin : SignatureOrigin signing a m) : SignatureOrigin signing b m := by
  induction m with
  | publicData _ => trivial
  | credential _ => trivial
  | key _ => trivial
  | pair left right ihl ihr => exact ⟨ihl origin.1, ihr origin.2⟩
  | sealed _ _ _ ih => exact ih origin
  | signed k body ih => exact ⟨fun eq => subset _ (origin.1 eq), ih origin.2⟩

theorem deduction_preserves_signature_origin (signing : Nat)
    (observations issued : List Message)
    (private_key : ¬ Derives observations (.key signing))
    (origins : ∀ m ∈ observations, SignatureOrigin signing issued m)
    {m : Message} (deduced : Derives observations m) : SignatureOrigin signing issued m := by
  induction deduced with
  | observed member => exact origins _ member
  | publicData _ => trivial
  | pair _ _ left right => exact ⟨left, right⟩
  | left _ pair => exact pair.1
  | right _ pair => exact pair.2
  | sign key _ _ body =>
    refine ⟨?_, body⟩
    intro eq
    subst eq
    exact (private_key key).elim
  | body _ signature => exact signature.2
  | encrypt _ _ _ plaintext => exact plaintext
  | decrypt _ _ ciphertext _ => exact ciphertext

/-- Source-labelled adaptive traces retain honest issuance separately from
    attacker observations. Replaying or copying a token does not issue it anew. -/
inductive Trace (secrets keys : Nat → Prop) : List Message → List Message → Prop where
  | empty : Trace secrets keys [] []
  | publicReply {obs issued} (n : Nat) : Trace secrets keys obs issued →
      Trace secrets keys (.publicData n :: obs) issued
  | attackerKey {obs issued} (n : Nat) : Trace secrets keys obs issued → ¬ keys n →
      Trace secrets keys (.key n :: obs) issued
  | issue {obs issued} (signing outerKey innerKey outerNonce innerNonce credential metadata : Nat) :
      Trace secrets keys obs issued → keys outerKey →
      Trace secrets keys
        (surrogate signing outerKey innerKey outerNonce innerNonce credential metadata :: obs)
        (surrogate signing outerKey innerKey outerNonce innerNonce credential metadata :: issued)
  | attacker {obs issued m} : Trace secrets keys obs issued → Derives obs m →
      Trace secrets keys (m :: obs) issued

theorem trace_is_public {secrets keys : Nat → Prop} {obs issued : List Message}
    (trace : Trace secrets keys obs issued) : PublicTrace secrets keys obs := by
  induction trace with
  | empty => exact .empty
  | publicReply n _ ih => exact .publicReply n ih
  | attackerKey n _ key ih => exact .attackerKey n ih key
  | issue s o i on inn c m _ key ih => exact .issue s o i on inn c m ih key
  | attacker _ deduced ih => exact .attacker ih deduced

theorem every_observation_has_signature_origin {secrets keys : Nat → Prop}
    {obs issued : List Message} (signing : Nat) (key_private : keys signing)
    (trace : Trace secrets keys obs issued) :
    ∀ m ∈ obs, SignatureOrigin signing issued m := by
  induction trace with
  | empty => simp
  | publicReply n _ ih =>
    intro m member
    rcases List.mem_cons.mp member with rfl | prior
    · trivial
    · exact ih m prior
  | attackerKey n _ _ ih =>
    intro m member
    rcases List.mem_cons.mp member with rfl | prior
    · trivial
    · exact ih m prior
  | issue s o i on inn c metadata _ _ ih =>
    intro m member
    rcases List.mem_cons.mp member with rfl | prior
    · simp [surrogate, SignatureOrigin]
    · exact signature_origin_monotone signing _ _ (by intro x hx; exact List.mem_cons_of_mem _ hx) m (ih m prior)
  | attacker previous deduced ih =>
    intro m member
    rcases List.mem_cons.mp member with rfl | prior
    · apply deduction_preserves_signature_origin signing _ _ ?_ ih deduced
      exact private_key_not_derivable secrets keys _
        (every_trace_observation_safe secrets keys (trace_is_public previous)) signing key_private
    · exact ih m prior

theorem protected_signature_was_issued {secrets keys : Nat → Prop}
    {obs issued : List Message} (signing : Nat) (key_private : keys signing)
    (trace : Trace secrets keys obs issued) (body : Message)
    (accepted : Derives obs (.signed signing body)) : .signed signing body ∈ issued := by
  have origin := deduction_preserves_signature_origin signing obs issued
    (private_key_not_derivable secrets keys obs
      (every_trace_observation_safe secrets keys (trace_is_public trace)) signing key_private)
    (every_observation_has_signature_origin signing key_private trace) accepted
  exact origin.1 rfl

end Garrett.History
