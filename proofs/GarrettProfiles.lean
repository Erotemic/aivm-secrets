import GarrettSecrecy

/-!
Configuration-dependent, ideal-cryptography claims. These reuse the protocol's
Dolev-Yao deduction model; they do NOT verify TPM hardware, host isolation,
key-enrollment provenance, response declassification, or runtime refinement.
`verifiedTpm` names a required environmental premise, never a caller assertion.
A device alone does not supply that premise. Provider credential confinement
is a separate property from resistance to copying the client identity.
-/
namespace Garrett.Profiles
open Garrett.Protocol

inductive KeyCustody where
  | software
  | deviceOnly
  | verifiedTpm
  deriving DecidableEq

/-- Broker decryption keys remain protected in every supported configuration.
    Only independently verified custody protects the client key from export. -/
def protectedKeys (custody : KeyCustody) (broker client key : Nat) : Prop :=
  key = broker ∨ (custody = .verifiedTpm ∧ key = client)

def protectedCredentials (provider credential : Nat) : Prop := credential = provider

/-- Allowing software identities does not require releasing provider credentials.
    All emitted messages must still refine PublicTrace under the listed profile. -/
theorem provider_credential_confined_in_every_profile
    (custody : KeyCustody) (broker client provider : Nat)
    {observations : List Message}
    (trace : PublicTrace (protectedCredentials provider)
      (protectedKeys custody broker client) observations) :
    ¬ Derives observations (.credential provider) :=
  all_traces_preserve_credential_secrecy _ _ trace provider rfl

/-- Reading an exportable software identity can defeat key-copy resistance.
    This is an explicit permitted attack, not an always-deny security model. -/
theorem software_identity_copy_witness (broker client provider : Nat)
    (separate : client ≠ broker) :
    PublicTrace (protectedCredentials provider)
      (protectedKeys .software broker client) [.key client] ∧
      Derives [.key client] (.key client) := by
  constructor
  · apply PublicTrace.attackerKey client PublicTrace.empty
    simp [protectedKeys, separate]
  · exact .observed (by simp)

/-- Adding a virtual device without moving/verifying the key changes no claim. -/
theorem device_presence_does_not_change_key_protection (broker client : Nat) :
    protectedKeys .deviceOnly broker client = protectedKeys .software broker client := by
  funext key
  simp [protectedKeys]

/-- Even a copied client key does not reveal a separately held provider token
    in this protocol model. Scope abuse and impersonation are separate risks. -/
theorem copied_software_identity_does_not_reveal_provider
    (broker client provider : Nat) (separate : client ≠ broker) :
    ¬ Derives [.key client] (.credential provider) :=
  provider_credential_confined_in_every_profile .software broker client provider
    (software_identity_copy_witness broker client provider separate).1

/-- With the additional verified-custody premise, the modeled client key
    cannot be exported through any admitted protocol history. -/
theorem verified_custody_prevents_key_export (broker client provider : Nat)
    {observations : List Message}
    (trace : PublicTrace (protectedCredentials provider)
      (protectedKeys .verifiedTpm broker client) observations) :
    ¬ Derives observations (.key client) :=
  private_key_not_derivable _ _ observations
    (every_trace_observation_safe _ _ trace) client (Or.inr ⟨rfl, rfl⟩)

/-- A signing oracle can produce an authentication signature without exporting
    the key. Non-exportability alone therefore does not exclude signing relays.
    An oracle is an external adapter here, not an extracted TPM implementation. -/
theorem signing_oracle_can_authenticate_without_key_export
    (broker client provider challenge : Nat) :
    let observations := [Message.signed client (.publicData challenge)]
    Derives observations (.signed client (.publicData challenge)) ∧
    ¬ Derives observations (.key client) ∧
    ¬ Derives observations (.credential provider) := by
  dsimp
  have safe : ∀ m ∈ [Message.signed client (.publicData challenge)],
      Safe (protectedCredentials provider) (protectedKeys .verifiedTpm broker client) m := by
    intro m member
    have eq : m = .signed client (.publicData challenge) := by simpa using member
    subst m
    exact .signed (.publicData challenge)
  exact ⟨.observed (by simp),
    private_key_not_derivable _ _ _ safe client (Or.inr ⟨rfl, rfl⟩),
    provider_credential_not_derivable _ _ _ safe provider rfl⟩

/-- A host executor handed the credential falls outside the confinement premise.
    No stronger client-key custody can make that observation confidential. -/
theorem credential_bearing_arbitrary_host_execution_counterexample (provider : Nat) :
    Derives [Message.credential provider] (.credential provider) :=
  .observed (by simp)

end Garrett.Profiles
