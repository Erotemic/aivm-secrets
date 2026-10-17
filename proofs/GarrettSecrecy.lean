import Garrett

/-! Ideal-cryptography protocol secrecy, separate from the implementation-linked
    controller proofs in Garrett. Crypto/library refinement remains explicit. -/
namespace Garrett.Protocol

inductive Message where
  | publicData (value : Nat)
  | credential (identity : Nat)
  | key (identity : Nat)
  | pair (left right : Message)
  | sealed (key nonce : Nat) (plaintext : Message)
  | signed (key : Nat) (body : Message)

/-- Public observations may contain encrypted secrets; protection is about what
    an adversary can derive, rather than a substring/AST-occurrence check. -/
inductive Safe (secrets keys : Nat → Prop) : Message → Prop where
  | publicData (n) : Safe secrets keys (.publicData n)
  | credential (n) (unprotected : ¬ secrets n) : Safe secrets keys (.credential n)
  | key (n) (unprotected : ¬ keys n) : Safe secrets keys (.key n)
  | pair {a b} : Safe secrets keys a → Safe secrets keys b → Safe secrets keys (.pair a b)
  | signed {k m} : Safe secrets keys m → Safe secrets keys (.signed k m)
  | sealedPrivate {k n m} : keys k → Safe secrets keys (.sealed k n m)
  | sealedPublic {k n m} : Safe secrets keys m → Safe secrets keys (.sealed k n m)

/-- Dolev-Yao knowledge: pair/signature contents are readable, ciphertext needs
    its key, and the attacker can construct messages with authority it knows. -/
inductive Derives (observations : List Message) : Message → Prop where
  | observed {m} : m ∈ observations → Derives observations m
  | publicData (n) : Derives observations (.publicData n)
  | pair {a b} : Derives observations a → Derives observations b → Derives observations (.pair a b)
  | left {a b} : Derives observations (.pair a b) → Derives observations a
  | right {a b} : Derives observations (.pair a b) → Derives observations b
  | sign {k m} : Derives observations (.key k) → Derives observations m → Derives observations (.signed k m)
  | body {k m} : Derives observations (.signed k m) → Derives observations m
  | encrypt {k n m} : Derives observations (.key k) → Derives observations m → Derives observations (.sealed k n m)
  | decrypt {k n m} : Derives observations (.sealed k n m) → Derives observations (.key k) → Derives observations m

theorem derivation_preserves_confinement (secrets keys : Nat → Prop)
    (observations : List Message) (safe : ∀ m ∈ observations, Safe secrets keys m)
    {m : Message} (deduced : Derives observations m) : Safe secrets keys m := by
  induction deduced with
  | observed member => exact safe _ member
  | publicData n => exact .publicData n
  | pair _ _ left right => exact .pair left right
  | left _ pair => cases pair with | pair left _ => exact left
  | right _ pair => cases pair with | pair _ right => exact right
  | sign _ _ _ body => exact .signed body
  | body _ signature => cases signature with | signed body => exact body
  | encrypt _ _ _ plaintext => exact .sealedPublic plaintext
  | decrypt _ _ ciphertext key =>
      cases ciphertext with
      | sealedPublic plaintext => exact plaintext
      | sealedPrivate isSecret =>
          cases key with | key _ notProtected => exact (notProtected isSecret).elim

theorem provider_credential_not_derivable (secrets keys : Nat → Prop)
    (observations : List Message) (safe : ∀ m ∈ observations, Safe secrets keys m)
    (credential : Nat) (isSecret : secrets credential) :
    ¬ Derives observations (.credential credential) := by
  intro deduced
  have confined := derivation_preserves_confinement secrets keys observations safe deduced
  cases confined with | credential _ unprotected => exact unprotected isSecret

theorem private_key_not_derivable (secrets keys : Nat → Prop)
    (observations : List Message) (safe : ∀ m ∈ observations, Safe secrets keys m)
    (key : Nat) (isSecret : keys key) : ¬ Derives observations (.key key) := by
  intro deduced
  have confined := derivation_preserves_confinement secrets keys observations safe deduced
  cases confined with | key _ unprotected => exact unprotected isSecret

def surrogate (signing outerKey innerKey outerNonce innerNonce credential metadata : Nat) : Message :=
  .signed signing (.pair (.publicData metadata)
    (.sealed outerKey outerNonce (.sealed innerKey innerNonce (.credential credential))))

theorem surrogate_can_be_public (secrets keys : Nat → Prop)
    (signing outerKey innerKey outerNonce innerNonce credential metadata : Nat)
    (outer_private : keys outerKey) :
    Safe secrets keys (surrogate signing outerKey innerKey outerNonce innerNonce credential metadata) := by
  exact .signed (.pair (.publicData _) (.sealedPrivate outer_private))

/-- Public traces expose only protocol-produced surrogates, declassified public
    data and keys outside the isSecret set. The attacker may then adaptively
    construct, replay, dissect or decrypt anything its knowledge permits. -/
inductive PublicTrace (secrets keys : Nat → Prop) : List Message → Prop where
  | empty : PublicTrace secrets keys []
  | publicReply {observations} (n : Nat) : PublicTrace secrets keys observations →
      PublicTrace secrets keys (.publicData n :: observations)
  | attackerKey {observations} (n : Nat) : PublicTrace secrets keys observations →
      (¬ keys n) → PublicTrace secrets keys (.key n :: observations)
  | issue {observations} (signing outerKey innerKey outerNonce innerNonce credential metadata : Nat) :
      PublicTrace secrets keys observations → keys outerKey →
      PublicTrace secrets keys
        (surrogate signing outerKey innerKey outerNonce innerNonce credential metadata :: observations)
  | attacker {observations m} : PublicTrace secrets keys observations →
      Derives observations m → PublicTrace secrets keys (m :: observations)

theorem every_trace_observation_safe (secrets keys : Nat → Prop)
    {observations : List Message} (trace : PublicTrace secrets keys observations) :
    ∀ m ∈ observations, Safe secrets keys m := by
  induction trace with
  | empty => simp
  | publicReply n _ ih =>
      intro m member
      rcases List.mem_cons.mp member with rfl | prior
      · exact .publicData n
      · exact ih m prior
  | attackerKey n _ unprotected ih =>
      intro m member
      rcases List.mem_cons.mp member with rfl | prior
      · exact .key n unprotected
      · exact ih m prior
  | issue signing outerKey innerKey outerNonce innerNonce credential metadata _ keyPrivate ih =>
      intro m member
      rcases List.mem_cons.mp member with rfl | prior
      · exact surrogate_can_be_public secrets keys signing outerKey innerKey outerNonce innerNonce credential metadata keyPrivate
      · exact ih m prior
  | attacker _ deduced ih =>
      intro m member
      rcases List.mem_cons.mp member with rfl | prior
      · exact derivation_preserves_confinement secrets keys _ ih deduced
      · exact ih m prior

theorem all_traces_preserve_credential_secrecy (secrets keys : Nat → Prop)
    {observations : List Message} (trace : PublicTrace secrets keys observations)
    (credential : Nat) (isSecret : secrets credential) :
    ¬ Derives observations (.credential credential) :=
  provider_credential_not_derivable secrets keys observations
    (every_trace_observation_safe secrets keys trace) credential isSecret

end Garrett.Protocol
