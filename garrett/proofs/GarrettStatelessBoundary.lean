import GarrettStatelessGrammar

/-!
# `garrett-stateless-v1`: the external boundary, as propositions

Everything the broker and proxy do is extracted from our Rust and proved
about directly. What is not ours is reached only through four trait
interfaces whose implementations the theorems quantify over:

* `stateless_token.KeyMaterial` — Ed25519 `sign`/`verify` and AES-256-GCM
  `seal`/`open` (`ring`, in `garrett-stateless/src/token.rs`);
* `stateless_token.StateKey` — AES-256-GCM for the login state;
* `stateless_mailbox.CodeExchange` — the provider's OAuth token endpoint;
* `stateless_proxy.Channel`/`Origin` — the TLS connection, its clock, and the
  pinned provider connection.

Randomness (nonces, login ids, token ids), the clock, the TLS peer
thumbprint, every OAuth answer and every socket or file result enter as
arbitrary values: no theorem constrains them. The only properties assumed of
the primitives are the ones below. Each is a `Prop` over a given instance,
taken as an explicit premise by the theorems that need it — never a global
axiom, and never a statement about our own code.
-/

open Aeneas Aeneas.Std

namespace garrett_stateless_core.stateless_boundary

open garrett_stateless_core.stateless_token

/-- **Ed25519 correctness.** A signature the signing half produced verifies,
    under the verifying half, over the same bytes. -/
def SignVerifies {M : Type} (inst : KeyMaterial M) (signer verifier : M) : Prop :=
  ∀ (msg msg' : Slice U8) (sig : alloc.vec.Vec U8) (sig' : Slice U8),
    inst.sign signer msg = Result.ok (some sig) → msg'.val = msg.val → sig'.val = sig.val →
    inst.verify verifier msg' sig' = Result.ok true

/-- **AES-256-GCM correctness.** What a key seals, the same key opens under
    the same nonce and associated data; the ciphertext is the plaintext and a
    16-byte tag. -/
def AeadInverse {M : Type} (inst : KeyMaterial M) (sealer opener : M) : Prop :=
  ∀ (n a pt : Slice U8) (ct : alloc.vec.Vec U8),
    inst.seal sealer n a pt = Result.ok (some ct) →
    ct.val.length = pt.val.length + 16 ∧
    ∀ (n' a' c' : Slice U8), n'.val = n.val → a'.val = a.val → c'.val = ct.val →
      ∃ out : alloc.vec.Vec U8, inst.open opener n' a' c' = Result.ok (some out) ∧ out.val = pt.val

/-- **Ed25519 unforgeability, over an execution.** The verifying half
    accepts only bytes that were signed, in this execution, by its signing
    half. This is the idealized form of EUF-CMA: the global theorems hold for
    every execution in which no signature was forged. -/
def SignaturesAuthentic {M : Type} (inst : KeyMaterial M) (verifier : M) (signed : List (List U8)) : Prop :=
  ∀ (msg sig : Slice U8), inst.verify verifier msg sig = Result.ok true → msg.val ∈ signed

end garrett_stateless_core.stateless_boundary
