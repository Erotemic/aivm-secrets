import GarrettStatelessProtocol
import GarrettStatelessRoundTrip

/-!
# `garrett-stateless-v1`: positive witnesses

The safety theorems would hold vacuously for a broker that issued nothing or
a proxy that opened nothing. These theorems show the extracted code does the
useful thing: a surrogate the broker issues opens, at the proxy or at
renewal, for the peer it is bound to, and yields exactly the credential
sealed into it. Their premises are the configured key set and the two
correctness contracts of the primitives (`SignVerifies`, `AeadInverse`).
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs
open garrett_stateless_core.stateless_token
open garrett_stateless_core.stateless_token.Proofs (seal_then_open KeysValid)

namespace garrett_stateless_core.stateless_protocol

variable {M : Type}

theorem admitted_issuer {c : stateless.SurrogateClaims} {k1 k2 : Slice U8} {a : stateless.Acceptance}
    {peer : Slice U8} {now : I64} (same : k1.val = k2.val) (h : stateless.Proofs.Admitted c k1 a peer now) :
    stateless.Proofs.Admitted c k2 a peer now := by
  unfold stateless.Proofs.Admitted at *
  rw [← same]; exact h

/-- **Issue, then use.** A surrogate `stateless::issue` produced with a key
    whose `kid` the configured set holds opens with `stateless::open` for
    every peer and time the admission rule accepts, with exactly the issued
    claims and exactly the issued credential. -/
theorem issue_then_open {inst : KeyMaterial M} {sealer : TokenSealer M} {keys : KeySet M} {e : KeyEntry M} {i : Nat}
    (configured : Configured keys) (at_i : keys.entries.val[i]? = some e) (sameKid : e.kid.val = sealer.entry.kid.val)
    (sig : stateless_boundary.SignVerifies inst sealer.entry.material e.material)
    (aead : stateless_boundary.AeadInverse inst sealer.entry.material e.material)
    {policy : stateless.IssuePolicy} {grant : stateless.Grant} {cred tid : Slice U8} {now lifetime : I64}
    {issued : stateless.Issued}
    (hi : stateless.issue (Sealing inst) sealer policy grant cred tid now lifetime = Result.ok (.Ok issued))
    {a : stateless.Acceptance} {peer : Slice U8} {later : I64}
    (admissible : stateless.Proofs.Admitted issued.claims (alloc.vec.Vec.deref e.issuer) a peer later) :
    ∃ opened : stateless.Opened,
      stateless.open (Opening inst) keys (alloc.vec.Vec.deref issued.token) a peer later = Result.ok (.Ok opened) ∧
      opened.claims = issued.claims ∧ opened.credential.val = cred.val := by
  obtain ⟨valid, _, sealed⟩ := stateless.Proofs.issue_trace (Sealing inst) sealer hi
  rw [sealing_seal] at sealed
  have kv : KeysValid (alloc.vec.Vec.deref keys.entries).val := by
    rw [deref_any]; exact configured_keys configured
  have at_i' : (alloc.vec.Vec.deref keys.entries).val[i]? = some e := by rw [deref_any]; exact at_i
  obtain ⟨v, hv, _, vclaims, viss, out, hout, outv⟩ := seal_then_open kv at_i' sameKid sig aead sealed
  refine ⟨⟨v.claims, out⟩, ?_, vclaims, outv⟩
  have hv' : (Opening inst).verify keys (alloc.vec.Vec.deref issued.token) = Result.ok (.Ok v) := by
    rw [opening_verify]; exact hv
  have hu' : KeySet.Insts.Garrett_stateless_coreStatelessSurrogateOpener.unseal inst keys v =
      Result.ok (.Ok out) := hout
  obtain ⟨r1, hr1, _⟩ := returned_of_spec (stateless.Proofs.admit_spec v.claims (alloc.vec.Vec.deref v.key_issuer)
    a peer later)
  have r1ok : r1 = .Ok () := (stateless.Proofs.admit_ok_iff _ _ _ _ _ r1 hr1).mpr (by
    rw [vclaims]; exact admitted_issuer (by rw [deref_any, deref_any, viss]) admissible)
  subst r1ok
  have same : alloc.vec.Vec.deref out = cred := Slice.ext _ _ (by rw [deref_any, outv])
  obtain ⟨b, hb, bv⟩ := returned_of_spec (http_auth.Proofs.valid_credential_contract (alloc.vec.Vec.deref out))
  have bt : b = true := bv.mpr (by rw [same]; exact valid)
  subst bt
  unfold stateless.open
  rw [hv']
  simp only [bind_ok]
  rw [hr1]
  simp only [bind_ok]
  rw [hu']
  simp only [bind_ok]
  rw [hb]
  simp only [bind_ok, ↓reduceIte]

/-- **The codec premise, discharged.** For the real opener and sealer, a
    verified issued token yields exactly the claims sealed into it — the
    premise `issued_only_opens_for_its_certificate` took — with no assumption
    on any primitive. -/
theorem issued_codec {inst : KeyMaterial M} {sealer : TokenSealer M} {keys : KeySet M} (configured : Configured keys)
    {policy : stateless.IssuePolicy} {grant : stateless.Grant} {cred tid : Slice U8} {now lifetime : I64}
    {issued : stateless.Issued}
    (hi : stateless.issue (Sealing inst) sealer policy grant cred tid now lifetime = Result.ok (.Ok issued)) :
    ∀ v, (Opening inst).verify keys (alloc.vec.Vec.deref issued.token) = Result.ok (.Ok v) →
      v.claims = issued.claims := by
  intro v hv
  obtain ⟨_, _, sealed⟩ := stateless.Proofs.issue_trace (Sealing inst) sealer hi
  rw [sealing_seal] at sealed
  rw [opening_verify] at hv
  have kv : KeysValid (alloc.vec.Vec.deref keys.entries).val := by
    rw [deref_any]; exact configured_keys configured
  obtain ⟨a1, b1, c1, _, _, _, _, tv, _, Ha, _, Hb, _, Hc, _⟩ := stateless_token.Proofs.verify_token_sound kv hv
  have part : SignedPart (alloc.vec.Vec.deref issued.token).val (a1 ++ 46#u8 :: b1) :=
    ⟨a1, b1, c1, ⟨tv, b64_no_dot Ha, b64_no_dot Hb, b64_no_dot Hc⟩, rfl⟩
  have part' : SignedPart issued.token.val (a1 ++ 46#u8 :: b1) := by
    rw [← deref_any]; exact part
  obtain ⟨_, _, _, same, _⟩ := accepts_sealed kv hv sealed part part'
  exact same

/-- **Issued for `C`, opens only for `C`**, for the real opener and sealer,
    with no premise beyond a configured key set. -/
theorem issued_opens_only_for_its_certificate {inst : KeyMaterial M} {sealer : TokenSealer M} {keys : KeySet M}
    (configured : Configured keys) {policy : stateless.IssuePolicy} {grant : stateless.Grant} {cred tid : Slice U8}
    {now lifetime : I64} {issued : stateless.Issued}
    (hi : stateless.issue (Sealing inst) sealer policy grant cred tid now lifetime = Result.ok (.Ok issued))
    (a : stateless.Acceptance) (peer : Slice U8) (later : I64) (opened : stateless.Opened)
    (ho : stateless.open (Opening inst) keys (alloc.vec.Vec.deref issued.token) a peer later = Result.ok (.Ok opened)) :
    peer.val = grant.certificate.val :=
  stateless.Proofs.issued_only_opens_for_its_certificate (Sealing inst) sealer (Opening inst) keys hi
    (issued_codec configured hi) a peer later opened ho

end garrett_stateless_core.stateless_protocol
