import GarrettHttpAuth

/-!
# `garrett-stateless-v1`: surrogate admission, opening, issuance, renewal

Source: `crates/garrett-stateless-core/src/stateless.rs`, extracted by
Aeneas into `generated/GarrettStatelessCore.lean` (`stateless.*`). Both the
proxy (`stateless_proxy::serve`) and the broker (`garrett-stateless`'s
renewal and issuance) call these functions; nothing here is a second model.

The cryptographic adapters are the traits `SurrogateOpener` (`verify`:
Ed25519 over the compact header and payload plus strict decoding; `unseal`:
AES-256-GCM with the header/claims AAD) and `SurrogateSealer`. Theorems take
their behaviour as arbitrary predicates (`Authentic`, `Unsealed`, `Sealed`),
so they hold for *any* adapter, and say exactly what the controller adds.

Proved:

* `admit_ok_iff`: admission accepts exactly the claims satisfying `Admitted`
  (issuer of the verifying key, accepted audience and provider, bounded
  lifetime and renewal, the clock inside `[iat - skew, exp)`, and
  `cnf = peer` byte for byte);
* `open_contract`: an opened surrogate came from an authentic envelope whose
  claims were admitted for **this** peer, and its credential is what the
  adapter unsealed from that envelope and a valid credential;
* `open_unadmitted_never_unseals`: if admission fails, the result is the same
  for every `unseal` adapter, so nothing was decrypted;
* `issue_contract`, `issue_window_contract`: an issued surrogate's
  authoritative claims are the policy's issuer and audience and the grant's
  provider, subject and certificate, its window is capped by lifetime,
  renewal limit, certificate and credential expiry, and it was sealed around
  a valid credential;
* `renew_contract`: renewal keeps the presented token's binding, provider,
  subject and credential, never extends `ren`, and requires the presenting
  peer to be that binding;
* `issued_only_opens_for_its_certificate`: under a codec contract (verified
  claims are the sealed claims), a surrogate issued for certificate `C` opens
  for no peer other than `C`.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core.Proofs

set_option maxHeartbeats 4000000

namespace garrett_stateless_core.stateless.Proofs

/-! ## Membership -/

/-- `value` is one of the members, byte for byte. -/
def Member (set : Slice (alloc.vec.Vec U8)) (value : Slice U8) : Prop :=
  ∃ x ∈ set.val, x.val = value.val

def MemberFrom (set : Slice (alloc.vec.Vec U8)) (start : Nat) (value : Slice U8) : Prop :=
  ∃ (index : Nat) (inside : index < set.length), start ≤ index ∧ set[index].val = value.val

theorem member_from_step (set : Slice (alloc.vec.Vec U8)) (start : Nat) (value : Slice U8)
    (inside : start < set.length) :
    MemberFrom set start value ↔ set[start].val = value.val ∨ MemberFrom set (start + 1) value := by
  constructor
  · rintro ⟨i, hi, after, equal⟩
    by_cases same : i = start
    · subst i; exact Or.inl equal
    · exact Or.inr ⟨i, hi, by omega, equal⟩
  · rintro (head | ⟨i, hi, after, equal⟩)
    · exact ⟨start, inside, Nat.le_refl _, head⟩
    · exact ⟨i, hi, by omega, equal⟩

theorem member_loop_contract (iter : core.slice.iter.Iter (alloc.vec.Vec U8)) (value : Slice U8) :
    member_loop iter value ⦃ out => out ↔ MemberFrom iter.slice iter.i value ⦄ := by
  suffices ∀ n (it : core.slice.iter.Iter (alloc.vec.Vec U8)), it.slice.length - it.i = n →
      member_loop it value ⦃ out => out ↔ MemberFrom it.slice it.i value ⦄ from this _ iter rfl
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro it measure
    rw [member_loop.eq_def]
    by_cases inside : it.i < it.slice.length
    · have next_return : core.slice.iter.IteratorSliceIter.next it =
          Result.ok (some it.slice[it.i], {it with i := it.i + 1}) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
        rfl
      rw [next_return]
      simp only [bind_ok, slice_eq_eq]
      change (if decide ((alloc.vec.Vec.deref it.slice[it.i]).val = value.val) = true then Result.ok true
          else member_loop {it with i := it.i + 1} value) ⦃ out => out = true ↔ MemberFrom it.slice it.i value ⦄
      split
      · rename_i same
        apply (WP.spec_ok _).mpr
        simp only [true_iff]
        exact ⟨it.i, inside, Nat.le_refl _, by simpa [alloc.vec.Vec.deref] using same⟩
      · rename_i same
        apply WP.spec_mono (ih (it.slice.length - (it.i + 1)) (by omega) {it with i := it.i + 1} rfl)
        intro out tail
        have different : ¬ it.slice[it.i].val = value.val := by simpa [alloc.vec.Vec.deref] using same
        have rest : MemberFrom it.slice it.i value ↔ MemberFrom it.slice (it.i + 1) value := by
          rw [member_from_step it.slice it.i value inside]
          simp only [different, false_or]
        exact tail.trans rest.symm
    · have next_return : core.slice.iter.IteratorSliceIter.next it = Result.ok (none, it) := by
        simp [core.slice.iter.IteratorSliceIter.next, inside]
      rw [next_return]
      simp only [bind_ok]
      apply (WP.spec_ok _).mpr
      simp only [Bool.false_eq_true, false_iff]
      rintro ⟨i, hi, after, equal⟩
      omega

@[step]
theorem member_spec (set : Slice (alloc.vec.Vec U8)) (value : Slice U8) :
    member set value ⦃ out => out ↔ Member set value ⦄ := by
  unfold member
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  apply WP.spec_mono (member_loop_contract ⟨set, 0⟩ value)
  intro out h
  refine h.trans ⟨?_, ?_⟩
  · rintro ⟨i, hi, _, equal⟩
    exact ⟨set[i], List.getElem_mem hi, equal⟩
  · rintro ⟨x, mem, equal⟩
    obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem mem
    exact ⟨i, hi, Nat.zero_le _, equal⟩

/-! ## Admission -/

/-- Every check `admit` makes, as one proposition. -/
def Admitted (c : SurrogateClaims) (keyIssuer : Slice U8) (a : Acceptance) (peer : Slice U8)
    (now : I64) : Prop :=
  1 ≤ a.max_lifetime.val ∧ a.max_lifetime.val ≤ 86400 ∧ 0 ≤ a.skew.val ∧ a.skew.val ≤ 300 ∧
  0 ≤ now.val ∧ now.val ≤ 9007199254740991 ∧
  c.issuer.val = keyIssuer.val ∧
  Member (alloc.vec.Vec.deref a.audiences) (alloc.vec.Vec.deref c.audience) ∧
  Member (alloc.vec.Vec.deref a.providers) (alloc.vec.Vec.deref c.provider) ∧
  0 ≤ c.issued_at.val ∧ c.issued_at.val ≤ 9007199254740991 ∧
  c.issued_at.val < c.expires_at.val ∧ c.expires_at.val - c.issued_at.val ≤ a.max_lifetime.val ∧
  c.expires_at.val ≤ c.renew_until.val ∧ c.renew_until.val - c.issued_at.val ≤ 2592000 ∧
  c.issued_at.val ≤ now.val + a.skew.val ∧ now.val < c.expires_at.val ∧
  c.certificate.val = peer.val

def AcceptanceValid (a : Acceptance) : Prop :=
  1 ≤ a.max_lifetime.val ∧ a.max_lifetime.val ≤ 86400 ∧ 0 ≤ a.skew.val ∧ a.skew.val ≤ 300

@[step]
theorem acceptance_valid_spec (a : Acceptance) :
    acceptance_valid a ⦃ out => out ↔ AcceptanceValid a ⦄ := by
  unfold acceptance_valid MAX_LIFETIME MAX_SKEW
  repeat' first
  | (solve | simp_all [WP.spec_ok, AcceptanceValid]; all_goals scalar_tac)
  | split

def LifetimeValid (c : SurrogateClaims) (m : Int) : Prop :=
  0 ≤ c.issued_at.val ∧ c.issued_at.val ≤ 9007199254740991 ∧
  c.issued_at.val < c.expires_at.val ∧ c.expires_at.val - c.issued_at.val ≤ m ∧
  c.expires_at.val ≤ c.renew_until.val ∧ c.renew_until.val - c.issued_at.val ≤ 2592000

@[step]
theorem lifetime_valid_spec (c : SurrogateClaims) (m : I64) :
    lifetime_valid c m ⦃ out => out ↔ LifetimeValid c m.val ⦄ := by
  unfold lifetime_valid MAX_TIME MAX_RENEW
  repeat' first
  | (solve | simp_all [WP.spec_ok, LifetimeValid]; all_goals scalar_tac)
  | split
  | step

theorem admitted_iff (c : SurrogateClaims) (k : Slice U8) (a : Acceptance) (peer : Slice U8) (now : I64) :
    Admitted c k a peer now ↔ AcceptanceValid a ∧ 0 ≤ now.val ∧ now.val ≤ 9007199254740991 ∧
      c.issuer.val = k.val ∧
      Member (alloc.vec.Vec.deref a.audiences) (alloc.vec.Vec.deref c.audience) ∧
      Member (alloc.vec.Vec.deref a.providers) (alloc.vec.Vec.deref c.provider) ∧
      LifetimeValid c a.max_lifetime.val ∧
      c.issued_at.val ≤ now.val + a.skew.val ∧ now.val < c.expires_at.val ∧ c.certificate.val = peer.val := by
  simp only [Admitted, AcceptanceValid, LifetimeValid]
  tauto

/-- **Admission is exactly `Admitted`.** -/
theorem admit_spec (c : SurrogateClaims) (k : Slice U8) (a : Acceptance) (peer : Slice U8) (now : I64) :
    admit c k a peer now ⦃ out => out = .Ok () ↔ Admitted c k a peer now ⦄ := by
  rw [admitted_iff]
  unfold admit MAX_TIME
  repeat' first
  | (solve | simp_all [WP.spec_ok, alloc.vec.Vec.deref, AcceptanceValid, LifetimeValid]; all_goals scalar_tac)
  | split
  | step

theorem admit_ok_iff (c : SurrogateClaims) (k : Slice U8) (a : Acceptance) (peer : Slice U8) (now : I64)
    (out : core.result.Result Unit Rejection) (h : admit c k a peer now = Result.ok out) :
    out = .Ok () ↔ Admitted c k a peer now := by
  have spec := admit_spec c k a peer now
  rw [h] at spec
  simpa only [WP.spec_ok] using spec

/-! ## Opening: verify, admit, and only then unseal

`open` is `authenticate` (verify, then admit) followed by `decrypt` (unseal,
then check the credential). The proxy calls the two halves itself, with its
operation policy between them; the broker's renewal calls `open`. -/

/-- **What an authenticated surrogate is.** For any opener adapter: an `Ok`
    result came from an envelope the adapter authenticated for this token,
    whose claims were admitted for **this** `peer` at `now` under the issuer
    of the verifying key. -/
theorem authenticate_contract {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a : Acceptance) (peer : Slice U8) (now : I64) (Authentic : Slice U8 → Verified → Prop)
    (verify_contract : ops.verify opener token ⦃ out =>
      match out with | .Ok v => Authentic token v | .Err _ => True ⦄) :
    authenticate ops opener token a peer now ⦃ out =>
      match out with
      | .Ok v => Authentic token v ∧ Admitted v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now
      | .Err _ => True ⦄ := by
  unfold authenticate
  apply WP.spec_bind verify_contract
  intro r authentic
  cases r with
  | Err e => simp [WP.spec_ok]
  | Ok v =>
    dsimp only at authentic ⊢
    apply WP.spec_bind (admit_spec v.claims _ a peer now)
    intro r1 admitted
    cases r1 with
    | Err e => simp [WP.spec_ok]
    | Ok u =>
      cases u
      simp only [WP.spec_ok]
      exact ⟨authentic, admitted.mp rfl⟩

/-- **What a decrypted surrogate is.** The credential is the adapter's
    unsealing of that envelope and is valid; the claims are unchanged. -/
theorem decrypt_contract {V : Type} (ops : SurrogateOpener V) (opener : V) (v : Verified)
    (Unsealed : Verified → alloc.vec.Vec U8 → Prop)
    (unseal_contract : ops.«unseal» opener v ⦃ out =>
      match out with | .Ok c => Unsealed v c | .Err _ => True ⦄) :
    decrypt ops opener v ⦃ out =>
      match out with
      | .Ok opened => opened.claims = v.claims ∧ Unsealed v opened.credential ∧
          http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref opened.credential)
      | .Err _ => True ⦄ := by
  unfold decrypt
  apply WP.spec_bind unseal_contract
  intro r unsealed
  cases r with
  | Err e => simp [WP.spec_ok]
  | Ok c =>
    dsimp only at unsealed ⊢
    apply WP.spec_bind (http_auth.Proofs.valid_credential_contract _)
    intro b valid
    split
    · rename_i yes
      simp only [WP.spec_ok]
      exact ⟨by simp, unsealed, valid.mp yes⟩
    · simp [WP.spec_ok]

/-- **What an opened surrogate is.** For any opener adapter: an `Ok` result
    came from an envelope the adapter authenticated for this token, whose
    claims were admitted for **this** `peer` at `now` under the issuer of the
    verifying key, and whose credential is the adapter's unsealing of that
    same envelope and a valid credential (`ValidCredential`). -/
theorem open_contract {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a : Acceptance) (peer : Slice U8) (now : I64)
    (Authentic : Slice U8 → Verified → Prop) (Unsealed : Verified → alloc.vec.Vec U8 → Prop)
    (verify_contract : ops.verify opener token ⦃ out =>
      match out with | .Ok v => Authentic token v | .Err _ => True ⦄)
    (unseal_contract : ∀ v, ops.«unseal» opener v ⦃ out =>
      match out with | .Ok c => Unsealed v c | .Err _ => True ⦄) :
    «open» ops opener token a peer now ⦃ out =>
      match out with
      | .Ok opened => ∃ v, Authentic token v ∧
          Admitted v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now ∧
          opened.claims = v.claims ∧ Unsealed v opened.credential ∧
          http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref opened.credential)
      | .Err _ => True ⦄ := by
  unfold «open»
  apply WP.spec_bind (authenticate_contract ops opener token a peer now Authentic verify_contract)
  intro r authenticated
  cases r with
  | Err e => simp [WP.spec_ok]
  | Ok v =>
    dsimp only at authenticated ⊢
    apply WP.spec_mono (decrypt_contract ops opener v Unsealed (unseal_contract v))
    intro out h
    cases out with
    | Err e => trivial
    | Ok opened => exact ⟨v, authenticated.1, authenticated.2, h.1, h.2.1, h.2.2⟩

/-- An authenticated surrogate: `verify` returned it and `admit` accepted its
    claims for this peer, now. -/
theorem authenticate_ok_trace {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a : Acceptance) (peer : Slice U8) (now : I64) (v : Verified)
    (h : authenticate ops opener token a peer now = Result.ok (.Ok v)) :
    ops.verify opener token = Result.ok (.Ok v) ∧
      admit v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now = Result.ok (.Ok ()) ∧
      Admitted v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now := by
  unfold authenticate at h
  obtain ⟨r, hr, h⟩ := bind_ok_inv h
  cases r with
  | Err e => simp at h
  | Ok w =>
    dsimp only at h
    obtain ⟨r1, hr1, h⟩ := bind_ok_inv h
    cases r1 with
    | Err e => simp at h
    | Ok u =>
      simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
      subst h
      cases u
      exact ⟨hr, hr1, (admit_ok_iff _ _ _ _ _ _ hr1).mp rfl⟩

/-- A decrypted surrogate: `unseal` returned exactly its credential, which is
    valid, and its claims are the authenticated ones. -/
theorem decrypt_ok_trace {V : Type} (ops : SurrogateOpener V) (opener : V) (v : Verified) (o : Opened)
    (h : decrypt ops opener v = Result.ok (.Ok o)) :
    ops.«unseal» opener v = Result.ok (.Ok o.credential) ∧ o.claims = v.claims ∧
      http_auth.valid_credential (alloc.vec.Vec.deref o.credential) = Result.ok true := by
  unfold decrypt at h
  obtain ⟨r, hr, h⟩ := bind_ok_inv h
  cases r with
  | Err e => simp at h
  | Ok c =>
    dsimp only at h
    obtain ⟨b, hb, h⟩ := bind_ok_inv h
    split at h
    · rename_i yes
      simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
      subst h
      exact ⟨hr, rfl, by rw [hb, yes]⟩
    · simp at h

/-- **The halves compose to `open`.** -/
theorem open_of_halves {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a : Acceptance) (peer : Slice U8) (now : I64) (v : Verified) (o : Opened)
    (ha : authenticate ops opener token a peer now = Result.ok (.Ok v))
    (hd : decrypt ops opener v = Result.ok (.Ok o)) :
    «open» ops opener token a peer now = Result.ok (.Ok o) := by
  simp [«open», ha, hd]

/-- **Authentication before decryption.** If the verified claims are not
    admitted, `open` refuses with the same result whatever the `unseal`
    adapter would do: the controller never asked for decryption. -/
theorem open_unadmitted_never_unseals {V : Type} (ops : SurrogateOpener V) (opener : V)
    (token : Slice U8) (a : Acceptance) (peer : Slice U8) (now : I64) (v : Verified)
    (verified : ops.verify opener token = Result.ok (.Ok v))
    (refused : ¬ Admitted v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now)
    (other : V → Verified → Result (core.result.Result (alloc.vec.Vec U8) Rejection)) :
    (∃ e, «open» ops opener token a peer now = Result.ok (.Err e)) ∧
    «open» ops opener token a peer now = «open» {ops with «unseal» := other} opener token a peer now := by
  obtain ⟨r1, returned, iff⟩ := returned_of_spec (admit_spec v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now)
  cases r1 with
  | Ok u => exact absurd (iff.mp (by cases u; rfl)) refused
  | Err e =>
    refine ⟨⟨e, ?_⟩, ?_⟩
    · simp [«open», authenticate, verified, returned]
    · simp [«open», authenticate, verified, returned]

/-- A failed verification is returned unchanged; nothing else is consulted. -/
theorem open_unverified {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a : Acceptance) (peer : Slice U8) (now : I64) (e : Rejection)
    (failed : ops.verify opener token = Result.ok (.Err e)) :
    «open» ops opener token a peer now = Result.ok (.Err e) := by
  simp [«open», authenticate, failed]

/-- **The trace of an accepted opening.** An `Ok` result means: `verify`
    returned `v`, `v`'s claims were admitted for this peer, `unseal` was then
    called on that same `v` and returned exactly the released credential,
    and that credential is valid. -/
theorem open_ok_trace {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a : Acceptance) (peer : Slice U8) (now : I64) (opened : Opened)
    (h : «open» ops opener token a peer now = Result.ok (.Ok opened)) :
    ∃ v, ops.verify opener token = Result.ok (.Ok v) ∧
      Admitted v.claims (alloc.vec.Vec.deref v.key_issuer) a peer now ∧
      opened.claims = v.claims ∧ ops.«unseal» opener v = Result.ok (.Ok opened.credential) ∧
      http_auth.Proofs.ValidCredential (alloc.vec.Vec.deref opened.credential) := by
  unfold «open» at h
  obtain ⟨r, hr, h⟩ := bind_ok_inv h
  cases r with
  | Err e => simp at h
  | Ok v =>
    dsimp only at h
    obtain ⟨hv, _, adm⟩ := authenticate_ok_trace ops opener token a peer now v hr
    obtain ⟨hu, hc, hval⟩ := decrypt_ok_trace ops opener v opened h
    obtain ⟨b, hb, valid⟩ :=
      returned_of_spec (http_auth.Proofs.valid_credential_contract (alloc.vec.Vec.deref opened.credential))
    rw [hb] at hval
    simp only [Result.ok.injEq] at hval
    subst hval
    exact ⟨v, hv, adm, hc, hu, valid.mp rfl⟩

/-- **Binding.** An opened surrogate's `cnf` is the peer, byte for byte, and
    the clock is inside its window. -/
theorem open_binds_peer {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a : Acceptance) (peer : Slice U8) (now : I64) (opened : Opened)
    (h : «open» ops opener token a peer now = Result.ok (.Ok opened)) :
    opened.claims.certificate.val = peer.val ∧ now.val < opened.claims.expires_at.val ∧
      opened.claims.issued_at.val ≤ now.val + a.skew.val := by
  obtain ⟨v, _, adm, same, _, _⟩ := open_ok_trace ops opener token a peer now opened h
  rw [same]
  exact ⟨adm.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2, adm.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1,
    adm.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1⟩

/-- **A copied surrogate fails on another certificate.** With a pure verifier
    (the same token always verifies to the same claims), the same surrogate
    cannot open for two peers whose certificates differ. -/
theorem open_one_peer {V : Type} (ops : SurrogateOpener V) (opener : V) (token : Slice U8)
    (a b : Acceptance) (peer other : Slice U8) (now later : I64) (o1 o2 : Opened)
    (first : «open» ops opener token a peer now = Result.ok (.Ok o1))
    (second : «open» ops opener token b other later = Result.ok (.Ok o2)) :
    peer.val = other.val := by
  obtain ⟨v1, h1, adm1, _, _, _⟩ := open_ok_trace ops opener token a peer now o1 first
  obtain ⟨v2, h2, adm2, _, _, _⟩ := open_ok_trace ops opener token b other later o2 second
  rw [h1] at h2
  simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h2
  subst h2
  exact adm1.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.symm.trans adm2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

/-! ## Issuance -/

@[step]
theorem earlier_spec (a b : I64) : earlier a b ⦃ out => out.val = min a.val b.val ⦄ := by
  unfold earlier
  split <;> simp_all [WP.spec_ok, min_def]

/-- The window `issue_window` computes, exactly. -/
def WindowSpec (p : IssuePolicy) (g : Grant) (now lifetime : Int) (w : Window) : Prop :=
  1 ≤ p.max_lifetime.val ∧ p.max_lifetime.val ≤ 86400 ∧ 0 ≤ p.max_renew.val ∧ p.max_renew.val ≤ 2592000 ∧
  0 ≤ now ∧ now ≤ 9007199254740991 - 2592000 ∧ 1 ≤ lifetime ∧ lifetime ≤ p.max_lifetime.val ∧
  w.issued_at.val = now ∧
  w.renew_until.val = min (now + p.max_renew.val) (min g.certificate_expires.val g.credential_expires.val) ∧
  w.expires_at.val = min (now + lifetime) w.renew_until.val ∧ now < w.expires_at.val

theorem issue_window_spec (p : IssuePolicy) (g : Grant) (now lifetime : I64) :
    issue_window p g now lifetime ⦃ out => ∀ w, out = .Ok w → WindowSpec p g now.val lifetime.val w ⦄ := by
  unfold issue_window MAX_LIFETIME MAX_RENEW MAX_TIME
  repeat' first
  | (solve | simp_all [WP.spec_ok, WindowSpec]; all_goals scalar_tac)
  | split
  | step

theorem issue_window_ok {p : IssuePolicy} {g : Grant} {now lifetime : I64} {w : Window}
    (h : issue_window p g now lifetime = Result.ok (.Ok w)) : WindowSpec p g now.val lifetime.val w := by
  have spec := issue_window_spec p g now lifetime
  rw [h] at spec
  simp only [WP.spec_ok] at spec
  exact spec w rfl

/-- What an issued surrogate's authoritative claims are. -/
def IssuedFor (p : IssuePolicy) (g : Grant) (tokenId : Slice U8) (now lifetime : Int)
    (c : SurrogateClaims) : Prop :=
  Member (alloc.vec.Vec.deref p.providers) (alloc.vec.Vec.deref g.provider) ∧
  c.issuer.val = p.issuer.val ∧ c.audience.val = p.audience.val ∧ c.subject = g.subject ∧
  c.provider = g.provider ∧ c.certificate = g.certificate ∧ c.token_id.val = tokenId.val ∧
  ∃ w, WindowSpec p g now lifetime w ∧ c.issued_at = w.issued_at ∧ c.expires_at = w.expires_at ∧
    c.renew_until = w.renew_until

theorem to_vec_val (s : Slice U8) (v : alloc.vec.Vec U8)
    (h : alloc.slice.Slice.to_vec core.clone.CloneU8 s = Result.ok v) : v.val = s.val := by
  obtain ⟨w, hw, eq⟩ := returned_of_spec (alloc.slice.Slice.to_vec_spec core.clone.CloneU8 s (by intro x _; rfl))
  rw [hw] at h
  simp only [Result.ok.injEq] at h
  subst h
  have := congrArg (fun x : Slice U8 => x.val) eq
  simpa [alloc.vec.Vec.val] using this.symm

theorem claims_for_trace {p : IssuePolicy} {g : Grant} {tokenId : Slice U8} {now lifetime : I64}
    {c : SurrogateClaims} (h : claims_for p g tokenId now lifetime = Result.ok (.Ok c)) :
    IssuedFor p g tokenId now.val lifetime.val c := by
  unfold claims_for at h
  obtain ⟨b, hb, h⟩ := bind_ok_inv h
  obtain ⟨b', hb', member⟩ := returned_of_spec (member_spec (alloc.vec.Vec.deref p.providers)
    (alloc.vec.Vec.deref g.provider))
  rw [hb'] at hb
  simp only [Result.ok.injEq] at hb
  subst hb
  split at h
  · rename_i yes
    obtain ⟨r, hr, h⟩ := bind_ok_inv h
    cases r with
    | Err e => simp at h
    | Ok w =>
      dsimp only at h
      obtain ⟨v, hv, h⟩ := bind_ok_inv h
      obtain ⟨v1, hv1, h⟩ := bind_ok_inv h
      obtain ⟨v2, hv2, h⟩ := bind_ok_inv h
      simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
      subst h
      exact ⟨member.mp yes, by simpa [alloc.vec.Vec.deref] using to_vec_val _ _ hv,
        by simpa [alloc.vec.Vec.deref] using to_vec_val _ _ hv1, rfl, rfl, rfl, to_vec_val _ _ hv2,
        w, issue_window_ok hr, rfl, rfl, rfl⟩
  · simp at h

/-- **Issuance correctness.** A successful issuance checked the credential,
    took issuer and audience from the policy and provider, subject and
    certificate from the grant, computed the window of `WindowSpec`, and
    returned exactly what the sealer produced for those claims and that
    credential. -/
theorem issue_trace {S : Type} (ops : SurrogateSealer S) (sealer : S) {p : IssuePolicy} {g : Grant}
    {credential tokenId : Slice U8} {now lifetime : I64} {issued : Issued}
    (h : issue ops sealer p g credential tokenId now lifetime = Result.ok (.Ok issued)) :
    http_auth.Proofs.ValidCredential credential ∧ IssuedFor p g tokenId now.val lifetime.val issued.claims ∧
      ops.«seal» sealer issued.claims credential = Result.ok (.Ok issued.token) := by
  unfold issue at h
  obtain ⟨b, hb, h⟩ := bind_ok_inv h
  obtain ⟨b', hb', valid⟩ := returned_of_spec (http_auth.Proofs.valid_credential_contract credential)
  rw [hb'] at hb
  simp only [Result.ok.injEq] at hb
  subst hb
  split at h
  · rename_i yes
    obtain ⟨r, hr, h⟩ := bind_ok_inv h
    cases r with
    | Err e => simp at h
    | Ok c =>
      dsimp only at h
      obtain ⟨r1, hr1, h⟩ := bind_ok_inv h
      cases r1 with
      | Err e => simp at h
      | Ok token =>
        simp only [Result.ok.injEq, core.result.Result.Ok.injEq] at h
        subst h
        exact ⟨valid.mp yes, claims_for_trace hr, hr1⟩
  · simp at h

/-- **Nothing invalid is sealed.** An invalid credential or an unconfigured
    provider is refused before the sealer is called. -/
theorem issue_invalid_never_seals {S : Type} (ops : SurrogateSealer S) (sealer : S) (p : IssuePolicy)
    (g : Grant) (credential tokenId : Slice U8) (now lifetime : I64)
    (invalid : ¬ http_auth.Proofs.ValidCredential credential) :
    issue ops sealer p g credential tokenId now lifetime = Result.ok (.Err .InvalidCredential) := by
  obtain ⟨b, hb, valid⟩ := returned_of_spec (http_auth.Proofs.valid_credential_contract credential)
  have no : b = false := by cases b <;> simp_all
  simp [issue, hb, no]

/-! ## Renewal -/

theorem renewal_grant_val (c : SurrogateClaims) (e : I64) (g : Grant)
    (h : renewal_grant c e = Result.ok g) :
    g.provider.val = c.provider.val ∧ g.subject.val = c.subject.val ∧ g.certificate.val = c.certificate.val ∧
      g.certificate_expires = e ∧ g.credential_expires = c.renew_until := by
  unfold renewal_grant at h
  obtain ⟨v, hv, h⟩ := bind_ok_inv h
  obtain ⟨v1, hv1, h⟩ := bind_ok_inv h
  obtain ⟨v2, hv2, h⟩ := bind_ok_inv h
  simp only [Result.ok.injEq] at h
  subst h
  exact ⟨by simpa [alloc.vec.Vec.deref] using to_vec_val _ _ hv,
    by simpa [alloc.vec.Vec.deref] using to_vec_val _ _ hv1,
    by simpa [alloc.vec.Vec.deref] using to_vec_val _ _ hv2, rfl, rfl⟩

/-- **Stateless renewal.** A renewed surrogate required the presented token to
    open for this peer, keeps its binding, provider, subject and credential,
    and its `ren` never exceeds the presented token's `ren` (nor the
    certificate's expiry). -/
theorem renew_trace {V S : Type} (opsO : SurrogateOpener V) (opsS : SurrogateSealer S) (opener : V)
    (sealer : S) {a : Acceptance} {p : IssuePolicy} {token peer tokenId : Slice U8}
    {certExpires now lifetime : I64} {issued : Issued}
    (h : renew opsO opsS opener sealer a p token peer certExpires tokenId now lifetime =
      Result.ok (.Ok issued)) :
    ∃ opened, «open» opsO opener token a peer now = Result.ok (.Ok opened) ∧
      issued.claims.certificate.val = opened.claims.certificate.val ∧
      issued.claims.certificate.val = peer.val ∧
      issued.claims.provider.val = opened.claims.provider.val ∧
      issued.claims.subject.val = opened.claims.subject.val ∧
      issued.claims.renew_until.val ≤ opened.claims.renew_until.val ∧
      issued.claims.renew_until.val ≤ certExpires.val ∧
      opsS.«seal» sealer issued.claims (alloc.vec.Vec.deref opened.credential) = Result.ok (.Ok issued.token) := by
  unfold renew at h
  obtain ⟨r, hr, h⟩ := bind_ok_inv h
  cases r with
  | Err e => simp at h
  | Ok opened =>
    dsimp only at h
    obtain ⟨g, hg, h⟩ := bind_ok_inv h
    obtain ⟨gp, gs, gc, ge, gr⟩ := renewal_grant_val _ _ _ hg
    obtain ⟨_, ⟨_, _, _, subject, provider, certificate, _, w, window, _, _, renew⟩, sealed⟩ :=
      issue_trace opsS sealer h
    have bound := (open_binds_peer opsO opener token a peer now opened hr).1
    obtain ⟨_, _, _, _, _, _, _, _, _, ren, _, _⟩ := window
    refine ⟨opened, hr, ?_, ?_, ?_, ?_, ?_, ?_, sealed⟩
    · rw [certificate, gc]
    · rw [certificate, gc, bound]
    · rw [provider, gp]
    · rw [subject, gs]
    · rw [renew, ren, gr]; omega
    · rw [renew, ren, ge]; omega

/-! ## End to end: issued for `C`, opens only for `C` -/

/-- **Binding correctness.** Suppose the opener's `verify` returns, for an
    issued token, exactly the claims the sealer sealed into it (the codec
    and signature contract of the adapters). Then a surrogate issued for
    certificate `C` opens only on a connection authenticated as `C`: for any
    peer `D` whose certificate differs, `open` does not succeed. -/
theorem issued_only_opens_for_its_certificate {S V : Type} (opsS : SurrogateSealer S) (sealer : S)
    (opsO : SurrogateOpener V) (opener : V) {p : IssuePolicy} {g : Grant} {credential tokenId : Slice U8}
    {now lifetime : I64} {issued : Issued}
    (hi : issue opsS sealer p g credential tokenId now lifetime = Result.ok (.Ok issued))
    (codec : ∀ v, opsO.verify opener (alloc.vec.Vec.deref issued.token) = Result.ok (.Ok v) →
      v.claims = issued.claims)
    (a : Acceptance) (peer : Slice U8) (later : I64) (opened : Opened)
    (ho : «open» opsO opener (alloc.vec.Vec.deref issued.token) a peer later = Result.ok (.Ok opened)) :
    peer.val = g.certificate.val := by
  obtain ⟨v, hv, adm, same, _, _⟩ := open_ok_trace opsO opener _ a peer later opened ho
  obtain ⟨_, ⟨_, _, _, _, _, certificate, _⟩, _⟩ := issue_trace opsS sealer hi
  have := codec v hv
  have cert : v.claims.certificate.val = peer.val := adm.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
  rw [this, certificate] at cert
  exact cert.symm

theorem issued_refused_on_other_certificate {S V : Type} (opsS : SurrogateSealer S) (sealer : S)
    (opsO : SurrogateOpener V) (opener : V) {p : IssuePolicy} {g : Grant} {credential tokenId : Slice U8}
    {now lifetime : I64} {issued : Issued}
    (hi : issue opsS sealer p g credential tokenId now lifetime = Result.ok (.Ok issued))
    (codec : ∀ v, opsO.verify opener (alloc.vec.Vec.deref issued.token) = Result.ok (.Ok v) →
      v.claims = issued.claims)
    (a : Acceptance) (other : Slice U8) (later : I64) (different : other.val ≠ g.certificate.val) :
    ∀ opened, «open» opsO opener (alloc.vec.Vec.deref issued.token) a other later ≠ Result.ok (.Ok opened) :=
  fun opened ho => different (issued_only_opens_for_its_certificate opsS sealer opsO opener hi codec a other later opened ho)

end garrett_stateless_core.stateless.Proofs
