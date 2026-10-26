import GarrettStateless
import GarrettLogin

/-!
# `garrett-stateless-v1`: agent-initiated login, binding and delivery

Source: `rust/crates/aivm-secrets-garrett-core/src/stateless_login.rs`,
extracted by Aeneas (`stateless_login.*`). The broker of the
`garrett-stateless` crate calls `begin` with the mTLS peer of the login
request, `accept_callback` and `begin_exchange` for the provider redirect,
`complete` after the code exchange and `deliver` for each poll. Sealing the
login state, PKCE, the HTTPS exchange and the mailbox map are adapters.

Proved:

* `begin_trace`: a login is bound to the certificate of the peer that began
  it, for a configured provider, on this replica, within at most 600 s;
* `accept_callback_trace`: a callback is accepted only for the mailbox
  entry of the same login, peer, provider, window and replica, only while
  pending and inside the window, and only under the provider's RFC 9207
  issuer rule (through the proved `oauth_login::claim`);
* `complete_trace`: a surrogate is issued only for an exchanging entry and
  its own state, bound to the entry's certificate and provider;
* `deliver_trace`, `deliver_other_peer`: only the entry's certificate can
  collect, only once complete and within the delivery grace;
* `login_surrogate_bound_to_starting_peer`: when the mailbox only changes an
  entry's stage, the surrogate a login produces is bound to the peer that
  began it, and the only peer that can collect it is that peer.
-/

open Aeneas Aeneas.Std
open aivm_secrets_garrett_core.Proofs
open aivm_secrets_garrett_core.proxy_http.Proofs (bind_ok_inv)
open aivm_secrets_garrett_core.stateless.Proofs
set_option maxHeartbeats 4000000

namespace aivm_secrets_garrett_core.stateless_login.Proofs

theorem vec_deref_mk (v : alloc.vec.Vec U8) : ({ slice := alloc.vec.Vec.deref v } : alloc.vec.Vec U8) = v := by
  cases v with
  | mk s =>
    congr 1
    rw [Slice.eq_iff]
    simp [alloc.vec.Vec.deref, alloc.vec.Vec.val]

def BeginSpec (policy : LoginPolicy) (provider peer subject : Slice U8) (certExpires : I64)
    (login verifier scope : Slice U8) (now : I64) (s : LoginState) : Prop :=
  s.certificate.val = peer.val ∧ s.provider.val = provider.val ∧
  Member (alloc.vec.Vec.deref policy.providers) provider ∧ s.replica.val = policy.replica.val ∧
  s.subject.val = subject.val ∧ s.login.val = login.val ∧ s.verifier.val = verifier.val ∧
  s.scope.val = scope.val ∧ s.certificate_expires = certExpires ∧ now.val < certExpires.val ∧
  s.issued_at = now ∧ s.expires_at.val = now.val + policy.ttl.val ∧
  1 ≤ policy.ttl.val ∧ policy.ttl.val ≤ 600

/-- **A login belongs to the peer that began it.** -/
theorem begin_spec (policy : LoginPolicy) (provider peer subject : Slice U8) (certExpires : I64)
    (login verifier scope : Slice U8) (now : I64) :
    «begin» policy provider peer subject certExpires login verifier scope now ⦃ out =>
      ∀ s, out = .Ok s → BeginSpec policy provider peer subject certExpires login verifier scope now s ⦄ := by
  unfold «begin» MAX_LOGIN stateless.MAX_TIME
  simp only [to_vec_eq, bind_ok]
  repeat' first
  | (solve | simp_all [WP.spec_ok, BeginSpec, alloc.vec.Vec.deref, alloc.vec.Vec.val]; all_goals scalar_tac)
  | split
  | step

theorem begin_trace {policy : LoginPolicy} {provider peer subject : Slice U8} {certExpires : I64}
    {login verifier scope : Slice U8} {now : I64} {s : LoginState}
    (h : «begin» policy provider peer subject certExpires login verifier scope now = Result.ok (.Ok s)) :
    BeginSpec policy provider peer subject certExpires login verifier scope now s := by
  have spec := begin_spec policy provider peer subject certExpires login verifier scope now
  rw [h] at spec
  simp only [WP.spec_ok] at spec
  exact spec s rfl

theorem entry_of_eq (s : LoginState) :
    entry_of s = Result.ok
      { login := s.login, provider := s.provider, certificate := s.certificate,
        issued_at := s.issued_at, expires_at := s.expires_at, stage := .Pending } := by
  simp only [entry_of, to_vec_eq, bind_ok, vec_deref_mk]

/-- The entry and the state belong to the same login on this replica. -/
def SameLogin (policy : LoginPolicy) (e : Entry) (s : LoginState) : Prop :=
  s.replica.val = policy.replica.val ∧ e.login.val = s.login.val ∧ e.provider.val = s.provider.val ∧
  e.certificate.val = s.certificate.val ∧ e.issued_at = s.issued_at ∧ e.expires_at = s.expires_at

@[step]
theorem same_login_spec (policy : LoginPolicy) (e : Entry) (s : LoginState) :
    same_login policy e s ⦃ out => out ↔ SameLogin policy e s ⦄ := by
  unfold same_login
  repeat' first
  | (solve | simp_all [WP.spec_ok, SameLogin, alloc.vec.Vec.deref])
  | split
  | step

theorem rule_copy_eq (rule : oauth_login.IssuerRule) :
    rule_copy rule = Result.ok (match rule with
      | .Absent => .Absent
      | .Exact x => .Exact ⟨alloc.vec.Vec.deref x⟩) := by
  cases rule <;> simp [rule_copy, to_vec_eq]

/-- The provider's RFC 9207 rule, over the callback's `iss` bytes. -/
def IssuerHolds (rule : oauth_login.IssuerRule) (issuer : Slice U8) (has : Bool) : Prop :=
  match rule with
  | .Absent => has = false
  | .Exact expected => has = true ∧ issuer.val = expected.val

theorem claim_ok {stage : oauth_login.Stage} {p : oauth_login.Pending} {cb : oauth_login.Callback}
    {now : I64} {st : oauth_login.Stage} (h : oauth_login.claim stage p cb now = Result.ok (.Ok st)) :
    oauth_login.Proofs.Bound stage p cb now ∧ st = (if cb.denied then .Denied else .Accepted) := by
  have claimed := oauth_login.Proofs.claim_contract stage p cb now
  rw [h] at claimed
  simp only [WP.spec_ok] at claimed
  exact (claimed st).mp rfl

/-- **Callback acceptance.** An accepted callback names this entry's login,
    peer, provider and window on this replica; the entry was pending; the
    clock is inside the window; the issuer rule holds; and the new stage is
    `Denied` exactly for an `error=` redirect. -/
theorem accept_callback_trace {policy : LoginPolicy} {e : Entry} {s : LoginState}
    {rule : oauth_login.IssuerRule} {issuer : Slice U8} {has denied : Bool} {now : I64}
    {stage : oauth_login.Stage}
    (h : accept_callback policy e s rule issuer has denied now = Result.ok (.Ok stage)) :
    SameLogin policy e s ∧ e.stage = .Pending ∧
      e.issued_at.val ≤ now.val ∧ now.val < e.expires_at.val ∧ e.expires_at.val ≤ e.issued_at.val + 600 ∧
      IssuerHolds rule issuer has ∧ stage = (if denied then .Denied else .Accepted) := by
  unfold accept_callback at h
  obtain ⟨b, hb, h⟩ := bind_ok_inv h
  obtain ⟨b', hb', same⟩ := returned_of_spec (same_login_spec policy e s)
  rw [hb'] at hb
  simp only [Result.ok.injEq] at hb
  subst hb
  split at h
  · rename_i yes
    have sl := same.mp yes
    simp only [pending_of, to_vec_eq, rule_copy_eq, bind_ok] at h
    obtain ⟨⟨pending, ⟨_, _, _, _, after, before⟩, _, issuerOk⟩, result⟩ := claim_ok h
    refine ⟨sl, pending, after, before, by assumption, ?_, result⟩
    cases rule with
    | Absent => simpa [oauth_login.Proofs.IssuerBound, IssuerHolds] using issuerOk
    | Exact x =>
      simp only [oauth_login.Proofs.IssuerBound] at issuerOk
      obtain ⟨hh, eq⟩ := issuerOk
      refine ⟨hh, ?_⟩
      have := congrArg alloc.vec.Vec.val eq
      simpa [alloc.vec.Vec.deref, alloc.vec.Vec.val] using this
  · simp at h

theorem grant_of_eq (e : Entry) (s : LoginState) (credExpires : I64) :
    grant_of e s credExpires = Result.ok
      { provider := e.provider, subject := s.subject, certificate := e.certificate,
        certificate_expires := s.certificate_expires, credential_expires := credExpires } := by
  simp only [grant_of, to_vec_eq, bind_ok, vec_deref_mk]

/-- **Issuance at completion.** A login yields a surrogate only from an
    exchanging entry and its own state; the surrogate is bound to the entry's
    certificate, provider and the state's subject, and is what the sealer
    produced (`issue_trace`). -/
theorem complete_trace {S : Type} (ops : stateless.SurrogateSealer S) (sealer : S)
    {lp : LoginPolicy} {p : stateless.IssuePolicy} {e : Entry} {s : LoginState}
    {credential : Slice U8} {credExpires : I64} {tokenId : Slice U8} {now lifetime : I64}
    {issued : stateless.Issued}
    (h : complete ops sealer lp p e s credential credExpires tokenId now lifetime = Result.ok (.Ok issued)) :
    e.stage = .Exchanging ∧ SameLogin lp e s ∧
      issued.claims.certificate = e.certificate ∧ issued.claims.provider = e.provider ∧
      issued.claims.subject = s.subject ∧ http_auth.Proofs.ValidCredential credential ∧
      ops.«seal» sealer issued.claims credential = Result.ok (.Ok issued.token) := by
  unfold complete at h
  cases hs : e.stage <;> rw [hs] at h <;> try simp at h
  obtain ⟨b, hb, h⟩ := bind_ok_inv h
  obtain ⟨b', hb', same⟩ := returned_of_spec (same_login_spec lp e s)
  rw [hb'] at hb
  simp only [Result.ok.injEq] at hb
  subst hb
  split at h
  · rename_i yes
    simp only [grant_of_eq, bind_ok] at h
    obtain ⟨valid, ⟨_, _, _, subject, provider, certificate, _⟩, sealed⟩ := issue_trace ops sealer h
    exact ⟨rfl, same.mp yes, certificate, provider, subject, valid, sealed⟩
  · simp at h

/-- **Delivery.** A surrogate is delivered only to the entry's certificate,
    only once complete, and only within the delivery grace. -/
theorem deliver_spec (e : Entry) (peer : Slice U8) (now : I64) :
    deliver e peer now ⦃ out => out = .Deliver →
      e.certificate.val = peer.val ∧ e.stage = .Complete ∧ now.val < e.expires_at.val + 300 ⦄ := by
  unfold deliver stateless.MAX_TIME DELIVERY_GRACE
  repeat' first
  | (solve | simp_all [WP.spec_ok, alloc.vec.Vec.deref]; all_goals scalar_tac)
  | split
  | step

theorem deliver_trace (e : Entry) (peer : Slice U8) (now : I64)
    (h : deliver e peer now = Result.ok .Deliver) :
    e.certificate.val = peer.val ∧ e.stage = .Complete ∧ now.val < e.expires_at.val + 300 := by
  have spec := deliver_spec e peer now
  rw [h] at spec
  simpa only [WP.spec_ok, forall_const] using spec

/-- A poll from any other certificate gets `WrongCertificate`, whatever the stage. -/
theorem deliver_other_peer (e : Entry) (peer : Slice U8) (now : I64)
    (different : e.certificate.val ≠ peer.val) :
    deliver e peer now = Result.ok .WrongCertificate := by
  simp [deliver, proxy_http.Proofs.slice_eq_eq, alloc.vec.Vec.deref, different]

/-- The mailbox changed nothing but the stage of the entry `begin` created. -/
def StageOnly (e0 e : Entry) : Prop :=
  e.login = e0.login ∧ e.provider = e0.provider ∧ e.certificate = e0.certificate ∧
  e.issued_at = e0.issued_at ∧ e.expires_at = e0.expires_at

/-- **OAuth binding, end to end.** A login begun by `peer0` creates an entry;
    if the mailbox only ever changes that entry's stage, then any surrogate
    `complete` issues for it — whatever (authenticated) state the callback
    carried — is bound to `peer0`'s certificate, and the only peer to which
    `deliver` hands it over is `peer0`. -/
theorem login_surrogate_bound_to_starting_peer {S : Type} (ops : stateless.SurrogateSealer S) (sealer : S)
    {policy : LoginPolicy} {provider peer0 subject : Slice U8} {certExpires : I64}
    {login verifier scope : Slice U8} {now0 : I64} {s0 : LoginState} {e0 : Entry}
    (begun : «begin» policy provider peer0 subject certExpires login verifier scope now0 = Result.ok (.Ok s0))
    (created : entry_of s0 = Result.ok e0)
    {p : stateless.IssuePolicy} {e1 : Entry} {s1 : LoginState} {credential : Slice U8}
    {credExpires : I64} {tokenId : Slice U8} {now1 lifetime : I64} {issued : stateless.Issued}
    (kept1 : StageOnly e0 e1)
    (completed : complete ops sealer policy p e1 s1 credential credExpires tokenId now1 lifetime =
      Result.ok (.Ok issued))
    {e2 : Entry} {peer : Slice U8} {now2 : I64}
    (kept2 : StageOnly e0 e2)
    (delivered : deliver e2 peer now2 = Result.ok .Deliver) :
    issued.claims.certificate.val = peer0.val ∧ peer.val = peer0.val := by
  have start := (begin_trace begun).1
  rw [entry_of_eq] at created
  simp only [Result.ok.injEq] at created
  subst created
  obtain ⟨_, _, certificate, _⟩ := complete_trace ops sealer completed
  obtain ⟨_, _, c1, _⟩ := kept1
  obtain ⟨_, _, c2, _⟩ := kept2
  have collected := (deliver_trace e2 peer now2 delivered).1
  rw [c2] at collected
  refine ⟨?_, ?_⟩
  · rw [certificate, c1]; exact start
  · rw [← collected]; exact start

end aivm_secrets_garrett_core.stateless_login.Proofs
