import GarrettStatelessComposition
import GarrettStatelessStrict
import GarrettStatelessWitness

/-!
# `garrett-stateless-v1`: what is proved

Start here. This module states the guarantees of the protocol in a few named
propositions and derives each from the implementation-linked theorems
underneath. Nothing here is a second model: every function mentioned is the
Aeneas extraction of `crates/garrett-stateless-core`
(`generated/GarrettStatelessCore.lean`), and every theorem is a projection of
`protocol_safety` (`GarrettStatelessProtocol`), `composed_egress`
(`GarrettStatelessComposition`), `strict_no_login_state`
(`GarrettStatelessStrict`) or `issued_opens_only_for_its_certificate`
(`GarrettStatelessWitness`).

## The actors

* the **agent**, untrusted, holds a client certificate and receives
  surrogates; it never receives a provider credential;
* the **broker** issues surrogates: after an OAuth login (`stateless_login`,
  `stateless_mailbox`), as an operator mint, or as a renewal (`stateless`);
* the **proxy** (`stateless_proxy`) opens a surrogate presented on an mTLS
  connection, authorizes the operation, decrypts the credential and sends
  exactly one request to the provider the surrogate names;
* the **provider** is the upstream API.

## The model of an execution

`World` records the broker's login mailbox and its history, and every
renewal, mint and proxy connection so far. `Step` is one extracted
transition with arbitrary inputs: any agent request, any OAuth answer, any
channel behaviour, any configured key set. `Reachable` is every finite
interleaving of steps from the empty world.

## The hypotheses (`docs/assumptions.json`)

* `AeadInverse`: AES-256-GCM decrypts what it encrypted under paired keys
  (`STATELESS-CRYPTO-01`). It is correctness only; nonce uniqueness is a
  runtime obligation of the application, not a theorem.
* `Unforged`: no Ed25519 signature was forged under a proxy's key set (an
  idealized EUF-CMA), stated per key set where the proxy relies on it.
* The native shells (TLS, sockets, clock, randomness) are trusted to call the
  core as `verification/shell_guard.py` checks (`STATELESS-NATIVE-01`), and
  the TLS layer to report the authenticated peer (`STATELESS-TLS-01`).

## What is not established

Whole-process I/O refinement of the native binaries, computational security
of the primitives, general information-flow noninterference, and
compatibility with a real provider.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core
open garrett_stateless_core.stateless_protocol
open garrett_stateless_core.stateless_token
open garrett_stateless_core.stateless_token.base64 garrett_stateless_core.stateless_token.grammar
  garrett_stateless_core.stateless_token.json garrett_stateless_core.stateless_token.payload
  garrett_stateless_core.stateless_token.keys garrett_stateless_core.stateless_token.opening
  garrett_stateless_core.stateless_token.sealing garrett_stateless_core.stateless_token.login_state

set_option autoImplicit false

namespace Garrett

variable {M P : Type}

/-! ## Guarantees over every execution -/

/-- **1. Every provider send is authorized.** Under a key set without
    forgery, every request a proxy sends was decided by the extracted
    `decide_request` as a dispatch, follows its acknowledged admission record,
    carries exactly the credential of a surrogate the broker issued, bound to
    this connection's peer, and descends from a login or mint. -/
def SendsAreAuthorized (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
    ∀ r w, stateless_proxy.Proofs.ProxyEvent.sent r w ∈ log →
      ∃ request now opened, stateless_proxy.Proofs.decide_request (Opening inst) cfg.policyInst keys cfg.policy
          request cfg.routes cfg.acceptance peer now = Result.ok (.dispatch r w opened) ∧
        (∃ A B, log = A ++ [.admitted opened.claims r true, .sent r w] ++ B) ∧
        ∃ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
          opened.claims = claims ∧ opened.credential.val = credential.val ∧
          claims.certificate.val = peer.val ∧ Lineage inst cfg W claims credential

/-- **2. A refused request sends nothing, and no request sends twice.** Every
    connection's record splits into one segment per request; a segment has at
    most one send, and none if the request was rejected. -/
def RefusalsSendNothing (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts →
    ∃ segs : List (List stateless_proxy.Proofs.ProxyEvent), log = segs.flatten ∧ ∀ seg ∈ segs,
      seg.countP stateless_proxy.Proofs.ProxyEvent.isSent ≤ 1 ∧
      ∀ rej, stateless_proxy.Proofs.ProxyEvent.rejected rej ∈ seg →
        ∀ r w, stateless_proxy.Proofs.ProxyEvent.sent r w ∉ seg

/-- **3. A login's surrogate goes to the agent that began it.** Every
    delivered surrogate is delivered to, and bound to, the certificate that
    started that login, and was issued at its end. -/
def DeliveredToInitiator (inst : KeyMaterial M) (cfg : Config P) (W : World M) : Prop :=
  ∀ σ peer t, stateless_mailbox.Proofs.Event.delivered σ peer t ∈ W.logins →
    ∃ st0 sealer claims credential, stateless_mailbox.Proofs.Event.started st0 σ ∈ W.logins ∧
      peer = st0.certificate.val ∧ claims.certificate = st0.certificate ∧
      IssuedIn inst cfg W sealer claims credential t (.login σ)

/-- **4. Each login completes at most once.** No login is accepted,
    exchanged, finished or delivered twice. -/
def LoginsAtMostOnce (W : World M) : Prop :=
  ∀ σ, stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isAcc σ) W.logins ≤ 1 ∧
    stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isExch σ) W.logins ≤ 1 ∧
    stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isFin σ) W.logins ≤ 1 ∧
    stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isDel σ) W.logins ≤ 1

/-- **5. Renewal never widens a surrogate.** Every issued surrogate descends
    from a login or mint with the same certificate binding, provider and
    credential, and a renewal limit (`ren`) no later. -/
def RenewalPreservesLineage (inst : KeyMaterial M) (cfg : Config P) (W : World M) : Prop :=
  ∀ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src →
    Lineage inst cfg W claims credential

/-- **6. No claim shows the credential.** The credential of an issued
    surrogate occurs in none of its string claims. -/
def ClaimsHideCredential (inst : KeyMaterial M) (cfg : Config P) (W : World M) : Prop :=
  ∀ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src →
    ∀ f ∈ ClaimFields claims, ¬ credential.val <:+: f

/-- **7. Every proxy record has a permitted form.** Under a key set without
    forgery, each record of a proxy connection is the agent's own request, a
    code or status, the admission of an issued surrogate for this peer, the
    encoder's request for its credential, or bytes to the agent that are a
    fixed refusal or a released provider reply (`Permitted`). This restricts
    the form of each output; it is not a general noninterference result. -/
def RecordsPermitted (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
    ∀ ev ∈ log, Permitted inst cfg W keys peer ev

section
variable {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
  (aead : ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V) {W : World M}
  (reach : Reachable inst Paired cfg W)
include aead reach

theorem sends_are_authorized : SendsAreAuthorized inst Paired cfg W :=
  fun keys peer log m unforged => ((protocol_safety aead reach).1 keys peer log m unforged).1

theorem records_permitted : RecordsPermitted inst Paired cfg W :=
  fun keys peer log m unforged => ((protocol_safety aead reach).1 keys peer log m unforged).2

theorem refusals_send_nothing : RefusalsSendNothing W :=
  (protocol_safety aead reach).2.1

theorem delivered_to_initiator : DeliveredToInitiator inst cfg W :=
  (protocol_safety aead reach).2.2.1

theorem logins_at_most_once : LoginsAtMostOnce W :=
  (protocol_safety aead reach).2.2.2.1

theorem renewal_preserves_lineage : RenewalPreservesLineage inst cfg W :=
  fun sealer claims credential token src h => ((protocol_safety aead reach).2.2.2.2 sealer claims credential token src h).1

theorem claims_hide_credential : ClaimsHideCredential inst cfg W :=
  fun sealer claims credential token src h => ((protocol_safety aead reach).2.2.2.2 sealer claims credential token src h).2

/-- **The protocol's guarantees, together**: `protocol_safety` with each
    conjunct named. -/
theorem guarantees :
    SendsAreAuthorized inst Paired cfg W ∧ RefusalsSendNothing W ∧ DeliveredToInitiator inst cfg W ∧
      LoginsAtMostOnce W ∧ RenewalPreservesLineage inst cfg W ∧ ClaimsHideCredential inst cfg W ∧
      RecordsPermitted inst Paired cfg W :=
  ⟨sends_are_authorized aead reach, refusals_send_nothing aead reach, delivered_to_initiator aead reach,
    logins_at_most_once aead reach, renewal_preserves_lineage aead reach, claims_hide_credential aead reach,
    records_permitted aead reach⟩

end

/-- **8. A strict broker keeps no login state.** With no OAuth provider
    configured, every reachable world has the empty mailbox and no login
    event (`strict_no_login_state`). -/
theorem strict_broker_is_stateless {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
    (none : cfg.login.providers.val = []) {W : World M} (reach : Reachable inst Paired cfg W) :
    stateless_mailbox.empty = Result.ok W.mb ∧ W.logins = [] :=
  strict_no_login_state none reach

/-! ## One request through the proxy

`composed_egress` is proved once for any operation policy meeting its
contract, and holds for every run of the extracted `serve`, for any origin
adapter and any key-set opener; `AuthorizedEgress` names its parts
(`NoDispatch`, `AuthenticatedSurrogate`, `AuthorizedOperation`,
`ExactUpstreamRequest`, `AcknowledgedDispatch`). -/

open garrett_stateless_core.stateless_proxy garrett_stateless_core.stateless_proxy.Proofs
  garrett_stateless_core.stateless_policy.Proofs in
/-- **9. Each proxy request is refused without egress, or makes one
    authorized, exact, acknowledged egress** — for Garrett's unrestricted
    proxy. -/
theorem unrestricted_request {V O : Type} (ops : stateless.SurrogateOpener V) (origin : Origin O) (opener : V)
    (io : O) (request : proxy_http.request.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (served : proxy_controller.Served) (after : O)
    (h : serve ops UnrestrictedPolicy origin opener () io request routes a peer now limit = Result.ok (served, after)) :
    AuthorizedEgress ops UnrestrictedPolicy origin opener () io (fun _ _ => True) request routes a peer now limit
      served after :=
  garrett_egress ops origin opener io request routes a peer now limit served after h

open garrett_stateless_core.stateless_proxy garrett_stateless_core.stateless_proxy.Proofs
  garrett_stateless_core.stateless_policy.Proofs in
/-- **10. The same for the read-only proxy**, whose operations are `GET` or
    `HEAD` with no body, on a configured resource of the surrogate's
    provider (`ReadOnlyAllowed`). -/
theorem read_only_request {V O : Type} (ops : stateless.SurrogateOpener V) (origin : Origin O) (opener : V)
    (p : stateless_policy.ReadOnly) (io : O) (request : proxy_http.request.Request) (routes : Slice Route)
    (a : stateless.Acceptance) (peer : Slice U8) (now : I64) (limit : Usize) (served : proxy_controller.Served)
    (after : O)
    (h : serve ops ReadOnlyPolicy origin opener p io request routes a peer now limit = Result.ok (served, after)) :
    AuthorizedEgress ops ReadOnlyPolicy origin opener p io (ReadOnlyAllowed p) request routes a peer now limit
      served after :=
  read_only_egress ops origin opener p io request routes a peer now limit served after h

/-! ## Binding, for the real token code -/

/-- **11. Issued for a certificate, opens only for it.** A surrogate the
    extracted `issue` sealed with the real `TokenSealer` opens, under a
    configured key set, only for the certificate it was issued to — with no
    assumption on any primitive. -/
theorem opens_only_for_its_certificate {inst : KeyMaterial M} {sealer : TokenSealer M} {keys : KeySet M}
    (configured : Configured keys) {policy : stateless.IssuePolicy} {grant : stateless.Grant}
    {cred tid : Slice U8} {now lifetime : I64} {issued : stateless.Issued}
    (hi : stateless.issue (Sealing inst) sealer policy grant cred tid now lifetime = Result.ok (.Ok issued))
    (a : stateless.Acceptance) (peer : Slice U8) (later : I64) (opened : stateless.Opened)
    (ho : stateless.open (Opening inst) keys (alloc.vec.Vec.deref issued.token) a peer later =
      Result.ok (.Ok opened)) :
    peer.val = grant.certificate.val :=
  issued_opens_only_for_its_certificate configured hi a peer later opened ho

end Garrett
