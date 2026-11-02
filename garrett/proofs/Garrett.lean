import GarrettConfidentiality
import GarrettNonce
import GarrettStatelessStrict
import GarrettStatelessWitness

/-!
# What Garrett guarantees

Start here. This module states Garrett's security guarantees as a few named
propositions and derives each from the implementation-linked theorems
underneath. Nothing here is a second model: every function mentioned is the
Aeneas extraction of `crates/garrett-stateless-core`
(`generated/GarrettStatelessCore.lean`).

## The parties and the adversary

* the **agent** is untrusted and may be malicious. It holds a client
  certificate and its private key and the surrogates issued to it, and it
  controls every byte it sends: requests, framing, which surrogate it
  presents and when;
* the **broker** issues surrogates — after an OAuth login, as an operator
  mint, or as a renewal — and holds the signing and sealing keys;
* the **proxy** (any number of replicas) opens a surrogate presented on an
  mTLS connection, authorizes the operation, decrypts the credential and
  sends one request to the provider the surrogate names;
* the **provider** is the upstream API.

## In one paragraph

Garrett does not disclose the provider credential through surrogate claims
or through the replies and records it constructs itself. Its verified proxy
hands the credential to its native writer only inside an authorized, exact
request for the configured destination of the surrogate's provider, and,
under the trusted transport contract, every application byte it emits to a
provider belongs to such a request — a prefix of it if the write was
interrupted. That a surrogate's ciphertext hides the credential is the
assumed security of AES-256-GCM, and what an authorized provider's answer
reveals is an explicit disclosure boundary. None of this is unconditional
credential secrecy.

## Five layers of evidence

Each result belongs to one layer. A claim in a higher layer never follows
from a lower layer alone.

| layer | about | established by | results |
| --- | --- | --- | --- |
| 1. extracted computations | the Rust functions `decide`, `serve`, `exchange`, `issue`, `renew` and the mailbox transitions, for any inputs | Lean theorems about the Aeneas extraction | `unrestricted_request`, `read_only_request`, `one_route_per_provider`, `opens_only_for_its_certificate`, `ProxyRepliesDeclassified`, `SurrogatesRevealOnlyCiphertext`, `replicas_decide_alike` |
| 2. the protocol and its effect trace | every reachable interleaving of extracted steps; the `log` of effects each connection asked the native shell for | Lean theorems over `Reachable` and the extracted connection loop | `SecurityGuarantees` (`CompromisedAgentConfinement`, `CompletedAfterWholeWrite`, `RefusalsSendNothing`, `ClaimsHideCredential`, `RecordsPermitted`, `BoundedDelegation`, `RenewalPreservesLineage`, `AuthorizedAcquisition`), `ConnectionsDeclassified`, `connection_needs_no_history`, `strict_broker_is_stateless` |
| 3. native network effects | the application data the proxy process emits to providers | layer 2 and the trusted contract `TransportFaithful`, whose native half is `upstream.rs` (`STATELESS-NATIVE-01`, `STATELESS-TLS-01`) | `ProviderBytesConfined` (`provider_writes_confined`), `completed_requests_emitted_whole` |
| 4. cryptography | signatures, AEAD correctness and secrecy, nonces | the hypotheses `AeadCorrect` and `Unforged`; IND-CPA, a documented assumption; a counting bound on nonce repeats (`Garrett.Nonce.nonce_collision_bound`) | `STATELESS-CRYPTO-01` |
| 5. deployment and providers | clocks, key custody and rotation, the TLS stack, the OAuth provider and the human, what a provider does with a request it receives | documented assumptions only | `STATELESS-DEPLOY-01`, `STATELESS-OAUTH-01`, `STATELESS-OPS-01`, `STATELESS-DISCLOSURE-01` |

Each main theorem below says what it **protects**, against which
**attacker**, from which **source** (extracted functions and theorems), under
what **trust**, and its **limit**.

## The model of an execution

`World` records the broker's login mailbox and its history, and every
renewal, mint and proxy connection so far. `Step` is one extracted transition
with arbitrary inputs: any agent request, any OAuth answer, any channel
behaviour, any authenticated peer, any configured key set. `Reachable` is
every finite interleaving of steps from the empty world. A proxy connection's
`log` is the sequence of native effects the extracted connection loop asked
for, in order (`ProxyEvent`).

## How to read a guarantee

| kind | meaning |
| --- | --- |
| **proved** | a Lean theorem about the extracted Rust, under the hypotheses named in its statement |
| **trusted** | a hypothesis or a documented contract of code outside the extraction (`docs/assumptions.json`) |
| **tested** | covered by tests, conformance vectors or the shell source guard, and by nothing here |

## The five guarantees

| | guarantee | Lean | status |
| --- | --- | --- | --- |
| A | compromised-agent confinement | `CompromisedAgentConfinement`, `CompletedAfterWholeWrite`, `ProviderBytesConfined` | proved for the log (layer 2); for the network under `TransportFaithful` (layer 3) |
| B | provider-credential confidentiality | `ClaimsHideCredential`, `RecordsPermitted`, `ProxyRepliesDeclassified`, `ConnectionsDeclassified`, `SurrogatesRevealOnlyCiphertext` | proved up to the declassification boundary; AEAD secrecy trusted |
| C | bounded, nontransferable delegation | `BoundedDelegation`, `RenewalPreservesLineage`, `opens_only_for_its_certificate` | proved; key custody and the clock trusted |
| D | authorized credential acquisition | `AuthorizedAcquisition` | proved for the broker; browser, human and OAuth provider trusted |
| E | stateless authorization | `ConnectionAllowed`, `connection_needs_no_history`, `replicas_decide_alike`, `replica_replies_differ`, `strict_broker_is_stateless` | proved |

`SecurityGuarantees` collects A, C and D, with `RefusalsSendNothing`,
`ClaimsHideCredential` and `RecordsPermitted`, for every reachable world
(`security_guarantees`). It is a structure of named fields, not one
conjunction: each field keeps its own statement. B's two-run theorems and
E's replica theorems compare two executions and are stated separately, and
the network statements of layer 3 take the transport contract as a premise.

## The trusted base

* `AeadCorrect`: AES-256-GCM decrypts what it encrypted under paired keys
  (`STATELESS-CRYPTO-01`). Correctness only. AEAD **secrecy** (IND-CPA) is
  an assumption of B, not a theorem, and it needs unique nonces, which are
  random and so unique only with high probability
  (`Garrett.Nonce.nonce_collision_bound`); keeping a key's use below the
  rotation limit is the operator's.
* `Unforged`: no Ed25519 signature was forged under a proxy's key set (an
  idealized EUF-CMA), stated per key set where the proxy relies on it.
* `TransportFaithful`: the provider sessions with application data
  correspond, in order, to the logged write attempts; each carries a prefix
  of the attempted bytes (all of them when the writer reported success) on a
  TLS session whose server proved the destination's name under its trust
  anchors (`STATELESS-NATIVE-01`, `STATELESS-TLS-01`). Its native half is
  `upstream.rs`, whose types allow one write per authenticated session;
  `verification/shell_guard.py` pins how the shells call the core.
* The clock passed to the core, and that the TLS layer reports the peer of
  the handshake it verified.

## What is not established

Whole-process I/O refinement of the native binaries, computational security
of the primitives, timing and other side channels, that `GET`/`HEAD` cannot
mutate a provider (provider API semantics), protection of the agent's private
key, and compatibility with a real provider.
-/

open Aeneas Aeneas.Std
open garrett_stateless_core
open garrett_stateless_core.stateless_protocol
open garrett_stateless_core.stateless_token
open garrett_stateless_core.stateless_token.base64 garrett_stateless_core.stateless_token.grammar
  garrett_stateless_core.stateless_token.json garrett_stateless_core.stateless_token.payload
  garrett_stateless_core.stateless_token.keys garrett_stateless_core.stateless_token.opening
  garrett_stateless_core.stateless_token.sealing garrett_stateless_core.stateless_token.login_state
open garrett_stateless_core.stateless_proxy.Proofs (ProxyEvent decide_request ExactWire)

set_option autoImplicit false

namespace Garrett

variable {M P : Type}

/-! ## The trusted base -/

/-- **AEAD correctness** (`STATELESS-CRYPTO-01`): for paired keys, opening
    undoes sealing. A hypothesis of every guarantee that follows a credential
    from issuance to the proxy. -/
abbrev AeadCorrect (inst : KeyMaterial M) (Paired : M → M → Prop) : Prop :=
  ∀ S V, Paired S V → stateless_boundary.AeadInverse inst S V

/-- The application data the proxy process emitted on one provider TLS
    session, as the network sees it: the server name the session's
    certificate proved, the trust anchors it chained to, the address and
    port, and the **plaintext** written into the session — application data,
    before TLS record protection. The encrypted bytes on the TCP connection
    are TLS's business (`STATELESS-TLS-01`), not modeled. -/
structure ProviderWrite where
  host : List U8
  trust : List U8
  address : List U8
  port : U16
  bytes : List U8

/-- Application data `bytes` emitted on a session to `D`. -/
def ProviderWrite.on (D : stateless_proxy.Destination) (bytes : List U8) : ProviderWrite :=
  ⟨D.host.val, D.trust.val, D.address.val, D.port, bytes⟩

/-- The write attempts a connection's log records, in order: the
    destination, the bytes handed to the native writer, and its report. -/
def attempts : List ProxyEvent → List (stateless_proxy.Destination × alloc.vec.Vec U8 × Bool)
  | [] => []
  | .attempted D w written :: rest => (D, w, written) :: attempts rest
  | _ :: rest => attempts rest

/-- What one attempt may have emitted: on a session to its destination, a
    **prefix** of the attempted bytes — any prefix, including none, since a
    failed write can stop anywhere — and all of them if the writer reported
    the whole request written. -/
def Emitted : stateless_proxy.Destination × alloc.vec.Vec U8 × Bool → ProviderWrite → Prop
  | (D, w, written), x => ∃ bytes, x = ProviderWrite.on D bytes ∧ bytes <+: w.val ∧ (written = true → bytes = w.val)

/-- **The native transport contract** (trusted, not proved:
    `STATELESS-NATIVE-01`, `STATELESS-TLS-01`). The provider sessions on which
    the proxy process emitted application data for one connection correspond,
    in order, to the write attempts its log records, and each emitted what
    `Emitted` allows: `Origin::connect` answers `true` only for a TLS session
    in which the server proved the destination's host under its trust
    anchors; `Origin::transmit` writes, as application data on that session
    and nowhere else, a prefix of the egress bytes, all of them when it
    reports success; and nothing else emits application data to a provider.
    It does not say a failed write emitted nothing, nor that a reported
    success reached the provider. The native half is one module,
    `crates/garrett-stateless/src/upstream.rs`, whose types allow one write
    per authenticated session; `verification/shell_guard.py` pins it. -/
def TransportFaithful (log : List ProxyEvent) (writes : List ProviderWrite) : Prop :=
  List.Forall₂ Emitted (attempts log) writes

theorem mem_attempts {log : List ProxyEvent} {D : stateless_proxy.Destination} {w : alloc.vec.Vec U8}
    {written : Bool} (m : (D, w, written) ∈ attempts log) : ProxyEvent.attempted D w written ∈ log := by
  induction log with
  | nil => cases m
  | cons ev rest ih =>
    cases ev with
    | attempted D' w' written' =>
      simp only [attempts, List.mem_cons, Prod.mk.injEq] at m
      rcases m with ⟨e1, e2, e3⟩ | m
      · subst e1 e2 e3; exact List.mem_cons_self
      · exact List.mem_cons_of_mem _ (ih m)
    | _ => exact List.mem_cons_of_mem _ (ih m)

theorem attempts_of_mem {log : List ProxyEvent} {D : stateless_proxy.Destination} {w : alloc.vec.Vec U8}
    {written : Bool} (m : ProxyEvent.attempted D w written ∈ log) : (D, w, written) ∈ attempts log := by
  induction log with
  | nil => cases m
  | cons ev rest ih =>
    rcases List.mem_cons.mp m with e | later
    · subst e; exact List.mem_cons_self
    · cases ev with
      | attempted D' w' b' => exact List.mem_cons_of_mem _ (ih later)
      | _ => exact ih later

theorem forall₂_mem_right {α β : Type} {R : α → β → Prop} {l1 : List α} {l2 : List β} (h : List.Forall₂ R l1 l2)
    {x : β} (m : x ∈ l2) : ∃ y ∈ l1, R y x := by
  induction h with
  | nil => cases m
  | cons r _ ih =>
    rcases List.mem_cons.mp m with e | m
    · subst e; exact ⟨_, List.mem_cons_self, r⟩
    · obtain ⟨y, my, ry⟩ := ih m
      exact ⟨y, List.mem_cons_of_mem _ my, ry⟩

theorem forall₂_mem_left {α β : Type} {R : α → β → Prop} {l1 : List α} {l2 : List β} (h : List.Forall₂ R l1 l2)
    {y : α} (m : y ∈ l1) : ∃ x ∈ l2, R y x := by
  induction h with
  | nil => cases m
  | cons r _ ih =>
    rcases List.mem_cons.mp m with e | m
    · subst e; exact ⟨_, List.mem_cons_self, r⟩
    · obtain ⟨x, mx, rx⟩ := ih m
      exact ⟨x, List.mem_cons_of_mem _ mx, rx⟩

/-! ## A. Compromised-agent confinement

Even if the agent is malicious and controls its own requests, every
credential-bearing write a proxy makes is an authenticated, authorized,
exact request to the configured destination of the provider the surrogate
names. -/

/-- **Who the credential belongs to.** `claims` and `credential` are those of
    a surrogate this broker issued, bound to the certificate `peer`, and
    descending from a login or an operator mint. -/
def IssuedFor (inst : KeyMaterial M) (cfg : Config P) (W : World M) (peer : Slice U8)
    (claims : stateless.SurrogateClaims) (credential : alloc.vec.Vec U8) : Prop :=
  claims.certificate.val = peer.val ∧ ∃ sealer issued token src, IssuedIn inst cfg W sealer claims issued token src ∧
    credential.val = issued.val ∧ Lineage inst cfg W claims issued

/-- **Operation authorization.** The proxy's configured operation policy
    permitted the request's operation for these claims. Under `Unrestricted`
    (Garrett's proxy) this holds for every operation; `read_only_writes`
    gives its meaning for the read-only proxy. -/
def PolicyPermits (cfg : Config P) (request : proxy_http.request.Request) (claims : stateless.SurrogateClaims) :
    Prop :=
  ∃ op, stateless_policy.operation_of request = Result.ok op ∧ cfg.policyInst.permits cfg.policy claims op = Result.ok true

/-- **The provider's route.** `route` is configured route `index`, and it
    serves `provider`. -/
def RouteFor (routes : Slice stateless_proxy.Route) (provider : List U8) (index : Usize)
    (route : stateless_proxy.Route) : Prop :=
  ∃ inside : index.val < routes.length, routes[index.val]'inside = route ∧ route.provider.val = provider

/-- **The exact request.** The bytes are the extracted encoder's output for
    the agent's request on `route` with `credential`, and exactly `ExactWire`
    (the agent's request with every credential-bearing and framing field
    removed, re-addressed to the route's host, and one authentication line
    carrying the credential) whenever that fits in memory. -/
def ExactRequest (request : proxy_http.request.Request) (route : stateless_proxy.Route)
    (credential wire : alloc.vec.Vec U8) : Prop :=
  proxy_http.upstream.encode_upstream (alloc.vec.Vec.new U8) request (alloc.vec.Vec.deref route.destination.host)
      (alloc.vec.Vec.deref route.rules) (alloc.vec.Vec.deref credential) route.authentication =
    Result.ok (.Ok (), wire) ∧
  ((ExactWire request route credential).length ≤ Usize.max → wire.val = ExactWire request route credential)

/-- **In order, for the request the connection received.** The write
    attempt follows, in the connection's log, the record of the request the
    connection framed from the agent's bytes, the acknowledged admission
    record and the authenticated connection to the same destination. -/
def AfterAuthenticatedConnection (log : List ProxyEvent) (request : proxy_http.request.Request)
    (claims : stateless.SurrogateClaims) (index : Usize) (D : stateless_proxy.Destination)
    (wire : alloc.vec.Vec U8) (written : Bool) : Prop :=
  ∃ A B, log = A ++ [.began request, .admitted claims index true, .connected D true, .attempted D wire written] ++ B

/-- **An authorized credential write attempt.** Handing `wire` for `D` to
    the native writer, on a connection authenticated as `peer`, was decided
    as a dispatch by the extracted `decide_request` for a request that
    connection received; it follows that request's record, the acknowledged
    admission and the authenticated connection to `D`; the surrogate was
    issued for `peer`; the operation policy permitted the operation; `D` is
    the destination of the route serving the surrogate's provider; and `wire`
    is exactly the agent's request carrying exactly the issued credential. -/
def CredentialWriteAuthorized (inst : KeyMaterial M) (cfg : Config P) (W : World M) (keys : KeySet M)
    (peer : Slice U8) (log : List ProxyEvent) (D : stateless_proxy.Destination) (wire : alloc.vec.Vec U8)
    (written : Bool) : Prop :=
  ∃ request now index route opened,
    decide_request (Opening inst) cfg.policyInst keys cfg.policy request cfg.routes cfg.acceptance peer now =
      Result.ok (.dispatch index wire opened) ∧
    AfterAuthenticatedConnection log request opened.claims index D wire written ∧
    IssuedFor inst cfg W peer opened.claims opened.credential ∧
    PolicyPermits cfg request opened.claims ∧
    RouteFor cfg.routes opened.claims.provider.val index route ∧ route.destination = D ∧
    ExactRequest request route opened.credential wire

/-- **A. Compromised-agent confinement** (the controller's part). On every
    proxy connection, under a key set without forgery, every write attempt is
    authorized (`CredentialWriteAuthorized`). This is about what the
    extracted controller asks the native writer to do; `ProviderBytesConfined`
    is the network-level statement. -/
def CompromisedAgentConfinement (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) :
    Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
    ∀ D wire written, ProxyEvent.attempted D wire written ∈ log →
      CredentialWriteAuthorized inst cfg W keys peer log D wire written

/-- **A, on the network.** Every application byte a proxy connection emitted
    to a provider belongs to an authorized request for that provider: each
    provider session's application data is a prefix of an authorized write
    attempt's bytes, on a session to that attempt's destination — all of the
    request when the writer reported success, never more and never other
    bytes. -/
def ProviderBytesConfined (inst : KeyMaterial M) (cfg : Config P) (W : World M) (keys : KeySet M)
    (peer : Slice U8) (log : List ProxyEvent) (writes : List ProviderWrite) : Prop :=
  ∀ x ∈ writes, ∃ D wire written, x = ProviderWrite.on D x.bytes ∧ x.bytes <+: wire.val ∧
    (written = true → x.bytes = wire.val) ∧ CredentialWriteAuthorized inst cfg W keys peer log D wire written

/-- **Completed only after a whole write.** A request is recorded as a
    completed provider operation only right after a write attempt that the
    native writer reported whole; a failed or partial write ends as an
    unknown outcome. -/
def CompletedAfterWholeWrite (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → ∀ status acked, ProxyEvent.completed status acked ∈ log →
    ∃ A B D wire, log = A ++ [.attempted D wire true, .completed status acked] ++ B

/-! ## B. Provider-credential confidentiality

What the agent can learn about a credential, beyond what is declassified on
purpose (`GarrettConfidentiality`): no claim shows it, every proxy record has
a permitted form, a proxy's reply depends on it only through the provider's
answer and one reflection bit, and a surrogate only through its AEAD
ciphertext. -/

/-- **No claim shows the credential.** The credential of an issued
    surrogate occurs in none of its string claims. -/
def ClaimsHideCredential (inst : KeyMaterial M) (cfg : Config P) (W : World M) : Prop :=
  ∀ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src →
    ∀ f ∈ ClaimFields claims, ¬ credential.val <:+: f

/-- **Every proxy record has a permitted form.** Under a key set without
    forgery, each record of a proxy connection is the agent's own request, a
    code or status, the admission of an issued surrogate for this peer, a
    connection to a dispatched route's destination, the encoder's request
    for its credential, or bytes to the agent that are a fixed refusal or a
    released provider reply (`Permitted`). This restricts the form of each
    output; B's relational theorems say what the outputs depend on. -/
def RecordsPermitted (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
    ∀ ev ∈ log, Permitted inst cfg W keys peer ev

/-- **The proxy's reply is declassified.** Two runs of `serve` on the same
    request, with openers that differ only in the valid credential they
    unseal, decide alike up to the credential; and with the same network
    answers the agent receives the same reply, unless the provider's answer
    reflected one credential and not the other. -/
def ProxyRepliesDeclassified : Prop :=
  ∀ {V P O1 O2 : Type} (ops1 ops2 : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (opener : V) (policy : P), stateless_proxy.Proofs.SameButCredential ops1 ops2 opener →
    ∀ (inst1 : stateless_proxy.Origin O1) io1 (inst2 : stateless_proxy.Origin O2) io2 request routes a peer now limit
      s1 s2 a1 a2,
    stateless_proxy.serve ops1 pol inst1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1) →
    stateless_proxy.serve ops2 pol inst2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2) →
    ∃ d1 d2 ans1 ans2, decide_request ops1 pol opener policy request routes a peer now = Result.ok d1 ∧
      decide_request ops2 pol opener policy request routes a peer now = Result.ok d2 ∧
      stateless_proxy.Proofs.Decision.view d1 = stateless_proxy.Proofs.Decision.view d2 ∧
      (d1.isDispatch = true → stateless_proxy.Proofs.AnsweredBy inst1 io1 routes limit d1 ans1 a1) ∧
      (d2.isDispatch = true → stateless_proxy.Proofs.AnsweredBy inst2 io2 routes limit d2 ans2 a2) ∧
      (ans1 = ans2 → s1 = s2 ∨ stateless_proxy.Proofs.ReflectionRefusal s1 ∨
        stateless_proxy.Proofs.ReflectionRefusal s2)

/-- **A surrogate reveals its credential only through the ciphertext.** Two
    issuances with the same grant, policy, sealer and clock, both issuing,
    under primitives that sign alike and whose AEAD returned the same
    ciphertext for the two credentials, give the same surrogate. Whether the
    ciphertext itself hides the credential is the IND-CPA assumption. -/
def SurrogatesRevealOnlyCiphertext : Prop :=
  ∀ {M : Type} (inst1 inst2 : KeyMaterial M), inst1.sign = inst2.sign →
    ∀ (sealer : TokenSealer M) policy grant (c1 c2 tid : Slice U8) now lifetime i1 i2,
    (∀ aad, inst1.«seal» sealer.entry.material (alloc.vec.Vec.deref sealer.nonce) aad c1 =
      inst2.«seal» sealer.entry.material (alloc.vec.Vec.deref sealer.nonce) aad c2) →
    stateless.issue (Sealing inst1) sealer policy grant c1 tid now lifetime = Result.ok (.Ok i1) →
    stateless.issue (Sealing inst2) sealer policy grant c2 tid now lifetime = Result.ok (.Ok i2) → i1 = i2

/-- **A whole connection is declassified.** Two runs of the extracted
    connection loop with openers that differ only in the valid credential
    they unseal, on channels that answer alike from related states — the
    same agent bytes, deadlines and clock, adaptively, and the same network
    answers whatever credential-bearing bytes were written — send the agent
    the same byte strings, or the same up to one reply at which one run sent
    the fixed reflection refusal. -/
def ConnectionsDeclassified : Prop :=
  ∀ {V P C1 C2 : Type} (ops1 ops2 : stateless.SurrogateOpener V) (pol : stateless_policy.OperationPolicy P)
    (opener : V) (policy : P), stateless_proxy.Proofs.SameButCredential ops1 ops2 opener →
    ∀ (R : C1 → C2 → Prop) (ch1 : stateless_proxy.Channel C1) (ch2 : stateless_proxy.Channel C2),
    stateless_proxy.Proofs.ChannelsAgree R ch1 ch2 → ∀ io1 io2, R io1 io2 →
    ∀ routes a authority peer limit f1 f2,
    stateless_proxy.connection ops1 pol (stateless_proxy.Proofs.logged ch1) opener policy (io1, []) routes a authority
      peer limit = Result.ok f1 →
    stateless_proxy.connection ops2 pol (stateless_proxy.Proofs.logged ch2) opener policy (io2, []) routes a authority
      peer limit = Result.ok f2 →
    (stateless_proxy.Proofs.agentView f1.2 = stateless_proxy.Proofs.agentView f2.2 ∧ R f1.1 f2.1) ∨
      stateless_proxy.Proofs.DivergeAtReflection (stateless_proxy.Proofs.agentView f1.2)
        (stateless_proxy.Proofs.agentView f2.2)

/-- **B, over whole connections.**

    * protects: nothing the agent is sent by a connection depends on the
      credential, beyond the provider's answers and one reflection bit;
    * attacker: an adaptive agent choosing each request after seeing every
      earlier reply, on any number of requests;
    * source: the extracted connection loop, `serve`, `exchange`, `collect`,
      `release` (`connection_declassified`);
    * trust: `ChannelsAgree` — the network answers alike whatever
      credential-bearing bytes were written — is exactly the provider-answer
      declassification (`STATELESS-DISCLOSURE-01`);
    * limit: termination-insensitive (both runs return); timing, sizes and
      other side channels are not modeled; after the first reflection
      refusal nothing is claimed. -/
theorem connections_declassified : ConnectionsDeclassified :=
  fun _ _ _ _ _ same _ _ _ agree _ _ r _ _ _ _ _ _ _ h1 h2 =>
    stateless_proxy.Proofs.connection_declassified same agree r h1 h2

theorem proxy_replies_declassified : ProxyRepliesDeclassified :=
  fun ops1 ops2 _ _ _ same inst1 io1 inst2 io2 _ _ _ _ _ _ _ _ _ _ h1 h2 =>
    stateless_proxy.Proofs.serve_declassified (ops1 := ops1) (ops2 := ops2) same inst1 io1 inst2 io2 h1 h2

theorem surrogates_reveal_only_ciphertext : SurrogatesRevealOnlyCiphertext :=
  fun _ _ same _ _ _ _ _ _ _ _ _ _ ct h1 h2 => stateless_token.Proofs.issue_ciphertext_only same ct h1 h2

/-! ## C. Bounded, nontransferable delegation

A surrogate carries only the authority of its binding, provider and window,
inherited unwidened from its root issuance. Certificate binding is not key
custody: whoever holds the agent's private key is, to Garrett, the agent. -/

/-- **Within its delegation.** At the time `now` it was used, the surrogate
    was presented on a connection authenticated as its own certificate; this
    proxy accepts its audience and provider; `now` is inside its validity
    window, which ends no later than its renewal limit; and it descends from
    a login or an operator mint with the same binding, provider, subject and
    credential and a renewal limit no earlier than its own. -/
def WithinDelegation (inst : KeyMaterial M) (cfg : Config P) (W : World M) (peer : Slice U8) (now : I64)
    (claims : stateless.SurrogateClaims) (credential : alloc.vec.Vec U8) : Prop :=
  claims.certificate.val = peer.val ∧
  stateless.Proofs.Member (alloc.vec.Vec.deref cfg.acceptance.audiences) (alloc.vec.Vec.deref claims.audience) ∧
  stateless.Proofs.Member (alloc.vec.Vec.deref cfg.acceptance.providers) (alloc.vec.Vec.deref claims.provider) ∧
  claims.issued_at.val ≤ now.val + cfg.acceptance.skew.val ∧ now.val < claims.expires_at.val ∧
  claims.expires_at.val ≤ claims.renew_until.val ∧
  ∃ issued, credential.val = issued.val ∧ Lineage inst cfg W claims issued

/-- **C. Bounded delegation.** Every credential-bearing write attempt used a
    surrogate within its delegation. -/
def BoundedDelegation (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
    ∀ D wire written, ProxyEvent.attempted D wire written ∈ log →
      ∃ request now index opened,
        decide_request (Opening inst) cfg.policyInst keys cfg.policy request cfg.routes cfg.acceptance peer now =
          Result.ok (.dispatch index wire opened) ∧
        WithinDelegation inst cfg W peer now opened.claims opened.credential

/-- **Renewal never widens a surrogate.** Every issued surrogate descends
    from a login or mint with the same binding, provider, subject and
    credential, and a renewal limit no later. -/
def RenewalPreservesLineage (inst : KeyMaterial M) (cfg : Config P) (W : World M) : Prop :=
  ∀ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src →
    Lineage inst cfg W claims credential

/-! ## D. Authorized credential acquisition

Credentials reach surrogates through two doors: an operator mint (a trusted
issuance path: the operator chooses the certificate) and the OAuth login,
whose mailbox is proved. The browser, the human approving the login, PKCE
secrecy and the OAuth provider's token endpoint are trusted. -/

/-- **A login's surrogate goes to the agent that began it.** Every
    delivered surrogate is delivered to, and bound to, the certificate that
    started that login, and was issued at its end. -/
def DeliveredToInitiator (inst : KeyMaterial M) (cfg : Config P) (W : World M) : Prop :=
  ∀ σ peer t, stateless_mailbox.Proofs.Event.delivered σ peer t ∈ W.logins →
    ∃ st0 sealer claims credential, stateless_mailbox.Proofs.Event.started st0 σ ∈ W.logins ∧
      peer = st0.certificate.val ∧ claims.certificate = st0.certificate ∧
      IssuedIn inst cfg W sealer claims credential t (.login σ)

/-- **Each login completes at most once.** No login is accepted, its code
    exchanged, its surrogate issued, or delivered twice. -/
def LoginsAtMostOnce (W : World M) : Prop :=
  ∀ σ, stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isAcc σ) W.logins ≤ 1 ∧
    stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isExch σ) W.logins ≤ 1 ∧
    stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isFin σ) W.logins ≤ 1 ∧
    stateless_mailbox.Proofs.cnt (stateless_mailbox.Proofs.isDel σ) W.logins ≤ 1

/-- **A failed or uncertain code exchange issues and delivers nothing.** -/
def FailedLoginsIssueNothing (W : World M) : Prop :=
  ∀ σ, stateless_mailbox.Proofs.Event.finished σ none ∈ W.logins →
    (∀ peer t, stateless_mailbox.Proofs.Event.delivered σ peer t ∉ W.logins) ∧
    ∀ iss, stateless_mailbox.Proofs.Event.finished σ (some iss) ∉ W.logins

/-- **Every credential a proxy sends came in through a door for this
    agent.** It was minted by the operator for this certificate, or it is the
    token the code exchange of a login started by this certificate returned. -/
def CredentialsEnteredForThePeer (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) :
    Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
    ∀ D wire written, ProxyEvent.attempted D wire written ∈ log →
      ∃ opened : stateless.Opened, (∃ request now index, decide_request (Opening inst) cfg.policyInst keys cfg.policy
          request cfg.routes cfg.acceptance peer now = Result.ok (.dispatch index wire opened)) ∧
        ((∃ sealer0 claims0 credential0 token0, IssuedIn inst cfg W sealer0 claims0 credential0 token0 .mint ∧
            claims0.certificate.val = peer.val ∧ opened.credential.val = credential0.val) ∨
         (∃ σ st0 x tok, stateless_mailbox.Proofs.Event.started st0 σ ∈ W.logins ∧ st0.certificate.val = peer.val ∧
            stateless_mailbox.Proofs.Event.exchanged x ∈ W.logins ∧ x.permit.serial = σ ∧ x.token = some tok ∧
            opened.credential.val = tok.credential.val))

/-- **D. Authorized acquisition**, together. -/
def AuthorizedAcquisition (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) : Prop :=
  DeliveredToInitiator inst cfg W ∧ LoginsAtMostOnce W ∧ FailedLoginsIssueNothing W ∧
    CredentialsEnteredForThePeer inst Paired cfg W

/-! ## Refusals -/

/-- **A refused request writes nothing, and no request writes twice.** Every
    connection's record splits into one segment per request; a segment has at
    most one write attempt, and none if the request was rejected. -/
def RefusalsSendNothing (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts →
    ∃ segs : List (List ProxyEvent), log = segs.flatten ∧ ∀ seg ∈ segs,
      seg.countP ProxyEvent.isAttempt ≤ 1 ∧
      ∀ rej, ProxyEvent.rejected rej ∈ seg → ∀ D w written, ProxyEvent.attempted D w written ∉ seg

/-- **Every provider write attempt is authorized** (`protocol_safety`'s
    first part): `CompromisedAgentConfinement` without the policy and the
    exact-bytes clauses. -/
def SendsAreAuthorized (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) : Prop :=
  ∀ keys peer log, Act.served keys peer log ∈ W.acts → Unforged inst Paired cfg W keys →
    ∀ D w written, ProxyEvent.attempted D w written ∈ log →
      ∃ request now index opened, decide_request (Opening inst) cfg.policyInst keys cfg.policy
          request cfg.routes cfg.acceptance peer now = Result.ok (.dispatch index w opened) ∧
        stateless_proxy.Proofs.DestinationOf cfg.routes index D ∧
        (∃ A B, log = A ++ [.began request, .admitted opened.claims index true, .connected D true,
          .attempted D w written] ++ B) ∧
        ∃ sealer claims credential token src, IssuedIn inst cfg W sealer claims credential token src ∧
          opened.claims = claims ∧ opened.credential.val = credential.val ∧
          claims.certificate.val = peer.val ∧ Lineage inst cfg W claims credential

/-! ## Every reachable world -/

/-- **Garrett's per-execution guarantees.** -/
structure SecurityGuarantees (inst : KeyMaterial M) (Paired : M → M → Prop) (cfg : Config P) (W : World M) :
    Prop where
  /-- A. -/
  confinement : CompromisedAgentConfinement inst Paired cfg W
  completed : CompletedAfterWholeWrite W
  refusals : RefusalsSendNothing W
  /-- B, per execution. -/
  claimsHide : ClaimsHideCredential inst cfg W
  records : RecordsPermitted inst Paired cfg W
  /-- C. -/
  delegation : BoundedDelegation inst Paired cfg W
  renewal : RenewalPreservesLineage inst cfg W
  /-- D. -/
  acquisition : AuthorizedAcquisition inst Paired cfg W

section
variable {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P}
  (aead : AeadCorrect inst Paired) {W : World M} (reach : Reachable inst Paired cfg W)
include aead reach

theorem sends_are_authorized : SendsAreAuthorized inst Paired cfg W :=
  fun keys peer log m unforged => ((protocol_safety aead reach).1 keys peer log m unforged).1

omit aead in
theorem completed_after_whole_write : CompletedAfterWholeWrite W := by
  intro keys peer log m status acked mc
  obtain ⟨_, segs, log, ok⟩ := served_segs reach m
  rw [log] at mc ⊢
  obtain ⟨seg, inSegs, inSeg⟩ := List.mem_flatten.mp mc
  obtain ⟨request, now, index, wire, opened, D, _, _, B, e⟩ := stateless_proxy.Proofs.seg_completed (Opening inst)
    cfg.policyInst keys cfg.policy cfg.routes cfg.acceptance peer (ok seg inSegs) inSeg
  obtain ⟨s1, s2, split⟩ := List.append_of_mem inSegs
  exact ⟨s1.flatten ++ [.began request, .admitted opened.claims index true, .connected D true], B ++ s2.flatten,
    D, wire, by rw [split, e]; simp⟩

theorem records_permitted : RecordsPermitted inst Paired cfg W :=
  fun _ _ _ m unforged => log_permitted aead reach m unforged

omit aead in
theorem refusals_send_nothing : RefusalsSendNothing W :=
  fun _ _ _ m => rejection_never_sends reach m

omit aead in
theorem delivered_to_initiator : DeliveredToInitiator inst cfg W :=
  fun _ _ _ del => stateless_protocol.delivered_to_initiator reach del

omit aead in
theorem logins_at_most_once : LoginsAtMostOnce W :=
  fun σ => login_once reach σ

theorem renewal_preserves_lineage : RenewalPreservesLineage inst cfg W :=
  fun _ _ _ _ _ issued => lineage aead reach issued

omit aead reach in
theorem claims_hide_credential : ClaimsHideCredential inst cfg W :=
  fun _ _ _ _ _ issued => (issued_secret issued).2.2

/-- **A.** Every credential-bearing write attempt is authorized.

    * protects: the credential reaches the native writer only inside the
      exact request the agent asked for, for the destination of the route
      of its surrogate's provider, after the operation policy permitted it;
    * attacker: a malicious agent with its own certificate and surrogates,
      choosing every request byte, over any number of connections and
      replicas, interleaved with any logins, mints and renewals;
    * source: the extracted connection loop and `decide`, `open`,
      `encode_upstream` (`send_origin`, `dispatch_permitted`,
      `encoded_exact`);
    * trust: `AeadCorrect`; `Unforged` for the connection's key set;
    * limit: about what the controller asked the native writer to do
      (layer 2), not what reached the network (`provider_writes_confined`). -/
theorem compromised_agent_confinement : CompromisedAgentConfinement inst Paired cfg W := by
  intro keys peer log m unforged D wire written sent
  obtain ⟨request, now, index, opened, hd, order, sealer, claims, credential, token, src, iss, oc, same, cert, lin,
    inside, prov, dest, enc⟩ := send_origin aead reach m unforged sent
  obtain ⟨op, hop, hperm⟩ :=
    stateless_proxy.Proofs.dispatch_permitted (Opening inst) cfg.policyInst keys cfg.policy request cfg.routes
      cfg.acceptance peer now hd
  refine ⟨request, now, index, _, opened, hd, order, ⟨by rw [oc]; exact cert, sealer, credential, token, src,
    by rw [oc]; exact iss, same, by rw [oc]; exact lin⟩, ⟨op, hop, hperm⟩, ⟨inside, rfl, by rw [prov, oc]⟩, dest, enc,
    stateless_proxy.Proofs.encoded_exact enc⟩

/-- **A, on the network.** Under the native transport contract, every
    application byte the proxy process emitted to a provider for a connection
    lies in a prefix of an authorized write attempt, on a session to the
    server named by the destination of the route of the surrogate's provider
    — even when the write failed part-way.

    * protects: no credential-bearing application data goes to any other
      server, or in any other request, or beyond the authorized request;
    * attacker: as for `compromised_agent_confinement`;
    * source: `compromised_agent_confinement`;
    * trust: `TransportFaithful` (layer 3), `AeadCorrect`, `Unforged`;
    * limit: application data (TLS plaintext) only — the TLS records and
      TCP segments are TLS's and the kernel's; a reported success means the
      bytes were written and flushed, not that the provider received them. -/
theorem provider_writes_confined {keys : KeySet M} {peer : Slice U8} {log : List ProxyEvent}
    (m : Act.served keys peer log ∈ W.acts) (unforged : Unforged inst Paired cfg W keys)
    {writes : List ProviderWrite} (faithful : TransportFaithful log writes) :
    ProviderBytesConfined inst cfg W keys peer log writes := by
  intro x mx
  obtain ⟨⟨D, wire, written⟩, ma, bytes, e, pre, whole⟩ := forall₂_mem_right faithful mx
  subst e
  exact ⟨D, wire, written, rfl, pre, whole,
    compromised_agent_confinement aead reach keys peer log m unforged D wire written (mem_attempts ma)⟩

omit aead in
/-- **A, for completed requests.** Under the native transport contract, a
    request recorded as completed emitted its whole authorized request on a
    session to its destination. -/
theorem completed_requests_emitted_whole {keys : KeySet M} {peer : Slice U8} {log : List ProxyEvent}
    (m : Act.served keys peer log ∈ W.acts) {writes : List ProviderWrite} (faithful : TransportFaithful log writes)
    {status : U16} {acked : Bool} (mc : ProxyEvent.completed status acked ∈ log) :
    ∃ D wire, ProxyEvent.attempted D wire true ∈ log ∧ ProviderWrite.on D wire.val ∈ writes := by
  obtain ⟨A, B, D, wire, e⟩ := completed_after_whole_write reach keys peer log m status acked mc
  have ma : ProxyEvent.attempted D wire true ∈ log := by rw [e]; simp
  have mt := attempts_of_mem ma
  obtain ⟨x, mx, bytes, ex, _, whole⟩ := forall₂_mem_left faithful mt
  rw [whole rfl] at ex
  exact ⟨D, wire, ma, ex ▸ mx⟩

/-- **C.** Every credential-bearing write used a surrogate within its
    delegation.

    * protects: a surrogate is used only by its own certificate, inside its
      window, for an accepted audience and provider, and never with more
      than its root issuance granted;
    * attacker: an agent replaying, renewing or presenting surrogates on
      other connections, including another agent's;
    * source: `send_origin`, `open_ok_trace`, `lineage`;
    * trust: `AeadCorrect`, `Unforged`, the clock;
    * limit: certificate binding is not key custody — whoever holds the
      certificate's private key is the agent. -/
theorem bounded_delegation : BoundedDelegation inst Paired cfg W := by
  intro keys peer log m unforged D wire written sent
  obtain ⟨request, now, index, opened, hd, _, sealer, claims, credential, token, src, iss, oc, same, cert, lin, _⟩ :=
    send_origin aead reach m unforged sent
  obtain ⟨_, _, hopen, _⟩ := stateless_proxy.Proofs.dispatch_trace (Opening inst) cfg.policyInst keys cfg.policy request
    cfg.routes cfg.acceptance peer now hd
  obtain ⟨v, _, adm, vc, _⟩ := stateless.Proofs.open_ok_trace (Opening inst) keys _ cfg.acceptance peer now opened hopen
  obtain ⟨_, _, _, _, _, _, _, aud, prv, _, _, _, _, ren, _, early, late, _⟩ := adm
  refine ⟨request, now, index, opened, hd, by rw [oc]; exact cert, by rw [vc]; exact aud, by rw [vc]; exact prv,
    by rw [vc]; exact early, by rw [vc]; exact late, by rw [vc]; exact ren, credential, same, by rw [oc]; exact lin⟩

omit aead in
theorem failed_logins_issue_nothing : FailedLoginsIssueNothing W :=
  fun _ failed => failed_login_quiet reach failed

theorem credentials_entered_for_the_peer : CredentialsEnteredForThePeer inst Paired cfg W :=
  fun _ _ _ m unforged _ _ _ sent => send_root aead reach m unforged sent

/-- **D.** Credentials enter through a door for the agent that uses them.

    * protects: a login's surrogate goes only to the certificate that began
      it, at most once; a failed exchange or issuance issues nothing; every
      credential a proxy sends was minted for that certificate or came from
      a login it started;
    * attacker: an agent polling, replaying callbacks or racing logins, any
      OAuth answer, any interleaving;
    * source: the extracted mailbox transitions (`mailbox_reachable`,
      `at_most_once`, `failed_never_delivered`), `send_root`;
    * trust: `AeadCorrect`, `Unforged`; the browser, the human, PKCE secrecy
      and the provider's token endpoint (`STATELESS-OAUTH-01`); the
      operator's mint input (`STATELESS-ACQ-01`);
    * limit: a mint is a trusted door — the operator chooses the
      certificate. -/
theorem authorized_acquisition : AuthorizedAcquisition inst Paired cfg W :=
  ⟨delivered_to_initiator reach, logins_at_most_once reach, failed_logins_issue_nothing reach,
    credentials_entered_for_the_peer aead reach⟩

/-- **Garrett's guarantees hold in every reachable world**, under AEAD
    correctness (and, where a proxy relies on signatures, no forgery under its
    key set). Layer 2: about the extracted steps and the effects they
    request; the network statements of layer 3 are separate. -/
theorem security_guarantees : SecurityGuarantees inst Paired cfg W where
  confinement := compromised_agent_confinement aead reach
  completed := completed_after_whole_write reach
  refusals := refusals_send_nothing reach
  claimsHide := claims_hide_credential
  records := records_permitted aead reach
  delegation := bounded_delegation aead reach
  renewal := renewal_preserves_lineage aead reach
  acquisition := authorized_acquisition aead reach

/-- **The protocol's guarantees, together**: `protocol_safety` with each
    conjunct named, as before. -/
theorem guarantees :
    SendsAreAuthorized inst Paired cfg W ∧ RefusalsSendNothing W ∧ DeliveredToInitiator inst cfg W ∧
      LoginsAtMostOnce W ∧ RenewalPreservesLineage inst cfg W ∧ ClaimsHideCredential inst cfg W ∧
      RecordsPermitted inst Paired cfg W :=
  ⟨sends_are_authorized aead reach, refusals_send_nothing reach, delivered_to_initiator reach,
    logins_at_most_once reach, renewal_preserves_lineage aead reach, claims_hide_credential,
    records_permitted aead reach⟩

end

/-! ## A, for one route catalogue -/

/-- **One destination per provider.** If the proxy's route catalogue passed
    the extracted `routes_valid` (as `Proxy::new` requires), two routes that
    serve the same provider are the same route: the destination of a
    provider is unambiguous. -/
theorem one_route_per_provider {routes : Slice stateless_proxy.Route} (valid : stateless_proxy.routes_valid routes =
    Result.ok true) {provider : List U8} {i j : Usize} {r1 r2 : stateless_proxy.Route}
    (h1 : RouteFor routes provider i r1) (h2 : RouteFor routes provider j r2) : r1 = r2 := by
  have distinct := stateless_proxy.Proofs.routes_valid_spec routes
  rw [valid] at distinct
  obtain ⟨in1, e1, p1⟩ := h1
  obtain ⟨in2, e2, p2⟩ := h2
  have same := (WP.spec_ok _).mp distinct rfl i.val j.val in1 in2 (by rw [e1, e2, p1, p2])
  have : i = j := by scalar_tac
  subst this
  rw [← e1, ← e2]

/-! ## The read-only proxy -/

open garrett_stateless_core.stateless_policy.Proofs in
/-- **What a read-only proxy writes.** Under the read-only policy, every
    credential-bearing write is for a `GET` or `HEAD` request with an empty
    body, on a path a configured resource of the surrogate's provider allows.
    This is a syntactic restriction: whether such a request mutates anything
    is the provider's API semantics. -/
theorem read_only_writes {inst : KeyMaterial M} {cfg : Config stateless_policy.ReadOnly}
    (readOnly : cfg.policyInst = ReadOnlyPolicy) {W : World M} {keys : KeySet M} {peer : Slice U8}
    {log : List ProxyEvent} {D : stateless_proxy.Destination} {wire : alloc.vec.Vec U8} {written : Bool}
    (authorized : CredentialWriteAuthorized inst cfg W keys peer log D wire written) :
    ∃ (request : proxy_http.request.Request) (opened : stateless.Opened), PolicyPermits cfg request opened.claims ∧
      ReadMethod request.method.val ∧
      request.body.length = 0 := by
  obtain ⟨request, now, index, _, opened, hd, _, _, permits, _⟩ := authorized
  rw [readOnly] at hd
  obtain ⟨read, body, _⟩ := stateless_proxy.Proofs.read_only_dispatch (Opening inst) keys cfg.policy request
    cfg.routes cfg.acceptance peer now hd
  exact ⟨request, opened, permits, read, body⟩

/-! ## E. Stateless authorization

The proxy's authorization decision is the extracted `decide_request`, a
function of the key set (through the opener), the operation policy, the
request, the routes, the acceptance policy, the authenticated peer and the
clock — its arguments, and nothing else. The proxy keeps mutable state per
connection (the read buffer, the provider connection, an optional audit file
handle), but no authorization state; the broker keeps the OAuth login
mailbox, and a strict broker not even that. -/

/-- **A connection the configuration allows on its own.** Some channel, from
    an empty buffer, ran a prefix of the extracted connection loop for `peer`
    under `keys` and logged exactly `log`. Nothing about any other connection,
    renewal, mint or login appears in it. -/
def ConnectionAllowed (inst : KeyMaterial M) (cfg : Config P) (keys : KeySet M) (peer : Slice U8)
    (log : List ProxyEvent) : Prop :=
  Configured keys ∧ ∃ (C : Type) (ch : stateless_proxy.Channel C) (io : C) (after : C × List ProxyEvent)
    (final : proxy_controller.Tunnel),
    Prefix (Opening inst) cfg.policyInst (stateless_proxy.Proofs.logged ch) keys cfg.policy cfg.routes cfg.acceptance
      cfg.authority peer cfg.limit (io, []) { buffer := alloc.vec.Vec.new U8, «open» := true } after final ∧
    after.2 = log

/-- **E. The proxy needs no history.** Every connection in every reachable
    world is one the configuration allows on its own, and every connection the
    configuration allows can happen in any world, whatever happened before.

    * protects: authorization does not depend on earlier connections,
      renewals, mints or logins, so replicas need no shared state;
    * attacker: any history of other agents' activity;
    * source: the `Step` relation over extracted transitions;
    * trust: none beyond the model of a world;
    * limit: the proxy keeps per-connection state and an optional audit
      handle; statelessness is about authorization, not the process. -/
theorem connection_needs_no_history {inst : KeyMaterial M} {Paired : M → M → Prop} {cfg : Config P} :
    (∀ {W : World M}, Reachable inst Paired cfg W → ∀ keys peer log, Act.served keys peer log ∈ W.acts →
      ConnectionAllowed inst cfg keys peer log) ∧
    (∀ keys peer log, ConnectionAllowed inst cfg keys peer log →
      ∀ W : World M, Step inst Paired cfg W { W with acts := W.acts ++ [.served keys peer log] }) := by
  constructor
  · intro W reach
    induction reach with
    | init _ => intro keys peer log m; simp at m
    | step _ move ih =>
      intro keys peer log m
      cases move with
      | login run => exact ih keys peer log m
      | renew _ _ run =>
        rcases List.mem_append.mp m with m' | m'
        · exact ih keys peer log m'
        · simp at m'
      | mint run =>
        rcases List.mem_append.mp m with m' | m'
        · exact ih keys peer log m'
        · simp at m'
      | serve ch io configured run =>
        rcases List.mem_append.mp m with m' | m'
        · exact ih keys peer log m'
        · simp only [List.mem_singleton, Act.served.injEq] at m'
          obtain ⟨ek, ep, el⟩ := m'
          subst ek ep el
          exact ⟨configured, _, ch, io, _, _, run, rfl⟩
  · rintro keys peer log ⟨configured, C, ch, io, after, final, run, rfl⟩ W
    exact .serve ch io configured run

open garrett_stateless_core.stateless_proxy in
/-- **E. Replicas decide alike, and reply alike given the same network
    answers.** Two proxies with the same keys, policy, routes and acceptance
    policy — any two origin adapters, in any state — make the same decision
    for the same authenticated request; if their adapters answered alike, the
    replies are identical; and for a refusal no adapter is asked, so the
    replies always are. -/
theorem replicas_decide_alike {V P O1 O2 : Type} (ops : stateless.SurrogateOpener V)
    (pol : stateless_policy.OperationPolicy P) (opener : V) (policy : P)
    (inst1 : Origin O1) (io1 : O1) (inst2 : Origin O2) (io2 : O2)
    (request : proxy_http.request.Request) (routes : Slice Route) (a : stateless.Acceptance) (peer : Slice U8)
    (now : I64) (limit : Usize) (s1 s2 : proxy_controller.Served) (a1 : O1) (a2 : O2)
    (h1 : serve ops pol inst1 opener policy io1 request routes a peer now limit = Result.ok (s1, a1))
    (h2 : serve ops pol inst2 opener policy io2 request routes a peer now limit = Result.ok (s2, a2)) :
    ∃ d ans1 ans2, decide_request ops pol opener policy request routes a peer now = Result.ok d ∧
      (d.isDispatch = true → Proofs.AnsweredBy inst1 io1 routes limit d ans1 a1 ∧
        Proofs.AnsweredBy inst2 io2 routes limit d ans2 a2) ∧
      (d.isDispatch = false → s1 = s2) ∧ (ans1 = ans2 → s1 = s2) :=
  Proofs.replicas_same_answers_same_reply ops pol opener policy inst1 io1 inst2 io2 request routes a peer now limit
    s1 s2 a1 a2 h1 h2

/-- **E. A strict broker keeps no login state.** With no OAuth provider
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
`ProviderRouteMatches`, `ExactUpstreamRequest`, `Dispatched`). -/

open garrett_stateless_core.stateless_proxy garrett_stateless_core.stateless_proxy.Proofs
  garrett_stateless_core.stateless_policy.Proofs in
/-- **Each proxy request is refused without egress, or makes one authorized,
    exact egress to its route's destination** — for Garrett's unrestricted
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
/-- **The same for the read-only proxy**, whose operations are `GET` or
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

/-- **C. Issued for a certificate, opens only for it.** A surrogate the
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
