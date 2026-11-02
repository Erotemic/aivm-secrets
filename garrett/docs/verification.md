# `garrett-stateless-v1`: what the Lean proofs establish

**Scope.** Implementation-linked theorems about the Rust that the
`garrett-stateless` broker and proxy run. Every decision, codec and transition
lives in the crate `crates/garrett-stateless-core`; Aeneas extracts it into
`proofs/generated/GarrettStatelessCore.lean` (namespace
`garrett_stateless_core`); the theorems are in `proofs/GarrettStateless*.lean`,
over the supporting HTTP, OAuth and base64 lemmas in the other `proofs/`
modules and the generic Aeneas facts in `proofs/GarrettFoundation.lean`. This
is experimental, unaudited work.

**Start with [`proofs/Garrett.lean`](../proofs/Garrett.lean).** It states
Garrett's five product-level guarantees as named propositions, with their
hypotheses, and derives each from the implementation-linked theorems below;
it adds no model of its own. [`PROTOCOL.md`](../PROTOCOL.md) walks through one
execution with links to the Rust and to these theorems.

Every claim in this project is one of four kinds:

| Kind | What | Where |
| --- | --- | --- |
| proved | properties of the extracted Rust computations and of the modeled executions built from them | the theorems below |
| assumed | correctness of AES-256-GCM and Ed25519 (and unforgeability), AEAD secrecy (IND-CPA) and nonce uniqueness, the native transport contract, TLS peer identity, randomness, the clock, the adapters' inputs | [`assumptions.json`](assumptions.json), as explicit premises |
| guarded or tested | the native shells' wiring to the core, interoperability, conformance | `verification/shell_guard.py`, the Rust and Python tests, `tests/vectors/` |
| not established | whole-process I/O refinement of the binaries, computational security of the primitives, noninterference beyond the stated declassification boundary (timing, sizes, side channels, a whole connection), compatibility with a real provider | — |

## The five guarantees

The question: can an untrusted, possibly malicious agent get useful access
to a provider without obtaining the provider credential or exercising
authority beyond what the broker and proxy permit? `Garrett.lean` answers it
in five parts; `security_guarantees` proves the per-execution ones together
(`SecurityGuarantees`) for every reachable world, under `AeadCorrect` and,
where a proxy relies on signatures, `Unforged`.

| | Guarantee (human statement) | Lean | Proved | Trusted | Tested only |
| --- | --- | --- | --- | --- | --- |
| A | Even a malicious agent cannot make Garrett transmit a credential except in an authenticated, authorized, exact request to the configured destination of the provider its surrogate names. | `CompromisedAgentConfinement` (`CredentialWriteAuthorized`: `IssuedFor`, `PolicyPermits`, `RouteFor`, `ExactRequest`, `AfterAuthenticatedConnection`); `provider_writes_confined`; `one_route_per_provider`; `read_only_writes` | every credential-bearing record of every connection, in every execution; the route-to-destination binding (each `Route` carries its `Destination`); one route per provider (`routes_valid_spec`); no write after a failed connection (`exchange_logged`) | `TransportFaithful`: the native `connect`/`transmit` perform exactly the logged writes on a TLS session that authenticated the destination (`STATELESS-NATIVE-01`, `STATELESS-TLS-01`); `Unforged` | the native proxy against an impostor destination (`workflow.rs`), the shell guard's pinning of `open_upstream` and `transmit` |
| B | The agent cannot recover the credential from its surrogate, from the proxy's replies or from the broker's outputs, beyond what is declassified on purpose. | `ClaimsHideCredential`, `RecordsPermitted`, `ProxyRepliesDeclassified`, `SurrogatesRevealOnlyCiphertext` (`GarrettConfidentiality`) | two-run theorems: the decision and the reply depend on the credential only through the provider's answer and one reflection bit; a surrogate only through its AEAD ciphertext | AES-256-GCM IND-CPA with unique nonces (`STATELESS-CRYPTO-01`); the declassification boundary (`STATELESS-DISCLOSURE-01`) | — |
| C | A surrogate grants only its binding, provider and window, and renewal cannot widen what the root issuance granted. | `BoundedDelegation` (`WithinDelegation`), `RenewalPreservesLineage`, `opens_only_for_its_certificate` | for every credential-bearing write: bound to the connection's certificate, accepted audience and provider, inside its window, `exp ≤ ren ≤` the root's `ren`, same provider, binding, subject and credential as its root | the clock; custody of the agent's private key (`STATELESS-DEPLOY-01`); what `Unrestricted` permits is everything on the route | — |
| D | OAuth credentials are bound to the agent that began the login, issued at most once per exchange, and delivered only to it; operator mint is a separate, trusted door. | `AuthorizedAcquisition` (`DeliveredToInitiator`, `LoginsAtMostOnce`, `FailedLoginsIssueNothing`, `CredentialsEnteredForThePeer`) | the mailbox over every interleaving; every credential a proxy sends was minted for that certificate or came from a login that certificate started | the browser, the human's approval, PKCE secrecy and the provider's token endpoint (`STATELESS-OAUTH-01`); the operator's mint input (`STATELESS-ACQ-01`) | the Rust and Python login workflows |
| E | The proxy decides from the authenticated request, keys, policies and the clock alone; replicas with the same inputs decide alike. | `connection_needs_no_history` (`ConnectionAllowed`), `replicas_decide_alike`, `replica_replies_differ`, `strict_broker_is_stateless` | the decision is a function of its arguments; a connection's behaviour does not depend on any earlier connection, renewal, mint or login; replica replies differ only through network answers; a strict broker holds no login state | the native shells keep only the state the guard allows | the replica tests |

The distinctions the guarantees keep:

* **A decision is not a write.** `composed_egress` and `decide_request` are
  about the extracted controller. `CompromisedAgentConfinement` is about the
  connection's log of native effects, which the extracted connection loop
  requests. That those requests are the process's only provider writes, each
  on a TLS session that authenticated the destination, is the explicit
  hypothesis `TransportFaithful` of `provider_writes_confined`, not a
  theorem.
* **`Unrestricted` is not least privilege.** Under Garrett's proxy the
  surrogate alone authorizes every operation on its provider's route (minus
  the deny rules); `ReadOnly` restricts the method, body and path
  syntactically (`read_only_writes`), which is not a proof that the provider
  performs no mutation.
* **Certificate binding is not key custody.** A surrogate works only on a
  connection authenticated by its certificate; whoever holds that
  certificate's private key is, to Garrett, the agent.
* **No authorization state is not no state.** The proxy keeps per-connection
  buffers, provider sessions and an optional audit handle; the broker keeps
  the OAuth mailbox (a strict broker does not).

It proves the **internal** protocol, our own code, over every execution. It is
not a proof of the cryptography, of TLS, of the operating system, of the
native shells' I/O, or of the toolchain. The specification is
[`garrett-stateless-v1.md`](garrett-stateless-v1.md).

## The internal protocol theorem

`stateless_protocol.protocol_safety` (`proofs/GarrettStatelessProtocol.lean`)
is stated over a transition system whose every step runs one extracted Rust
function on arbitrary inputs:

| Step | Extracted function |
| --- | --- |
| a login start, browser check, callback, code exchange, finish or poll | `stateless_mailbox::{start, pending, accept, exchange, finish, poll}` |
| a renewal | `stateless::renew` with the `KeySet` opener and the `TokenSealer` |
| an operator mint | `stateless::issue` with the `TokenSealer` |
| any finite prefix of a proxy connection, closed or still open | `stateless_proxy::connection_step`, from the state `connection` starts in |

The inputs are arbitrary: any clock value, random draw (login ids, PKCE
verifiers, nonces, token ids), TLS peer, OAuth endpoint answer, `Channel`
behaviour (reads, writes, deadlines, failures), configured key set and
signing key. Steps interleave arbitrarily. The mailbox is one mutex in
`broker.rs`, so its transitions are atomic; renewal and the proxy share no
state with anything, so running each atomically loses no interleaving.

For every reachable world, the theorem proves:

1. **Every credential-bearing provider write has an authorized origin.** Each
   `sent D w` record follows, in the same connection, the `began` record of
   the request the connection framed, the acknowledged admission of the same
   claims and route, and the authenticated connection to `D`; it was decided
   by `decide_request`, which is the extracted pure `stateless_proxy::decide`,
   for that request and the connection's own TLS peer; `D` is the
   destination of the route serving the surrogate's provider; the surrogate
   is one this broker issued, bound to exactly that peer's certificate; the
   bytes are exactly the encoder's request carrying exactly the issued
   credential; and that credential descends from a login or a mint
   (`send_origin`). More
   precisely, it is an operator-minted credential for that certificate, or
   the token returned by the code exchange of a login started by a client
   holding exactly the sending connection's certificate (`send_root`).
2. **A rejection creates no send, and no request sends twice**
   (`rejection_never_sends`).
3. **Every delivered surrogate belongs to its initiator**: it goes only to the
   certificate that began its login, is bound to it, and is the one issued
   for that login. **No login is exchanged, issued or delivered twice**, and
   a failed or uncertain exchange issues and delivers nothing
   (`delivered_to_initiator`, `login_once`, `failed_login_quiet`).
4. **Renewal never extends the absolute limit or changes the surrogate**,
   over any number of renewals: every issued surrogate has a login or mint
   root with the same certificate, provider, subject and credential and a
   `ren` no later than the root's (`lineage`).
5. **Every output has a permitted form.** Every proxy record is one of the
   permitted forms (`log_permitted`): the guest's own request; a rejection
   code; the admission of an issued surrogate for this peer, whose claims do
   not contain its credential; exactly the encoder's request (the one
   permitted effect); a status or refusal code; or guest bytes that are a fixed
   refusal or a `guest_response` release in which the raw credential does not
   occur. No issued surrogate shows its credential in its header, public
   payload or claims (`issued_secret`); it leaves the broker only as the
   plaintext of the AEAD `seal` primitive. This restricts the form of each
   record and excludes the raw credential (and, in released replies, its
   listed encodings) from the checked outputs; it is not a general
   information-flow or noninterference result.

Also proved, outside the summary statement: **informational claims have no
influence** — two tokens sealed over the same claims by the same entry verify
to the same claims, key and key issuer, whatever their `scope` and `upstream`
(`informational_no_influence`); **key retirement** — under a
configured key set a token opens only if its header `kid` names an entry of
that set (`kid_configured`, `retired_never_opens`); and **replica
equivalence** — `decide_request` (`replicas_decide_alike`) and `renew` take no
replica state, so replicas with the same configuration decide alike.

## Composable authorized egress (`GarrettStatelessComposition`)

The request path is composed of separately verified extracted components, and
one theorem composes them for **any** operation policy:

| Component | Extracted Rust | Contract |
| --- | --- | --- |
| identity verification | `stateless::authenticate` (verify, then admit) | `authenticate_ok_trace` (`Admitted`) |
| operation authorization | an `OperationPolicy` instance (`stateless_policy.rs`) | `Sound pol policy Allowed` |
| provider selection | `stateless_proxy::route_of` | `route_of_loop_contract` |
| credential release | `stateless::decrypt` | `decrypt_ok_trace`; `open_of_halves` (the two halves are `open`) |
| exact request encoding | `proxy_http::encode_upstream` | `encode_upstream_contract` |
| controlled egress | `stateless_proxy::serve`, `exchange`, any `Origin` | `serve_follows_decision` (`Dispatched`: one `exchange` with `egressTo routes index`, the route's own destination); `exchange_logged` |

`composed_egress`: for any policy component meeting its contract `Allowed`,
every run of `serve` either makes **no egress** (not a dispatch; `admitted`
and no exchange is attempted; the reply is the fixed `401` or a fixed
refusal) or makes **one** egress, after which the surrogate was verified and
admitted for this TLS peer, the request's `Operation` is `Allowed` for its
claims, the route serves its provider, the credential is that surrogate's
unsealed credential, the bytes are the encoder's output (exactly
`ExactWire` when they fit in memory), and admission was acknowledged before
the one exchange, which goes to the route's own destination. The statement
is `AuthorizedEgress`, proved once: either `NoDispatch`, or one dispatch
that is `AuthenticatedSurrogate`, `AuthorizedOperation`,
`ProviderRouteMatches` and `ExactUpstreamRequest` and whose egress is
`Dispatched`. It constrains the extracted controller; the native socket code
that performs the exchange is outside it (`STATELESS-NATIVE-01`).

**Route and destination.** Each `stateless_proxy::Route` carries its
`Destination` (server name, address, port, trust anchors), so selecting the
route selects where the credential goes; there is no second table to keep in
step. `serve` builds the `Egress` from that route's destination, and the
extracted `exchange` asks the shell to connect to exactly that destination,
hands it the egress only if the shell reported that the server authenticated
there, and collects the answer within `answer_limit` (`exchange_logged`,
`collect_loop_preserves`). `routes_valid` (which `Proxy::new` requires)
refuses a catalogue with two routes for one provider (`routes_valid_spec`,
`one_route_per_provider`).

It is instantiated, without repeating the proof, for the two policies the
proxy runs, each an actual extracted trait instance:

* `garrett_egress`: `Unrestricted`, contract `True` (`unrestricted_sound`) —
  Garrett's proxy, where the surrogate alone authorizes;
* `read_only_egress`: `ReadOnly p`, contract `ReadOnlyAllowed p`
  (`read_only_sound`, from `read_only_permits_spec`, `any_allows_spec` over
  the extracted loop, `resource_allows_spec`, `read_method_eq`, and the
  existing `method_ok_spec`/`path_matches_spec`).
  `read_only_dispatch` restates it for the request: a dispatched request is
  `GET` or `HEAD`, has an empty body, and its path (the target before any
  `?`, `operation_of_spec`) is allowed by a configured resource for the
  surrogate's provider. `read_only_refuses`: any other method, or any body, is
  never dispatched, so nothing is sent.

The policy sees only the claims and the `Operation`, never the credential or
upstream bytes (its Rust signature). `decide_unpermitted`
(`GarrettStatelessProxy`): when the policy refuses, the decision is the fixed
`denied` refusal whatever the `unseal` adapter would do — the credential is
not decrypted. `dispatch_permitted`: every dispatch was permitted by the
policy for the opened claims. The dispatch payload (`Dispatch`) has private
fields, so only `stateless_proxy` reads it.

The shell side is guarded, not proved: `shell_guard.py` checks that the
proxy runs the core loop only under `&Unrestricted` or the configured core
`ReadOnly`, that the shell implements no `OperationPolicy`, and that it never
calls `permits`, `authenticate` or `decrypt` itself.

**Replicas, answer by answer.** `serve_answered`: a reply is `reply` of the
pure decision and of `Answered`, exactly what the origin adapter was asked and
answered — `none` (no dispatch: nothing asked), `unadmitted` (the admission
record was not acknowledged), or `exchanged answer done` (the provider
exchange's result and, only for a completed release, the completion
acknowledgement). `replicas_same_answers_same_reply`: two replicas with the
same keys, policy, routes and acceptance make the same decision; a refusal
gives identical replies; equal answers give identical replies.
`replica_replies_differ`: different replies imply a dispatch whose admission
acknowledgements, provider exchange results or completion acknowledgements
differ. All three hold for both policies, since they are proved for any
policy. `tests/test_garrett_stateless_operations.py` runs the same requests
against a Python and a Rust replica of each configuration.

## What the credential can influence (`GarrettConfidentiality`)

`ClaimsHideCredential` and `RecordsPermitted` restrict the **form** of single
outputs. `GarrettConfidentiality` adds **two-run** theorems that say what an
output can depend on. The adversary is the agent: it chooses every request
byte and holds its surrogates, and it sees every reply. The theorems compare
two executions that differ only in the protected credential.

| Theorem | Statement |
| --- | --- |
| `decide_declassified` | two proxies whose openers verify alike and unseal two valid credentials (`SameButCredential`) decide the same request alike up to the credential: the same refusal, or a dispatch to the same route for the same claims |
| `encode_upstream_verdict` | the encoder accepts or refuses two valid credentials alike (its refusals come from checks made before the credential is read, or from its validity) |
| `release_declassified`, `guest_response_forms` | releasing one provider answer against two credentials' reflection forms gives the same reply, unless one is the fixed reflection refusal |
| `reply_declassified`, `serve_declassified` | with the same network answers, the agent receives the same reply, unless the provider's answer reflected one credential and not the other |
| `seal_token_ciphertext_only`, `issue_ciphertext_only` | two issuances that both succeed, under primitives that sign alike and return the same AEAD ciphertext for the two credentials, give the same surrogate |

Declassified on purpose (`STATELESS-DISCLOSURE-01`): the bytes sent to the
provider; the provider's answers (a provider whose answers depend on the
credential can reveal it); one bit per request, whether the answer reflected
the credential in a checked encoding; at issuance, whether the credential is
valid and whether it occurs in the header or public claims; and the
ciphertext, which hides the credential only under the IND-CPA assumption
(`STATELESS-CRYPTO-01`) and reveals its length. Not covered: timing, sizes on
the network, side channels, the native shells (`STATELESS-NATIVE-01`), and a
whole-connection two-run theorem (the connection loop adds only framing
refusals, which do not involve the opener).

## Statelessness and acquisition (`GarrettStatelessProxy`, `GarrettStatelessStrict`)

**A pure request decision.** `stateless_proxy::decide(opener, policy, request,
routes, acceptance, peer, now)` is the Rust function every request is decided
by; it returns `Unauthorized`, `Refused` or `Dispatch` (route, bytes, opened).
It performs no effect of its own: the opener and policy are trait
parameters, and the theorems hold for whatever those implementations return
(the real `KeySet` and `ReadOnly`/`Unrestricted` are themselves extracted;
the primitives inside `KeySet` are the assumed boundary). Its inputs are the keys (through the `KeySet` opener),
the static operation policy, the authenticated peer, the request carrying the
surrogate, the clock and the static routes and acceptance policy; it has no
other input, so no history-dependent acceptance is possible. `serve` calls it first and only
then, for a dispatch, records the admission and makes the one exchange.
`decide_request` is that extracted function (`Decision.ofCore` only renames
constructors), so `send_origin` above says every provider write in any
reachable world is a `Dispatch` value of `decide`.

**Decisions versus network outcomes.** `serve_outcome`: every run of `serve`
returns `outcome` of the decision and of its origin adapter's three answers
(the admission acknowledgement, the exchange's answer, the completion
acknowledgement); no other adapter state reaches the reply.
`replicas_differ_only_by_answers`: two proxies with the same keys and
configuration, with any two adapters in any state, make the same decision —
for a dispatch, the same route and bytes — and their replies can differ only
because those adapter answers differ. "Answers" are **three** things, not only
the provider's reply: the local admission acknowledgement, the provider
exchange's result, and the local completion acknowledgement. The composition
section above (`serve_answered`, `replica_replies_differ`) separates them.
Equal decisions are proved; equal network outcomes are not, and cannot be.

**The strict profile.** The profile's one piece of mutable process state is the
broker's login mailbox, which only the OAuth acquisition adapter uses. The
shell builds the mailbox's `LoginPolicy` from the OAuth providers only, and a
`"stateless": "strict"` broker configuration refuses every OAuth provider.
`no_providers_no_state`: when the login policy names no provider, every
reachable mailbox is the empty one and the login history has no event,
whatever agents and browsers send. `strict_no_login_state` lifts this to
every reachable world of the whole protocol model. The proxy has no mutable
state in the model at all. "Stateless" here means no mutable authorization or
login state; the processes still hold ordinary runtime and transport state
(sockets, TLS sessions, buffers). The other half of the strict profile — no audit
file, and no other mutable state or file write in the shell — is a source
guard, not a proof (section 5 below).

**Acquisition is outside the isolation core.** Issuance (`stateless::issue`)
consumes a `Grant` (provider, binding, expiries) and a credential and nothing
about where they came from; the proxy and renewal never see the source. The
model's `mint` step takes *any* grant and credential, so it stands for every
non-OAuth acquisition adapter — direct provisioning today — and the OAuth
adapter is the mailbox. `protocol_safety` therefore holds for any mix of the
two, including a deployment with no OAuth at all. What each adapter is
trusted for is in the specification's section 7.1; in particular, a
provider-reported scope is an informational claim
(`informational_no_influence`), never an authorization input.

### The premises: only the external boundary

`protocol_safety` has exactly these premises, all about code we do not own
(`proofs/GarrettStatelessBoundary.lean`):

| Premise | External operation | Form |
| --- | --- | --- |
| `aead : ∀ S V, Paired S V → AeadInverse inst S V` | AES-256-GCM `seal`/`open` (`ring`) | correctness: what a key seals, its pair opens under the same nonce and AAD; the ciphertext is the plaintext and a 16-byte tag. Correctness only: **nonce uniqueness is not proved**; each `TokenSealer` gets a fresh random nonce and `seal` consumes it (`STATELESS-CRYPTO-01`) |
| `Unforged … keys` at each renewal (a field of the `renew` step) and for each proxy key set | Ed25519 `verify` (`ring`) | the idealized EUF-CMA boundary: in this execution, an entry verifies only signed parts of tokens this broker issued with a key paired to it |
| `Paired : M → M → Prop` | key management (`keys.rs` rotate/export) | which verification material belongs to which signing key |

`Unforged` is stated per step for renewals, at the moment they verify, so a
renewal can never rest on a token issued later. Configuration (`Config`,
`KeySet::new`) and the key material are public inputs. **No premise is about
the correctness of code we own**: the codec premise the earlier theorem
`issued_only_opens_for_its_certificate` took is now proved
(`accepts_sealed`, `issued_codec`, `issued_opens_only_for_its_certificate`).
No global axiom is added; the proofs use only Lean's standard axioms (see
the end-of-campaign audit below).

**Positive witnesses.** `seal_then_open` (`GarrettStatelessRoundTrip`): a
`seal_token` output verifies under any configured set holding its `kid` and
unseals to exactly the sealed credential, for any informational claims.
`issue_then_open` (`GarrettStatelessWitness`): a surrogate `stateless::issue`
produced opens with `stateless::open` for every peer and time admission
accepts, with exactly the issued claims and credential. Their only premises
are the correctness contracts `SignVerifies` and `AeadInverse`. Delivery
through `poll` is witnessed by the Rust and Python workflow tests, not by a
Lean theorem.

## Build and check

```bash
python verification/toolchain.py bootstrap   # pinned Aeneas, Rust nightly, Lean; Mathlib cache
python verification/extract.py check          # proofs/generated matches the Rust
cd proofs && lake build && cd ..              # every proof
python verification/mutate.py                 # Rust mutants
python verification/shell_guard.py check      # shell guard
```

## Theorem-to-Rust coverage map

| Lean module | Theorems | Extracted Rust (`crates/garrett-stateless-core/src/`) |
| --- | --- | --- |
| `Garrett` | the five guarantees: `compromised_agent_confinement`, `provider_writes_confined`, `one_route_per_provider`, `read_only_writes` (A); `claims_hide_credential`, `records_permitted`, `proxy_replies_declassified`, `surrogates_reveal_only_ciphertext` (B); `bounded_delegation`, `renewal_preserves_lineage`, `opens_only_for_its_certificate` (C); `authorized_acquisition`, `delivered_to_initiator`, `logins_at_most_once`, `failed_logins_issue_nothing`, `credentials_entered_for_the_peer` (D); `connection_needs_no_history`, `replicas_decide_alike`, `strict_broker_is_stateless` (E); `security_guarantees`; and, as before, `sends_are_authorized`, `refusals_send_nothing`, `guarantees`, `unrestricted_request`, `read_only_request` | everything below, through the theorems it projects |
| `GarrettConfidentiality` | `guest_response_forms`, `release_declassified`, `append_header_valid`, `encode_upstream_verdict`, `decide_declassified`, `reply_declassified`, `serve_declassified`, `seal_token_ciphertext_only`, `issue_ciphertext_only` | `proxy_http::response::guest_response`, `proxy_controller::release`, `proxy_http::encode_upstream`, `http_auth::append_header`, `stateless_proxy::{decide, serve}`, `stateless_token::seal_token`, `stateless::issue` |
| `GarrettStatelessCodec` | `from_b64url_sound`, `from_b64url_complete` (strict url-b64: exactly the canonical encoding), `natural_some`/`natural_of` (canonical decimals ≤ 2^53−1), `plain_string_some`/`_of`, `word_some`/`_of`/`_absent`, `payload_bytes_ok` | `stateless_token/` (`base64.rs`, `payload.rs`): `from_b64url`, `group`, `symbol_value`, `natural`, `digits`, `plain_string`, `word`, `append*`, `payload_bytes` |
| `GarrettStatelessGrammar` | exact Boolean characterizations `is_text_eq`, `is_provider_eq`, `is_kid_eq`, `is_id_eq`, `is_thumbprint_true`, `is_scope_true`, `is_verifier_eq`; `payload_valid_true`, `state_valid_true`; `select_spec`, `keys_valid_true`, `select_unique` (key selection is unambiguous); `header_bytes_ok`, `header_kid_spec`, `header_kid_of`; `segments_spec`; `occurs_spec`; `b64url_spec` | `is_*`, `payload_valid`, `state_valid`, `select`, `named`, `keys_valid`, `entry_valid`, `header_bytes`, `header_kid`, `ascii`, `dot_from`, `segments`, `occurs`, `b64url` |
| `GarrettStatelessToken` | `parse_payload_sound` (accepted bytes are exactly the canonical payload, which is valid), `parse_payload_complete`; `verify_token_ok`, `verify_token_sound` (the exact signed header and payload are what authorization uses; the AAD is exactly label, header, zero, public payload); `unseal_token_ok` (decryption uses the entry the verified `kid` selected); `seal_token_ok` (credential absent from header and public payload; exact AAD; signature over exactly the first two segments); `b64url_fits` | `parse_payload`, `field`, `number`, `verify_token`, `unseal_token`, `seal_token`, `associated`, `copy_claims`, `copy_info` |
| `GarrettStatelessState` | `state_bytes_ok`, `parse_state_sound`, `parse_state_complete`, `seal_state_ok`, `open_state_ok`, `seal_open_state` | `state_bytes`, `parse_state`, `seal_state`, `open_state` |
| `GarrettStatelessRoundTrip` | `seal_then_open` | `seal_token`, `verify_token`, `unseal_token` |
| `GarrettStatelessMailbox` | `reachable_inv`; `slot_from_start`, `accepted_matches_start`, `at_most_once`, `issued_for_starting_peer`, `delivered_to_starting_peer`, `failed_never_delivered`, `delivered_is_gone` | `stateless_mailbox.rs`: `start`, `pending`, `accept`, `exchange`, `finish`, `poll` and their loops |
| `GarrettStatelessConnection` | `connection_runs`, `collect_loop_preserves`, `exchange_logged`, `serveLog_events`, `step_logged`, `connection_logged`, `seg_sent`, `seg_connected`, `connection_egress_authorized`, `connection_sends_once_per_request`, `connection_guest_bytes` | `stateless_proxy.rs`: `connection`, `connection_step`, `serve`, `exchange`, `collect` |
| `GarrettStatelessProtocol` | `accepts_sealed`, `informational_no_influence`, `opened_issued`, `lineage`, `login_root`, `send_origin`, `send_root`, `rejection_never_sends`, `kid_configured`, `retired_never_opens`, `issued_secret`, `log_permitted`, `delivered_to_initiator`, `login_once`, `failed_login_quiet`, `prefix_logged`, `connection_prefix`, **`protocol_safety`** | all of the above, composed |
| `GarrettStatelessWitness` | `issue_then_open`, `issued_codec`, `issued_opens_only_for_its_certificate` | `stateless::issue`, `stateless::open`, the `KeySet`/`TokenSealer` instances |
| `GarrettStatelessStrict` | `no_providers_no_state`, `strict_no_login_state` | `stateless_mailbox.rs` (all transitions), `stateless_login::begin` |
| `GarrettStatelessComposition` | `Sound`, `operation_of_spec`, `unrestricted_sound`, `read_method_eq`, `resource_allows_spec`, `any_allows_spec`, `read_only_permits_spec`, `read_only_sound`; **`composed_egress`** (`AuthorizedEgress`), `garrett_egress`, `read_only_egress`, `read_only_dispatch`, `read_only_refuses`; `serve_answered`, `replicas_same_answers_same_reply`, `replica_replies_differ` | `stateless_policy.rs` (both `OperationPolicy` instances, `operation_of`, `any_allows` and its loop, `resource_allows`, `read_method`); `stateless_proxy::serve` |

The earlier theorems remain and are reused:

| Property | Theorem | Extracted Rust |
| --- | --- | --- |
| Admission is exactly the specification | `admit_spec`, `admit_ok_iff` (`Admitted`) | `stateless::admit` |
| Binding (opened ⇒ bound to this peer; one token, one peer) | `open_binds_peer`, `open_one_peer` | `stateless::open` |
| Authentication before decryption | `open_unadmitted_never_unseals`, `open_unverified`, `open_ok_trace` | `stateless::open` |
| Issuance | `issue_trace` (`IssuedFor`), `issue_window_spec`, `claims_for_trace`, `issue_invalid_never_seals` | `stateless::issue`, `claims_for`, `issue_window` |
| One renewal | `renew_trace` | `stateless::renew`, `renewal_grant` |
| Login binding | `begin_spec`, `begin_trace`, `accept_callback_trace`, `complete_trace`, `deliver_trace`, `deliver_other_peer` | `stateless_login.rs` |
| `serve` acts on the pure decision | `serve_follows_decision`, `decide_dispatch_trace`, `dispatch_trace`, `dispatch_permitted`, `decide_unpermitted`, `serve_dispatch_exact`, `serve_rejected_never_sends`, `serve_guest_reply`, `serve_outcome`, `replicas_decide_alike`, `replicas_differ_only_by_answers` | `stateless_proxy::decide`, `stateless_proxy::serve` |
| One destination per provider | `route_of_loop_first`, `route_of_first`, `routes_valid_spec` (`ProvidersDistinct`), `copy_destination_eq` | `stateless_proxy::{route_of, routes_valid, copy_destination}` |
| Opening in two halves (`open` is defined as `authenticate` then `decrypt`) | `authenticate_contract`, `decrypt_contract`, `authenticate_ok_trace`, `decrypt_ok_trace`, `open_of_halves` | `stateless::authenticate`, `stateless::decrypt`, `stateless::open` |

## Section 5 audit: endpoints and privileged paths

Each public endpoint makes its decision in extracted code; the shell does I/O.
`verification/shell_guard.py` (tested by
`tests/test_garrett_stateless_shell.py`) pins the shell side: the proxy keeps
no destination table; it connects only in `Origin::connect`, to the
destination the core passes (its address and port, its host as the TLS name,
its trust anchors); one provider write, of `egress_wire` of a core-made
`Egress`, only from `Origin::transmit`, after checking the connection is to
that egress's destination, and never retried; every proxied and every broker agent decision uses the
mutual-TLS peer of its handshake; sealing only through `issue`, `renew` or the
mailbox's `finish`, each from one endpoint; the access token becomes a `Token`
only in the permitted exchange, and a refresh token is dropped; audit records
name claims, routes, statuses and codes only; the shell never calls
`stateless::open` or `stateless_proxy::decide` itself; its only mutable state
is the mailbox (whose policy names OAuth providers only), the optional audit
file handle, and listener stop flags and connection counters; and the broker
and proxy write no file except that audit file, which a strict proxy
configuration refuses. This is a source guard, not a proof.

| Endpoint | Decision (proved) | Success | Failure, partial failure, retry |
| --- | --- | --- | --- |
| `POST /v1/logins` (agent mTLS) | `stateless_mailbox::start`, `seal_state` | 201: login id, confirmation, URL; the slot is bound to the peer | refusal codes; a seal failure after `start` leaves a slot that expires unused |
| `GET /authorize` (browser) | `open_state`, `pending` (read-only) | interstitial page | `invalid_state` |
| `GET /callback` (browser) | `open_state`, `accept`, `exchange` (the `Permit` is moved, so at most once), `finish` | issued surrogate stored for that login | denial, failed or uncertain exchange → `Failed`/`Uncertain`, never issued or delivered (`failed_login_quiet`); a replayed callback is refused (`login_once`) |
| `GET /v1/logins/{id}` (agent mTLS) | `poll` | the surrogate, once, to the starting certificate | wrong peer refused; **attempted vs completed delivery**: the slot is removed when `poll` returns it (`delivered_is_gone`), so a reply lost in transit is not resent; the agent starts a new login |
| `POST /v1/renewals` (agent mTLS) | `stateless::renew` | a new surrogate, same binding/provider/credential, `ren` not later | any refusal is 401; a retried renewal issues another surrogate within the same limit (`lineage`) |
| `mint` (operator) | `stateless::issue` | a surrogate for the operator's certificate and credential, from the keys and issuance policy alone (no listener, OAuth client or client secret) | refusal before any seal (`issue_invalid_never_seals`); an active key for another issuer is refused |
| proxy (agent mTLS) | `stateless_proxy::connection` | exactly one `sent` per admitted request, after `connected D true` | **attempted vs completed**: `connected D false` (the server did not authenticate as `D`) sends nothing and is `unreachable`; `sent` is the hand-off to `Origin::transmit`; `completed` records a provider answer; a native write or read failure is `OutcomeUnknown` and is never retried; an answer past `answer_limit` is `too_large` |
| key rotation, retirement, export | `KeySet::new` (`keys_valid_true`) | a valid set: 1–8 entries, unique `kid`s | an invalid set is refused; retirement removes a `kid` from proxies (`retired_never_opens`) |

## Implementation linkage: mutation evidence

`verification/mutate.py` applies each defect to the
**Rust source**, re-extracts with Charon/Aeneas, and recompiles the proof
import closure against the mutant. Each must break a proof.

| Mutant (Rust) | Rejected by |
| --- | --- |
| certificate binding removed; expired token accepted; audience not checked; verifying key issuer not checked; decrypted before admission; issuance binds the wrong certificate; renewal extends `ren`; renewal changes the subject | `GarrettStateless` |
| login binds a request value instead of the peer; callback state not checked; delivered to any peer | `GarrettStatelessLogin` |
| mailbox: duplicate login accepted; serial reused; capacity not enforced; exchange answer reaches another login; finish ignores the stage; poll ignores the peer | `GarrettStatelessMailbox` |
| proxy: wrong provider destination; egress without acknowledged admission; surrogate forwarded instead of credential; credential reflection unchecked; dispatches despite an encoder refusal; egress to another route's destination; `Host` from another route's destination; catalogue accepts two routes for a provider | `GarrettStatelessProxy` (within the `GarrettStatelessConnection` closure) |
| proxy: credential written after a failed connection | `GarrettStatelessConnection` (`exchange_logged`) |
| covert channels: the decision, the reply or the encoder's verdict reveals a credential bit; a token carries a credential byte outside the ciphertext | `GarrettConfidentiality` (some rejected first in its closure) |
| login started for an unconfigured provider | `GarrettStatelessStrict` (rejected first by `GarrettStatelessLogin`, in its closure) |
| proxy connection decides for the authority, not the peer | `GarrettStatelessConnection` |
| token: `kid` not used to select the key; duplicate `kid` accepted in a key set; header prefix not checked; provider grammar not checked | `GarrettStatelessGrammar` |
| token: non-canonical base64 accepted | `GarrettStatelessCodec` |
| token: associated data omits the header; payload with trailing bytes accepted; signature checked over the payload only; decrypted with the first key; credential allowed in the public payload | `GarrettStatelessToken` |
| login state: label not bound | `GarrettStatelessState` |
| proxy: operation policy not consulted; credential decrypted before authorization | `GarrettStatelessComposition` (rejected first by `GarrettStatelessProxy`, in its closure: `decide_dispatch_trace`, `decide_unpermitted`) |
| read-only policy: permits a write method; permits a body; ignores the destination provider; ignores the resource path; ignores the resource method; operation path includes the query | `GarrettStatelessComposition` |

**Result, 2026-10-29 (`c3f2437`): all 42 mutants are rejected**, in a copy of
this directory alone (`verification/standalone.py`), each by a real error in
the recompiled closure, not a cached object: after the import refactor, the
`open` change (whose mutant now inlines an `open` that unseals before it
admits), the module splits (the token mutants now live in
`stateless_token/*.rs`, each mapped to its first rejecting module) and the
refusal rename. Earlier runs: 42 (2026-10-27 and, after the extraction,
2026-10-29 at `5ebbc6d`), 34 and 32. The two proxy
policy mutants are caught by `GarrettStatelessProxy` before
`GarrettStatelessComposition` is reached. The strict-profile mutant is caught by the existing login proof
before `GarrettStatelessStrict` is reached, so the run does not show that the
strict theorem alone would catch it.

## What remains trusted

The assumption ledger entries are `STATELESS-NATIVE-01`, `STATELESS-CRYPTO-01`,
`STATELESS-TLS-01`, `STATELESS-OAUTH-01`, `STATELESS-DEPLOY-01`,
`STATELESS-CLAIMS-01`, `STATELESS-PY-01`, `STATELESS-ACQ-01`,
`STATELESS-OPS-01` and `STATELESS-DISCLOSURE-01`
([ledger](assumptions.json)). In short:

- **Primitives.** Ed25519 and AES-256-GCM (`ring`) satisfy the three boundary
  propositions above; no computational proof is claimed, and `Unforged` is
  the idealized form of EUF-CMA (the guarantees hold for executions without a
  forgery). `StateAeadInverse` is used only by the positive login-state
  round trip; login safety does not depend on it, because the mailbox accepts
  only a callback that matches its own pending entry.
- **Native shells.** The shell must do what `shell_guard.py` checks: pass
  the handshake peer; answer `connect` with `true` only for a TLS session to
  the destination it was given in which the server proved its host under its
  trust anchors; write exactly `egress_wire` on that session in `transmit`;
  and write only `served.reply` to the guest. In `Garrett.lean` this is the
  explicit hypothesis `TransportFaithful`. That the native code meets it, and
  that a provider-side effect follows, are not proved.
- **TLS and X.509.** The peer thumbprint must be that of the certificate the
  TLS stack verified; CRLs are not consulted.
- **Rust ownership.** `Permit`, `Exchanged` and `Egress` have private fields
  and are moved into the call that consumes them, so a permit is exchanged at
  most once and an egress is sent at most once. The mailbox model's `exchange`
  step takes this as its `held`/`unspent` premises; rustc, not Lean, checks it.
- **Toolchain.** Charon/Aeneas translation, their standard library models,
  the Lean kernel and the Rust compiler are trusted.
- **Responses.** The reply depends on the credential only through the
  provider's answer and the reflection bit (`serve_declassified`); a provider
  that echoes a transformed credential the reflection forms miss reveals it,
  and timing is not covered (`STATELESS-DISCLOSURE-01`).
- **Python.** `garrett_stateless.core` mirrors the Rust crate and is tested
  against the same vectors and the interop matrix; it is not proved.

## Axiom audit

The last audit ran on 2026-10-26, before the extraction, over the combined
package these proofs then lived in: every theorem, `protocol_safety`
included, depended only on Lean's standard axioms (`propext`,
`Classical.choice`, `Quot.sound`); the boundary propositions of
`GarrettStatelessBoundary` are premises, not axioms. The extracted model has
no `axiom` declarations (`proofs/generated/GarrettStatelessCore.lean`: every
function the protocol reaches is translated). A fresh audit of this package
is an opt-in, end-of-campaign step.

## Claim categories

| Category | Items |
| --- | --- |
| Implemented and tested | Python and Rust libraries; OAuth login with PKCE against a synthetic HTTPS provider; JWT and opaque tokens; substitution through the stateless proxy; refusals; renewal; key rotation and retirement; 4-way interop; container demo; swtpm-backed agent key |
| Implementation-linked formally proved | the theorems above, about the extracted Rust, including `protocol_safety` |
| Assumed from an external interface | Ed25519, AES-GCM, rustls/webpki/OpenSSL, OS sockets and clock, randomness, the provider's OAuth behaviour |
| Checked by a source guard only | the shell's privileged call sites (`shell_guard.py`) |
| Not established | live identity providers and APIs; hardware TPM provenance; whole-process I/O refinement of the shells; computational cryptography; independent review |
