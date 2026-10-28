# `garrett-stateless-v1`: what the Lean proofs establish

**Scope.** Implementation-linked theorems about the Rust that the
`garrett-stateless` broker and proxy run. Every decision, codec and transition
lives in `rust/crates/aivm-secrets-garrett-core/src/stateless*.rs`; Aeneas
extracts them into `proofs/generated/AivmSecretsGarrettCore.lean`; the theorems
are in `proofs/GarrettStateless*.lean`. This is experimental, unaudited work.
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
   `sent` record follows, in the same connection, the acknowledged admission
   of the same claims and route; it was decided by `decide_request`, which is
   the extracted pure `stateless_proxy::decide`, for the connection's own TLS
   peer; the surrogate is one this broker issued, bound
   to exactly that peer's certificate, for the route's provider; the bytes are
   exactly the encoder's request carrying exactly the issued credential; and
   that credential descends from a login or a mint (`send_origin`). More
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
   root with the same certificate, provider and credential and a `ren` no
   later than the root's (`lineage`).
5. **Outputs disclose no credential.** Every proxy record is one of the
   permitted forms (`log_permitted`): the guest's own request; a rejection
   code; the admission of an issued surrogate for this peer, whose claims do
   not contain its credential; exactly the encoder's request (the one
   permitted effect); a status or refusal code; or guest bytes that are a fixed
   refusal or a `guest_response` release in which the raw credential does not
   occur. No issued surrogate shows its credential in its header, public
   payload or claims (`issued_secret`); it leaves the broker only as the
   plaintext of the AEAD `seal` primitive.

Also proved, outside the summary statement: **informational claims have no
influence** — two tokens sealed over the same claims by the same entry verify
to the same claims, key and key issuer, whatever their `scope` and `upstream`
(`informational_no_influence`); **key retirement** — under a
configured key set a token opens only if its header `kid` names an entry of
that set (`kid_configured`, `retired_never_opens`); and **replica
equivalence** — `decide_request` (`replicas_decide_alike`) and `renew` take no
replica state, so replicas with the same configuration decide alike.

## Statelessness and acquisition (`GarrettStatelessProxy`, `GarrettStatelessStrict`)

**A pure request decision.** `stateless_proxy::decide(opener, request, routes,
acceptance, peer, now)` is the Rust function every request is decided by; it
returns `Unauthorized`, `Refused` or `Dispatch(route, bytes, opened)` and
performs no effect. Its inputs are the keys (through the `KeySet` opener),
the authenticated peer, the request carrying the surrogate, the clock and the
static routes and acceptance policy; it has no other input, so no
history-dependent acceptance is possible. `serve` calls it first and only
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
because those adapter answers differ, for instance because their upstream
exchanges failed differently. Equal decisions are proved; equal network
outcomes are not, and cannot be.

**The strict profile.** The profile's one piece of mutable process state is the
broker's login mailbox, which only the OAuth acquisition adapter uses. The
shell builds the mailbox's `LoginPolicy` from the OAuth providers only, and a
`"stateless": "strict"` broker configuration refuses every OAuth provider.
`no_providers_no_state`: when the login policy names no provider, every
reachable mailbox is the empty one and the login history has no event,
whatever agents and browsers send. `strict_no_login_state` lifts this to
every reachable world of the whole protocol model. The proxy has no mutable
state in the model at all. The other half of the strict profile — no audit
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
| `aead : ∀ S V, Paired S V → AeadInverse inst S V` | AES-256-GCM `seal`/`open` (`ring`) | correctness: what a key seals, its pair opens under the same nonce and AAD; the ciphertext is the plaintext and a 16-byte tag |
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
cd proofs && lake exe cache get
lake build GarrettStatelessProtocol GarrettStatelessWitness GarrettStatelessState GarrettStatelessStrict   # focused
python dev/verification/garrett.py mutate --mutation-filter '^stateless '            # Rust mutants
python dev/verification/stateless_shell.py check                                    # shell guard
```

## Theorem-to-Rust coverage map

| Lean module | Theorems | Extracted Rust (`aivm-secrets-garrett-core/src/`) |
| --- | --- | --- |
| `GarrettStatelessCodec` | `from_b64url_sound`, `from_b64url_complete` (strict url-b64: exactly the canonical encoding), `natural_some`/`natural_of` (canonical decimals ≤ 2^53−1), `plain_string_some`/`_of`, `word_some`/`_of`/`_absent`, `payload_bytes_ok` | `stateless_token.rs`: `from_b64url`, `group`, `symbol_value`, `natural`, `digits`, `plain_string`, `word`, `append*`, `payload_bytes` |
| `GarrettStatelessGrammar` | exact Boolean characterizations `is_text_eq`, `is_provider_eq`, `is_kid_eq`, `is_id_eq`, `is_thumbprint_true`, `is_scope_true`, `is_verifier_eq`; `payload_valid_true`, `state_valid_true`; `select_spec`, `keys_valid_true`, `select_unique` (key selection is unambiguous); `header_bytes_ok`, `header_kid_spec`, `header_kid_of`; `segments_spec`; `occurs_spec`; `b64url_spec` | `is_*`, `payload_valid`, `state_valid`, `select`, `named`, `keys_valid`, `entry_valid`, `header_bytes`, `header_kid`, `ascii`, `dot_from`, `segments`, `occurs`, `b64url` |
| `GarrettStatelessToken` | `parse_payload_sound` (accepted bytes are exactly the canonical payload, which is valid), `parse_payload_complete`; `verify_token_ok`, `verify_token_sound` (the exact signed header and payload are what authorization uses; the AAD is exactly label, header, zero, public payload); `unseal_token_ok` (decryption uses the entry the verified `kid` selected); `seal_token_ok` (credential absent from header and public payload; exact AAD; signature over exactly the first two segments); `b64url_fits` | `parse_payload`, `field`, `number`, `verify_token`, `unseal_token`, `seal_token`, `associated`, `copy_claims`, `copy_info` |
| `GarrettStatelessState` | `state_bytes_ok`, `parse_state_sound`, `parse_state_complete`, `seal_state_ok`, `open_state_ok`, `seal_open_state` | `state_bytes`, `parse_state`, `seal_state`, `open_state` |
| `GarrettStatelessRoundTrip` | `seal_then_open` | `seal_token`, `verify_token`, `unseal_token` |
| `GarrettStatelessMailbox` | `reachable_inv`; `slot_from_start`, `accepted_matches_start`, `at_most_once`, `issued_for_starting_peer`, `delivered_to_starting_peer`, `failed_never_delivered`, `delivered_is_gone` | `stateless_mailbox.rs`: `start`, `pending`, `accept`, `exchange`, `finish`, `poll` and their loops |
| `GarrettStatelessConnection` | `connection_runs`, `step_logged`, `connection_logged`, `seg_sent`, `connection_egress_authorized`, `connection_sends_once_per_request`, `connection_guest_bytes` | `stateless_proxy.rs`: `connection`, `connection_step`, `serve` |
| `GarrettStatelessProtocol` | `accepts_sealed`, `informational_no_influence`, `opened_issued`, `lineage`, `login_root`, `send_origin`, `send_root`, `rejection_never_sends`, `kid_configured`, `retired_never_opens`, `issued_secret`, `log_permitted`, `delivered_to_initiator`, `login_once`, `failed_login_quiet`, `prefix_logged`, `connection_prefix`, **`protocol_safety`** | all of the above, composed |
| `GarrettStatelessWitness` | `issue_then_open`, `issued_codec`, `issued_opens_only_for_its_certificate` | `stateless::issue`, `stateless::open`, the `KeySet`/`TokenSealer` instances |
| `GarrettStatelessStrict` | `no_providers_no_state`, `strict_no_login_state` | `stateless_mailbox.rs` (all transitions), `stateless_login::begin` |

The earlier theorems remain and are reused:

| Property | Theorem | Extracted Rust |
| --- | --- | --- |
| Admission is exactly the specification | `admit_spec`, `admit_ok_iff` (`Admitted`) | `stateless::admit` |
| Binding (opened ⇒ bound to this peer; one token, one peer) | `open_binds_peer`, `open_one_peer` | `stateless::open` |
| Authentication before decryption | `open_unadmitted_never_unseals`, `open_unverified`, `open_ok_trace` | `stateless::open` |
| Issuance | `issue_trace` (`IssuedFor`), `issue_window_spec`, `claims_for_trace`, `issue_invalid_never_seals` | `stateless::issue`, `claims_for`, `issue_window` |
| One renewal | `renew_trace` | `stateless::renew`, `renewal_grant` |
| Login binding | `begin_spec`, `begin_trace`, `accept_callback_trace`, `complete_trace`, `deliver_trace`, `deliver_other_peer` | `stateless_login.rs` |
| `serve` acts on the pure decision | `serve_follows_decision`, `dispatch_trace`, `serve_dispatch_exact`, `serve_rejected_never_sends`, `serve_guest_reply`, `serve_outcome`, `replicas_decide_alike`, `replicas_differ_only_by_answers` | `stateless_proxy::decide`, `stateless_proxy::serve` |

## Section 5 audit: endpoints and privileged paths

Each public endpoint makes its decision in extracted code; the shell does I/O.
`dev/verification/stateless_shell.py` (tested by
`tests/test_garrett_stateless_shell.py`) pins the shell side: one provider
write, of `egress_wire` of a core-made `Egress`, only from `Origin::exchange`
and never retried; every proxied and every broker agent decision uses the
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
| proxy (agent mTLS) | `stateless_proxy::connection` | exactly one `sent` per admitted request | **attempted vs completed**: `sent` is the hand-off to `Origin::exchange`; `completed` records a provider answer; a native write or read failure is `OutcomeUnknown` and is never retried |
| key rotation, retirement, export | `KeySet::new` (`keys_valid_true`) | a valid set: 1–8 entries, unique `kid`s | an invalid set is refused; retirement removes a `kid` from proxies (`retired_never_opens`) |

## Implementation linkage: mutation evidence

`garrett.py mutate --mutation-filter '^stateless '` applies each defect to the
**Rust source**, re-extracts with Charon/Aeneas, and recompiles the proof
import closure against the mutant. Each must break a proof.

| Mutant (Rust) | Rejected by |
| --- | --- |
| certificate binding removed; expired token accepted; audience not checked; verifying key issuer not checked; decrypted before admission; issuance binds the wrong certificate; renewal extends `ren` | `GarrettStateless` |
| login binds a request value instead of the peer; callback state not checked; delivered to any peer | `GarrettStatelessLogin` |
| mailbox: duplicate login accepted; serial reused; capacity not enforced; exchange answer reaches another login; finish ignores the stage; poll ignores the peer | `GarrettStatelessMailbox` |
| proxy: wrong provider destination; egress without acknowledged admission; surrogate forwarded instead of credential; credential reflection unchecked; dispatches despite an encoder refusal | `GarrettStatelessProxy` (within the `GarrettStatelessConnection` closure) |
| login started for an unconfigured provider | `GarrettStatelessStrict` (rejected first by `GarrettStatelessLogin`, in its closure) |
| proxy connection decides for the authority, not the peer | `GarrettStatelessConnection` |
| token: `kid` not used to select the key; duplicate `kid` accepted in a key set; header prefix not checked; provider grammar not checked | `GarrettStatelessGrammar` |
| token: non-canonical base64 accepted | `GarrettStatelessCodec` |
| token: associated data omits the header; payload with trailing bytes accepted; signature checked over the payload only; decrypted with the first key; credential allowed in the public payload | `GarrettStatelessToken` |
| login state: label not bound | `GarrettStatelessState` |

**Result, 2026-10-27: all 34 stateless mutants are rejected** against the
tree of the composable-isolation increment, each by a real error in the
recompiled closure, not a cached object. The 2026-10-26 run rejected the
first 32. The strict-profile mutant is caught by the existing login proof
before `GarrettStatelessStrict` is reached, so the run does not show that the
strict theorem alone would catch it.

## What remains trusted

The assumption ledger entries are `STATELESS-NATIVE-01`, `STATELESS-CRYPTO-01`,
`STATELESS-TLS-01`, `STATELESS-OAUTH-01`, `STATELESS-DEPLOY-01`,
`STATELESS-CLAIMS-01` and `STATELESS-PY-01`
([ledger](planning/aivm-secrets-assumptions.json)). In short:

- **Primitives.** Ed25519 and AES-256-GCM (`ring`) satisfy the three boundary
  propositions above; no computational proof is claimed, and `Unforged` is
  the idealized form of EUF-CMA (the guarantees hold for executions without a
  forgery). `StateAeadInverse` is used only by the positive login-state
  round trip; login safety does not depend on it, because the mailbox accepts
  only a callback that matches its own pending entry.
- **Native shells.** The shell must do what `stateless_shell.py` checks: pass
  the handshake peer, write exactly `egress_wire` to the route's pinned
  address over verified TLS, and write only `served.reply` to the guest. That
  the native `exchange` writes exactly its argument to that socket, and that
  a provider-side effect follows, are not proved.
- **TLS and X.509.** The peer thumbprint must be that of the certificate the
  TLS stack verified; CRLs are not consulted.
- **Rust ownership.** `Permit`, `Exchanged` and `Egress` have private fields
  and are moved into the call that consumes them, so a permit is exchanged at
  most once and an egress is sent at most once. The mailbox model's `exchange`
  step takes this as its `held`/`unspent` premises; rustc, not Lean, checks it.
- **Toolchain.** Charon/Aeneas translation, their standard library models,
  the Lean kernel and the Rust compiler are trusted.
- **Responses.** Only the raw credential (and, through `guest_response`, its
  unfolded reflection forms) is excluded from replies; providers that echo
  transformed credentials, and timing, are not covered.
- **Python.** `aivm_secrets.garrett_stateless` mirrors the Rust and is tested
  against the same vectors and the interop matrix; it is not proved.

## Claim categories

| Category | Items |
| --- | --- |
| Implemented and tested | Python and Rust libraries; OAuth login with PKCE against a synthetic HTTPS provider; JWT and opaque tokens; substitution through the stateless proxy; refusals; renewal; key rotation and retirement; 4-way interop; container demo; swtpm-backed agent key |
| Implementation-linked formally proved | the theorems above, about the extracted Rust, including `protocol_safety` |
| Proved only in a symbolic model | credential non-derivability (`GarrettSecrecy.lean`) |
| Assumed from an external interface | Ed25519, AES-GCM, rustls/webpki/OpenSSL, OS sockets and clock, randomness, the provider's OAuth behaviour |
| Checked by a source guard only | the shell's privileged call sites (`stateless_shell.py`) |
| Not established | live identity providers and APIs; hardware TPM provenance; whole-process I/O refinement of the shells; computational cryptography; independent review |
