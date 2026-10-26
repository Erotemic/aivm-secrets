# `garrett-stateless-v1`: what the Lean proofs establish

**Scope.** These are implementation-linked theorems about the Rust controllers
that the `garrett-stateless` broker and proxy run. The controllers live in
`rust/crates/aivm-secrets-garrett-core/src/stateless{,_login,_proxy}.rs`. Aeneas
extracts them into `proofs/generated/AivmSecretsGarrettCore.lean`, and the
theorems are in `proofs/GarrettStateless{,Login,Proxy}.lean`. This is
experimental, unaudited work. It is not a proof of the whole service, of the
cryptography, or of TLS. The specification is
[`garrett-stateless-v1.md`](garrett-stateless-v1.md).

Every theorem quantifies over **arbitrary** adapters: opener and sealer
(signature and AEAD), origin (sockets and diagnostics), and the mailbox. So
each one says exactly what the extracted decision code guarantees, given only
the adapter facts it names.

## Build and check

```bash
cd proofs && lake exe cache get
lake build GarrettStateless GarrettStatelessLogin GarrettStatelessProxy   # focused
python dev/verification/garrett.py mutate --mutation-filter '^stateless '  # 14 Rust mutants
```

## Theorem map

| Property (assignment wording) | Theorem | Extracted Rust function |
| --- | --- | --- |
| Admission is exactly the specification | `admit_spec`, `admit_ok_iff` (`Admitted`) | `stateless::admit` |
| **Binding correctness** (an opened surrogate is bound to this peer; one token opens for one peer) | `open_binds_peer`, `open_one_peer` | `stateless::open` |
| **Binding correctness, end to end** (issued for C, refused for D ≠ C) | `issued_only_opens_for_its_certificate`, `issued_refused_on_other_certificate` | `stateless::issue`, `stateless::open` |
| **Authentication before decryption** | `open_unadmitted_never_unseals` (result independent of `unseal`), `open_unverified`, `open_ok_trace` (unseal called on the verified envelope only after admission) | `stateless::open` |
| What an opened surrogate is | `open_contract` | `stateless::open` |
| **Issuance correctness** | `issue_trace` (`IssuedFor`), `issue_window_spec` (`WindowSpec`), `claims_for_trace`, `issue_invalid_never_seals` | `stateless::issue`, `claims_for`, `issue_window` |
| Stateless renewal never extends `ren`, keeps binding and credential | `renew_trace` | `stateless::renew`, `renewal_grant` |
| **OAuth binding**: a login belongs to its starting peer | `begin_spec`, `begin_trace` | `stateless_login::begin` |
| **OAuth binding**: callback acceptance (same login, peer, provider, window, replica; pending; RFC 9207 rule; denial) | `accept_callback_trace` (through the existing `oauth_login.Proofs.claim_contract`) | `stateless_login::accept_callback`, `oauth_login::claim` |
| **OAuth binding**: completion issues for the entry's certificate only | `complete_trace` | `stateless_login::complete` |
| **OAuth binding**: only the starting peer collects | `deliver_trace`, `deliver_other_peer` | `stateless_login::deliver` |
| **OAuth binding, end to end** | `login_surrogate_bound_to_starting_peer` (premise `StageOnly`: the mailbox changes only the stage) | all of the above |
| `serve` acts only on its pre-egress decision | `serve_follows_decision` (`decide_request`, `Dispatched`) | `stateless_proxy::serve` |
| **Provider-use authorization** | `dispatch_trace`: one surrogate, opened for this peer, route in range and serving the token's provider, encoder accepted | `serve`, `surrogate_of`, `route_of`, `stateless::open`, `proxy_http::encode_upstream` |
| **Credential substitution correctness** (exact bytes at the exchange boundary) | `serve_dispatch_exact`: `exchange` receives `UpstreamPrefix ++ HeaderPrefix ++ credential ++ CRLF ++ UpstreamSuffix` for the route's host and scheme, with the credential `unseal` returned for the admitted envelope, after an acknowledged admission | `serve`, `encode_upstream` (`encode_upstream_contract`) |
| **No dispatch on rejection / failure safety** | `serve_rejected_never_sends`: a missing, duplicate, malformed, forged, expired, wrong-certificate, wrong-audience, unknown-provider or undecryptable surrogate, no route, or an encoder refusal never reaches `admitted` or `exchange` | `serve` |
| **Credential confinement in replies** | `serve_guest_reply`: the reply is the fixed `401` (a closed term), a fixed refusal, or a `guest_response` release in which the raw substituted credential does not occur | `serve`, `proxy_controller::release`, `proxy_http::guest_response` |
| **Stateless replica equivalence** | `replicas_decide_alike`: two origin adapters of any types, in any states, follow the same `decide_request` decision for the same opener, request, routes, acceptance, peer and clock, and refuse with identical replies | `serve` |
| Route selection | `route_of_loop_contract` | `stateless_proxy::route_of` |

**Replica equivalence, precisely.** `decide_request` is not a new model. It is
the literal prefix of `serve`, composed from extracted functions.
`serve_follows_decision` proves that `serve` acts on it. Its parameters contain
no origin or adapter state, so what a proxy decides depends only on the key-set
adapter, the request, the configuration, the authenticated peer and the clock.
Determinism of a pure function would be trivial. The content here is that no
mutable adapter state is an input. The A/B/C restart tests and the four-way
interoperability matrix check the same property at runtime.

## Implementation linkage: mutation evidence

`garrett.py mutate --mutation-filter '^stateless '` applies 14 defects to the
**Rust source**, re-extracts with Charon/Aeneas, and recompiles the whole proof
import closure against each mutant. Each mutant must break a proof:

| Mutant (Rust) | Assignment item |
| --- | --- |
| certificate binding removed (`admit`) | removing certificate binding |
| expired token accepted (`>=` → `>`) | accepting an expired token |
| verifying key issuer not checked | signature/issuer confusion (signature verification itself is the adapter) |
| decrypted before admission (unseal moved before admit) | decrypting before authentication |
| audience not checked | accepting a surrogate without the expected audience |
| issuance binds the wrong certificate | changing the client identity used during issuance |
| renewal extends `ren` | renewal widening |
| login binds a request value instead of the peer | changing the client identity used during issuance |
| login callback state not checked | bypassing OAuth state validation |
| login delivered to any peer | delivery to an unrelated client |
| proxy wrong provider destination | substituting the wrong provider destination |
| proxy egress without acknowledged admission | treating a rejected request as an authorized send |
| proxy surrogate forwarded instead of credential | credential substitution |
| proxy credential reflection unchecked | emitting the real credential to the client |

**Result, 2026-10-26: all 14 mutants rejected.** Seven were rejected by
`GarrettStateless`, three by `GarrettStatelessLogin` and four by
`GarrettStatelessProxy`. Each was a real error in the recompiled proof
closure, not a cached object. The opt-in axiom audit of the same tree found
1,497 theorems depending only on `propext`, `Classical.choice` and
`Quot.sound` ([axiom-audit.md](assurance/axiom-audit.md)).

## What remains trusted

The assumption ledger entries are `STATELESS-NATIVE-01`, `STATELESS-CRYPTO-01`,
`STATELESS-TLS-01`, `STATELESS-OAUTH-01`, `STATELESS-DEPLOY-01`,
`STATELESS-CLAIMS-01` and `STATELESS-PY-01`
([ledger](planning/aivm-secrets-assumptions.json)). In short:

- **Cryptography and codec.** Ed25519 verification, AES-256-GCM and the
  strict JSON/b64url codec (`ring`; Python `cryptography`) are adapters.
  `issued_only_opens_for_its_certificate` takes the premise that a verified
  issued token decodes to the claims sealed into it. No computational proof is
  claimed. The existing symbolic model `GarrettSecrecy.lean`
  (`provider_credential_not_derivable`) states the corresponding Dolev-Yao
  argument for credentials carried only under keys the attacker lacks. It is
  a symbolic result, not a proof about this code.
- **TLS and X.509.** The peer thumbprint must come from the certificate the
  TLS stack verified. CRLs are not checked.
- **Native shells.** The proxy must call `serve` for every request with the
  handshake peer and send `exchange`'s argument only to the route's pinned
  address. The broker must change mailbox entries only by stage.
- **Event distinctions.** A controller returning a dispatch, an `exchange`
  call, bytes written to the upstream TLS writer, a completed provider
  request, a provider-side effect, and a reply released to the client are
  different events. The theorems cover the decision, the arguments of the
  `exchange` callback, and the reply bytes `serve` returns. That the native
  `exchange` writes exactly those bytes to that socket is the adapter
  contract. Delivery and provider-side effects are not covered.
- **Responses.** Only the raw credential (and, through `guest_response`, the
  unfolded reflection forms) is excluded from replies. A provider that
  transforms or derives from the credential in other ways is not covered,
  and nothing is claimed about timing or other response content.
- **Python.** `aivm_secrets.garrett_stateless` mirrors the controllers and is
  tested against the same vectors and in the interop matrix. It is not
  proved.

## Claim categories

| Category | Items |
| --- | --- |
| Implemented and tested | Python and Rust libraries; full OAuth login with PKCE against a synthetic HTTPS provider; JWT and opaque tokens; substitution through the stateless proxy; refusals; renewal; key rotation and retirement; 4-way interop; container demo; swtpm-backed agent key |
| Implementation-linked formally proved | The theorems above, about the extracted Rust controllers |
| Proved only in a symbolic model | Credential non-derivability (`GarrettSecrecy.lean`, existing model) |
| Assumed from an external adapter | Ed25519, AES-GCM, rustls/webpki/OpenSSL, the strict codec, OS sockets, the provider's OAuth behaviour |
| Validated only in a particular environment | swtpm (not hardware provenance); single-host loopback; the container demo |
| Not established | Live identity providers and provider APIs; hardware TPM provenance and relay resistance; whole-process I/O refinement of the stateless shells; computational cryptography; independent review |
