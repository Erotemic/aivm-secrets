# One execution of `garrett-stateless-v1`

This walks through one surrogate's life, start to finish. Each step names
the Rust function that decides it, all in
[`crates/garrett-stateless-core/src/`](crates/garrett-stateless-core/src), and
the theorem that proves it. The theorems are about the Aeneas extraction of
that same Rust; [`proofs/Garrett.lean`](proofs/Garrett.lean) collects the
guarantees. The normative wire format is
[`docs/garrett-stateless-v1.md`](docs/garrett-stateless-v1.md). What is
trusted rather than proved is in
[`docs/assumptions.json`](docs/assumptions.json), and the
[closing section](#what-this-does-not-show) summarizes it.

## The four parties

| Party | Holds | Never holds |
| --- | --- | --- |
| **agent** (untrusted) | a client certificate and key; surrogates | a provider credential |
| **broker** | the signing and sealing keys; the transient login mailbox | the agent's private key |
| **proxy** (any number of replicas) | the verification and opening keys; static routes and policy | any per-agent or per-token state |
| **provider** | the real API and its OAuth server | — |

A **surrogate** is a signed token (Ed25519 over a JSON header and payload)
whose payload carries the provider credential AES-256-GCM-encrypted (`enc`)
and the SHA-256 thumbprint of the agent's certificate (`cnf`). The code
names the agent's side of the proxy "guest".

## 1. Getting a credential to the broker

Two acquisition adapters feed issuance, and issuance does not know which one
ran (spec section 7.1).

* **Operator mint.** The operator supplies a credential and the agent's
  certificate; the shell calls `stateless::issue` directly
  (`broker.rs: mint_with`).
* **OAuth login** (spec section 8), through the broker's one piece of
  mutable state, the mailbox (`stateless_mailbox.rs`):

  | Step | Rust | What it fixes |
  | --- | --- | --- |
  | agent starts a login over mTLS | `start` (→ `stateless_login::begin`) | the slot is bound to the starting certificate |
  | the human opens the authorization page | `pending` | read-only |
  | the provider redirects back | `accept` (→ `accept_callback`) | the sealed state must match this login; at most once |
  | the broker exchanges the code | `exchange` | the exchange `Permit` is moved, so it happens at most once |
  | the broker issues | `finish` (→ `complete` → `stateless::issue`) | the surrogate is for the starting certificate |
  | the agent collects it | `poll` (→ `deliver`) | only for the starting certificate, and only once |

  Proved: `delivered_to_initiator`, `login_once`, `failed_login_quiet`
  (`GarrettStatelessProtocol`), named `DeliveredToInitiator` and
  `LoginsAtMostOnce` in `Garrett.lean`. A **strict** broker configures no
  OAuth provider, and then holds no login state at all
  (`strict_no_login_state`).

## 2. Issuance

`stateless::issue(sealer, policy, grant, credential, token_id, now, lifetime)`:

1. refuse a credential outside the token grammar (`http_auth::valid_credential`);
2. compute the claims (`claims_for`: issuer, audience, subject, `jti`,
   provider, `cnf`, and the window `iat`/`exp`/`ren`, capped by every
   policy and expiry, `issue_window`);
3. seal: `TokenSealer::seal` → `stateless_token::seal_token`, which encodes the
   header and canonical payload, encrypts the credential with associated
   data binding it to that header and payload, and signs the first two
   segments.

`seal` consumes the `TokenSealer`, which carries the one fresh nonce for this
seal; the application draws it at random (`token::sealer`). Nothing is sealed
if any check fails (`issue_invalid_never_seals`).

Proved: `issue_trace`; `seal_token_ok` (the credential occurs in neither the
header nor the public payload; the associated data is exact; the signature
covers exactly the first two segments); `issued_secret` and
`ClaimsHideCredential`.

## 3. A request through the proxy

The agent sends an ordinary HTTP request to the proxy over mTLS, with the
surrogate as its bearer token. The native shell (`garrett-stateless`'s
`proxy.rs`) completes the TLS handshake and hands the connection to the core
loop `stateless_proxy::connection` with the **handshake's** peer thumbprint.
The loop frames requests (`proxy_controller::frame`) and calls `serve` on
each; `serve` first calls the pure decision `decide`, the centre of the
protocol:

```rust
pub fn decide(opener, policy, request, routes, acceptance, peer, now) -> Decision {
    let token = surrogate_of(&request.fields)?;              // exactly one surrogate, or Unauthorized
    let verified = stateless::authenticate(opener, &token,   // verify the signature and header,
                                           acceptance, peer, now)?;  // then admit the claims for THIS peer
    let index = route_of(routes, &verified.claims.provider); // the route of the signed provider,
                                                             // never a request value
    if !policy.permits(&verified.claims, &operation_of(request)) {
        return Decision::Refused(Code::Denied);              // refused before any decryption
    }
    let opened = stateless::decrypt(opener, verified)?;      // only now unseal the credential
    encode_upstream(&mut wire, request, &route.host, &route.rules,
                    &opened.credential, &route.authentication)?;  // the exact upstream bytes
    Decision::Dispatch(Dispatch { route: index, wire, opened })
}
```

(Simplified: the real function matches every `Result` explicitly, which keeps
the extracted model's control flow small.) Each line is a separately proved
component:

| Step | Rust | Contract |
| --- | --- | --- |
| identity | `stateless::authenticate` = `verify_token`, then `admit` | `authenticate_contract`, `authenticate_ok_trace`, `admit_spec` (`Admitted`: issuer, audience, provider, lifetime, clock, and `cnf` = peer) |
| provider selection | `route_of` | `route_of_loop_contract` |
| authorization | any `OperationPolicy`: `Unrestricted` (Garrett's proxy) or `ReadOnly` | `Sound`; `unrestricted_sound`, `read_only_sound` |
| credential release | `stateless::decrypt` = `unseal_token`, then `valid_credential` | `decrypt_contract`, `decrypt_ok_trace`, `unseal_token_ok` |
| exact encoding | `proxy_http::encode_upstream` | `encode_upstream_contract` (exactly `ExactWire` when it fits in memory: the agent's request with every credential-bearing or framing field removed, and one authentication header carrying the credential) |
| egress | `serve`, with any `Origin` adapter | `serve_follows_decision`: the admission record is acknowledged, then exactly one `Origin::exchange` of exactly those bytes |

`composed_egress` composes them, once, for any operation policy:
every run of `serve` is `NoDispatch` (nothing sent; a fixed refusal) or one
dispatch that is `AuthenticatedSurrogate`, `AuthorizedOperation`,
`ProviderRouteMatches`, `ExactUpstreamRequest` and `Dispatched`
(`AuthorizedEgress`). `garrett_egress` and `read_only_egress` instantiate it.
The policy never sees the credential, and a refused operation is never
decrypted (`decide_unpermitted`).

Credential-bearing egress is closed in the types: the bytes reach the shell
only inside an `Egress`, which only `serve` can build and only
`Origin::exchange` consumes.

## 4. The response

The provider's answer comes back through `Origin::exchange`;
`proxy_controller::release` re-frames it with `proxy_http::guest_response`,
which drops hop-by-hop fields and `Set-Cookie` and **refuses** (`502`) a
response in which the credential occurs in any of the checked encodings
(`reflection_forms`: raw, JSON-escaped, percent-encoded, hex, and standard and URL-safe base64 at each alignment). Every record the
proxy produces has one of a few permitted forms (`log_permitted`,
`RecordsPermitted`); this restricts each output's form and is not a general
information-flow result.

Over a whole execution: every provider send has an authorized,
issued-surrogate origin bound to the connection's own peer
(`send_origin`, `SendsAreAuthorized`), and a refused request sends nothing,
with at most one send per request (`rejection_never_sends`,
`RefusalsSendNothing`).

## 5. Renewal

The agent presents its surrogate to the broker over mTLS.
`stateless::renew` = `open` (that is, `authenticate` then `decrypt`, for the
renewing peer) → `renewal_grant` (the same provider, subject and binding,
with the old `ren` as the credential's expiry) → `issue` with a fresh sealer.
A renewal can neither extend the absolute limit `ren` nor change the binding,
provider or credential, however many times it is applied (`lineage`,
`RenewalPreservesLineage`).

## 6. Many replicas

`decide` reads no state but its arguments, so replicas with the same keys
and configuration decide alike (`replicas_decide_alike`). Their replies can
differ only through what their adapters answered, the admission
acknowledgement, the provider's answer and the completion acknowledgement
(`replica_replies_differ`).

## What this does not show

* **Trusted primitives**: Ed25519 and AES-256-GCM correctness, Ed25519
  unforgeability, and **nonce uniqueness**, which the application ensures by
  drawing each nonce at random and sealing once per sealer
  (`STATELESS-CRYPTO-01`).
* **TLS and the shells**: that the handshake's peer thumbprint is the one
  passed to the core, and that the native shells call the core as
  `verification/shell_guard.py` checks; this is a source guard, not a proof
  (`STATELESS-NATIVE-01`, `STATELESS-TLS-01`).
* **Not established**: whole-process I/O refinement, computational security,
  noninterference, and compatibility with any real provider.

[`docs/verification.md`](docs/verification.md) has the full theorem map, the
premises and the mutation evidence: Rust defects that the proofs reject.
