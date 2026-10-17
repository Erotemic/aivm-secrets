# W0: conditional credential-confinement security contract

Status: **W0 specification baseline for review**, 2026-10-17, source `28e466d`.
This is a **target and threat model, not a proved theorem, audited call graph,
or a claim that any deployment satisfies the assumptions**. The versioned
[machine-readable boundary inventory](aivm-secrets-w0-boundaries.json) is the
companion source for sink, release, profile, and assumption identifiers. A
[consistency checker](../../dev/verification/w0_contract.py) checks references
and classification; it does **not** discover all I/O paths. W3/W6 must inspect
the transitive Rust call graph and amend this inventory if it is incomplete.

This contract is the starting point for [W1-W8](aivm-secrets-active-work.md),
not an alternative roadmap. The [assumption ledger](aivm-secrets-assumptions.json)
is authoritative for what remains trusted. The
[existing extracted-controller guarantees](../verified-composition.md) and
[typed filter guarantees](../verified-disclosure.md) are useful narrower facts.

## Scope, principals, and explicit non-goals

The **initial native theorem target** is one foreground `garrett-bridge`
instance configured with a *native* `manifest-https-v1` provider session, its
Rust mTLS guest endpoint, and its transitive request, describe, renounce,
authority-lease, audit, and provider-execution paths, plus host-side
startup/token-source configuration. OAuth refresh is a separate host-initiated
lifecycle effect.
The actor issuing frames may be fully malicious. The broker executable and
selected policy, disclosure document, provider origin, CA, identity registry,
vault, clock source, and operator configuration are host-controlled.

The exact gateway in `rust/crates/aivm-secrets-garrett/src/tls.rs` accepts
`request`, `describe`, and `renounce`; it explicitly refuses `delegate`.
`manifest-https-v1` is implemented in `custody/manifest_session.rs`. It may
perform a **credential-bearing preflight** and a final provider call for one
authorized guest operation. In certain policies there is no final call; a
preflight-derived value can be returned after revalidation. An OAuth-backed
session may refresh its access token during **host startup** in
`OAuthVault::session_snapshot`; the guest-request path calls
`OAuthSource::active` to **check the lease**, not refresh it. W3 must confirm
this remains true across future source changes. Successful
replies include a host-reviewed projection and potentially pagination
metadata. The current native manifest profile requires an explicit
`request_limit: "unbounded"` override: **do not assume that the Python broker's
request budgets or one-shot write approvals apply to this native profile**.

Three adjacent paths are inventoried but **not included** in the initial native
manifest theorem:

- Native `account-status-v1`: a fixed-operation provider session using
  `credential_use.rs`/`protocol.rs`. Existing extracted guarantees apply to
  its controller; the complete service and I/O are still unverified.
- Legacy `tls::Bridge::forward`: sends an unwrapped **inner capability** to a
  separate local Python broker via a host Unix socket. This is a different
  trusted-executor boundary, **not** a native Rust provider flow and not a
  permitted fallback for the native theorem.
- `garrett-authority`, OAuth login/administration, bootstrap, TPM issuance,
  and Rust development conformance binaries: host-operator or tooling
  workflows with their **own** I/O, subject to an explicit premise that they
  are not guest-reachable. An administrator is not the untrusted guest.

The Python standalone scenario W1 has its own policy/approval/budget semantics;
passing W1 does not prove Rust parity. No VM manager or firewall is needed to
state or prove the conditional Rust-source theorem. A deployed AIVM VM or
container may later *supply evidence* for the host/guest separation premise;
it does not discharge that premise by being called a VM or container.

## Data classification and authority

| Class | Examples | Guest access and permitted release |
| --- | --- | --- |
| `provider_credential` | Bearer/API key, access token | **Never** directly to guest, host diagnostic or audit. May be used in the approved auth header of an exact host-selected HTTPS provider effect. |
| `refresh_credential` | Refresh tokens, OAuth client authentication material | **Never** to guest. Only approved OAuth token endpoint as required by the registered provider contract; host vault storage remains private. |
| `host_keys` | Inner-envelope key, private signing keys, TLS server key, vault encryption key | No guest disclosure. Protected host storage and in-process use under environmental/crypto premises. |
| `inner_capability` | Opened inner capability forwarded to Python | Not guest-visible. Its transfer to the trusted *host-local legacy broker* is out of the native theorem. |
| `operator_configuration` | Vault, policy, disclosure rules, audit path, registry | Host integrity mandatory. Some names, operation descriptions, identifiers and digests are intentionally public; secrets, file bytes and privilege to modify them are not. |
| `guest_capability` | Authenticated outer signed surrogate | Intentionally delivered to the selected guest during host provisioning; stealing it does not authorize an unrelated mTLS peer under the peer-binding premise. Not interchangeable with provider credentials. |
| `provider_response` | Raw provider JSON, preflight facts, error body | Untrusted/possibly sensitive. Only reviewed schema-selected values, checked metadata and fixed response forms may become guest-visible. A provider-controlled approved string is **not automatically safe**. |
| `public_metadata` | Allowed operations, approved result keys, documented error code, success/denial, certain counters and expiry | Guest-visible only when declared by release rule; status/length/order may still reveal private facts. |

The effective authority is determined by **host policy plus authenticated
identity, current grant, time and mode at the point of dispatch**. A token
valid for an operation does not grant authority to select a different host,
port, CA, path, method, header, body, provider account or disclosure schema.
Exact approved effects may include provider-visible user-controlled values,
but those values must pass the operation's declared argument constraints.
Do not treat a signed capability alone as proof of authorization.

## Channels, sinks and observations

We use `guest`, `provider-api`, `oauth-token`, `host-audit`, `host-diagnostic`,
`host-private-storage`, `host-control` and `legacy-broker` as **distinct
principals**. Only guest-readable channels participate in the primary
adversary's observations. The full machine inventory associates each sink
with source entry points, release rule, ledger premises, and a scope.

- **Guest reply**: TLS 1.3 application data emitted by `tls::Bridge::serve`
  and `answer`: typed success fields, described operations, renounce response,
  or fixed error structure. Frame status, *bytes and length*, event order,
  failures and connection closure are guest observations. A client program's
  saved files/stdout are treated as downstream copies of those replies.
- **Provider HTTPS**: credential-bearing preflight/final API requests, sent
  only to the policy's configured origin and endpoint using the approved
  header/method/path/body. Credential bytes may appear in this channel. TLS
  DNS-name validation, address pinning, no off-policy redirect/proxy, and
  correct serialization remain adapter obligations.
- **OAuth token HTTPS**: host-side startup refresh/grant-management may send refresh material
  to a **separate**, operator-selected OAuth endpoint. Its endpoint and
  outputs are not implicitly covered by permission for the API provider.
- **Host audit**: persisted dispatch, completion and renunciation records.
  Intended to include identity/policy/operation/route metadata, never bearer
  tokens or raw request bodies. Its exact fields and serialization need W6
  scrutiny. Audit durability and locks are not mathematical facts.
- **Host stdout, stderr and exit status**: bridge startup prints an
  *outer capability* and its expiry; stderr prints error codes on fatal paths.
  Neither output is silently ignored: they must remain host-only at
  deployment, and source-controlled messages must be checked for leakage.
- **Private storage and privileged control**: vault, keys, mutable grants,
  registry, policy files, operator CLI and authority channels. Their effects
  must be modeled, although they are not disclosed to the guest under the
  compartment assumption. **A host account shared with the agent would
  invalidate the isolation premise.**
- **Legacy broker forwarding**: a protected host-only Unix socket that may
  carry an inner capability. It is excluded from the initial native manifest
  theorem; using that configuration requires a separate guarantee for the
  Python broker and the host socket.

The primary observation function includes parsed reply content **and the
actual serialized guest-visible bytes**, rejection codes, frame length,
connection closure, message order and guest-visible resource-limit outcomes.
A proof over only parsed `PublicReply` values would be insufficient. Whether
observable outcomes match under different secrets is a *proof obligation*,
not an environmental premise. Explicit exclusions from the first theorem:
wall-clock and microarchitectural timing, cache/power/co-resident process
side channels, third-party observations of encrypted packet lengths, and
DoS/availability/fairness under unbounded adversarial load. Cryptographic
ciphertext indistinguishability is an assumption of the chosen crypto model,
not proved by the symbolic source controller. External HTTPS servers and
privileged host operators may see different information than the guest; their
views require distinct policies. The initial finite-trace theorem makes no
claim about information leaked by authorized remote providers after receipt.

## Transition system and adaptive adversary

Model a finite, possibly concurrent history. It contains events from these
separate sources:

```text
Guest(peer, bytes | disconnect)            # adversarial protocol frame/abort
Environment(tick | IOFailure | schedule)   # including arbitrarily delayed I/O
Provider(origin, status, headers, body)    # may return adversarial bytes
Operator(revoke | configure | stop)         # host-only trusted authority

Event = GuestReply(peer, serialized_bytes)
      | GuestClose(peer, close_reason)
      | ProviderDispatch(origin, method, path, headers, body, credential_ref)
      | OAuthDispatch(token_origin, auth_material_ref, request)
      | AuditAppend(redacted_record)
      | HostDiagnostic(stream, serialized_bytes)
      | HostStateWrite(target, bytes)
      | LegacyForward(socket, inner_capability_ref, frame)
      | AuthorityChange(approved_change)
```

`credential_ref` stands for a protected byte value, not an opaque label that
can be declassified at will. An *interpreter-refinement obligation* must
connect these effects to concrete socket writes and disk bytes. We do not
assume that the Rust executable emits only listed effects: proving or
checking that **complete mediation** is W3/W4/W6 work.

For every finite guest observation prefix `o`, the adversary's strategy
`A(o)` may choose its next frame, its target connection, an earlier capability
it possesses, or disconnect. It may replay, interleave connections, send
malformed/oversized data, try a different operation/resource/endpoint,
renounce its grant and act again, and adapt based on public errors or content.
The guest can observe its own outputs and alter subsequent requests, but
cannot choose the host's authenticated peer identity, signing material, policy,
vault contents, audit files or administrative instructions. The environment
may inject transport and filesystem failures, schedule worker threads and
supply provider responses; adversarial provider-controlled response values
are not treated as inherently public.

For the first relational theorem, compare executions using the **same public
scheduler and public host-operator commands**, or prove observational trace-set
equivalence over allowed schedules. Do not assume away secret-dependent
scheduling by simply treating it as a private input. Model concurrent grant
checking and the last admission check **after** blocking audit or preflight
at the actual linearization point; no claim that completed revocation undoes
a previously admitted remote effect. Provider failure after dispatch may
have applied a write and may yield `outcome_unknown`.

## Release rules and proposed proof statements

Rules in the JSON companion define permitted disclosures independently of
what the current implementation happens to output:

- `R-GUEST-RESULT`: fixed structural fields, *host-reviewed*, typed
  projection of the selected response and separately reviewed pagination
  metadata. Current `manifest.rs::pagination` constructs only `per_page`
  (host-declared size), `possibly_more` (whether provider array length equals
  that size), and optional validated request `page`. The `possibly_more` bit
  is a **deliberate data-dependent disclosure** that policy review must
  approve. No raw provider documents, raw HTTP bodies, credential material,
  inner capabilities or ad hoc exception messages. Selected provider fields
  require a **provider/data provenance contract**; a malicious endpoint could
  return an encoded credential in an otherwise approved field.
- `R-GUEST-CONTROL`: only documented `describe`/`renounce` fields with a current
  bound grant; `describe` reports profile, operation names, write mode and
  `request_limit: "unbounded"`; no credentialed provider dispatch.
- `R-GUEST-DENIAL`: bounded, predeclared error code and message; no raw parsing,
  TLS, OAuth, filesystem or provider error strings. The fixed error *format*
  is allowed, **not blanket declassification of whichever code the broker
  chooses**. Secret-dependent code selection and closure remain potential
  information-flow channels to prove independent, normalize, or separately
  authorize as deliberately disclosed bits.
- `R-GUEST-TRANSPORT`: connection close/no-reply behavior after both success
  and failure. The actual close/timeout/failure class and order are observed;
  they are not made safe merely by excluding exact wall-clock latency.
- `R-PROVIDER`: exact authorized request and selected credential only to its
  reviewed API origin; any credential-bearing preflight is an explicit effect.
- `R-OAUTH`: refresh/authentication material only to the configured token
  origin, independent from API egress permission.
- `R-AUDIT`, `R-HOST-DIAG`, `R-HOST-PERSIST`, `R-HOST-CONTROL`:
  separately reviewed host-only content and access conditions. Their sinks
  cannot be presumed guest-invisible without `ENV-GUEST-01` and
  `RUST-OPERATOR-01`. `R-LEGACY` is a separately reviewed integration path.

Proposed obligations (all **open** for whole-service Rust):

**SINK-01 — authorized effects.** For every prefix and each provider dispatch
with credential `k`, there exists contemporaneous admission evidence for
the authenticated peer, exact operation, policy/grant, approved origin, actual serialized method/path/headers/body and selected `k`. The
admission evidence applies at the dispatch linearization point, after
required successful audit acknowledgement. The native manifest profile
explicitly permits an unbounded session: this is **not** a claim that a
one-shot ticket is consumed or that Python request budgets apply. An OAuth
dispatch needs a **different** host-startup/administration,
OAuth-source/endpoint/lease witness; do not infer
it from API admission alone. Under the current native guest-request call
graph, only OAuth lease validation, not token refresh, is guest-triggered.
Denials before preflight have no credentialed provider effect. A failed
preflight may have emitted its *authorized* preflight but no later final effect.

**TRACE-01 — complete mediation.** Every concrete I/O effect reachable from
an untrusted client frame refines **exactly one** classified model effect, and
every model effect selects a release rule. There must be no bypassing writer,
unmodeled administrative call, unbounded diagnostic, unclassified error path
or hidden credential egress. This includes startup-time refresh when the scoped service lifecycle is
considered, guest-time lease checks, errors, audit,
termination, startup information *when visible to the guest*, and concurrent
execution. This does not follow from an enum declaration alone.

**NI-TRACE-01 — declassification-aware noninterference.** Define
`Low(s)` as the host-approved, genuinely public configuration and grants,
not the protected credentials. Let `D_P` be the **predeclared** release
function for approved operation results and selected public controls;
**do not define it as the observed output, all provider fields, or the chosen
error code**. Error shape may be public, but a denial *reason* derived from
protected state must be shown not to leak (or explicitly justified as a
separately reviewed, bounded declassification). With
identical public input/scheduler histories and the same `D_P` releases, a
pair of executions differing in protected credentials/vault state/unselected
provider data must produce equivalent guest-observation traces (including
error codes, lengths and close events). For an adaptive attacker, couple the
next request chosen from equal observation prefixes. This property permits
differences in reviewed disclosures only, not arbitrary secret-dependent
failure or request count. Equality premises that exclude precisely the
sensitive behavior one wishes to prove must be called out, not hidden.

**IO-REFINE-01 — implementation link.** Connect extracted Rust controllers
and typed filters to the actual route/template/JSON/TLS/HTTP/audit/clock/
filesystem adapters, including all failure paths; record any unrefined
adapter as an assumption in the ledger. The existing Lean proof of bytewise
literal reflection does **not** prove absence of encoded, fragmented,
semantic, or timing leaks and may introduce a secret-dependent denial oracle.

**LIVE-01 — non-vacuity.** Alongside theorem proofs, execute a permitted
synthetic credentialed operation and verify its expected disclosed result,
exact authorized provider request and audit. Also execute forbidden operations
and a credential-reflecting response. An always-deny implementation must fail
this gate. W1 supplies the Python baseline; W2 supplies the native Rust witness.

## Assumption accountability and handoff

Each sink and release rule in the machine inventory names assumption IDs from
`aivm-secrets-assumptions.json`. Environmental premises such as compartment
separation, trusted host principal, KVM/kernel behavior and administrative
channel inaccessibility are **deployment obligations**, not Lean results.
Concrete TLS, crypto, HTTP, JSON, audit, time, and toolchain premises are
**adapter/refinement obligations**. They must not be restated as a premise
that the broker 'does not leak': that would assume the theorem's conclusion.

W3 must replace the hand-assembled source inventory with a reviewed transitive
call graph (including `std::net`, `std::fs`, `println!`, errors/panics,
external library output and spawned processes), make alternate I/O writers
explicit, and report deviations. W4/W5 use the identifiers and semantics
above to implement actual source-linked proofs. W6 owns byte-level adapter
correspondence and negative tests. W8 validates one chosen VM/container's
compartment contract separately. Changing an authorized release or excluding
an additional observation requires a versioned W0 contract/ledger edit and
security review; silently narrowing the modeled traces is not acceptable.

**W0 acceptance:** a reviewable fixed scope; a protected/public-data list;
all currently identified output paths with source owners and classification;
an explicit adaptive attacker and observation semantics; independently
specified declassification; all used environmental/adapter assumptions
ledgered; positive non-vacuity gate; no assertion that current proofs or
runtime have already met the new global objective. The consistency checker
checks mechanical traceability, not completeness or logical consistency of
the information-flow policy. A maintainer must approve the release rules and
assumptions before W4/W5 make the final claim.
