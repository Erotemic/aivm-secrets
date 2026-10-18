# Active work: useful broker workflows and conditional credential confinement

Status: **work plan, not a completed assurance claim**, reconciled 2026-10-18
against frozen runtime/proof implementation `078ef2d` and its
[coordinator authorization validation record](../../dev/validation/2026-10-18-coordinator-dispatch.json). This is the authoritative **priority and task queue**
for new agents. Existing P0-P5, M0-M6, and G0-G5 stages remain useful design,
implementation history, and prerequisite inventories; they are **not three
competing current schedules**. Revisit this queue after each accepted milestone.

W0 has a [scoped conditional-confinement contract](aivm-secrets-conditional-confinement.md)
and [machine-readable sink/observation inventory](aivm-secrets-w0-boundaries.json),
with a structural check at `python dev/verification/w0_contract.py check`.
This is a **specification baseline pending maintainer security review**, not
evidence that the inventory is complete or the theorem is proved. W3/W6 must
complete and independently review the transitive I/O reachability audit.

W2 has a [native Rust synthetic workflow fixture](../standalone-rust-github-workflow.md)
and W3 has a [source-boundary review and checker](../verified-w3-effect-boundary.md).
Neither establishes service-level credential confinement; their runtime and
source-completeness review gates remain explicit.

W1 now has a [standalone GitHub-like workflow](../standalone-github-workflow.md),
with reusable [scenario data](../../tests/secrets_github_scenario.py) and
[process-level tests](../../tests/test_secrets_w1_github_workflow.py). It
establishes the stated local synthetic Python behavior only, not live
GitHub compatibility, guest OS isolation or native Rust parity.

Sources of truth for technical detail remain the
[formal assurance specification](aivm-secrets-formal-assurance.md),
[Garrett protocol obligations](aivm-secrets-garrett-verification.md),
[modular proof dependencies](aivm-secrets-modular-proof-architecture.md),
[assumption ledger](aivm-secrets-assumptions.json), and the
[actual proof-scope records](../verified-composition.md) and
[disclosure record](../verified-disclosure.md). This work plan ranks and connects
them; it does not silently change protocol formats, current policies, or
already verified theorems.

## Local validation update, 2026-10-17

The previously uncompiled native overlays now build on the pinned toolchain.
The combined W1/W2/W5/W6 native/reference workflows pass 20 tests with zero
skips, Rust workspace unit tests pass, and W4/W5 compile under Lean. These
results close the local build/runtime availability gap in the historical
snapshot table below, not the outstanding semantic refinement/security review.
The [usable-system gate and configuration comparison](../assurance-profiles.md)
add fail-on-skip automation, copied-software-key runtime witnesses and a separate
conditional protocol-profile theorem module. Broad Python/Rust core parity,
complete native trace refinement and live deployment/provider gates remain open.
The [interactive comparison](../assurance-profiles.html) keeps credential
confinement, surrogate binding and identity-key custody as separate dimensions.

## Native dispatch follow-up

The [dispatch freshness increment](../verified-dispatch-freshness.md) brings
forward the saved late-admission fix into the newer W3/W6 adapters: eight
blocking-setup regressions reproduced on the baseline and pass with the fix.
The small extracted emission controller and repeated protocol admission are
kernel-checked; concrete clock/lease/call-site correspondence stays explicit.
The usable-system gate includes the new regressions in both software-key
workflows. W4/W5 model records report local kernel checking with native
refinement still open. The [current-session OAuth increment](../verified-oauth-current-session.md) adds
native rollover without restarting and preserves epoch/lifetime fencing. The [native coordinator client and keyed-write increment](../verified-coordination.md)
adds terminal revocation checks and shared retry reservation against the Python
server. The [same-key identity increment](../verified-identity-rebinding.md) also carries
the existing grant through certificate/JWT renewal without restarting the broker.
The [optional native coordinator authority](../native-coordinator-authority.md) now
implements the same mTLS/SQLite protocol and schema, with cross-backend vectors,
broker workflows and scoped core/terminal-history proofs. SQL/TLS/native I/O
correspondence, broader core differential coverage and atomic guest delivery
remain open. The typed admission follow-up moves exhaustive action-to-role
selection into the extracted core: operator authority does not imply active
principal membership, nor does membership grant operator authority. Lean checks
the exact gate for every action, terminal denial of all member actions and
positive role-gate witnesses. A 144-case Python/native role-state matrix retains
both durable tables on denial. Wire-to-enum, SQL and native I/O correspondence
remain separate obligations.

The [compiler-derived native call-site ledger](../native-call-ledger.md) is a
reproducible W3/W6 investigation aid. It preserves all extracted owned bodies
and explicitly leaves callbacks, dependency behavior, drops and unwind open;
its direct-root traversal underapproximates reachability. It supplies no
complete-mediation status or additional service-level theorem.

The [specialized compiler check](../specialized-call-ledger.md) now exposes
concrete account/manifest controller-to-executor call paths. Its bounded full
extraction and streaming projector retain unresolved dependency/drop obligations;
presence of the intended callback links is not admission dominance or native
trace refinement. Continue W3/W6 through those remaining obligations.

The [concrete authentication-line refinement](../verified-http-auth.md) now
connects both native provider writers to extracted credential validation and
byte appending. Its exact-header, unchanged-buffer and single-line theorems
cover that leaf. The [request-line refinement](../verified-http-request.md)
additionally checks method/target admission and exact single-line bytes.
Destination/full-request/TLS/native-trace obligations remain.

The [parsed-policy identity increment](../verified-policy-normalization.md) closes
the known raw-document fingerprint difference in coordinated manifest writes.
Finite differential and durable-record tests are the evidence; normalization
and hashing remain concrete adapters, not new Lean proofs or broad parity.

The [independent Rust primitive runner](../primitive-conformance.md) now supplies
the formerly pending complete-table corpus backend. The usable-system gate
selects it explicitly and rejects skips. Binding/digest/frame adapters are
tested, while the extracted freshness theorem scope remains unchanged; this
does not promote broad broker CORE-01 parity.

## Product question and security objective

A hostile agent should be able to perform a *real, specifically authorized*
provider operation using a broker-held credential without learning that
credential or causing an unauthorized credentialed request. The agent can send
arbitrary protocol inputs, adapt later requests to previous outputs, and use
its legitimate permissions. An always-deny broker does not satisfy the goal.

The principal **conditional assurance objective** is:

> For every finite sequence of untrusted client requests, the implemented Rust
> broker's credential-bearing provider effects have the required authorization,
> binding, approved destination, and dispatch evidence; information originating
> in protected broker state reaches guest-visible outputs only through
> explicitly reviewed declassification rules. This holds assuming the stated
> OS compartment, cryptographic, authenticated-channel, trusted-provider, and
> concrete I/O-adapter contracts. All such contracts and excluded observation
> channels must be named in the published theorem/assurance record.

This is a target **to establish**, not a description of the present proofs.
The existing composed-controller and recursive disclosure noninterference
results cover narrower conditional cases (not whole-service I/O histories).

### What is and is not an authorized channel

| Compartment / sink | Permitted information flow | Boundary to model or assume |
| --- | --- | --- |
| Untrusted guest / client | Bounded operation requests and reviewed public replies, including specified denials and allowed result fields | Broker must not expose plaintext provider credentials, raw vault state, unwrapped inner capabilities, or unrestricted exception strings |
| Intended HTTPS provider | The selected credential **only** as required by the approved provider authentication method, with the authorized request | Exact origin, TLS peer identity, method/path/headers/body, redirects and proxy behavior must obey an adapter contract; no arbitrary guest-selected destination |
| Host-only audit / operator control | Selected operational metadata; strictly defined privileged administration paths | Audit content, stdout/stderr, process exit status, log files and other output paths must be inventoried and classified; admin channels are not guest-accessible under deployment assumptions |
| Broker private state | Credentials, refresh tokens, keys, policy, authority/registry and vault contents | Host process/filesystem integrity and lack of direct guest access are environmental assumptions, **not** results proved about KVM or containers |

Enumerate guest-visible observations before proving equivalence: protocol
frames and errors, their statuses and lengths, exposed files/logs, and any
other broker-origin output the guest can access. Decide explicitly whether
connection closure, failure ordering, ciphertext length and resource-limit
behavior are observed. The initial relational theorem may exclude wall-clock
timing, microarchitectural effects, hidden host memory and computational
ciphertext indistinguishability, but **must say so**. Other privileged host
observers need their own release policies; they cannot be treated as the guest.

Guest isolation does not mean forbidding every guest network connection.
It means the guest cannot directly read or modify broker-private state or
reach privileged channels outside the declared model. Firewall/VM/container
configuration is evidence for this premise, not a Lean proof obligation for
the Rust controller. AIVM is one possible implementer of the premise; it is
not required to run the standalone broker workflow or source-level proofs.

### Distinct obligations: do not conflate them

- **SINK-01 (confinement):** every broker-generated credential-bearing effect
  has an admitted operation, current binding and matching selected provider
  destination. A provider credential is *allowed* to reach its designated
  provider; it is not globally prohibited from crossing the broker boundary.
- **TRACE-01 (complete mediation):** every security-relevant I/O effect in the
  guest-request reachable call graph corresponds to a modeled, authorized
  effect. Include denials, failures, audit, refresh during use, and concurrency
  at the selected linearization point. Positive success witnesses are required.
- **NI-TRACE-01 (declassification-aware noninterference):** for pairs of
  executions with equal public initial state, equal/adaptively matched public
  inputs and **equal policy-approved declassifications**, modeled guest
  observations agree even if protected private state and discarded provider
  fields differ. State precisely how secret-dependent denials, lengths,
  termination, and ciphertext are treated. Do not assume arbitrary approved
  strings are harmless: provider-controlled fields can encode credentials.
- **IO-REFINE-01 (implementation link):** actual Rust source-to-Lean controller
  behavior and concrete request builders, parsers, serializers, TLS/HTTP,
  audit, storage and output adapters preserve the relevant trace contracts.
  Any part not refined stays an explicit, reviewable assumption.
- **LIVE-01 (utility):** at least one permitted real broker operation succeeds
  and releases its expected approved result while forbidden requests fail.
  Unit-level or symbolic witnesses alone do not discharge this gate.

The exact-string reflection check is useful defense-in-depth, but may itself
create a secret-dependent denial oracle; it is not general noninterference.
Existing symbolic `publicData`/credential constructor separation is not a
byte-level confidentiality theorem. Neither theorem counts nor mutation
counts substitute for the obligations above.

## Active task queue

Statuses below reflect the checked implementation, with remaining acceptance
conditions kept explicit. The older milestone plans retain historical detail.
The [frozen validation record](../../dev/validation/2026-10-18-coordinator-dispatch.json)
reports 2,472 portable tests with zero skips and all 250 required workflow tests in
both conformance and ordinary release modes. These tests do not discharge
unproved native I/O correspondence or independent security review.

| ID / owner role | Task and concrete exit gate | Status / dependencies |
| --- | --- | --- |
| **W0 — Specification / threat-model agent** | Specify broker operation/profile scope, all identified guest-reachable sinks, protected values, public metadata, release contracts and excluded side channels. Map each environmental/adapter premise to the [assumption ledger](aivm-secrets-assumptions.json); model an *adaptive* attacker and distinguish native mTLS, legacy host-local forwarding and privileged administration. Deliver and review the [W0 contract](aivm-secrets-conditional-confinement.md) and [inventory](aivm-secrets-w0-boundaries.json); **do not** treat hand inventory as audited exhaustive call-graph coverage. | **Specification baseline authored; review pending.** Scope, release rules and adapter assumptions must be accepted before a global theorem/refactor. The structural checker does not prove complete reachability. |
| **W1 — Workflow / test agent** | Standalone **process-level** Python broker + client + local synthetic HTTPS GitHub-like provider. Demonstrate allowlisted PR read/diff/checks (as supported), provider-observed credential use, exact disclosed result, denials of a different PR, forbidden write, arbitrary endpoint, credential-reflecting result and revoked/expired grant; check audit and cleanup. No AIVM and no live credential. | **Local implementation and tests pass; maintainer review pending.** Named `synthetic-github-pr-read-v1` workflow and broker/CLI/TLS subprocess checks are in [W1 documentation](../standalone-github-workflow.md). Live GitHub and OS isolation remain untested. |
| **W2 — Rust runtime agent** | Run the same *named, narrowly scoped workflow* using the native Rust manifest executor, then close only the needed CLI alias/resolver and policy gaps. Compare operation semantics and approved disclosure rather than asserting byte-identical Python/Rust replies where contracts differ. A failed Rust operation must not silently fall back to Python. | **Named native workflow passes in both build modes; broad parity and maintainer review remain open.** See [W2 test contract](../standalone-rust-github-workflow.md) and the frozen usable-system evidence. There is no Python fallback. The normative core catalogue still records partial contracts. |
| **W3 — Rust core / boundary agent** | Audit all guest-request reachable paths that can perform I/O (`request`, `describe`, `renounce`, refresh, error paths and any reachable administrative handlers). Define a *closed typed effect vocabulary* and identify every constructor and interpreter. Refactor narrowly where needed so no alternate secret-bearing/public-output path bypasses admission or typed disclosure. Add source/call-graph gates and deliberate bypass mutants. | **Native build and reviewed-source/negative gates pass; transitive reachability and independent review remain open.** The [inventory](aivm-secrets-w3-reachability.json) pins the reviewed Rust/build files and 13 effect classes; the checker reports the current source count. The [compiler ledger](../native-call-ledger.md) preserves unresolved callbacks, dependency boundaries and drops; it is not a completeness proof. Continue W3/W6 at those gaps. |
| **W4 — Lean / core verification agent** | State and prove SINK-01 + TRACE-01 for the **extracted actual Rust transitions**, including authorized success, denial, failed preflight, refused audit, provider failure, revocation-at-linearization and allowed declassification. Explicitly connect the existing `protocol.rs`/`credential_use.rs`/`manifest.rs`/`disclosure.rs` proofs; no premises that merely assert the conclusion. | **Scoped W4 trace lemmas compiled in the maintainer's pinned Lean environment; native I/O correspondence remains W6.** See [W4 scope and validation](../verified-w4-core-trace.md). Existing controller proofs are inputs, not completion. |
| **W5 — Lean / information-flow agent** | Prove NI-TRACE-01 over a clearly defined two-run, adaptive finite-trace observation relation. Decide how secret-dependent literal-reflection rejections are handled; do not hide them under an unchecked assumption of equal public behavior. Supply successful/denied witnesses and attacker-chosen field mutations. | **Modeled Lean and native finite runtime gates pass; serialized-byte/native trace refinement remains open.** See [W5 scope](aivm-secrets-w5-proof-scope.json) and [review](../verified-w5-information-flow.md). Equal approved declassifications remain an explicit premise; finite runtime witnesses do not prove service-level noninterference. |
| **W6 — Adapter / integration verification agent** | Enumerate Rust actual bytes/sinks and show adapter correspondence to typed effects with adversarial TLS/HTTP, JSON parser/render, fixed route, header, proxy/redirect, audit and error-path tests. Refine selected adapters in Lean where tractable; list each remaining contract with an owner and negative test. No unscoped `std::net`/`println!` bypass. | **Twelve-sink review inventory, native unit/process gates and concrete hardening pass; authentication/request-line and optional authority typed-role/core/history refinements compiled; broader refinement remains open.** The [W6 review](../verified-w6-adapter-correspondence.md) records actual provider/audit/guest traces and the reproduced JSON marker-object fix. Complete mediation and the remaining byte-adapter proofs remain deliverables. |
| **W7 — Operator / release agent** | Opt-in *read-only* live GitHub smoke test using an intentionally narrow disposable credential, then publish exact passing commands and a claim matrix: tested behavior, extracted proofs, assumed adapters, deployment evidence, excluded channels. Never require live credentials in ordinary CI. | **Local W1/W2 prerequisites pass; opt-in live provider smoke remains unexecuted.** Requires an intentionally narrow disposable credential and explicit operator selection; not a prerequisite for local proof development. |
| **W8 — AIVM / deployment agent** | Translate the environmental compartment contract to one chosen AIVM VM profile, test host-file/privileged-socket absence, identity/transport, network destinations and teardown. Keep KVM, guest kernel and firewall as deployment assumptions, not inferred properties of the Rust proof. | **Separate downstream integration; deployment validation remains open.** Optional AIVM vTPM creation/offline upgrade is implemented at `24c5fe0`, with no live VM evidence. A device alone does not establish protected identity custody. W8 remains nonblocking for W0-W7. |

### Dependencies and merge discipline

```text
W0 ──> W3 ──> W4 ──> W5
 |       └────────────> W6
 ├──> W2 (after W1 scenario)
 └──> W8 (external deployment evidence)
W1 ──> W2 ──> W7
W4 + W5 + W6 ──> conditional service-level assurance review
```

- Before editing shared Rust core interfaces, W2/W3/W4 agents agree on the
  request/effect schema, authorized sink types and versioning plan. Work on
  independent test fixtures and specifications may run in parallel.
- Each agent reports which source files were changed, existing theorems reused,
  tests actually executed, mutants detected, and which assumptions remain
  unproved. Do not label a subset as a whole-service theorem. Regenerate Lean
  from pinned Rust for implementation-linked obligations. During proof
  development, use focused Lean compilation and surface compiler errors;
  reserve broader provenance and dependency reviews for release gates.
- Expand a provider manifest only after its operation-specific request *and*
  declassification contracts have been reviewed; the executor must not become
  an authenticated arbitrary-URL proxy.
- Do not alter working Python policy/wire behavior incidentally to match Rust.
  Record intentional differences and migrate via versioned, reviewed changes.

## Python Garrett follow-on: operational core and Rust parity

This is an **independent Python implementation workstream**, not a claim that
Rust W4–W6 proofs now cover Python. See the [Python core API inventory](aivm-secrets-python-core-api.json)
and [new functionality and trust boundaries](../garrett-python-core-extensions.md).

| ID | Python deliverable and status | Rust parity/operational gate |
| --- | --- | --- |
| **P-CORE-07** | Durable terminal cross-host principal revocation using one local SQLite coordinator, mTLS member/operator pins, check at every broker and bound-bridge request; tests use synthetic same-host distinct member certificates | Native account/manifest clients and optional native server tested against independent Python implementations; core terminal decision/history proofs compiled; SQL/native I/O refinement, real separate-host deployment, rollback witness and operational failover unvalidated |
| **P-CORE-06** | Running OAuth broker leases the vault's current access token at each request, preserving capability and enrolled epoch; identity `renew-bound` issues fresh cert/JWT without broker/bridge restart | Rust same-session token rollover implemented and locally tested; same-key native renew/rebind tested without broker restart; broader differential gate incomplete and guest material delivery remains manual |
| **P-CORE-08/09** | Durable per-principal idempotency reservations before any coordinated write; guest ASCII retry keys, optional explicit upstream `Idempotency-Key`, strict no-replay even after ambiguous result | Native keyed manifest dispatch and shared retry names tested; normalized policy fingerprints checked against Python and durable records; all-input parity and production provider header semantics unverified |
| **P-PARITY** | All Python modules classified core vs non-core, 11 normative security contracts with Rust status and acceptance criteria | Implement independent Rust behavior and bidirectional negative/positive trace tests before marking any contract parity-complete |

A previous approved operation may still finish if global revocation commits
after its last authorization check. A coordinator outage fails closed. Neither
SQLite backup rollback nor shared cross-host OAuth vault state is solved by
this implementation. Local-only Python sessions continue working without a
coordination config; that is not a distributed security guarantee.

## Retained, deferred and removed from the active critical path

**Retained:** existing Garrett identity, certificate binding, OAuth custody,
issuance, enrolled-identity generation, audit ordering and primitive proofs.
They are prerequisites or reusable evidence where they actually supply a
premise, not disposable work. Keep security bug fixes in any subsystem active.

**Deferred as milestones:** new TPM/vTPM provenance campaigns, physical AK
trust sourcing, multi-tenant identity, broader CA lifecycle research,
additional abstract primitive theorems, generic plugin ecosystems and broad
provider expansion. Their design and existing tests remain in the repository;
resume when they discharge a concrete missing premise or serve a demonstrated
workflow. Do not delete these historical planning records.

**Removed as success criteria:** counting standalone theorems, citing mutation
counts without an attacked security claim, and equating a typed-controller
success with proof that the deployed broker has no other output path.

**Review stop:** do not publish a system-level confidentiality or verified
isolation statement until the scoped traces, I/O-refinement assumptions,
positive workflow witness and environmental exclusions are reviewable together.
A formal theorem may be published earlier with its exact narrower statement.
