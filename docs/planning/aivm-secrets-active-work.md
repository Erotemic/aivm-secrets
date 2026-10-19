# Active work: useful broker workflows and conditional credential confinement

Status: **work plan, not a completed assurance claim**, reconciled 2026-10-18
against frozen runtime/proof implementation `1ce2bbb` and its
[native exact-write approval validation record](../../dev/validation/2026-10-18-native-write-approval.json). This is the authoritative **priority and task queue**
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
correspondence, broader core differential coverage and cross-machine guest delivery
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
The [complete encoder increment](../verified-http-wire.md) now composes the
actual native writer through Host, standard/custom headers, authentication,
decimal Content-Length and exact body bytes, with grammar/uniqueness admission
and unchanged buffers on rejection. The extracted byte contract applies to the
native provider paths with either software or TPM-backed client identity;
it does not strengthen key custody. Route/effect conversion, canonical JSON,
TLS, response parsing and complete native I/O correspondence remain open.

The frozen encoder validation passes 2,489 portable tests with zero skips,
264 required workflows in both build configurations, the 351-name Garrett
audit and all 13 new encoder mutations. Compiler profiles retain eight bridge
paths and six coordinator paths. These are scoped byte/admission and call-path
results; broad core parity, transitive mediation, cross-machine guest delivery,
independent review and live deployment remain open.

The [newline framing follow-up](../verified-line-framing.md) closes nine
reproduced native acceptance discrepancies at guest ingress and post-send reply
boundaries. The native client and bridge share the extracted bounded terminal-LF
and observed-buffer validator. Real Python/native TLS/Unix cases cover partial
reads, clean EOF, coalesced suffixes and exact limits. The frozen gate passes
2,524 portable tests, all 296 workflows in both configurations, the 360-name
Garrett audit and six new framing mutations. Later-arriving bytes, JSON/TLS and
native mediation remain explicit obligations.

The [guest bundle increment](../guest-identity-bundles.md) replaces manual local
certificate/JWT switching with one versioned private snapshot, expected-current
digest and cooperating reader/writer locks. Python and Rust clients each load one
pair per call. Eight installer/client/provider combinations renew the same running
account/manifest broker, fence the old pair and accept the newly installed pair.
The extracted native CAS/stage/publish controller has nine checked obligations;
filesystem atomicity/durability, hashing, parsing and client loading remain adapter
premises. Frozen validation passes 2,586 portable tests, 357 required workflows in
both build configurations, the 369-name audit and five new bundle mutations.
Host renewal and guest activation remain separate operations; remote delivery,
private-key rotation, rollback protection and uninterrupted availability are not
provided. This closes the local pair-activation step, not whole-service secrecy.

The [decoded JSON reflection increment](../verified-json-reflection.md) moves
the existing native key/text traversal into the extracted core. Its exact
recursive admission contract and accepted-tree literal exclusion theorem cover
all array/object children, with explicit depth exhaustion and an accepted witness.
The final serialized-byte check remains independent. Native provider and Python
broker cases cover nested selected text, JSON escapes and discarded credentials.
Frozen validation passes 2,606 portable tests, 365 workflows in both build modes,
the 378-name audit and five new traversal mutations. JSON conversion, rendering,
call-site mediation, alternate encodings, semantic leakage and the observable
reflection-denial oracle remain explicit limitations.

The [native named-operation client](../native-operation-client.md) now submits
bounded JSON and host-authorized keyed writes through the existing identity and
broker protocol, with full public errors and conservative post-send uncertainty.
Both identity inputs and both coordinator backends pass allow/deny, spent-name,
provider-failure and terminal-revocation cases. The host/client share an extracted
exact ASCII retry-name validator. Frozen validation passes 2,656 portable tests,
410 required workflows in both build modes, the 384-name audit and five new retry
mutations. Native coordinator shutdown is additionally bounded and half-closed
after an observed malformed-reply truncation; the interrupted run and lack of
deterministic reproduction are retained. The unchanged W4/W5 models were
recompiled and their combined-extraction provenance refreshed after the initial
gate rejected stale pins. CLI/I/O, SQL,
whole-service mediation and broad parity remain separate obligations.

The [native coordinator operator client](../native-coordinator-control.md) now
covers host activation/revocation/status without Python or a mandatory SQLite
client dependency. Two deterministic Python commit-then-drop regressions motivated
conservative mutation uncertainty in both clients. Typed receipts distinguish an
absent principal from a terminal tombstone; the extracted validator composes with
successful pure revocation. Frozen validation passes 2,691 portable tests, 443
required workflows in both builds, the 391-name audit and six new receipt
mutations. The new host-only sink is separated from member admission. JSON/TLS,
transport placement, remote commit/durability and broad parity remain open.

The optional [native exact-write approval](../native-write-approval.md) port adds
owner-only host control, matching unexpired one-use admission before preflight
and no refund after failure. Allow mode stays unbounded; approval is an explicit
operator choice. A frozen 90-row corpus is re-evaluated against Python admission,
and native process tests cover provider/preflight failure, concurrent reuse,
revocation during blocked provider I/O and existing Python operator CLI use.
Frozen validation passes 2,721 portable tests, 689 selected parity tests, 467
required workflows in both builds, the 400-name audit and eight new approval
mutations; all 246 pinned package inputs match. The actual issue/consume leaves
have nine checked contracts. The approve configuration, host socket and public
approval digest remain outside the current W4/W5 whole-trace model. Kernel
owner credentials, no guest forwarding, hashing/normalization, clock/slot-store
linearization, audits and concrete I/O remain adapter premises. Already admitted
remote effects cannot be cancelled. Delegation/budgets, broad parity, complete
mediation, live deployment and independent security review remain open.

The [parsed-policy identity increment](../verified-policy-normalization.md) closes
the known raw-document fingerprint difference in coordinated manifest writes.
Finite differential and durable-record tests are the evidence; normalization
and hashing remain concrete adapters, not new Lean proofs or broad parity.

The [offline HTTP/disclosure adapter increment](../garrett-offline-adapter-assault.md)
closes Python and native Rust HTTP response-acceptance gaps:
ambiguous or close-delimited success, partial representations, incompatible
response media, and forbidden body framing on 204 now fail closed. A stricter native W6 observation oracle and raw TLS fixture
are added, with positive-response witnesses and deliberate negative oracle
mutants. Native Rust process scenarios need a pinned-toolchain run before they
count as tested. Complete I/O reachability/refinement and whole-service
noninterference remain open.

The [independent Rust primitive runner](../primitive-conformance.md) now supplies
the formerly pending complete-table corpus backend. The usable-system gate
selects it explicitly and rejects skips. Binding/digest/frame adapters are
tested, while the extracted freshness theorem scope remains unchanged; this
does not promote broad broker CORE-01 parity.

## Audited native read slice, 2026-10-19 (partial W3/W6)

The [offline native read slice](../garrett-native-read-refinement-slice.md)
restricts the native executor to a private audited-dispatch value and checks
read-only operation phase/write invariants. Local HTTPS process tests now
observe the durable-audit **file contents at provider request arrival** and
the exact TLS guest JSONL reply, in addition to final provider and audit
traces. The read-slice mutation tests preserve the original W3/W6 assumptions.
This is a useful implementation/observation increment only: the Rust and Lean
full gate must run on the maintainer's pinned toolchain, W4/W5 still specify
abstract events, and whole-service implementation-to-proof refinement remains
open. It does not close W3 transitive I/O reachability or W8 guest isolation.

## Native read release and metadata, 2026-10-19 (partial W3/W6)

The [completed release slice](../garrett-native-read-release-refinement.md)
adds a private source-level completion-audit receipt after selected projection
and reflection checks, independent finite read-release/pagination oracles, and
real native TLS scenarios for no-preflight, returned checked facts, fixed
errors and raw guest frames. The separate fast gate reuses native executables
and does **not** run Charon, full tests, or Lean. Native compilation for this
increment is pending the maintainer's toolchain; the established W4/W5 Lean
scope and its open NO-PREFLIGHT/METADATA/IO-REFINE obligations are unchanged.

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
The [frozen validation record](../../dev/validation/2026-10-18-coordinator-operator.json)
reports 2,691 portable tests with zero skips and all 443 required workflow tests in
both conformance and ordinary release modes. These tests do not discharge
unproved native I/O correspondence or independent security review.

| ID / owner role | Task and concrete exit gate | Status / dependencies |
| --- | --- | --- |
| **W0 — Specification / threat-model agent** | Specify broker operation/profile scope, all identified guest-reachable sinks, protected values, public metadata, release contracts and excluded side channels. Map each environmental/adapter premise to the [assumption ledger](aivm-secrets-assumptions.json); model an *adaptive* attacker and distinguish native mTLS, legacy host-local forwarding and privileged administration. Deliver and review the [W0 contract](aivm-secrets-conditional-confinement.md) and [inventory](aivm-secrets-w0-boundaries.json); **do not** treat hand inventory as audited exhaustive call-graph coverage. | **Specification baseline authored; review pending.** Scope, release rules and adapter assumptions must be accepted before a global theorem/refactor. The structural checker does not prove complete reachability. |
| **W1 — Workflow / test agent** | Standalone **process-level** Python broker + client + local synthetic HTTPS GitHub-like provider. Demonstrate allowlisted PR read/diff/checks (as supported), provider-observed credential use, exact disclosed result, denials of a different PR, forbidden write, arbitrary endpoint, credential-reflecting result and revoked/expired grant; check audit and cleanup. No AIVM and no live credential. | **Local implementation and tests pass; maintainer review pending.** Named `synthetic-github-pr-read-v1` workflow and broker/CLI/TLS subprocess checks are in [W1 documentation](../standalone-github-workflow.md). Live GitHub and OS isolation remain untested. |
| **W2 — Rust runtime agent** | Run the same *named, narrowly scoped workflow* using the native Rust manifest executor, then close only the needed CLI alias/resolver and policy gaps. Compare operation semantics and approved disclosure rather than asserting byte-identical Python/Rust replies where contracts differ. A failed Rust operation must not silently fall back to Python. | **Named native workflow passes in both build modes; broad parity and maintainer review remain open.** See [W2 test contract](../standalone-rust-github-workflow.md) and the frozen usable-system evidence. There is no Python fallback. The normative core catalogue still records partial contracts. |
| **W3 — Rust core / boundary agent** | Audit all guest-request reachable paths that can perform I/O (`request`, `describe`, `renounce`, refresh, error paths and any reachable administrative handlers). Define a *closed typed effect vocabulary* and identify every constructor and interpreter. Refactor narrowly where needed so no alternate secret-bearing/public-output path bypasses admission or typed disclosure. Add source/call-graph gates and deliberate bypass mutants. | **Native build and reviewed-source/negative gates pass; transitive reachability and independent review remain open.** The [inventory](aivm-secrets-w3-reachability.json) pins the reviewed Rust/build files and 14 effect classes; the checker reports the current source count. The [compiler ledger](../native-call-ledger.md) preserves unresolved callbacks, dependency boundaries and drops; it is not a completeness proof. Continue W3/W6 at those gaps. |
| **W4 — Lean / core verification agent** | State and prove SINK-01 + TRACE-01 for the **extracted actual Rust transitions**, including authorized success, denial, failed preflight, refused audit, provider failure, revocation-at-linearization and allowed declassification. Explicitly connect the existing `protocol.rs`/`credential_use.rs`/`manifest.rs`/`disclosure.rs` proofs; no premises that merely assert the conclusion. | **Scoped W4 trace lemmas compiled in the maintainer's pinned Lean environment; native I/O correspondence remains W6.** See [W4 scope and validation](../verified-w4-core-trace.md). Existing controller proofs are inputs, not completion. |
| **W5 — Lean / information-flow agent** | Prove NI-TRACE-01 over a clearly defined two-run, adaptive finite-trace observation relation. Decide how secret-dependent literal-reflection rejections are handled; do not hide them under an unchecked assumption of equal public behavior. Supply successful/denied witnesses and attacker-chosen field mutations. | **Modeled Lean and native finite runtime gates pass; serialized-byte/native trace refinement remains open.** See [W5 scope](aivm-secrets-w5-proof-scope.json) and [review](../verified-w5-information-flow.md). Equal approved declassifications remain an explicit premise; finite runtime witnesses do not prove service-level noninterference. |
| **W6 — Adapter / integration verification agent** | Enumerate Rust actual bytes/sinks and show adapter correspondence to typed effects with adversarial TLS/HTTP, JSON parser/render, fixed route, header, proxy/redirect, audit and error-path tests. Refine selected adapters in Lean where tractable; list each remaining contract with an owner and negative test. No unscoped `std::net`/`println!` bypass. | **Thirteen-sink review inventory, native unit/process gates and concrete hardening pass; complete native request encoding and optional authority typed-role/core/history refinements compiled; broader refinement remains open.** The [W6 review](../verified-w6-adapter-correspondence.md) records actual provider/audit/guest traces and the reproduced JSON marker-object fix. Complete mediation and JSON/response/guest-output correspondence remain deliverables. |
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
| **P-CORE-06** | Running OAuth broker leases the vault's current access token at each request, preserving capability and enrolled epoch; identity `renew-bound` issues fresh cert/JWT without broker/bridge restart | Rust same-session token rollover implemented and locally tested; same-key native renew/rebind tested without broker restart; explicit local cert/JWT bundle activation tested with both clients; broader differential gate incomplete, remote delivery still manual and no host/guest transaction |
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

### Incremental read-profile W4/W5 bridge (2026-10-19)

See [`garrett-read-paths-and-two-run-refinement.md`](../garrett-read-paths-and-two-run-refinement.md).
The new `GarrettReadPaths.lean` candidate distinguishes no-preflight,
checked-only, and two-phase read event traces and states conditional
noninterference under explicit selected-release and metadata premises. A
paired native TLS-provider test oracle checks concrete finite two-run
observations against independent host-owned inputs. **Portable checks only
have been run on the authoring machine**; focused Lean and native execution
are pending on the maintainer's VM. Existing W4 `IO-REFINE` and W5 concrete
correspondence obligations remain open. Prefer
`python dev/verification/quick_w6_read.py [--lean] [--native]` over a heavy
full compiler-linkage capture for this source-unmodified increment.

### Read failure W4/W5/W6 observation slice (2026-10-19)

See [`garrett-read-failure-trace-refinement.md`](../garrett-read-failure-trace-refinement.md).
The finite native read witness now covers the denial side of three previously
modeled paths: final-only, checked-only, and preflight-then-final. A synthetic
provider changes private 4xx/5xx diagnostics or malformed success bodies while
the oracle independently fixes the expected public error class and effect
prefix. Paired raw guest TLS frames must remain identical; completion records,
extra provider sends, request identity changes and unreviewed audit fields are
rejected. A portable reviewed-source guard pins the native error/JSONL leaf.
**Only portable checks were executed when authored**; selected native process
cases must run with `quick_w6_read.py --failure-only --native`. No additional
Lean claims were introduced. Audit-but-no-send, error/close timing, complete
Rust-to-Lean I/O correspondence and transitive compiler reachability remain
explicitly open. Prefer the focused gate over Charon for this test-only slice.
