# Garrett native read assurance: implementation-to-trace roadmap

**Plan, not an assurance certificate. Last reconciled 2026-10-19.**

**Start here if you are the next implementation agent.** The authoritative
priority order is [active work](aivm-secrets-active-work.md); this document
specifies the first campaign's technical scope, dependencies, deliverables and
exit gates. The earlier running commentary was archived as
[historical work](aivm-secrets-active-work-history-2026-10-19.md).

**Priority guardrail:** This is a means to the original goal: an agent
actually uses a host-held credential for narrowly authorized work without
being given the credential. Keep the independent offline guest-to-broker
workflow in the [active queue](aivm-secrets-active-work.md) as a parallel
acceptance witness. Do not postpone all integration and operator usability
until the final theorem, and do not promote additional inventories, source
hashes, synthetic traces or unrelated abstract lemmas into new milestones.
The next substantive assurance change must be **production-called Rust
extraction**, followed by an implementation-linked simulation proof. NR-0
is one baseline check, not a continuing evidence-generation campaign.

## 1. Target result and why it is still missing

We want a **useful** broker: an untrusted native mTLS client can read the
specifically allowed provider data using a host-held synthetic credential,
while unauthorized or unreleased protected state cannot escape. The first
conditional claim is restricted to a selected **native Rust
`manifest-https-v1`, read-only, sequential-session** configuration.

A plausible final result, **not yet established**, is:

> Under an explicitly enumerated host-isolation, cryptographic/TLS, trusted
> policy, audit and I/O-adapter contract, every credential-bearing provider
> send attempt reachable from the selected guest request interface is linked
> to a current authorized manifest operation, a matching origin and a
> preceding acknowledged audit; every successful guest reply is produced
> by reviewed disclosure followed by a completion audit. The same modeled
> execution supports conditional declassification-aware observation equality
> for paired sequential sessions, subject to named public-channel exclusions.

This statement deliberately refers to **send attempts**, not merely requests
seen by a test provider, and to **audit acknowledgements**, not an unqualified
claim of durable storage after sudden power loss. Revalidation just before
network I/O is not an atomic transaction with a network syscall; a revocation
that commits after the final admission check does not undo an already admitted
send. These distinctions must survive the proof and its public summary.

### Evidence classes — do not promote them

| Evidence | What it currently supports | What it does not support |
| --- | --- | --- |
| Live native Rust + synthetic local TLS/provider tests | Sampled credentialed requests, selected replies, public denials, causal host audit, sequential histories; passing runs were reported during this campaign | All executions, bytes attempted but not received, real provider compatibility |
| Source guards (`w3_effect_boundary`, `w6_adapter`, read/failure/pending review scripts) | Pinned reviewed source shapes, manifest contracts and deliberate bypass mutations | Closed transitive call graph, semantic proof of runtime branches |
| Specialized Charon callback ledger | Evidence of intended compiler-specialized paths in an analyzed build | Unresolved dependency/callback/drop effects, dominance or complete reachability |
| `GarrettConfinement`, `GarrettNoninterference`, `GarrettReadPaths`, `GarrettReadPrefixes` | Scoped theorem statements derived from extracted admission/disclosure leaves; read-path/prefix `prove` reportedly passed on the maintainer's pinned Lean toolchain | Extraction of the complete native `Session::request` orchestration; trustworthiness of adapter-provided `auditOK` or `providerReached` |
| `AuditedDispatch` and `CompletedRelease` private Rust types | Source-level restrictions on calling the native provider writer and returning success | That no other sink can be reached, or that the actual I/O matches the abstract trace |

**Evidence provenance rule:** The source snapshot available to this planning
round is `b91748b` plus incremental Garrett overlays through the reported
read-path/prefix proof repair. It is not a newly exported HEAD of the user's
current working tree. Agents must record the actual `git rev-parse HEAD`,
`git status --short`, feature/configuration choices and the result of
re-running focused acceptance before replacing “reported” with “reproduced”.
A source-scope JSON `status` of `source-reviewed-kernel-verification-required`
means a portable source check cannot certify compilation; do not overwrite
this value merely because a different checkout previously passed `prove`.

## 2. Profile boundary: what the eventual theorem quantifies over

### Included

- Native `garrett-bridge` request entry through `manifest-https-v1`, verified
  client certificate, bound surrogate and current grant/epoch/time admission;
  host-owned policy, destination and disclosure.
- The host is configured with `writes=deny`, and **all selected operations
  must themselves be nonwriting**. Preflight is nonwriting even if the
  manifest later contains a separately excluded write operation.
- No-preflight final read, checked-only preflight fact return, and
  preflight-then-final read; authorization failures at entry, preflight,
  final and release; provider 4xx/5xx/malformed responses; audit failures;
  late revocation and audited-but-unsent transitions.
- Sequential guest requests during one native session, including future
  requests chosen from earlier public replies. The *current* Lean coupled
  list proof is about paired steps under supplied agreements; proving an
  adaptive **native** attacker relation remains work.
- Native host-only audit, provider HTTP(S), guest frames, errors and
  connection closure as explicitly modeled/assumed observations.
- A permitted local read that succeeds and releases approved selected data;
  failing everything must fail the positive acceptance gate.

### Excluded unless independently justified

Provider writes, approval consumption, keyed retry/reservation, opt-in
coordinated writes, delegated/legacy Python forwarding, `account-status`
profile, host OAuth login/refresh, cross-machine replication, physical TPM
provenance, full arbitrary `gh` CLI, live provider compatibility, KVM/guest
isolation proof, and general shared-broker concurrency.

**Proof boundary caveat:** A feature excluded from the claim must not remain a
reachable, credential-bearing bypass in the chosen configuration. NR-0 must
show a concrete startup/config/guest-route restriction or incorporate that
feature's effects. `describe` and `renounce` are real guest control verbs;
include their reachable effects or establish a narrower executable interface.
OAuth token **lease checks**, optional coordination checks and audit/diagnostic
side effects may still be reached from reads; don't declare them irrelevant
merely because OAuth acquisition and writes are out of scope.

The normative threat, protected-value, release and environmental definitions
are [W0](aivm-secrets-conditional-confinement.md) and
[assumptions](aivm-secrets-assumptions.json). Do not silently redefine them
here. In particular, a credential sent **to its authorized provider** is an
expected authorized release, not a violation; another provider/destination
or the guest is not authorized to receive it.

### NR-1 handoff (pure orchestration and preservation; event simulation next)

**October 20 update:** the exact extracted `prepare`/`acknowledge` seam now has
a checked preservation lemma. The same core also supplies production-called
`complete_current`, with distinct current-authority checkpoints before the
completion audit and before release. See [the increment's scope and commands](../garrett-read-completion-preservation.md).
The paragraphs below describe the original NR-1A seam; their initial missing
dispatch theorem is discharged by this increment. The [subsequent production
orchestration extraction](../garrett-native-request-orchestration.md) now
consumes optional phase and provider/error outcomes through the real
`request_current`, with exact success/data-flow and failure lemmas. The production entry now constructs and consumes a private mutable invocation;
33 focused obligations retain exact receipt states and reject saved success
after an extra invalid wrapper call. The full raw-callback/effect and
orchestration-to-W4/W5-trace relation is still missing. The distinction between
accepted wrapper calls and transitive native I/O is explicit in that scope note.

`rust/crates/aivm-secrets-garrett-core/src/read_transition.rs` implements the
actual phase/effect admission and audit-acknowledgment transition used by
`PreparedDispatch::preflight`, `::final_effect`, and `::audit` in the native
manifest broker. `AuditedDispatch` carries the resulting opaque `Audited`
value into `exchange_manifest`; there is no second native phase field to
silently diverge. This is production code, not a test-only mirror.

For this first seam, `read_transition::acknowledge(prepared, true)` is invoked
**only after** `Audit::write_record` returns successfully. The adapter is
responsible for the correctness of that acknowledgment; neither the Rust
value nor a future extracted Lean theorem proves fsync/OS durability. Late
authority checks and provider send attempts remain external NR-2/NR-3
obligations. The new theorem is in `GarrettReadTransition.lean` and checks the
regenerated production core; it is separate from the older W4/W5 abstract proofs.

The [staged provider continuation](../garrett-provider-exchange-simulation.md)
now extracts mutable setup/check/send/receive flow and the native writer's
single-attempt state. Its 30 obligations include returned-run forward simulation
under explicit primitive contracts, with stamp-origin and binding relations.
This is the first provider component, not completion of NR-2: contract
instantiation against the native I/O seam and composition through full requests,
completion/denial and connected histories remain required.

Focus the next proof work on the extracted controller's callback invocation
relation and W4/W5 event prefixes, including post-completion-audit
revocation. Do not create an independently hand-written `read_transition`
model. Preserve an authorized success witness from the standalone offline
workflow in parallel.

## 3. Concrete trust and transition boundary

Inspect the *actual production* code before any refactor:

- `rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs`:
  `Session::request`, `PreparedDispatch::preflight/final_effect`,
  `PreparedDispatch::audit → AuditedDispatch`, `Executor::exchange_manifest`,
  `manifest_request_bytes`, `manifest_response`,
  `PendingRequest` and `PendingCompletion`.
- `rust/crates/aivm-secrets-garrett/src/custody.rs`:
  `emit_current` and `Executor::exchange`, to find any alternate provider I/O.
- `rust/crates/aivm-secrets-garrett/src/tls.rs` and bridge entry:
  verified guest peer, bounded request framing, fixed error mapping,
  serialization, guest output and close behavior.
- `rust/crates/aivm-secrets-garrett-core/src/`:
  `manifest.rs`, `credential_use.rs`, `protocol.rs`, `disclosure.rs`,
  `emission.rs`, `coordination.rs`. Existing extractable controllers are the
  first primitives to reuse, not a reason to create a new authorization model.
- `proofs/GarrettConfinement.lean`, `GarrettNoninterference.lean`,
  `GarrettReadPaths.lean`, `GarrettReadPrefixes.lean` and
  `proofs/generated/AivmSecretsGarrettCore.lean`:
  the theorem vocabulary and what is/was actually extracted.
- `docs/planning/aivm-secrets-w{0,3,6}*`,
  `docs/verified-w3-effect-boundary.md`,
  `docs/verified-w6-adapter-correspondence.md`,
  `docs/native-call-ledger.md`, `docs/specialized-call-ledger.md`:
  known sink classes and unresolved compiler/dependency edges.

A minimal **candidate** abstract event sequence is below. It is a planning
model, **not** a claim that every native branch currently emits these events:

```text
Guest request and verified identity
  -> entry validation / admission OR fixed denial
  -> optional preflight compiled effect
  -> audit attempt and acknowledged audit OR denial
  -> provider TCP/TLS setup OR pre-send failure
  -> fresh authority/lease check OR audited-but-unsent denial
  -> credentialed write ATTEMPT -> response/transport/error outcome
  -> optional checked facts -> fresh check -> final effect, if any
  -> same audit/setup/fresh/write-attempt chain for final phase
  -> parse, bound, select/project, paginate, reflection check OR denial
  -> completion-audit acknowledgement OR denial
  -> guest frame serialization, TLS send and close outcome
```

Keep `auditAttempt`, `auditAcknowledged`, `providerWriteAttempt`,
`providerReceived` and `guestFrameAttempt` distinct where the proof needs
them. A provider-arrival snapshot validates causal audit order *in that test*;
it is not equivalent to an exhaustive network-syscall trace. Likewise a
completed host audit is not proof that a guest actually received a frame.

### Adapter contracts still needed

| Boundary | Contract / candidate assumption | Failure/negative witness |
| --- | --- | --- |
| Authorization and late lease | Extracted predicate matches live claim/grant/epoch/time and selected operation; revocation linearizes at specified check | Revoke after audit but before provider write; recognize post-check races |
| Audit write | A successful write/flush/sync acknowledgement corresponds to an append of one typed row with exact identity/phase/digest/route; define crash-durability separately | Fail before/during acknowledgement; prove no credentialed send follows false ack |
| Provider request | Exact typed effect maps to target, fixed headers, allowed authentication and credentialed bytes; no guest-controlled arbitrary destination or redirect | Smuggled header/route, partial network write, wrong provider CA |
| Provider return | Status/headers/bounded body parse to expected result or fixed denial; no raw diagnostic echo | Malformed frame, wrong content type, 204 behavior, nested marker objects |
| Disclosure | Actual recursive projection/pagination and reflection test correspond to W5 released data and public status | Change only private provider fields; change selected field; secret-dependent reflection status |
| Guest reply | Canonical one-frame JSONL encoder and TLS write produce stated observations; separate send attempts from successful receive | Extra metadata, malformed/extra frame, EOF/connection failure after send |
| Other reachable sinks | Files, stdout/stderr, admin/control sockets, coordinator, OAuth leases, drop/unwind and library callbacks are not unreviewed leak channels in the selected profile | Deliberately add a bypass; source/compiler/test gate must detect it |

Map each retained assumption to an actual identifier in
[aivm-secrets-assumptions.json](aivm-secrets-assumptions.json) and W0 sink IDs;
propose new identifiers through review rather than inventing unexplained
trusted primitives. **No theorem may assume the desired complete-mediation or
secrecy conclusion as a premise.**

## 4. Work packages: owners, deliverables, dependencies, exit gates

### NR-0 — Reproducible profile and evidence freeze (prepared; maintainer replay pending)

The [NR-0 evidence record](aivm-secrets-native-read-nr0-evidence.md),
[machine-readable profile](aivm-secrets-native-read-nr0.json), and
`dev/verification/native_read_profile.py` now pin the 30 source/proof/harness
files, selected native fixture, all 14 W0 sink dispositions and eight native
test nodes across six witness classes. Portable checks were reproduced on the
reconstructed archive. **Exit remains open** until `--portable --native --lean`
passes on the actual checked-out tree with recorded binary digests and zero
skips; the fixture's ability to override `writes=deny` and remaining alternate
backend/control channels are explicit boundaries, not proof of isolation.


**Owner:** integration/security review. **Dependencies:** none.

1. Record exact checkout/dirty state, production Rust hashes, generated Lean
   hashes, toolchain pins/features, start profile and denial of writes.
2. Establish the selected binary's guest entry points and the operative
   trust/compartment rules. Classify all W0/W6 sinks as included, host-only
   assumption, separately modeled control, or unreachable **with evidence**.
3. Replay one selected successful read, one denied request, one failed
   provider read, one audited-but-unsent path and a two-request session using
   the **same actual Rust code** and synthetic TLS/provider. Record all tests
   executed and skips; do not invent a new mock broker.
4. Reproduce `read_prefixes.py prove` with a named axiom report, rather than
   treating the `check` status label as kernel output.

**Exit:** `docs/planning` evidence record or review appendix with sources,
configuration, observable trace sample, trust assumptions and exact commands;
no unverified “all native cases pass” claim. This can be a documentation-only
PR. Failure to restrict write/alternate profile channels blocks NR-1's claim.

### NR-1 — Extract the actual read step and make it authoritative

**Owner:** Rust/extraction. **Dependencies:** NR-0.

Identify the smallest pure, production-called Rust transition(s) encoding:
current admission, preflight/final decisions, dispatch-audit acknowledgement,
late fresh admission, provider-result/error classification and completion
release. Supply bounded typed inputs and explicit outcome enums for I/O
acknowledgements; keep key material, TLS, socket/file handles, time sampling,
JSON and filesystem mutations in adapters. If one pure step is not sufficient,
use a small sequence of phases and an interpreter but keep the decisions in the
production code. The existing private `AuditedDispatch` and
`CompletedRelease` are useful guardrails and should not be bypassed.

**Required extraction approach:** make the *real* native call site invoke the
Rust function(s) extracted through the existing pinned Aeneas/Charon pipeline;
commit generated artifacts with source/build provenance and exact hashes. A
separate hand-written Lean equivalent is a specification, not a source link.
Do not add an independent Rust “proof helper” with no runtime callers.

**Exit:** targeted Cargo build/tests, successful regenerated Lean import,
source-linkage/hash gate, and a checked theorem for at least one nontrivial
transition. Include an authorized positive witness and an invalid-transition
counterexample. Do not claim the network adapters have been extracted.

### NR-2 — Forward-simulate all scoped request transitions

**Owner:** Lean/model. **Dependencies:** NR-1; coordinate with NR-3.

Define concrete-to-abstract relation from extracted step state to
`Gate`, `Attempt`, `ReadPath`, `Event` and `ObservedStep` in the existing proofs.
Handle early denial, audit refusal, audited-but-unsent, provider reply or
failure, fresh-check revocation, checked-only facts, final-only and two-phase
read paths, completion-audit refusal and release. Represent multi-step current
grant/identity continuity; spell out which policy and lease values are host
supplied. Treat `providerReached` and `auditOK` as **observable adapter facts
needing correspondence**, not free assumptions that silently prove the goal.

**Exit:** kernel-checked step-preservation/simulation lemmas about the actual
extracted function(s), plus a compositional sequential-history result when
those steps are linked. State the simulation relation, the accepted external
I/O contracts, and what part remains conditional. A toy interpreter theorem
alone does **not** complete NR-2.

### NR-3 — Close scoped W3/W6 reachable effects

**Owner:** Rust boundary + W6 reviewer. **Dependencies:** NR-0; parallel NR-1;
needed before integrated NR-2/NR-4 claim.

1. Reconcile startup, `Bridge::answer`, `Session::request` and all scoped
   control/error paths with W0/W3/W6 sink inventories, including dependency
   callbacks, dynamic dispatch, destructors, panics and transport error cases.
2. Constrain privileged sockets/files/credentialed writers behind minimal
   trusted modules and mechanically checked call-site visibility when useful.
   Do not infer absence of alternate effects from a hand-maintained allowlist.
3. Link typed request, audit/authority acknowledgement, actual provider
   `write_all` attempt (including partial failure), parser/disclosure, and
   guest frame/close observations to the NR-1/NR-2 steps.
4. For every remaining unmodeled external operation, record a contract,
   trust owner, negative test and why excluding it is safe in this profile.

**Exit:** reviewable reachable-effect inventory with no unknown sink marked
safe, source or proof-linked correspondence for source-owned paths, explicit
external contracts for TLS/filesystem/JSON dependencies, deliberate bypass
mutants, and required native integration witnesses. **Use the expensive Charon
specialized capture only when the source graph/feature profile changed in a
way the smaller gates cannot justify**; record unresolved edges, not just a
success exit code.

### NR-4 — Relational guest observations and adaptive behavior

**Owner:** information flow. **Dependencies:** NR-2 + NR-3.

Relate `observedRead`/`CoupledRead` to actual selected response bytes,
`meta`/pagination, fixed error code, secret-reflection refusal, frame length,
return/EOF and any guest-readable diagnostic. Model later guest requests as
functions of earlier public output, or explicitly limit the theorem to
nonadaptive paired sequences; the current per-step `DeclassificationAgreement`
premise alone is not an adaptive application-security proof. Decide whether
secret-dependent literal-reflection denials are a declassified status bit or
whether implementation hardening is required. Treat allowed selected provider
fields as deliberate declassifications, not intrinsically secret-free.

**Exit:** kernel-checked relational statement with precise public initial
state, adaptive input relation, approved declassification premises, observed
channels, timing/termination exclusions, and positive/negative witness tests
against the same native profile.

### NR-5 — Assurance integration and independent review

**Owner:** independent reviewer + integration. **Dependencies:** NR-1..4.

Build a claim/evidence matrix for SINK-01, TRACE-01, NI-TRACE-01 and
IO-REFINE-01 (terminology from active work/W0). Include exact extracted
functions/source hashes, compiler and Lean pins, proof names/axioms, reviewed
I/O contracts, test runs and mutants, known concurrency/close/partial-send
limits, and a local positive successful operation. Reconcile trusted library
assumptions with evidence and independent review comments.

**Exit:** publishable **scoped conditional** read-only native assurance
statement; no omitted reachable guest sink, no unreviewed trusted assumption,
no inference about real KVM/TPM or live GitHub. If a condition cannot be
closed, narrow the claim and keep the corresponding task open rather than
invent an admission/completeness assumption.

## 5. Acceptance gates and iteration economics

Start with the cheapest meaningful check. All tests use fake credentials and
loopback servers. On code/test changes, avoid repeating the full native suite,
Aeneas extraction or Charon analysis unless the changed boundary warrants it.

```bash
# Portable models, source/fingerprint guards, adversarial reference oracles
python dev/verification/quick_w6_read.py

# Native mTLS/HTTPS observations; old binaries only when no Rust source changed
python dev/verification/quick_w6_read.py --native

# Incremental native build after Rust changes, then selected integration cases
python dev/verification/quick_w6_read.py --native --build

# Focused Lean kernel + exact named axiom check (must pass on pinned toolchain)
python dev/verification/read_prefixes.py prove

# Optional narrower per-area paths
python dev/verification/quick_w6_read.py --composition-only --native
python dev/verification/quick_w6_read.py --failure-only --native
python dev/verification/quick_w6_read.py --pending-only --native
```

NR-1 may require *additional* focused extraction, Lean and Rust tests to
validate its new source, not just these existing gates. Update the quick gate
when adding security-significant behavior; fail on accidental skips. If the
Lean source changes, update proof fingerprints **after review**, never to
conceal a failed theorem. The source checks print "kernel pending" by design;
`prove` produces the real kernel result.

The expensive
`python dev/verification/system.py --proofs --full-tests --call-linkage`
combines full Python/native, Lean and specialized Charon analyses and may
consume multi-gigabyte compiler output. Reserve it for a planned integration
checkpoint or the specific NR-3 closure that needs it. Its output is
additional evidence, not itself the NR-3 completeness or NR-2 simulation
proof. If it appears idle, inspect the stage log and compiler process before
assuming it is hung.

## 6. Risk register and decisions not to shortcut

| Risk | Decision / proof burden |
| --- | --- |
| A parallel, hand-written trace program drifts from production | Extract production-called Rust; prove correspondence to a *specification*, not two unrelated models |
| Missing callbacks, drop paths, side-effecting dependencies | Preserve unresolved compiler edges and contracts; minimize privilege to make review finite |
| Audit succeeds but provider never receives HTTP | Model audited-but-unsent separately; do not collapse audit into send |
| `write_all` partially emits data or fails before response | Distinguish attempted/received effects and uncertain guest result; do not infer absence from empty provider fixture |
| Revocation races a just-checked send | State the actual linearization point; do not promise retroactive cancellation |
| Semantic W5 equivalence hides public denial/timing leaks | Define declassification and observation precisely; model reflectionStatus and errors explicitly |
| Proof depends on `providerReached`/`auditOK` supplied by trusted test oracle | Establish adapter link or list these as retained assumptions; not a service-level theorem |
| Test/build/proof passes with skipped or stale binaries | Record non-skipped native test evidence, source hashes and generated-proof provenance |
| Implementing broader features distracts from first claim | Defer writes, general provider adapters, real OAuth, TPM and VM proof work unless necessary for the scoped read profile |

## 7. Cross-agent handoff contract

A new agent should first run `git status --short`, record `git rev-parse HEAD`,
read `AGENTS.md`, [active work](aivm-secrets-active-work.md), W0, this roadmap,
and the source/proof files named in section 3. Select exactly one NR task.
Avoid simultaneous edits to the native transition APIs, extracted Lean files
and shared W3 manifests by independent agents without a handoff. Parallelize
independent trace fixtures, adapter contract review and theorem planning
instead. Never run a credentialed real-provider operation as an implicit test.

In the PR/overlay description include:

1. **Task and claim:** NR ID, precise old/new contract, and whether evidence is
   type/source/test/kernel/implementation-refinement.
2. **Source link:** Rust paths, production call site, extraction pins,
   generated Lean provenance and reviewed source fingerprints.
3. **Acceptance:** exact commands/results, whether new native tests ran,
   relevant counterexample mutations, and any tests **not** run. Prefer fast
   focused gates while developing.
4. **Unresolved obligations:** list explicit trusted I/O contracts, excluded
   guest observations, concurrency and side effects; keep incomplete NR tasks
   open even when a subset is green.
5. **Next action:** one concrete acceptance failure or missing lemma for the
   next agent, with the best file/function to start from.

This roadmap is intentionally a plan with falsifiable acceptance conditions.
Do not add a new “verified” milestone just because another theorem compiles;
close the production-to-model link first.

## 8. Immediate next-agent assignment

**Issue: NR-0 acceptance replay, then NR-1 extraction.** The NR-0 source
freeze and targeted runner now exist; first reproduce the maintainer native and
Lean acceptance using the [NR-0 instructions](aivm-secrets-native-read-nr0-evidence.md).
If hashes differ, review the exact change rather than automatically accepting
new source. Then begin the first production-called Rust transition extraction
in NR-1; the evidence record names the precise seam.

**Original NR-0 acceptance definition:**
Before extending any Lean theorem, reconcile the checked-out Rust/Lean
revision and produce one compact provenance record for the chosen
`manifest-https-v1`, `writes=deny`, software-identity read configuration.
Show exactly how the guest is restricted to the modeled request and control
entry points; list reachable host-only authority, OAuth-lease, audit and
network sinks. Reproduce the portable W6, focused native read, and focused
Lean kernel/axiom gates on the checked-out tree. Record one successful
selected read, one denied request, one provider failure and one audited-but-
unsent trace, including provider arrivals and audit ordering. Describe any
skipped or unrun test rather than calling the profile verified.

**Definition of done:** reviewed profile/configuration, hashes and feature
flags, reproducible command results with no unexpected native skips,
assumption/sink crosswalk, and a proposed smallest production-called Rust
transition for NR-1. **Do not** create another independent formal trace
constructor and call that a native simulation. If the checkout already has a
fresh equivalent NR-0 evidence record, review it and proceed directly to
NR-1, linking that record in the new PR.
