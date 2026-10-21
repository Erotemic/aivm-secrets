# Active work: Garrett broker security and useful native workflows

**Current priority queue — reconciled October 19, 2026.** This is the entry point
for agents deciding **what to implement next**. For the detailed first campaign,
read [Native read-profile assurance roadmap](aivm-secrets-native-read-assurance-roadmap.md)
*before* editing code. Earlier rolling milestone narratives are preserved in
[the October 19 history archive](aivm-secrets-active-work-history-2026-10-19.md);
that archive is not a second current task queue.

**October 20 acceptance update:** source `aeae955` preserves the maintainer's
21 incoming commits and passes 2,976 full-suite tests, 543 required workflows
in both build modes, packaging, the offline native product witness and scoped
Lean checks. See the [frozen validation record](../../dev/validation/2026-10-20-main-reconciliation.json)
and [consolidation notes](../main-reconciliation-2026-10-20.md). This frozen
acceptance is separate from the NR-1 increment below.

**October 20 NR-1 increment:** [dispatch/completion preservation](../garrett-read-completion-preservation.md)
adds thirteen source-linked extracted Rust obligations and a production
completion controller. It closes full freshness checks after the last provider
response and after completion audit. An opt-in installed-vTPM witness now
exercises native CSR/enrollment/mTLS/provider use. This advances NR-1;
provider-outcome/orchestration simulation and NR-2–NR-5 remain open.
Source `304b5eb` passed 2,999 full-suite tests without skips, the 413-name
Garrett axiom audit, four new re-extracted bypass mutants, scoped read proofs,
both native product build modes and the five-case installed-vTPM witness.
See the [increment validation record](../../dev/validation/2026-10-20-read-completion.json).

**NR-1 orchestration update:** the [actual post-admission request kernel](../garrett-native-request-orchestration.md)
now selects preflight/final phases, consumes provider/error outcomes, and
chooses completion input in production Rust. The expanded 25-obligation proof
characterizes successful returned data and failure propagation. This supplies
the pure orchestration and initial preservation exit of NR-1. The next task
is NR-2's invocation/event relation; result equality alone does not account for
all native I/O calls. The NR-3/4/5 and W7/W8 gates remain open.
Source `64d3caa` passes 3,000 full-suite cases without skips, 425 named axiom
audits, four new orchestration mutants, both native product modes, packaging
and six installed-vTPM cases including manifest read/deny/revoke. See the
[orchestration validation record](../../dev/validation/2026-10-20-request-orchestration.json).

**Stateful invocation update:** the production `run_current` now constructs,
executes and consumes a private mutable invocation. Invalid or extra wrapper
calls halt it, and a saved success cannot pass the consuming gate afterward.
The [33 focused obligations](../garrett-native-request-orchestration.md) include
exact receipt states and the production entry's success characterization.
NR-2 remains open: accepted wrapper prefixes still need the actual native
adapter/effect relation and W4/W5 event simulation. In particular, the wrapper's
raw callback internals retain an explicit source-review boundary.
Source `11e0a5a` passes 3,003 full-suite cases without skips, 433 named axiom
checks, eight targeted re-extracted mutants, both native product modes,
packaging with all 254 manifest inputs intact and six installed-vTPM cases.
See the [invocation validation record](../../dev/validation/2026-10-20-request-invocations.json).

**Provider continuation update:** the [production staged provider driver and
conditional simulation](../garrett-provider-exchange-simulation.md) now separate
TLS setup, actual current-stamp construction, submission and parsing. The native
write helper owns an extracted single-attempt state, including failed and partial
submissions. Thirty focused obligations cover returned callback/channel states,
W4 provider-event extension under explicit local primitive contracts and binding
preservation. This advances one NR-2 component; native primitive/I/O contract
instantiation, full request/history simulation and NR-3/4/5 remain open.
Source `e2cd788` passes 3,005 full-suite cases without skips, 463 named axiom
checks, six targeted source-extracted mutants, both native product modes,
packaging with all 259 manifest inputs intact and six installed-vTPM cases.
See the [provider validation record](../../dev/validation/2026-10-20-provider-exchange.json).

**Request-wide receipt update:** the [production effect gate and conditional
request composition](../garrett-request-effect-receipts.md) now record actual
dispatch/completion acknowledgements and a composite phase/current send gate.
Effectful callbacks carry their actual mutable post-state, including failures.
The existing 33 obligations retain their generality; new reachable-record
invariants compose with the actual request entry under explicit local adapter
contracts. Complete W4/W5 event/history correspondence, native contract
instantiation and NR-3/4/5 remain open.

Source `6cc5724` passes 3,017 full-suite cases with zero skips, 492 named
axiom checks, five selected final-source mutants, both native product modes,
71 Rust workspace cases, all 263 source-archive pins and six safe installed-vTPM
cases. See the [request-effect validation record](../../dev/validation/2026-10-20-request-effects.json).

**All-returned prefix update:** the [actual controller's failure-prefix and
receipt-event composition](../garrett-returned-request-traces.md) now covers all
returned outcomes. Exact occupied-prefix invariants exclude sticky-bit audit
replay; source-gate counting, checked-stamp origin and captured binding feed a
conditional W4 audit/provider/denial projection. Six native fsync/revocation
cases retain an acknowledged completion audit while denying the actual guest,
after a prior permitted success. Native callback/primitive instantiation,
selected-value/framing correspondence, connected adaptive histories and
NR-3/4/5 remain open.

Source `c70dc78` passes 3,023 full-suite cases with zero skips, 521 named
axiom checks, 54 focused receipt/prefix/trace and 37 request obligations,
767 release parity cases, three new repeat-audit mutants, both 164-case native
build-mode gates and product workflows, all 268 archive pins and six safe
installed-vTPM cases. See the [returned-prefix validation record](../../dev/validation/2026-10-20-returned-request-traces.json).

**Outbound frame update:** the [actual native reply encoder and attempt gate](../garrett-outbound-guest-frame.md)
now bound the complete newline-terminated wire before writing and reject a
second application attempt after any returned send result. Nine extracted
production obligations connect admitted payload bytes to the writer callback
and preserve errors and mutable state. Selected-value/JSON correspondence,
TLS/close observations, native primitive instantiation and NR-2–NR-5 remain open.

Source `29ddf1e` passes 3,029 full-suite cases with zero skips, 530 named
axiom checks, 767 release parity cases, 74 Rust workspace cases, six new
source-extracted mutants, both 164-case native build-mode gates and product
workflows, all 270 archive pins and six safe installed-vTPM cases. The first
concurrent full run's one-second Python grant timing failure is retained;
the unchanged isolated case and final clean-load full rerun pass. See the
[outbound frame validation record](../../dev/validation/2026-10-20-guest-frame.json).

**Owned completion update:** the [production completion adapter and request composition](../garrett-owned-completion.md)
now establish receipt steps and the selection/check/audit/check origins from
extracted code. Twenty obligations include exact returned error state, native
report/outcome linkage and integration with the actual request entry; the prior
whole-completion Steps/success-gate premises are derived under that linkage.
Native link/primitive instantiation, dispatch, selected JSON/frame observations,
connected adaptive histories and NR-2–NR-5 remain open.

Source `259d8d3` passes 3,031 full-suite cases with zero skips, 550 named
axiom checks, 767 release parity cases, 76 Rust workspace cases, eight selected
source-extracted mutants, both 164-case native build-mode gates and standalone
product workflows, all 273 archive pins and six safe installed-vTPM cases. See
the [owned-completion validation record](../../dev/validation/2026-10-20-owned-completion.json).

**Owned dispatch update:** the [production dispatch controller and request composition](../garrett-owned-dispatch.md)
now own audit, admission/reservation, provider/local attempt and finish gates.
Twenty-four obligations cover all returned receipt paths, exact returned state,
refusal prefixes, positive reads in both phases and composition with owned
completion. Whole-dispatch and whole-completion receipt assumptions are derived
under explicit native report/copy/outcome links. Instantiating those links and
primitive/context contracts, selected JSON/frame observations, connected
adaptive histories and NR-2–NR-5 remain open. Validation is recorded separately
for the committed source; prior frozen evidence retains its original scope.

Source `3e51590` passes 3,031 full-suite cases with zero skips, 574 named
axiom checks, 767 release parity cases, 79 Rust workspace cases, seven new
source-extracted mutants, both 164-case native build-mode gates and standalone
product workflows, all 276 archive pins and six safe installed-vTPM cases.
The updated optional specialized bridge capture finds eight required paths;
its 42 fixture/capture tests pass, with no mediation claim. See the
[owned-dispatch validation record](../../dev/validation/2026-10-20-owned-dispatch.json).

**Owned request update:** the [actual production request adapter](../garrett-owned-request.md)
now owns its receipt across both extracted effect controllers, prepares exact
phase/write authority and returns the core's private completed value. Fourteen
obligations derive all former whole-callback receipt/readiness and outer-check
frame contracts, exact report and selected-value origins, consuming-entry
reachability and a positive final-read witness. Native report/copy/outcome links
are no longer premises for this producer. Primitive/context, native event/JSON/
frame observation, connected adaptive history and NR-2–NR-5 remain open.

Source `db55279` passes 3,036 full-suite cases with zero skips, 588 named
axiom checks, 767 release parity cases, 82 Rust workspace cases, eight new
source-extracted mutants, both 164-case native build-mode gates and standalone
product workflows, all 278 archive pins and six safe installed-vTPM cases.
The updated optional specialized bridge capture finds nine required paths;
47 ledger fixture/capture cases pass without a mediation claim. See the
[owned-request validation record](../../dev/validation/2026-10-20-owned-request.json).

**Current admission update:** the [actual bound admission controller](../garrett-current-admission.md)
now owns coordination/clock/control/lease/identity/grant validation order in
production Rust. Twenty-four extracted obligations derive stamp origin and
preserve the captured context through the read provider driver, including its
actual owned-send wrapper and failed prefixes. Native primitive semantics,
whole-request event/history simulation and NR-2–NR-5 remain open.

Source `6cfb8a6` passes 3,046 full-suite cases with zero skips, 612 named
axiom audits, 767 release parity cases, 85 Rust workspace cases, six targeted
source-extracted mutants, both 168-case native build-mode gates and standalone
product workflows, all 280 archive pins and six safe installed-vTPM cases.
The fresh optional specialized bridge capture retains nine paths and passes
47 fixture/capture cases without a mediation claim. See the
[current-admission validation record](../../dev/validation/2026-10-20-current-admission.json).

**Owned-controller trace update:** [actual dispatch/completion/request traces](../garrett-owned-request-traces.md)
now compose source-derived stamp origin and chronological receipt gates through
all returned outcomes of the actual request entry. Twenty-three new obligations
remove whole-current and whole-dispatch/completion history premises. The precise,
state-indexed native constructor/typeclass/context-frame input contract remains
uninstantiated; native primitive/I/O, selected JSON/frame/close and adaptive
history correspondence and NR-2–NR-5 remain open.

Source `f3ba897` records 3,046 full-suite cases with zero skips, 635 named
axiom audits, 767 release parity cases, 85 Rust workspace cases, two selected
source-extracted mutations rejected in dispatcher prerequisites, both 168-case
native build-mode gates, both standalone product workflows and six safe
installed-vTPM cases. All 283 source-archive inputs and the embedded manifest
match. The record distinguishes the final proof EOF normalization/re-audit
from the unchanged-runtime full-suite result, and retains prior read-prefix/
optional compiler evidence only after verifying its exact source pins. See the
[owned-controller trace validation record](../../dev/validation/2026-10-20-owned-controller-traces.json).

**Source-owned context update:** the [production request context/factory wrapper](../garrett-request-context.md)
now keeps the captured context private and constructs the canonical bound
provider after the raw factory returns. Ten extracted obligations derive every
former `NativeContext` clause, exact factory order/post-states/keyed-write bits,
planning/denial forwarding and the actual constructor/controller/consuming-entry
trace and selected-value origin. Native factory context preservation is no
longer a premise for this producer. Startup/input conversion, native primitive/
I/O, selected JSON/frame/close and adaptive-history correspondence remain open;
this is not an NR-2–NR-5 exit.

Source `cde04b3` passes 3,053 full-suite cases with zero skips, 645 named
axiom audits, 767 release parity cases, 86 Rust workspace cases, four selected
source mutations rejected in the new context-wrapper proof, both 168-case
native build-mode gates and standalone product workflows, all 285 archive pins
and six safe installed-vTPM cases. Focused read-path/prefix proofs pass against
the new extraction. The fresh optional compiler capture retains ten required
paths and 48 fixture cases, without a mediation claim. See the
[request-context validation record](../../dev/validation/2026-10-20-request-context.json).

**Captured provider I/O update:** the [production routed provider and request
submission](../garrett-provider-io.md) now capture the admitted grant route,
forward it to setup/audit, and own the zeroizing native request buffer through
an extracted one-attempt writer controller. Twenty additional obligations cover
exact arguments/post-states, route preservation and all returned write/flush
prefixes. The native raw setup/audit/current paths refuse direct use. This
advances the primitive seam without proving complete native I/O correspondence.

Source `87f5313` passes 3,061 full-suite cases with zero skips, 665 named
axiom audits, 767 release parity cases, 88 Rust workspace cases, six selected
source-extracted mutations rejected in the provider-I/O leaf, both 168-case
native build-mode gates and standalone product workflows, all 287 archive pins
and six safe installed-vTPM cases. Focused read-path/prefix proofs pass against
the final extraction. The fresh optional compiler capture retains eleven paths,
including actual captured submission to the native writer, and 49 fixture cases
without a mediation claim. See the
[provider-I/O validation record](../../dev/validation/2026-10-20-provider-io.json).

**Owned provider channel update:** the [production captured channel and
response gate](../garrett-provider-channel.md) now own request/writer/lifetime
state in extracted Rust. Eleven obligations derive exact fields and post-states,
failed/repeated-submission refusal and the actual successful write/flush origin
of released response parts. Native receive must consume this gate before
parsing.

Source `7d1069d` passes 3,071 full-suite cases with zero skips, 676 named
axiom audits, 767 release parity cases, 91 Rust workspace cases, six selected
source mutations rejected in the channel leaf, both 168-case native build-mode
gates and standalone product workflows, all 288 archive pins and six safe
installed-vTPM cases. Eight read-path and five prefix kernel audits pass.
The fresh optional compiler capture retains twelve paths and 51 fixture cases,
including native receive to the actual response-parts gate, without a mediation
claim. See the
[channel validation record](../../dev/validation/2026-10-20-provider-channel.json).

**Route-bound encoder update:** the [production route/byte/endpoint producer](../garrett-provider-wire.md)
now binds Host, checked port and authentication in extracted Rust and returns
an immutable endpoint only after complete encoding. Native TCP/TLS setup uses
that endpoint. Twelve obligations derive exact bounded bytes and compose actual
encoding with channel write/flush origin under the explicit local buffer-view
contract.

Source `1b58b20` passes 3,083 full-suite cases with zero skips, 688 named
axiom audits, 767 release parity cases, 94 Rust workspace cases, six selected
source mutations rejected in the route/encoder leaf, both 168-case native
build-mode gates and standalone product workflows, all 290 archive pins and
six safe installed-vTPM cases. Eight read-path and five prefix kernel audits
pass. The fresh bounded compiler capture retains fourteen paths and 53 fixture
cases, including native endpoint getters, without a mediation claim. See the
[route/encoder validation record](../../dev/validation/2026-10-21-provider-wire.json).

**JSON string refinement update:** the [production scalar-list string encoder](../garrett-json-string.md)
now supplies native canonical JSON string quoting. Twenty-nine extracted
obligations establish scalar admission, lowercase escapes and surrogate pairs,
exact bounded appended bytes, invalid-input buffer preservation and printable
output without raw line breaks. Exhaustive Rust scalar coverage and native
nested JSON fixtures check the preserved wire behavior. Native UTF-8/scalar and
byte/String conversion remain explicit local contracts; this does not discharge
JSON containers/numbers, parsing, observation or whole-service secrecy.

The next implementation task remains native primitive correspondence: connect
native UTF-8/scalar and byte/String conversion, header and remaining JSON
conversion, faithful zeroizing buffer view and
std/TLS/DNS/parser/storage contracts to the now-source-derived endpoint, complete
request bytes and channel submission/release. Relate the actual native outcomes
to the existing all-returned event projection. Keep trusted TLS/DNS/Write/parser and storage semantics
explicit, and connect actual source parameters and returned states rather than
adding a whole-provider-history, fake-arrival or whole-service mediation premise.
The JSON/frame observation and sequential-session history obligations remain in
the queue; another inventory is not their replacement.

## Goal and present assurance level

Garrett should let an untrusted guest perform **useful, explicitly authorized**
provider operations using credentials retained by the trusted broker, without
learning those credentials or causing unauthorized credentialed I/O. An
always-denying broker is not a satisfactory implementation. The first assurance
target is a **native Rust, `manifest-https-v1`, read-only, sequential** profile
with synthetic provider credentials, pinned TLS endpoints, and reviewed
host-owned policy/disclosure. This is a deliberately restricted first claim,
not a claim about arbitrary Garrett configurations or deployed VMs.

As of this reconciliation:

- **Functioning code:** Python and Rust synthetic broker/guest workflows,
  host-side custody, surrogate/certificate binding, native policy-controlled
  manifest requests, audited dispatch, late admission, completed-release gating,
  selected disclosure and JSONL guest replies exist. The October 20 record
  freezes actual native/full-suite acceptance at `aeae955`. It certifies only
  its recorded source and checks; later revisions require fresh validation.
- **Finite implementation evidence:** independent W6 oracles and native process
  tests cover successful no-preflight/checked-only/two-phase reads, selected
  result and pagination metadata, provider failures, private diagnostic
  mutations, audited-but-unsent requests, late revocation and sequential
  history. Some new native cases were rerun during follow-up debugging; a
  passing *portable* check must never substitute for running required native
  cases without skips.
- **Kernel-checked models:** the frozen October 20 run passed
  `python dev/verification/read_prefixes.py prove` after repairing a kernel
  recursion failure in the read-prefix list proof. Its W4/W5 prerequisites and the scoped eight
  read-path and five read-prefix theorem sets are **abstract and conditional**.
  `read_paths.py check` and `read_prefixes.py check` deliberately still say
  "kernel required/pending": those portable actions inspect *source*, do not
  run the Lean kernel, and cannot certify another checkout. The proof-scope
  JSON `status` values are gate semantics, not a contradiction of a reported
  successful `prove` run.
- **Not established:** a universal correspondence from actual native
  execution and all guest-reachable I/O to those abstract traces; complete
  transitive W3 sink/callback/drop coverage; all concrete guest-observable
  channel semantics; physical TPM custody, real provider compatibility,
  deployed VM isolation, or a whole-service noninterference theorem.

The precise security contract is
[W0 conditional confinement](aivm-secrets-conditional-confinement.md), with
[machine-readable boundaries](aivm-secrets-w0-boundaries.json) and the
[assumption ledger](aivm-secrets-assumptions.json). The existing
[W3 reachability](aivm-secrets-w3-reachability.json),
[W4 proof](aivm-secrets-w4-proof-scope.json),
[W5 proof](aivm-secrets-w5-proof-scope.json), and
[W6 adapter](aivm-secrets-w6-adapters.json) manifests retain their exact
narrow meanings. The two newer
[read-path](aivm-secrets-read-path-proof-scope.json) and
[read-prefix](aivm-secrets-read-prefix-proof-scope.json) manifests are
**source guards plus an optional kernel gate**, not native-I/O proof records.

## Product-first anti-drift checkpoint

The original goal is **useful and safe credential use by an untrusted agent**:
a host operator grants specific operations; the standalone broker retains the
provider credential; the guest invokes them without accessing that credential;
unapproved requests do not cause credentialed provider effects. The initial
GitHub pull-request workflows are one concrete compatibility goal. Proofs
matter because they must justify the *running broker*, not because every
possible helper model or test ledger deserves to be built.

Before accepting a new assurance work package, require at least one concrete
advance: (1) a usable host/guest operation or operator workflow, (2) production
Rust enforcement of a previously open security boundary, or (3) a
kernel-checked, implementation-linked result that discharges a named open
obligation. A new source fingerprint, test inventory, abstract theorem, or
synthetic counterexample alone is **supporting evidence**, not a new major
milestone. Add those only when they directly enable one of the three outcomes.

The standalone [offline operator/guest executable](../offline-native-operator-guest.md)
now supplies this product witness using real Rust binaries, host-held synthetic
credential and an operator-driven revocation. It must pass on a native-equipped
checkout before calling the checkpoint complete. It does not validate OS/VM
isolation; do not mistake `host/` versus `guest/` folders for access control.

Maintain an **offline product acceptance witness in parallel with NR-1–NR-4**:
from an independently configured guest, call an allowed GitHub-shaped read
through a real standalone broker to a local synthetic HTTPS provider; deny an
unapproved operation; confirm the host credential is absent from the guest,
selected output and guest-accessible logs; revoke and confirm subsequent
admission fails. Record required setup and actual CLI interface, not only
internal test fixtures. This is a practical acceptance gate, **not** a claim of
VM isolation or whole-service secrecy. Use no real provider credentials or
external service in this stage. A physical VM deployment and real provider
validation remain W8 and W7 respectively.

After collecting one NR-0 baseline, proceed to NR-1. Do not repeatedly
expand NR-0 metadata unless a concrete source/configuration change makes its
evidence incorrect. Balance the next round's work between the production
transition extraction and this offline user workflow, rather than continuing
to grow source guards.

## Active task queue

| Priority | Work package | Deliverable / acceptance evidence | State |
| --- | --- | --- | --- |
| **P0 / NR-0** | Freeze native read profile and evidence baseline | Identify the checked-out commit, exact source/feature profile, full list of guest and provider effects, verified successful/denied synthetic witnesses and reproducible focused gates. Name all excluded configurations. | **Baseline locally accepted at `aeae955`**: 31 source pins, all W0 sinks, no-skip native workflows and focused Lean checks passed in the October 20 record. Inventory and tests remain evidence, not native I/O refinement |
| **P0 / guest utility** | Reproduce the actual standalone guest-to-broker workflow offline, beyond internal Rust test fixtures | A documented operator+guest run with a synthetic host-held credential, a permitted selected GitHub-shaped read, broker-denied write, host audit, no credential in the distributed guest files, and a revocation check | **Native witness passed at `aeae955` in both builds**: `python dev/offline_native_guest.py`, [workflow documentation](../offline-native-operator-guest.md). Selected reads, denied write, credential absence in guest files and revocation succeeded. Same-UID demo is not isolation. |
| **P0 / NR-1** | Connect real Rust read orchestration to a small extractable transition kernel | Production `Session::request` uses a single checked transition interface with explicit external audit, authority, provider and release outcomes. Extract the *same* Rust decisions to Lean and prove the first preservation/simulation lemma. | **Pure orchestration and initial preservation locally checked.** Production uses `run_current` with private mutable invocation tracking and extracted dispatch/completion controllers; 37 obligations cover exact result origins, receipt states, the consuming gate, errors, freshness and uncertainty. Native callback invocation/effect correspondence is the next NR-2/3 obligation. |
| **P0 / NR-2** | Establish admission/audit/send/release forward simulation | Relate extracted steps to `GarrettReadPaths`/`GarrettReadPrefixes` events for successful, failed and audited-but-unsent final-only, checked-only and two-phase reads. Include host-state/identity continuity and an authorized successful witness. | **Open**; the actual owned request adapter derives all returned receipt paths and selected-value origin without whole-callback or native report-link assumptions. The source-owned controllers derive all returned audit/provider-attempt/denial histories and stamp origin; the context wrapper derives its native context-input clauses; startup/conversion, primitive/I/O semantics, selected JSON/frame and session-history correspondence remain open. |
| **P0 / NR-3** | Close W3/W6 actual-I/O boundary for the restricted native profile | Enumerate guest-reachable effectful call paths (including callback, error, drop and dependency boundaries). Prove source-owned paths or assign explicit external contracts. Relate emitted HTTP/audit/guest frames to modeled events and acknowledge ambiguity of partial sends. | **Open**; develop alongside NR-1/2, final integration depends on both |
| **P1 / NR-4** | Complete W5 guest observation/declassification correspondence | Define exact public response fields, errors, metadata, reflection-denial bit, lengths/close behavior and adaptive sequential input model. Prove only the relational property supported by explicit declassification premises; list excluded channels. | **Open**; depends on NR-2/3 |
| **P1 / NR-5** | Integrate and independently review a scoped assurance claim | Reproducible evidence manifest, all proof axioms/assumptions, one real local successful operation, negative mutants, all profiled sinks accounted for, recorded limitations and review sign-off. | **Open**, last gate for the native read claim |

These are **dependency-ordered outcomes**, not estimates, timeboxes, or a
promise that each fits one overlay. NR-1 should be small enough to validate
incrementally; do not defer correctness until a monolithic proof exists. Exact
work packages and acceptance failures are in the
[native read assurance roadmap](aivm-secrets-native-read-assurance-roadmap.md).

```text
           W0 scope, assumptions, selected native read configuration
                                  |
                  NR-0 baseline / observation inventory
                                  |
                       NR-1 Rust/extracted step
                          /               \
             NR-2 simulation           NR-3 W3/W6 effect closure
                          \               /
                       NR-4 W5 observed NI
                                  |
                       NR-5 reviewed claim

W1/W2: usable synthetic workflows (existing, maintain positive witnesses)
W7: opt-in LIVE read-only provider validation (afterward; not offline gate)
W8: deployment compartment evidence (independent downstream gate)
```

## Practical boundaries and deferred work

**In this first proof profile:** native Rust `manifest-https-v1` with
host-owned `writes=deny` and read-only selected operations, real local mTLS
and synthetic HTTPS provider, no-preflight/checked-only/two-phase operation
shapes, sequential session histories, current grant/epoch checks, host audit,
allowed public release, fixed public errors, and revoke/deny transitions.
This is an **intended narrowed runtime configuration**: NR-0 must demonstrate
that unmodeled write, alternate profile, or privileged controls cannot be
reached through the selected guest interface rather than assume so.

**Not required for this first claim:** proving KVM/Linux/rustls/cryptography,
physical TPM attestation, live GitHub/OAuth compatibility, coordinating
writes/approvals/retry reservations, Python/Rust whole-core parity, cross-host
coordinator/failover, generic plugins, or extending to every native profile.
These remain valuable independent efforts; their existing code is retained.
Host-only OAuth lease validation, coordination and administrative boundaries
must still be inventoried if reachable in the selected configuration. A
feature's exclusion from a theorem is not permission to ignore a reachable
sink that could violate that theorem.

**W7** remains opt-in live-provider compatibility using deliberately limited,
disposable credentials. **W8** separately validates real guest/host filesystem,
privileged socket, identity, and network compartment assumptions. Neither is
a prerequisite for the offline NR-1–NR-4 proof campaign, and neither may be
inferred from successful synthetic tests.

## Minimum fast feedback before a handoff

Run only gates relevant to changed sources; do not invoke the multi-gigabyte
Charon/compiler-linkage capture after a documentation or pure Lean edit.

```bash
# Portable scope, W3/W6 source inventories, and read-oracle regressions:
python dev/verification/quick_w6_read.py

# Existing native binaries; run when native behavior/trace contracts change:
python dev/verification/quick_w6_read.py --native

# Focused kernel + named axiom audits for read paths/prefixes:
python dev/verification/read_prefixes.py prove

# Build binaries only when Rust changed (and then re-run native):
python dev/verification/quick_w6_read.py --native --build
```

The portable `check` result is **not** a Lean proof result. The `--native`
runner requires fresh binaries and rejects skips; its mtime check is not
binary provenance. For boundary/source-linkage changes, run the matching
focused Cargo/Lean/extraction steps and schedule the heavyweight
`python dev/verification/system.py --proofs --full-tests --call-linkage`
**at a deliberate integration/release checkpoint**, not automatically on
all increments. Record its large artifact, open compiler edges and limits;
its passing result is still not a transitive reachability theorem. The
ordinary `--proofs --full-tests` is also a periodic integration gate, not a
substitute for NR-1/NR-2 proof evidence.

## Agent handoff and completion discipline

An agent resuming work should first read this file, the
[native read roadmap](aivm-secrets-native-read-assurance-roadmap.md), W0,
`AGENTS.md`, the relevant `docs/verified-w{3,4,5,6}*` reports and the named
Rust/Lean source. Inspect `git status`, the source commit, enabled features,
and **actual** verification logs; do not infer that an uncommitted overlay was
merged. Preserve independent Python provider policy behavior unless a
reviewed protocol/version change requires otherwise.

For every PR/overlay: identify the NR task and claimed property, source files
and trust boundary changed, exact extracted Rust source and generated Lean
provenance, proofs and assumptions, passing **and unrun** gates, deliberate
counterexamples, known failure/revocation/concurrency paths, and the next
unresolved step. Do not conflate type privacy, source-pattern guards,
compiler call-path witnesses, finite tests, model-level proofs, or a
runtime-refinement theorem. A reviewable narrowing of a claim is better than
an unfounded stronger claim. Historical implementation details remain in the
[archive](aivm-secrets-active-work-history-2026-10-19.md).
