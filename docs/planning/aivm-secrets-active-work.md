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
| **P0 / NR-1** | Connect real Rust read orchestration to a small extractable transition kernel | Production `Session::request` uses a single checked transition interface with explicit external audit, authority, provider and release outcomes. Extract the *same* Rust decisions to Lean and prove the first preservation/simulation lemma. | **Dispatch and completion preservation added.** Production uses extracted `prepare`, `acknowledge` and `complete_current`; thirteen focused obligations cover preservation and external completion outcomes. Provider-outcome/orchestration simulation remains pending; this is not complete NR-1. |
| **P0 / NR-2** | Establish admission/audit/send/release forward simulation | Relate extracted steps to `GarrettReadPaths`/`GarrettReadPrefixes` events for successful, failed and audited-but-unsent final-only, checked-only and two-phase reads. Include host-state/identity continuity and an authorized successful witness. | **Open**, depends on NR-1 |
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
