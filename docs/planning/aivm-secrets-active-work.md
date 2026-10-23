# Active work: proof-backed credential use for untrusted agents

**Current priority queue — reconciled 2026-10-21.** Start with the
[product outcome roadmap](aivm-secrets-product-roadmap.md) for the destination
and [W0](aivm-secrets-conditional-confinement.md) for the normative security
contract. This file alone orders the *next implementation work*. The detailed
[native read roadmap](aivm-secrets-native-read-assurance-roadmap.md) specifies
NR-0..NR-5 technical proof gates. For the current extended proof run, the
[overnight source-linked campaign](aivm-secrets-overnight-formalization.md)
provides the ordered tasks and maintainer-readable acceptance explanation.
Prior implementation/validation chronology
is in the [October 21 archive](aivm-secrets-active-work-history-2026-10-21.md),
[October 19 archive](aivm-secrets-active-work-history-2026-10-19.md), and
`dev/validation/`; don't append long milestone narratives here.

**North star:** A host-controlled broker holds provider credentials. An agent
in an untrusted AIVM guest invokes *specific authorized* provider actions,
gets only selected replies, and never receives the raw credential. Normal
AIVM use remains independent of the separately installed service. A system
that only denies operations fails the product goal. An authorized write is a
separate, more demanding claim than the first read-only proof profile.

## Status at the available source boundary

**Evidence basis:** the initial source archive `8986ce6` plus the applied
Track A/documentation/NR-0/VM overlays, and the maintainer's actual host report
of `python dev/verification/system.py` passing, both real `aivm-2404` KVM
acceptance modes passing and the corrected real GitHub read-only fixture
passing with 55 focused tests. The initial OUT-2 fixture was committed as
`b21e212`; the live OUT-3 fixture and correction were committed as `b465c16`.
On resumption inspect
`git status --short` and `git rev-parse HEAD`, but do not downgrade successful
user-reported Lean compilation for want of a pasted success log. The older
2026-10-21 frozen source record at `e741383` reports 3,116 Python tests and
102 Rust workspace tests; those counts describe that source boundary, not
new code.

| Work | Current state and exact remaining boundary |
| --- | --- |
| **OUT-0: useful offline broker** | **Demonstrated** with actual native authority/broker/guest, synthetic HTTPS, allowed read, denied write, audit and revocation. The [same-UID operator/guest workflow](../offline-native-operator-guest.md) is not a VM-isolation claim. |
| **NR-0: frozen native read profile** | **Initial baseline accepted** in the October 20 validation at `aeae955`; preserve its versioned profile/limitations, refresh only after source/config scope changes. |
| **NR-1: source-owned transition** | **Initial production-extraction gate accepted**: invocation, admission, dispatch, provider channel and completion now use extracted Rust decisions. This does not imply actual native I/O correspondence. |
| **NR-2: request/event simulation** | **In progress**: source-linked returned traces, writer callbacks, dispatch-to-writer composition. Production-instance theorems (2026-10-22) discharge `NativeContext` and the guest denial/success frame premises; see the [proof tour](../assurance/native-read-proof-tour.md#strongest-production-instance-statements-2026-10-22). Need the provider document parse and connected requests. |
| **NR-3: reachable I/O and adapter effects** | **In progress**: W3/W6 guards, route-bound bytes, zeroizing-buffer/channel seam, file-audit-before-write native witness. Need complete callback/drop/error reachability review and external std/DNS/TLS/serde/parser/storage contracts. |
| **NR-4 / NR-5** | **NR-4 in progress**: the extracted production read release is proved to depend only on the selected JSON and the pagination row count (`manifest_release_noninterference`). Adaptive histories over complete requests are proved (`adaptive_request_noninterference`). A [claim-to-evidence matrix](../assurance/claim-evidence-matrix.md) is ready for the NR-5 independent review; the baseline-comparator axiom audit remains. |
| **W8 / OUT-2** | **Real-VM native baseline passed**, reported by maintainer on `aivm-2404` (KVM, authenticated read/diff, 3 synthetic provider GETs, write denied, revocation, tested host paths inaccessible; fixture commit `b21e212`). [Adversarial extension](../aivm-vm-native-acceptance.md#opt-in-adversarial-extension-out-2-negative-witnesses) adds network canary, identity, mount and reconnect probes behind `--adversarial`; **the extension passed a maintainer-run real-VM test** (2026-10-21, four authorized synthetic provider GETs). The [optional native session contract](../aivm-native-session.md) and an opt-in, process-only AIVM flag (`aivm ssh --secrets_native_spec`) now exist and pass synthetic tests; a maintainer real-VM run through that adapter, full guest share analysis and the remaining negative tests remain open. |
| **W7 / OUT-3** | **Scoped live GitHub read-only acceptance passed** (maintainer real-VM report, 2026-10-21): 55 focused tests, `ok: true`, authenticated `/user`, bounded repository/README reads for `Erotemic/aivm-secrets`, denied out-of-scope repository and write, durable identity revocation (`invalid_capability`). The real provider does not supply an independent provider-side request transcript; `whole_service_secrecy_proved` remains false. See [OUT-3 evidence and opt-in instructions](../aivm-github-live-readonly-acceptance.md). Never use a live credential in CI. |
| **OUT-4** | **First increment (2026-10-23):** the exact-write gate is extracted (`write_gate::run_approved`), and `production_write_has_approval_and_authorized_attempts` ties a returned write to an `Allowed`, single-use approval and to authorized, audited, bound and unretried attempts (see the [proof tour](../assurance/native-read-proof-tour.md#out-4-first-increment-the-exact-write-gate-2026-10-23)). Still open: provider-side write semantics, uncertain outcomes across sessions, budgets and Python/Rust parity per operation. |
| **OUT-5** | **Open**: profile-specific claims/evidence, reproducible deployment and independent review before production-use claims. |

**Verification edge:** The maintainer has advanced through the Track A
native-dispatch Lean repairs and reports a successful full host usable-system
gate. Do not claim the prior Lean increment is unverified solely because a
successful `lake build` log was not pasted: compilation errors are reported
when present, and continuing to the next task is confirmation of success.
Track A's native I/O correspondence still has genuine formal and environmental
gaps as listed under NR-2/3. Both real KVM test modes (ordinary and adversarial)
have successful maintainer reports. The fixed live GitHub acceptance test
also **passed** on real KVM: three approved reads, out-of-scope/write denial,
and persisted identity revocation plus no additional broker dispatch. The
finite live acceptance is independent of NR-2/3/4 and does not prove the
whole service. The operator's next priority is formal assurance and personal
understanding before unattended, credential-bearing AIVM use.

## Active task queue

Next actions in priority order:

| Priority | Task and concrete deliverable | Acceptance / avoid |
| --- | --- | --- |
| **P0 (new, maintainer 2026-10-23) — OUT-6 HTTPS proxy profiles** | Follow [HTTPS proxy profiles](aivm-secrets-http-proxy-profiles.md): HP-0 schema/profile metadata, HP-1 Python `credential-substitution` reference proxy, HP-2 `constrained-http`, then HP-4/HP-5 extracted Rust and Aeneas proofs. Keep `named-operation` as the default and strictest profile. | Synthetic provider and credential only; adversarial parser/reflection/origin tests before claims; no silent fallback from constrained to substitution; per-credential opt-in; AIVM never requires it. Substitution must not claim authority confinement. |
| **P0 — overnight formalization / operator comprehension** | Execute the [source-linked campaign](aivm-secrets-overnight-formalization.md), starting at the actual `Session::request` -> `begin_send` -> channel seam. Produce checked, source-relevant proof increments and update the [maintainer proof tour](../assurance/native-read-proof-tour.md). | Every new theorem identifies precise Rust source, removes or documents security-bearing premises and covers meaningful failures. Preserve accepted previous compilation; no theorem-count targets, axiom dumps, self-certification or live credentials. |
| **P0 — NR-2/3 primitive-to-event link** | Connect native `Session::request` admission -> real audit-file acknowledgement -> late authorization -> provider writer/flush -> completion audit -> guest frame to existing `TraceSteps`/W4 events. Instantiate source-bound callbacks where possible; state real external I/O contracts. | Positive final/checked/two-phase read and denied/revoked/audit-failed/partial-write/flush-failed/replay witnesses; no assumed whole-provider history, fake arrival or unchecked I/O equivalence. See [Track A handoff](../native-dispatch-callback-observation.md). |
| **P0 in parallel — W8 / OUT-2** | The adversarial VM run has **passed**. Continue guest mount/share reachability (including aliases), unregistered/expired identities and a properly optional persistent AIVM adapter; do not re-run accepted validation as a substitute for this open work. | The prior baseline already passed on real KVM. The additional negative tests **passed on real KVM**; canary denial is not a proof of all forbidden egress. Normal AIVM must remain independent. |
| **P2 — provider independence (after core proof work)** | **Synthetic scope done (2026-10-22):** `tests/test_rust_second_provider.py` drives a package-registry-shaped service (different host, `x-api-key` authentication, nested selection, pagination) through the generic native `invoke` path with no provider-specific Rust; out-of-scope names, pages and operations never reach the provider. | A new real provider still needs separate operator opt-in. Existing OUT-3 GitHub read acceptance is complete at its stated scope and need not be rerun. |
| **P1 — NR-4, then NR-5** | Tie actual JSON projection, errors, metadata, frame lengths/EOF and sequential adaptive sessions to model observations; independently review claim/assumptions/source provenance at the end. | Precisely conditional noninterference, finite reviewed I/O boundary, positive allowed action. Final comparative axiom audit only, not per build. |
| **P2 — OUT-4** | Extend assurance to a single bounded write, approval and idempotency/uncertain-send behavior; track Python/Rust parity per operation. | Approved effect succeeds; denied effect never reaches provider; ambiguous success is never silently retried. |

Dependencies: NR-2 and NR-3 progress together, NR-4 requires both, NR-5
requires NR-1..4. W8 and W7 have **successful finite integration gates**,
but neither substitutes for the formal read claim. The operator chooses to
hold unattended credential-bearing AIVM deployment until the conditional
native claim and actual environment assumptions have been reviewed. OUT-4
is outside the first read-only proof target. See the
[product dependencies](aivm-secrets-product-roadmap.md#outcome-gates-and-dependencies).

## Fast feedback and handoff

Use only gates relevant to the change; document-only edits need link/status
checks, not a full native build. Typical focused commands from repo root:

```bash
python3 dev/verification/quick_w6_read.py
python3 dev/verification/w3_effect_boundary.py check
python3 dev/offline_native_guest.py             # when changing product behavior

# After changes to the Rust writer or dispatch implementation:
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib \
  native_read_dispatch_audit_to_writer_callback_chronology

# Focused proof build when the native dispatch trace changes:
cd proofs
lake exe cache get
lake build GarrettNativeDispatchEvents
```

Compilation is the routine Lean gate. Do **not** add `#print axioms`, bulk
`#check` output or repetitive `sorry`/`admit` scans to development builds.
An opt-in transitive axiom **comparison** belongs to final NR-5 review; see
`../../AGENTS.md`. Run broader native/process suites after related Rust changes,
and full system/Charon call-linkage checks at explicit integration points,
not on routine documentation or pure Lean edits.

For each new overlay/PR, report the changed production boundary and source
revision, precise claim and proof module, assumptions retained, positive and
negative native witness, tests passed/**not run**, and one next concrete task.
Check the current tree instead of assuming an overlay was applied or committed.
Move dated validation detail into `dev/validation/` or a focused note rather
than extending this queue with progress prose. Follow the
[product roadmap](aivm-secrets-product-roadmap.md) when choosing work outside
the restricted native read proof campaign.
