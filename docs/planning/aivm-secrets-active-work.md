# Active work: proof-backed credential use for untrusted agents

**Current priority queue — reconciled 2026-10-21.** Start with the
[product outcome roadmap](aivm-secrets-product-roadmap.md) for the destination
and [W0](aivm-secrets-conditional-confinement.md) for the normative security
contract. This file alone orders the *next implementation work*. The detailed
[native read roadmap](aivm-secrets-native-read-assurance-roadmap.md) specifies
NR-0..NR-5 technical proof gates. Prior implementation/validation chronology
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
of `python dev/verification/system.py` passing and real `aivm-2404` KVM
acceptance passing. The original OUT-2 fixture was committed as `b21e212`;
the new `--adversarial` mode has not yet run on the VM. On resumption inspect
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
| **NR-2: request/event simulation** | **In progress**: source-linked returned traces, writer callbacks, dispatch-to-writer composition. Need actual native primitive/result instantiation, connected requests and proof of the whole scoped observation mapping. |
| **NR-3: reachable I/O and adapter effects** | **In progress**: W3/W6 guards, route-bound bytes, zeroizing-buffer/channel seam, file-audit-before-write native witness. Need complete callback/drop/error reachability review and external std/DNS/TLS/serde/parser/storage contracts. |
| **NR-4 / NR-5** | **Open**: guest observation/noninterference linkage including adaptive histories; then reviewed conditional claim and baseline-comparator audit. |
| **W8 / OUT-2** | **Real-VM native baseline passed**, reported by maintainer on `aivm-2404` (KVM, authenticated read/diff, 3 synthetic provider GETs, write denied, revocation, tested host paths inaccessible; fixture commit `b21e212`). [Adversarial extension](../aivm-vm-native-acceptance.md#opt-in-adversarial-extension-out-2-negative-witnesses) adds network canary, identity, mount and reconnect probes behind `--adversarial`; **that extension has no operator run reported yet**. Full guest share analysis and optional adapter remain open. |
| **W7 / OUT-3** | **Open**: opt-in disposable-credential live GitHub compatibility; not an automatic CI or development requirement. |
| **OUT-4** | **Open formal assurance** for precisely authorized writes, approvals, budgets, uncertain retries and normative Python/Rust semantics. Existing implementations are not covered by the read theorem. |
| **OUT-5** | **Open**: profile-specific claims/evidence, reproducible deployment and independent review before production-use claims. |

**Verification edge:** The maintainer has advanced through the Track A
native-dispatch Lean repairs and reports a successful full host usable-system
gate. Do not claim the prior Lean increment is unverified solely because a
successful `lake build` log was not pasted: compilation errors are reported
when present, and continuing to the next task is confirmation of success.
Track A's native I/O correspondence still has genuine formal and environmental
gaps as listed under NR-2/3. The real VM positive smoke test now has an actual
successful user report; only the new adversarial mode lacks a VM run.

## Active task queue

Next actions in priority order:

| Priority | Task and concrete deliverable | Acceptance / avoid |
| --- | --- | --- |
| **P0 — finish current Track A increment** | On the current checkout, build `GarrettNativeDispatchEvents`; fix any actual failure without changing the security statement to hide it. Close or record remaining writer/event composition premises. | Pinned Lean build passes; report actual result and any assumptions. No routine axiom dumps. |
| **P0 — NR-2/3 primitive-to-event link** | Connect native `Session::request` admission -> real audit-file acknowledgement -> late authorization -> provider writer/flush -> completion audit -> guest frame to existing `TraceSteps`/W4 events. Instantiate source-bound callbacks where possible; state real external I/O contracts. | Positive final/checked/two-phase read and denied/revoked/audit-failed/partial-write/flush-failed/replay witnesses; no assumed whole-provider history, fake arrival or unchecked I/O equivalence. See [Track A handoff](../native-dispatch-callback-observation.md). |
| **P0 in parallel — W8 / OUT-2** | Run `python dev/aivm_vm_acceptance.py --vm aivm-2404 --adversarial` on a fresh private workspace and record its redacted result. Investigate any failed host TCP canary, wrong-subject, out-of-scope read, or tunnel-reconnection check rather than weakening it. Continue guest mount/share review and an optional adapter. | The prior baseline already passed on real KVM. The new negative tests require their own actual VM evidence; canary denial is not a proof of all forbidden egress. Normal AIVM must remain independent. |
| **P1 in parallel — W7 / OUT-3** | Prepare an opt-in real GitHub read smoke with operator-created disposable, narrow-scope token and recorded exact requests/results. | Only run after explicit operator opt-in; never place credentials into agent logs or source. No live API calls in ordinary CI. |
| **P1 — NR-4, then NR-5** | Tie actual JSON projection, errors, metadata, frame lengths/EOF and sequential adaptive sessions to model observations; independently review claim/assumptions/source provenance at the end. | Precisely conditional noninterference, finite reviewed I/O boundary, positive allowed action. Final comparative axiom audit only, not per build. |
| **P2 — OUT-4** | Extend assurance to a single bounded write, approval and idempotency/uncertain-send behavior; track Python/Rust parity per operation. | Approved effect succeeds; denied effect never reaches provider; ambiguous success is never silently retried. |

Dependencies: NR-2 and NR-3 progress together, NR-4 requires both, NR-5
requires NR-1..4. W8 and W7 have independent integration/authorization gates
and should proceed without waiting for NR-5; neither substitutes for the
formal read claim. OUT-4 is outside the first read-only proof target. See the
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
