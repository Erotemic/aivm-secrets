# NR-0: reproducible native-read profile and evidence freeze

**2026-10-19 baseline. Status: portable snapshot checks reproduced; native/Lean
acceptance must be rerun on the maintainer's checked-out revision.**

This is the first deliverable from the [native read assurance
roadmap](aivm-secrets-native-read-assurance-roadmap.md). The machine-readable
[profile record](aivm-secrets-native-read-nr0.json) and
[`native_read_profile.py`](../../dev/verification/native_read_profile.py) are
the executable handoff. They are **not** a new authorization policy, an
implementation-derived trace semantics, or a whole-broker security proof.

## Exactly what is frozen

The profile is the real native `manifest-https-v1` provider backend exercised
by `tests/test_rust_garrett_manifest.py::ManifestCase` and the W6 local mTLS
fixtures. Its default `writes=deny` is host configuration; the fixture
explicitly **permits a caller to override it** for separately scoped write
tests. Selected native witness cases use the deny setting. The test provider
is local HTTPS using a synthetic credential and private CA; it makes no live
GitHub/OAuth connection. The guest uses the bound surrogate and a software
client certificate, and requests are sequential in one session where the
history witness requires it. No coordinator is configured in this selected
fixture; the code still calls `check_coordination` and retains optional
coordinator/OAuth execution branches.

The profile is **not a separately compiled read-only binary**. The same Rust
source supports `account-status-v1`, Python forwarding, optional OAuth leases,
approvals and coordinated writes in other configurations. This record does
not assert they are unreachable in arbitrary deployments. The selected
configuration must remain a proof premise or be enforced by a future runtime
profile gate. Any alternate path selectable by guest input would block the
first confinement claim even when the nominal selected fixture passes.

The source/proof/harness fingerprints pin 30 files, including native bridge,
TLS, custody, manifest policy and disclosure, relevant core controllers,
Cargo lock/toolchain, generated Lean core, W4/W5 model proofs, and the
existing native witness fixtures. These hashes identify the reconstructed
source used for this NR-0 preparation; they do not establish that a given
binary was built from it. The previous exported base commit is `b91748b`
plus the earlier read/Lean/planning overlays; it is **not necessarily the
user's present `HEAD`**. Fresh run evidence records that actual `HEAD`, its
tracked-worktree status, executable SHA-256 hashes, toolchain pins, stage
statuses, selected node count, executed case count, and skip count.

### Fast local commands

From the root of the maintainer's checkout:

```bash
# Structural freeze and W0 sink completeness (no Rust/Lean):
python dev/verification/native_read_profile.py

# Repeat the portable source/oracle gate (seconds, not Charon):
python dev/verification/native_read_profile.py --portable

# Complete NR-0 local reproducibility evidence with existing Rust binaries:
python dev/verification/native_read_profile.py --portable --native --lean \
  --output .tools/native-read-nr0-evidence.json

# Only when binaries are actually stale because Rust sources changed:
python dev/verification/native_read_profile.py --portable --native --lean --build \
  --output .tools/native-read-nr0-evidence.json
```

The optional `--build` uses an incremental Cargo binary build with the pinned
nightly toolchain. **Neither default nor `--portable --native --lean` runs a
full Rust test suite, general pytest, new Aeneas extraction, or Charon's
multi-gigabyte compiler-linkage analysis.** The focused Lean gate calls
`read_prefixes.py prove`, which compiles and axiom-audits the read-path and
read-prefix modules and their imports. If the command fails, the evidence
JSON records which stage failed or was not reached; success is not printed
when a stage failed. Native acceptance rejects **every skip** or missing
JUnit report. Binary timestamps are an early stale-build warning; binary
hashes are recorded for later comparison but are not proof of Cargo build
provenance.

The runner deliberately does not print or persist the synthetic token or any
private source content. It records only a bounded diagnostic tail on stage
failure. Save evidence under `.tools/` rather than in the committed planning
folder. Human review should compare the recorded hashes with the checkout
being considered and explicitly approve any source-pin update.

## Selected positive and negative native evidence

The acceptance runner uses **existing real-Rust process tests** rather than
a second mock execution engine. All following groups must pass without
skips; inspect the cited tests for exact route, disclosure and audit assertions:

| Witness | Source test | What it checks / what it does not |
| --- | --- | --- |
| Authorized selected result | `test_rust_w6_adapter.py::test_w6_native_no_preflight_pagination_is_exact_selected_guest_release` | Real native bridge, mTLS, provider-arrival and selected pagination bytes; finite run only |
| Checked-only fact | `test_rust_w6_adapter.py::test_w6_native_preflight_only_check_release_has_no_final_send` | Preflight without a final provider send |
| Denial and write exclusion | `test_rust_garrett_manifest.py::test_no_provider_call_for_denied_arguments_or_declared_write` | `writes=deny` blocks write operations, including an operation whose HTTP method would otherwise look read-only |
| Provider error | `test_rust_w6_adapter.py::test_w6_failed_final_read_private_diagnostics_are_invisible` | Fixed guest denial despite changed private diagnostics |
| Audited but unsent | `test_rust_w6_pending.py::{test_native_untrusted_provider_ca_leaves_audited_but_unsent_read,test_native_late_remote_revocation_never_emits_pending_read}` | Audit/arrival separation under TLS failure and late remote revocation; not a network syscall proof |
| Sequential session | `test_rust_w6_adapter.py::test_w6_native_two_sequential_reads_refine_one_complete_session_audit` | Ordered multiple request audit and provider events in a single broker session |
| Guest controls | `test_rust_garrett_manifest.py::test_manifest_keeps_actual_peer_binding_and_renunciation` | Binding, `describe`, `renounce`; does not prove all control-path effects |

The witness selection itself is pinned in the JSON. Removing a success,
denial, failure or pending witness fails NR-0 review. The separate full quick
W6 gate continues to cover more synthetic source and mutation scenarios.

## W0 sinks: explicit dispositions, not reachability certificates

**Every one of the 14 sink IDs in W0** has a status, basis, and open obligation
in the JSON manifest. Unknown/new sink IDs make the review gate fail until
classified. The key distinctions are:

| Sinks | NR-0 treatment |
| --- | --- |
| `S-GUEST-FRAME`, `S-PROVIDER-HTTPS`, `S-HOST-AUDIT` | Included; local positive/negative observations, but byte-attempt and total-path refinement remain open |
| `S-GUEST-CLOSE`, `S-HOST-STDOUT`, `S-HOST-STDERR` | Included and **not closed**; termination, close, logging and dependency behaviors need refinement |
| `S-HOST-PRIVATE-STATE`, `S-HOST-ADMIN`, `S-COORDINATOR-REPLY`, `S-COORDINATOR-ADMIN` | Other principals/host-only compartment assumptions; actual guest isolation remains unvalidated |
| `S-OAUTH-HTTPS`, `S-LEGACY-UNIX`, `S-COORDINATOR-HTTPS`, `S-WRITE-APPROVAL-CONTROL` | Not selected by this test configuration; **not** proven unreachable in all other configurations |

W0 remains the authoritative sink and allowed-release taxonomy. The JSON
manifest cannot justify a new trust assumption: assumption IDs must already
exist in `aivm-secrets-assumptions.json`. Source guards and test arrival
snapshots are evidence with different logical strengths; they cannot jointly
replace the missing NR-2/NR-3 proof obligation.

## Results recorded during this overlay round

On the reconstructed exported source plus applied overlays, the NR-0 profile
inventory check passed. The existing W6 portable gate passed **142 tests**,
and **12 new NR-0 mutation/guard tests** passed. Rust binaries and the pinned
Lean toolchain were unavailable in this environment; there was **no** new
native or Lean acceptance here. The prior user's successful focused Lean and
native runs are *maintainer-reported*, not a new independently reproduced
NR-0 baseline. The evidence record on the maintainer's machine is the next
required handoff artifact.

## Exact next implementation handoff: NR-1

Do not add another hand-written abstract `Attempt` constructor as a stand-in
for the implementation. Start at `Session::request` in
`rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs`:

1. The guest input is normalized by `self.policy.operation`; `guards::authorize`
   admits the operation. `fresh` samples the current host state again.
2. `PreparedDispatch::preflight/final_effect` checks write restrictions and
   `PreparedDispatch::audit` returns `AuditedDispatch` only after an audit write
   acknowledgement. This is **one useful first extraction candidate**:
   implement a small pure typed transition in `aivm-secrets-garrett-core`,
   then have this exact production call site invoke it. It must model admitted
   write status, phase, selected effect/write flag, and audit success with
   explicit typed inputs. Avoid any uncalled shadow helper.
3. The privileged `exchange_manifest` in the Rust host continues to own
   TLS, current lease checking, and credentialed network bytes. Its accepted
   `AuditedDispatch` alone does not prove complete mediation; account for
   other sinks separately.
4. `CompletedRelease::after_completion` must follow actual projection,
   reflection checks and a completion audit; guest `GuestFrame::send` must be
   linked to the resulting public envelope.
5. Extract the **production-called** Rust pure step using the pinned
   Charon/Aeneas pipeline. Record exact source/export hashes and an import
   smoke test before writing the first Lean simulation lemma. Do not add an
   extracted theorem only about an unrelated reimplementation.

NR-1 is **not completed by this overlay**. It requires a targeted Rust build,
extraction and Lean kernel run; no production Rust code or proof statement was
changed here. Current open proof work is listed in the roadmap's NR-1 through
NR-5 gates.
