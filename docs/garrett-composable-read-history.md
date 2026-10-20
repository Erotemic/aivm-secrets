# Garrett: compositional read-history correspondence

October 19, 2026. Baseline: the accepted native audited-dispatch, completed-release,
success, provider-failure, pending-dispatch, and two-run read overlays. This
increment uses only offline synthetic data and the same native Rust binaries.

## Improvement over case-by-case observations

The read oracles independently check provider HTTP requests against host-selected
policy, causal audit-before-provider arrival, canonical guest frames, selected
release and declassified metadata. Until now, the success, provider-failure,
and audited-but-unsent paths emitted distinct ad hoc event strings.

`tests/secrets_w6_composition.py` gives them **one normal form**, with a
host-declared contract rather than inferring authorization from observed
network traffic:

| Outcome | Audited phases | Provider-received phases | Terminal events |
| --- | --- | --- | --- |
| Release | final / preflight / preflight+final | all audited | completion audit, guest release |
| Provider denial | same | all audited | fixed guest denial; no completion |
| Audited but unsent | same | all but final audited phase | fixed guest denial; no completion |

A provider request must be preceded by its corresponding audit record; an
unsent trailing dispatch is distinct from a provider rejection. A success has
exactly one completion audit and a canonical single public reply. Neither
provider-failure nor pending paths may have a completion audit. Each phase
must be a read-only host-selected effect.

`read_prefix` is deliberately an *additional* causal grammar check; it does
**not** replace the independent W6 HTTP/disclosure/freshness oracles. Calls
from the existing success, provider-failure and pending witnesses ensure they
all produce a common abstract event form. The proof would be circular if a
mere log record were allowed to authorize its own provider send.

## Sequential native sessions

`sequential_history` combines any finite number of previously checked
`ReadPrefix` witnesses against a **single complete host audit** and the
provider's global audit-at-arrival snapshots. It requires precisely the
validated `session_open` and `issued` startup prefix, a fixed grant/policy and
issued public identity at every dispatch, and exact continuity between the
per-request audit slices. There is no allowance for unknown intermediate or
trailing rows, or for a later request's completion to appear at an earlier
provider arrival.

A new native test issues **two successful read requests over the same live Rust
manifest session**, observes their actual mTLS guest frames and synthetic
provider HTTP, checks each with the original host-policy/byte oracle, then
checks the joined global audit. No new service, credentials or Rust build is
needed; real native execution remains an explicit maintainer test gate.

Portable mutants reject swapped phases, a final send without audit, changed
request digests, a write appearing in a read plan, missing or premature
completion, extra guest frames, extra provider arrivals, principal changes,
policy changes, and audit records between requests.

## New scoped Lean theorems

`proofs/GarrettReadPrefixes.lean` imports the existing source-linked W4/W5
read paths and adds an `Attempt` with two *adapter-provided* decisions:
`auditOK` and `providerReached`. A true `providerReached` event only appears
after admission and audit; a stopped attempt can be audited without provider
emission. The following are **candidates pending maintainer kernel compilation**:

- `blocked_has_no_provider`: no modeled provider-send event after the
  adapter-supplied `providerReached = false`.
- `attempt_sound`: any modeled attempt is a `SoundTrace` under the extracted
  Rust authorization and recursive disclosure proof's definition.
- `attempt_send_requires_admission`: every modeled provider send implies the
  exact extracted Rust manifest admission predicate and acknowledged audit.
- `history_sound`: the result composes over lists of *arbitrary finite length*;
  no proof-length bound comes from the test suite.
- `coupled_history_noninterference`: per-request W5 declassification
  agreements imply the same ordered abstract observations for arbitrarily
  many sequential reads, including all three read shapes.

The new `dev/verification/read_prefixes.py` guard checks proof provenance,
the exact named theorem set, dependency fingerprint and unresolved obligations.
`prove` compiles the pinned W4/W5 imports and new Lean file, then audits the
reported axioms. **The source guard does not kernel-check the theorem claims.**

## Fast acceptance

```bash
# Portable source guards and adversarial/composition tests; no Rust/Lean/Charon.
python dev/verification/quick_w6_read.py --composition-only

# Also run the new real-Rust two-request session; reuse existing binaries.
python dev/verification/quick_w6_read.py --composition-only --native

# Focused Lean kernel and axiom check. Requires the pinned provisioned toolchain.
python dev/verification/read_prefixes.py prove
```

The regular `python dev/verification/quick_w6_read.py --native` also includes
the new session check. `--full-tests --call-linkage` is unnecessary for this
change: it does not alter Rust source or the compiler's call graph.

## What this does **not** establish

These are conditional source-model theorems and checked finite native witnesses.
A **universal native-to-model forward simulation has not yet been proved**.
In particular, `providerReached` is an external observation, not an extracted
Rust/TLS effect, and an audit write is not by itself crash-durable proof.
The gap between late authorization and a network syscall, TLS partial writes,
connection-close/error/timing observations, nested callbacks and dependency
reachability, read concurrency, pre-audit denials, writes, TPM/key custody,
and VM isolation are not discharged here. In addition, the two-run theorem
requires explicit agreement on all declassified statuses, projections,
reflection decisions, and metadata. Equality of public requests alone is
insufficient to infer noninterference.

The next step after kernel/native acceptance is mapping the concrete native
state-machine branches and external I/O acknowledgements to these abstract
`Attempt` events, with the unresolved trust boundary named for each mapping.

## Focused Lean runner maintenance (October 19, 2026)

The optional `read_prefixes.py prove` gate initially failed while compiling
`GarrettReadPaths.lean` with no captured stdout or stderr. The original Python
wrapper did not report the child's return code, so that failure alone did not
establish whether it was a Lean elaboration error or process termination.

The focused runner now reports each command and elapsed time, and on failure
includes the return code or terminating signal, cwd, and captured diagnostics.
`SIGKILL` is **not** automatically classified as OOM: kernel logs must confirm
that diagnosis. The read-path kernel/axiom pass also emits its `.olean` file,
which the prefix checker imports directly; this removes an unnecessary second
read-path compilation without skipping any proof or axiom check.

```bash
python dev/verification/read_prefixes.py prove
```

If the kernel check still fails without Lean text diagnostics, inspect the
reported signal/exit code. For a `SIGKILL`, inspect `journalctl -k -n 100`
and host memory pressure before changing the proof. All existing security
assumptions and open native-to-trace correspondence obligations remain in force.
The portable regression tests cover the runner and cannot certify Lean theorems.
