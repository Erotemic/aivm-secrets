# Owned native completion and request composition

The production native manifest completion callback now delegates its receipt
operations to `aivm-secrets-garrett-core::completion::complete`. This advances
NR-2's implementation-to-receipt relation. The extracted controller establishes
its own receipt transitions, rather than requiring a premise that an entire
completion callback already follows `Steps` and returns only a ready value.

This does not complete NR-2 or establish whole-service I/O correspondence. The [source-owned request adapter](garrett-owned-request.md) now derives
the receipt/report handoff from extracted code, replacing the former native
report/copy-back/outcome obligation for the actual producer. Actual JSON selection/conversion, current-authority semantics, audit bytes and
durability, other callbacks, sink closure and adaptive observations remain open.

## Production path

`Session::request` supplies `PendingCompletion` with the existing selection
closure, full freshness closure, and fixed completion-audit metadata. Selection
still checks host control, computes approved pagination, projects the provider
value, builds the same fixed public envelope and applies reflection refusal.
The native `Work` methods perform only these primitive operations. They receive
no reference to the controller's owned receipt.

The core begins completion, invokes selection, marks successful selection, and
uses the existing `read_transition::complete_current` order: freshness before
completion audit, the audit, freshness after that potentially blocking audit,
and release. The extracted `Pending` methods gate each primitive call and mark
its success only after that call returns successfully. The selected value is
private and consumed with `Option::take` behind `value_ready`; a `Completed<T>`
cannot be constructed by callers.

The generic completion driver now borrows its mutable adapter. Its extracted
return includes the exact adapter post-state on error as well as success.
Request/provider orchestration, write uncertainty, wire versions, authorization
rules and runtime dependencies are unchanged. Successful OAuth refresh and
bound certificate renewal retain their separate existing flows.

`completion::Report` returns the primitive work state, exact receipt and outcome
on every return. The extracted request adapter retains the returned receipt
and exact outcome, including failures. Native factories and primitives hold no
reference to this private receipt. An early selection error has an all-false
flag record but retains non-replayable progress; restoring an older receipt
would incorrectly reopen completion.

## Checked relation

Sixteen obligations in `GarrettCompletion.lean` cover actual extracted methods:

- Receipt transitions and retained selected value for every returned check,
  audit, release, generic completion and selection/completion prefix.
- Necessary-and-sufficient check/audit success equations, and exact primitive
  refusal states without assuming any unused continuation terminates.
- Successful selection/check/audit/check primitive states in order, with the
  exact selected value; reachable receipt preservation and required completion
  acknowledgments/checks.
- A positive extracted witness and refusal to invoke a primitive when completion
  is replayed from a returnable state.
- An exact returned-report equivalence, including error post-state, rather than
  merely requiring some earlier sound receipt.

Four obligations in `GarrettCompletionSimulation.lean` integrate this with the
generic request controller. Their older `Link` requires equality to the actual core
report, copy-back of that report's receipt on all returns, and exact success/error
outcome mapping through the private native wrapper. It does **not** assume the
receipt invariant or the desired whole-request conclusion. Under this link,
the two old whole-completion receipt/success-gate hypotheses are derived from
the extracted body. Dispatch and outer recheck correspondence remain independent
premises. The production request adapter now derives these receipt contracts
without `Link`; native primitive/context, conversion and I/O semantics still
need their own correspondence.

The central named axiom audit includes all twenty obligations. No new project
security axiom or independent executable trace interpreter is introduced. The
existing six generic completion proofs now retain actual returned error state.

## Boundaries and reproduction

Existing ledger identifiers retain their precise limits: `RUST-COMPILER-01`
for compiler/extraction/standard models and Lean; `RUST-AUDIT-01` for filesystem
primitives; `RUST-CLOCK-01` for clocks/locks; `RUST-JSON-01` for underlying JSON
representations; and `MANIFEST-RUST-01` for host policy intent and outstanding
project-owned adapter refinement. None grants project-owned audit ordering,
selection conversion or full mediation. The relevant existing sinks remain
`S-HOST-AUDIT` and `S-GUEST-FRAME`; completion of a native value is not guest
frame delivery. TLS, EOF/close, non-returning operations, allocator/drop/unwind,
other reachable effects and connected adaptive histories remain separate.

During proof iteration, build only the needed imports and leaves:

```sh
cd proofs
lake build +GarrettRequestEffects +GarrettRequestSimulation
lake env lean -DwarningAsError=true -o .lake/build/lib/lean/GarrettCompletion.olean GarrettCompletion.lean
lake env lean -DwarningAsError=true GarrettCompletionSimulation.lean
```

Exact regeneration and the full named audit use `garrett.py record`. The scoped
source-extracted mutation filter is `^owned completion `; the existing generic
completion-audit and post-audit-check mutants remain relevant. Source guards
check selected native/controller/copy-back bypasses and pin 97 Rust/build files;
that inventory is not exhaustive I/O evidence.

Core tests check failed primitive prefixes and replay refusal. Native unit tests
use the actual durable audit and mutable request adapter for selection failure,
audit failure, success and post-audit revocation; native process tests exercise
all three read shapes and both coordinators with real completion fsync barriers.
All peers and credentials are synthetic. An installed TPM is optional and is
used only by the separate safe device workflow.

The [frozen acceptance](../dev/validation/2026-10-20-owned-completion.json) pins
source `259d8d3`: 3,031 full cases without skips, 550 named axiom audits,
767 release parity cases, 76 Rust workspace cases, all eight selected typed and
re-extracted mutations, both 164-case native build-mode gates and product
workflows, six safe installed-vTPM cases and packaging with all 273 source pins
and the embedded Garrett manifest byte-identical. Proof/mutation jobs finished
before the full suite. These results retain the scoped/open boundaries above.
