# Returned native request prefixes

The production post-admission request kernel now has a necessary-and-sufficient
returned-run relation covering successful and failed outcomes, with exact
mutable callback states. This extends the earlier success-only request
composition. It does not change Rust authorization or the wire protocol.

`GarrettReadInvocations.lean` defines `FactsRun`, `FinishRun`,
`FinalCompletionRun` and `RequestRun` using equalities to the actual extracted
callbacks. The four new iff theorems cover the real facts controller, finishing
controller, request controller and consuming `run_current` entry. Constructors
retain planning/freshness/provider/completion errors and the actual write
uncertainty callback. They do not require unused callbacks to terminate or
succeed. Panic, divergence and unhandled effects are not fabricated into
returned errors. All earlier 33 general statements are retained.

The six new `GarrettRequestSimulation.lean` results compose every returned
prefix with the same production receipt used on success and failure. A
completion audit followed by late denial remains an acknowledged audit in
that returned state; denial does not erase history.

## Count actual gates before projecting events

The old implication invariant, such as attempt implying audit acknowledgement,
is insufficient to exclude a repeated audit whose already-true bit is reused.
`GarrettRequestPrefix.lean` strengthens it with exact occupied prefixes for
both dispatch slots and completion. It checks every actual Rust receipt
mutator, including rejected calls. A live progress stage fixes its past and
future flags. Halted calls retain the ordinary soundness invariant and cannot
restart through these mutators. Copying/resetting the native cell outside the
reviewed call sites is not authorized by this relation.

`GarrettRequestTrace.lean` projects differences between consecutive receipt
states to existing W4 audit and provider-attempt events. Its exact-count
lemmas establish one audit marker for an accepted dispatch/completion audit
entry, no second marker for acknowledgement, and exactly the actual local
`SendState` event for an accepted composite submission. A rejected duplicate
submission does not replay the old attempted state. The prefix invariant is
needed for this counting claim: merely observing a sticky bit is insufficient.

A local `FreshOrigin` records equality to the actual `manifest::current`
constructor only for newly marked submissions. The theorem
`checked_send_establishes_origin` discharges it at the actual composite Rust
send gate from the checked local stamp's constructor origin. This is a
primitive origin contract to instantiate, not an independent audit-success or
provider-arrival Boolean. Attempt includes zero-byte, partial and flush errors;
no claim of complete provider delivery follows.

`TraceSteps` sequences those actual extracted receipt mutators and their
local stamp origins. The all-returned controller relation composes local
callback histories into a sound W4 audit/provider/denial projection, including
final-only, checked-only and two-phase shapes. A captured-context theorem
preserves identity, operation and grant-route binding throughout that
projection. Context conversion and its association with authenticated startup
remain native adapter obligations. Acknowledged completion followed by an
entered post-audit check retains its acknowledgement, emits no second event,
and cannot pass the completed-value gate while that check is pending.

## What remains

The native callback histories are explicit local contracts. These theorems
concern the projection of production receipt transitions; they do not assert
that every native I/O effect is captured. Exact phase/data correspondence for
each native callback, context conversion, universal current/audit/Write
primitive instantiation, non-returning/drop/unwind paths and transitive sinks
remain NR-2/NR-3 obligations. The existing named assumptions, including
`RUST-CLOCK-01`, `RUST-AUDIT-01`, `RUST-HTTPS-01`, `RUST-JSON-01`,
`RUST-COMPILER-01`, `MANIFEST-RUST-01` and optional `COORD-RUST-01`, retain
their meanings; no new complete-mediation or secrecy premise is introduced.

Successful outputs are deliberately absent from this audit/provider/denial
projection until their selected-value and guest-frame correspondence is
proved. A ready native value is not a guest frame, and a completed audit is not
a delivered reply. Full W5 observations, adaptive native histories, all sink
closure and independent review remain open. These are conditional,
implementation-linked results, not whole-service secrecy or VM isolation.

## Native late-denial witness

The six non-core process cases in `tests/test_rust_w6_completion.py` use the
actual Rust broker, mTLS guest protocol, HTTPS provider and both supported
SQLite coordinator implementations. They keep `writes=deny`. Each case first
releases an allowed value, then uses that public ID in the next request.

A Linux test-only preload library pauses **after real successful fsync** of
that second request's exact completion row and before fsync returns to Rust.
The independent coordinator commits terminal revocation while the broker
waits. When released, the broker acknowledges its completed row, rechecks live
authority and sends exactly one canonical fixed denial frame with no result.
The audit remains present. A subsequent request also fails without another
provider call or request audit. This witnesses a particular acknowledged-audit
then denied-release prefix; it is not a proof of arbitrary scheduling or
native I/O correspondence.

The C helper is non-core test instrumentation, never installed or loaded by
production configuration. It requires Linux, a C compiler and dynamically
linked native executables, and uses private one-byte marker files with a
bounded cleanup timeout. Only synthetic credentials and local endpoints are
used. The test does not enable the approval-only host control socket in the
read-only startup profile or change authorization to make the race reachable.

## Reproduction

```sh
.venv/bin/python dev/verification/read_transition.py
.venv/bin/python dev/verification/request_effects.py
.venv/bin/python dev/verification/garrett.py mutate --mutation-filter '^request prefix '
.venv/bin/python dev/verification/quick_w6_read.py --native
```

The focused receipt verifier now checks 54 named obligations, including the
new prefix and trace modules, after exact regeneration. The request verifier
checks 37, including all returned-run characterizations. Their temporary axiom
audits remain separate from the leaf proof sources. The aggregate manifest
pins the new native test and C source as well as the proof modules. The six
native cases are required in release parity and both quick native build-mode
gates; packaging includes their C source for independent replay.
