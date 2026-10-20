# Production request-wide effect receipts

The native `manifest-https-v1` request adapter now shares one private
`RequestEffects` gate from dispatch audit through completed-value construction.
The gate is production Rust, extracted with pinned Charon/Aeneas. It contains
only bounded flags, phase progress and sampled admission stamps; it retains no
credential or provider value and is never serialized to the guest.

This advances the NR-2 callback/effect relation. It does not close native
primitive correspondence, W4/W5 event/history simulation, NR-3 sink closure,
NR-4 observation correspondence or NR-5 independent review.

The [all-returned prefix increment](garrett-returned-request-traces.md) extends
this to failed callbacks, exact occupied prefixes and conditional W4 receipt-event
composition. The original validation below remains specific to its frozen source.

## Actual call sites

Each dispatch starts its audit marker immediately before `Audit::write_record`
and acknowledges it only after that primitive returns successfully. The opaque
prepared/audited permit and existing coordination controller remain in use.
Provider setup requires that acknowledgement. The sole credential-bearing
`Write` helper checks the request phase and local `SendState` together before
calling `write_all` and `flush`, recording the exact local admission stamp and
an attempt. A zero-byte error, partial acceptance or flush error is still an
attempt; no retry is added. Provider completion and successful coordinated
return have separate markers, so an uncertain coordinator finish cannot
silently become completed dispatch.

Completion requires either no dispatch or a successfully returned last
phase. Selection is marked after disclosure and envelope reflection checks.
Both freshness checks, audit attempt and audit acknowledgement have separate
markers. `CompletedRelease` is constructed only after the second check and
`value_ready` gate. Invalid extra gate calls poison progress without clearing
previous acknowledgements. A sticky value flag cannot reopen the return gate.
Here, **value ready means an authorized native value**, not a guest frame write
or evidence of complete network delivery.

The actual `Request::dispatch`, `recheck` and `complete` callbacks, and the
completion freshness/audit callbacks, now take mutable adapter state. All 33
existing dispatch/completion/orchestration theorems follow the exact returned
states, including failures; they are not restricted to a state-preserving
specialization. Native `PendingRequest` copies its shared gate into a plain
snapshot after each effectful callback, even on error. This supplies a
realizable state observation, which an unchanged shallow adapter could not
supply. The completion adapter also checks that snapshot's return gate.
No `RefCell` borrow is held across network, filesystem or freshness operations.

## Checked scope and local contracts

The 29 focused obligations in `GarrettRequestEffects.lean` and
`GarrettRequestSimulation.lean` check each actual extracted gate operation,
including rejected transitions, against dispatch and completion invariants.
`Step` consists of equalities to these extracted functions; `Steps` is their
returned-transition closure. Induction from `RequestEffects::new` establishes
that an attempted provider submission has an acknowledged, attempted dispatch
audit and a recorded current stamp. A returnable completed value has selected
output, both successful freshness checks and an acknowledged completion audit.
Separate results retain completion acknowledgement during a denied post-audit
check and close the return gate after an invalid extra call.

`GarrettRequestSimulation.lean` composes the actual mutable request controller
and consuming entry with that reachable gate record. Its local `Contracts`
require each returned native callback to follow the extracted receipt
transitions, and require successful native completion to pass the actual
return gate. These are explicit native-adapter correspondence premises,
reviewed at the production call sites and exercised by tests; their universal
native I/O instantiation is still open. They do not assume a whole-request
conclusion or introduce independent provider-reached/audit-success booleans.
The result covers optional preflight/final shapes and actual callback states;
it does not yet connect the complete receipt to W4/W5 events or an adaptive
session history.

A stamp records the authority check's sampled time and write classification.
The existing stamp theorem characterizes its actual authorization constructor.
Neither a stamp nor these receipts make revocation atomic with a network
syscall. Audit fsync/durability, std/rustls Write semantics, parser/JSON and
policy-to-wire conversion, native callback completeness, non-returning I/O,
panic/drop/unwind, guest framing and transport dependencies remain separate
contracts or obligations. The bounded receipt is not an exhaustive I/O log.

## Reproduction

```sh
.venv/bin/python dev/verification/read_transition.py
.venv/bin/python dev/verification/request_effects.py
.venv/bin/python dev/verification/w0_contract.py check
.venv/bin/python dev/verification/w3_effect_boundary.py check
.venv/bin/python dev/verification/w6_adapter.py check
```

The new verifier is non-core development tooling. Its default run checks exact
source regeneration, focused Lean compilation and a separate temporary named
axiom audit. `--no-regenerate` is for proof iteration only. The complete Garrett
record includes these obligations and source pins. Source guards reject
selected bypasses; they do not prove transitive reachability.

Native unit tests use the actual completion adapter, snapshot and durable file
audit for success, audit refusal, and acknowledgement followed by late
revocation. The last case retains the acknowledgement while withholding the
value. Existing real mTLS/HTTPS tests cover selected successful reads, private
provider errors and audited-but-unsent prefixes. Only synthetic credentials
are used. Installed-device tests retain isolated negative authorization tests
and preserve existing persistent TPM objects.
