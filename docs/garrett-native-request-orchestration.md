# Extracted native manifest request orchestration

This NR-1 increment makes the real post-admission `Session::request` flow call
`read_transition::run_current`, which constructs a private `Invocation`, runs
`request_current` and consumes the receipt before returning. The Rust core chooses optional
preflight, final-effect compilation, fresh admission, optional final dispatch,
completion input and write-error uncertainty. These decisions are extracted
from production-called Rust, rather than duplicated in a hand-written Lean
interpreter. The earlier [dispatch/completion increment](garrett-read-completion-preservation.md)
remains the foundation for its private permits and completion checks.

## Runtime boundary

The native entry still opens the authenticated surrogate/credential, validates
the request and host policy, authorizes the operation, and consumes any required
write approval before entering this kernel. The initial proof profile remains
`manifest-https-v1`, sequential, `writes=deny`, with synthetic provider secrets.
Existing write, approval, coordination and OAuth behavior is retained and tested;
it is not silently added to the read-profile assurance claim.

The private `PendingRequest` adapter supplies the following actual operations:

| Extracted callback | Native implementation | Result consumed by core |
| --- | --- | --- |
| `preflight` | `Policy::preflight(op, args)` | Error, no effect, or compiled preflight effect |
| `empty_facts` | `Value::Null` | Baseline for a request with no preflight |
| `dispatch(phase, effect)` | Phase-specific `PreparedDispatch`, host audit, existing coordination controller, `exchange_manifest` and late emission gate | Provider value or the existing native error |
| `final_effect(facts)` | `Policy::final_effect(op, args, facts)` | Error, checked-only return, or compiled final effect |
| `recheck` | Existing full `fresh` closure | Current coordinator/lease/peer/surrogate/grant/time outcome |
| `effect_write` | Compiled effect's `write` field | Classification for completion uncertainty |
| `complete(raw)` | Pagination, disclosure, reflection checking, then `complete_current` | Private `CompletedRelease` or existing error |
| `outcome_unknown` | `Error::OutcomeUnknown` | Conservative error after a sent write's completion failure |

`request_facts` and `finish_request` are private Rust functions actually called
by `request_current`. Only the private child module
`read_transition/invocation.rs` owns the raw adapter. The parent controller must
thread a mutable invocation through every callback. Invalid calls halt that
invocation without calling the raw adapter. The bounded `Trace` enum records
accepted wrapper prefixes without allocating a log or retaining request data.
There is no second native preflight/final interpreter.
The prepared/audited types, audit contents, provider encoder, HTTP parser,
coordinated reservation/finish sequence, and last pre-send freshness check are
retained. `CompletedRelease::into_public` runs only after the kernel returns its
protected completed value. No wire version, state format, Python policy rule,
credential source or fallback is introduced.

For checked-only operations, the completion input is the returned preflight
facts and no final provider call occurs. For a final effect, completion receives
that effect's returned provider value. Compilation, freshness or provider errors
stop the sequence. A dispatch error is preserved, because its adapter determines
whether it was pre-send denial or post-send uncertainty. Only a failure after a
successful final write dispatch is mapped to `outcome_unknown` by this kernel.
No retry is added.

## Exact extracted result

The focused modules `proofs/GarrettReadTransition.lean` and
`proofs/GarrettReadInvocations.lean` check 33 named obligations: thirteen
dispatch/completion results, twelve state-threaded orchestration results and
eight constructor, receipt and consuming-gate results. The new success characterization is necessary **and**
sufficient for the extracted computation to return a particular successful
reply. It requires witnesses for:

1. Facts returned by either the actual empty-facts adapter with no preflight,
   or the preflight provider adapter for the exact selected effect and phase.
2. A successful current check after final compilation.
3. Completion input equal to those facts for no final effect, or equal to the
   actual final provider return for the exact compiled effect.
4. The completion adapter returning that same reply successfully.

These witnesses are equalities to the actual extracted callback results, not
unconstrained `auditOK`/`providerReached` booleans. Proofs invert successful
monadic returns without assuming termination or successful outcomes for unused
continuations. Failure lemmas retain exact errors at preflight compilation,
preflight provider, final compilation, freshness and final provider boundaries.
Read-continuation equalities also retain completion failure or divergence;
they do not describe only happy paths. A separate theorem preserves write
uncertainty, and a two-phase positive witness rules out a deny-only controller.
Successful request characterization includes the exact returned invocation
state. `run_current_success_iff` covers the production constructor, controller
and consuming gate together. `ignored_extra_dispatch_rejects_saved_reply`
shows that an extra rejected dispatch cannot reuse a previously saved success.
The wrapper makes invalid progression terminal; it does not retry the adapter.

The installed-device witness now also exercises a TPM-signed native manifest
read, selected output, a denied write and terminal revocation, in addition to
the account-status workflow. Its six selected device cases retain unused-handle
admission, pinned cleanup and unchanged dictionary-attack state. Wrong-auth
negatives remain isolated-emulator tests. This validates use of the installed
vTPM with the new running request kernel, not guest/host compartment isolation.

The pure core unit tests exercise all four optional-phase combinations with
distinct baseline/preflight/final values and inject a failure at each callback
boundary. Their recorded callback prefixes check no later callback or retry in
those finite executions. Native HTTPS/mTLS workflows remain the practical
authorized-success and denied-effect witnesses.

Four re-extracted Rust mutations target missing freshness, a wrong
preflight phase, substitution of the final provider return, and loss of write
uncertainty. Their rejection is a check of these concrete theorem obligations,
not a complete security mutation campaign. Four additional mutations target
an ignored repeated plan, an ignored extra callback after completion, an
unfinished saved reply and an omitted receipt transition. The mutation runner
now retains nested Rust module paths and recompiles the invocation proof after
its dispatch/completion dependency against each regenerated mutant.

The [request-wide receipt increment](garrett-request-effect-receipts.md) now
threads mutable raw-adapter states through these same 33 theorems and supplies
a production effect gate with conditional request-level receipt composition.
It retains the native I/O and event/history obligations below.

## What remains for NR-2 and NR-3

This closes the production orchestration extraction and exact result/data-flow
part of NR-1. It does not complete native execution-to-event simulation.
The dispatch callback still contains real audit, authority, socket, TLS and
parser operations. Completion still contains projection/serialization and
external audit/current checks. Their result equalities must be related to
actual acknowledged effects and typed W4/W5 events under the named W0 adapter
contracts.

The stateful wrapper addresses the earlier controller-level counterexample:
an ignored extra wrapper call changes the invocation to `Halted`, and the
consuming gate rejects a saved successful result. The exact-state proofs also
reject the changed controller receipt. This is an enforcement and extraction
advance, not the full NR-2 effect relation. `Trace` records accepted calls to
this wrapper; it does not observe all native effects, panic/unwind prefixes or
calls made *inside* a raw adapter. The wrapper-to-raw-callback step is reviewed
source, and raw callbacks still have an extensional extracted `Result` contract.
An ignored duplicate raw callback *inside the wrapper* is not excluded merely
by those result equalities. The W3 source guard pins the private ownership,
callback multiplicity and consuming gate, but this is not a semantic proof of
that multiplicity. NR-2/NR-3 must establish the actual invocation/effect relation
and inspect reachable sinks, callbacks, errors, drops and dependencies.
The valid completion-audit-acknowledged/guest-denied prefix from late revocation
also remains to be represented in the complete forward simulation.

The next acceptance task is therefore the extracted-controller-to-event
relation for these same callbacks and all three scoped read shapes, rather
than another independent trace constructor or source inventory. W7 live
providers, W8 guest/host compartment evidence and independent NR-5 review remain
separate gates. vTPM availability does not discharge those obligations.

## Reproduction

```bash
.venv/bin/python dev/verification/read_transition.py
.venv/bin/python dev/verification/garrett.py mutate --mutation-filter 'request orchestration|request invocation'
cargo test --locked --manifest-path rust/Cargo.toml -p aivm-secrets-garrett-core
.venv/bin/python dev/verification/quick_w6_read.py --native --build
.venv/bin/python dev/offline_native_guest.py
```

During proof editing only, `read_transition.py --no-regenerate` reuses the
generated source. The default command requires the existing pinned tool/model
coordinates, matching fresh Charon/Aeneas regeneration, focused kernel
compilation, and the named axiom audit. W0/W3/W6 inventory checks retain their
source-review scope. The historical `dev/validation/2026-10-20-request-orchestration.json`
records source `64d3caa`; it does not certify the stateful invocation changes.

The stateful increment is frozen at source `11e0a5a` in
[the invocation validation record](../dev/validation/2026-10-20-request-invocations.json):
3,003 full-suite cases without skips, 433 named axiom audits, eight targeted
mutants, both native product modes, packaging and six installed-device cases.
The ordinary release run used the same quick-gate pytest selection with
explicit release paths; `quick_w6_read.py --native` itself installs debug paths.
