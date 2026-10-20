# Extracted native manifest request orchestration

This NR-1 increment makes the real post-admission `Session::request` flow call
`read_transition::request_current`. The Rust core now chooses optional
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
by `request_current`. There is no second native preflight/final interpreter.
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

The focused module `proofs/GarrettReadTransition.lean` now checks 25 named
obligations: the previous thirteen dispatch/completion results plus twelve
orchestration results. The new success characterization is necessary **and**
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

The four new re-extracted Rust mutations target missing freshness, a wrong
preflight phase, substitution of the final provider return, and loss of write
uncertainty. Their rejection is a check of these concrete theorem obligations,
not a complete security mutation campaign.

## What remains for NR-2 and NR-3

This closes the production orchestration extraction and exact result/data-flow
part of NR-1. It does not complete native execution-to-event simulation.
The dispatch callback still contains real audit, authority, socket, TLS and
parser operations. Completion still contains projection/serialization and
external audit/current checks. Their result equalities must be related to
actual acknowledged effects and typed W4/W5 events under the named W0 adapter
contracts.

An extensional result equality alone does not count I/O calls. For example, an
extra successful callback whose result is ignored can leave a result equality
unchanged. NR-2/NR-3 must establish the invocation/effect relation and inspect
all reachable sinks, callbacks, errors, drops and dependencies; the present
theorem must not be promoted into a complete-mediation argument. Native source
guards and finite callback-prefix tests support that work but do not prove it.
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
.venv/bin/python dev/verification/garrett.py mutate --mutation-filter 'request orchestration'
cargo test --locked --manifest-path rust/Cargo.toml -p aivm-secrets-garrett-core
.venv/bin/python dev/verification/quick_w6_read.py --native --build
.venv/bin/python dev/offline_native_guest.py
```

During proof editing only, `read_transition.py --no-regenerate` reuses the
generated source. The default command requires the existing pinned tool/model
coordinates, matching fresh Charon/Aeneas regeneration, focused kernel
compilation, and the named axiom audit. W0/W3/W6 inventory checks retain their
source-review scope. New validation is recorded separately from the historical
`304b5eb` increment in
`dev/validation/2026-10-20-request-orchestration.json`; that older record does
not certify these changed sources.
