# Owned-controller request trace composition

The actual extracted request adapter now has a chronological W4
**audit/provider-attempt/denial projection for every returned outcome**, under
explicit native context-input and primitive/environment obligations. The proof
composes the existing production controllers; it introduces no replacement
execution function, provider-arrival flag, or whole-dispatch/completion history
assumption. Runtime Rust and wire protocols are unchanged in this increment.

`GarrettDispatchTrace.lean` derives thirteen named obligations. Successful current
recheck stores exactly the reported stamp in the private local send state. The
actual bound current controller supplies its manifest/identity origin. The
composite `begin_send` gate records this stamp before invoking the raw writer;
a failed or partial writer return retains that attempt. Preparation, audit,
configuration, freshness, reservation, provider-driver and coordinator-finish
prefixes compose with their actual returned primitive states. Invalid
preparation and all returned errors are included. The whole dispatcher preserves
its captured context and yields a source-gate `TraceSteps` history, without a
whole-current origin premise.

`GarrettCompletionTrace.lean` derives six named obligations for actual selection,
check/audit/check and consuming release. Its source-gate histories are valid for
any supplied provider context because these completion gates introduce no
provider attempt. It retains exact selected-value origin, mutable error state
and the private completed-value gate. These facts do not equate the selected
value to native JSON or bytes observed by the guest.

`GarrettOwnedRequestTrace.lean` derives four named obligations through the real
request constructor, request adapter and consuming request entry. The dispatcher
and completion reports, receipt copies, outer freshness frames and callback
histories come from their actual extracted code. The resulting trace covers
no-preflight final reads, checked-only preflight returns and two-phase reads,
including failed and audited-but-unsent returned prefixes. Core support lemmas
also cover writing uncertainty; the initial native assurance claim remains the
read-only sequential profile in the active queue.

The remaining `NativeContext` input contract is **state indexed**. It requires:

- The actual canonical `Bound` dispatcher trait instance.
- The primitive dispatch factory's returned plan uses the context captured in
  its input work state, and its returned work state preserves that context.
- The primitive outer-check and completion-factory returned work states preserve
  that same captured context.

These are constructor/typeclass and immutable-field correspondence obligations,
not admitted-stamp, audit-success, provider-reached or callback-history premises.
For the production path they are now derived by the extracted
[source-owned request context wrapper](garrett-request-context.md). The generic
interface remains state indexed: each request tracks its own initial context,
rather than fixing one context over every possible work value. Native startup
and input conversions, primitive/environment and I/O semantics remain separate.

`TraceSteps` records exact receipt changes in controller order and feeds the
existing W4 gate-soundness and captured-binding results. Native audit
acknowledgement/durability, clocks, revocation/control, credential leases,
coordination, input conversions, TLS, byte submission and response parsing keep
their separate semantics. A provider Send stage denotes callback invocation;
delivery is not proved. Source guards and optional compiler paths do not close
transitive I/O, dependency, nonreturning, panic/drop/unwind or alternate-sink
obligations. Guest selected JSON/frame/close observations, W5 native
observational correspondence and connected adaptive session histories remain
open, as do NR-2–NR-5 exit and independent security review. No whole-service
mediation, secrecy or VM/physical-TPM isolation claim follows.

Focused proof iteration:

```sh
cd proofs
lake build +GarrettCurrentAdmission +GarrettRequestTrace +GarrettRequestAdapter
lake env lean -DwarningAsError=true -o .lake/build/lib/lean/GarrettDispatchTrace.olean GarrettDispatchTrace.lean
lake env lean -DwarningAsError=true -o .lake/build/lib/lean/GarrettCompletionTrace.olean GarrettCompletionTrace.lean
lake env lean -DwarningAsError=true GarrettOwnedRequestTrace.lean
```

The 23 names are audited centrally in `GarrettCheck`. The new leaves add no
per-theorem default axiom dumps. Verification tooling remains non-core Python.
Targeted re-extracted source mutations use `garrett.mutate("^trace origin ")`;
the harness rebuilds the selected leaf's local import closure against each
mutated extraction. A failure in a prerequisite proof is reported as that
prerequisite's rejection, not promoted to an independent new-leaf result.
