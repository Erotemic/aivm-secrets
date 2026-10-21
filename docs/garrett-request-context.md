# Source-owned request context and factory binding

The native manifest path now constructs `request_context::ScopedRequest` before
the existing receipt adapter and consuming request entry. This private core
wrapper borrows the one `current_admission::Context`, owns the raw native work
and a check factory, and supplies the canonical `Bound` provider instance.
Native dispatch factories return raw provider plans; they cannot select the
context installed in the bound plan. The native raw provider's recheck still
refuses direct use.

The extracted wrapper calls the raw dispatch factory once, then the check
factory once, and binds their actual returned work/check states to its private
context. It preserves the plan's keyed-write bit exactly. Outer checks and
completion factories retain their actual returned primitive state and outcome;
the wrapper's context field stays unchanged. Planning, data, write flags and
public denial classifications are exact forwards. The native check factory
only copies its session and lease references, preserving the previous current
check ordering and policy behavior.

`proofs/GarrettRequestContext.lean` has ten named obligations over the actual
Charon/Aeneas extraction. They prove the exact constructor and dispatch-factory
return relation, outer-check/completion return relations, unchanged context and
all four `NativeContext` clauses from the preceding request trace composition.
The actual sequence of scoped constructor, receipt constructor and consuming
entry now has a chronological W4 audit/provider-attempt/denial projection on
every returned outcome, with initial binding preserved and **no native context,
factory-link, whole-callback history or whole-current-origin premise**. A
successful entry retains exact raw native completion-factory and selector
origin. These are proof statements about the actual source-called controllers,
not a new execution interpreter.

A core unit case exercises all three read shapes, keyed writes, exact selected
values, every fallible primitive prefix and invalid preparation before either
factory. It verifies that the raw provider recheck is never called. Existing
native process workflows remain acceptance gates; skips are not passes. The
source guards reject private-context, constructor, factory, keyed-write,
completion-input and outer-check bypasses. The optional compiler ledger adds a
selected path through the actual scoped dispatch to the concrete native check
factory. This path is not dominance or complete I/O reachability evidence.

The native startup/input conversion from parsed identity, peer, grant, policy
and operation to the supplied context remains separate. Clock, revocation,
OAuth lease, coordinator, durable audit, TLS/Write/parser and native selection
semantics retain their explicit primitive/environment contracts. Provider send
stages record callback invocation, not complete delivery. The proof covers the
request control projection, not every native I/O, nonreturning/panic/drop/unwind
path, selected JSON/frame/close observation, adaptive session history, W5 native
noninterference, physical TPM provenance or VM isolation. The initial native
claim remains the read-only sequential profile; generic write support in the
core lemmas does not complete native write assurance or Rust core API parity.
NR-2–NR-5 and independent security review remain open.

Focused development:

```sh
cd proofs
lake build +GarrettOwnedRequestTrace
lake env lean -DwarningAsError=true GarrettRequestContext.lean
```

The ten names are audited centrally in `GarrettCheck`. This leaf adds no default
per-theorem axiom dumps. Verification scripts and fixture changes are non-core
Python tooling; no Python core module, runtime dependency or wire version is
introduced. Targeted re-extracted mutations use
`garrett.mutate("^request context ")`.
