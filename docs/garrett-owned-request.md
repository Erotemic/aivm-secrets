# Source-owned request receipts

The production manifest path constructs `request_adapter::Pending` and passes
it to the actual consuming `read_transition::run_current` entry. One private
core receipt now spans preflight, final dispatch, outer freshness and completion.
Native code supplies primitive factories and has no receipt reference, shared
`Rc<RefCell<RequestEffects>>`, or snapshot to copy back. Successful output is the
core's private `Completed<Value>`, consumed through `Completed::into_value`.

The extracted request adapter prepares the exact phase and operation/effect
write flags before constructing a provider adapter. Refused preparation calls
no native factory. Accepted dispatch calls the existing owned dispatcher and
retains its exact outcome and receipt on every return. Completion similarly
constructs the selection primitive and calls the owned completion controller.
Outer freshness can change its work state or return denial, while the private
receipt stays unchanged. The existing invocation kernel still controls the
single request sequence, consumes the adapter and preserves write uncertainty.
The policy, wire versions, audit rows and optional coordinator behavior stay
unchanged. Factories cannot mutate receipts through their interface; their
other effects, allocation/panic/drop behavior and native context semantics are
separate obligations.

`proofs/GarrettRequestAdapter.lean` checks fourteen obligations from the actual
Rust extraction. They derive all four `request_effects::Simulation::Contracts`
fields, exact completion reports, phase/write admission and dispatcher origin,
primitive freshness/refusal prefixes, initial receipts, returned-entry
reachability, completion acknowledgments, selected-value origin and a positive
final-provider-read witness. These request-entry results need neither native
report/copy/outcome links nor whole-callback receipt or freshness-frame
premises. The older `GarrettCompletionSimulation` and
`GarrettDispatchSimulation` links remain valid generic conditional results;
the actual producer now derives the receipt contracts directly.

Rust tests exercise exact selected values for final-only, checked-only and
two-phase reads and keyed writes, each terminal primitive failure prefix,
preparation refusal before any factory, retained partial-send/selection-error
receipts and replay rejection. Native tests retain real completion fsync and
late-revocation checks. The standalone synthetic HTTPS operator/guest workflow
provides the useful operation witness in both build modes. The optional
compiler ledger checks a concrete owned-request dispatch path and a completion
path to the native audit writer; these are call-graph witnesses, not control-flow
dominance or complete mediation.

This closes the former shared-receipt/native-copy gap. It does not instantiate
all native primitive or captured-context contracts, prove JSON projection and
serialization/reflection/metadata observations, establish native I/O event or
connected adaptive session correspondence, close dependency/callback/drop
reachability, or complete NR-2/3/4/5 and independent security review. Existing
compiler, audit, clock, JSON and manifest assumptions retain their stated limits;
none grants project-owned conversion or whole-service confinement. Installed
vTPM evidence remains separate from physical custody and deployed VM isolation.

For focused proof development:

```sh
cd proofs
lake build +GarrettDispatch +GarrettCompletion +GarrettRequestSimulation
lake env lean -DwarningAsError=true -o .lake/build/lib/lean/GarrettRequestAdapter.olean GarrettRequestAdapter.lean
```
