# Source-owned current admission

The production manifest request captures one borrowed `current_admission::Context`
from the bound identity, expected issuer/audience/subject/epoch, actual peer,
credential-use claims and grant, selected operation and host write policy. Its
fields are private. The native request passes this context to the extracted
`Bound` dispatch adapter; raw provider primitives cannot replace it.

`Context::current` owns the former native closure's order: coordination,
wall-clock sample, control/revocation check, credential lease check, identity
`present`, monotonic elapsed sample, and `manifest::current`. Control, lease and
identity validation use the same wall-clock sample. Errors stop the prefix and
retain the actual primitive state. Identity denial maps to `InvalidCapability`;
manifest denial uses the existing native `use_error` mapping. OAuth refresh and
bound certificate renewal remain separate, and coordinator unavailability still
denies admission.

The bound provider's actual recheck calls this controller directly. It never
calls a raw provider's `recheck`; the native raw implementation now refuses
with `InternalError` if accidentally driven alone. The owned dispatcher still
wraps this adapter with its single-check/single-send and receipt gates. The
request's outer and completion checks also call the same context controller.
TLS setup can occur before admission; authorization is not atomic with a
network syscall, and a provider send stage records callback invocation rather
than delivery of all bytes.

`proofs/GarrettCurrentAdmission.lean` supplies 24 named obligations over the
exact Charon/Aeneas extraction. They characterize successful current admission
with every primitive's returned state, derive actual manifest stamp origin and
identity acceptance, and show context preservation for provider and dispatch
primitives. The read driver theorem also covers the actual outer owned-send
adapter: every reported current stamp, including failed-send/response prefixes,
was issued from the context captured before setup. This removes a whole-current
callback-origin premise at that driver seam. It does not yet connect all
request receipt deltas to W4/W5 events or adaptive native histories.

The clock, coordination, control and lease primitives still have explicit native
semantics to instantiate. Input byte conversions, TLS/parser behavior, complete
native I/O/drop/unwind reachability, selected JSON/frame/close observations,
whole-request/history correspondence and NR-2–NR-5 exit remain open. A private
context and passing source guard are not a whole-service mediation proof.
Compiler/standard-model correctness and the documented environment assumptions
remain conditional; vTPM tests do not establish physical custody or VM isolation.

Three native core unit tests exercise exact sampler order and terminal errors,
identity/grant/policy refusals, and the real bound owned dispatcher in both read
phases and a final write. Existing process tests cover positive reads, late
revocation and the retained completion audit. All credentials are synthetic.
The verification scripts are non-core developer tooling; no Python core API or
wire version changes.

Focused compilation:

```sh
cd proofs
lake build +GarrettProviderSimulation +GarrettDispatch
lake env lean -DwarningAsError=true GarrettCurrentAdmission.lean
```

Named axiom auditing remains in `GarrettCheck`; this leaf adds no default
per-theorem axiom dumps. Targeted re-extracted mutations use:

```sh
PYTHONPATH=dev/verification .venv/bin/python -c 'import garrett; garrett.mutate("^current admission ")'
```
