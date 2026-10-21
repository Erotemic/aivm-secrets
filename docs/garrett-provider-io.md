# Captured provider route and request submission

The production `ScopedRequest` now takes the provider route from its private
admission context's grant. It wraps each raw provider in `provider_io::Routed`
before constructing `current_admission::Bound`. The raw native factory no
longer carries a second route. `Routed` supplies its captured route to the
actual setup and dispatch-audit primitives; every returned mutable operation
retains that route. Native setup uses it for the request encoder, port and TLS
server name, and audit records its host and port. Direct raw native setup,
audit and current checks fail closed.

The native setup encodes the request before TCP/TLS and moves the zeroizing
buffer into `provider_io::Request`. Its private buffer has no setter or reset.
The native channel owns that request alongside its TLS stream. Submission marks
the request attempted before viewing the buffer or calling the writer, passes
that exact view to `write_all`, and calls `flush` only after a successful write.
Every returned prefix leaves the request spent, including zero or partial
acceptance and flush failure. Repeated submission refuses before accessing the
buffer or writer. The native adapter maps write/flush failure to the existing
upstream error; the provider controller retains its existing post-attempt
uncertainty classification. Protocol versions and authorization policy are
unchanged.

`proofs/GarrettProviderIO.lean` contains nineteen named obligations over the
actual Charon/Aeneas extraction. They characterize route/setup/audit arguments
and exact returned primitive state, preserve the route through all mutable
forwards, and characterize every returned submission by its actual buffer,
write and flush callback returns. The additional `dispatch_route` obligation
in `GarrettRequestContext.lean` derives the connection to the captured grant
without a native route/frame premise. All preceding production-entry trace
obligations remain general over the routed primitives. Named axiom audits are
centralized in `GarrettCheck`; normal leaf compilation emits no axiom dumps.

Core tests cover exact binary bytes, zero/partial write errors, flush error,
success and replay refusal without another buffer read. Native tests exercise
the actual `std::io::Write` adapter under the same prefixes and preserve the
existing controller failure/uncertainty cases. Read workflow gates still need
real native process execution without skips. Source guards and re-extracted
bypass mutants are complementary checks, not semantic I/O proofs.

The buffer-view trait and native zeroizing wrapper correspondence, native
channel field wiring, standard `Write`, TLS, DNS/IP selection, parser, durable
audit and environment semantics remain explicit contracts. The captured host
and port do not prove the resolver's IP or TLS implementation. `write_all`
invocation is an attempt and may have partially accepted bytes on error; it
does not establish provider arrival or delivery. The source-owned submission
proof is not a complete native controller-to-syscall or whole-service I/O
correspondence theorem. Native setup/encoder conversion, selected JSON,
framing/close observations and connected adaptive session histories remain
open. NR-2–NR-5, native write assurance, normative Rust core parity, independent
security review, physical TPM provenance and deployed isolation are not closed
by this increment.

Focused development:

```sh
cd proofs
lake build +GarrettDispatch +GarrettOwnedRequestTrace
lake env lean -DwarningAsError=true GarrettProviderIO.lean
lake env lean -DwarningAsError=true GarrettRequestContext.lean
```

Re-extracted deliberate source mutations are selected with
`garrett.py mutate --mutation-filter '^provider io '`. This selects six cases,
not the complete mutation campaign. Python verification changes are non-core
tooling; no Python core contract or runtime dependency is added.
