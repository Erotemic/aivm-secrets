# Owned provider channel and response eligibility

The native manifest channel is now the production
`provider_io::Channel<ManifestWire, ProviderWriter<TlsStream>, Deadline>`.
The core privately owns the captured request, the actual writer, the response
lifetime state and a response-ready flag. Native setup still encodes before
TCP/TLS, retains the zeroizing buffer through setup failures, and constructs
the channel from that buffer, completed stream and deadline. The native writer
owns its stream; the core selects the exact captured request and writer fields
when calling the previously extracted submission controller.

Channel construction creates an unattempted request and denies response access.
Submission withdraws any prior readiness, then runs the actual request
submission. Only successful write and flush enable response access. A write
error, flush error or refused repeated submission leaves it disabled. The
consuming `into_parts` refuses an unready channel; otherwise it releases the
exact writer, spent request and response-lifetime state. Native receive invokes
this gate before constructing its buffered response reader. Thus an early
parser call, or one after a failed/repeated submission, fails closed in the
actual runtime. Valid provider outcomes and their existing public uncertainty
classification remain unchanged.

`proofs/GarrettProviderChannel.lean` contains eleven named obligations over
actual Charon/Aeneas output. They derive constructor state, exact mutable
submission states, captured body/metadata preservation, spent status, exact
parts release/refusal, replay withdrawal, successful operation and the actual
write/flush origin of parser eligibility. In particular, released parts after
an actual channel submission require the captured buffer view, successful
`write_all` on the captured writer, and successful `flush` on its actual returned
state. The result does not assume a provider arrival, a native readiness bit,
or an entire callback history. The earlier route/context and all-returned
entry trace contracts remain unchanged.

Core and actual native writer tests cover binary bytes, zero/partial writes,
flush error, positive release, early response refusal and replay withdrawal.
The existing native controller failure tests use the same channel and response
gate. Source guards include rebaselined constructor, field visibility,
submission, readiness, request-reset and native parser-gate bypasses. The
optional specialized compiler capture checks the response path to the actual
`into_parts`, alongside the request submission to the concrete native writer.
Compiler paths are linkage evidence, not dominance or complete mediation.

This closes source-owned channel field selection and response-eligibility
preservation from its actual constructor through submission/release. Native
setup/encoder conversion, `ManifestWire`'s buffer view, standard/TLS writer,
DNS/IP and parser/storage semantics still require explicit contracts. A flush
acknowledgement does not prove provider arrival or complete delivery. No
whole-service native I/O, selected JSON/frame/close, nonreturning/drop/unwind,
adaptive history or W5 native noninterference theorem is claimed. NR-2–NR-5,
native write assurance, normative Rust core parity, independent review, real
provider validation, physical TPM provenance and deployed isolation remain open.

Focused development:

```sh
cd proofs
lake build +GarrettProviderIO
lake env lean -DwarningAsError=true GarrettProviderChannel.lean
```

The eleven axiom audits are centralized in `GarrettCheck`; the leaf adds no
default axiom dumps. Select six source-extracted mutations with
`garrett.py mutate --mutation-filter '^provider channel '`, not a complete
mutation campaign. Python verification changes are non-core tooling. No Python
core contract, runtime dependency, protocol version or identity requirement is
introduced.
