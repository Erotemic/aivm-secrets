# Route-bound encoding and immutable endpoint

The production `provider_wire::append` now constructs Host and the checked
16-bit port from the admitted route and passes that route's authentication
mode to the complete HTTP encoder. Its `Fields` input contains only method,
target, Accept and custom headers. It cannot supply a competing host, port or
authentication mode; reserved custom headers remain rejected by the existing
encoder. The selected target remains the compiled operation target, not the
route's legacy path field.

Only successful complete encoding returns an `Endpoint`. Its host and port
are private, it has no public constructor or setter, and its getters return
exactly the Host/port supplied to that encoding. Native manifest setup receives
the zeroizing bytes and endpoint together. It takes TCP port and TLS server
name from the endpoint, removing its second port conversion and independent
route-field selection. The resolver's cached IP still comes from the executor
and requires the existing DNS/IP contract. An endpoint is not evidence that
TLS or a provider connection has succeeded.

The native byte adapter still converts operation strings and ordered headers
and renders its optional JSON body. It supplies the caller-owned zeroizing
buffer, route, borrowed credential and body to the extracted appender; refusal
retains the buffer for zeroizing drop. Existing invalid-policy versus
credential-source errors are preserved. Encoding completes before any TCP/TLS
setup. Actual request submission and consuming response eligibility continue
through the previously extracted owned channel.

`proofs/GarrettProviderWire.lean` defines twelve named obligations over actual
Charon/Aeneas output: endpoint getters, nonwrapping checked port conversion,
exact head construction/refusal, actual authentication/body/buffer argument
forwarding, endpoint origin, complete encoded bytes, and encoder-to-channel
write/flush composition. Byte theorems retain the complete encoder's explicit
`output length + request length + 22 <= usize::MAX` bound. Successful channel
release requires a write of those encoded bytes and successful flush on the
actual returned writer state, under the small, explicit faithful native buffer
view contract. No native readiness bit, provider arrival or whole-callback
history is assumed. A constructive accepted-input result retains positive use.

Core and native adapter tests cover both authentication modes, a nonstandard
port, selected target, complete binary/body framing, invalid port/host/target/
credential/header rejection, endpoint identity and exact bytes submitted through
the actual native writer/channel. Source guards and selected re-extracted
mutants complement those contracts. Optional compiler paths cover the actual
manifest encoder and endpoint getters; they do not establish dominance or
complete I/O mediation.

Native String/header/JSON conversion, faithful zeroizing buffer view,
std/TLS/DNS/parser/storage and drop/close/unwind semantics remain explicit
contracts. These results do not establish native whole-service I/O
correspondence, selected JSON/frame/close observations, adaptive histories or
W5 native noninterference. NR-2–NR-5, native write assurance, normative Rust API
parity, independent review, physical TPM provenance, real providers and deployed
isolation remain open. No Python core API, runtime dependency, wire version or
identity requirement is changed; Python verification edits are non-core.

Focused development:

```sh
cd proofs
lake build +GarrettHttpWire +GarrettProviderChannel
lake env lean -DwarningAsError=true GarrettProviderWire.lean
```

Named audits are centralized in `GarrettCheck`, with no default per-theorem
axiom dumps in this leaf. `garrett.py mutate --mutation-filter '^provider wire '`
selects six source mutants, not the complete mutation campaign.
