# NR-2/NR-3 exact native I/O and guest boundary push

## 2026-10-22

Goal: advance from the already compiled NR-2/NR-3 source-event composition
toward enforceable production native security assurance in one large proof
batch, without altering production Rust behavior.

New modules:

- `GarrettNR23ExactSinks`: replace native-event membership with an ordered,
  multiplicity-sensitive equality; prove implications for authorization,
  audit, binding, and send count; derive stronger top-level results from the
  returned source request, subject to `ExactNativeSinkCoverage`.
- `GarrettNR23WriterOrigin`: connect real extracted `Channel.submit` to
  captured exact `WireBytes`, writer/flush callbacks, response eligibility,
  and failed writer replay confinement. Explicit `PayloadCorresponds` is the
  still-open native OS/TLS observation binding.
- `GarrettNR23NativeRoute`: strengthen source-owned captured-route forwarding
  for audit, setup, recheck, send, receive, and dispatch callback sequences.
- `GarrettNR23GuestObservations`: paired successful completed source reads
  with equal allowed JSON bytes prepare equal public frames; failed frame
  attempts cannot silently retry; preserve callback-byte equality even when
  writer results differ.
- `GarrettNR23ProductionBoundary`: compose ordered native attempts, current
  authorization, successful completion audit, native exact payload, and
  public response-frame bytes for successful reads and returned denials.

Also added `nr23_native_edges.py` and mutation tests for 15 production Rust
source anchor sequences; a static source guard, emphatically **not** a
semantic Rust extraction or proof of full effect reachability.

Authoring-time validation: 170 Python tests passing across native-edge
mutations and W3 effect regression; W0/W3/W6 source guards passed. The
pinned Lean 4.35.0/Lake is not available here; the new Lean modules are
**uncompiled candidates** until the maintainer runs the focused target.

Outstanding high-impact issues: transitive sink-closure and exact correspondence
of real TLS/OS sends; unextracted native `ManifestProvider` callback effects;
concrete audit durability; native `serde_json`/error-to-guest conversion;
whole-session adaptive noninterference. Avoid declaring the system trusted for
unattended host-held credentials until these obligations are either proved or
explicitly reviewed as defensible external contracts.
