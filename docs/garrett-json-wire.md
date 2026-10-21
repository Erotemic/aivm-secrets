# Complete canonical JSON bytes and guest frames

The native canonical encoder captures a serde JSON value once into
`json_wire::Value`. Native conversion retains map iteration order and the
existing `as_i64`/number-token spelling, and converts text and names to Unicode
scalars. The captured tree is private and immutable during encoding. Its native
Drop implementation clears owned number, text and name buffers; allocation,
partial construction and drop/unwind semantics remain host/dependency contracts.
The extra tree copy and traversal are explicit runtime costs.

Production `json_wire::append` now writes null, booleans, captured number tokens,
quoted scalar strings, arrays, objects and all separators into the final byte
vector. `json::canonical` returns that vector directly. The previous native
recursive String builder and ASCII-to-String append are removed from this path.
No wire version, sorting, numeric spelling, identity or authorization change is
intended. Compatibility tests compare the old independent encoder over nested
values, controls, non-BMP text, number spellings and 4,300-digit integers.

Guest reply construction captures the selected success or fixed error value and
calls `Captured::prepare`. This calls the actual core `json_wire::prepare`, which
encodes that captured tree and passes only the returned payload directly to the
existing bounded, single-attempt `guest_frame`. Encoding refusal cannot construct
a frame. Successful frame preparation retains the existing newline/length rules;
even a raw number-token contract violation containing LF is rejected there.
Number-token grammar is not redefined or proved by this encoder.

`GarrettJsonWire.lean` proves the actual recursive Rust encoder's exact bytes
through arrays, objects, keys, strings and scalars. `GarrettJsonFrame.lean` links
actual returned encoding, frame and send states. The thirteen named obligations
cover bounded exact layout, accepted encoding, positive construction, refusal,
frame admission/denial, wire length/line/readiness, and actual writer input,
including returned write/flush errors. A paired-preparation lemma gives equal
bounded wires for equal modeled encodings; it is not adaptive native secrecy.

Proof depth is a mathematical induction parameter, not a runtime fuel limit.
`Valid depth value` requires sufficient depth and valid string/name scalars.
`Bound depth value` counts worst-case twelve-byte scalar escaping, punctuation
and captured number lengths. Positive encoding uses `output length + Bound <=
usize::MAX`; this is not an allocation guarantee. Complete frame contracts also
use the actual reply limit and reject raw embedded LF. The local native serde
capture, number grammar/spelling and map-order contracts remain explicit.

The actual `Bridge::serve` now matches frame and parse results directly before
calling `answer`. This preserves the previous `and_then` failure mapping while
making the source-owned dispatch edge visible in the optional compiler graph.
The graph root is `serve`; new paths connect reply capture to core encoding and
frame preparation. These are bounded call paths, not execution traces, dominance
or complete I/O reachability evidence.

Native UTF-8/scalar and serde capture correspondence, faithful provider buffer
views, parser/TLS/DNS/filesystem/close semantics, actual request event projection,
selected-value disclosure and adaptive histories still need their separate
contracts and implementation links. NR-2–NR-5, native write/API parity,
independent review, real provider compatibility and deployed isolation remain
open. Python verifier/test changes are non-core; no Python module or runtime
dependency is added.

The existing [assumption ledger](planning/aivm-secrets-assumptions.json) maps
underlying parser/representation semantics to `RUST-JSON-01`, compiler/runtime
correspondence to `RUST-COMPILER-01`, and guest TLS/Write/close semantics to
`RUST-MTLS-01`. Project-owned serde capture, conversion and disclosure links
remain obligations under `MANIFEST-RUST-01`; these entries do not grant them as
trusted application conclusions. The affected W0 sinks are `S-GUEST-FRAME` and
`S-GUEST-CLOSE` in the [sink inventory](planning/aivm-secrets-w0-boundaries.json).
This increment adds no new approved environmental assumption.

Focused development:

```sh
cd proofs
lake build +GarrettJsonWire
lake env lean -DwarningAsError=true GarrettJsonFrame.lean
```

`GarrettCheck` contains the thirteen named axiom audits. The two leaves contain
no default axiom dumps. `garrett.py mutate --mutation-filter '^json wire '`
selects eight re-extracted source mutants, not the entire mutation campaign.
