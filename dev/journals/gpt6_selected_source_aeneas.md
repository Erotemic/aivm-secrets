## 2026-10-22 14:59:12 -0400

Moved the native projection renderer's recursive structural traversal into
`aivm-secrets-garrett-core::selected_conversion::render`; the production
`Disclosure::project` calls it via `SerdeBuilder`. Callback order matches the
previous native `render` (name decode, child render, duplicate insertion).
The approved tree remains the only input to this traversal; serde, UTF-8,
map representation, canonical encoding, and guest I/O remain boundaries.

Validation here: W0 and reviewed W3 source gates passed. 172 focused W3
regression tests passed, including mutants removing the extracted call or
opaque rejection. The environment lacks the pinned Rust, Aeneas/Charon and
Lean binaries and cannot download them, so neither the new Rust build nor
Aeneas extraction/Lean compilation was performed here. No generated Lean
file or proof manifest was fabricated or re-fingerprinted. After the pinned
host extraction, prove the structural traversal and then the narrower
SerdeBuilder/SelectedConversion correspondence instead of assuming it.

Risk: the pinned Aeneas translator may reject a generic mutable recursive
builder or its associated types. If so, preserve production semantics and
report the specific translator diagnostic. Confidence: source linkage and
native failure-order design are straightforward; extractor acceptance has
not yet been measured.
