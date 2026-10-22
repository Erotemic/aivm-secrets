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

## 2026-10-22 16:53:38 -0400

Extended the successful extracted-root projection proof: its selected value
must be a JSON object with exactly the host schema's ordered field names, and
the previously proved entire-tree `OpaqueFree` invariant still holds. The
proof reuses `project_fields_contract`, `refFields` and `fieldsWith` rather
than constructing another execution surrogate.

Moved the native policy's ASCII output-name test into the production-called
`selected_conversion::public_field_name` Rust function to expose it to
Aeneas. The native policy parser validates the same allocated field name
before building the `Field`; no additional validation is added at request
time. Rust unit regression compares the previous predicate across all bytes
and policy-length boundaries. The W3 source anchors and two Rust fingerprints
were refreshed following source review.

Local checks: W0 and W3 source guards pass; 174 focused W3 Python tests pass.
The pinned Rust/Charon/Aeneas/Lean toolchain is absent here, so extraction,
Rust compilation and focused Lean compilation remain host checks for this
new increment. No generated Lean or manifest hash has been fabricated.

Next: prove the extracted public-field-name predicate's exact accepted byte
language, then derive the structural callbacks of the actual generated
`selected_conversion.render` with an explicit serde-builder contract.
