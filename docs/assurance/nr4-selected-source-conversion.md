# NR-4 selected-result rendering: production source extraction increment

This increment moves the **actual production-called recursive rendering
traversal** from native `manifest/disclosure.rs` into the Aeneas-extracted Rust
crate. It does not add a second reference implementation or a runtime check.
The native `SerdeBuilder` still implements the conversion primitives.

## One production path

`Session::request` -> `ManifestSelection::project` -> `Disclosure::project`
-> extracted `disclosure::project_fields` ->
**`selected_conversion::render(&selected.value, &mut SerdeBuilder)`** ->
`ensure_safe` -> `json::canonical(&value)` -> extracted `manifest::release`
-> `json::parse` -> `ManifestSelection::assemble` / `check_safe` ->
`Completed::into_value` -> `json::capture` -> `json_wire::prepare` ->
`GuestFrame::send`.

`selected_conversion::render` is a recursive, production-used Rust function
with an Aeneas-compatible generic callback interface. It traverses only its
`disclosure::Json` input, never receives the raw provider response, preserves
array and object member order, rejects `Opaque`, and short-circuits on failing
name/child/insertion callbacks. Name decoding precedes the child; duplicate
insertion is checked afterward, matching the previous native renderer. The
native implementation still constructs the same `serde_json::Value` variants
and applies the same UTF-8 and duplicate-key errors. Inlining can eliminate
the callback abstraction; no additional authorization or serialization pass
is introduced.

## Second increment: extracted projection guarantees renderer input shape

The maintainer confirmed that the preceding Rust extraction and Lean increment
worked on the pinned host. The follow-up
[`GarrettSelectedConversionInput.lean`](../../proofs/GarrettSelectedConversionInput.lean)
uses the existing Aeneas-extracted `disclosure.project` and
`disclosure.project_fields` contracts to prove that **every successfully
selected tree excludes `Opaque` at every depth**, rather than relying on a
source comment or a flat top-level check. The input cannot contain an opaque
leaf when the production `render(selected.value)` call is reached after a
successful `project_fields`. The new module is included in Lake's focused proof
gate and the ordinary source manifest; the generated file is not hand-edited.

Native tests now exercise **each** `SerdeBuilder` callback's value/error
behavior and compare nested selected serde output with the existing extracted
wire encoder. This evidence is executable parity testing, **not** a Lean proof
of the native callbacks.

## Third increment: source-owned public names and exact root-key provenance

`manifest/disclosure.rs::Projection::fields` now validates its host-configured
output names using `selected_conversion::public_field_name` in the same Rust
crate as the production renderer. Its explicit byte loop has the same
32-byte bound, lowercase-ASCII first character and ASCII alphanumeric / `_`
continuation policy as the previous native predicate. Names are allocated
once into the `Field` passed to `disclosure::project_fields`; no new check or
extra pass occurs during a guest request. Rust tests exhaustively compare
one- and two-position byte cases and the 31/32/33-byte boundaries with the
previous predicate. The production name predicate is now an Aeneas extraction
target; its exact boolean postcondition needs a later generated-source proof.

`GarrettSelectedConversionInput.successful_project_fields_has_exact_root_keys`
derives, from the existing Aeneas-extracted `project_fields` contract, that a
successful result is a root `Json.Object` with *exactly* the ordered names in
the host `Field` schema. The helper `fieldsWith_preserves_names` proves name
preservation for successful recursive specification traversals. Together with
`OpaqueFree`, the companion `successful_project_fields_has_public_shape`
provides the two renderer-input facts without assuming that selected keys
match the schema. This does not prove the native builder faithfully encodes
those names, that recursively nested names satisfy the host name predicate,
or that the emitted guest bytes match the selected tree.

The W3 source guard now rejects production callers that bypass the extracted
name validation, and rejects changed length/byte policy anchors. Its reviewed
source hashes have been updated for only the two modified Rust files.

## Precisely what is not proved yet

- **Extracted renderer output:** `OpaqueFree` and exact schema-owned root
  keys constrain its input. The next theorem must establish structural output
  preservation from the actual
  Aeneas-generated `selected_conversion.render` definition (including arrays,
  object keys, and short-circuit behavior), without postulating that behavior.
- **Builder contract:** `SerdeBuilder` is native, not itself Aeneas-extracted.
  UTF-8 decoding, integer/boolean/array construction, duplicate-key map
  insertion and error behavior are covered by focused native tests but are not
  formally related to the extracted builder interface.
- **Byte conversion:** `SelectedConversion` in
  `proofs/GarrettNR4ProjectedRelease.lean` remains a hypothesis. Linking the
  approved selected tree to `json::capture`, serde parsing, canonical byte
  conversion and guest-frame observations needs additional source-linked work.
- **Whole service:** this change proves nothing about socket delivery,
  cancellation, panics, audit durability or exhaustive I/O sink reachability.

## Focused validation on the pinned development host

From the repository root:

```bash
python3 dev/verification/w0_contract.py check
python3 dev/verification/w3_effect_boundary.py check
python3 -m pytest -q tests/test_secrets_w3_effect_boundary.py

cd rust
cargo +nightly-2026-09-17 fmt --all -- --check
cargo +nightly-2026-09-17 test --locked -p aivm-secrets-garrett-core --lib selected_conversion
cargo +nightly-2026-09-17 test --locked -p aivm-secrets-garrett --lib manifest::disclosure::tests
cd ..

python3 dev/verification/garrett.py extract
cd proofs
lake exe cache get
lake build GarrettSelectedConversionInput GarrettNR4ProjectedRelease
cd ..

# After reviewing generated Lean and confirming focused Rust/Lean checks:
python3 dev/verification/garrett.py record-sources
```

The previous pinned-host extraction is user-confirmed. This follow-up
adds Lean input-invariant proofs and native parity tests without changing
production traversal. After focused compilation of the new module, prove the generated
`selected_conversion.render` output-refinement theorem and then discharge the
specific `SerdeBuilder`/`json::capture` correspondence before claiming that
`SelectedConversion` has been eliminated.

`proofs/garrett-manifest.json` is intentionally **not re-fingerprinted here**:
source and generated proof coordinates should be recorded only after the
actual pinned extraction, Rust tests and Lean compilation. The explicit
`record-sources` action checks generated-source freshness and compiles Lean,
then refreshes the normal source fingerprints **without an axiom audit**. It
is not a proof of the serde adapter or an independent security certification.
