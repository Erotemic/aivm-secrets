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

## Precisely what is not proved yet

- **Translation gate:** the checked-in generated Lean file predates this new
  Rust function until Aeneas is run on the pinned host toolchain. This source
  overlay is not a new Lean theorem or an accepted NR-4 proof. Do not manually
  insert alleged generated definitions into `proofs/generated/`.
- **Builder contract:** `SerdeBuilder` is native, not itself Aeneas-extracted.
  Its text/name UTF-8 conversion, integer/boolean/array construction,
  duplicate-key map insertion and error semantics still need a proof or a
  reviewed external contract tied to `selected_conversion.Builder`.
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
lake build GarrettNR4ProjectedRelease GarrettProductionSelectedRelease
cd ..

# After reviewing generated Lean and confirming focused Rust/Lean checks:
python3 dev/verification/garrett.py record-sources
```

Aeneas/Charon may require a further extraction-compatibility adjustment to
this generic recursive interface; it was not executed in the overlay-creation
environment. Preserve the actual production traversal rather than replacing
it with a proof-only copy. After successful extraction and focused compilation,
review the generated `selected_conversion.render` definition and prove its
structural preservation/no-opaque-release property, then discharge the
specific `SerdeBuilder` callbacks before claiming that
`SelectedConversion` has been eliminated.

`proofs/garrett-manifest.json` is intentionally **not re-fingerprinted here**:
source and generated proof coordinates should be recorded only after the
actual pinned extraction, Rust tests and Lean compilation. The explicit
`record-sources` action checks generated-source freshness and compiles Lean,
then refreshes the normal source fingerprints **without an axiom audit**. It
is not a proof of the serde adapter or an independent security certification.
