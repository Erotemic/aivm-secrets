# NR-4 selected-result rendering: production source extraction increment

This campaign moves the **actual production-called selected-response rendering**
from native `manifest/disclosure.rs` into the Aeneas-extracted Rust crate. The
first increment extracted the recursive traversal with native `SerdeBuilder`
callbacks. The latest increment makes the production builder concrete and
extractable as well: UTF-8 decoding, integer token formatting, object insertion
and canonical bytes are all owned by the Garrett core. The native serde builder
is removed, rather than retained as a proof-only alternative.

## Current production path (fourth increment)

`Session::request` -> `ManifestSelection::project` -> `Disclosure::project`
-> extracted `disclosure::project_fields` -> extracted
**`selected_conversion::render_wire(&selected.value)`** (calls the same generic
`render` with concrete `WireBuilder`) -> extracted `json_wire::encode`
-> **`ensure_selected_safe(&selected.value, &selected_bytes, credential)`**
-> extracted `manifest::release` -> native `json::parse` ->
`ManifestSelection::assemble` / `check_safe` -> `Completed::into_value` ->
`json::capture` -> extracted `json_wire::prepare` -> `GuestFrame::send`.

The selected-value traversal and builder now operate only on `disclosure::Json`.
`WireBuilder` uses an explicit RFC 3629 UTF-8 decoder for names/text, an explicit
signed-decimal formatter (including `i64::MIN`) for numeric tokens, a concrete
object insertion with duplicate detection, and `json_wire::Value` for each
constructor. The existing extracted `json_wire::encode` produces canonical
ASCII escaped bytes. A failing decode, duplicate, or `Opaque` terminates the
conversion. No provider raw-response parameter or fallback is available.

**The production path does not deserialize/re-serialize the selected value.**
Credential reflection checks consume the same source-owned selected tree and
its emitted bytes. The approved bytes then pass directly to `manifest::release`.
The native `ensure_safe` still independently checks the *assembled* guest reply.
The native serde parse of released public bytes and final assembly are still
important unproved adapter steps; moving selected conversion into the core
alone does not settle end-to-end byte correspondence.

The host disclosure schema is built by iterating a `serde_json::Map`, whose
ordered keys are the order supplied to `project_fields`. The existing Lean
root-key provenance theorem establishes that extraction preserves the host
field order, but a fully transitive proof of native map order, nested schema
order and wire-byte equivalence remains open. The direct concrete builder
retains that order; it performs no extra sorting, serialization, runtime
validation pass or alternate output encoding.

## First increment: extracted generic traversal (historical)

`selected_conversion::render` was moved into the Aeneas-extracted core while
production used native `SerdeBuilder` callbacks. Its failure order is name
decode -> child render -> duplicate insertion, and it rejects `Opaque`.
The native builder has now been replaced by the concrete `WireBuilder` above.

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

The earlier native-callback tests established parity at that stage. The current
code instead tests the real extracted `WireBuilder` and compares its bytes with
the independent native JSON encoder on nested, Unicode and integer fixtures.
Those are executable tests, not replacement Lean theorems.

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

- **Generated-source byte semantics:** `OpaqueFree` and schema-owned root keys
  are proved. A Lean refinement theorem still needs to derive from the
  *regenerated Aeneas definitions* that `render_wire` constructs the selected
  `json_wire.Value` and that `json_wire.encode` returns its exact bytes.
  The previous native `SerdeBuilder` premise is no longer part of this
  production path; there is no need to prove a deleted callback implementation.
- **Native input and ordering:** `document(response)` and the serde schema map
  are still native. The source-extracted projection preserves host field names
  and order, but the host map enumeration / string normalization / JSON parse
  must be connected to the trusted input and key-order assumptions.
- **Final guest observation:** `SelectedConversion` in
  `proofs/GarrettNR4ProjectedRelease.lean` has **not been discharged**. The
  remaining link is now narrower: source-produced public bytes through
  `manifest::release`, native `json::parse` and assembly, `Completed`, final
  `json::capture`, and guest frame. Errors and metadata are visible too.
- **Whole service:** socket delivery, cancellation, panics, audit durability,
  exhaustive I/O sink reachability, and provider-side effects are independent
  proof/environment obligations.

The source guard enforces the new production path and detects bypass mutants;
its source fingerprints and Rust parity tests are not themselves correctness
or whole-program mediation proofs.

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

The prior selected-input and root-key proofs compiled on the maintainer's pinned
host. This iteration changes the production Rust path, so compile and extract
the new concrete builder before extending the Lean proof. The next formal
theorem should target the *generated* `selected_conversion.render_wire`
specialization and `json_wire.encode`; after that, narrow the remaining
native `json::parse`/assembly/`json::capture` correspondence. Do not claim
`SelectedConversion` has been eliminated yet.

`proofs/garrett-manifest.json` is intentionally **not re-fingerprinted here**:
source and generated proof coordinates should be recorded only after the
actual pinned extraction, Rust tests and Lean compilation. The explicit
`record-sources` action checks generated-source freshness and compiles Lean,
then refreshes the normal source fingerprints **without an axiom audit**. It
is not a proof of the serde adapter or an independent security certification.
