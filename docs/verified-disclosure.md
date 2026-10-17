# Conditional verification of native response disclosure

The optional Rust `manifest-https-v1` backend constructs provider responses using
an extracted typed filter. Lean checks the actual Rust selection algorithm
against an independent recursive specification. This is experimental, unaudited
work; it does not verify the complete broker or prove that a provider cannot
encode a credential in an approved public field.

## The claim

Given the same host schema, construction budget and recursion fuel, two parsed
provider documents that agree on the schema-selected values produce exactly the
same filter result. Agreement follows nested objects and array elements;
unselected fields can have arbitrary different values. Equality includes the
owned output tree, output names, remaining budget and denial outcome.

The filter constructs output names from the schema and output leaves from
selected typed inputs. Unknown provider fields have no serialization path in
the filter. For example, with only `rows[].id` approved, changing an element's
`secret`, adding a provider field named like an output alias, or changing private
siblings at a nested path cannot change the selected response.

The schema itself must be reviewed. If an operator approves a text field in
which the provider places a credential, selection alone cannot make that field
public. The native adapter additionally rejects literal credential reflection
in selected decoded names/strings and canonical output bytes. That scan does
not detect arbitrary encodings, fragments, semantic leaks or timing channels.

## Implementation and proof connection

- [disclosure.rs](../rust/crates/aivm-secrets-garrett-core/src/disclosure.rs)
  owns typed lookup, strict scalar matching, recursive object/array selection,
  text rejection and a conservative construction budget. It has no provider I/O
  or fallback serializer for discarded input.
- [the native adapter](../rust/crates/aivm-secrets-garrett/src/manifest/disclosure.rs)
  parses the host schema, decodes bounded provider JSON into the typed input,
  invokes the core filter and renders only its owned selected tree. Unsupported
  numeric forms cannot become integer leaves. Conversion/rendering failures
  reject the result.
- [GarrettDisclosure.lean](../proofs/GarrettDisclosure.lean) states an independent
  list specification and proves equivalence of the Aeneas-extracted functions.
  `project_contract` covers every projection and `project_fields_contract`
  covers the root field set. These include rejection and successful execution.
  The array/object loop contracts prove traversal and sticky rejection rather
  than assuming the loop's accumulated values are already safe.
- `view_injective` proves that the public tree representation loses no successful
  output structure. Noninterference therefore compares actual filter results,
  not a truncated observation that could omit a private subtree.
- `recursive_projection_noninterference` uses the schema-directed
  `ProjectionAgreement` relation. Its premises constrain selected leaves and
  selected array structure, while leaving unselected provider fields unconstrained.
  `ignored_input_field_noninterference` also provides a concrete arbitrary
  ignored-field result. A successful Boolean witness excludes an always-deny
  implementation.

No project security axiom or admitted proof is permitted. The gate audits all
named obligations and their transitive dependencies; only the established Lean
axioms `propext`, `Classical.choice` and `Quot.sound` are allowed. Rust mutations
challenge wrong keys/paths, text rejection, changed values/names, projection from
the wrong object, skipped array elements and depth/schema guard bypasses.

## Exact literal reflection search

[reflection.rs](../rust/crates/aivm-secrets-garrett-core/src/reflection.rs)
implements the borrowed-byte search used by the native reflection checks.
[GarrettReflection.lean](../proofs/GarrettReflection.lean) proves that it reports
exactly every nonempty literal occurrence, including the first and last possible
offsets. A false search result excludes such an occurrence, and every nonempty
value matches itself. Empty needles are deliberately false; credential
acquisition separately rejects empty credentials.

The native JSON adapter applies this predicate to selected decoded strings and
keys and to the complete canonical public success frame. A numeric credential
reflected through an allowed integer id is rejected too. The source proof covers
the byte predicate; correct JSON walking, serialization, invocation and final I/O
remain adapter obligations. The predicate detects no encoding, fragmentation,
semantic or timing channel and has no constant-time claim.

A test-only conformance action compares 5,010 seeded binary and boundary cases
with Python byte operations. Five Rust mutations invert comparison, omit the
first/last position, reject equal-length matches or skip alternating positions.
The implementation borrows credentials and uses slice equality instead of
copying them. A worst-case synthetic benchmark under the pinned Rust compiler
measured about 135 ms against 112 ms for the previous standard search; this is
local performance evidence, not a resource or timing-security theorem.

## Practical limits

This source proof begins with the typed input tree. It relies on the host schema
and provider JSON adapters, UTF-8 conversion, output rendering and error mapping
being faithful. It does not refine the JSON parser, TLS, filesystem, audit,
clock, pagination metadata, concurrency or operating-system execution into this
model. Translation, standard models, Lean's kernel and the Rust toolchain remain
trusted. The native adapter's fixed recursion bound and response size limits
are operational protections; the proof does not model process resource failure.

Even equal filter results do not imply equal whole-service traces. A changed
private provider field could change HTTP size, parsing limits, duration or a
transport failure before filtering. Metadata and timing are outside this
noninterference theorem. Provider credentials, host keys and the enrolled
client's signing oracle retain the custody assumptions in the
[Garrett overview](verified-garrett.md) and assumption ledger.

The [native manifest tests](../tests/test_rust_garrett_manifest.py) exercise real
synthetic HTTPS requests, nested ignored-field changes, schema-owned output
names, strict child types, whole-result rejection and literal reflection denial.
They complement independent Python effect-compilation and protocol parity tests;
finite tests are not a proof of the complete Python and Rust services' equivalence.

Reproduce the source, axiom and parity gates with:

```bash
.venv/bin/python dev/verification/garrett.py check
.venv/bin/python dev/verification/garrett.py mutate
```
