# Source-owned canonical JSON string quoting

The [complete production encoder](garrett-json-wire.md) captures each native
string as Unicode scalars and calls `json_string::append` directly into its
final byte vector. The scalar/list quoting implementation and theorems below
remain the actual production leaf. Native recursive String layout and
ASCII-to-String append have now been removed from canonical serialization;
ordering, number spelling and UTF-8/scalar capture remain local contracts.

The core accepts the complete Unicode scalar domain, including supplementary
planes, controls and noncharacters; it refuses surrogate code points and values
above U+10FFFF. It validates the whole scalar list before modifying the caller's
buffer. Accepted output is quoted printable ASCII: the existing short escapes,
lowercase four-digit UTF-16 escapes, and mathematically matched surrogate pairs
for non-BMP scalars. Invalid input anywhere leaves the original buffer intact.
The caller's pre-existing prefix is preserved on success.

`GarrettJsonStringScalar.lean` and `GarrettJsonString.lean` contain 29 named
obligations over actual Charon/Aeneas output. They cover scalar admission,
hexadecimal digits, UTF-16 pair bounds/reconstruction, exact scalar and list
bytes, complete validation, all returned quoting outcomes, buffer preservation,
positive construction, printable output and absence of raw CR/LF in the appended
segment. Accepted byte proofs retain the explicit bound
`output length + 12 * scalar count + 2 <= usize::MAX`; this is not a host-memory
allocation guarantee. Invalid-input preservation and success-implies-admission
do not require that capacity premise. No callback-wide history, readiness bit
or whole-service secrecy conclusion is supplied as an assumption.

Tests compare every valid Unicode scalar with the previous independent
`encode_utf16`/formatting implementation. Mixed and nested native JSON tests
cover exact bytes, controls, BMP/non-BMP text, quoted names, and parser round
trip. Invalid scalar positions preserve binary prefixes. Source guards and
re-extracted mutations complement these checks; optional compiler linkage to
the actual native canonical/string/core encoder is not dominance or mediation.

This discharges the source-owned scalar/list quoting segment. Native UTF-8
iteration and scalar-list conversion, number spelling and object order,
zeroizing views, JSON parsing, TLS/close behavior,
complete native outcome/event and adaptive-history correspondence remain
contracts or open implementation links. The printable-byte theorem is not a
proof of the native parser or of decoded/encoded credential noninterference.
The existing reflection checks still apply. NR-2–NR-5, native write assurance,
normative Rust parity, independent review, physical TPM provenance, real
providers and deployed isolation remain open.

The scalar vector and temporary encoded bytes add allocation/copy work; they
are zeroized on drop. Memory allocation, reallocation and dependency drop/unwind
semantics retain the existing host/environment contracts. No new runtime
dependency or Python core API is introduced. Python verification edits are
non-core tooling.

Focused development:

```sh
cd proofs
lake build +GarrettJsonStringScalar
lake env lean -DwarningAsError=true GarrettJsonString.lean
```

All 29 audits live in `GarrettCheck`; these leaves add no default axiom dumps.
`garrett.py mutate --mutation-filter '^json string '` selects six source
mutations, not the complete mutation campaign.
