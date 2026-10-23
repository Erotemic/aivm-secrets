# Anodized 0.7 contract pilot (2026-10-23): no-go, direct theorem kept

**Question.** Can Anodized `#[spec]` contracts on production Rust be carried
through the pinned Charon/Aeneas pipeline (`nightly-2026.10.16-d95aeac`,
Lean 4.35.0) into Lean, so that a source-annotated postcondition becomes the
statement we prove? Pilot function: `selected_conversion::public_field_name`,
which the native manifest parser calls on every host output field name.

**Decision: no-go for production.** The Anodized dependency, feature and
attribute were not kept in the production crate. The strongest useful result,
a complete theorem about the unannotated extracted function, is kept.

Reproduce: `python dev/verification/anodized_pilot.py`. It patches a scratch
copy of the core crate under `.tools/anodized-pilot`, never the production
sources or `proofs/generated`, and prints a JSON report.

## What was observed

Setup: `anodized = "=0.7.0"` behind an optional `verification-specs` feature,
`#[cfg_attr(feature = "verification-specs", anodized::spec(ensures: |output|
[!output || (1 <= len <= 32 && 'a' <= bytes[0] <= 'z')]))]`, crate-level
`register_tool(charon)` under `cfg(anodized_charon)`, and
`RUSTFLAGS="--cfg anodized_charon"`.

1. **Rust.** The default build, the feature build and the
   `anodized_charon` build all compile. The validator test gives the same
   verdicts with and without the contract (empty, 33-byte, uppercase/`_`/digit
   first byte, `-`/`.`/space/non-ASCII/`/` later bytes refused; mixed-case,
   digit and `_` suffixes accepted).
2. **Macro output.** Anodized emits separate
   `__anodized_fn_requires_public_field_name` and
   `__anodized_fn_ensures_public_field_name` items tagged
   `#[charon::contract(kind = "precondition" | "postcondition", for =
   "public_field_name")]`. Contrary to the expectation that the annotated body
   is untouched, it also **inserts two unused closures into every loop
   iteration** of the body (`__anodized_loop_maintains`,
   `__anodized_loop_decreases`). They do not change behaviour, but the body
   handed to Charon is not the production body.
3. **Charon.** The pinned Charon understands these attributes. It folds the
   contract into the function: in the LLBC, `public_field_name` becomes a
   wrapper that runs the original body as a closure and then the
   postcondition.
4. **Aeneas.** The extracted Lean `selected_conversion.public_field_name` is:

   ```lean
   let __anodized_output ← anodized.__.eval_once <body closure> bytes
   let (__anodized_post, __anodized_output1) ←
     anodized.__.apply_keep <postcondition closure> (true, bytes) __anodized_output
   if __anodized_post then ok __anodized_output1 else ok __anodized_output1
   ```

   `anodized.__.eval_once`, `apply_keep` and `eval` are **new uninterpreted
   axioms** (Anodized's helper functions are not translated). The function's
   result therefore goes through an axiom: nothing about what it returns can
   be proved, including the contract itself. The contract is not emitted as a
   Lean statement or proof obligation either; it exists only as closure code,
   and the wrapper returns the same value whether or not it holds.

So adopting it would replace a transparent, provable definition with an
opaque one and add three axioms. That is the opposite of the project's
"Aeneas first, no new axioms" rule. Not attempted, per the brief: hax,
a different Charon, or hand-written models of the Anodized helpers (that
would be an unproved assumption standing in for the contract).

## What is proved instead

[`GarrettPublicFieldNameContract`](../../proofs/GarrettPublicFieldNameContract.lean),
over the authoritative, unannotated extraction (`proofs/generated`, unchanged):

| Theorem | Says |
| --- | --- |
| `public_field_name_spec` | The function always returns, and returns `true` **exactly** for names of 1–32 bytes whose first byte is `a`–`z` and whose every byte is `a`–`z`, `A`–`Z`, `0`–`9` or `_` (`PublicFieldName`). |
| `public_field_name_loop_spec` | The extracted loop from `index` answers `true` exactly when every byte from `index` on is allowed. |
| `public_field_name_necessary` | The condition that was tried as the Anodized `ensures` contract: acceptance implies length 1–32 and a lowercase first byte. |

Semantics obtained from extracted Rust: the function and its loop, as
compiled. Handwritten in Lean: the predicates `FieldNameByte` and
`PublicFieldName`, which state the intended language. The proof shows the
extracted code decides exactly that language; reviewers should check that the
predicates say what they want (they are eight lines).

## Comparison with the direct-Aeneas boundary

| | Direct Aeneas (kept) | Anodized + pinned Charon/Aeneas |
| --- | --- | --- |
| Extracted `public_field_name` | Transparent; the production body | Wrapper over three uninterpreted axioms |
| Where the specification lives | Lean predicate, reviewed in the proof file | Rust attribute; reaches Lean only as closure code |
| What is proved | Exact accepted language (both directions), totality | Nothing provable about the result |
| New axioms | None (baseline two) | `anodized.__.eval_once`, `apply_keep`, `eval` |
| Production build | Unchanged | Unchanged if feature-gated, but the verified body differs from the shipped one |

## Next function, if a later toolchain changes this

When Charon/Aeneas translate Anodized's helpers (or emit contracts as Lean
statements), rerun the pilot. The next candidate is `route::segment_ok`
(`rust/crates/aivm-secrets-garrett-core/src/route.rs`): a small, total,
production-called byte validator with an existing Lean contract
(`segment_ok_contract`) to compare against, used on every provider target.
