# Rust primitives and Lean verification: reconnaissance

Date: **2026-10-16**. Inspected standalone source at
`7de33b7` (Python package 0.2.0). This is an implementation proposal grounded
in source and upstream inspection. No Rust implementation, extraction run,
Lean proof build, or new verification claim is delivered by this reconnaissance.

## What we can start

Start M5 now with an independent Rust leaf crate and one implementation-linked
Lean theorem for epoch advancement. Extend that working extraction/proof path
to epoch equality, half-open time validity, and exact identity equality before
attempting JSON or the complete broker state machine. M3's pending Python
budget/scope extraction does not block these existing leaf contracts.

The existing [modular architecture](aivm-secrets-modular-proof-architecture.md)
and [assurance plan](aivm-secrets-formal-assurance.md) already define this
direction. Aeneas translates Charon's representation of Rust into Lean; proofs
should concern those generated definitions. A handwritten Lean specification
can state the target, with a theorem connecting the extracted implementation
to that specification. A separate Lean mirror alone would leave that connection
unproved. See [Aeneas usage and supported subset][aeneas-readme].

## Existing substrate

There are no Cargo manifests, Rust sources, Lake projects, Lean sources, proof
manifests, or Rust/proof CI jobs in this repository. There are six Python
primitive modules, a closed JSONL runner, structural purity gates, frozen
positive/negative vectors, and a documented theorem inventory.

| First implementation unit | Existing API | Frozen rows | First obligations |
| --- | --- | ---: | --- |
| Epochs | `epochs.advance`, `epochs.require_current` | 37 | Exact successor and errors, no overflow/wrap, stale or negative epochs rejected |
| Time validity | `validity.require_active` | 27 | Acceptance exactly on `not_before <= now < expires_at`, including bounds and malformed-input denial |
| Binding equality | `binding.require_match` | 20 | Exact equality, no normalization, empty/Unicode strings handled as specified |
| Canonical digest | `codec.digest` | 20 | Exact accepted value domain and canonical bytes; hash security remains an assumption |
| Broker frame shape | `wire.parse_frame` | 33 | Closed verb/key grammar, exact types, UTF-8 byte limits |
| Runner envelope | `primitives_runner.evaluate` | 20 | Exact request shape/version/dispatch/error behavior |

The first three modules supply **84 rows**; the complete corpus supplies
**157 rows**. These rows include malformed arguments; their test coverage
therefore includes adapter behavior beyond each typed Rust function.

The existing `AIVM_SECRETS_RUST_PRIMITIVES_RUNNER` gate calls the complete
runner contract, including raw framing, bounded-line draining and flushing.
A partial implementation must use an explicitly scoped leaf test gate. Leave
the complete gate pending until all six operations and framing pass; do not
weaken it, invoke Python from Rust, or advertise leaf coverage as full parity.

## The first proof should be concrete

Port `epochs.advance` first, using signed 64-bit inputs and a closed result
enum. For every representable input pair `(current, maximum)`, establish:

- Invalid range (`maximum < 0`, `current < 0`, or `current > maximum`)
  returns `invalid_capability`.
- At a valid maximum, return `revoked`.
- Below a valid maximum, return exactly `current + 1`, still within maximum.
- All cases terminate without panic, overflow, or silent reset.

The omitted maximum must retain the current default `2^31 - 1`; the largest
allowed explicit maximum remains `2^63 - 1`. Add a successful last-step witness
and a maximum-exhaustion witness so a function that always refuses cannot
satisfy the acceptance gate. Mutating the maximum check or increment must
break the corresponding proof/test gate.

Next prove `require_current`'s exact acceptance condition, then validity's
inclusive start/exclusive expiry. Binding needs equality over the exact UTF-8
representation with an explicit parser invariant; evaluate a simple byte
sequence loop if Rust string-library operations do not extract cleanly.
The leaf currently accepts equal empty strings, and compares case and Unicode
without normalization. Restricting it to nonempty SHA-256 hex would change its
contract. The equality theorem assumes that higher layers supplied authenticated
peer/token fields; it does not authenticate a TLS peer or prove constant-time
secret comparison.

## Keep typed decisions and wire refinement separate

Use two Rust workspace members initially:

```text
rust/crates/aivm-secrets-primitives/   pure decisions, closed results
rust/crates/primitives-conformance/   JSONL input/output and denial mapping
proofs/generated/                    Charon/Aeneas output; regenerated
proofs/Primitives/                   specifications and implementation proofs
proofs/manifest.json                 pins, source/generated hashes, theorems,
                                    external models, declared assumptions/axioms
```

These are proposed paths, not files already created. Keep JSON, hashing, process
streams, clocks, credentials, filesystem and networking outside the extracted
leaf crate. The Rust runner must call the same Rust functions being extracted.

The wire adapter must preserve distinctions that Rust typing cannot express
after a lossy decode: `true` is not integer `1`; `1e0` is a float; `-0` is
integer zero; duplicate keys are rejected; oversized integers must reach the
appropriate denial path. Do not assume deserializing straight into a normal
JSON map and `i64` preserves those distinctions and error classifications.

Canonical bytes require the existing Unicode sorting, ASCII escapes, surrogate
pairs and integer rules. Normal JSON serialization is not automatically this
canonicalization. Line bounds include the newline; depth is bounded before
recursive decoding; raw invalid UTF-8, lone surrogates and oversized-line
recovery have tests. Freeze explicit language-neutral contract notes alongside
the vectors before implementing those adapters. Their conformance tests are
empirical evidence until a parser/encoder refinement theorem connects them to
the typed kernel.

## Toolchain reconnaissance

No toolchain installation or project setup was performed. On this machine,
Rust/Cargo/rustup, Charon/Aeneas, OCaml/opam/dune and Nix are not on PATH.
Elan is present; an existing **Lean 4.34.0-rc2** binary runs. Elan's default
resolves to 4.35.0 but reports that it is not installed. Docker is on PATH;
daemon availability and container-based extraction have not been tested.

The upstream snapshot inspected gives this **candidate**, not yet an exercised
project pin set:

| Component | Observed pin |
| --- | --- |
| Aeneas | `d95aeacab40f33e99e30c30955e36c072c5baf3a` |
| Matching Charon from Aeneas `charon-pin` | `08d7c9d50144bd84848212c24701253585e90d1f` |
| That Charon's Rust channel | `nightly-2026-09-17` |
| Aeneas Lean backend | `leanprover/lean4:v4.35.0` |
| Aeneas mathlib dependency | `v4.35.0` |

These pins come from [Aeneas's compatibility file][charon-pin],
[Charon's compiler specification][charon-toolchain], and
[Aeneas's Lean toolchain][lean-toolchain] and [Lake file][aeneas-lake].
Use the matched Charon revision, not its independently moving HEAD. Upstream's
current command form is `charon cargo --preset=aeneas`, followed by Aeneas's
Lean extraction; the project's scripts must be tested against the selected
revision before being called reproducible. Source builds also need Aeneas's
OCaml dependencies; Nix is an upstream-supported alternative. Toolchain setup
and one real extraction are the immediate feasibility gate.

## h5i evaluation

The existing design requests an h5i-app evaluation; source inspection found
useful examples worth carrying into the first spike:

- `h5i-app-std` contains byte/set/map/time Rust functions, generated Lean, named
  specifications, and a `Check.lean` that prints named theorems' axioms.
- Its proof package pins an older Aeneas revision
  `b86120db3183b0107eb5f2637b11c424cd06ef1c` and Lean **4.31.0**. Its lemmas
  cannot be assumed compatible with the current Aeneas/Lean family above.
- Its `expired(exp, now, 0)` tests `exp < now`; our capability expires at
  `now == exp`. Its `within` predicate can accept `now < start`. Neither is
  a direct implementation of our half-open validity predicate.
- h5i-app's default features are empty, but its **HTTP feature enables its
  PostgreSQL engine**. Runtime framework adoption is a separate architectural
  choice; it is unnecessary for these pure local-broker leaves.

These findings are from [h5i-app-std's time code][h5i-time],
[proof package][h5i-lake], [Lean pin][h5i-lean], [axiom checks][h5i-check],
and [h5i-app's feature graph][h5i-features], at h5i commit
`5d03fc82d9cbbf6a748b31a9797323c2bd7193d5`. Upstream proof artifacts were
read, not built or independently revalidated here. Recommended starting point:
direct pinned Aeneas, using h5i's workflow as a reference; evaluate library
reuse only against our exact contracts and one coherent toolchain family.

## Implementation sequence and exit gates

1. **Extraction spike:** provision an isolated pinned toolchain; compile the
   real Rust epoch function; generate LLBC/Lean; prove its full result contract
   and absence of panic for all typed inputs; record actual pins and assumptions.
2. **First reusable leaves:** add epoch equality, validity and binding;
   replay the 84 rows through the Rust adapter; prove the typed functions and
   explicitly inventory remaining adapter assumptions. Add targeted mutations.
3. **Complete primitive runner:** implement exact canonical digest/frame/envelope
   contracts, raw-byte negatives, line recovery and flush behavior. Turn on the
   existing complete parity gate only when it genuinely passes.
4. **Budget and scope:** specify standalone contracts from `kernel.machine.admit`
   and `kernel.scope`; prove bounded reservation and semantic attenuation.
   Shared ancestor budgets, reservation uniqueness and concurrency/commit
   linearization need their own composition arguments.
5. **Identity and effect composition:** port the pure Garrett protocol and
   authorization transitions, then connect accepted requests to the exact
   credentialed effects. Extend to revocation, approvals and audit ordering.

The first deliverable can establish genuine theorems about shipped Rust leaf
source. It cannot establish broker-wide mediation, cryptographic security,
TLS/X.509 correctness, durable rollback prevention, OS permissions, concurrency,
or Python equivalence on all inputs. Keep SHA-256/AEAD/signatures/TLS as explicit
trusted boundaries initially; proving a policy primitive does not verify those
implementations.

Proof CI must regenerate from pinned Rust, compare generated artifacts, check
every named theorem and its transitive axiom dependencies, and reject `sorryAx`,
missing theorems, stale sources and undeclared assumptions. A textual search for
`sorry` alone is insufficient. Keep Python reference tests, Rust conformance,
and Lean verification as separately reported gates with explicit coverage.

## Checks performed

Focused Python gates (`test_secrets_primitives_parity`, `test_secrets_purity`,
`test_secrets_garrett_modularity`): **158 passed, 2 skipped in 4.66 seconds**.
Both skips report absent Rust runners. Counts and contracts above were inspected
from the existing source and corpus. No Rust/proof build has been tested, so
first-slice feasibility is an engineering assessment, not a completed result.

[aeneas-readme]: https://github.com/AeneasVerif/aeneas/blob/d95aeacab40f33e99e30c30955e36c072c5baf3a/README.md
[charon-pin]: https://github.com/AeneasVerif/aeneas/blob/d95aeacab40f33e99e30c30955e36c072c5baf3a/charon-pin
[charon-toolchain]: https://github.com/AeneasVerif/charon/blob/08d7c9d50144bd84848212c24701253585e90d1f/charon/rust-toolchain
[lean-toolchain]: https://github.com/AeneasVerif/aeneas/blob/d95aeacab40f33e99e30c30955e36c072c5baf3a/backends/lean/lean-toolchain
[aeneas-lake]: https://github.com/AeneasVerif/aeneas/blob/d95aeacab40f33e99e30c30955e36c072c5baf3a/backends/lean/lakefile.lean
[h5i-time]: https://github.com/h5i-dev/h5i/blob/5d03fc82d9cbbf6a748b31a9797323c2bd7193d5/crates/h5i-app-std/src/time.rs
[h5i-lake]: https://github.com/h5i-dev/h5i/blob/5d03fc82d9cbbf6a748b31a9797323c2bd7193d5/crates/h5i-app-std/proofs/lakefile.lean
[h5i-lean]: https://github.com/h5i-dev/h5i/blob/5d03fc82d9cbbf6a748b31a9797323c2bd7193d5/crates/h5i-app-std/proofs/lean-toolchain
[h5i-check]: https://github.com/h5i-dev/h5i/blob/5d03fc82d9cbbf6a748b31a9797323c2bd7193d5/crates/h5i-app-std/proofs/Check.lean
[h5i-features]: https://github.com/h5i-dev/h5i/blob/5d03fc82d9cbbf6a748b31a9797323c2bd7193d5/crates/h5i-app/Cargo.toml
