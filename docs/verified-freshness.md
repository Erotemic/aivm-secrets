# Verified Rust capability freshness

The first Rust verification unit checks an authenticated claim's **current
epoch and half-open time validity**, and implements bounded epoch advancement.
The experimental broker as a whole remains unaudited and is not formally
verified. Python's implementation is unchanged.

## Contract and implementation

The proved functions are in
[`rust/crates/aivm-secrets-primitives/src/lib.rs`](../rust/crates/aivm-secrets-primitives/src/lib.rs).
Inputs are signed 64-bit integers; the functions perform no I/O or clock reads.

| Function | Exact result |
| --- | --- |
| `advance(current, maximum)` | Invalid ranges yield `InvalidCapability`; a nonnegative epoch at maximum yields `Revoked`; otherwise return exactly `current + 1`, bounded by maximum |
| `require_current(actual, expected)` | Accept exactly when `0 <= actual` and `actual == expected` |
| `require_active(now, not_before, expires_at)` | Accept exactly when bounds are nonnegative and `not_before <= now < expires_at` |
| `require_fresh(actual, expected, now, not_before, expires_at)` | Accept exactly when both epoch and time checks accept |

The separate scoped JSONL adapter preserves the Python default epoch maximum
`2^31 - 1`. It rejects Booleans/floats as integer arguments and refuses values
outside `i64` without coercion. Before dispatch it checks JSON syntax, duplicate
keys, Unicode, finite floats, the 65,536-byte line limit, 64-container depth
limit, and default Python 3.11+ 4,300-digit integer conversion limit. Parity
assumes that default interpreter policy; changing it requires a reviewed
adapter contract and parity update. Lines are drained in bounded chunks after
an oversize refusal, with one flushed reply per input line.

The runner supports `epochs.advance`, `epochs.require_current`,
`validity.require_active`, and `freshness.require_fresh`. It is a development
conformance executable. The separate complete-table
[`primitives-conformance` runner](primitive-conformance.md) now exercises the
existing `AIVM_SECRETS_RUST_PRIMITIVES_RUNNER` gate. Its binding/digest/frame
adapters are runtime-tested, not additions to this proof scope.

## What is proved

Charon extracts the real crate; Aeneas generates
[`proofs/generated/AivmSecretsPrimitives.lean`](../proofs/generated/AivmSecretsPrimitives.lean).
[`proofs/Freshness.lean`](../proofs/Freshness.lean) proves properties of those
functions, relating them to independent mathematical integer predicates.
The ten named obligations are listed in
[`proofs/manifest.json`](../proofs/manifest.json):

- Total epoch correctness for every typed input: precise invalid/exhausted
  classifications, exact successor, boundedness, absence of panic/overflow.
- Exact epoch, time and composed freshness results, including denial paths.
- Acceptance if and only if the mathematical freshness predicates hold.
- Rejection of stale epochs and expired claims.
- Advancing the epoch invalidates the old epoch value.
- Successful epoch and start-boundary witnesses to guard against vacuity.

The fresh axiom audit checks every theorem's transitive dependencies. Only
`propext`, `Classical.choice`, and `Quot.sound` are allowed. There are no
admitted obligations, `sorryAx`, or project-specific security axioms; this is
not a zero-axiom claim.

The result trusts Charon/Aeneas translation, standard arithmetic/Result models,
the Lean kernel, and compilation/linking of the checked Rust source. Input
authentication, clocks, durable rollback prevention, concurrency/linearization,
TLS/crypto, credential custody, egress and side channels remain outside these
proofs. JSON adapter behavior and Python equivalence are tested on enumerated
inputs, not formally proved for all inputs.

## Reproduce

Use Linux x86_64, Python 3.12+, curl, tar, rustup, elan and the project's
`.[tests]` environment. No root operations or default-toolchain changes are
needed. First setup downloads several GiB of dependencies:

```bash
umask 077
.venv/bin/python dev/verification/freshness.py bootstrap
.venv/bin/python dev/verification/freshness.py check
.venv/bin/python dev/verification/freshness.py mutate
```

The helper logs concrete commands. Bootstrap verifies the pinned Aeneas archive
SHA-256, installs matching Rust/Lean versions, and fetches locked mathlib data.
Build outputs stay under ignored `.tools/`, `rust/target/` and `proofs/.lake/`.

`check` verifies source, proof, model and tool hashes; regenerates Lean into a
temporary directory and compares it with the committed artifact; checks all
proofs and named axiom dependencies; builds the optimized Rust runner; and
compares it with Python. Stale or incomplete manifests, failed/missing proofs,
undeclared axioms, missing selected executables and parity differences fail.

`mutate` starts from a passing proof baseline and changes actual Rust in
temporary workspaces. It re-extracts and compiles each changed Lean module,
then requires the unchanged proofs to reject a missing successor, exhaustion
guard or epoch comparison, inclusive expiry, and a composed gate bypassing
time. A stale-file comparison alone does not count as rejecting a mutant.

The Python tests replay **64 existing epoch/time vectors and 20 envelope
vectors**, plus more than 4,600 generated boundary/composition cases and raw
typing, Unicode, length/depth/integer, recovery and flush checks. The composed
oracle calls the existing Python epoch and time functions directly. To run
only parity after building the runner:

```bash
AIVM_SECRETS_FRESHNESS_RUNNER="$PWD/rust/target/release/freshness-conformance" \
  .venv/bin/python -m pytest -q tests/test_rust_freshness.py
```

Python-only development skips this scoped gate unless explicitly selected.
The dedicated CI job requires the Rust runner, checked Lean proofs and mutation
failures. Ordinary Python packaging/imports gain no Rust, Lean or AIVM runtime
dependency.

## Validation of this implementation

Local validation on Python 3.12.3 completed with **1,868 passed, 10 skipped**
(266.19 seconds), including the original Python mutation gate. The skips are
for other unimplemented Rust runners. The scoped gate passed all seven tests:
84 frozen rows, 4,634 generated cases, and raw JSON/streaming checks. Lean checked
all ten named obligations and the declared axiom inventory; all five
re-extracted Rust security mutations were rejected. Rust formatting/Clippy and
wheel/sdist metadata checks passed. The sdist includes every declared proof
input; the wheel contains no Rust/proof code. Hosted CI is configured but has
not been run as part of this local work.

## Reviewed proof updates

After an intentional Rust change, regenerate, review the diff, update the
proofs/tests and record new evidence:

```bash
.venv/bin/python dev/verification/freshness.py extract
.venv/bin/python dev/verification/freshness.py record
.venv/bin/python dev/verification/freshness.py check
.venv/bin/python dev/verification/freshness.py mutate
```

`record` requires fresh extraction, proofs/axiom audit and parity before writing
new hashes. Commit reviewed source, generated Lean, proofs, tests, lockfiles and
manifest together. Frozen reference vectors remain authoritative. Broader
identity authentication or credentialed-effect claims need further proofs.
