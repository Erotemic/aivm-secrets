# Independent Rust primitive conformance runner

The Rust `primitives-conformance` development executable implements the six
entries in Python's closed `primitives_runner` table. It replaces the previously
pending independent-runner test with an executable test backend. It calls no
Python process and has no fallback. It is a JSONL test adapter, not a broker or
a new guest endpoint.

```bash
cargo +nightly-2026-09-17 build --locked --release --manifest-path rust/Cargo.toml \
    -p freshness-conformance --bins
AIVM_SECRETS_RUST_PRIMITIVES_RUNNER="$PWD/rust/target/release/primitives-conformance" \
    python -m pytest -q tests/test_secrets_primitives_parity.py
```

The [usable-system gate](assurance-profiles.md) builds and selects this runner
and includes the entire primitive parity test file among required tests. Missing,
failed, empty or skipped required tests fail the gate. An ordinary pytest run
without the selected executable still reports skips instead of pretending to
have exercised Rust.

| Entry | Tested contract | Lean scope |
| --- | --- | --- |
| `validity.require_active` | Inclusive start, exclusive expiry, strict integer inputs | Calls the existing extracted freshness function |
| `epochs.advance` | Default bound, invalid ranges and exhausted denial | Calls the existing extracted freshness function |
| `epochs.require_current` | Exact current nonnegative epoch | Calls the existing extracted freshness function |
| `binding.require_match` | Exact string identity, including empty and Unicode strings; other types refused | Adapter tested, not newly extracted |
| `codec.digest` | SHA-256 over sorted-key ASCII JSON, only signed 64-bit integers; fractions/exponents refused | Encoder and cryptographic adapter tested, not proved |
| `wire.parse_frame` | Exact version/key grammar, one of four verbs, UTF-8 byte capability bound and exact control booleans | Parser tested, not proved |

The complete table deliberately excludes the additional
`freshness.require_fresh` composition accepted by the older scoped
`freshness-conformance` executable. Conversely, the scoped runner continues
to refuse binding/digest/frame entries. Both reuse the same bounded stream
reader and strict duplicate/Unicode/depth/number validation; their dispatch
tables remain separate. Neither executes an operation from a parsed frame.

The frozen six corpora contain 157 rows. The native gate compares actual Rust
process replies against both their expected results and the independent Python
process. It also exercises malformed and oversized-line draining, exact line
and UTF-8 byte limits, negative-zero/exponent distinctions, duplicate keys,
lone surrogates, flushing before EOF and JSON type fidelity. Additional
deterministic differential cases cover recursive Unicode digest documents,
code-point key ordering, forbidden nested digest numbers and arbitrary frame
payloads, including a 4,300-digit integer and finite floats.

Those differential cases exposed a concrete native decoding defect: Serde's
generic `Value` deserializer interprets internal Number/RawValue marker keys,
so a JSON object could become a number or another value. Both the test adapter
and the native broker decoder now construct object/array values explicitly.
Native unit tests and four real guest/provider regressions cover the defect;
see [the W6 parser record](verified-w6-adapter-correspondence.md). It is parser
hardening backed by tests, not a new parser-refinement theorem.

The narrower runner failed the binding corpus before this implementation;
it could not stand in for this gate. Passing this finite corpus does not prove
all-input Python/Rust equivalence. It does not add binding, digest, codec or
frame theorems to [the freshness proof](verified-freshness.md), and it does not
prove that the separate native broker uses these test adapters. CORE-01 remains
an implemented subset with explicit broker-level and refinement obligations.

`python dev/verification/freshness.py check` now builds both executables and
runs both conformance files after its existing extraction/proof checks. Its
source manifest pins the added Rust adapter sources, Python contracts and
corpora. Rust source review inventories also include these development modules;
their stream I/O is not a new broker guest/provider path.
