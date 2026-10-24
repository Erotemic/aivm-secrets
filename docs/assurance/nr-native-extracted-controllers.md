# Production native adapter refinement: extracted controllers

**Scope:** native read-only Garrett `ManifestProvider`, durable audit recorder,
selected-value release, and provider response handoff. This is a **new
implementation/proof attempt** on top of the maintainer-accepted, compiling
`GarrettNR23ProductionBoundary` and `GarrettNR4Assurance` developments.

## Goal and actual change

Rather than ask a caller to assert that native callbacks happen in the correct
sequence, production Rust now **calls three controllers in the extractable core**.
Aeneas can translate those very controller functions, so the Lean facts about
callback order can be derived from executable Rust rather than copied into a
handwritten source-equivalence assumption.

| Controller | Concrete production entry | Previously native-only scheduling now owned by extractable Rust | External callback / environment still owed |
| --- | --- | --- | --- |
| `audit_record::append_durable_record` | `Audit::write_record`, holding `AuditState` mutex, passing `AuditFile` | Refuse if poisoned; poison *before* I/O; append exact supplied canonical row; append one LF; sync; acknowledge/clear poison only after all three succeed | `json::canonical`; actual `File::write_all` short/partial/error behavior, `File::sync_all` durability, inode/lock/host filesystem, panic and power failure |
| `selected_release::select` | `PendingCompletion::select` via `ManifestSelection` | Current control → pagination → projection → public JSON assembly → full-reply reflection validation, with fail-stop denial at every error-producing stage | Native clock/control and pagination; serde `Value`; correctness and strictness of `Disclosure::project` and `ensure_safe`; `Completed::into_value` and final JSON rendering |
| `response_gate::receive` | `ManifestProvider::receive`, then token-consuming `ManifestResponse::parse` | `Channel::into_parts` readiness gate mints a sealed, single-use `Released` token; the native parser takes only that token | `ManifestResponse::parse`, rustls/TCP/HTTP semantics, response size/deadline, and all alternate reachable sinks |

`AuditFile<'_>` is intentionally a **local newtype**. Implementing this core
trait directly on `std::fs::File` is forbidden by Rust orphan rules. The wrapper
has only one `append` and one `sync_record` implementation, both mapped to the
underlying file API and `Error::InternalError` on error. Since 2026-10-24
`sync_record` also appends the record's line to the `.chain` sidecar after the
record is synced; a chain failure is the append's failure, so the record's
action still stops. The chain is native glue, not part of the extracted
controller.

## Formal theorems attempted (all three functions are to be Aeneas-extracted)

- `GarrettProductionAuditRecord.lean`: poisoned-state refusal; returned error
  prefixes; exact LF delimiter; **successful returned** record yields actual
  ordered payload/delimiter/sync witnesses and cannot claim acknowledgement
  without them.
- `GarrettProductionSelectedRelease.lean`: exact denial prefixes for current,
  pagination, projection and reflection; exact approved success; **successful
  returned** selection yields witnesses for all five callbacks and returns the
  same reply that passed `check_safe`.
- `GarrettProductionResponseGate.lean`: a not-ready channel cannot mint a parser
  token; a returned token requires a successful `Channel::into_parts` and
  therefore supplies the exact captured channel parts. Successful prior
  `Channel.submit` further supplies the high-level `write_all` and `flush`
  callback witnesses. The actual native parse remains outside Aeneas.
- `GarrettProductionAdapterRefinement.lean`: single entrypoint composing these
  three returned-run witness theorems (the third is a token-release theorem,
  not a symbolic parser callback). The component source executions are
  passed individually; connecting them to a *particular* native request's
  ownership/state remains an explicit adapter correspondence task.

The security-relevant change is **eliminating the independent scheduler
assumptions for these three controllers**, not claiming that the callback
implementations are all formally verified.

## Aeneas parser-trait compatibility repair (October 22, 2026)

The first native Cargo build passed **100** tests, but the pinned Aeneas
translator aborted in `InterpPaths.ml` while symbolically interpreting the
`response_gate::Parser` trait method declaration. The offending signature
combined a parser-associated `Output` and a writer-associated `W::Error` in
one trait method that consumed owned writer/request/metadata. This was an
Aeneas symbolic-interpreter failure, **not** a Rust type-checking or runtime
test failure. It stopped extraction before Lean compilation.

The new source has **no parser callback trait**. `response_gate::receive` is
an extractable function that calls `Channel::into_parts()?` and is the only
safe constructor of the private-field `Released<B, W, M>` token. A `Released`
token is neither `Clone` nor `Copy`. The concrete native parser now takes a
`Released` token **by value** and obtains its exact parts from its consuming
`into_parts` method. Only a source-ready channel can make a token and
attempted replay never reopens readiness. This enforces the response gate at
the Rust type boundary while eliminating the untranslatable trait method.

The corresponding Lean theorem has **changed shape intentionally**: it proves
that every *successful token-producing* extracted gate invocation implies
successful channel release and derives exact submitted writer/flush witnesses.
It does **not** pretend the native `ManifestResponse::parse` implementation is
an Aeneas-extracted callback. Safe-Rust parser call-site correspondence is
reviewed by W3/W6 and NR-2/NR-3 source guards; transitive correctness, native
parser behavior, and TLS/socket effects remain open obligations. Those guard
scripts are evidence of source shape, not a semantic proof.

The repair must pass `garrett.py extract` on the maintainer's pinned Aeneas
before the new Lean proofs can be accepted. Do not treat the earlier failed
extraction or an old generated file as a passing gate.

## Extraction, testing, and iterative compilation

This overlay does **not** hand-author `proofs/generated/AivmSecretsGarrettCore.lean`.
The generated file *must* come from the pinned Aeneas toolchain applied to
these production Rust core modules. In the maintainer's checkout:

```bash
cd ~/code/aivm-secrets
python dev/verification/nr23_native_edges.py check
python dev/verification/nr4_observation_edges.py check
python dev/verification/w3_effect_boundary.py check
python dev/verification/w6_adapter.py check
python -m pytest -q \
  tests/test_secrets_w3_effect_boundary.py \
  tests/test_rust_w6_adapter.py \
  tests/test_nr23_native_edges.py \
  tests/test_nr4_observation_edges.py
cd rust
cargo test -p aivm-secrets-garrett-core -p aivm-secrets-garrett --lib
cd ..
python dev/verification/garrett.py extract
cd proofs
lake exe cache get
lake build GarrettProductionAdapterRefinement
cd ..
```

The `extract` action replaces the generated Lean module **from the production
Rust sources**, not from a handwritten approximation. In the initial repair
iteration, report all cargo, extraction and focused Lean errors together so
that one consolidated overlay can address them. Pinning the refreshed
`garrett-manifest.json` follows successful generation/compilation and the
separate release assurance process; do not silence a stale-manifest check by
claiming the old generated file already reflects this refactor.

The local assistant environment has no Rust/Lean/Aeneas toolchains and cannot
regenerate this output. It can run the Python source/mutation suite; its
passing result is not evidence of successful Rust or Lean compilation.

## What is *not* discharged

1. **Actual I/O sink closure** (`ExactNativeSinkCoverage`): one native high-level
   `write_all` can perform multiple system calls, accept a prefix, retry
   `Interrupted`, or report error after a partial effect. Direct, conditional
   or dependency-internal network sinks require independent exhaustive review.
2. **Audit durable persistence**: a successful `sync_all` callback is still a
   system/library contract, not proved disk durability or rollback resistance.
3. **Native callback correctness**: actual policy, clock, pagination, serde,
   reflection and response parser behavior are not Aeneas-extracted through
   these trait calls. Their effect/return fidelity is still an obligation.
4. **Full cross-request NR-4 refinement**: the `PairedStepCertificate`
   instantiation and guest-visible metadata/partial-write/EOF equality remain
   unclosed, as do host TLS/kernel/VM side channels.
5. **Nonreturning paths**: `panic`, process termination, cancellation, `Drop`
   and failure/restart across the audit line require further source and
   environment arguments. Poison-before-I/O is useful but not complete crash
   durability or nonce-reuse prevention.

Do not upgrade the read-only broker to unattended use on the basis of these
scoped controller proofs alone. The acceptance criterion is eventually removing
*all application-owned premises* from the final per-request and adaptive
security statement, then bounding external TLS/kernel/VM assumptions in NR-5.
