# Garrett W3/W6: completed native read release and observation correspondence

Status: **incremental overlay, native compile/process acceptance pending on a
Rust-equipped machine**. Baseline: source commit `b91748b` with the previously
accepted native-read confinement overlay. This does not claim a W4/W5
implementation-to-theorem refinement or complete I/O mediation.

## Security question

After a guest-triggered native read reaches a provider, can the broker return
unselected provider data, unreviewed metadata, or provider-supplied error text?
Can an authorized no-preflight read or a useful preflight-only fact return be
modeled by the same source-level audit/release boundary as a two-phase read?

This increment answers those questions for **selected offline executions**, not
for all possible Rust executions. The approved provider facts, host policy and
host disclosure are separate oracle inputs; the guest reply is an observation,
never the source of the expected value.

## Source boundary

`manifest_session.rs` now uses two private transition objects:

- `AuditedDispatch` exists after the host dispatch audit acknowledges, before
  fresh admission and credential-bearing provider emission (previous slice).
- `CompletedRelease` exists only after a successful typed disclosure projection,
  literal reflection checks on the full public reply, and a host completion
  audit. This slice moves the final completion audit into its private
  constructor. The public `Value` leaves the request path through
  `CompletedRelease::into_public`; the existing sent-write `OutcomeUnknown`
  classification remains unchanged.

The source guards in W3 and W6 reject deletion of either transition, or
conversion to a raw result. Both guards remain reviewed-source heuristics:
this is **not** an unforgeable compiler-level capability, proof of audit
crash durability, or proof that no other binary/library I/O paths exist.

## Concrete read observations

The independent test oracle in `tests/secrets_w6_release.py` interprets the
host disclosure shape and pagination rule using native-independent Python test
code. It rejects missing or incorrectly typed selected fields, unexpected
array lengths, and literal selected credential reflection. It does not call the
Python broker's projection, the Rust interpreter, or a supplied guest result.
The W6 trace oracle additionally checks:

- one audited dispatch per observed credentialed provider request;
- no completion audit before dispatch, and completion only on success;
- a host-normalized canonical request digest on selected scenarios;
- the exact fixed guest error vocabulary, never provider diagnostics;
- the actual canonical JSONL frame, including selected result and the complete
  public pagination metadata;
- provider-side snapshots of the audit file when the request arrives.

The new native scenarios exercise (1) a no-preflight paginated read with a
full page, a short page, ignored-field mutations, wrong selected type and
malformed guest arguments; and (2) a preflight-only `returns=check` operation
with **no** final request. The tests use the real native bridge/client, actual
loopback TLS and an invented local HTTPS service. There are no real accounts,
provider credentials, or external network dependencies.

These scenarios provide finite W6 **NO-PREFLIGHT** and **METADATA** evidence;
those labels remain open in the W4 proof-scope manifest. The interpreter
supports only the declared nested object/array/typed-field subset in these
fixtures. It does not establish all path grammars, UTF-8 normalization, wire
segmentation, concurrent histories, or arbitrary large outputs.

## Fast validation (preferred for this overlay)

From the repo root:

```bash
python dev/verification/quick_w6_read.py
python dev/verification/quick_w6_read.py --native
```

The first command checks W0/W3/W6 source guards and portable/mutation oracles.
The second reuses existing `rust/target/debug` native binaries and adds the
selected real mTLS + HTTPS scenarios; missing binaries or pytest skips are a
failure. To rebuild stale native executables once, add `--build`. Neither form
runs Charon, the entire test suite, the Rust workspace tests or Lean proof
compilation. The source guard must not be mistaken for a native compile check:
run `--native --build` once after modifying Rust sources.

For a separate focused Rust unit check, if desired:

```bash
cargo test --locked --manifest-path rust/Cargo.toml -p aivm-secrets-garrett --lib \
  unapproved_read_or_preflight_cannot_become_write_dispatch
```

The maintainer's previously passing full `--proofs --full-tests --call-linkage`
run is baseline evidence for the earlier overlay only. Do not copy that status
to this Rust edit before a new native build and selected runtime cases pass.

## Still open

- Universal source-to-W4/W5 trace refinement, including actual TLS/JSON/filesystem
  semantics and identity binding in all schedules.
- Compiler-wide mediation, external dependencies, callbacks, destructor
  effects, panic paths, error metadata and timing/closure observations.
- Concrete guest-output semantics for approval, writes, OAuth, coordinator,
  legacy Python forwarding and all other profiles.
- Literal-credential reflection is a public denial oracle; semantic/encoded
  disclosure remains a host-policy/provider trust problem.
- Real AIVM compartment isolation, physical TPM assertions, and live provider
  compatibility (deliberately not exercised).
