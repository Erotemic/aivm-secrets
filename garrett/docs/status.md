# Status and work queue

The current state of `garrett-stateless` and what comes next, in order. The
dated notes from before the extraction are in [`history/`](history).

## State (2026-10-29)

Both implementations are complete for `garrett-stateless-v1`: the OAuth and
provisioned acquisition adapters, the broker, the stateless proxy with the
unrestricted and read-only operation policies, strict mode, key rotation and
retirement, and an optional TPM agent key. The Rust core is extracted to Lean
and proved; the composed internal theorem is `protocol_safety`, and
`composed_egress` covers both operation policies
([verification.md](verification.md)).

**Extraction from `aivm-secrets` (2026-10-29).** This tree was developed
inside `aivm-secrets` and is now self-contained:

- the core crate owns the HTTP/1.1, base64 and OAuth-login code it uses,
  forked from that project and pruned to what the protocol reaches (no
  function in it is unreachable from the protocol's own code);
- the proofs are their own Lake package; the supporting HTTP and OAuth proofs
  came with the code and were pruned to the lemmas the protocol proofs use;
- the Python reference is the `garrett_stateless.core` package, module for
  module as the Rust crate, with its own copy of the HTTP subset; the crypto
  calls moved behind the same `KeyMaterial`/`StateKey` interfaces as in Rust;
- the TPM signer was ported into `crates/garrett-stateless` (feature `tpm`);
- verification tooling, vectors, examples, the demo and the documentation
  moved here.

## Validation

| Check | Result |
| --- | --- |
| `cargo test` (core and application, with `--features tpm`) | 49 pass |
| `python -m pytest` (including interop, replicas, operations, vectors, purity) | 109 pass (with the swtpm test required) |
| swtpm test (`GARRETT_REQUIRE_TPM_TESTS=1`) | pass |
| `verification/extract.py check` | pass; the model has no `axiom` |
| `lake build` (independent package) | pass |
| `verification/mutate.py` | all 42 mutants rejected, each by its mapped proof module (in the separate-directory copy, 3882 s with `--jobs 8`) |
| `verification/shell_guard.py check` | pass (12 checks) |
| Separate-directory check (`verification/standalone.py`) | pass at `5ebbc6d`: a copy of this directory alone, with a fresh virtual environment, Cargo target, toolchain bootstrap and Lake build, ran every row above; no source names the origin project outside the allowed history notes |

## Next, in order

1. **Behaviour that still names the old project.** The fixed refusal response
   says `"proxy":"aivm-secrets"` and `realm="aivm-secrets"`, and the shared
   `Code` enum still has two codes only the old project used (`revoked`,
   `unsupported_request`). Renaming and removing them is a deliberate wire
   change: update both implementations, the refusal vectors, and the proofs
   about the refusal table together.
2. **Readability of the core** (the review that motivated the extraction):
   split `stateless_token.rs` into its codec, grammar, JSON, payload, key-set,
   open/seal and sealed-state parts (mapping the proof modules and mutants
   with it); define `open` as `authenticate` then `decrypt` (`open_of_halves`
   already proves they agree); have the application's grammar checks
   (`crates/garrett-stateless/src/encoding.rs`) call the core's; add a short
   `PROTOCOL.md` that walks through issuance, opening and egress with links
   to the theorems.
3. **API tightening.** Make the fixed-nonce sealers (`sealer_with_nonce`,
   `fixture_seal`) test-only; have the agent reject a broker response without
   `expires_at`/`renew_until` instead of substituting 0; consider typed
   identifiers at the public boundary.
4. **Independent review** of the specification, the trusted shells
   (`STATELESS-NATIVE-01`), the `Isolated` statement and `STATELESS-OPS-01`.
   An agent cannot self-certify it.
5. **Live provider compatibility (maintainer).** One real OAuth provider with
   PKCE and a read-only call, outside tests and CI.
6. **Hardware TPM (maintainer).** The swtpm test against a device TPM, with
   provenance verified by the CA.
7. **Provider-specific read-only catalogues** (narrows `STATELESS-OPS-01`).
8. **An opt-in axiom audit** for this package (the last one, before the
   extraction, found only Lean's standard axioms; see verification.md).
9. **Later, separate increments:** OAuth without the mailbox (a protocol
   change); further acquisition adapters; a multi-replica broker run; a
   whole-process syscall witness for the proxy; the release decision.
