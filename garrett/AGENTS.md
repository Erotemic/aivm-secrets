# Contributor instructions

`garrett-stateless` implements Matthew Garrett's stateless agentic-identity
architecture as the wire profile `garrett-stateless-v1`
(`docs/garrett-stateless-v1.md`, normative). It is experimental and
unaudited. Start with `README.md`, then `docs/status.md` for the current work
queue and `docs/verification.md` for what is proved and what is trusted.

**This tree is self-contained.** It builds, tests, extracts and proves with
only its own manifests and tooling. Never import, depend on or copy from
another project at build or test time, and keep paths relative to this
directory. Synthetic credentials only: never use a real provider account or
token in tests, examples or defaults. Do not publish the crates or the Python
package without the maintainer's authorization.

**The protocol is the core.** Every security decision, codec and state
transition lives in `crates/garrett-stateless-core` (no dependencies; Aeneas
extracts it) and, module for module, in the Python reference
`src/garrett_stateless/core` (standard library only; `tests/test_core_purity.py`).
The applications around them (`crates/garrett-stateless`,
`src/garrett_stateless`) supply I/O, clocks, randomness and cryptography and
must not decide anything themselves; `verification/shell_guard.py` checks the
Rust shell. Both implementations must stay byte-compatible with
`tests/vectors/` (and with each other: the interop and replica tests).

**Writing core Rust.** Keep the extraction-friendly style: explicit loops,
indices and `match`es, `len() == 0` rather than `is_empty()`, no iterator
chains, no `?`. Shorter code that Aeneas cannot extract, or that changes the
generated model's shape, is not an improvement. After a core change:

```bash
python verification/extract.py write      # regenerate proofs/generated, review the diff
(cd proofs && lake build)                 # every theorem
python verification/mutate.py --filter …  # the mutants for the code you touched
```

`verification/toolchain.py bootstrap` installs the pinned toolchain first.

**Lean.** Compilation is the routine check; keep builds quiet on success. Do
not add `#print axioms`, bulk `#check`, or per-theorem axiom reports to proof
modules or default targets. An axiom audit is a separate, explicitly
requested end-of-campaign step that reports differences from a reviewed
baseline only. Extend the existing theorems (`protocol_safety`,
`composed_egress`) rather than proving parallel copies; a new operation
policy is a new instantiation of `composed_egress`.

**Claims.** Name the exact scope of every theorem. Never describe a source
guard, a passing test or a compiling model as a proof of whole-service
secrecy, TLS, cryptography or native I/O. Statelessness and operation
authorization are separate properties. The trusted boundary is
`docs/assumptions.json`; update it when a change moves something across it.

**Changes to security boundaries** need focused adversarial tests (and, for
the core, a mutant the proofs reject). Do not change the protocol version,
the wire format or the vectors as an incidental part of another change.

Every agent-authored commit carries a `Co-authored-by:` trailer naming the
actual model.
