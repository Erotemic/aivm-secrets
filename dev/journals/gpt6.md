## 2026-10-17 11:01:19 -0400

Reviewed the 2026-10-17 source snapshot (`28e466d`) against the proposed
conditional broker credential-confinement target. The design already records
important assumptions and proof dependencies, but overlapping P/M/G milestones
and stale Rust/repository status statements can send agents toward unrelated
new primitives or TPM work before there is a useful, verified service boundary.

Added a canonical W0-W8 active queue and linked it from `AGENTS.md` and the
main planning documents. The plan prioritizes a standalone real broker/provider
scenario, complete enumeration of guest-reachable sinks, a closed Rust effect
boundary, extracted trace confinement, relational information-flow proofs and
concrete adapter refinement. AIVM is an optional downstream deployment
validation, not a requirement for local formal reasoning. Existing Garrett,
identity, issuance, custody and disclosure work remains preserved.

Main uncertainty: complete reachable-I/O and declassification contracts still
need a source audit; the current Lean results cannot be extended to
whole-service traces merely by composing theorem names. The new environmental
compartment ledger entry is explicitly unestablished by local tests. This
change alters planning and assumption documentation only, not runtime behavior
or actual proof validity. No Rust/Lean toolchain verification was attempted.

Validation for this planning-only edit: 137 structural and installed CLI
checks passed after installing the standalone package in the test environment;
all planning Markdown relative links resolve, the assumption ledger passes its
structure checks, and `git diff --check` is clean. Wheel/sdist build tests were
not reproduced because this environment has no `build` module; the initial
uninstalled-source run had three environment/setup failures, which are not
recorded as product regressions.
