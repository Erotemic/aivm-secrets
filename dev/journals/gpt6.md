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
## 2026-10-17 11:32:40 -0400

W0 contract baseline for the active conditional credential-confinement plan.
Kept runtime code and existing Lean theorems unchanged. Inventoried native
manifest-https-v1 separately from fixed account-status-v1, legacy Python
forwarding, guest-owned CLI, and operator-only authority. Documented
protected/public values, guest/host/provider/OAuth sinks, serialized error/
length/close observations, excluded timing/side channels, finite adaptive
request strategies, concurrency/linearization and a deliberately restricted
declassification model. The spec does not classify arbitrary accepted result
strings as safe or treat a fixed error enum as blanket declassification.

Added versioned W0 JSON with traceable sources/assumption IDs and a structural
validator plus negative tests; added eight narrowly described Rust/deployment
assumptions to the ledger. Distinct host-selected origin/bytes construction
remains a project proof/refinement obligation, **not** an assumption that
credential confinement holds. Updated active plan, assurance plan and agent
instructions to point to the W0 specification.

Source audit correction: OAuthSource::active is a guest-time lease check, not
a refresh. Native OAuth refresh may occur at host-controlled startup via
session_snapshot; its token endpoint is a separate authorized sink.
Native pagination exposes per_page, possibly_more and optional page, so the
possibly_more bit is an explicit declassification decision. The initial model
includes errors, frame lengths and closure in guest observations but not
wall-clock timing or packet traffic analysis.

Uncertainties: the sinks list was assembled by source inspection rather than
an audited complete transitive call graph, and the schema/release decisions
still require maintainer security approval. W3/W6 must check all concrete
writers (including errors and panics); W4/W5 must prove linked trace and
relational properties. The validator only checks structure and references.
No proof of virtualization, complete service confinement, or Lean
implementation correspondence is claimed by W0.

Validation: `python dev/verification/w0_contract.py check` passed (5 profiles,
10 sinks, 11 release rules, 10 observation classes); 141 W0/structural tests
passed; `git diff --check` passed. A full `python -m pytest -q` run exceeded
180 seconds at about 16% (slow pre-existing integration coverage) and its
first failing test was `test_standalone_wheel_and_sdist`, because the current
environment has no Python `build` module. `python -m build` fails for the same
missing module. No Rust/Lean rebuild attempted because W0 changes neither
Rust implementation nor Lean proof source.

## 2026-10-17 11:54:00 -0400

W1 implementation on top of the `28e466d` source and W0/planning overlays.
Added `tests/secrets_github_scenario.py` as stable synthetic provider data and
policy intent for W2, plus `tests/test_secrets_w1_github_workflow.py` as an
independent multi-process workflow. The test starts the real Python broker,
uses separate installed CLI processes for requests, and records real locally
TLS-protected HTTPS traffic. The policy is the expanded GitHub manifest with
host-selected synthetic credential, pinned loopback address and test CA.

Positive steps cover exact checked PR metadata, `gh` JSON projection, raw
diff and commit-bound checks; assertions include the provider's observed
bearer credential, method, Accept/version headers and precise preflight/final
paths. Denied steps cover a different PR, an operation admitted in policy but
forbidden by the host write gate, unknown API operation, injected URL argument
and the absence of real `gh` fallback. The provider's deliberate literal
token reflection is rejected; a wrong head-repository fact prevents final
execution after an allowed preflight. Host revocation and grant expiry reject
additional requests; audit records are chain-verified and exclude literal
credential/capability, and runtime socket/capability files are removed.

This is local functional integration evidence for the Python broker only.
It does not prove credential isolation from a same-UID client, validate a
real GitHub token/API, prove general declassification or confer Rust parity.
Python's `pr.view` protocol returns the whole checked response, whereas W0's
intended native Rust declassification boundary is stricter; W2 must compare
intended semantics and explicitly document differences. Left production code,
wire versions, and existing W0 proof files unchanged.

Validation: three W1 tests passed twice (final run 26.65 seconds), 506 nearby
Python guest/policy/broker/W0/purity regression tests passed, W0 structural
checker passed. A broad CLI-heavy regression invocation exceeded its timeout
after 19 tests, so it is not counted as passing. No live GitHub, Rust, Lean or
VM test was attempted. Maintainer review of test coverage remains open.
