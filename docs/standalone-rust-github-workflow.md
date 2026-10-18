# W2: native Rust GitHub-like PR workflow

**Local runtime validation (2026-10-17):** the pinned Rust binaries compile,
Rust workspace unit tests pass, and the combined W1/W2/W5/W6 workflow selection
passes 20 tests with **zero skips**. This supersedes the original overlay's
uncompiled status. The repeatable gate is now
`python dev/verification/system.py --proofs`; it additionally exercises the
Python/Rust copied-software-identity scenario and rejects software enrollment
when a native TPM-required profile is selected. Hosted CI and live GitHub
validation remain separate gates. Neither successful runtime tests nor the
scoped Lean proofs establish whole-service confidentiality or VM isolation.

## What is exercised

`tests/test_rust_w2_github_workflow.py` reuses the exact synthetic repository,
PR number, head SHA, metadata facts, diff, checks, and TLS route fixtures from
`tests/secrets_github_scenario.py`. The test provider is a local, independently
recording HTTPS server, not the Python broker. Native Rust authority, bridge,
client, manifest policy interpreter, credential custody, HTTPS request builder,
response disclosure, and mTLS identity are run as subprocesses.

The host Rust policy is compiled from the W1 schema-1 GitHub preset expanded
to schema 2, with its Python-only `cli` table removed. Its PR-number,
author, base/head repository, checked head-SHA binding, egress pins, host
headers, methods and arguments are retained. A separately supplied **native
recursive disclosure** releases only PR number/title/head SHA, the approved
diff string, or selected check fields. It does **not** release W1 Python's
entire `pr.view` metadata object.

Positive assertions cover the native provider's observed bearer token,
preflight vs final path and Accept header, stable checked SHA, selected
replies and the exact five provider requests for the three read operations.
Negative assertions cover cross-PR reads, forbidden writes, unknown operations,
argument injection, unsupported `gh` actions and fields, metadata mismatch,
reflected token bytes, and renunciation. Auditing is checked for literal token
and capability absence. These tests do not establish semantic safety of
arbitrary selected text, command alias completeness, live GitHub compatibility
or OS/VM isolation.

## Narrow guest-side CLI

`garrett-client` supports these explicit *read-only* conveniences in addition
to its existing stdin-frame interface:

```bash
rust/target/debug/garrett-client --config guest-client.json --capability-file guest-capability gh pr view 13861 --repo TauCetiProject/TauCeti --json number,title,headRefOid
rust/target/debug/garrett-client --config guest-client.json --capability-file guest-capability gh pr diff 13861 --repo TauCetiProject/TauCeti
rust/target/debug/garrett-client --config guest-client.json --capability-file guest-capability gh pr checks 13861 --repo TauCetiProject/TauCeti --json name,status
```

These are protocol requests to the authenticated **native** bridge, not to the
GitHub CLI or a general network client. The config and capability paths above
are representative filenames in the guest working directory; the configured
files must satisfy the client's private-file requirements and contain a
host-issued, mTLS-peer-bound capability. The commands do not invoke `gh`,
inspect Git remotes, read `GH_REPO`, discover a default repository, accept a
URL, or fall back to Python. `--repo` is required and operation/field sets are
closed. The request's normalized repository and PR still face full host-side
policy validation. CLI JSON projections operate only on already selected
native broker reply fields. Unsupported commands fail before transport; denied
broker operations produce a fixed `denied` CLI error.

The capability is read from a guest-owned private file rather than exposed
in process arguments. It is an **outer surrogate**, not a provider credential.
Actual separation from the host custody paths remains an environmental premise.

## Required binary validation

From a checkout of `aivm-secrets`, with its Python test dependencies installed
and Rust's pinned nightly toolchain available:

```bash
cargo +nightly-2026-09-17 build --manifest-path rust/Cargo.toml --bins
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml --bin garrett-client

AIVM_SECRETS_RUST_AUTHORITY_ADMIN="$PWD/rust/target/debug/garrett-authority" \
AIVM_SECRETS_RUST_GARRETT_BRIDGE="$PWD/rust/target/debug/garrett-bridge" \
AIVM_SECRETS_RUST_GARRETT_CLIENT="$PWD/rust/target/debug/garrett-client" \
python -m pytest -q -ra tests/test_rust_w2_github_workflow.py
```

The environment variables are intentional: without them, the native
integration cases skip, since test environments may not have Rust built.
For a meaningful W2 acceptance run, set all three and require **zero skips**.
The independent Python policy-shape test can run before compiling Rust.

The native disclosure parser permits explicitly selected camelCase **output**
keys such as `headRefOid` (still a bounded ASCII identifier); operation and
request-argument names retain their lowercase grammar. The policy-shape test
uses the Python parser, so it cannot validate Rust disclosure parsing.
`cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml --lib camel_case_public_projection` exercises that native grammar and projection
without starting the bridge. A bridge startup failure reporting
`invalid_policy` may originate in either the manifest or disclosure file.

## Remaining differences from Python W1

- No generic schema-2 `cli` manifest alias interpreter; just three explicitly
  wired guest-side read commands. No write, `gh api`, Git remote discovery or
  arbitrary GitHub CLI parity.
- Native `request_limit: "unbounded"`; W1 Python request budgets and one-shot
  write approval are **not** inherited. The Rust `writes: deny` gate protects
  this read-only scenario.
- Different approved response projection and pagination framing (`meta`).
  Compare authorized intent, provider effects and approved disclosure rather
  than require identical Python/Rust response bytes.
- Rust project-wide security, verified isolation, adaptive trace
  noninterference and concrete I/O refinement remain W3-W6/W8 work.
