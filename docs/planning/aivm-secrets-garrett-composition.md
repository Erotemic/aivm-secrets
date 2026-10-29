# Composable Garrett credential isolation

Status of the composable-isolation work in the `garrett-stateless-v1` profile.
The profile's overall status is in
[aivm-secrets-garrett-stateless.md](aivm-secrets-garrett-stateless.md); the
specification is [garrett-stateless-v1.md](../garrett-stateless-v1.md)
(sections 7.1, 9 and 11.1) and the proofs are described in
[verified-garrett-stateless.md](../verified-garrett-stateless.md).

## Goal

Build the proxy's credential isolation from separately verified extracted
components, keep Garrett's statelessness (keys and static configuration
only), and show that one composition theorem serves more than one
configuration. Acquisition stays outside the isolation core.

## Increments

**1. Acquisition and statelessness (`55d85b2`, `f135ceb`, 2026-10-27).** The
pure `stateless_proxy::decide`; the closed choice of acquisition adapters
(`provisioned`, `oauth`); the strict profile (`GarrettStatelessStrict`).

**2. Operation authorization and the composition theorem (2026-10-27).**

| Piece | Where |
| --- | --- |
| `OperationPolicy` trait: `permits(&self, &SurrogateClaims, &Operation) -> bool`, and its two implementations `Unrestricted` (Garrett's proxy) and `ReadOnly` (`GET`/`HEAD`, no body, allowed provider and path) | `rust/crates/aivm-secrets-garrett-core/src/stateless_policy.rs` |
| `decide` authenticates (`stateless::authenticate`), selects the route, asks the policy, and only then decrypts (`stateless::decrypt`); a refusal is `403 denied` | `stateless_proxy.rs`, `stateless.rs` |
| The dispatch payload is a private-field `Dispatch` | `stateless_proxy.rs` |
| `read_only` proxy configuration; the shell runs the core loop under `&Unrestricted` or the configured core `ReadOnly` and implements no policy itself | `garrett-stateless/src/{config,proxy}.rs`, guarded by `dev/verification/stateless_shell.py` (12 checks) |
| Python mirror (same order, same codes) | `aivm_secrets/garrett_stateless/{decisions,config,proxy,cli}.py` |
| Composition theorem `composed_egress` (identity, authorization, provider selection, credential release, exact encoding, controlled egress), proved once for any policy with a `Sound` contract | `proofs/GarrettStatelessComposition.lean` |
| Instantiations for the two extracted instances: `garrett_egress` (`unrestricted_sound`), `read_only_egress` (`read_only_sound`), with `read_only_dispatch` and `read_only_refuses` | same |
| Replicas answer by answer: `serve_answered`, `replicas_same_answers_same_reply`, `replica_replies_differ` | same |
| `decide_dispatch_trace`, `dispatch_permitted`, `decide_unpermitted` (no decryption for a refused operation); `authenticate_ok_trace`, `decrypt_ok_trace`, `open_of_halves` | `GarrettStatelessProxy.lean`, `GarrettStateless.lean` |
| The protocol model's `Config` carries the policy, so `protocol_safety` holds for either | `GarrettStatelessProtocol.lean` |
| End-to-end: one surrogate through a Garrett and a read-only proxy, 14 request cases (method, path, body and destination changes), Python and Rust; replica equivalence per configuration | `tests/test_garrett_stateless_operations.py`, `rust/crates/garrett-stateless/tests/workflow.rs` |
| Mutation evidence: eight operation-authorization mutants | `dev/verification/garrett.py` |
| Assumption `STATELESS-OPS-01` (what "read-only" means at the provider) | `aivm-secrets-assumptions.json` |

## Acceptance criteria (increment 2)

| Criterion | Evidence |
| --- | --- |
| One valid surrogate used through two differently configured proxies | `test_one_surrogate_two_policies` (minted once, used through both) |
| Successful authorized provider access in both | the three `ALLOWED_BOTH` cases; Rust `strict_provisioned_workflow` |
| An operation allowed by the Garrett proxy, refused by the constrained proxy | the nine `GARRETT_ONLY` cases (changed method, path, body, destination) |
| No upstream credentialed request on that refusal | the provider log is unchanged for each refusal; `read_only_refuses`, `decide_unpermitted` |
| No new token database, grant registry or coordination service | the policy is static configuration; the shell guard's mutable-state check is unchanged |
| One general composition theorem reused for both extracted configurations | `composed_egress`, instantiated by `garrett_egress` and `read_only_egress` |
| Mutation tests for removal or bypass of operation authorization | eight mutants, all rejected (validation table) |
| Passing Rust, Python, extraction and Lean validation | see the validation table |

## Validation (increment 2, 2026-10-27)

| Check | Result |
| --- | --- |
| `cargo test -p garrett-stateless -p aivm-secrets-garrett-core` | pass (core 110, including `the_read_only_policy_refuses_before_egress` and the policy unit test; the strict workflow's read-only proxy section) |
| `pytest tests/test_garrett_stateless*.py` | 103 pass, including `test_garrett_stateless_operations.py` for Python and Rust |
| Full `python -m pytest -q` | 2827 passed, 779 skipped (optional backends not configured) |
| `garrett.py extract`, then full default `lake build` (1921 jobs) | pass |
| `generated_scope.py diff e9aa9fa` | no declaration outside the `stateless*` sources changed |
| Stateless Rust mutants | 42 of 42 rejected, including the eight operation-authorization mutants |
| `stateless_shell.py check` | pass (12 checks) |
| W0 and W3 checkers; NR-0, read-path, W4 and W5 gate tests | pass after the re-pins below |
| `python -m build` | pass |

## Review points from increment 1

* **Strict configuration to theorem hypothesis.** `strict_no_login_state`
  assumes a login policy with no providers. The native chain is: a strict
  broker configuration refuses every `oauth` provider (`config.rs`, tested
  in both implementations); `Broker::login_policy` keeps only `oauth`
  providers (shell guard); the Rust workflow test asserts that a strict
  broker's `login_policy().providers` is empty. The link from the native
  value to the Lean hypothesis is that test plus the guard, not a proof.
* **Issuance configuration.** `mint` parses `broker.json` but reads only the
  issuance fields and the key file. A configuration naming absent TLS files
  loads (Rust workflow test), so the TLS paths are inert for `mint`. A
  separate issuance schema would add a second configuration format without
  removing any code from the trusted path, so it is not added.
* **`mint` for `oauth` providers.** Kept, and documented as a trusted
  operator override (spec section 7, `STATELESS-ACQ-01`). Restricting it would
  not constrain an operator who holds the broker keys, and the protocol model
  already treats every mint as an issuance root.
* **Replica theorem naming.** `replicas_differ_only_by_answers` covers three
  answers (admission acknowledgement, exchange result, completion
  acknowledgement), not only the provider's reply. Its documentation says so,
  and `replica_replies_differ` separates them.
* **Re-pinned gate hashes** (below).

## Gate pins that changed, for maintainer review

NR-0 (`aivm-secrets-native-read-nr0.json`), read-path
(`aivm-secrets-read-path-proof-scope.json`), W4 and W5 pin the SHA-256 of the
whole generated file `proofs/generated/AivmSecretsGarrettCore.lean`; W3
(`aivm-secrets-w3-reachability.json`) pins the stateless Rust sources it
inventories. Every `garrett-stateless-v1` commit has re-pinned them,
starting at `2b8918d`. The last value before the stateless series came from
`843c89f` (2026-10-24), and the last commit before the series is `e9aa9fa`.

Re-recording a pin is not approval. To check what a re-pin covers:

```bash
python dev/verification/generated_scope.py diff e9aa9fa
```

It compares the generated file declaration by declaration (ignoring source
line numbers) and exits non-zero if anything outside the `stateless*` Rust
sources changed. Its result on this tree, against both `e9aa9fa` and
`843c89f`: all 887 pre-existing declarations and the preamble are unchanged;
the only differences are added declarations from `stateless.rs`,
`stateless_login.rs`, `stateless_mailbox.rs`, `stateless_policy.rs`,
`stateless_proxy.rs` and `stateless_token.rs`. `git diff e9aa9fa --stat --
rust/crates/aivm-secrets-garrett-core/src` shows only those new files and
their `pub mod` lines in `lib.rs`. The W3 entries that changed are
`stateless*` and `garrett-stateless` shell sources, which entered W3 with the
profile (`88755ea`), the new `stateless_policy.rs`, and the core `lib.rs`,
whose only change in this increment is the line `pub mod stateless_policy;`.
NR-0 pins that `lib.rs` too, and was re-pinned for the same line. **Maintainer approval of these re-pins is pending**; no
agent commit constitutes it.

## Remaining work (not in this increment)

1. Mailbox-free OAuth acquisition (a protocol change; spec section 9).
2. Further acquisition adapters, such as providers' own short-lived
   credentials.
3. Provider-specific operation descriptions (for example, a GitHub read-only
   resource catalogue reviewed against the API), to narrow `STATELESS-OPS-01`.
4. A proof, rather than a guard, that the native shell selects the policy
   from configuration and keeps no other state.
5. Independent review of the composition theorem's statement (`Isolated`).
