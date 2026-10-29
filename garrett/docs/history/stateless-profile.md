# `garrett-stateless-v1`: status and what remains

> **History.** Written while this profile lived inside `aivm-secrets`; paths
> such as `rust/crates/aivm-secrets-garrett-core`, `aivm_secrets/garrett_stateless`
> and `dev/verification/garrett.py` are now `crates/garrett-stateless-core`,
> `src/garrett_stateless` and `verification/`. Gate pins and AIVM ledgers it
> mentions belong to that project.

Started 2026-10-26 from baseline `e9aa9fa`. Goal: Matthew Garrett's described
architecture as standalone Python and Rust libraries, with implementation-linked
Lean proofs of the Rust decisions. This profile is separate from the stateful
AIVM profile and does not change it.

Read first: [specification](../garrett-stateless-v1.md) (section 14 separates
the article from our choices), [usage](../usage.md),
[proofs](../verification.md).

## Where things are

| Piece | Location |
| --- | --- |
| Extracted decisions (Rust) | `rust/crates/aivm-secrets-garrett-core/src/stateless{,_login,_proxy,_mailbox,_token}.rs` |
| Rust library and CLI | `rust/crates/garrett-stateless` (`tests/workflow.rs`, `tests/vectors.rs`) |
| Python library and CLI | `aivm_secrets/garrett_stateless/` (`decisions.py` mirrors the core) |
| Lean | `proofs/GarrettStateless*.lean` (default `lake build` roots); the global theorem is `protocol_safety` in `GarrettStatelessProtocol.lean`, the external boundary is `GarrettStatelessBoundary.lean` |
| Shell guard | `dev/verification/stateless_shell.py check` (`tests/test_garrett_stateless_shell.py`) |
| Mutants | `dev/verification/garrett.py`, labels starting `stateless ` |
| Vectors | `tests/secrets_vectors/garrett-stateless-v1.jsonl` (generator `dev/garrett_stateless_vectors.py`; regenerate only on a deliberate format change) |
| Tests | `tests/test_garrett_stateless{,_vectors,_interop,_tpm,_shell,_strict}.py`; `rust/crates/garrett-stateless/tests/{workflow,vectors,codec_agreement}.rs` |
| Strict profile, acquisition adapters | spec sections 7.1 and 9; `proofs/GarrettStatelessStrict.lean`; `config.rs`/`config.py` (`acquisition`, `stateless`) |
| Synthetic IdP/API fixture | `examples/garrett-stateless/synthetic_provider.py` |
| Demo | `scripts/garrett-stateless-demo.sh`, `examples/garrett-stateless/` |
| Assumptions | ledger IDs `STATELESS-*` |

## Validation status (2026-10-27)

| Check | Result |
| --- | --- |
| `cargo test -p garrett-stateless -p aivm-secrets-garrett-core` | pass (core 110; shell unit, vectors, end-to-end over TLS and the strict provisioned workflow with its read-only proxy) |
| `pytest tests/test_garrett_stateless*.py` | 103 pass (including the 4-way interop matrix, the 4-way strict provisioned matrix, the operation-policy cases and the swtpm test, with both Rust builds present) |
| Full default `lake build` (1921 jobs) | pass; `garrett.py record-sources` re-recorded the manifest |
| Stateless Rust mutants (`garrett.py mutate --mutation-filter '^stateless '`) | 42 of 42 rejected (2026-10-27, operation-authorization increment) |
| Opt-in axiom audit | 2026-10-26 only (1,885 theorems, standard axioms); not re-run for this increment |
| `protocol_safety` (global internal theorem) | compiles; premises are only the external boundary |
| Shell guard `stateless_shell.py check` | pass (12 checks) |
| Container demo | pass, `ok: true`, `--network none` |
| External project depending on the crate (stable 1.98) | builds and runs |

The mutant and audit runs are also recorded in `dev/journals/claude.md`
(2026-10-26 and 2026-10-27).

## Composable isolation, first increment (2026-10-27)

- Requests are decided by the pure Rust `stateless_proxy::decide(opener,
  request, routes, acceptance, peer, now)`; `serve` acts on it. Lean:
  `decide_request` is that function; `serve_outcome` and
  `replicas_differ_only_by_answers` separate equal decisions from network
  outcomes, which can differ.
- Acquisition is a closed choice of two adapters, `provisioned` and `oauth`
  (spec section 7.1, ledger `STATELESS-ACQ-01`). Provisioned providers need no
  OAuth client, browser listener or token endpoint; `mint` reads only the keys
  and the issuance policy.
- `"stateless": "strict"` (spec section 9) refuses OAuth providers in a
  broker and an audit file in a proxy. `no_providers_no_state` and
  `strict_no_login_state` prove a broker whose login policy names no provider
  never holds a login; the shell guard checks the policy names only OAuth
  providers and that no other mutable state or file write exists.

## Composable isolation, second increment (2026-10-27)

- A static operation policy in the extracted core (`stateless_policy`):
  Garrett's `Unrestricted` and a constrained `ReadOnly` proxy (spec section
  11.1). `decide` consults it after authenticating and before decrypting.
- `composed_egress` (`GarrettStatelessComposition`) composes identity,
  authorization, provider selection, exact encoding and controlled egress
  for any policy with a `Sound` contract, and is instantiated for both
  extracted policies. Details, acceptance evidence and the gate re-pin review
  are in [aivm-secrets-garrett-composition.md](composition.md).

## Remaining work (none of it blocks local use)

1. **Live provider compatibility (maintainer).** Run one real OAuth provider
   with PKCE (for example a GitHub OAuth app, which supports PKCE) and a
   read-only API call. Configure `token_url`/`authorization_url` and a client
   secret file. Never use live credentials in tests or CI.
2. **Hardware TPM (maintainer).** Repeat `tests/test_garrett_stateless_tpm.py`
   with a device TPM. Provenance (EK/AK) must be verified by the CA before it
   certifies the key. The profile does not check it.
3. **Independent review** of the specification, the trusted shells
   (`STATELESS-NATIVE-01`) and the proof map. An agent cannot self-certify it.
4. **Stronger linkage (optional).** The connection loop, the mailbox, the
   token and login-state codecs and the key set are now extracted and proved,
   and composed into `protocol_safety` (2026-10-26 and 2026-10-27). What remains outside is
   the shell's I/O (guarded, not proved) and a whole-process syscall witness
   for the stateless proxy, like `dev/native_syscall_witness.py`. A Lean
   witness of delivery through `poll` would complete the positive witnesses.
5. **Release (maintainer decision).** The crate has `publish = false`.
   Publishing the crate or the Python distribution needs approval and a
   version decision.
6. **Multi-replica broker run.** Two broker replicas with distinct redirect
   URIs behind one agent population. The design supports it; it is untested.
7. **OAuth without the mailbox (separate increment).** The mailbox is the only
   mutable process state, and only OAuth logins use it. Removing it means a
   protocol change (for example, an agent-held encrypted login handle the
   browser result is bound to); it is not part of `garrett-stateless-v1`.
8. **Further acquisition adapters.** A provider-specific short-lived
   credential exchange would be a third closed variant with its own trust
   row in section 7.1, not a plugin interface.
9. **The final axiom audit** is opt-in and end-of-formalization
   (`python dev/verification/axiom_audit.py run`, differences only). Record
   its result in `docs/assurance/axiom-audit.md` when the maintainer asks.

## Decisions an agent made (revisit freely)

- Transient in-memory mailbox for login delivery. It is bounded, single-use,
  holds only cert-bound surrogates, and is lost on restart.
- No refresh tokens. Stateless renewal is capped by `ren` and cannot extend it.
- Copied claims default to access claims only (`copy_claims`).
- A reverse proxy whose destination is chosen by the authenticated `prv`.
- The Python agent has no TPM mode. It refuses rather than falling back.
- CRLs are not checked. Revocation is by expiry and key retirement.
- Strict mode is an explicit configuration value, not inferred, so a
  deployment can demand it and fail closed.
- Keys are injected as private files; no inherited-descriptor loader (spec
  section 9 says why).
- A provisioned credential's lifetime is unknown (`+∞`); `max_renew` and the
  certificate bound `ren`.
