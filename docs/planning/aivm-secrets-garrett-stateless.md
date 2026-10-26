# `garrett-stateless-v1`: status and what remains

Started 2026-10-26 from baseline `e9aa9fa`. Goal: Matthew Garrett's described
architecture as standalone Python and Rust libraries, with implementation-linked
Lean proofs of the Rust decisions. This profile is separate from the stateful
AIVM profile and does not change it.

Read first: [specification](../garrett-stateless-v1.md) (section 14 separates
the article from our choices), [usage](../garrett-stateless-usage.md),
[proofs](../verified-garrett-stateless.md).

## Where things are

| Piece | Location |
| --- | --- |
| Extracted decisions (Rust) | `rust/crates/aivm-secrets-garrett-core/src/stateless{,_login,_proxy}.rs` |
| Rust library and CLI | `rust/crates/garrett-stateless` (`tests/workflow.rs`, `tests/vectors.rs`) |
| Python library and CLI | `aivm_secrets/garrett_stateless/` (`decisions.py` mirrors the core) |
| Lean | `proofs/GarrettStateless{,Login,Proxy}.lean` (default `lake build` roots) |
| Mutants | `dev/verification/garrett.py`, labels starting `stateless ` |
| Vectors | `tests/secrets_vectors/garrett-stateless-v1.jsonl` (generator `dev/garrett_stateless_vectors.py`; regenerate only on a deliberate format change) |
| Tests | `tests/test_garrett_stateless{,_vectors,_interop,_tpm}.py` |
| Synthetic IdP/API fixture | `examples/garrett-stateless/synthetic_provider.py` |
| Demo | `scripts/garrett-stateless-demo.sh`, `examples/garrett-stateless/` |
| Assumptions | ledger IDs `STATELESS-*` |

## Validation status (2026-10-26)

| Check | Result |
| --- | --- |
| `cargo test -p garrett-stateless -p aivm-secrets-garrett-core` | pass (unit, 72 vectors, end-to-end over TLS) |
| `pytest tests/test_garrett_stateless*.py` | 78 pass (including the 4-way interop matrix and the swtpm test, with both Rust builds present) |
| Full default `lake build` (1909 jobs) | pass; `garrett.py record-sources` re-recorded the manifest |
| Stateless Rust mutants (`garrett.py mutate --mutation-filter '^stateless '`) | 14 of 14 rejected (7 by `GarrettStateless`, 3 by `GarrettStatelessLogin`, 4 by `GarrettStatelessProxy`) |
| Opt-in axiom audit | 1,497 theorems, all on Lean's three standard axioms; baseline re-recorded |
| Container demo | pass, `ok: true`, `--network none` |
| External project depending on the crate (stable 1.98) | builds and runs |

The mutant and audit runs are also recorded in `dev/journals/claude.md`
(2026-10-26).

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
4. **Stronger linkage (optional).** Extract the connection-loop glue and the
   mailbox stage update. Add a whole-process syscall witness for the stateless
   proxy, like `dev/native_syscall_witness.py`.
5. **Release (maintainer decision).** The crate has `publish = false`.
   Publishing the crate or the Python distribution needs approval and a
   version decision.
6. **Multi-replica broker run.** Two broker replicas with distinct redirect
   URIs behind one agent population. The design supports it; it is untested.
7. **The final axiom audit** is opt-in and end-of-formalization
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
