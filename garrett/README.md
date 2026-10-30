# garrett-stateless

An implementation of the credential-brokering architecture Matthew Garrett
described in [*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/)
(July 2, 2026), as the wire profile **`garrett-stateless-v1`**:

- an untrusted agent authenticates to a **broker** with a client certificate
  (mTLS); after a human approves an OAuth login in a browser, or an operator
  mints one directly, the broker issues a **surrogate**: a signed token that
  carries the real provider credential AES-256-GCM-encrypted and is bound to
  the agent's certificate;
- the agent sends ordinary API requests with the surrogate as its bearer
  token to a **stateless mTLS proxy**, which checks the binding against the
  connection's certificate, decrypts the credential, substitutes it, and
  forwards the request to the provider the token names.

The proxy's decisions depend only on its keys, its static configuration, the
request and the clock, so any number of replicas with the same keys behave
alike. The broker's one piece of mutable state is the transient mailbox of
an in-progress OAuth login; a `"stateless": "strict"` configuration refuses
OAuth (credentials are minted by an operator instead) and the proxy's audit
log, leaving no mutable authorization or login state (only ordinary runtime
and transport state: sockets, TLS sessions, buffers). A proxy can also be limited to
read-only operations on configured resources.

**Experimental and unaudited.** Not published to any registry.

## Layout

| Path | What |
| --- | --- |
| `docs/garrett-stateless-v1.md` | the normative specification, including every divergence from the article |
| `crates/garrett-stateless-core` | the protocol: every decision, codec and state transition, as pure Rust with no dependencies. Aeneas extracts it to Lean |
| `crates/garrett-stateless` | the application: broker, proxy, agent client and CLI, with `ring`, `rustls` and an optional TPM signer |
| `src/garrett_stateless/core` | the Python reference of the protocol, module for module as the Rust crate; standard library only |
| `src/garrett_stateless` | the Python application (same CLI as the Rust one), using `cryptography` |
| `proofs/` | an independent Lake package: the generated Lean model of the core crate and the theorems about it |
| `verification/` | the pinned toolchain, extraction, mutation testing and the shell guard |
| `tests/`, `tests/vectors/` | Python tests and the conformance vectors both implementations are checked against |
| `examples/` | a synthetic provider, a library example and a container walkthrough |

## Quick start

```bash
cargo build && cargo test                     # Rust
pip install -e '.[tests]' && python -m pytest  # Python (interop tests use the Rust build)
bash examples/garrett-stateless-demo.sh        # narrated container walkthrough, no network
```

[`docs/usage.md`](docs/usage.md) covers deployment, configuration and the
library APIs.

## Verification

```bash
python verification/toolchain.py bootstrap   # pinned Aeneas release, Rust nightly, Lean; Mathlib cache
python verification/extract.py check          # proofs/generated is exactly what the tools produce
(cd proofs && lake build)                     # every theorem
python verification/mutate.py                 # 42 security mutants, each rejected by a proof
python verification/shell_guard.py check      # the application calls the core as the proofs assume
```

[`docs/verification.md`](docs/verification.md) states what is proved (the
composed protocol theorem `protocol_safety`, the isolation theorem
`composed_egress` for both operation policies, and the per-function contracts
under them), what is only tested, and what is trusted:
[`docs/assumptions.json`](docs/assumptions.json).

## Origin

This project was developed inside `aivm-secrets` and extracted with its
history; [`docs/history/`](docs/history) keeps the planning notes from that
period.
