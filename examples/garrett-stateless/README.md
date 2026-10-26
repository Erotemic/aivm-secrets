# garrett-stateless-v1: one-command synthetic demonstration

This runs Matthew Garrett's stateless agentic-identity architecture
([*Securing agentic identity*](https://codon.org.uk/~mjg59/blog/p/securing-agentic-identity/))
with the **real** `garrett-stateless` broker, proxy and agent client. The broker
and proxy are the Rust implementation, and a second proxy replica is the Python
implementation. Only the identity provider and the protected API are fixtures
(`synthetic_provider.py`). All credentials are synthetic.

```bash
bash scripts/garrett-stateless-demo.sh            # unattended
bash scripts/garrett-stateless-demo.sh --pause    # stop after each step
```

The first image build downloads the pinned Rust toolchain and Python
dependencies. At runtime the container has **no network** (`--network none`),
runs as a nonroot user with a read-only root filesystem and a 64 MiB private
`/tmp`, and binds only loopback. Set `CONTAINER_ENGINE=podman` for Podman.

Without a container, from a checkout with `cargo build -p garrett-stateless`
done and the package installed:

```bash
python examples/garrett-stateless/walkthrough.py \
    --rust rust/target/debug/garrett-stateless --python-cmd "python -m aivm_secrets.garrett_stateless"
```

## What it walks through

1. The trust model, and what this run cannot show.
2. A development CA, the server certificate, and two agent certificates
   (`agent-c` with a SPIFFE URI, `agent-d`). Broker keys, and the exported
   proxy keys, which have no signing seed and no login-state key.
3. The synthetic provider, the Rust broker (agent API over mTLS, and the
   browser endpoint) and the Rust proxy start.
4. `agent-c` begins a login and receives a URL and a confirmation code. It
   runs no callback listener.
5. A simulated human opens the broker's page, checks the code, approves at the
   identity provider, and is redirected to the broker. The broker exchanges the
   code using the PKCE verifier sealed in `state`.
6. The agent collects its surrogate and inspects the public claims.
7. `GET /user` and a `POST` with a body go through the proxy. The provider log
   shows it received the hash of the *real* token, not the surrogate.
8. `agent-d` presents the copied surrogate and gets `401`; nothing is sent
   upstream. A deny rule (`403`) and a reflected credential (`502`) are also
   refused.
9. The broker stops and the proxy restarts as a new process. The same
   surrogate works, and so does a Python proxy replica: **no state is
   shared**.
10. Rotating and retiring the signing key, then redeploying the proxy key set,
    revokes the surrogate (`401`).
11. Evidence: the last stdout line is a JSON report with every check, and
    `ok: true` only if all of them hold.

## Limits

This is one container and one Unix user, so it is not VM isolation. The agent
keys are software keys: a copied key and certificate impersonate the agent.
The TPM mode, real identity providers and real provider APIs are not exercised.
See [`docs/garrett-stateless-v1.md`](../../docs/garrett-stateless-v1.md) and
[`docs/verified-garrett-stateless.md`](../../docs/verified-garrett-stateless.md).
