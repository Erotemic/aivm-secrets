# Garrett protocol: executable, synthetic-credential walkthrough

This MWE drives the **real native Rust** authority, read-only bridge and guest
client in `aivm-secrets`. It is not a rewrite or mock of the protocol. A small
Python script provides a disposable synthetic HTTPS endpoint, deterministic
example responses and operator setup. The native Rust binaries do the identity,
policy, TLS, provider-credential dispatch, projection, audit and revocation.

## One command

From the repository root, with Docker installed and running:

```bash
bash scripts/garrett-container-demo.sh
```

To stop after each step and advance with Enter:

```bash
bash scripts/garrett-container-demo.sh --pause
```

For Podman, set `CONTAINER_ENGINE=podman`. The first image build needs internet
access to fetch pinned Rust and Python dependencies. **The demo runtime is
fully offline** (`--network none`); the only HTTPS service is bound to
`127.0.0.1` inside the container. There are no bind mounts, external
credentials, Docker socket mounts, `--privileged` or KVM requirements.

The script runs as a nonroot user with a read-only root filesystem and a private
64 MiB temporary workspace. The image builds the **`garrett-bridge-read-only`**
binary, installs it as `garrett-bridge` for the existing operator script, and
rejects any config outside the native `manifest-https-v1` read-only profile.
It is a functional demonstration: **host and guest run as the same Unix user in
one container** and their directory separation is not an isolation boundary.
A real deployment uses a separate VM, controlled mounts and optionally TPM
custody, with additional checks.

## What it walks through

1. Explain the trust boundary and synthetic-only assumptions.
2. Prepare the host's credential, pinned local HTTPS provider, named operation
   policy and response disclosure contract.
3. Create a software signing key and CSR; approve enrollment; issue the
   native mTLS client certificate.
4. Bring up the real native TLS bridge and its certificate-bound surrogate.
5. Read one approved synthetic PR and verify that private response fields
   were excluded from the guest's reply.
6. Request the approved diff and verify the provider received the **host-held**
   bearer credential, not the surrogate.
7. Enroll a second independently keyed client, give it the first guest's
   **stolen surrogate**, and verify it cannot cause an additional provider call.
   This does not protect copied software keys.
8. Request `pr.comment` and see native `writes=deny` block the actual request
   before any provider send.
9. Revoke enrollment; verify the old client can no longer make a provider call.
10. Check the host audit and guest distribution for credential and surrogate
   leaks, and print a machine-readable JSON report to stdout.

The results cover a **bounded local run**, not an arbitrary agent, container
isolation, physical TPM provenance, production OAuth acquisition, live GitHub,
complete protocol equivalence, or the assumptions behind the Lean theorems.
The container's synthetic TLS provider is a positive demonstration of
credential substitution. The proof claims and scope are documented in
`docs/assurance/claim-evidence-matrix.md` and `docs/assurance/native-read-proof-tour.md`.

## Without Docker

If the pinned Rust toolchain and Python dependency are already installed,
run directly on the host:

```bash
cargo build --locked --manifest-path rust/Cargo.toml \
    -p aivm-secrets-garrett \
    --bin garrett-authority --bin garrett-bridge-read-only --bin garrett-client
mkdir -p /tmp/garrett-demo-read-only
cp rust/target/debug/garrett-authority rust/target/debug/garrett-client /tmp/garrett-demo-read-only/
cp rust/target/debug/garrett-bridge-read-only /tmp/garrett-demo-read-only/garrett-bridge
python dev/offline_native_guest.py --bin-dir /tmp/garrett-demo-read-only --walkthrough
```

This local example copies already-built executables into a separate demo bin
directory because the operator script expects a binary named `garrett-bridge`.
`--pause` works here too; it requires a terminal. For a persistent local
inspection, specify a fresh `--workspace` directory on the host (never point
it at an existing directory); the ephemeral default deletes all credentials
and private keys at the end. Do not use real credentials in this demo.

## What is not demonstrated

- The container has no TPM. Software key copying is a permitted counterexample
  to claims of hardware-backed instance non-exportability.
- The mock upstream is an HTTPS provider, **not** an OAuth authorization server.
  OAuth PKCE acquisition, refresh, consent and live-provider compatibility have
  their own native code, tests and narrower proof contracts.
- Garrett's proposed stateless sealed-token placement is not the exact runtime
  architecture here: this native profile uses enrollment state and an inner
  capability/reference monitor. The demo exercises that explicit extension.
- The actual native read assurance is conditional on named I/O, crypto,
  admission, audit, policy and deployment contracts. A successful demo does not
  discharge these contracts or amount to an independent security review.
