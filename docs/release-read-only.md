# Read-only release profile

This is how to build, deploy, operate and recover the native broker in the
one configuration its proofs cover: a guest that may run named **read**
operations from a host manifest, and nothing else. It is the release
described in OUT-5 of the [product roadmap](planning/aivm-secrets-product-roadmap.md).
The claims, and the evidence and assumptions behind each, are in the
[claim-to-evidence matrix](assurance/claim-evidence-matrix.md).

## What the profile is

- Native Rust broker (`garrett-bridge`) in provider mode with profile
  `manifest-https-v1` and `writes = "deny"`.
- One guest identity per session, enrolled with `garrett-authority`, talking
  [protocol v1](protocol-v1.md) over mTLS on a forwarded Unix socket.
- No forwarding to the Python broker, and no cross-host coordinator.

The `garrett-bridge-read-only` binary enforces this at startup: it refuses
any configuration outside the profile (`profile::read_only`). It is the
ordinary bridge with that one check added. Guest input cannot choose a
configuration with either binary.

## Build

On the trusted host, from a checkout the guest cannot write to:

```bash
cargo build --release --locked --manifest-path rust/Cargo.toml --bins
```

Deploy `garrett-bridge-read-only` under the name `garrett-bridge` in the
directory the session uses (`bin_dir`), next to `garrett-authority` and
`garrett-client`, so nothing else on the host can start the general bridge
for this deployment.

The toolchain is pinned in `rust/rust-toolchain.toml`. Record the commit and
the SHA-256 of `garrett-bridge`, `garrett-authority` and `garrett-client`
with each deployment.

Before deploying a build, check it:

```bash
python dev/verification/system.py --proofs --full-tests   # tests and proofs, no skips
python dev/native_syscall_witness.py --bin-dir rust/target/release
```

The witness runs a full read, a denied write and a revocation with the bridge
under `strace`. It fails if the credential appears in any write the broker
makes, or if the broker connects anywhere but the provider.

## Deploy with AIVM

AIVM never needs this package. To give one VM a session:

1. Prepare host-private (mode 0600) files: the manifest policy, the
   disclosure contract, the provider CA and the credential. Use a credential
   scoped as narrowly as the provider allows.
2. Optionally disable the guest's direct internet access in AIVM
   (`firewall.public_egress = false` on the VM's network, then
   `aivm host fw apply`). The broker does not need it, and it stops a guest
   from reaching the provider directly with anything it might hold.
3. Write a native-session template (the [session contract](aivm-native-session.md)
   without `guest` and `binding`) and start the session:

   ```bash
   aivm ssh --secrets_native_spec TEMPLATE
   ```

   AIVM fills in the guest and binding, runs `aivm-secrets native-session`
   as a child process, and exports the client, config and capability paths
   into the login shell. Closing the shell ends the session and removes the
   guest directory.

4. In the guest, tools call the client:

   ```bash
   "$AIVM_SECRETS_NATIVE_CLIENT" --config "$AIVM_SECRETS_NATIVE_CONFIG" \
     --capability-file "$AIVM_SECRETS_NATIVE_CAPABILITY" \
     gh pr view 123 --repo owner/name --json number,title
   ```

Without AIVM, the [offline operator guide](offline-native-operator-guest.md)
shows the same steps by hand.

## Check a deployment

Run these against the real VM before trusting it with a real credential:

```bash
python dev/aivm_vm_acceptance.py --vm VM --adversarial --agent --workspace "$RUN"
```

This runs approved reads, a denied write and revocation. It also runs the
identity, network, mount and socket probes and a simulated agent that tries
21 ways to get more than it was granted. It then searches every file and
process in the guest, as root, for the credential. All of it uses a synthetic
credential and a local provider. The opt-in live check against GitHub is
`dev/aivm_github_live_acceptance.py`; read
[its guide](aivm-github-live-readonly-acceptance.md) first.

## Operate

| Task | Command |
| --- | --- |
| See identities and CA state | `garrett-authority status --root ROOT` |
| End one guest's access now | `garrett-authority revoke --root ROOT --request REQ` |
| Renew a guest certificate | `garrett-authority renew --root ROOT --request REQ` |
| Rotate the issuer key | `garrett-authority rotate-issuer`, later `retire-issuer` |
| Rotate the session CA | `garrett-authority rotate-ca` |
| Read the audit log | One JSON record per line in the provider `audit_file`; each record is synced before the action it records |

A guest can also end its own grant with the `renounce` verb. That is
audited, and the grant is refused for every later request
(`renounced_grant_refuses_every_use`).

## Recover

- **Broker stopped or host rebooted:** start a new session. Grants and
  capabilities are per session and are never reused.
- **Interrupted authority change:** `garrett-authority transactions` lists
  pending trust transactions. `transaction-status` shows one, and `recover`
  finishes or rolls it back. `recover` needs the transaction ID and the
  SHA-256 of the plan you reviewed.
- **Suspected credential exposure:** revoke the guest, rotate the credential
  at the provider, and read the audit log. The native audit log is not
  hash-chained (the Python reference's is), so its integrity rests on the
  host file permissions. The broker cannot revoke a credential at the
  provider.
- **`outcome_unknown`:** for reads this only means the reply was lost. Retry
  the read once you understand why. The broker never retries automatically.

## What this release does not claim

It claims no writes; those are OUT-4, with their own proofs and tests. It
does not claim protection against a compromised host, the kernel or VM
isolation (environment assumptions), timing side channels, or harm from data
the policy chose to release. Read the [trusted, not proved](../README.md#trusted-not-proved)
list before deploying.
