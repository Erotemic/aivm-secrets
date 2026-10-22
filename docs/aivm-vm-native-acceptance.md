# Native Garrett in a real AIVM VM (OUT-2 first witness)

This is an **opt-in, finite integration smoke test**. The `--adversarial`
extension below adds controlled negative checks; it has not yet been run on
the actual VM. It exercises actual
`garrett-authority`, `garrett-bridge` and `garrett-client` binaries, with the
client **inside a managed KVM/QEMU AIVM VM** and the authority, broker,
synthetic HTTPS provider and newly randomized synthetic credential **only on
the trusted host**. It is not a whole-service isolation or noninterference
proof, and it does not invoke GitHub or use a real credential.

The fixture lives in `dev/aivm_vm_acceptance.py` and is independent of normal
AIVM use. It invokes the installed AIVM CLI for **read-only discovery**
(`aivm vm list`, `aivm vm ssh_config`), then uses ordinary OpenSSH. It does
not import AIVM internals, mount or share the host custody tree, modify
firewall rules or SSH daemon settings, or enable the secrets component by
default. Run it only on a disposable/test VM you are permitted to use.

## Run from the host

The operator runs all the commands below on the **host**, not inside the VM.
The test itself transfers and runs the native client inside `aivm-2404`.

```bash
cd ~/code/aivm-secrets

cargo +nightly-2026-09-17 build --locked \
  --manifest-path rust/Cargo.toml --bins

# Portable preflight for the fixture; does not contact the VM.
python -m pytest -q tests/test_aivm_vm_acceptance.py

RUN="/tmp/garrett-vm-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python dev/aivm_vm_acceptance.py --vm aivm-2404 --workspace "$RUN" && \
  python -m json.tool "$RUN/summary.json"
```

If the AIVM-generated SSH configuration reports `VM_IP_UNKNOWN`, run
`aivm vm wait_ip` from the host and rerun the fixture. If SSH host identity
has never been accepted, first review the guest SSH host key through your
normal AIVM connection workflow. The test respects OpenSSH host-key checking
and **never** sets `StrictHostKeyChecking=no`.

Requirements: a running and SSH-reachable `aivm-2404` with
`strict_firewall=yes`; `systemd-detect-virt` in the guest reporting `kvm` or
`qemu`; compatible host/guest CPU architecture; OpenSSH remote Unix-domain
socket forwarding permitted in guest `sshd`; and the compiled `garrett-client`
executable runnable on the guest. No extra guest package should be required
for a normal Ubuntu 24.04 VM, aside from the guest's existing OpenSSH and
systemd tools. If guest SSH forwarding is disabled, the test **fails closed**;
do not change `sshd` settings without a separate security review.

A private **host** workspace is required: use `/tmp` or an equivalently
protected path. The authority rejects writable non-sticky ancestors, so a
workspace under a group-writable Git checkout (including `.tools/`) is not
suitable. The guest's private workspace is created with `mktemp -d` under its
own `/tmp` and deleted on exit; the test never attaches the host workspace to
AIVM. The optional host `--workspace` is retained for evidence and contains
synthetic operator key material: do not commit it. Omit `--workspace` to use
an automatically cleaned-up host workspace and print only the redacted report.

## What actually crosses the VM boundary

1. AIVM supplies its selected VM's SSH destination and identity. The harness
   requires the selected VM's `strict_firewall=yes` setting. The ordinary
   smoke opens no direct host TCP port; the separate `--adversarial` mode
   temporarily exposes only a credential-free host gateway canary.
2. The native `garrett-client` binary is sent to a **guest-owned private
   directory**. It creates its own key and CSR *inside the guest*. The host
   receives only the public CSR and verifies the reported fingerprint.
3. The native host authority enrolls the CSR, issues a client certificate,
   and returns public CA/certificate material. The native host broker starts
   with a random *per-run* synthetic bearer credential, manifest, disclosure
   policy, host-local HTTPS destination and write denial.
4. The host distributes the certificate, CA, short-lived capability and
   restricted guest config. A temporary SSH `-R` forward creates **one guest
   Unix socket** directed to the native broker's host Unix socket. The guest
   application socket is checked for owner-only permissions. SSH agent and
   X11 forwarding are explicitly disabled. The native mTLS protocol still
   authenticates the client inside that stream.
5. The guest requests the selected PR view and diff. It then submits a named
   `pr.comment` write, which must be denied by the **host broker**, and finally
   attempts another read after the host authority revokes the subject. Host
   provider observations must contain exactly the three approved GETs.
6. Before the authorized application socket is forwarded, the guest must not
   be able to read or resolve the host's private credential, authority state,
   or privileged broker socket **at their actual host absolute paths**. A
   redacted report is saved, and SSH forwarding, native broker, provider,
   and temporary guest files are cleaned up.

Expected `summary.json` fields include `ok: true`, `denied_write: true`,
`revocation_fenced: true`, `host_private_paths_unreadable_in_guest: true`,
`virtualization: "kvm"` or `"qemu"`, and three credential-substituted GET
observations. These are **test observations**, not theorem conclusions.

## Scope and remaining OUT-2 work

This positive witness establishes that the real native guest can communicate
with the host broker over the VM boundary without distributing the runtime
provider credential or exporting the host private paths used by this run. The
SSH forward is a **test transport**, not a completed AIVM release adapter.

It does **not** establish:

- a general negative proof that the guest cannot access *any* host file or
  host-side socket (AIVM may have other existing virtiofs attachments);
- absence of every alternate network/provider egress route (the synthetic
  provider here listens on host loopback; a separate outbound-firewall test
  against a controlled, reachable endpoint is still needed);
- denial for other independently enrolled/unenrolled guest identities, VM
  identity/attestation binding, or guest snapshots and cloning;
- confidentiality of all side channels, SSH administrative access, arbitrary
  guest OS compromise, TPM-backed custody, or formal NR-2/NR-3 I/O refinement;
- a persistent, independently packaged optional AIVM adapter for an actual
  agent, live GitHub interoperability, or approved write effects.

The maintainer's original real-VM smoke run has passed. The **next** gate is
the controlled adversarial run described below. AIVM adapter lifecycle and
cleanup, more complete file/share reachability, and release verification are
still open. The trust claims in
[W0](planning/aivm-secrets-conditional-confinement.md) and the
[product roadmap](planning/aivm-secrets-product-roadmap.md) remain bounded.

## Opt-in adversarial extension (OUT-2 negative witnesses)

The maintainer's **2026-10-21 host run** of the original real-VM fixture on
`aivm-2404` passed: KVM, authorized view/diff, three observed provider GETs,
denied write, inaccessible tested host paths and revocation. Commit `b21e212`
contains that baseline fixture. This is a recorded operator result, not an
assertion that a general VM-isolation theorem was proved.

After building the native binaries, the additional adversarial mode is run
**from the host** using a fresh private workspace:

```bash
cd ~/code/aivm-secrets
python -m pytest -q tests/test_aivm_vm_acceptance.py

RUN="/tmp/garrett-vm-adversarial-$(date -u +%Y%m%dT%H%M%SZ)-$$"
python dev/aivm_vm_acceptance.py --vm aivm-2404 --adversarial \
  --workspace "$RUN" && python -m json.tool "$RUN/summary.json"
```

The ordinary invocation **without** `--adversarial` is unchanged. The new
mode is explicitly opt-in because it creates a short-lived, credential-free
TCP listener bound to the host's actual VM default-gateway interface for a
reachability canary. It closes the listener promptly and never changes AIVM
firewall rules, opens a provider TCP listener, mounts a host path or forwards
an SSH agent. The VM needs `python3` for the two-second TCP probe; absent
probe tooling causes a failed acceptance, not a silently skipped check.

**Additional checks made while the native broker/provider remain live:**

1. Parse the guest's real IPv4 default gateway from `/proc/net/route` and
   connect to the host gateway at the synthetic provider's loopback-only
   port. A direct connection must fail. A separate, actually listening host
   gateway TCP canary on an ephemeral port must receive **no** connection,
   and the guest must also report that the connection failed. This tests one
   non-allowlisted guest-to-host port with the *effective* network behavior,
   rather than trusting `strict_firewall=yes` as evidence that rules are active.
   A local routing failure could also explain the negative result; this is
   **not** an exhaustive firewall inspection or proof of all egress blocking.
2. Inspect guest `/proc/self/mountinfo`, count virtiofs/9p attachment mounts,
   and refuse an explicit reference to the host custody workspace. This is a
   bounded mount-metadata check, **not** a search of every path reachable
   through shared mounts or a proof of general filesystem isolation.
3. Submit an out-of-scope repository read through native `invoke`, **past**
   the `gh` alias parser. It must be rejected without new provider traffic.
4. Generate a **second private key in the VM**, enroll its public CSR as a
   *different subject* in the test authority **before the native broker
   starts**, and attempt a read using that valid same-CA identity and the
   original guest's capability. Also try a
   certificate/private-key mismatch and a capability with one modified
   signature byte. Every attempt must fail without new provider traffic.
   A wrong-subject denial is not proof of an unregistered-certificate or
   expired-certificate path; those are distinct outstanding cases.
5. Terminate the SSH Unix-socket forward while the original capability is
   still active. The disconnected guest must get no data and cause no
   provider request. Reestablish the forward *only* to the same host-owned
   application socket and verify another permitted read, then revoke the
   original subject and verify denial. This tests transport reconnect and
   revocation, **not** a guest reboot/snapshot/clone.

Expected successful extended output has `ok: true`, an `adversarial` object
with bounded network, mount, identity and lifecycle results, and **four**
credential-substituted GET observations: the original three plus one
permitted read after tunnel restoration. No write or rejected request may
reach the synthetic provider. Failed attempts must produce nonzero exit
status; a missing optional capability, missing Python, unexpected output or
inconclusive canary causes a failed gate, not `ok: true`.

The extended mode has **portable unit-test coverage only until an actual
`--adversarial` run is reported**. Do not mark this gate accepted based on
Python source tests or on the earlier successful non-adversarial VM run.

The following remain for OUT-2: verified end-to-end AIVM firewall rules,
full guest mount/share exposure analysis including aliases, unregistered or
expired certificates, full guest reboot and snapshot/clone behavior, an
independently reviewed optional adapter lifecycle, and preservation of
normal AIVM workflows. The synthetic provider never receives a real GitHub
credential. OUT-3 real-provider compatibility is a separate opt-in gate.
