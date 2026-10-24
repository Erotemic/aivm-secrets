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

The maintainer's original real-VM smoke **and the controlled adversarial
extension** have both passed on actual `aivm-2404` KVM. AIVM adapter lifecycle and
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
   **(Added 2026-10-23, not yet run on a VM.)** The inventory now groups
   share mounts by device and root and reports `attachment_devices`,
   `whole_share_root_mounts` and `aliased_mounts`. A mount is an alias when
   another mount of the same device has the same or an enclosing root, as with
   AIVM's persistent share root and its per-directory bind mounts (an AIVM
   guest's own table gives 1 device, 1 whole-share root, 24 aliases). The run
   also writes a random `aivm-secrets-canary-*` file into the host custody
   workspace and searches every share mount point for that name
   (`find -xdev -maxdepth 4`, 20 s cap). A hit fails the run. A timeout is
   reported as `complete: false`, never as absence. Depth and time are capped
   because a whole-tree walk of a large virtiofs share can exhaust the host
   daemon's file handles.
3. Submit an out-of-scope repository read through native `invoke`, **past**
   the `gh` alias parser. It must be rejected without new provider traffic.
4. Generate a **second private key in the VM**, enroll its public CSR as a
   *different subject* in the test authority **before the native broker
   starts**, and attempt a read using that valid same-CA identity and the
   original guest's capability. Also try a
   certificate/private-key mismatch and a capability with one modified
   signature byte. Every attempt must fail without new provider traffic.
   A wrong-subject denial is not proof of an unregistered-certificate or
   expired-certificate path; those are distinct cases. They now have
   synthetic native-bridge coverage (`tests/test_rust_identity_negative.py`):
   an unregistered subject, an enrollment past `not_after`, a re-enrolled
   certificate and an expired capability are refused with no provider call,
   and restoring the registry restores service. That is not a real-VM run.
   Those synthetic tests use the legacy `registry_path` bridge mode. For the
   authority-root mode this VM run uses, `tests/test_rust_garrett_authority.py`
   (2026-10-23) shows that a live re-enrollment with a new key fences the old
   certificate (`invalid_capability`, no provider call), that an enrollment
   reaching `not_after` while the bridge runs is refused at TLS with no
   provider call, and that `forget` refuses active and merely revoked
   subjects, so a live identity cannot become "unregistered" in that mode.
6. **(Added 2026-10-23, not yet run on a VM.)** Last, generate a third key in
   the VM and re-enroll the original subject with it (`replace`). The original
   certificate and capability must be refused without provider traffic
   (`adversarial.identities.reenrolled_certificate_rejected`). Revocation
   follows as before.
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

The maintainer reported an **actual successful `--adversarial` VM run** on
2026-10-21: 23 portable tests passed; the KVM run returned `ok: true`,
blocked the selected host gateway canary and direct provider-port probe,
rejected foreign/mismatched/tampered client authority and out-of-scope reads,
passed the bounded mount inventory and reconnect/revocation checks, and
recorded exactly four authorized synthetic GETs. The report correctly keeps
`filesystem_isolation_proved` and `whole_service_secrecy_proved` false.

The following remain for OUT-2: verified end-to-end AIVM firewall rules,
full guest mount/share exposure analysis including aliases, a real-VM run of
the unregistered/expired identity cases (synthetic bridge coverage exists),
full guest reboot and snapshot/clone behavior, an
independently reviewed optional adapter lifecycle, and preservation of
normal AIVM workflows. The synthetic provider never receives a real GitHub
credential. OUT-3 real-provider compatibility is a separate opt-in gate.

The next independent service-facing test is the [opt-in real GitHub read-only fixture](aivm-github-live-readonly-acceptance.md), which targets `Erotemic/aivm-secrets` without creating a PR, issue, or repository.


## Simulated agent (`--agent`)

`--agent` runs [`dev/guest_agent.py`](../dev/guest_agent.py) inside the
guest as an ordinary program. It does an allowed read, then tries 21 ways to
get more: path, query and header injection in arguments, other repositories
and pull requests, malformed, oversized or extra arguments, unlisted and
denied operations, plain HTTP and garbage on the broker socket, and TLS
without a client certificate. Finally it does the allowed read again. The host
fails the run if any attempt is not refused or if the provider saw anything
other than the two allowed reads. The agent's own report is not enough.

The same flag then runs [`dev/guest_secret_hunt.py`](../dev/guest_secret_hunt.py)
as guest root. It searches the root filesystem, the guest tmpfs mounts and
every process's environment and command line for the credential and its
base64 forms. The patterns are sent on stdin, so the credential never appears
in a guest file or argument. Tests with planted files and environments
(`tests/test_guest_agent_probes.py`) show that the search finds what it is
looking for.

```bash
python dev/aivm_vm_acceptance.py --vm aivm-2404 --adversarial --agent --workspace "$RUN"
```


## Approved write (`--write`)

`--write` runs the broker with `writes = "approve"` and a host-only control
socket. It then checks one comment end to end:
1. The guest's comment is held with `approval_required` and its digest, and
   nothing reaches the provider.
2. The host sees exactly that normalized request pending and approves it on
   the control socket (`aivm-secrets approve DIGEST` does the same).
3. A different comment is still held.
4. The approved comment reaches the provider exactly once.
5. Asking again needs a new approval, and a comment on another repository is
   refused.

The provider is the same local synthetic one. A run against a real
repository is the maintainer's opt-in step.

```bash
python dev/aivm_vm_acceptance.py --vm aivm-2404 --write --adversarial --agent --workspace "$RUN"
```


## Identity lifecycle through AIVM

`dev/aivm_identity_lifecycle_acceptance.py` drives `aivm vm identity_*`
against the active managed VM with a fresh, temporary identity authority.
It checks each step against the authority's own `identity status`:
enrollment, the operator-only refusal of `enroll --replace` under
`--yes_sudo`, renewal, key rotation, renewal after a real shutdown and start,
a guest restored to an older key (renewal refused, the retired key cannot be
re-enrolled, recovery with a fresh key by compare-and-swap), a guest without
`openssl` (nothing issued), and revocation. The VM's SSH host key must be
pinned first (`aivm vm access reconcile`).

```bash
python dev/aivm_identity_lifecycle_acceptance.py --vm aivm-2404
```
