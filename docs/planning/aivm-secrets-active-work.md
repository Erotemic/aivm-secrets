# Plan: where we are and what comes next

Updated 2026-10-24 at `0b9cc33`. This is the single ordered work queue.
The [product roadmap](aivm-secrets-product-roadmap.md) defines the outcome
gates (OUT-0 to OUT-6) and the [native read roadmap](aivm-secrets-native-read-assurance-roadmap.md)
defines the proof gates (NR-0 to NR-5). The previous queue is archived in
[aivm-secrets-active-work-history-2026-10-24.md](aivm-secrets-active-work-history-2026-10-24.md).

## Where we are

The broker works. The native Rust implementation runs an authority, a bridge
and a guest client. It has done approved reads, refused a write and revoked a
guest, both offline and from a real KVM guest. It has also made approved reads
against GitHub. A large part of its decision logic is extracted with Aeneas
and proved in Lean (113 proof modules, about 30k lines of Lean against 32k
lines of Rust).

The gap that matters most is between those proofs and the whole native
process. The top-level read theorem
(`production_accepted_read_has_exact_attempt_accounting_and_guest_frame`)
proves that every provider write the request path makes was authorized,
audited and bound. It does so under the premise `ExactNativeSinkCoverage`: no
other native code writes credential bytes. That premise (`NATIVE-SINK-01`) is
checked today by source guards and tests, not by a proof. Proving that the
authorized path is safe does not, on its own, rule out a second path.

The other open items are integration runs that the maintainer has not yet
done in a VM, the read-only release package, and the write campaign.

What changed for planning: this host can now run AIVM VMs itself (nested KVM;
`aivm host install_deps` was fixed to work here). Real-VM acceptance runs no
longer have to wait for the maintainer. They can be part of the normal loop.
An "agent" in those runs is just a guest program, so a scripted adversarial
guest is a faithful stand-in.

## Phase 1: integration evidence from a local VM

| Step | Deliverable | Done when |
| --- | --- | --- |
| 1.1 | Create `aivm-2404` on this host with `aivm` (no secrets adapter) | **Done 2026-10-24.** Required two aivm fixes: `install_deps` past a broken apt source, and cloud-init errors on new VMs |
| 1.2 | Rerun `dev/aivm_vm_acceptance.py`, baseline and `--adversarial` | **Done 2026-10-24**, with and without an attached workspace. The canary search now runs as guest root (the guest user has passwordless sudo) |
| 1.3 | Run `dev/aivm_proxy_acceptance.py` (substitution) and `dev/aivm_constrained_acceptance.py` (guest-side translator) | **Done 2026-10-24.** The constrained script had two bugs that only a real run could show; both fixed with a test |
| 1.4 | Check the AIVM no-public-egress firewall mode (HP-7) | **Done 2026-10-24.** No direct public connection; the proxies and the adversarial run still pass |
| 1.5 | Write a simulated agent: a guest program that tries every attack listed in the [claim matrix](../assurance/claim-evidence-matrix.md) and also does one useful read | **Done 2026-10-24.** `dev/guest_agent.py` (21 attacks plus reads before and after) runs with `--agent`; the verdict uses the provider's own record. `dev/guest_secret_hunt.py` then searches the whole guest as root: 73,718 files and 186 processes, credential not found. Positive controls in `tests/test_guest_agent_probes.py` |

Record each run in `dev/validation/` with the checkout hash, VM image and
summary. Runs so far: [2026-10-24](../../dev/validation/2026-10-24-local-vm-acceptance.json). These runs are evidence for OUT-2 and OUT-6, not a proof of
isolation. The maintainer still signs off on OUT-2.

## Phase 2: close the native sink premise

This is the main proof gap (`NATIVE-SINK-01`, `ExactNativeSinkCoverage`).

| Step | Deliverable | Done when |
| --- | --- | --- |
| 2.1 | Seal the credential type and pin its readers | **Done 2026-10-24.** `custody::Credential` and OAuth's `CurrentCredential` are sealed with `static_assertions` (a derived `Clone` fails the build) and the seven production readers are pinned by `tests/test_native_credential_readers.py` |
| 2.2 | Whole-process witness | **Done 2026-10-24.** `dev/native_syscall_witness.py`: no credential bytes in any write-family syscall of the bridge, only the provider as a network destination, positive control on the audit records. TLS decryption was not needed: plaintext credential bytes have no reason to appear in any syscall at all |
| 2.3 | Restate the premise as a contract | **Done 2026-10-24.** Ledger entry, roadmap row, claim matrix and proof tour now state the narrowed premise and its evidence |

Step 2.2 is a test, not a proof, but it covers std, rustls and the OS, which
source guards cannot reach. Together with 2.1 it leaves a premise small
enough for a reviewer to accept or reject.

## Phase 3: finish the read claim and prepare review

| Step | Deliverable | Status |
| --- | --- | --- |
| 3.1 | Extract the grant-window check in `AccountSession::start` (`EMISSION-RUST-01`) | **Done 2026-10-24.** `credential_use::grant_window`, `grant_window_spec` |
| 3.2 | Make renounce end the grant through the state the request path checks (`CONTROL-NATIVE-01`) | **Done 2026-10-24.** The extracted `control` marks the grant inactive itself; `renounced_grant_refuses_every_use` |
| 3.3 | Fold `GuestFrame::from_answer`'s type mapping into extracted code (`NATIVE-GLUE-01`) | **Done 2026-10-24 (assessment).** Nothing left to fold: the error conversion is the identity (now written as such), and the reply capture is serde-to-wire, which belongs to `RUST-JSON-01` |
| 3.4 | Comparative axiom audit, run once at the maintainer's request, against a recorded baseline | Open |
| 3.5 | NR-5 review package: claim matrix, proof tour and assumption ledger reviewed together by someone other than the author | Open |

## Phase 4: a read-only release profile (OUT-5, reads only)

A release claims reads only.

| Step | Deliverable | Status |
| --- | --- | --- |
| 4.1 | Versioned host/guest protocol | **Done 2026-10-24.** [protocol-v1.md](../protocol-v1.md): transport, frames, verbs, replies, the 17 error codes, versioning and retry rules |
| 4.2 | A build that can only run the proved profile | **Done 2026-10-24.** Cargo feature `read-only`: the bridge refuses any configuration but `manifest-https-v1` with `writes = deny`, no legacy forwarding and no coordinator (`profile::read_only`, tested); the offline flow passes with it |
| 4.3 | Build, deploy, operate and recover instructions | **Done 2026-10-24.** [release-read-only.md](../release-read-only.md) |
| 4.4 | Tamper-evident native audit log | Open. The native audit file is synced JSON lines without the Python reference's hash chain |
| 4.5 | AIVM adapter as an optional extra (`aivm[secrets]`) | Open, decided after review (repository boundary) |
| 4.6 | Independent security review of the read-only profile | Needs a reviewer other than the author |

## Phase 5: writes (OUT-4)

One narrowly scoped write, first against the synthetic provider and then
(opt-in) against a real one. Prove that an uncertain send is never retried
automatically, carry `outcome_unknown` across sessions, and record
Python/Rust parity for each write operation. Budgets stay unbounded in native
until this phase decides otherwise.

## Phase 6: proxy profiles (OUT-6)

Prove HP-6: an accepted constrained request is the host encoding of exactly
one named operation. Then compose it with the read theorems. **Done
2026-10-24:** `translate_round_trip` plus `translate_unique` (single-segment
path values; the condition is necessary). The translator runs in the guest,
so its output is an ordinary guest request and the read theorems apply to it
unchanged. Substitution stays
the weakest profile and never claims authority confinement.

## Deferred by decision

- `RUST-JSON-01`: verified JSON parsing. Read confinement already holds for
  every parsed document, so this would only change which documents two runs
  compare. It is high cost for little benefit.
- Python/Rust parity beyond the contracts listed in the
  [core API inventory](aivm-secrets-python-core-api.json).
- Hardware-backed custody claims (`VTPM-01`), clone and rollback protection
  (`CLONE-01`, `ROLLBACK-01`) and cross-host coordination at scale.

## Working rules

- Every change keeps one useful success and one meaningful denial working.
- Synthetic credentials only. A live provider credential is used only in the
  opt-in live acceptance runs, by the maintainer.
- Lean: compile the touched module. No axiom printing in routine builds.
- Rust changes: run the W0/W3 checkers and the full gate
  (`python dev/verification/system.py --full-tests`) before committing.
- When a step finishes, update its row here and the matching ledger entry.
  Put run logs in `dev/validation/`, not in this file.
- AIVM stays independent: no new mandatory dependency, import or setup step.
