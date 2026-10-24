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
| 1.1 | Create `aivm-2404` on this host with `aivm` (no secrets adapter) | `aivm status` is green; normal AIVM use needs nothing from this repo |
| 1.2 | Rerun `dev/aivm_vm_acceptance.py`, baseline and `--adversarial` | Includes the three probes never run in a VM: re-enrollment, alias-aware mount inventory, host canary search |
| 1.3 | Run `dev/aivm_proxy_acceptance.py` (substitution) and `dev/aivm_constrained_acceptance.py` (guest-side translator) | Both pass. The substitution run makes no authority-confinement claim |
| 1.4 | Check the AIVM no-public-egress firewall mode (HP-7) | The guest reaches the bridge and the proxy but not a public address |
| 1.5 | Write a simulated agent: a guest program that tries every attack listed in the [claim matrix](../assurance/claim-evidence-matrix.md) and also does one useful read | Repeatable script with a JSON summary. Its findings become tests |

Record each run in `dev/validation/` with the checkout hash, VM image and
summary. These runs are evidence for OUT-2 and OUT-6, not a proof of
isolation. The maintainer still signs off on OUT-2.

## Phase 2: close the native sink premise

This is the main proof gap (`NATIVE-SINK-01`, `ExactNativeSinkCoverage`).

| Step | Deliverable | Done when |
| --- | --- | --- |
| 2.1 | Make the credential's reach a compile-time fact. The credential type implements no `Debug`, `Display`, `Clone` or `Serialize`, and only custody and the extracted encoder can read its bytes. Pin this with `static_assertions` (`assert_not_impl_any!`) and module privacy, not with a new checker | A negative compile check fails if someone adds a trait or a reader |
| 2.2 | Whole-process witness. Run the broker under `strace -f` (`write`, `writev`, `sendto`, `sendmsg`, `pwrite64`) with a synthetic credential, and decrypt the provider TLS stream with rustls `KeyLogFile` | In a full read, a denied read, a revocation and an audit failure, the credential bytes (and their base64 forms) appear only inside the authorized provider request |
| 2.3 | Restate `ExactNativeSinkCoverage` as a short contract on the single native writer, using steps 2.1 and 2.2 as its evidence | The ledger entry names one function and one contract, and the proof tour explains it |

Step 2.2 is a test, not a proof, but it covers std, rustls and the OS, which
source guards cannot reach. Together with 2.1 it leaves a premise small
enough for a reviewer to accept or reject.

## Phase 3: finish the read claim and prepare review

| Step | Deliverable |
| --- | --- |
| 3.1 | Extract the grant-window check in `AccountSession::start` (`EMISSION-RUST-01`) next to `nested_lifetime`, with a proof |
| 3.2 | Represent control-path revocation as the same current-admission state the request path checks (`CONTROL-NATIVE-01`) |
| 3.3 | Fold `GuestFrame::from_answer`'s type mapping into the extracted frame code if Aeneas allows it (`NATIVE-GLUE-01`) |
| 3.4 | Comparative axiom audit, run once at the maintainer's request, against a recorded baseline |
| 3.5 | NR-5 review package: claim matrix, proof tour and assumption ledger reviewed together by someone other than the author |

## Phase 4: a read-only release profile (OUT-5, reads only)

Versioned host/guest protocol document, install and deployment instructions
for the native binaries, the AIVM adapter as an optional extra, recovery
steps, and an independent security review of the read-only profile. A release
claims reads only.

## Phase 5: writes (OUT-4)

One narrowly scoped write, first against the synthetic provider and then
(opt-in) against a real one. Prove that an uncertain send is never retried
automatically, carry `outcome_unknown` across sessions, and record
Python/Rust parity for each write operation. Budgets stay unbounded in native
until this phase decides otherwise.

## Phase 6: proxy profiles (OUT-6)

Prove HP-6: an accepted constrained request is the host encoding of exactly
one named operation. Then compose it with the read theorems. Substitution stays
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
