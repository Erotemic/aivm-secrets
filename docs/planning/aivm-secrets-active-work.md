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
| 3.4 | Comparative axiom audit, run once at the maintainer's request, against a recorded baseline | **Done 2026-10-24.** [axiom-audit.md](../assurance/axiom-audit.md): 1,444 theorems (rerun after the history models) rest only on Lean's three standard axioms; one `bv_decide` proof that trusted the native evaluator was replaced with a kernel proof. `dev/verification/axiom_audit.py run` compares against the recorded baseline |
| 3.5 | NR-5 review package: claim matrix, proof tour and assumption ledger reviewed together by someone other than the author | Open |

## Phase 4: a read-only release profile (OUT-5, reads only)

A release claims reads only.

| Step | Deliverable | Status |
| --- | --- | --- |
| 4.1 | Versioned host/guest protocol | **Done 2026-10-24.** [protocol-v1.md](../protocol-v1.md): transport, frames, verbs, replies, the 17 error codes, versioning and retry rules |
| 4.2 | A build that can only run the proved profile | **Done 2026-10-24.** The `garrett-bridge-read-only` binary refuses any configuration but `manifest-https-v1` with `writes = deny`, no legacy forwarding and no coordinator (`profile::read_only`, tested); the offline flow passes with it |
| 4.3 | Build, deploy, operate and recover instructions | **Done 2026-10-24.** [release-read-only.md](../release-read-only.md) |
| 4.4 | Tamper-evident native audit log | **Done 2026-10-24** (agent decision; revisit freely). A `.chain` sidecar beside each native audit file holds one SHA-256 chain line per record, synced after the record and before the action goes ahead; a chain failure stops the action like a record failure. The record file and the proved record shapes are unchanged. `audit-verify --native` checks it; a session refuses to start on a broken chain. Tests: `tests/test_rust_audit_chain.py`. Anchoring the head outside the host is still the operator's job |
| 4.5 | AIVM adapter as an optional extra (`aivm[secrets]`) | Open, decided after review (repository boundary) |
| 4.6 | Independent security review of the read-only profile | Needs a reviewer other than the author |

## Phase 5: writes (OUT-4)

One narrowly scoped write, first against the synthetic provider and then
(opt-in) against a real one. **Synthetic, through a real VM: done
2026-10-24** (`--write`). One exactly approved comment is held, approved by
the host, sent once and single use. Already proved: the write gate, the
approval store, that a sent write which fails is `outcome_unknown` and never
retried, and that keyed writes reserve before and finish after the exchange
(see the [proof tour](../assurance/native-read-proof-tour.md#out-4-first-increment-the-exact-write-gate-2026-10-23)).
Still open: the live-repository run (maintainer), and remembering an
uncertain write across sessions without a coordinator. Prove that an uncertain send is never retried
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

## Phase 7: Garrett's stateless architecture (`garrett-stateless-v1`)

A separate profile beside the stateful AIVM profile: standalone Python and
Rust libraries, a stateless mTLS proxy, an OAuth broker and Lean proofs of the
extracted Rust decisions. **Implemented 2026-10-26.** Status, evidence and the
remaining external validations (live provider, hardware TPM, independent
review, release decision) are in
[aivm-secrets-garrett-stateless.md](aivm-secrets-garrett-stateless.md).

**Composable isolation (2026-10-27).** The proxy's isolation is now composed
from separately verified extracted components, with one composition theorem
(`composed_egress`) instantiated for Garrett's unrestricted proxy and a
constrained read-only proxy, and acquisition kept outside the core. Status and
the review items are in
[aivm-secrets-garrett-composition.md](aivm-secrets-garrett-composition.md).
Next, in order:

1. Maintainer review of the re-pinned NR-0, read-path, W3, W4 and W5 hashes
   (`python dev/verification/generated_scope.py diff e9aa9fa` shows what they
   cover; no agent commit approves them).
2. Independent review of the `Isolated` statement and `STATELESS-OPS-01`.
3. Provider-specific read-only resource catalogues (narrows `STATELESS-OPS-01`).
4. Mailbox-free OAuth acquisition, and further acquisition adapters: later,
   separate increments.

## Everything else the planning documents list

A sweep of every document in this directory on 2026-10-24 found the items
below. Each one is either done, part of a phase above, waiting on a decision
or on something only the maintainer can provide, or deferred by decision.
Status changes are recorded here, not in the older documents.

| Item | Source | Status |
| --- | --- | --- |
| `ca_not_after` in `identity status` | operations policy | **Done 2026-10-24**, both authorities |
| `identity verify` | issuer API | **Done 2026-10-24** (Python reference) |
| `identity prune-keys --superseded` | issuer API, rollback policy | **Done 2026-10-24** (Python reference; locked, audited) |
| `rotate-issuer` skips names whose files exist | rollback policy | **Done 2026-10-24** (Python now matches native) |
| AIVM: operator-only confirmation for `enroll`; registry writes user-owned | issuer API | **Done 2026-10-24** in AIVM (`CommandManager.operator_verb`) |
| AIVM: `identity_enroll --replace` passes the CAS | certificate lifecycle | **Done 2026-10-24** in AIVM |
| Read-only runtime profile gate | NR-0 evidence | **Done 2026-10-24** (`garrett-bridge-read-only`) |
| W0 obligation statuses, CORE-12 notes, roadmap rows | several | **Done 2026-10-24** |
| Clamp new certificates to the CA's expiry | operations policy | **Done 2026-10-24** (agent decision: one-day minimum). Both authorities; the native window is the extracted `authorize_client` (`PlanBound`, `near_ca_expiry_is_clamped`, `less_than_a_day_refused`) |
| `aivm vm identity_renew --all`, session-start expiry warning | operations policy | **Done 2026-10-24** in AIVM (`dev/0.6.2`, unpushed): both extend existing commands. Tested against the in-tree copy and the real package (76 pass); `--all` tried on the local VM store |
| AIVM prompts to revoke the old enrollment on VM rename or move | managed-VM design | **Done 2026-10-24** in AIVM (`a1fc350`, unpushed): `vm delete`, `vm rename` and `vm access remove`/`disable` take `--identity_root` and then run a guarded `revoke-if-current` with its own confirmation before the operation; a decline or failure stops it, `--keep_identity` skips it. Opt-in, so AIVM without aivm-secrets is unchanged. Access removal revokes only the caller's own enrollment |
| Authenticated upgrade of the forced bootstrap helper on existing guests | managed-VM design | **Done 2026-10-24** in AIVM: `aivm vm update` reinstalls `aivm-guestctl` over the pinned host key; tried on the local VM |
| Issuer authenticates the broker session's VM against the enrolled subject (`IDENT-ENROLL-04`) | P4a enrollment | **Decided 2026-10-24** (agent decision; revisit freely): it stays an operator premise in the ledger. The issuer is never told VM facts, which keeps the rollback policy's boundary. What the premise covers is narrowed by AIVM: a bound session derives the subject from the managed VM record and starts the broker with that VM's certificate, so a miswired broker needs the operator to point it at another VM's identity root by hand |
| Real-libvirt identity lifecycle tests: shutdown, restore, clone, stale enrollment, expired CA, miswired broker | P4a enrollment, assurance profiles | **Done 2026-10-24** for shutdown, guest restore, stale (revoked) enrollment, missing guest `openssl` and key rotation (`dev/aivm_identity_lifecycle_acceptance.py`, 13 checks on the local VM). Clone is `CLONE-01` (deferred). Expired CA needs a CA with a short lifetime, which `init` does not offer; its decisions are covered off-VM instead: the extracted window (`near_ca_expiry_is_clamped`, `less_than_a_day_refused`) and AIVM's `identity_renew --all` CA tests against a real authority. Miswired broker needs a bound session, which AIVM only starts interactively |
| Tamper-evident native audit log | Phase 4.4 | **Done 2026-10-24** (agent decision): a `.chain` sidecar, so the record file and the proved record shapes stay unchanged. See 4.4 |
| Native write campaign (OUT-4): approvals, uncertain outcomes, budgets | Phase 5, kernel spec, formal assurance | Phase 5 |
| Idempotency keys declared in the manifest | operations policy, kernel spec | Phase 5 |
| Retire legacy forwarding to the Python broker (`RUST-LEGACY-01`) | assumption roadmap | Kept while a deployment uses the Python broker; the read-only bridge already refuses it |
| Coordinator client transport phases (`COORD-RUST-01`) | assumption roadmap | **Assessed 2026-10-24:** member and operator reply acceptance are extracted and proved. What stays native is canonicalizing the operator's member list (sort, de-duplicate, 1 to 32 hex names), the HTTP framing of the request, and the transport. Extracting the list check would need a proved sort; it changes no authorization decision, which the coordinator makes |
| OAuth service-history theorem; OAuth login I/O refinement | Garrett verification | **Partly done 2026-10-24:** for each emitted request, `admitted_stamp_had_current_lease` shows the control and credential-lease checks passed at the stamp's own time with a current identity; for OAuth sessions that lease check is the extracted `require_current_lease` (`current_lease_contract`: revoked, re-enrolled or mid-refresh sessions cannot dispatch). **History model done 2026-10-24** ([GarrettServiceHistory](../../proofs/GarrettServiceHistory.lean)): every emitted request had a current identity and lease at its step, revoked or superseded epochs never emit again, and an in-doubt refresh blocks until settled, across crashes, concurrent refresh and uncertain publication. The model's steps rest on stated adapter postconditions (atomic writes under the vault lock). **Login history done 2026-10-24** ([GarrettLoginHistory](../../proofs/GarrettLoginHistory.lean)): at most one code exchange per login, each after a bound callback inside the window, install only from that exchange, nothing after a crash. Open, as for every profile: refinement of the listener, TLS and storage adapters themselves |
| Models for the account-status and OAuth-startup profiles (W4/W5 `OTHER-PROFILES`) | W4/W5 scopes | **Done 2026-10-24 as the scope asks: separate results per profile**, mapped in [verified-w4-core-trace.md](../verified-w4-core-trace.md#other-profiles-the-separate-results-2026-10-24). Account status: `perform_contract`, `perform_projection_noninterference`. OAuth startup and refresh: `GarrettLogin`, `GarrettOAuth`, `GarrettServiceHistory`. Administration: `GarrettAuthority`, `GarrettTrust`, `GarrettEnrollment`. Session lifecycle: `GarrettControl`, `GarrettServiceHistory`. Legacy forwarding has no Lean result; the read-only bridge refuses it (`RUST-LEGACY-01`). I/O refinement stays open for every profile |
| Budget and scope primitives (M3); attenuation and delegation proofs (`AUTH-01`, `ATTEN-01`) | kernel spec, modular proofs, formal assurance | **Assessed 2026-10-24:** `AUTH-01` is proved for the native broker (`GarrettManifest`). Delegation and budgets exist only in the Python reference; the native broker refuses `delegate` and has unbounded budgets by decision, so `ATTEN-01`, `BUDGET-01` and the M3 refactor stay with the Python reference until those features are ported (Phase 5 decides budgets) |
| Automatic upstream token revocation (RFC 7009) | OAuth implementation | **Done 2026-10-24** (agent decision): optional `revocation_url` on the token origin; `oauth-revoke` deactivates locally first, then revokes upstream and reports `upstream`. Both authorities, tested against a real local TLS endpoint |
| GraphQL cursor following; `gh pr checks` commit statuses; per-command `--json` audit | 2026-10 remediation | Commit statuses **done 2026-10-24** (`pr.statuses`, `gh pr statuses` in both clients). Cursor following is **deferred to manifest schema 3** (agent decision): it needs a parameter kind that carries a cursor from one reply into the next request, which schema 2 freezes out. Today a query that would need it is refused rather than returned incomplete. The `--json` audit is **done for `pr view`** against `gh` 2.45 (`dev/gh_json_audit.py`, `tests/test_gh_json_audit.py`); `pr checks` audited against `gh` 2.63.2 the same day: the native client now accepts the stock `state` and `link` |
| Manifest schema freeze and introspection; signed manifests; least-privilege resolvers | agnostic integrations | Freeze **done 2026-10-24** (agent decision): [manifest-schema-2.md](../manifest-schema-2.md) fixes every key set and the digest and versioning rules. Signed manifests and a third-party adapter ecosystem are P5, long-term. Resolver isolation is `RES-01`, Python reference only |
| `trusted-host-exec` profile; declarative plugin grammar; verified `gh` subset | credential-free tools | **Decided 2026-10-24** (agent decisions, [section 8](aivm-secrets-credential-free-tools-and-policy-plugins.md#8-open-design-decisions)): the proxy profiles are the transport for stock tools, rules name typed operations, and output follows the disclosure contracts. **No host executor**: `trusted-host-exec` is not built. The verified `gh` subset is the native client alias. Repository-scoped provider tokens need a live provider |
| Proxy hard cases: server-sent events, cross-host `Link` pagination | HTTPS proxy profiles | **Deferred by decision** (agent decision): both fall outside the bounded design. A proxy response is read whole within a size and time bound, and each profile has one pinned origin. Both are refused today, never half-served |
| Separate CI with a pinned cross-project compatibility workflow | repository boundary | **Done 2026-10-24:** `.github/workflows/aivm-compat.yml` runs AIVM's adapter tests at the commit pinned in `dev/compat/aivm.json` against this package (`dev/aivm_compat.py`). It found that AIVM's own suite tests AIVM's stale in-tree copy of `aivm_secrets`; removing that copy is the recorded cutover, a maintainer decision |
| VS Code launcher secrets mode | validation | **Needs maintainer** (a new AIVM secrets surface, which AIVM's rules forbid) |
| Optional `aivm[secrets]` extra | repository boundary | After review |
| Rollback journal, `accept-restore`, anchors A and B, clone detection | rollback and clone policy | **Deferred by decision** |
| Host TPM counter or remote witness anchors (C, D); vTPM custody (`VTPM-01`) | rollback policy, vTPM policy | Deferred; needs hardware or a second host |
| Multi-host coordinator deployment, anti-rollback ledger | core API inventory | Needs several hosts |
| Verified JSON parsing (`RUST-JSON-01`), broad CLI parity | assumption roadmap | **Deferred by decision** |
| Independent reviews (NR-5, OUT-5, `NATIVE-SINK-01` contract), maintainer sign-off on OUT-2 and the W0 release rules | several | Needs a reviewer other than the author |
| Live-provider runs (GitHub GraphQL, other providers, `gh pr diff` through the gateway) | several | Needs a live credential; the maintainer runs them |

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
