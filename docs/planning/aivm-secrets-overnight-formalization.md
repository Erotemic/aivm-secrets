# Overnight campaign: source-linked native read security formalization

**Operator assignment prepared 2026-10-21. Work plan, NOT proof evidence or permission to deploy an untrusted agent with credentials.** The maintainer accepts the reported Lean compilation and the host, synthetic KVM, adversarial KVM, and live GitHub read-only acceptance runs at their stated scope. Do not relitigate successful prior builds because no success transcript was pasted. The live GitHub OUT-3 run succeeded with 55 focused tests; the actual VM response recorded `revocation_fenced: true`, `unauthorized_repository_denied: true`, `write_denied: true`, and `whole_service_secrecy_proved: false`. Operational acceptance is not the formal claim.

**Objective:** make the *strongest honest, kernel-checked, production-source-linked progress* toward [NR-2/3/4](aivm-secrets-native-read-assurance-roadmap.md), while leaving the operator able to **understand and independently challenge** every security claim. An overnight agent should do proof work, not merely write another roadmap, pile up easy theorems, or rerun already accepted integration tests. [The proof tour](../assurance/native-read-proof-tour.md) is the maintainer-facing explanation to update as proofs advance. The [agent assignment](../../dev/agent_prompts/overnight-native-read-formalization.md) is the concise executable handoff.

## 1. Freeze the intended claim before editing

The *first* theorem profile is **native Rust `manifest-https-v1`, `writes=deny`, one sequential mTLS guest session, host-approved nonwriting operations**, with all reachable `request`, `describe`, `renounce`, denial/error and completion paths included or proved unreachable by that configuration. It is **not** generic arbitrary URL/CLI execution, native writes, shared-broker concurrency, Python backend parity, TPM assurance, or a proof of KVM itself. See [W0](aivm-secrets-conditional-confinement.md), [NR profile](aivm-secrets-native-read-nr0.json), [assumption ledger](aivm-secrets-assumptions.json), and [provider semantics](aivm-secrets-agnostic-integrations.md).

The desired source-connected statement is conditional, approximately:

> For every reachable selected native guest execution, each credential-bearing **provider write attempt** is bound to a current authorized source-issued admission, exact host-selected destination/request bytes, and a preceding acknowledged intent audit. A denied request has no unauthorized credential-bearing effect; permitted response release follows reviewed projection, reflection policy and completion audit. Paired sequential sessions that agree on **explicitly permitted disclosures** have equivalent specified guest-visible observations, even when later requests depend on previous public responses, under named external contracts.

This target is **not yet proved**. Distinguish `auditAttempt`, `auditAcknowledged`, `providerWriteAttempt`, bytes accepted by `std::io::Write`, provider receipt, `completionAuditAcknowledged`, `guestFrameAttempt`, and guest receipt. In particular, `write_all` can partially write before error; an audit acknowledgement does not mean provider receipt or power-loss durability; revocation does not cancel a send already admitted after its final check. If a property needs an external contract, expose that contract *at the boundary* instead of assuming the conclusion.

Two critical anti-vacuity conditions: **(a)** at least one real, authorized read succeeds under the same selected configuration (accepted live/synthetic witnesses are available); **(b)** no input premise says, in different words, “all native effects are already authorized” or “all guest outputs are already safe.” A conditional theorem with that assumption is not the sought implementation proof.

## 2. Existing proofs to *compose*, not replace

| Existing source / proof | Established use | Key missing binding |
| --- | --- | --- |
| `proofs/GarrettDispatchTrace.lean` and extracted `dispatch.dispatch` | Chronological returned-dispatch W4 trace and bound current-admission context | Real request invocation/callback arguments and complete effects |
| `proofs/GarrettNativeWriterEvents.lean` | Returned `Request.submit`/`Channel.submit` high-level writer-callback schedule; one W4 attempt on fresh write even when callback fails | Actual native `std::io::Write` / rustls/OS behavior and call reachability |
| `proofs/GarrettNativeDispatchEvents.lean` — `returned_dispatch_with_writer_segment` | Same `begin_send` gate connects dispatch and writer event segment under explicit premises | Derive `beforeTrace`/`after`, `checkedOrigin`, `fresh`, and `returned` from the **same** real `Session::request` execution, rather than accepting them as arbitrary caller facts |
| `proofs/GarrettReadPaths.lean`, `GarrettReadPrefixes.lean`, `GarrettRequestTrace.lean`, `GarrettCompletion*.lean` | Existing production-source-linked path, prefix, and completion results | Source-to-adapter mapping through provider outcome, complete audit and released frame on all included branches |
| `proofs/GarrettDisclosure.lean`, `GarrettGuestFrame.lean`, `GarrettJsonWire.lean`, `GarrettNoninterference.lean` | Selected disclosure, byte encoding, model-level adaptive relational theorem | Actual guest frames/errors/length/EOF and native `step_preserves` assumptions |

The current project-owned Rust path to inspect first is:

```text
rust/crates/aivm-secrets-garrett/src/tls.rs                    Bridge::answer / frame handling
rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs  Session::request
  -> PreparedDispatch::preflight/final_effect/audit
  -> custody/manifest_session.rs  Executor::exchange_manifest / send_manifest_bytes
  -> rust/crates/aivm-secrets-garrett-core/src/{current_admission,dispatch,request_effects,provider_io}.rs
  -> native audited writer + provider parser + selected reply
rust/crates/aivm-secrets-garrett/src/custody.rs               Audit::write_record / other execution routes
```

Verify exact call sites against the **current checkout**. A test-only `Work` instance is not a substitute for the production `Session::request` factory. Do not edit `proofs/generated/` manually; regenerate through the existing supported Rust/Aeneas extraction workflow if source changes require it, with exact pins and provenance. Do not introduce a second hand-written dispatcher or oracle-provided `providerReached`/`auditOK` to make the theorem look stronger.

## 3. Overnight work order (advance as far as real proofs permit)

### A. Close the current Track A dispatch-to-writer *binding* (NR-2, highest priority)

1. Inspect the actual production `Session::request` invocation and `dispatch.dispatch`/`Channel.submit` data flow, including which values and phases are single-use and source-issued.
2. Identify **one concrete returned execution** where the source creates the checked stamp and the same request reaches `begin_send`; derive (rather than postulate) the gate prefix/suffix and the channel's fresh/returned state. Extend to all returned outcomes as feasible.
3. Strengthen the existing compositional proof or add a small source-extracted adapter lemma. Quantify over an actual returned invocation, not a fabricated list of correct events. Do not weaken `SoundTrace`, remove denial branches, or state the proof as “if all dispatch effects are safe, they are safe.”
4. Prove denial, spent-request, write-failure and flush-failure branches wherever the same source relations admit them. For anything not yet represented (panic, non-return, incomplete dependency callbacks), name the exact unclosed edge and keep the parent milestone open.

**Useful acceptance:** a kernel-checked lemma with fewer *security-bearing adapter assumptions* at the same native boundary, precise source linkage, and a written before/after premise delta. A theorem that merely renames those premises is not progress.

### B. Source audit acknowledgement and attempt ordering (NR-2/3)

Relate the return of native `Audit::write_record` (including error handling and actual file callback result) to the `RequestEffects.audit` acknowledgement consumed by the dispatch. Then connect late current-admission checks to the actual `ProviderWriter::write_all` call. Preserve distinction between callback invocation and bytes accepted, and distinguish audit append/write/flush/sync/crash durability. Include audit-refusal and audited-but-unsent cases, not just successful sends. The `native_read_dispatch_audit_to_writer_callback_chronology` synthetic Rust test is an existing finite **witness**, not the proof itself.

If `std::io::Write`, rustls, OS flush/fsync, DNS, TCP setup, a destructor or dependency callback cannot be extracted, record an **exact narrow external contract**: which call is trusted, inputs/outputs and errors, adversary control, effects allowed, what might leak, which theorem relies on it, and a falsifying test. Never assert that a hand-authored source inventory is a closed transitive call graph.

### C. Complete the native request-to-guest observation path (NR-2/3)

Connect extracted provider parsing/outcomes -> host-selected disclosure/reflection -> completion-audit acknowledgement -> JSON bytes/framing -> `Bridge::answer` and guest TLS output, *including errors and close/EOF*. Cover final-only, checked/preflight-only and two-phase reads, denied/revoked/audit-failed/provider-error branches, and repeated sequential requests. Bind actual serialized fields and fixed public denial codes rather than only showing equality of parsed `PublicReply` structures. Account explicitly for `describe` and `renounce` or prove their scoped reachability does not produce forbidden effects.

### D. Close reachable sinks and adaptive information flow (NR-3 then NR-4)

Review transitive entry points from startup through mTLS request dispatch and privileged sinks: files, sockets, host diagnostics, provider/auth header, guest reply and possible alternate executors. Include dynamic calls, `Drop`, unwind, error and shutdown paths. Reuse existing W3/W6 source guards and specialized call ledger, but do not treat their passing as exhaustiveness. Prove project-owned mappings and isolate external contracts.

Use the existing `GarrettNoninterference.adaptive_noninterference` as a **conditional** building block. Instantiate its actual `step_preserves` requirement for paired native steps, with a named initial-state relation and declassification agreement; include status/reflection, selected metadata, frame lengths, fixed errors and connection closure. If native observations demonstrably differ under a secret while permitted disclosures agree, **report a counterexample and patch only with security review**; do not add a new permissive declassification just to finish a proof. Precisely exclude timing/co-resident side channels if the scope does not support them.

### E. Scope-limited final composition (NR-5 only when prerequisites are ready)

If A–D genuinely close, produce the integrated conditional theorem and claim-to-evidence matrix. An **independent** reviewer must still assess premises, reachability, trusted library/OS/VM contracts and deployment controls. **Do not automatically run or add transitive axiom dumps:** the named, baseline-comparator audit is opt-in at the end of formalization and is not authorized by this overnight assignment.

If a difficult item blocks progress, record the exact unproved statement and concrete counterexample/rust link, then move to the **next highest-value independent sublemma**. Prefer closing an existing premise or an actual previously unhandled branch to inventing new abstractions, freshness checks, proof dashboards or status labels.

## 4. Constraints and verification economics

- **Safety:** no real credential reads, GitHub live tests, AIVM VM modifications, firewall changes, token inspection, generated credential files, opportunistic write enabling, permission relaxation or production security semantic changes. Never import/require AIVM to run the broker. The host already has a private GitHub token; **do not open or use it**. **Crucially, a coding agent running under the operator's host UID may have read access to that token regardless of what this prompt says.** A Git worktree is only source-file separation, not a credential sandbox. Before an unattended run, the operator should revoke/remove the disposable OUT-3 token if no longer needed, or execute the agent under an isolated OS identity/container that cannot read host credential material. Neither a verbal instruction nor an assumed CLI write sandbox replaces that boundary.
- **Source changes:** Lean and local documentation are the default edit surface. A tightly scoped production Rust extraction/refactor is allowed only when essential, with demonstrated behavior preservation and relevant Rust unit/process regression tests; put security-semantics changes in a separate, explicitly review-required proposal rather than silently implementing them.
- **Lean:** use focused `cd proofs && lake exe cache get && lake build <changed-module>`. Quiet success; inspect errors when present. No automatic `#print axioms`/bulk `#check`, routine `sorry`/`admit` inventories, or turning a missing proof into a new axiom, `opaque` shortcut, broad `native_decide` assumption, or reduced theorem strength.
- **Rust/source-linked gates:** run affected focused cargo tests, `python3 dev/verification/w0_contract.py check`, `w3_effect_boundary.py check`, `w6_adapter.py check` **when the boundary changes**. Use `quick_w6_read.py` for related portable checks. Do not run full extraction, full `system.py --proofs --full-tests --call-linkage`, specialized Charon capture or entire test suite for every pure Lean change.
- **Evidence:** pin source and generated artifacts honestly, update hashes only after matching source/proof review and appropriate successful build. Distinguish `not run`, compiler verified, finite native witness and external assumption. Never convert a test or model-only proof into a whole-service claim.
- **Environment / worktree:** the `proofs/lakefile.lean` resolves Aeneas through repository-local `.tools/aeneas/backends/lean`. A fresh Git worktree does not automatically contain that ignored dependency. Prepare its **own** pinned environment with `python3 dev/verification/garrett.py bootstrap` before the unattended agent starts, or otherwise explicitly validate the existing toolchain. Do **not** symlink/copy the main checkout's entire `.tools/` tree: it may contain private transient acceptance workspaces. Likewise, never copy credential files into the worktree.
- **Committing:** one coherent proof/correspondence increment per commit, actual model attribution in `Co-authored-by:` trailer, no unrelated files. Preserve existing commits and user's working changes; do not push, merge, deploy or modify AIVM. Use a separate worktree/branch for unattended work.

## 5. What the maintainer must receive in the morning

Keep a single append-only `dev/journals/<agent_name>.md` and update [the proof tour](../assurance/native-read-proof-tour.md) **as proved facts change**, not as a self-congratulatory diary. End with a concise handoff containing:

1. **Actual commits and checkout:** branch, commit IDs, changed modules, exact proof/source revisions.
2. **Claim delta:** theorem name and signature, *plain-English explanation* of what newly follows, and a table of security-relevant **old vs new assumptions**. Highlight any hypothesis tantamount to the conclusion.
3. **Proof reading guide:** one trace of a permitted read and one rejected request through Rust entry -> Lean relations -> expected observable effect. Give the precise lines/lemmas and explain them without assuming the maintainer trusts the author's paraphrase.
4. **Tests run:** focused Lean/Rust/source gates, outputs on failure, tests not run, exact scope of any synthetic witness. Never mark a failed or not-run gate green.
5. **Remaining unproved edges:** callback/panic/close/external contracts and attack consequences; prioritize the next obligation. A blocked premise stays visible.
6. **Trust recommendation:** `read-only untrusted AIVM deployment: NOT YET REVIEWED/APPROVED` unless an independently reviewed assurance case and named deployment contracts truly close. An agent cannot self-certify NR-5 or OUT-5.

A productive overnight run may end with one significant source-linked theorem and several named blockers. That is better than twenty tautologies or an unreviewed claim that whole-service secrecy is proved.
