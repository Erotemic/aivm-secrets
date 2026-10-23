# Contributor instructions

`aivm-secrets` is an experimental, unaudited, independently packaged credential
broker and identity project. **The end goal** is a host-owned, proof-backed
secret-*use* service: an untrusted AIVM agent performs exactly authorized
provider actions without receiving the provider credential. It must provide
useful authorized success, not just denials. Normal AIVM remains independent;
the secrets adapter is explicitly enabled, versioned and process/wire-only.

**Start warm, in this order:**
1. `docs/planning/aivm-secrets-product-roadmap.md` for product OUT-0..OUT-5,
   proof/deployment/write gates, and what success actually requires.
2. `docs/planning/aivm-secrets-active-work.md` for the **sole current task
   priority/acceptance queue** and latest known verification boundary.
3. The relevant technical scope, especially
   `docs/planning/aivm-secrets-native-read-assurance-roadmap.md` (NR-0..NR-5),
   `docs/planning/aivm-secrets-conditional-confinement.md` and assumptions.
4. The actual source tree: inspect `git status --short`, `git rev-parse HEAD`,
   latest commit and applicable reports; do not assume an overlay is committed
   or overwrite user-confirmed Lean build success. In this project, moving on
   to the next increment normally means the prior Lean change compiled; the
   maintainer supplies compiler diagnostics when there is a failure.

**OUT-2 integration evidence (2026-10-21):** the maintainer ran both
native real-KVM acceptance modes on `aivm-2404`: the positive three-GET
baseline (`b21e212`) and the opt-in adversarial extension (four synthetic
GETs; foreign/mismatched/tampered identities, out-of-scope read, live host TCP
canary, mount metadata, disconnected/reconnected socket and revocation). The
adversarial real-VM run is user-confirmed, **not** a general filesystem,
network or whole-service secrecy proof. See `docs/aivm-vm-native-acceptance.md`.

**OUT-3 live GitHub read-only evidence (2026-10-21):** the maintainer ran
`dev/aivm_github_live_acceptance.py` after correcting the `invoke` denial-frame
assertion: 55 focused tests passed and real KVM/GitHub `summary.json` reported
`ok: true`, three bounded authenticated GitHub reads, denied out-of-scope
repository and write, and `revocation_fenced: true` with identity denial
`invalid_capability`. This accepts the **scoped live read-only integration
witness**, not exhaustive provider-side effects, native implementation-to-I/O
proof, whole-service secrecy, or approval for unattended AIVM agent use. The
host-only GitHub credential must never enter the guest, Git or ordinary CI.
Read `docs/aivm-github-live-readonly-acceptance.md` before optional live runs.

**Formalization-first overnight work:** when the operator assigns an extended
proof campaign, follow `docs/planning/aivm-secrets-overnight-formalization.md`
and the concise `dev/agent_prompts/overnight-native-read-formalization.md`.
Strengthen actual source-to-trace and guest-observation correspondence in
NR-2/3/4; update `docs/assurance/native-read-proof-tour.md` to explain exactly
what the theorem proves and what remains trusted. Producing many standalone
lemmas or new unchecked proof assumptions is not completion. The maintainer
requires independently reviewable formal evidence and understood deployment
assumptions before trusting unattended credential-bearing AIVM use. An agent
cannot self-certify NR-5 or OUT-5, enable the live token, or deploy AIVM.

**Anti-drift:** the read-only NR proof is one product gate, not the product.
Move NR-2/3 toward concrete native primitive-to-event refinement instead of
creating new trace surrogates, inventory-only milestones or recurring proof
publicity. Real VM guest isolation (W8), opt-in provider compatibility (W7),
and scoped authorized-write assurance are separately necessary for broader
product claims and can progress in parallel. Never imply that a source guard,
compiling model or same-UID offline demo establishes whole-service credential
secrecy, VM isolation or native writes. Keep accepted NR-0/NR-1 initial work
accepted unless new evidence changes their stated scope; read dated progress
history as history, not the next assignment.

Read `docs/extraction.md` and
`docs/planning/aivm-secrets-repository-boundary.md` before changing boundaries.
W0 now has the
[conditional-confinement scope](docs/planning/aivm-secrets-conditional-confinement.md)
and [sink inventory](docs/planning/aivm-secrets-w0-boundaries.json); check
references with `python dev/verification/w0_contract.py check`. The W0
inventory is hand-assembled and **not** exhaustive I/O reachability evidence.
Older P/M/G milestone documents are detailed design/history, not alternative
task assignments. W1 has a standalone broker/guest/TLS workflow in
`docs/standalone-github-workflow.md` and
`tests/test_secrets_w1_github_workflow.py`. W2 adds native Rust
`tests/test_rust_w2_github_workflow.py` and `docs/standalone-rust-github-workflow.md`;
**skipped native tests are not W2 completion**. W3's reviewed-effect inventory
and source guard are in `docs/verified-w3-effect-boundary.md` and
`dev/verification/w3_effect_boundary.py`; they do not prove transitive I/O
reachability. The optional [compiler call-site ledger](docs/native-call-ledger.md)
retains unresolved callbacks, dependencies and drop/unwind obligations; it is
also not a mediation gate. The optional [specialized ledger](docs/specialized-call-ledger.md)
checks concrete compiled controller-to-executor paths with bounded capture;
it establishes neither dominance nor whole-service I/O refinement. Run both
W0/W3 checkers after Rust boundary changes. W4 has a source-linked trace model at `proofs/GarrettConfinement.lean`,
reported to compile on the maintainer's pinned Lean toolchain; it is not a
proof of native I/O correspondence. W5 extends that model with explicit
status/reflection/metadata declassification and an adaptive two-run theorem
candidate in `proofs/GarrettNoninterference.lean`. Run
`python dev/verification/w5_noninterference.py prove` for quick, focused
Lean compilation; run the separate `check` action for review provenance,
not on every proof edit.
See `docs/verified-w5-information-flow.md`. W6 now has a source-reviewed
provider request byte encoder, HTTP parser hardening and a native trace/test
oracle in `docs/verified-w6-adapter-correspondence.md`. Run
`python dev/verification/w6_adapter.py check` for the reviewed inventory;
the native Rust unit/process gates must still pass. W6 does **not** prove a
whole-service implementation-to-trace correspondence, mediation or secrecy.
The [authentication-line refinement](docs/verified-http-auth.md) extracts the
actual native validator/appender for both provider writers. It proves exact
bytes and rejection of header splitting under its stated buffer bound; it does
not discharge destination selection, full request formatting or complete I/O
mediation. Use focused compilation of `GarrettHttpAuth.lean` during development.
The [request-line refinement](docs/verified-http-request.md) checks the actual
method/target validator and exact appender used by both writers. It prevents
framing injection within that segment; full request/destination/I/O refinement
remains open. Use focused `GarrettHttpRequest.lean` compilation during iteration.
The [complete request encoder](docs/verified-http-wire.md) extends these leaves
through Host, standard/custom headers, decimal content length and body bytes.
Use the five focused `GarrettHttpWire*.lean` modules during development. Its
byte/admission contracts retain explicit buffer bounds; route conversion, JSON,
TLS, parsers and complete native I/O correspondence remain separate obligations.
The [newline framing contract](docs/verified-line-framing.md) checks the actual
bounded terminal-newline/observed-buffer validator shared by the native client
and bridge. Missing/trailing reply bytes stay post-send uncertainty. Use focused
`GarrettLineFrame.lean` compilation; JSON/TLS/read-segmentation and whole-service
mediation remain separate obligations.
The optional [native coordinator authority](docs/native-coordinator-authority.md)
uses the existing mTLS/SQLite protocol and Python schema. Its extracted
exhaustive typed action/role authorization and terminal decision/history proofs are separate from SQL,
HTTP, commit/reply and durability refinement. Build it only with the explicit
`coordinator-server` feature; no ordinary AIVM or broker requirement is added.
Focus on a useful standalone broker workflow and conditional, implementation-linked credential
confinement; do not advertise formal VM isolation or whole-service secrecy.


### Lean proof development and diagnostic output

- **Compilation, not an axiom-print inventory, is the routine proof-development
  check.** Keep `lake build <module>` and focused Lean commands quiet on
  success so genuine elaboration/type errors are easy to find. Do not add
  `#print axioms`, bulk `#check`/`#print`, or per-theorem axiom reporting to
  proof modules, default Lake targets, automatic `prove` commands, or CI.
- Do not repeatedly scan for `sorry` or `admit`, or advertise their absence as
  a meaningful result. Handle actual compiler warnings and errors when they
  occur. Do not manufacture a new proof-obligation gate merely to check that
  contributors wrote ordinary Lean proofs.
- Transitive axiom dependency review is a **separate, explicitly requested,
  end-of-formalization audit**. Compare named theorem dependencies against a
  previously reviewed baseline/allowed set, report **differences only**, and
  keep raw `#print axioms` output captured rather than flooding stdout. The
  opt-in `Check` and `GarrettCheck` modules are audit inputs, **never default
  compilation targets**. An audit is not a prerequisite for every edit.

- Python's normative core (including new durable coordinator decisions,
  same-session OAuth credential leases, and keyed write retries) is catalogued
  in `docs/planning/aivm-secrets-python-core-api.json`, with explanatory
  boundaries in `docs/garrett-python-core-parity.md`. Classify any new Python
  module as core/non-core, and test the exact contract before declaring Rust
  parity. CLI/alias/UI spelling is non-core; its effects and error semantics
  must obey the core. Current Rust parity is **not** complete for these new
  coordination/idempotency contracts.
- The Python and optional Rust coordinators are an opt-in, single durable SQLite writer reached
  over mTLS, not distributed consensus, replicated credential custody, or an
  anti-rollback ledger. Never turn an unavailable coordinator into a cached
  authorization. All coordinated writes require a durable key and one
  reservation before egress; a retry after uncertainty is never automatic.
- Keep the two in-place renewal flows separate: OAuth access-token refresh
  updates the current lease in a running broker; bound certificate renewal
  replaces the guest cert/JWT under CAS but keeps the broker and bridge live.
  Neither silently reverses terminal global revocation.
- Keep runtime dependencies in root `pyproject.toml`. Do not import or depend
  on AIVM internals, libvirt, or a VM manager to install, import, or test this
  package. Existing AIVM adapters and VM integration tests remain in AIVM.
- Keep authorization, credential custody, provider effects, audit, identity,
  and OAuth decisions inside this project. Preserve versioned process/wire
  interfaces and fail closed; never silently broaden credentials or fall back
  to a weaker transport or identity mode.
- Do not redesign authorization, migrate stored state, or change protocol
  versions as an incidental part of extraction. Changes to security boundaries
  need focused adversarial tests and maintainer security review.
- Local broker use does not require TPM, another VM, OAuth, or a CA. Keep
  optional identity research separate. Do not claim a project-wide security
  audit, whole-service formal verification, production approval, or unproved
  backend parity; name the exact scope and assumptions of checked Rust/Lean
  theorems.
- Keep command logging reproducible and redact secrets. Preserve all existing
  authorship and co-author trailers; `dev/port/` records source provenance.
- Prefer clear, focused changes and intent-level comments. Use `textwrap` for
  multiline strings and explicit context-manager classes instead of
  `contextlib.contextmanager`.
- Run `python -m pytest -q` and `python -m build` after installing `.[tests]`.
  Tests must use synthetic credentials, not live provider accounts.
- Append a journal entry in `dev/journals/<agent_name>.md` with a local
  `## YYYY-MM-DD HH:MM:SS -ZZZZ` heading. Record decisions, reflections,
  uncertainties, tradeoffs, risks, and confidence; do not edit older sessions.
- Every agent-authored commit needs a `Co-authored-by:` trailer identifying
  its actual model and, when known, weights/config variant. State when the
  exact variant is unavailable.

<!-- BEGIN llm_resource_tally v0.3.0 (managed block — regenerated by `install`; edits below will be overwritten) -->
## LLM resource accounting
A git post-commit hook — and Claude Code hooks when wired — records the measured token and model
usage this repository costs. It is automatic bookkeeping and is not part of whatever task you were
given.

- Rows and mutable rollups are written under `.llm_resource_tally/local/`, which is gitignored.
  Recording therefore never modifies a tracked file and never blocks a commit, merge, rebase, or
  stash.
- Never hand-edit, hand-count, revert, or clean up ledger rows, and never let accounting block the
  repository work you were asked to do. Recording is best-effort by design.
- Treat totals as coverage of observed, allocated work rather than proof of complete history.
  Cross-repo/submodule duplicate guards are local to this user and machine, and
  `python3 .llm_resource_tally/tool doctor` can identify common gaps but cannot prove historical
  completeness.
- **Publish before you hand off substantial work.** Run
  `python3 .llm_resource_tally/tool publish`: it snapshots local rows onto the append-only ledger
  at `.llm_resource_tally/ledger/` and refreshes lifetime totals at
  `.llm_resource_tally/lifetime-totals.json`. Stage and commit what it writes in whichever
  repository owns those paths, preferably as its own commit so accounting stays out of unrelated
  diffs. This is routine — nobody should have to remember to ask you for it, and unpublished rows
  exist only on this machine.
- If accounting itself looks unhealthy, run `python3 .llm_resource_tally/tool doctor` — it checks
  hook wiring, backends, transcript retention, and ledger health, and names what to fix. Otherwise
  continue the repository task normally.
- After a fresh clone, run `python3 .llm_resource_tally/tool install` once to arm git-local hooks.
  It is offline and idempotent, and it reads the committed `.llm_resource_tally/settings.json`
  policy.
<!-- END llm_resource_tally -->

## Long unattended runs: the goal guard

`scripts/goal_guard.py` is a deterministic Stop hook (wired in
`.claude/settings.json`). An armed goal blocks a session's Stop and restates
the goal; only a clock (`deadline_utc`, `max_run_hours`), the stalled-commit
fuse or a human ends a run. It runs no commands and no model judges
completion, so a status report never releases it. Details and rules:
`docs/tools/goal-guard.md`; a ready template is
`dev/goal_examples/docs-planning-24h.json`.

```bash
python3 scripts/goal_guard.py --status
python3 scripts/goal_guard.py --arm goal.json      # the maintainer arms runs
python3 scripts/goal_guard.py --extend 48h
python3 scripts/goal_guard.py --pause "maintainer asked me to finish X and wait"
```

Use `--pause`/`--hold` only when the maintainer asks. Never hand-edit
`.goal/active.json` (it is gitignored). Commit real progress: a run that stops
moving HEAD trips the stall fuse. Guard tests are outside the default suite:
`python -m pytest -q scripts/tests`.
