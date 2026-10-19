## 2026-10-17 11:01:19 -0400

Reviewed the 2026-10-17 source snapshot (`28e466d`) against the proposed
conditional broker credential-confinement target. The design already records
important assumptions and proof dependencies, but overlapping P/M/G milestones
and stale Rust/repository status statements can send agents toward unrelated
new primitives or TPM work before there is a useful, verified service boundary.

Added a canonical W0-W8 active queue and linked it from `AGENTS.md` and the
main planning documents. The plan prioritizes a standalone real broker/provider
scenario, complete enumeration of guest-reachable sinks, a closed Rust effect
boundary, extracted trace confinement, relational information-flow proofs and
concrete adapter refinement. AIVM is an optional downstream deployment
validation, not a requirement for local formal reasoning. Existing Garrett,
identity, issuance, custody and disclosure work remains preserved.

Main uncertainty: complete reachable-I/O and declassification contracts still
need a source audit; the current Lean results cannot be extended to
whole-service traces merely by composing theorem names. The new environmental
compartment ledger entry is explicitly unestablished by local tests. This
change alters planning and assumption documentation only, not runtime behavior
or actual proof validity. No Rust/Lean toolchain verification was attempted.

Validation for this planning-only edit: 137 structural and installed CLI
checks passed after installing the standalone package in the test environment;
all planning Markdown relative links resolve, the assumption ledger passes its
structure checks, and `git diff --check` is clean. Wheel/sdist build tests were
not reproduced because this environment has no `build` module; the initial
uninstalled-source run had three environment/setup failures, which are not
recorded as product regressions.
## 2026-10-17 11:32:40 -0400

W0 contract baseline for the active conditional credential-confinement plan.
Kept runtime code and existing Lean theorems unchanged. Inventoried native
manifest-https-v1 separately from fixed account-status-v1, legacy Python
forwarding, guest-owned CLI, and operator-only authority. Documented
protected/public values, guest/host/provider/OAuth sinks, serialized error/
length/close observations, excluded timing/side channels, finite adaptive
request strategies, concurrency/linearization and a deliberately restricted
declassification model. The spec does not classify arbitrary accepted result
strings as safe or treat a fixed error enum as blanket declassification.

Added versioned W0 JSON with traceable sources/assumption IDs and a structural
validator plus negative tests; added eight narrowly described Rust/deployment
assumptions to the ledger. Distinct host-selected origin/bytes construction
remains a project proof/refinement obligation, **not** an assumption that
credential confinement holds. Updated active plan, assurance plan and agent
instructions to point to the W0 specification.

Source audit correction: OAuthSource::active is a guest-time lease check, not
a refresh. Native OAuth refresh may occur at host-controlled startup via
session_snapshot; its token endpoint is a separate authorized sink.
Native pagination exposes per_page, possibly_more and optional page, so the
possibly_more bit is an explicit declassification decision. The initial model
includes errors, frame lengths and closure in guest observations but not
wall-clock timing or packet traffic analysis.

Uncertainties: the sinks list was assembled by source inspection rather than
an audited complete transitive call graph, and the schema/release decisions
still require maintainer security approval. W3/W6 must check all concrete
writers (including errors and panics); W4/W5 must prove linked trace and
relational properties. The validator only checks structure and references.
No proof of virtualization, complete service confinement, or Lean
implementation correspondence is claimed by W0.

Validation: `python dev/verification/w0_contract.py check` passed (5 profiles,
10 sinks, 11 release rules, 10 observation classes); 141 W0/structural tests
passed; `git diff --check` passed. A full `python -m pytest -q` run exceeded
180 seconds at about 16% (slow pre-existing integration coverage) and its
first failing test was `test_standalone_wheel_and_sdist`, because the current
environment has no Python `build` module. `python -m build` fails for the same
missing module. No Rust/Lean rebuild attempted because W0 changes neither
Rust implementation nor Lean proof source.

## 2026-10-17 11:54:00 -0400

W1 implementation on top of the `28e466d` source and W0/planning overlays.
Added `tests/secrets_github_scenario.py` as stable synthetic provider data and
policy intent for W2, plus `tests/test_secrets_w1_github_workflow.py` as an
independent multi-process workflow. The test starts the real Python broker,
uses separate installed CLI processes for requests, and records real locally
TLS-protected HTTPS traffic. The policy is the expanded GitHub manifest with
host-selected synthetic credential, pinned loopback address and test CA.

Positive steps cover exact checked PR metadata, `gh` JSON projection, raw
diff and commit-bound checks; assertions include the provider's observed
bearer credential, method, Accept/version headers and precise preflight/final
paths. Denied steps cover a different PR, an operation admitted in policy but
forbidden by the host write gate, unknown API operation, injected URL argument
and the absence of real `gh` fallback. The provider's deliberate literal
token reflection is rejected; a wrong head-repository fact prevents final
execution after an allowed preflight. Host revocation and grant expiry reject
additional requests; audit records are chain-verified and exclude literal
credential/capability, and runtime socket/capability files are removed.

This is local functional integration evidence for the Python broker only.
It does not prove credential isolation from a same-UID client, validate a
real GitHub token/API, prove general declassification or confer Rust parity.
Python's `pr.view` protocol returns the whole checked response, whereas W0's
intended native Rust declassification boundary is stricter; W2 must compare
intended semantics and explicitly document differences. Left production code,
wire versions, and existing W0 proof files unchanged.

Validation: three W1 tests passed twice (final run 26.65 seconds), 506 nearby
Python guest/policy/broker/W0/purity regression tests passed, W0 structural
checker passed. A broad CLI-heavy regression invocation exceeded its timeout
after 19 tests, so it is not counted as passing. No live GitHub, Rust, Lean or
VM test was attempted. Maintainer review of test coverage remains open.

## 2026-10-17 13:32:00 -0400

W2/W3 implementation, using the source snapshot at `28e466d` with the
planning/W0/W1 overlays applied. Implemented a deliberately closed guest-side
Rust `garrett-client gh pr view/diff/checks` translator, with explicit `--repo`,
selected `--json` fields, guest-owned private capability-file input, no `gh`
subprocess/network fallback, and no write aliases. Added a native manifest
fixture reusing W1's synthetic GitHub provider and PR data. The host policy
compiler still independently checks every requested operation, arguments,
checked facts, declared HTTPS route, and host write gate. Native disclosure
selects a smaller set of fields than Python W1; CLI selection cannot expand it.

W3 consolidated native manifest preflight/final credentialed HTTP sends into
one phase-tagged dispatch closure that checks the destination against literal
credential reflection, durably records an audit event, rechecks authorization,
and then performs the provider exchange. Added one authenticated guest-frame
serializer for success/error results. Inventoried provider, guest, audit,
startup, legacy forwarding, OAuth and host-admin sinks with links back to W0.
Added source-change digests and targeted bypass guards; six mutants were
rejected after rebaselining their digests. A separate negative test
rejects a newly added Rust source file. The source guard is neither a sound
transitive I/O analysis nor an implementation-linked confinement theorem.

Validation: W0 and W3 contract checkers passed; ten W3 tests passed; the W2
native-policy fixture passed. Four W2 native runtime cases skipped because the
Rust authority/bridge/client binaries and Rust compiler are unavailable here.
W1 baseline was verified after local editable installation: three subprocess
integration tests passed in 35.54 seconds. Consequently no new Rust code was
compiled/executed in this environment, and W2 runtime acceptance and W3
refactor runtime behavior remain *unverified*. The W4 whole-trace proof and W6
I/O refinement remain open.

Tradeoffs/risks: a three-command read-only surface makes the useful workflow
measurable without prematurely committing to generic `gh` parity. The source
fingerprints intentionally require re-review after any Rust change and may be
noisy during subsequent work. `PreparedDispatch` and `GuestFrame` centralize
selected boundaries, but do not encode independent authorization witnesses or
prove every path to physical I/O. No assumption of VM isolation was discharged.
The actual model is GPT-6; the exact weights/config variant is unavailable.

## 2026-10-17 13:41:15 -0400

Follow-up on user-reported native W2 failures after compiling Rust: all four
process-level tests terminated at `ManifestCase.__enter__` because the bridge
reported `invalid_policy` before announcing readiness. The Python-only fixture
check had passed, but Rust's `manifest/disclosure.rs` applies the lowercase
policy identifier grammar to *public release field names*. The W2 fixture
requests `headRefOid` for native `gh pr view --json`, which that grammar
rejects even though the selected path is explicit and legitimate.

Scoped the fix to output field-name parsing in the Rust disclosure adapter:
accept a bounded ASCII lower-initial alphanumeric/underscore identifier with
internal uppercase letters. Kept input operation/argument/check names and
policy authorization unchanged. Added native unit tests for camelCase
selection, malformed output names, discarded private provider fields and
credential reflection. Updated the W3 source fingerprint and documented the
native-parser-only test requirement.

Uncertainty: the Rust compiler and Garrett binaries are absent in this
container, so neither the new Rust unit tests nor the four native TLS
subprocess workflows could be run here. This is an implementation-level
root-cause inference from the Rust parser, not yet a verified full runtime
repair. W0/W3 structural checks and Python regression tests can be run here.

## 2026-10-17 16:29:00 -0400 — W4 conditional core-trace candidate

- Built `proofs/GarrettConfinement.lean` as a finite effect semantics tied to Aeneas-extracted `manifest::authorize`, `manifest::parameter` and `disclosure::project`. The native W3 I/O interpreter is not extracted, so the model and its pending Lean theorems are intentionally **not** labeled whole-service assurance.
- Explicitly modeled audit acknowledgement, preflight/provider failure, completion audit refusal, and revocation at a fresh final-phase authorization sample. Imported `protocol::perform` contract proofs are separately referenced rather than equated with native manifest dispatch.
- Added source/proof digest inventory, a static guard and a separate `prove` mode to demand Lean kernel compilation and axiom audit; mutation tests exercise guard integrity. Does not modify the recorded Garrett proof manifest or production Rust.
- Toolchain limitation in the working environment: no `cargo`, `lake`, or `lean`, and no access to download the pinned binaries. The candidate's Lean scripts are **not verified to compile**. This risk must be resolved before W4 is marked complete. W5/W6 remain independent obligations; practical value depends on corresponding real native I/O traces.

## 2026-10-17 17:31:00 -0400 — W3/W4 acceptance runner repair

A user run of W4 showed W3's complete-Rust-source scanner traversing Cargo's
`target/` output after native Rust builds, so generated `.rs` files triggered a
false source-inventory drift. Prune `target/` subtrees while keeping fail-closed
review for repository-owned and untracked Rust source; added positive and
negative regression tests. W4's `prove` reached Lake but failed before parsing
any proof because the pinned Aeneas Lean backend had not been installed. Add
actionable preflight diagnostics and explicit `garrett.py bootstrap` instructions.
Do not auto-download dependencies from a proof command. The container lacks
network access and a Lean toolchain: the W4 proof remains uncompiled and unverified.
No source-level security assurance claim was expanded.

## 2026-10-17 - W4 Lean parser and linter repair

The maintainer bootstrapped the pinned Aeneas backend and reached actual W4
Lean elaboration. Existing Garrett proof dependencies built successfully.
The W4 module failed with Lean's constructor-name linter for a local `unit`
variable and parser errors from using reserved `prefix` as a `let` binder.
Downstream proof goals contained implicit `sorryAx`; these are not accepted
by the W4 axiom allowlist. Renamed the local bindings to `resultUnit` and
`phaseEvents`, refreshed the recorded proof digest, and added a regression
test ensuring the axiom audit rejects elaborator-inserted `sorryAx`.
No theorem statements, source-linked guards, or model semantics changed.
W4 remains pending a new pinned Lean kernel run; Python structural tests
do not establish proof validity.

## 2026-10-17 17:53:52 -0400 - W4 orphaned Lean doc-comment repair

The maintainer's post-bootstrap W4 run narrowed the only reported error to
`GarrettConfinement.lean:407`: a Lean documentation comment (`/--`) directly
preceded a `#check` command. `#check` cannot receive documentation comments;
use an ordinary block comment (`/-`) for source-controller evidence notes.
No theorems or effect-model semantics changed. Updated the reviewed proof digest
and added a structural regression test that rejects documentation comments
attached to `#check`, `#print` or `#eval`.

The previous maintainer log showed 19 W4 theorem axiom reports without
`sorryAx`, but Lean exited with a parser error. This correction is still
subject to the pinned Lean kernel gate on the maintainer's machine; Python
structural checks alone do not prove W4. Exact model variant unavailable.

## 2026-10-17 18:06:37 -0400 - W5 modeled adaptive noninterference

- Decision: W4 source-linked two-phase trace compiled on the maintainer's pinned Lean toolchain, but the native manifest adapter refinement remains assigned to W6. Do not expand W4's claim to concrete I/O.
- Added `proofs/GarrettNoninterference.lean`, importing W4 and the extracted Rust recursive-disclosure noninterference proof. The modeled guest observes denied/released messages plus explicit wire metadata; internal audit/provider events are not guest-visible in the model.
- The two-run and adaptive finite-history theorems require matching admission decisions, adapter results, credential-dependent reflection outcome, metadata and recursive schema projection agreement. No premise directly assumes equality of selected guest payloads; the extracted projection lemma proves that equality.
- A direct ignored-leading-field mutation lemma and Boolean positive projection witness constrain the model beyond denial-only behavior. An explicit reflection distinguishing theorem shows that a credential-dependent reject/allow status can leak one bit.
- Added deterministic static contract/axiom-audit checks and optional native Rust synthetic-provider mutations for ignored fields, approved field changes and credential reflection. No production Rust sources were modified.
- Authoring environment: Python structural tests pass; Lean, Aeneas, and Rust runtime binaries are unavailable, so all new kernel/native run claims remain **unverified**. Run W5 `prove` on the maintainer machine and fix any actual elaboration errors before marking accepted.
- Risks: current W5 audit cannot establish transitive socket/HTTP reachability, concrete wire lengths/status/closure, the correctness of reflection classification, or state-transition bisimulation. Those are W6 obligations; reflective-denial equality is an explicit release condition, not a secrecy proof.

## 2026-10-17: W5 proof iteration diagnostics

- Separated fast Lean compilation from provenance checks: `w5_noninterference.py prove` builds only W4's imported proof roots, compiles W4 and W5, and prints diagnostics only on failure. The unrelated GarrettCheck default target and per-theorem axiom dumps no longer run.
- Removed W5 `#print axioms` declarations and their output parser/tests; retain explicit source-level prohibition of `sorry`/`admit`/`axiom` in the optional structural `check`.
- Repaired the reported W5 binder/typeclass errors using a local classical `Decidable` instance for `Gate.accepted`, fully qualified the extracted result constructors, and simplified the two witness proofs.
- Note: the repaired Lean file has not been compiled with the pinned toolchain in this environment.

## 2026-10-17 20:35:00 -0400 - W6 native adapter correspondence pass

- Implemented the *actual* native manifest HTTP byte encoder as a pure,
  zeroizing function used by `Executor::exchange_manifest` before TCP connects.
  Validates credential bytes even if produced by OAuth rather than the file
  credential constructor; rejects CR/LF, reserved and duplicate headers,
  malformed targets, and oversized bodies. The adapter rejects HTTP 206 as a
  partial representation outside the declared manifest response contract.
- Added Rust unit tests of this production encoder and response parser; added
  native bridge/client/TLS provider/audit trace tests and an independent
  mutation-sensitive Python observation oracle. `W6` explicitly includes
  preflight provider sends, checked-fact-only results and denied/error paths.
- Classified ten W0 sinks with source, trusted adapter assumptions and tests;
  added W6 structural/negative guards and refreshed W3 source provenance after
  review. Existing authorization/disclosure theorems are not changed.
- Validation here: W0/W3/W4/W5/W6 checkers and 50 focused Python tests pass;
  native Rust integration tests skipped because compiled Garrett binaries are
  unavailable. Rust unit tests and end-to-end native acceptance remain **open**.
  No claim of formal whole-service I/O refinement or complete reachability.
- Main risks: adapter testing is observational, not a verified bisimulation;
  TLS/crypto, host `sync_all`, dependencies, error/closure metadata, timing,
  provider-controlled declassification semantics and VM isolation remain
  separate assumptions or downstream obligations. Recheck Rust compilation
  and any behavior differences on the pinned nightly before merging.

## 2026-10-17 20:55:00 -0400 - Python operational core, revocation and write retries

Implemented an opt-in cross-host coordination authority for the existing Python
Garrett broker: one locally durable SQLite WAL/FULL ledger and a strict,
authenticated mTLS interface with operator/member certificate fingerprints.
The new principal registry has irreversible tombstones and atomic write
reservation keys shared across hosts and broker restarts. Broker and bound
identity bridge admit new guest calls only after uncached coordinator checks;
coordinated writes require durable keys and fail closed on replay, mismatched
requests, or a missing authority. A per-operation policy opt-in forwards a
host-derived Idempotency-Key header to providers that support it. No provider
request is sent on a duplicate reservation.

A running OAuth-backed broker now resolves the current vault credential inside
a locked lease rather than pinning an obsolete access token at session setup;
refresh preserves the current epoch and capability, while local revocation or
replacement remains final for that broker session. The `renew-bound` operator
workflow performs certificate renewal plus new bound JWT issuance using the
existing broker capability; already-running bridge and broker reread identity
expectations so guest cert/JWT renewal needs no server restart.

Added an exhaustive classification of all current Python modules into core
security behavior and non-core entry points, plus eleven normative core
contracts and conservative, unverified Rust parity statuses. Tests cover
storage restart, TLS host separation, coordinator outage, authenticated
revocation, broker/bridge refusal, concurrent writes, same-key replay,
ambiguous write failure, provider header integrity, and live credential
rollover. Older historical milestones are preserved.

Open: no external anti-rollback witness for SQLite backups, no actual
separate-machine coordinator deployment, no network-fault-tolerant consensus
or upstream credential vault replication, no provider-specific guarantee from
Idempotency-Key, no automatic guest-side cert/JWT swap, incomplete Rust core
parity, and no formal proof of Python runtime safety. Python coordination is
strictly opt-in; a host running without it is outside cross-host confinement.
Tests used synthetic certificates and tokens and localhost transports only.


## 2026-10-19 10:46:53 -0400 - Offline native HTTP/W6 test-oracle hardening

- Scope: security-boundary hardening entirely with synthetic credentials and local TLS, without any external provider account, real secret, VM installation, or TPM. The source snapshot was commit 7120838.
- Python egress now refuses HTTP 206, ambiguous or unsupported 2xx framing, unbounded/mismatched Content-Length, and a response media type incompatible with the host-selected effect. A standards-compliant bodyless 204 works for text but not JSON; forbidden 204 framing is rejected. Compatibility consequence: formerly accepted close-delimited/no-Content-Type replies now fail closed.
- Native Rust manifest parser now also rejects unframed non-204 2xx responses; 204 remains bodyless and refuses forbidden framing fields. Native Rust unit and real-process synthetic TLS regressions are authored, **not built or executed here** because cargo/rustc and the pinned toolchain are absent. No new Lean theorems were authored.
- Improved finite native W6 oracle: all expected provider headers must derive from host policy, raw wire header pairs detect case-insensitive duplicates, typed JSON comparison refuses duplicate keys and bool/integer confusion, audit identifiers and selected guest outputs are independently checked. Raw synthetic HTTPS response fixture exercises the production adapters. Added positive chunked and selected-release witnesses and adversarial mutations. This is a runtime oracle, not W3 reachability completeness or I/O refinement.
- Updated the W3 reviewed Rust source SHA-256 after inspecting the manifest parser's updated match branch and 204 status guard; added a W6 structural guard and recorded the trust/assurance limitations. This review does not establish Rust compilation or full dependency reachability.
- Validation executed: Python structural W0/W3/W6 checkers passed; 135 targeted Python tests passed, including W3 guard mutation tests, egress cases, and the W6 oracle. Python compileall completed. A prior loopback W1 workflow reported three passing tests but pytest process shutdown did not terminate within the outer shell time limit. No network service other than local test TLS endpoints was contacted by those tests.
- Environment limitation: `python -m build` failed because the Python `build` module is not installed, and cargo/rustc/lean are unavailable. Authoritative `python dev/verification/system.py --proofs --full-tests` must be run on a provisioned maintainer machine; full native acceptance is pending.
- Confidence: high in the exercised Python behavior and portable guards, moderate in the source-reviewed Rust edit pending compile/tests, low for any broader confinement, noninterference or runtime isolation claim. No source-level guarantee about unobserved guest I/O is asserted.

## 2026-10-19 11:12:00 -0400

Follow-up to the offline HTTP/W6 overlay after the maintainer's full workflow
gate reported 479 passes and eight identity-bundle failures. Six exercised
`os.memfd_create` on a Python build without that attribute; two used a stale
installed `aivm-secrets` CLI under `python -I`, which ignores the gate's
`PYTHONPATH`. The current source already contained `install-bundle`.

Replaced the Linux memfd assumption with `tempfile.TemporaryFile` and the
existing `/proc/self/fd/N` certificate path. This remains an anonymous
certificate-only snapshot; the JWT and key are never copied. TLS verification,
identity selection, and wire behavior do not change. Temporary-file or loader
failures are closed as `invalid_capability`. A new real TLS test removes
`os.memfd_create`, another injects a temporary-file failure, and the existing
mid-call bundle-replacement and wrong-private-key tests remain covered.

Added an early system-gate probe using the same isolated interpreter (`-I`)
that selected tests use. It rejects an installed package from another source
location with a specific editable-install instruction, before running the
expensive Rust/Lean build. Added positive and adversarial guard tests and a
positive real CLI bundle-install subprocess test. Do not bypass `-I`; reinstall
the current checkout with `uv pip install --python "$(command -v python)" --no-deps -e .` instead.

Validation in a local editable test environment: 9 focused bundle/guard tests,
22 identity/operator/mTLS tests, and 71 HTTPS-egress/W1 synthetic workflow
tests passed (102 distinct passing cases); W0, W3, and W6 structural review
checks passed; `git diff --check` passed. Also reproduced detection of an
isolated interpreter importing the previous checkout. Cargo and Lean were not
available in this environment, so those gates remain for the maintainer.
This is a portability/verification-environment repair, not a new claim about
whole-service credential confinement or VM isolation.

## 2026-10-19 11:53:00 -0400

Follow-up to maintainer full-system run after the Python identity-bundle
compatibility overlay: all required workflows and proof stages completed;
`full-python-native` reported 2,734 passed, six failed, seven skipped. Four
failures reached optional software-TPM tests with `swtpm` present but missing
`tpm2_createprimary`. Fixed the partial prerequisite check by centralizing
all TPM CLI requirements, using PATH resolution, and maintaining explicit
fail (required) versus skip (optional) semantics. Suggested an opt-in, offline
`sudo apt install swtpm tpm2-tools` to get real emulator test coverage.

A synthetic HTTPS fixture advertised `Content-Length: 0` on HTTP 204 while
the hardened production parsers rightly reject this framing. Fixed the
fixture, retained the deliberate malformed-response injection capability,
and added a real loopback-TLS wire regression. Also corrected the installed
CLI independence test: AIVM may be separately installed on a development
machine, so actively reject attempts to import AIVM rather than requiring
its global absence. No Rust/Lean source, protocol, policy, or production code
changed. Full native tests and pinned Lean proofs still require execution on
the maintainer's provisioned environment; no production credential used.

## 2026-10-19 13:41:59 -0400

Follow-up to the maintainer's complete native/full-Python run: 2,750 tests
passed, with one remaining failure in text/204 manifest writes. The full
Rust/Lean gate reached full-python-native with no remaining TPM skips.

Root cause from source review: the native manifest parser's 204 branch used
`read_to_end` to reject extra bytes after the response headers, though
204 messages terminate at the blank line and TLS may not send clean EOF.
Removed that read, preserving forbidden 204 framing rejection and empty-JSON
rejection, so only empty text is projected. The upstream TLS connection is not
reused; any trailing bytes cannot be consumed as another response. Added a
native no-EOF reader regression, an explicit no-release trailing-bytes test,
and a W6 mutation test that refuses reintroduction of extra reads after 204.
Reviewed and updated the W3 exact-source checksum and documented the
remaining unproved protocol/TLS assumptions.

Validation: W0, W3, W6 checks passed; 67 portable W3/W6 and TLS-fixture tests
passed. Cargo, rustc and Lean are unavailable here; native unit/integration
behavior remains to be reproduced by the maintainer, and the full gate must
be rerun. No real provider, hardware TPM, service account or credential used.

## 2026-10-19 15:08:00 -0400

Native manifest read-only W3/W6 slice on b91748b. Chose an audited-effect
handoff instead of a new protocol or broad feature work. Added preflight/write
and read/write mismatch guards, with the existing final current-grant checks
left intact. Added causal provider-arrival audit snapshots and actual guest
frame capture over local mTLS; source/oracle mutant tests. Tradeoff: the audit
receipt does not prove that the code complied at every reachable I/O sink,
that sync_all survives power loss, or that the Lean abstract trace refines
native behavior. Rust/Lean unavailable in the overlay authoring container;
full toolchain validation remains required. No real credentials or services.

## 2026-10-19 19:00:00 -0400

Advanced the offline native manifest read slice without repeated heavy Charon/Lean
work. Added a private `CompletedRelease` constructed after selected projection,
reflection rejection and completion audit; retained conservative write outcome
classification. Added independent selected-data/pagination oracle, exact denial
vocabulary and canonical request-audit identity checks, native no-preflight and
preflight-only fact-return experiments, and a fail-on-skip targeted runtime gate.
The finite tests and reviewed-source guards are NOT universal I/O refinement;
Rust binaries and native cases must be rebuilt/run on the maintainer toolchain.
Kept the W4/W5 open obligations and external trust assumptions explicit.

## 2026-10-19 18:51:26 -0400

Extended the offline native manifest read assurance slice to the final-only,
preflight-only and two-phase paths without changing production Rust sources.
Added a separate W4/W5 Lean read-path module, a pinned dependency/source
manifest and a focused optional kernel+axiom gate. The new theorems are proof
*candidates* until compiled with Lean v4.35.0: Lean/Aeneas are unavailable in
this authoring container. Retained existing W4/W5 checksums and all open
native I/O refinement obligations rather than treating portable checks as a
proof. Added an independent paired-real-process observation oracle for
synthetic provider private-field mutations, including exact guest JSONL bytes,
pagination, host-normalized request identity, causal audits and no-unreviewed
credential disclosure. Portable counterexamples cover changed selected fields,
metadata, reflection decisions, hidden audit fields, frame injection, and
read-to-write promotion. Rust process acceptance is to run on the maintainer's
provisioned toolchain. Charon/full-suite checks intentionally not re-run; no
real account, TPM, credential or external service used. Confidence: high in
the portable tests and source inventory; provisional in the new Lean tactics
and native case integration until their focused acceptance gates run.

## 2026-10-19 19:13:53 -0400

Advanced W4/W5/W6 native-read finite refinement to public failures while
keeping all production Rust and existing Lean proof sources unchanged. Added
host-specified failure contracts for provider 4xx/5xx, invalid representations
and disclosure veto; modeled audited preflight/final provider prefixes and
fixed canonical guest denials. New paired native-process scenarios use only
invented credentials and local TLS to detect private error/header disclosure,
unexpected sends/completions and differing guest frames. Strengthened real
read observations with closed-form audit key, grant/policy and bound-client
consistency checks, and added a review guard for the actual Rust guest-error
serialization leaf. Kept pre-egress errors, authority races, timing, TLS close,
write paths, universal I/O refinement and complete reachability open.

Portable quick gate and mutation cases executed here, without Rust, Lean or
Charon. Native subprocess acceptance must run separately on the maintainer's
provisioned toolchain; previous passing validation cannot be transferred to
new native tests. Confidence: high in the reviewed Python oracles and their
portable counterexamples; native-case compatibility provisional until run.
