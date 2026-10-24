# Claude journal

## 2026-10-22 21:04:30 -0400

Session goal (from the maintainer): get every existing proof working with
Aeneas and remove as many assumptions as possible, keeping the proofs
understandable.

Baseline found: the committed generated Lean was byte-identical to a fresh
pinned extraction, but `lake build` had failed since e7e8071 (three imported
modules were never Lake roots), and `system.py` had failed since 3e4ab7f/48b6c59
on stale review pins, W6 mutation fixtures missing two files, a vacuous
mutation test and an incomplete MANIFEST.in. All repaired; pins refreshed only
after reviewing the drifted source (agent review, not maintainer review).

Removed premises, each with extracted Rust and Lean proof:
- `NativeContext`/`capture`: composed the existing ScopedRequest proof.
- Denial frame: core `public_error` table; 17 fixed JSON lines proved.
- `toJson`/`SelectedConversion`/`toCapturedJson`/`Valid`/`Bound`: moved the
  read release (pagination, projection, assembly, reflection, wire value)
  into core `selected_release::Manifest`; proved noninterference over the
  provider document and the exact success frame.

Finding: the old NR-4 `SelectedConversion` premise silently forced pagination
metadata equal across runs; `possibly_more` reveals the row count. Now an
explicit declassification in `DocumentsAgree`.

Decisions/tradeoffs: kept native `Error::code()` as a host-side `&'static str`
table pinned by test (Aeneas rejects `&'static [u8]` match arms); kept a
test-only copy of each replaced native pipeline as a byte-equality oracle.

Risks: guards are source-shape checks; I tightened one anchor that a mutation
showed was a substring of its bypass. Confidence: high that behaviour is
unchanged (oracle tests + 3210-test gate); the remaining NR-3 sink premise is
the largest open gap.

## 2026-10-22 22:19:17 -0400

Continued removing premises after the maintainer's goal check.

- `PayloadCorresponds`: core `channel_work::Submitting` now owns channel
  construction (encode for the captured route, then connect), the send
  (`Channel::submit`) and the response gate. Proved every read exchange
  reaching send wrote exactly its own route's encoded body.
- Status classification: core `provider_status` (strict line parser,
  manifest classes) with an oracle over all 1000 codes; proved the exact
  class table and extended the adaptive theorem to whole exchanges
  (transport failure / status refusal / release).

Decision: did not extract the provider JSON body parser. NI over documents
already carries to bytes for any deterministic parser, and responses never
contain the credential; the cost of a second JSON parser in core outweighs
the assurance gain. Recorded in the proof tour.

Remaining honest gap: `ExactNativeSinkCoverage`, now narrowed to "native
primitives and the rest of the crate make no other credential write". That is
native reachability, guarded by W3/W6 source checks, not Lean.

Lesson: a guard clause I wrote had an `and ... or` precedence bug that made
it vacuous; caught on review and replaced with an exact equality check.
Confidence: high on behaviour preservation (oracles + 3213-test gate).

## 2026-10-22 23:58:39 -0400

W8/OUT-2 optional adapter, and MODEL-EXCHANGE-01 narrowed.

- `aivm_secrets native-session`: one versioned process contract (spec in,
  one readiness line out, stdin EOF ends it). The guest makes its own key;
  the credential stays in the host bridge. Synthetic local-guest test does a
  read and a denial and scans guest files and outputs for the token.
- AIVM side (`../aivm`, commit `f0f6ad6` on local `dev/0.6.2`, **not pushed**:
  that remote is HTTPS and I have no credentials for it): `--secrets_native_spec`
  starts the child with `-I`, never imports the package, and fills in only the
  guest route and principal. A template cannot set either. Tests use a fake
  child at the process boundary. A subprocess test shows default `aivm ssh`
  loads neither. Full AIVM suite: 3617 pass. The one local failure
  (`test_core_sdist_excludes_experimental_package`) comes from ignored build
  artifacts in that checkout; it passes in a clean worktree at my commit.
- `GarrettNR4FrameAdaptive`: the adaptive theorem stated over the frames the
  guest reads. Transport failures need only agree on their public code, not
  the native error. With `denial_frame_exact` that turns "native errors
  carry no private data" into an explicit at-most-17-value declassification.
  MODEL-EXCHANGE-01 is now P3 (body parse only).

- W8 identity negatives at the native bridge (synthetic): unregistered subject,
  expired enrollment, re-enrolled certificate and expired capability are
  refused with no provider call. Each test restores the registry and gets
  service back, so the denial is caused by the change.
- Lesson: running native tests concurrently with the gate made a 1-second
  grant test flake. Do not load the machine during the gate.

Tradeoff: the native adapter has no live identity-revocation poll, unlike the
Python adapter; the session ends with the shell. Documented as open. Risk: the
SSH guest transport is untested on real KVM through `aivm ssh`; only the
local guest is tested here. Confidence: high on the contract and default-path
independence; medium on SSH-transport details until a real-VM run.

## 2026-10-23 00:46:39 -0400

Maintainer pivot: an optional Docker-sandbox-style HTTPS credential
substitution profile is now a priority, beside (not replacing) named
operations.

- Planning: `docs/planning/aivm-secrets-http-proxy-profiles.md` defines three
  interface profiles (`named-operation`, `constrained-http`,
  `credential-substitution`), their exact allowed claims, HP-0..HP-7 and
  OUT-6. Before writing it I checked `../aivm/aivm/firewall.py`: the forward
  chain accepts public egress, so `HTTPS_PROXY` is not mediation. The plan
  says so; the maintainer's notes were right on that point.
- HP-1, Python reference: `aivm_secrets/proxy`. It has a strict HTTP/1.1
  subset parser, canonical re-encoding, credential stripping and injection,
  a pinned upstream, a name-constrained per-session CA, reflection refusal
  at any base64 offset, a deny list, revocation re-sampled per request, an
  audit and a stdin-lease process contract. 54 synthetic tests, including
  stock `curl`.
- Mutation check: a mutant that removed the per-request revocation check
  survived, because the tunnel-level check masked it. I added a mid-tunnel
  revocation test that kills it. The other eight mutants were caught.
- Decisions: refuse compressed responses rather than decode them, so the
  reflection check always sees plain bytes. Never follow redirects. Kept
  interface profiles out of the identity-binding assurance table (different
  axis). Five new ledger rows (`PROXY-*`). Substitution's lack of authority
  confinement is a specification entry, not hidden.

Risk: credential amplification is inherent to substitution; documented, not
solved. Confidence: medium-high on the reference's refusals (tested and
mutated); the parser has no proof yet (HP-4/HP-5 next, after HP-2).

HP-2 (same session): `constrained-http` uses the broker's schema-2 operations
as the allowlist instead of a separate shape table. A request is served only
if the host encoder, run on arguments read off it, reproduces it exactly, so
a matcher bug cannot widen authority. A test injects a broken matcher and
checks that it is refused. The proxy holds no credential in this profile; the
in-process Broker does. 19 tests, including the process contract. Not yet
translated: checks, GraphQL and pagination metadata. Stock-tool
compatibility is open (HP-3).

## 2026-10-23 02:00:03 -0400

HP-4/HP-5(a): extracted the proxy request side into Rust and proved where
the credential goes.

- `proxy_http.rs` in the Aeneas core: strict parser, field filter, deny
  rules, upstream encoder. Byte parity with the Python reference over 64
  vectors (`tests/secrets_vectors/proxy-http-v1.tsv`), checked from both
  sides. A `Cookie`-forwarding mutant fails the Rust oracle.
- `GarrettProxyHttp.lean`: `dropped_eq`, `forwarded_contract`,
  `append_fields_contract`, `needs_length_eq`, totality of `path_end` and
  `denied`, and `encode_upstream_contract`. An accepted encode is exactly
  prefix ++ verified auth line ++ suffix, and neither prefix nor suffix
  mentions the secret. Refusals leave the buffer unchanged. No sorry, no
  warnings.
- Aeneas lessons: `Vec::as_slice` and slice `!=` / array `==` extract to
  uninterpreted axioms (`alloc.vec.Vec.as_slice`,
  `PartialEqShared.ne`, `CoreCmpPartialEqArray`). Write
  `let x: &[u8] = &v; x == y` and `!(a == b)` instead. I checked the
  generated axiom list was back to HEAD's two before proving anything.
- Python changed to the Rust header spelling (`Authorization`,
  `X-API-Key`), dropped the `token` scheme and added the 4096-byte credential
  bound, all for parity.

Next: prove the parser's value/target admission (PROXY-PARSE-01, P1), then
the response reflection check in Rust. Confidence: high on the encoder
theorem; the parser is tested, not proved.

## 2026-10-23 02:41:56 -0400

HP-5(b) by design rather than by parser proof. Instead of proving the large
parser admits only CR/LF-free fields, the extracted encoder now re-validates
method, a visible-ASCII target and every forwarded field (`clean_fields`)
before writing, and drops credential names ignoring ASCII case (via the
already proved `http_wire::ascii_equal`). `encode_upstream_contract` now
also concludes target visibility and that every forwarded field is clean;
`clean_field_single_line` shows none has CR or LF. Framing no longer depends
on the parser. PROXY-PARSE-01 drops to a specification entry (provider
routing semantics; deny list is best effort).

Rust tweaks for provability, with byte parity kept: `escape_at` written
without `start + 3` (an overflow the model would expose), `segment_ok` as
plain early returns, `all_token` also requiring `visible`. Proof lesson:
when simp normalizes `decide (x ∈ list)` into an `||` chain, use `change`
to restore membership form and peel the if-chain with a `map fold` lemma.

## 2026-10-23 03:22:04 -0400

HP-4 core complete and HP-5(c) proved. The response side (parser, field
filter, reflection forms, re-framing) is now in the extracted core, with byte
parity over 40 response vectors (a mutant without the hex form fails).
`GarrettProxyResponse` proves that a released response never contains the
raw credential: `reflects_spec`, `guest_response_contract` (HEAD is a
prefix of the checked bytes) and `reflection_forms_include_raw`. The last is
partial correctness, proved by inversion because the form loop only pushes,
which avoids proving totality of the base64 arithmetic. That is enough for
the safety claim. Rust change for provability: `form_present` helper, so the
loop body starts with a call that `step` can take.

Remaining for OUT-6: a native proxy server (rustls plus rcgen) wiring the core,
HP-3 AIVM wiring, HP-6 constrained-http proof. Confidence: high for the stated
theorems; they cover the extracted functions, not the Python server or a
native server that does not exist yet.

## 2026-10-23 03:39:36 -0400

Native `garrett-proxy` (HP-4 server). It has the same policy and process
contract as `aivm-secrets proxy` and is a thin I/O shell (sockets, rustls,
rcgen name-constrained session CA, audit, stdin lease). Every decision calls
the extracted core. All 27 native tests passed on the first run: stock curl,
re-encoding, keep-alive, ambiguous requests, deny list, tunnel auth,
reflection (raw, base64, hex), compression, redirects, oversize, expiry,
unreachable, lease end and bad policy. Added to the gate's required no-skip
workflow tests.

Review fix before commit: the first draft fell back to an unchecked
`std::fs::read` for the upstream CA file. It now uses
`files::read_trusted_public` (made pub). The scope is stated explicitly:
NATIVE-SINK-01 covers the bridge; the proxy binary is PROXY-NATIVE-01, pinned
by a write-shape test.

## 2026-10-23 03:56:58 -0400

HP-3: `aivm-secrets proxy-session`, plus the opt-in AIVM flag
`--secrets_proxy_spec`. Both reuse the native-session transports and AIVM
adapter; the latter gained a `contract` parameter. The guest gets a CA, a
bundle and an env file. The token lives only in that guest file and never on
stdout. A local-guest curl test passes against both the Python and the native
proxy. Design decision: tools that honour `HTTPS_PROXY` send all HTTPS through
the proxy, and it refuses unlisted origins rather than relaying them. That
keeps it from being an open relay, at the cost of breaking such tools for
other hosts while the env is sourced. Documented. Not tested on real KVM yet:
the SSH TCP reverse forward is exercised only by code review and the AIVM unit
tests (fake child).

## 2026-10-23 04:59:03 -0400

HP-5(d): the proxy's refusal responses moved into the extracted core
(`proxy_http::refusal(&Code)`) with byte parity to Python over all 11 codes.
`refusal_exact` proves each is exactly the ASCII of a fixed text that mentions
only the code. The native shell now calls the core function. Proof
technique: after `step*`, `simp_all` with a two-digit `Digits` lemma makes
everything concrete, then `scalar_tac`, `rfl` or `decide` close it. This
completes HP-5 for the credential-substitution profile's request, response
and refusal paths. The native shell's own writes stay PROXY-NATIVE-01.

## 2026-10-23 05:31:28 -0400

NATIVE-GLUE-01 narrowed. The bridge's guest frame choice, a released or native
reply versus a fixed denial, is now the extracted
`public_error::answer_frame`. `GuestFrame::from_answer` only maps types and
calls it once. In Lean, `productionFrame` is that extracted function rather
than a model of native code, so `production_frame_noninterference` and
`production_failure_frame` are about production code; there is also a new
`production_success_frame`. Native: the dead `Reply::prepare` and
`Captured::prepare` were removed in favour of `Reply::captured` and
`Captured::wire`. Four guards and their mutation tests were re-anchored to
the new shape, plus a released-reply byte-equality oracle. Existing oracles
already cover all 17 denial frames.

## 2026-10-23 05:53:51 -0400

HP-7 in AIVM (local commit `32b475d`, unpushed): `firewall.public_egress =
false`. The key observation is that the proxy's guest port is carried by the
host-initiated SSH session, so dropping *new* guest-initiated forwarded
connections leaves the proxy working and removes direct egress. It is
minimal: one config field and one final rule, and the default fingerprint is
unchanged, so no repair is triggered. The full AIVM suite passes in a clean
worktree (3625; only the known 1-second timing test excluded). Risk: not
exercised on real nftables or a VM. A wrong rule order would either break
SSH or fail open; a unit test checks the order.

## 2026-10-23 06:05:42 -0400

OUT-4 first increment: the exact-write gate. The native session used to
branch on the approval decision itself before calling the production
controller. That branch is now the extracted `write_gate::run_approved`,
which is the session's only call of `run_current`. `GarrettWriteGate`:
`run_approved_ran`, `run_approved_refusals`,
`approve_mode_write_ran_consumed_its_approval` (composed with the existing
single-use approval proofs), `deny_mode_write_never_runs` and
`production_write_has_approval_and_authorized_attempts` (composed with the
production attempt-accounting theorem, which already holds for any
operation). All of them compiled on the first try because the existing
infrastructure did the heavy lifting.

Behaviour is unchanged: 151 native approval, invoke and manifest tests pass.
The Required path now builds the (side-effect-free) closures before
returning. Five guards were re-anchored, and a new mutant that forces
`Decision::Allowed` is detected. APPROVAL-RUST-01 is narrowed to "the
session passes this request's own decision". A new visual scene,
`proof_write_gate`, was added.

## 2026-10-23 07:02:00 -0400

Proxy security-review fixes (all six findings of the independent review),
in the extracted core, the Python reference and the native shell, with
proofs, parity vectors and both-backend tests
(`tests/test_proxy_review_hardening.py`).

- Deny-list spellings now fail closed in the encoder: `;`, malformed
  escapes and escapes of unreserved characters, `/`, `\\`, NUL or `;` are
  refused; rules match trailing-slash variants. Only totality of
  `rule_matches` is proved; I rewrote its `len + 1` comparisons as guarded
  subtractions so the extraction has no overflow obligations. I chose not to
  prove deny semantics: it is a host filter, and claiming more would invite
  reading it as confinement.
- Method-override and Range/If-Range fields join the dropped set (19 names);
  `dropped_eq` restated over the new list. `_method` in query/body remains
  a documented limit in PROXY-AUTHORITY-01, not a fix.
- Reflection: `unwrapped_spec` gives the exact CR/LF-filtered bytes, and
  `reflects_spec` now also excludes each case-sensitive form there
  (`Unreflected`). JSON `\/` form is listed when the secret has `/`.
- Native DoS bounds (connection cap, deadlines, raw buffer) and the 0600
  hash-chained audit are tested, not proved; recorded in PROXY-NATIVE-01.
- Confidence: high for the proofs as stated; medium for completeness of the
  spelling list against real provider normalizers (PROXY-PARSE-01 stays).

## 2026-10-23 07:32:30 -0400

PROXY-NATIVE-01 narrowed: `proxy_controller::serve` is now the extracted
per-request controller of `garrett-proxy`; the native shell supplies only
`current`, `admitted` and `exchange` callbacks and records the audit
from the returned `Served`. `GarrettProxyController` proves, for any
callbacks: the three paths (`serve_paths`); exchange only after current
and admitted, with exactly the encoder's output (`serve_upstream`); the
reply is a fixed refusal or `guest_response` output (`serve_guest_reply`).

- Decision: I kept the size premises (encoding / checked response fits in
  a usize) explicit rather than trying to derive them from parse limits. They
  are memory bounds; deriving them would need a length theory for
  `ResponseBytes` that buys no security. I avoided a tempting universally
  quantified fit premise because it would be false and make the theorem
  vacuous.
- I briefly wrote a placeholder theorem concluding `True`; removed before
  building. Noting it so the pattern is watched for.
- Oracle: Rust tests compare `serve` against the pre-extraction composition
  byte for byte and check callback order with a recording mock.
- Remaining native: the CONNECT/tunnel loop, the callbacks themselves and
  socket/TLS. Confidence high for the stated theorems.

## 2026-10-23 07:53:43 -0400

HP-6, first step: guest-side constrained-http in Python
(`aivm_secrets/proxy/bridge.py`). The existing translator now has a second
dispatcher that calls the guest's native `invoke` instead of an in-process
broker, selected by `aivm-secrets proxy --bridge-client`. It refuses a
credential file in that mode (one authority source, no fallback).

- Why Python first: the translator's correctness is a usability property
  once it sits on the guest side; authority is the bridge's. A native
  translator only matters for guests without Python and for a proved round
  trip, so it comes second.
- Key test: a tampered guest route copy that allows `gamma` still gets
  nothing from the provider, because the bridge decides on its own policy.
- I tripped over my own `str.replace` replacing every `server_hostname=HOST`
  in the substitution tests; caught by the suite and restored the one that
  connects by IP. Lesson: use anchored, single replacements in test edits.
- Confidence: high on the authority argument; medium on stock-tool
  compatibility (disclosure-only bodies) which is unchanged from HP-2.

## 2026-10-23 08:37:10 -0400

Named-operation targets are now written by the extracted
`route::fill_target`; the native manifest only parses templates and turns
arguments into text. `GarrettRoute` proves the exact bytes
(`fill_target_exact`) and the byte classes (`fill_target_safe`) in
inversion style, so no size premise appears. New ledger row
ROUTE-NATIVE-01 for what stays native.

- Why this before a native HP-6 matcher: a matcher round trip is only
  meaningful against the function the host really uses. This also narrows
  host-side native code that every read and write goes through.
- Semantics: one deliberate difference from the replaced code. A referenced
  argument that is not a scalar now gives Denied instead of InvalidRequest.
  It is unreachable because `Operation::request` already requires scalar
  parameters; the oracle test asserts both refuse in that case and are
  byte-identical otherwise (>500 combinations).
- Tooling: installed rustfmt/clippy components for the pinned nightly. The
  tree has substantial pre-existing rustfmt drift; I formatted only files I
  created, to avoid churning pinned hashes in an unrelated commit.
- Pitfall noted: building bins without `--all-features` overwrites the
  conformance runner with a featureless build and makes retry-key tests fail
  spuriously.

## 2026-10-23 09:02:16 -0400

Work-order item C asked to account for `describe` and `renounce`. Neither
was covered by any proof or ledger row. Both sessions now hand them to the
extracted `control::control` after authorization. `GarrettControl`
proves the three paths for any callbacks (`control_paths`) and the exact
content of the manifest description (`manifest_description_exact`). New
row CONTROL-NATIVE-01 for the three callbacks.

- Behaviour preserved, checked by a byte-equality oracle against the old
  serde replies through the same extracted frame encoder, and by the 229
  existing native describe/renounce process tests.
- Observation worth review: on renounce the control state is revoked
  *before* the audit record; if the record fails the grant stays active but
  control is revoked and no reply is sent. That is the pre-existing order,
  now proved; it fails closed for further use but leaves the grant flag set.
  I did not change it (security-semantics change needs review).
- I drafted the description theorem with a placeholder `sorry` and replaced
  it with the real statement before the first build; nothing with `sorry`
  was compiled or committed.

## 2026-10-23 09:26:46 -0400

HP-6 native: `garrett-proxy` gains the guest-side constrained mode
(`--routes`, `--bridge-client`, no credential). Matching is the extracted
`route_match::translate`, which accepts candidate arguments only when the
host's own `route::fill_target` reproduces the target;
`translate_round_trip` / `translate_exact` are proved. The native
manifest's `Policy::translate` then types the arguments and re-checks
method, target and body through the route copy's validation, and requires
exactly one match.

- Design choice: prove soundness by construction (the extracted matcher ends
  in the host's encoder and a byte comparison) rather than proving the
  matching heuristics. This mirrors the Python round-trip guard and keeps
  the proof small; completeness is a usability property only.
- Known differences from the Python translator, documented: query order must
  match the policy (BTreeMap) order, path parameters are single segments, and
  bridge errors collapse to four refusal codes.
- Exactly one authority source is enforced in argv parsing and in `load`
  (constrained + credential, or substitution + routes, is invalid).
- Tests: the guest-translator suite now runs on both backends (12 passed),
  including the tampered route copy.

## 2026-10-23 09:54:25 -0400

PROXY-NATIVE-01 narrowed again: the CONNECT decision of `garrett-proxy` is
the extracted `proxy_connect::admit`, including base64 decoding and a
constant-time token comparison. `GarrettProxyConnect` proves
`same_secret_true` (bit-vector reasoning via `bv_decide`),
`authenticated_true` and `admit_open`.

- The decoder is deliberately not proved to be base64: the security claim
  only needs "whatever it presents equals the token". Compatibility with the
  `base64` crate (canonical padding, zero trailing bits) is checked by an
  880-case oracle test against the replaced native code.
- Two Aeneas pitfalls hit and avoided: `?` on `Option` extracts to
  uninterpreted `Try` axioms (rewritten as `match`); tuple destructuring
  extracts to a pair `let` that `simp` cannot reduce, but `bind_ok_inv`
  sees through it by unification.
- `admit_open` states the host index is valid and equals the host slice the
  code compared; it does not (yet) tie that slice to the head bytes. The
  claim used is "only to a configured origin", which does not need it.

## 2026-10-23 10:12:26 -0400

Made the constrained profile usable end to end: `native-session` accepts an
optional `constrained_proxy` and starts the native translator inside the
guest (spawned over the same SSH config, stdin as lifetime lease), with a
sanitized route copy (no `egress`, dummy credential source) and an env
file. Stock `curl` reads through it in the local-guest test; out-of-scope
and unmatched requests never reach the provider; no guest file holds the
credential.

- Not run: a real VM. The SSH spawn path is untested beyond the code shared
  with the existing SSH transport; this is a maintainer action.
- I reused `proxy_session.environment_file` with new name parameters
  rather than duplicating it, since the bridge already uses `ca.pem`.

## 2026-10-23 10:26:27 -0400

Wrote `dev/aivm_constrained_acceptance.py` (maintainer real-VM run of the
constrained profile through native-session). Rehearsing it locally with a
local guest found two real gaps before any VM run:

1. The GitHub-shaped policy's `repository` parameter spans two segments
   (`owner/repo`). The extracted matcher now takes allowed texts as
   candidates; acceptance is still the proved round trip, so the theorem is
   unchanged apart from the new argument.
2. Every GitHub-shaped operation has a host check (`requires: pull`), and
   both translators skipped such operations. That was stricter than needed:
   the host runs the check for any named request, and the round trip already
   rejects operations whose final target needs check facts (`pr.checks`,
   head SHA). Relaxed in the Python reference and the native translator.

The local rehearsal now reads a pull request diff through stock `curl`;
the provider sees the host's own check and the diff, both via the bridge.

## 2026-10-23 10:47:55 -0400

ROUTE-NATIVE-01 narrowed: argument text is the extracted
`route::scalar_text` (strings as is, integers in decimal via the already
proved `append_decimal`). `scalar_text_integer` carries an explicit
platform premise (`|n| + 2 ≤ usize::MAX`): Aeneas models `usize`
abstractly, and `as usize` would truncate on a 32-bit target. I stated it
rather than hide it; it holds on the 64-bit native build. Oracle test against
Rust formatting includes `i64::MIN` (absolute value computed without
overflow).

## 2026-10-23 11:11:21 -0400

`garrett-proxy`'s framing decision (raw bound, then the strict parser) is
now the extracted `proxy_controller::frame`, with `frame_paths` proved. With
`serve` and `admit`, every decision in the proxy's request path is in the
extracted core; what remains native in PROXY-NATIVE-01 is socket/TLS I/O,
deadlines and the session clock. The strict parser itself is still tested,
not proved; the encoder re-checks everything it writes, so framing safety
does not depend on it.

## 2026-10-23 11:42:34 -0400

Template parsing moved into the core (`route::parse_template`,
`parse_piece`) and proved: a parsed template writes back to exactly its
text and every piece is a valid segment or `{name}`. I restructured the
loop (single branch over a `next_slash` helper) because the first version
extracted with duplicated branches; the oracle test (1,700+ templates)
confirms the restructure matches the old native parser. The loop theorem
carries a size premise (template shorter than `usize::MAX`; policy limits it
to 1024). ROUTE-NATIVE-01 is now only the JSON layer.

Proof-engineering notes for the next agent: `step*` shadows hypothesis names
(`inner_post✝`); refer to them by type with `‹...›`. Contradictory
`if` branches from extraction need an explicit `exfalso; scalar_tac` first.

## 2026-10-23 12:04:21 -0400

Installed manim (and the pango/cairo headers it needs) into the
visualization venv and rendered stills of the proof scenes for the first
time in this session. Found and fixed two layout bugs shared by every scene:
card headings shifted right by half their width (overflowing for long
names) and long subtitles running off the frame. Structural tests had
passed throughout; only rendering showed it. Lesson: render at least one
still after changing a scene.

## 2026-10-23 12:22:34 -0400

`system.py --proofs` had been failing since before this session: the
freshness manifest pinned old hashes of `proofs/lakefile.lean` (roots added
over many commits) and `dev/verification/freshness.py` (changed in
`523408e`). `freshness.py record` would refresh them but also runs the
transitive axiom audit, which AGENTS.md reserves for an explicit
end-of-formalization request, so I updated only those two hashes after a full
`lake build` passed. I also added the proxy, route, control and write-gate
modules to the `--proofs` build list. Whoever runs the next requested audit
should re-record the manifest normally.

## 2026-10-23 12:23:55 -0400

HP-3 compatibility evidence beyond curl: installed the GitHub CLI (Ubuntu
package) and added `tests/test_proxy_gh_compat.py`. Stock `gh api` with a
placeholder `GH_ENTERPRISE_TOKEN` reads through both proxies from a synthetic
enterprise-shaped provider; the provider sees only the substituted bearer;
a deny-listed path fails. Skips where `gh` is absent. Not checked: gh
GraphQL commands (`gh pr view` uses GraphQL), which would need a GraphQL
route on the synthetic provider.
Follow-up: `gh pr view --json` (GraphQL) also works through both proxies;
added to the test with a GraphQL route on the synthetic provider.

## 2026-10-23 12:42:07 -0400

Independent review (subagent, unanchored brief) of today's proxy, translator,
native-session, route and control changes: no high-severity defects; three
low ones fixed here.

1. The native translator passed invoke arguments on argv (visible to other
   guest users, and over-long arguments made the client fail, reported as
   "outcome unknown"). It now uses `--arguments-file -` on stdin, refuses
   arguments over the client's 16 KiB limit as `too_large` before any call,
   and bounds the client with a 60 s deadline and a 4 MiB reply.
2. `route::scalar_text` truncates on a 32-bit `usize`; a compile-time
   assertion in the native manifest now refuses to build there (matches the
   theorem's stated premise).
3. A malformed guest-written translator announcement raised an unexpected
   exception on the host; it is now validated and reported as
   `proxy_failed`, with a test for four malformed lines.
The reviewer also confirmed (and I keep documented) that the Rust
translator requires the policy's query order while Python accepts any order.

## 2026-10-23 13:37:47 -0400

Maintainer task: bounded Anodized 0.7 pilot on `public_field_name` with the
pinned Charon/Aeneas. Result: **no-go**, documented in
`docs/assurance/anodized-pilot-2026-10-23.md`, reproducible with
`dev/verification/anodized_pilot.py` (scratch copy only).

- Charon understands `#[charon::contract]` and folds the contract into the
  function; Aeneas then extracts `public_field_name` as a wrapper around
  `anodized.__.eval_once`/`apply_keep` (and `eval`), all new
  uninterpreted axioms. The result is unprovable and the contract never
  becomes a Lean obligation.
- The brief assumed the annotated body is untouched in Charon mode; it is
  not: Anodized inserts two unused loop-spec closures per loop iteration.
  Behaviour is unchanged (validator test identical with and without), but the
  verified body would differ from the shipped one.
- Kept: `GarrettPublicFieldNameContract` with the complete accepted-language
  theorem over the unannotated extraction, a validator unit test, and the
  pilot script. Reverted: the optional dependency, feature, crate attributes
  and annotation (the lockfile is unchanged).
- Toolchain reuse: I used the existing pinned binaries and `lake exe cache
  get`; nothing reimplemented. I did not try hax or newer Charon, per the
  brief.
- I parked my in-progress proxy-parser refactor in `git stash` to keep this
  commit focused; it resumes next.

## 2026-10-23 14:22:29 -0400

Resumed and finished the parser increment: `parse_request` now delegates
to two small helpers (`request_fields`, `body_of`) so its extraction is
linear instead of duplicating the tail per field branch (behaviour checked by
the Python/Rust parity vectors). `GarrettProxyParse` proves
`parse_request_bounds`: an accepted request used at most the buffered bytes
and its body is at most the limit. Premises are size bounds only (buffer and
limit at least 2^32 below `usize::MAX`), which the native shell's raw bound
guarantees. Notes: `step*` applies the induction hypothesis itself, leaving
measure goals closed by `rfl`; `‹...›` with holes plus `generalize`
recovers inaccessible hypotheses at the end of a long inversion. Full
`lake build`: 1,898 jobs, no warnings.

## 2026-10-23 14:55:07 -0400

APPROVAL-RUST-01 narrowed: the host approval store (native `BTreeMap`) is now
the extracted `approval::take/admit/install` over a `Vec<Approval>`, proved
in `GarrettApprovalStore.lean` (first-slot lookup, admit = consume on that
slot, Allowed removes it, uniqueness preserved, spent approval Required again,
install replaces same digest / drops expired / refuses when full). Oracle test
`store_oracle` replays 200x120 random admit/approve steps against the old map.
Decision: a full store now refuses *without* pruning (old code pruned first and
could lose a still-valid same-digest slot on refusal or audit failure); the
oracle resynchronizes only at that point. Aeneas needed indexing `store[index]`
directly (a shared `here` borrow across the join failed context matching).
Lean: pair-let after `consume` reduced with `WP.spec_bind (Pₘ := (· = pair))`
then `change`. Still assumed: the one native line passing `admit`'s decision
to `run_approved`, digest computation, lock. Confidence: high on proofs;
medium that the 16-slot/TTL behaviour is what the maintainer wants (unchanged).

## 2026-10-23 15:36:42 -0400

OUT-6 "framing loop into the core" done: `proxy_controller::step/tunnel` behind a
`Guest` trait (overdue/read/send/refused/serve); `garrett-proxy` keeps only
`GuestTunnel` callbacks and close_notify. `GarrettProxyTunnel.lean`:
`step_paths` (four cases, exact callback arguments), `step_request_fits`
(parse_request_bounds through frame_paths; carries the 64-bit-size premises),
loop equations. Oracle `extracted_tunnel_matches_the_native_loop` replays 400
scripted tunnels (random chunking, truncation, refusals, send failures,
deadlines) against the old loop: identical effect logs. Behaviour deltas,
deliberate and small: the request deadline restarts after `serve` returns,
not before (old code counted serve time against the next request); read/write
errors now end the tunnel and still send close_notify. Aeneas: `Vec::is_empty`
is an unmodelled axiom, so `len() == 0` with a clippy allow. Lean: pair
bindings from trait calls are inverted only by unification
(`bind_ok_inv`, new `ite_ok_inv`, `ok_pair_inv`); `simp` cannot reduce them.

## 2026-10-23 16:12:14 -0400

CONTROL-NATIVE-01 / work order B (record content): `control::revoked_record`
builds the revocation audit record in the core; `control` encodes it with the
extracted `json_wire::append` and hands exactly those bytes to a new
`Control::record` callback, which both sessions implement as
`Audit::append_bytes` -> extracted `append_durable_record` (same relation as
read records). Proofs: `control_paths` (new Unencodable branch),
`renounce_records_exactly`, `revoked_record_exact`. Oracle
`extracted_revocation_records_match_the_serde_records` covers escapes, control
chars and non-ASCII for both profiles. Deferred NATIVE-SINK-01 step 2 (opaque
core credential type): it would retype the secret in dozens of extracted
signatures/proofs while four native readers (envelope seal, OAuth marker,
legacy account writer, inner-issue export) still need bytes; low payoff now.

## 2026-10-23 16:55:11 -0400

W8 identity negatives: found that the existing synthetic coverage
(test_rust_identity_negative.py) exercises only the legacy registry_path bridge
mode, while AIVM uses authority-root mode. Added authority-mode tests: live
re-enrollment fences the old cert (invalid_capability, no provider call);
an enrollment reaching not_after mid-run is refused at TLS (back-dated init +
enroll, 12 s window); forget refuses active and revoked subjects (so
"unregistered" is unreachable for a live identity in this mode). Added the
re-enrollment probe as the last --adversarial VM step (portable test; not run
on a VM). Uncertainty: the 12 s expiry window could flake on a very slow host.

## 2026-10-23 16:56:20 -0400

W8 mount aliases: `--adversarial` mount inventory now parses share mounts by
device/root and counts whole-share roots and aliases (validated against this
AIVM guest's own mountinfo: 1 device, 1 root, 24 aliases), plus a bounded
canary-name search of share mount points (depth 4, 20 s; timeout = incomplete,
not absence). Chose bounds after exhausting virtiofsd fds earlier today with an
unbounded find. Not run on a VM; the maintainer run decides whether depth 4
is meaningful for their shares.

## 2026-10-23 17:03:06 -0400

Audit-record link (Track A "connect the audit callback to the receipt"),
second step: `session_audit::event_record` now builds the account profile's
four event records and the manifest completion record; native appends exactly
the extracted encoding via `Audit::append_value` -> `append_bytes` ->
`append_durable_record`. `GarrettSessionAudit.event_record_exact`. Guards
(W3, W6, NR-2/3 mutation tests) moved to the new source shape. Left native:
the manifest dispatch record (nested identity claims + route); next candidate.

## 2026-10-23 17:31:12 -0400

Dispatch record into the core: `session_audit::dispatch_record` (+
`dispatch_record_exact`), `Captured::into_wire` to hand captured identity
claims to it, oracle with nested/escaped claims. W3, NR-2/3 edge and W3
mutation tests moved to the new shape (the mutation that inserts a credential
print before the dispatch audit still trips the guard). Manifest dispatch and
completion records now have core-built content; still native: the manifest
`session_open` (with profile), `issued`, and the account-profile dispatch
record (custody.rs:750, 1013, 1079).

## 2026-10-23 17:58:59 -0400

Remaining session records moved: `opened_record`, `issued_record`,
`account_dispatch_record` (+ `authentication_name`), each with an exact
theorem and a byte oracle. Every audit record both sessions write is now
core-built; the approval extension's three host-control records remain native.

## 2026-10-23 18:26:38 -0400

Approval extension records (`approval_requested`, `approved`, host
`revoked`) also core-built (`approval_requested_record_exact`,
`approved_record_exact`, `event_record`); `Audit::write_record` is now
`#[cfg(test)]`, so no production audit record is assembled natively.

## 2026-10-23 19:08:07 -0400

PROXY-PARSE-01: deny-list matching semantics proved. Restated
`proxy_http::rule_matches` as `method_ok && path_matches` (helpers
`plus_slash`, `ends_with_slash`) because the early-return form extracted
into a ~500-line duplicated tree; exhaustive oracle (all paths/rule paths of
length <= 4 over {a,/}, all method pairs) against the old matcher.
`rule_matches_spec`/`denied_spec` now state exact semantics
(`RuleMatches`/`PathMatches`) instead of totality. A splice error of mine
briefly duplicated part of GarrettProxyHttp.lean; reconstructed and re-spliced
before any build/commit.

## 2026-10-23 19:30:28 -0400

`check_target_plain`: byte-level refusals of the proxy target check proved
(visible, not #/\\/;, no refused escape at any position — the escape fact is
stated as the extracted `bad_escape_at` returning false there, not as a
handwritten escape grammar). `check_target_spec` (visible only, @[step]) is
now derived from it. Dot/empty segment refusal still tested only: a
splitOn-based segment invariant for `segments_ok_loop` is the next proof.

## 2026-10-23 19:39:56 -0400

`check_target_segments`: dot-segment and empty-segment refusal proved. Specs:
`segment_ok_exact` (`SegOk` of `Piece`), `segments_ok_loop_exact` with a
positional invariant (`InteriorOk`/`FinalOk` stated over `p[i]? = some '/'`
instead of `List.splitOn`, which kept the loop proof short). PROXY-PARSE-01's
remaining unproved part is now only provider-side normalization.

## 2026-10-23 19:49:06 -0400

CONNECT head reader extracted (`proxy_controller::connect_head`, `HeadSource`
trait) with oracle (same result and same bytes consumed as the old loop).
`connect_head_returned` proved by induction on remaining room under
MAX_HEAD, stated as an inversion of a returned result because callbacks may
fail. Every sequencing loop of garrett-proxy is now extracted.

## 2026-10-23 20:12:47 -0400

Parity note: the approval-store behaviour change (full store refuses without
pruning) matches Python `kernel/machine.approve`, which is functional and
raises `exhausted` before replacing state. Updated the claim matrix with
today's evidence and an explicit "outside this profile" section so OUT-4/OUT-6
proofs are not counted toward the native read claim.

## 2026-10-23 20:24:22 -0400

FINDING and fix (security, fail-open → fail-closed): the native proxy's
`Session::record` ignored write/fsync failures, so a failed admission audit
still let `serve` call `exchange` (the Python proxy failed closed by
letting the OSError escape and closing the tunnel silently). Now
`Upstream::admitted -> bool`; the extracted `serve` refuses with a new public
code `internal_error` (502) before any exchange; the native translated path
and both Python admission sites do the same. Proofs: `serve_paths` has a
fourth path; `serve_upstream` now says exchange follows an *acknowledged*
record. Tests: core mock, native RLIMIT_FSIZE=0 (SIGXFSZ ignored) adversarial
test (mutation-checked: fails with the check disabled), Python monkeypatch.
Needs maintainer security review (changes the public refusal set: twelve
codes now).

## 2026-10-23 20:49:08 -0400

Second fail-open gap, same pattern: the native proxy released the provider's
reply even when the `completed` record failed (Python's OSError stopped the
reply). Both proxies (direct and translated paths) now return
`outcome_unknown` unless the completion record is durable. Native check is
source-shape only (in `serve_one`, after the extracted `serve`); a native
integration test would need the audit to fail on exactly the third write,
which I judged too fragile to build with RLIMIT_FSIZE (record lengths depend
on ports/timestamps). Candidate: move the completion record into the core so
it is proved like admission.

## 2026-10-23 21:14:05 -0400

Completion gate moved into the core: `Upstream::completed(status) -> bool`,
called by the extracted `serve` after a completed release; failure →
`outcome_unknown` (Failed). `serve_paths` path 4 now carries the completion
callback; new helper `exchanged_outcome`; `serve_upstream` states the
exchange with an existential post-state. Core mock test and the
byte-for-byte composition oracle updated (it now expects the completed call).

## 2026-10-23 21:38:24 -0400

Native proxy now refuses to start if `session_start` cannot be recorded
(`ready:false, error:internal_error`), matching Python. Native integration
tests let exactly N audit records through via RLIMIT_FSIZE sized from a
measured run (record lengths are deterministic): startup, admission and
completion gates each tested live; completion test mutation-checked.

## 2026-10-23 22:03:08 -0400

Session reflection (evening). Pattern that paid off: moving a native
decision into the core with a byte/behaviour oracle against the old code,
then proving it, repeatedly surfaced real issues (two fail-open audit gaps in
the native proxy; deny matching extracted as a 500-line tree until restated).
Risks I want the maintainer to weigh: (1) `internal_error` is a new public
proxy refusal code; (2) several W8 probes exist only as portable tests; (3) the
RLIMIT_FSIZE live tests depend on deterministic audit line lengths (they
measure first, so a format change shows as a failure, not a false pass).
Uncertainty: authority-root expiry test has a 12 s window. Confidence: high
that every committed theorem is about the production-called extracted
function named in its docstring; medium-high on the completeness of the
"still assumed" lists in the tour.

## 2026-10-23 22:30:30 -0400

Translated proxy path sequencing extracted: `proxy_controller::serve_translated`
behind a `Bridge` trait; exhaustive oracle over all 96 callback outcomes vs the
old native order; `translated_release`/`translated_outcome` proved. Native
`serve_translated` now only builds the 200 response; removed the dead native
`refusal(&str)` helper.

## 2026-10-23 23:04:27 -0400

End of run. `system.py --proofs` passes at `74fbe33` (includes
`translated_release`). Next concrete removals, in order: (1) fold the approval
decision into a core `write_gate` entry that takes the store admission
callback, removing the one native line; (2) core-build the proxy's audit rows
(hash chain stays native) as done for the bridge sessions; (3) revisit the
opaque core credential type once the four native byte readers are reduced.

## Correction to the next-removals list

Item (1), folding the approval decision into the write gate, is not a real
removal on its own: what APPROVAL-RUST-01 assumes is that the decision belongs
to *this request's digest*, and the digest is canonical JSON hashed with
SHA-256 natively (ring). Moving the call into the core would move the line, not
the assumption. Reordered: (1) core-build the proxy's audit rows; (2) the
approval digest needs an extracted canonical-request encoder plus a stated
SHA-256 contract (crypto stays external-trusted) before the gate fold is worth
doing; (3) opaque core credential type as before.

## 2026-10-23 23:06:45 -0400 (branch wip/proxy-audit-rows)

Started the proxy audit-row extraction on a branch, not main: core
`proxy_audit::row` (fixed fields merged with key-sorted detail) and an oracle
against serde `row.to_string()`. Finding: the extracted JSON encoder escapes
non-ASCII as \uXXXX while serde emits raw UTF-8, so rows match only for ASCII
fields (true in production: visible-ASCII targets, ASCII origins/codes). Before
merging: rewrite `merge` with index loops (Peekable is not Aeneas-friendly),
extract, prove sortedness and fields, wire `Session::record`, run the gate.
Not wired into garrett-proxy yet.

## 2026-10-23 23:08:07 -0400 (branch wip/proxy-audit-rows)

`clone_value` (structural recursion) and an index-loop `merge` make the
proxy row extractable: scratch Aeneas run clean, still 2 axioms, oracle still
passes. Remaining before merge: prove `merge` keeps key order and every
field, wire `Session::record` through `row`, gate.

## 2026-10-23 23:12:28 -0400 (branch wip/proxy-audit-rows)

Lesson: a clean scratch Aeneas run is not enough; the first `merge` extracted
to Lean that did not compile (`Decidable take_left`). Restructured to a single
condition; authoritative extraction now compiles (2 axioms). Proved
`key_before_loop_spec` (`KeyLt`, lexicographic by scalar value) in
`proofs/GarrettProxyAudit.lean` (not yet a lakefile root). Next: merge spec,
row structure, wiring, gate.
