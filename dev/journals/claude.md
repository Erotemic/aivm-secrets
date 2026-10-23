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
