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
