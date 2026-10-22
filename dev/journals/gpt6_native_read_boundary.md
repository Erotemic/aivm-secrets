## 2026-10-21 22:33:00 -0400

Goal: implement the first sizable Track A source-to-callback proof increment after the
scoped OUT-2/OUT-3 VM/live-provider tests. Do not infer Lean compilation from the
user's earlier completed changes: this is a newly authored proof module.

Decision: add `GarrettNativeReadBoundary.lean` over the existing Aeneas-extracted
`provider_exchange.exchange`/`dispatch.Pending`/`current_admission.Bound` and
`provider_io.Channel.submit`, rather than creating another interpreter or
freestanding event trace. Compose existing source-derived `ReadRun`,
`driver_trace`, `owned_read_driver_stamp_origin`, and exhaustive
`Request.submit`/`Channel.submit` callback classification. Prove the early
setup/current-refusal receipt preservation separately from the attempted-read
case, which includes send-error, response-error, and successful response.

Two production adapter obligations remain explicit and local:
`SetupReturnsFresh` must be established from the actual ManifestProvider
setup-route factory's `Channel.new`; `SendsThroughChannel` must be established
from native `send_manifest_bytes`/`ManifestProvider::send`. Separating these
rather than assuming arbitrary sent channels are fresh avoids a false global
freshness assertion for replayed channels. No custom callback-observation
oracle, new Lean axioms, production Rust changes or broad claims were added.

Open gaps: this theorem does not explicitly locate its projected callback event
inside the returned receipt event list; exact audit File/Write completion
chronology, transitive I/O closure, rustls/TCP/partial writes, exceptional
paths, completion audit, guest-frame bytes and noninterference remain NR-2/3/4
work. A native adapter can still bypass the source-owned channel through an
unreviewed I/O path unless the separate sink/reachability closure is proved.

Verification limitation: Lean 4 and Lake are unavailable in this isolated
artifact environment; the pinned toolchain cannot be downloaded here because
network resolution is unavailable. Focused compilation is therefore NOT RUN.
The maintainer must run `cd proofs && lake exe cache get && lake build
GarrettNativeReadBoundary` before accepting the theorem. Static source/import
and Python verification checks can be run locally, but are not substitutes for
Lean elaboration. The agent must not advertise this as a compiler-verified proof.

## 2026-10-21 / next native read-boundary proof batch

Extended `proofs/GarrettNativeReadBoundary.lean` rather than creating a parallel
read interpreter. The added theorems target the `ManifestProvider::setup_route`
`Channel::new`, `send_manifest_bytes` -> `Channel::submit`, and native
`ManifestProvider::receive` -> `Channel::into_parts` seams visible in
`rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs`:

- `constructed_setup_implies_fresh`: a new, narrower adapter contract
  `SetupReturnsConstructed` (a witnessed returned `Channel.new` call) implies
  the existing `SetupReturnsFresh` hypothesis by reduction of the extracted
  actual constructor. Does not pretend that the unextracted native setup was
  machine-checked by Lean.
- `constructed_setup_locks_response`: before submission, the constructor's
  response handoff refuses `into_parts` with the concrete writer's
  invalid-transition result.
- `returned_postsend_read_has_exact_flushed_wire`: for every returned read
  classified `.Response` or `.Complete`, combine the existing chronological
  sound trace and current-issued stamp with an exact returned `Channel.submit`
  and derive the captured bytes, successful high-level `write_all` then
  successful `flush`, and response-handoff eligibility. No arbitrary ready
  flag, wire buffer, gate origin or trace split is supplied by the caller.
- `returned_send_failure_is_spent_and_cannot_retry`: source-owned `.Send`
  failures consume a fresh channel after one projected writer attempt,
  cannot release a response, and cannot retry a credential-bearing callback
  through the same channel even after partial write/flush failure.

The remaining narrowly named native contracts are: (1) successful native setup
really returns that `Channel.new` result, and (2) native send results are
identical to `Channel.submit` on the same state. In addition, proving native
`receive` calls `Channel.into_parts`, transitive `Write`/TLS/OS sink closure,
completion audit and guest-frame emission remains outside this batch.
A successful `write_all`/`flush` is neither proof of actual TCP delivery nor
an assertion of audit fsync/durability or whole-service noninterference.
This batch introduces no Rust behavior or production policy changes.

The maintainer accepted the preceding source-read boundary theorem after
focused Lean compilation; the added statements require their own focused
`lake build GarrettNativeReadBoundary` gate on the pinned toolchain.
