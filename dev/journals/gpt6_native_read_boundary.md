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
