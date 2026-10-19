# W3: native Rust manifest effect-boundary review

This document preserves the initial review snapshot below. Later native builds,
workflows and extracted-controller results are recorded in
[dispatch freshness](verified-dispatch-freshness.md),
[coordination](verified-coordination.md) and
[identity rebinding](verified-identity-rebinding.md). The current machine-readable
inventory is authoritative for source counts. The optional
[compiler call-site ledger](native-call-ledger.md) now supplies structured
candidate paths, with callbacks, dependencies and drop/unwind still unresolved.
It does not close the exhaustiveness obligation described below.

**Status:** Initial source audit and narrow refactor authored. Not a
complete-mediation proof, a verified whole-service call graph, a Lean theorem,
or an I/O adapter correctness result. The changed Rust sources need a successful
pinned-toolchain build and maintainer security review. W4 and W6 remain open.

## Scope and source record

The primary scope is **`manifest-https-v1` only**. The machine-readable
`docs/planning/aivm-secrets-w3-reachability.json` maps 11 effect classes to
W0 sinks, entry paths, constructor sites and concrete interpreters. It pins
all 61 repository-owned Rust source and workspace build files in this snapshot,
excluding Cargo-generated `rust/target/` and nested package `target/` trees. A
normal Rust build must not invalidate the source review inventory. It still
requires re-review of new untracked repository-owned Rust modules, including
adjacent profiles and operator-only code, not just files containing `write_all`.
`python dev/verification/w3_effect_boundary.py check` demands an explicit
review/update when any pinned Rust file changes and tests several risky
bypasses after allowing an updated fingerprint. It is not a compiler,
whole-program call-graph analyzer, or evidence that external dependencies
conform to these local source contracts.

| Path | Constructed effects | Concrete interpreter / sink |
| --- | --- | --- |
| `Bridge::serve` + `answer(request)` → `ProviderSession::request` → native `Session::request` | `Policy::preflight` and `Policy::final_effect` create host-selected `Effect` values, wrapped as `PreparedDispatch::{preflight,final_effect}` | Single `dispatch` closure checks target reflection, acknowledges host audit, revalidates grant, then calls `Executor::exchange_manifest` → provider HTTPS |
| Native successful request | `Disclosure::project`, allowed pagination metadata, final reflection check and completion audit | `GuestFrame::from_answer` → one `GuestFrame::send` TLS serializer |
| Invalid frame, deny, failed provider/parse/audit | `Error::code` + bounded `tls::failure` message | Same `GuestFrame` writer; error code/closure/length remain guest observations |
| `answer(describe)` | Current grant + public operation names/write mode | Same guest frame, no credentialed provider dispatch |
| `answer(renounce)` | Current grant + host audit acknowledgement + inactive grant | Same guest frame, no provider dispatch after completed renunciation |
| Startup and issuance | Host-selected registry, keys, certificate identity, policy, OAuth snapshot and outer capability | Host-only filesystem/authority, optional OAuth token endpoint, `bridge_main` startup stdout |
| Legacy `Backend::Socket` | Host-selected forwarded request with opened inner capability | `Bridge::forward` to protected Python broker Unix socket, **not** a native fallback |
| Fixed `account-status-v1` | Separate credential-use controller | Separate `Executor::exchange`, not covered by primary manifest claim |

A native request can produce **two provider sends**, because the metadata
preflight is itself credentialed. The route, API host/TLS peer, method, selected
Accept and request body are decided by the host manifest and bound inputs;
client input only supplies declared operation arguments. Returned preflight
facts must satisfy requirements and checked captures before the final effect
is compiled. For checked-facts-only results, a fresh authorization check still
precedes releasing selected metadata even with no final dispatch.

## Boundary refactor

- `custody/manifest_session.rs` now has one private, phase-tagged
  `PreparedDispatch` vocabulary and **one** call site into credentialed
  `exchange_manifest`. Both preflight and final effects use the same target
  check, durable audit and fresh binding/authorization check. `PreparedDispatch`
  is not a proof-carrying authorization witness; code review, W4's extracted
  transition proof and W6's adapter refinement must establish those facts.
- `tls.rs` now has a single `GuestFrame` writer for native and adjacent bridge
  replies/errors. This centralizes observable serialization; the wrapper can
  still carry a value returned by a faulty backend, so disclosure correctness
  is **not** established by its Rust type alone.
- `manifest/disclosure.rs` accepts bounded, explicitly declared camelCase
  **public output keys**, needed for GitHub `headRefOid`; it does not relax
  operation/argument identifiers or permit additional provider fields. The
  W3 source fingerprint is updated for this parser review. The disclosure
  projection and reflection-rejection logic remains the same, with Rust unit
  coverage for selection, malformed keys and reflected credentials.
- `client_alias.rs` is guest-owned presentation only, pinned in the source
  inventory. It cannot grant an operation; the host manifest must authorize
  every translated command independently.

The W3 source checker also requires reviewed authorization/policy/response
markers, the ordering of audit/freshness before provider I/O, approved
projection before guest release, and a single credentialed HTTP adapter in
the native manifest module. Six deliberately introduced source bypasses were
rejected even after regenerating affected SHA-256 hashes: direct unchecked
exchange, deleted freshness check, raw disclosure, token diagnostics, direct
guest write, and raw error diagnostic. Additional checks detect changed Rust source, newly added
repository-owned Rust modules, and omitted sink classes. Cargo-generated Rust
sources are excluded by regression tests. These are **regression guards** against
known edits, not proof of absence of other ways to bypass the boundary.

## Unproved or deferred obligations

1. **Exhaustiveness:** The call chains above are manually inspected source
   paths, not the output of a sound interprocedural reachability analysis.
   External crates, callbacks, TLS error paths, panics, concurrency and future
   dynamically introduced modules need additional W6 review. Pinning local
   files does not prove the full I/O graph is closed.
2. **Concrete adapters:** HTTP parsing/serialization, TLS peer binding,
   filesystem permissions, audit durability, redirect/proxy absence and
   `GuestFrame` bytes need I/O refinement or explicit versioned assumptions.
3. **Data releases:** Typed projection constrains structure, not semantics of
   selected provider strings. Literal credential reflection detection is not
   a noninterference theorem; error/closure and `possibly_more` remain
   observable declassifications requiring W5 analysis.
4. **Other profiles:** Legacy forwarding, fixed account reads, operator
   administration, OAuth token requests during host startup, host stdout,
   logs, storage and executable startup have different observers and release
   rules. They cannot be imported into the native manifest claim without
   additional lemmas, checks and environmental premises.
5. **Build and proof:** This W3 source refactor has no new Lean extraction,
   verified Rust build, compiler-to-machine-code correspondence, or tested VM
   isolation in the overlay-creation environment. Do not claim W4/W6 passed.

To review this source snapshot:

```bash
python dev/verification/w0_contract.py check
python dev/verification/w3_effect_boundary.py check
python -m pytest -q tests/test_secrets_w3_effect_boundary.py
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml
```

When intentionally changing Rust code, audit the sink set and new call paths,
update `docs/planning/aivm-secrets-w3-reachability.json` source hashes only
after review, add an adversarial test for changed authority or release
semantics, then execute the checker. The hash list is a **review checkpoint**,
not a claim of formal provenance.

## W6 refinement checkpoint (2026-10-17)

The reviewed `manifest_session.rs` source now routes actual outgoing HTTPS
bytes through `manifest_request_bytes`, a zeroizing pure encoder executed
before socket creation. Additional defenses reject malformed OAuth credential
bytes, ambiguous injected headers, unsafe request targets, and unmodeled 206
partial responses. The W3 source inventory has been deliberately refreshed.
See [W6 adapter review](verified-w6-adapter-correspondence.md) for concrete
unit tests, finite runtime-trace checks and still-unproved assumptions.

## Explicit host coordinator control

The separate `garrett-coordinatorctl` / `coordinator_admin::Client` path adds an
operator-only effect class and `S-COORDINATOR-ADMIN`. It reuses the member TLS
transport, but selects only activate/revoke/status from a private host config.
The primary member sink still forbids those operator actions; guest handlers do
not invoke the operator wrapper. Typed receipt validation and phase-specific
operator errors are source-guarded, including deliberate bypass edits. This
inventory/review is not a transitive call-graph or complete mediation proof.
See [operator control](native-coordinator-control.md) for concrete tests and the
separate extracted receipt theorem; remote commit and transport refinement stay
explicit obligations.

## Offline HTTP parser review checkpoint (2026-10-19)

The reviewed `custody/manifest_session.rs` manifest response parser rejects
close-delimited non-204 2xx successes and forbids Content-Length /
Transfer-Encoding on 204. A bodyless 204 still produces empty text but
not JSON. These checks happen after the selected credentialed provider send
and before parsing, disclosure or guest release. There are no new outbound
effect constructors, destination choices, credential-bearing request writers
or guest serialization sites. The exact-source SHA-256 fingerprint in the W3
inventory has been refreshed after this focused review; the W6 checker also
pins the relevant framing guards. Neither structural check proves reachability
completeness or the correctness of Rust code generation. The new Rust source
and tests have **not** been built on a pinned toolchain in this environment.

## Follow-up: 204 cannot depend on TLS EOF (2026-10-19)

The 204 text path previously read one byte through `read_to_end` after the
HTTP header terminator to check for a stray body. That makes a successful,
header-terminated 204 depend on a clean TLS EOF; a peer may keep the connection
open or close without TLS `close_notify`. The full native integration run on
2026-10-19 reached 2,750 passing tests but failed the text/204 write case.

The native parser now returns empty text directly after validating the 204
headers. It still refuses `Content-Length` and `Transfer-Encoding` on 204,
refuses close-delimited non-204 success, and refuses empty JSON. Any bytes
following a 204 header terminator are not interpreted or released as text;
the provider TLS connection is not reused for another request. Requiring EOF
to reject such extra bytes is incompatible with 204 framing and cannot be a
reliable discriminator across network segmentations.

The W3 manifest source fingerprint was refreshed after this bounded change;
the W6 structural guard now explicitly refuses reintroducing an EOF read to
the 204 branch. The new native unit regression simulates a provider that
never signals EOF. This is a source-reviewed repair, not a proof of upstream
TLS semantics or full native-to-Lean refinement; rerun the Rust integration
test and full gate on the maintainer toolchain.
