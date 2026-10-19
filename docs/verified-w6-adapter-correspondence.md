# W6: native manifest adapter / concrete event correspondence

The initial report below predates the local native validation recorded in
[dispatch freshness](verified-dispatch-freshness.md),
[coordination](verified-coordination.md) and
[identity rebinding](verified-identity-rebinding.md). Native binaries and
synthetic process workflows now run on the pinned local toolchain; this does
not close the whole-service correspondence obligations.

**Status: locally tested native adapters; full native trace refinement remains
open.** Frozen [frame admission validation](../dev/validation/2026-10-18-line-framing.json)
records the runnable native suite. The [authentication-line follow-up](verified-http-auth.md)
adds an extracted, kernel-checked byte leaf used by both provider writers.
The [request-line refinement](verified-http-request.md) additionally checks exact
method/target bytes and framing. The [complete encoder increment](verified-http-wire.md)
moves Host, standard/custom headers, decimal lengths and body bytes into the same
extracted core. Public-field conversion, JSON, parsers, TLS and native call-site
correspondence remain open.

The [newline framing follow-up](verified-line-framing.md) fixes native acceptance
of clean EOF without a terminal newline and hidden coalesced suffixes, sharing an
extracted validator across guest ingress, broker replies and the guest client.
Its stream/JSON/TLS and caller-placement boundaries remain explicit.

This milestone follows W4's finite source-controller trace and W5's conditional
information-flow relation. Both concern **modeled** events. W6 now checks
selected **concrete** TLS-provider sends, durable audit records, and guest
frames against the expected manifest effect for one request. These finite
observations are not a proof that all possible Rust executions refine W4.

The [2026-10-19 offline adapter increment](garrett-offline-adapter-assault.md)
adds Python and native Rust HTTP response framing checks, Python response-media
checks, raw local HTTPS reply fixtures, an exact-header/typed-body and
selected-result observer, and native negative/positive parser scenarios. The Python and pure-oracle tests have been
run locally. The newly authored native process scenarios still require a
pinned Rust build and have not been executed in that environment. These
changes do not strengthen the claims about whole-service reachability or
Rust-to-Lean I/O refinement below.

## Actual native boundary (the same executable used by the agent)

1. `Bridge::serve` receives a bounded JSON request over authenticated TLS;
   `Bridge::answer` verifies bound identity and chooses `Backend::Provider`.
   Guest forwarding through Python is a **different backend**, never a native
   fallback. `manifest::Session::request` opens the inner credential, parses
   one host-approved operation, and invokes the extracted `manifest::authorize`.
2. The policy compiler creates a preflight effect, if needed, and a final
   effect from checked facts. `PreparedDispatch` tags them. Both enter the
   same closure, which checks reflected targets, writes a durable `dispatch`
   audit record, rechecks grant/peer freshness, and invokes
   `Executor::exchange_manifest`. A preflight **also uses the credential**.
3. W6 extracts the **actual outgoing HTTP bytes** into
   `manifest_request_bytes(route, credential, effect, headers)`, a pure
   zeroizing encoder called **before `TcpStream::connect_timeout`**. It checks
   the selected host, target, method, Accept, body limit, custom-header
   syntax, reserved-header collisions (including case-insensitive duplicates),
   and credential bytes. This last check covers OAuth-provided `Credential`
   instances not constructed through `credential_at_least`.
4. The adapter makes one pinned-address TCP connection using rustls with the
   host-selected DNS name and CA. It sends one origin-form HTTP request, with
   one bearer/API-key authentication header; no redirect or proxy client is
   involved. The response parser refuses malformed headers, conflicting
   transfer framing, unsupported encodings and the unmodeled `206 Partial
   Content` success case. It bounds the response body and parses JSON/text.
5. The release path runs the existing schema-directed projection, checks
   literal credential reflection, and only returns success after a durable
   `completed` audit. `GuestFrame` writes the resulting canonical JSON line
   or a bounded fixed error. Renunciation emits its own host audit event.

Rust unit tests in `manifest_session::wire_tests` check byte-level request
framing, reserved/injected headers, bearer credential placement, target
validation, body length, valid response framing, redirects, partial responses,
conflicting lengths and compressed/unapproved media. These tests exercise the
**same encoder and parser called by the production executor**, not a retyped
Python model of their implementation.

## Runtime observation/negative test contract

`tests/secrets_w6_trace.py` independently compares:

- the **planned effects** of the declared manifest (using the existing Python
  policy compiler as a reference oracle, not a Python broker fallback);
- HTTPS server-observed method, target, host, headers, authorization and body;
- host audit `dispatch` phase, request digest, route and completion;
- decoded guest success/denial JSON with no secret or raw provider fields.

`tests/test_rust_w6_adapter.py` runs the native bridge and native client in
separate processes with synthetic credentials. It tests authorized GitHub PR
view/diff/checks, arbitrary/other-PR denials, renunciation, checked-fact
mismatch, credential reflection and malformed/redirect/partial/compressed/
ambiguous upstream HTTP. It also poisons `HTTP_PROXY` and `HTTPS_PROXY` to
check that the native provider adapter does not silently use environment
proxy routing. Those tests **must not be reported passing** when native Rust
executables are unavailable.

The `assert_native_effect_trace` observer deliberately handles only a
nonconcurrent finite request at a time. It uses after-the-fact records and
cannot by itself establish actual cross-channel scheduling, crash ordering,
TLS peer authenticity, audit durability under power loss, or transitive
completeness of I/O. A passing test supports an observed scenario, not a
universal trace refinement. The source guards catch some known bypass edits;
they are not sound static program analysis.

## Reviewed channels and unresolved premises

`docs/planning/aivm-secrets-w6-adapters.json` classifies **all eleven** W0
sinks, links them to Rust code, W4 modeled events (or exclusions), concrete
tests and assumption-ledger IDs. The three principal primary-scope sinks are
provider HTTPS, host audit and guest frame. Guest connection closure is an
observable additional channel (not covered by W4's `guestReply/guestDenied`);
startup stdout/stderr, storage, operator endpoints, OAuth startup and legacy
Unix forwarding have separately named trust boundaries.

The following are **not discharged** by W6:

- A verified total abstraction function from native socket/file effects to
  W4/W5 traces, or a mechanized proof of all `manifest_session` paths;
- sound interprocedural completeness for Rust/Cargo dependencies and panic,
  allocator, OS/network and concurrency behavior;
- TLS/CA/crypto, host filesystem `sync_all` durability and isolated principal
  correctness, which remain assumptions until separately evidenced;
- guest-visible timing, close/error/length and literal-reflection oracles;
- semantic leakage through provider-controlled but authorized result fields;
- all-input refinement of the remaining native request/parser/render adapters;
- live GitHub and AIVM virtualization evidence (W7/W8).

## Focused acceptance commands

From the repository root, after applying W0-W5 and this overlay:

```bash
python dev/verification/w3_effect_boundary.py check
python dev/verification/w6_adapter.py check
python -m pytest -q tests/test_secrets_w6_adapter.py

cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
    -p aivm-secrets-garrett --lib wire_tests
cargo +nightly-2026-09-17 build --manifest-path rust/Cargo.toml --bins

AIVM_SECRETS_RUST_AUTHORITY_ADMIN="$PWD/rust/target/debug/garrett-authority" \
AIVM_SECRETS_RUST_GARRETT_BRIDGE="$PWD/rust/target/debug/garrett-bridge" \
AIVM_SECRETS_RUST_GARRETT_CLIENT="$PWD/rust/target/debug/garrett-client" \
python -m pytest -q -ra \
    tests/test_rust_w2_github_workflow.py \
    tests/test_rust_w5_noninterference.py \
    tests/test_rust_w6_adapter.py
```

Review failures before claiming a completed W6 acceptance gate. No AIVM VM,
real provider credential or external service is needed for the local tests.

## JSON object preservation follow-up (2026-10-18)

The independent primitive corpus exposed a concrete adapter mismatch with
Serde's enabled `arbitrary_precision` / `raw_value` features. Generic `Value`
deserialization recognizes internal marker keys. A guest object such as
`{"$serde_json::private::Number":"7"}` could become the integer `7`; the analogous
RawValue marker could reinterpret a string as another JSON value. Checking
syntax, duplicates and depth before a generic second decode did not preserve
the already-checked JSON types.

The native decoder now constructs object and array values explicitly while
retaining duplicate, Unicode, finite-number, depth, byte and integer-digit
checks. Scalar strings/numbers use their typed deserializers; marker keys are
ordinary data. The independent primitive adapter preserves frame payloads the
same way. This is a codec implementation change, not a change to accepted
policy types or authorized destinations.

Two native unit regressions and four real process regressions reproduced the
old behavior. Against the preceding normal release binaries, marker objects
were accepted as guest ticket arguments and as provider integer disclosure
fields. With the fix, malformed typed guest arguments cause zero provider
requests, and object-valued provider fields cannot satisfy integer disclosure.
Both marker spellings are exercised. The combined W6/primitive/freshness native
selection passes 40 tests. A W3 deliberate bypass edit also restores the unsafe
generic decoder after updating its source fingerprint; the structural guard
must still refuse it. That guard is a targeted regression check, not a parser
proof or an exhaustive ban on all alternative decoders.

No claim of credential theft, whole-service noninterference or full parser
refinement follows from these cases. The production byte parser remains a
concrete adapter obligation; the extracted Lean controllers are unchanged.

## Host operator coordinator channel

The inventory now separately classifies `S-COORDINATOR-ADMIN`: host-only mTLS
activation/revocation/status, fixed typed receipts and conservative post-send
mutation uncertainty. The member channel's scope is unchanged. Evidence in
`tests/test_coordinator_operator.py` includes real commit-then-drop faults,
independent clients/servers, typed public reply vectors, native restart and
fencing of running native brokers. The extracted receipt gate does not refine
JSON/TLS, pre-send/post-send placement or remote SQL commit. Those premises are
named by `COORD-OPERATOR-RUST-01`; the W4/W5 guest trace excludes these privileged
observations. No complete mediation or whole-service correspondence follows.

## 204 end-of-headers correction (2026-10-19)

After the prior HTTP-framing hardening and correction of the synthetic 204
server, the maintainer's full native suite still failed
`test_empty_write_reply_obeys_explicit_response_type[text]` (2,750 passed,
one failed). The production Rust `manifest_response` read for transport EOF
*after* the 204 header terminator. HTTP 204 has no response body and ends at
that terminator; TLS EOF/`close_notify` is not a valid prerequisite to accept
an otherwise well-framed 204. The parser now leaves the body empty without
further reads. Text operations release the projected empty string; JSON
operations reject the empty body. Framing-field rejections stay in place.

Added a native unit reader that delivers a complete 204 over a connection
that never returns EOF, plus an explicit check that any trailing data is not
released as guest text. The W6 source guard mutation test detects restoring
an extra read in this branch. This changes acceptance of 204 replies that
lack clean connection shutdown but does not broaden credential-bearing
outbound effects. These additions remain unexecuted as native tests in this
environment; the maintainer's next Rust/full-system run is required.
