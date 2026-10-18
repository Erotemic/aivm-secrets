# W6: native manifest adapter / concrete event correspondence

**Status: candidate implementation and test oracle. Not whole-service formal
refinement.** Rust unit tests and native subprocess tests require a successful
pinned-toolchain run on the maintainer's host. The Python source guard, oracle
negative controls, and structural regression tests pass in the authoring
container; native tests are skipped here because binaries are absent.

This milestone follows W4's finite source-controller trace and W5's conditional
information-flow relation. Both concern **modeled** events. W6 now checks
selected **concrete** TLS-provider sends, durable audit records, and guest
frames against the expected manifest effect for one request. These finite
observations are not a proof that all possible Rust executions refine W4.

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

`docs/planning/aivm-secrets-w6-adapters.json` classifies **all ten** W0
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
- native Rust execution and Rust unit gates in this authoring environment;
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
