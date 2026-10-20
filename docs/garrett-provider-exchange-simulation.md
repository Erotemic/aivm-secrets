# Production provider continuation and conditional simulation

The native manifest executor now calls the extracted Rust
[`provider_exchange::exchange`](../rust/crates/aivm-secrets-garrett-core/src/provider_exchange.rs).
The driver separates verified TLS setup, the last current-authority check,
credential-bearing submission and response parsing. It returns the exact
phase, sampled admission stamp and terminal stage alongside the original
result. This advances the provider component of NR-2; it does not complete
native request/history simulation or W3/W6 transitive I/O correspondence.

## Running path

`Session::request` still performs authentication, authorization, approval and
phase-specific dispatch audit before invoking the provider executor. Its
private `AuditedDispatch` carries the existing extracted audit permit. The
executor checks the effect's write flag against that permit, then constructs
one private `ManifestProvider` and invokes the core driver.

| Driver primitive | Native implementation | Boundary |
| --- | --- | --- |
| `setup` | Reviewed request encoder, pinned TCP address, verified server-name TLS handshake and existing 40-second watchdog | Produces a private channel containing the stream, zeroizing request bytes and live deadline. No credential-bearing HTTP submission occurs here. |
| `recheck` | Existing coordinator, host revocation, OAuth lease, peer/surrogate/time and manifest guards | `manifest::current` calls the unchanged `authorize` decision and returns an opaque `AdmissionStamp` with its exact sampled time, elapsed time and operation write flag. |
| `send` | Private `send_manifest_bytes` | Requires the native `SendState` gate, then calls `Write::write_all` and `flush` on the reviewed bytes. Partial acceptance or flush failure is still a submission attempt. |
| `receive` | Existing bounded HTTP parser, media/framing checks, JSON/text conversion and GraphQL error handling | Consumes the updated channel; provider data still goes through the existing disclosure/completion path afterward. |

The native writer owns a source-extracted `SendState`. Its progression is
empty → checking → checked stamp → attempted stamp. Rejected early operations
halt it; operations after an attempt retain that attempt and cannot re-arm a
send or replace its stamp. The helper checks this gate before the actual Write
primitive. Failed current checks cannot supply a stamp. The state contains no
credential or provider value, allocates no log, and is never sent to the guest.
It supplies a concrete recorded-attempt projection for the simulation; a
read-only shallow adapter record would not suffice for a growing trace.

A stamp is **not an authorization token on its own**. The enclosing native
adapter binds it to its captured identity, grant, selected operation and host
route; the simulation states this context explicitly. Its validity refers to
the sampled check, not an atomic transaction with a later syscall. No cached
stamp, unavailable-coordinator fallback or automatic retry is introduced.

Setup/current errors keep their pre-send errors. Read send/parser failures
keep the existing public error classification. Any write send/parser failure
remains `OutcomeUnknown`, including zero-byte failure, partial acceptance and
flush failure. The driver rejects a writing effect supplied only a read-only
stamp. A read preflight for an admitted writing operation remains supported.
No wire version, stored schema, credential source or runtime dependency changes.

## Checked result

[`GarrettProviderExchange.lean`](../proofs/GarrettProviderExchange.lean) checks
22 named results: the stamp's exact relation to the real admission decision;
an all-returned-run characterization of the real read driver; exact failure
prefixes, positive read witness, updated adapter/channel state and write
uncertainty; and the native send gate's construction, admission and terminal
single-attempt properties. `ReadRun` is a relating predicate over actual
callback returns, proved equivalent to the extracted function. It is not a
second executable Rust/Lean request interpreter.

[`GarrettProviderSimulation.lean`](../proofs/GarrettProviderSimulation.lean)
checks eight further results. `Context` and its binding projection name the
claims, grant identity, operation, route and policy inputs. `Issued` is equality
to the actual `manifest::current` constructor, whose guard is already extracted.
The resulting `Gate` uses the returned stamp's sampled clocks. The simulation
threads exact mutable callback/channel states; its returned trace extension
has zero or one provider-attempt event, including failed sends and failed
responses. It preserves the stated binding and composes with a previously
sound observed prefix. Another theorem starts with actual `prepare` and
`acknowledge` results, relating the same audited phase to the driver. Source
send-state lemmas relate its concrete attempt mark to the modeled event and
show that a rejected repeated send retains the first mark.

The four primitive `Contracts` are explicit local obligations. Setup and current
checking preserve the projected provider trace; a successful current check
establishes the ready state and stamp origin; a ready send extends the trace
once **regardless of its return status**; receiving preserves that projection.
Native `SendState` makes this recorded projection realizable. Establishing the
full relation between these marks and native I/O, and excluding extra effects,
still requires the native primitive/world contract and NR-3 review. The theorem
does not assume the whole controller conclusion or an arbitrary
`providerReached`/`auditOK` flag. It also does not prove syscall behavior from a
result equality, or count effects merely from a provider's successful arrival.

The focused development checker is non-core; it adds no Python broker API:

```bash
.venv/bin/python dev/verification/provider_exchange.py
.venv/bin/python dev/verification/garrett.py mutate --mutation-filter '^provider (driver|native gate|current stamp)'
cargo test --locked --manifest-path rust/Cargo.toml -p aivm-secrets-garrett-core
.venv/bin/python dev/verification/quick_w6_read.py --native --build
.venv/bin/python dev/offline_native_guest.py
```

The default verifier compares fresh pinned Charon/Aeneas output, compiles the
two modules and audits all 30 named results. `--no-regenerate` is only for local
proof iteration. No standard model was changed. Core tests inject every
returned failure stage; native unit tests use the actual guarded Write helper
with zero-byte/partial-write/flush failures and reject a second submission.
The targeted Rust mutations include ignored raw setup/send calls, sending
before current admission, lost uncertainty, repeated-send permission and
stamp construction without authorization. Required native tests still need
to pass; source guards and theorem-name inventories cannot substitute for them.

The [request-wide receipt increment](garrett-request-effect-receipts.md) adds
actual shared audit/completion markers, a composite request/local send gate and
conditional returned-request composition. The earlier provider theorem and
primitive contracts remain in force; full event/history composition stays open.

## Still open

- The primitive bridge from native audit acknowledgements, `SendState` marks,
  actual TLS application-write attempts and parsed provider outputs to the
  callback contracts. The private Write primitive is reviewed and tested;
  std/rustls semantics, context conversion and no-extra-effect claims are not
  extracted native I/O theorems.
- All non-returning, panic, drop/unwind, timeout-worker, dependency and transport
  prefixes; partial network delivery remains ambiguous. A marked Write attempt
  is not a claim that the provider received a complete request.
- Composition through all three complete request shapes, audit refusal,
  disclosure, completion-audit acknowledgement followed by late denial, guest
  frame emission and connected sequential/adaptive session histories.
- NR-3 reachable sink closure, NR-4 actual observation correspondence and NR-5
  independent review, plus real-provider and deployed compartment validation.

These limits retain the original restricted read-only/sequential target. They
do not establish whole-service secrecy, physical TPM provenance or VM isolation.

The [validation record](../dev/validation/2026-10-20-provider-exchange.json)
freezes source `e2cd788`: 3,005 full-suite cases without skips, 463 named
Garrett axiom audits, all 30 focused provider obligations after regeneration,
six selected mutants rejected, both native product build modes, six safe
installed-device cases and identical archive bytes for all 259 source pins.
This validates only the listed scopes and assumptions above.
