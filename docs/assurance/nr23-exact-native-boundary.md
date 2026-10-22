# NR-2/NR-3: exact native sink and guest-byte proof campaign

**Status (2026-10-22): uncompiled large Lean implementation candidate.**
The maintainer confirmed that the earlier five-module `GarrettNR23Assurance`
chain compiles. This document covers the **new** modules; these claims must
not be called verified until `lake build GarrettNR23ProductionBoundary`
succeeds on the pinned toolchain. The new package does not change production
Rust, credentials, TLS, AIVM configuration, or live authorization policy.

## The concrete gap this increment attacks

Earlier `GarrettNR23Effects.AllNativeAttemptsAccounted` was a **membership**
contract: every listed native attempt could cite *some* modeled send event.
This was not sufficient to rule out two real credential-bearing sends citing
one modeled send, or a reordered sequence of sends. Also, the modeled
`Event.providerSend` does not itself include the credential-bearing request
bytes handed to the native `write_all` callback.

The new modules strengthen the *conditional* model and connect more of the
actual Aeneas-extracted callbacks. **They do not discharge the main native
sink-closure assumption.** In fact, ordered equality in the new theorem is a
stronger runtime obligation that must be proved against the actual compiled
Rust process. Treat it as a review target, not as evidence already obtained.

## Read these theorem statements first

| Lean module / theorem | Derived fact | Remaining significant hypothesis |
| --- | --- | --- |
| `GarrettNR23ExactSinks.exact_sequence_implies_event_coverage` | An ordered, multiplicity-sensitive sequence of native sends implies the older membership coverage | `ExactNativeSinkSequence` is supplied, not derived from the process |
| `GarrettNR23ExactSinks.exact_sequence_has_no_extra_attempt_count` | Real-observation list length equals modeled provider-send event count under exact coverage | Complete observation and exact coverage |
| `GarrettNR23ExactSinks.no_modeled_send_has_no_native_attempt` | No represented source send implies an empty native attempt list under exact coverage | Exact coverage; no automatic proof of native absence of effects |
| `GarrettNR23ExactSinks.returned_request_has_exactly_accounted_authorized_native_sends` | From a returned actual extracted request, derive its trace, authorization/audit/binding, and, under exact sink coverage, exact ordered accounting | `NativeContext` source adapter identity and `ExactNativeSinkCoverage` of all actual native effects |
| `GarrettNR23WriterOrigin.fresh_returned_channel_exposes_exact_writer_bytes` | A returned fresh `Channel.submit` has one high-level writer callback using the captured `WireBytes` body, including write/flush error cases | Link the actual native writer implementation and concrete `ManifestWire` to the extracted `Channel` |
| `GarrettNR23WriterOrigin.actual_response_handoff_requires_write_then_flush` | Parser eligibility requires successful high-level write **and** flush of the captured request bytes | No TCP delivery or OS persistence guarantee |
| `GarrettNR23WriterOrigin.returned_failed_writer_cannot_replay_or_release` | A returned failed high-level submission spends the request and locks parser entry and same-channel replay | Different channel/process/restart, socket partial emission and crash recovery excluded |
| `GarrettNR23WriterOrigin.admitted_released_channel_pins_observed_native_payload` | Any native attempt externally linked to the same released channel carries exactly the captured writer bytes | `PayloadCorresponds` connects the native event to this precise channel; not proved from Rust callback graph |
| `GarrettNR23NativeRoute.*` | Actual extracted `Routed` dispatcher forwards one captured route to audit and setup and preserves route across current check, send, receive, prepare, configure, reserve and finish callbacks | Native `ManifestProvider` and `AuditState` implementations obey invoked route; their unextracted I/O effects remain external |
| `GarrettNR23GuestObservations.paired_successful_source_reads_prepare_same_guest_bytes` | Given equal **declassified encoded JSON bytes**, paired successful source completions prepare equal public guest bytes | Actual `Completed::into_value`/`serde_json` conversion, denial/reflection/timing/eof observations and declassification agreement |
| `GarrettNR23GuestObservations.failed_public_frame_is_single_attempt` | Failed frame sends do not permit same-frame retransmission | Partial transport delivery and channel recreation excluded |
| `GarrettNR23ProductionBoundary.accepted_read_has_exact_provider_attempt_accounting_and_guest_frame` | Composes returned source authorization and completion audit with exact native-send sequence and exact guest-frame bytes | Complete native coverage and exact native-to-JSON/frame conversion |
| `GarrettNR23ProductionBoundary.returned_denial_needs_separate_checked_public_frame` | Returned denial can only be asserted to produce a bounded frame by separately supplying its sanitized JSON and actual frame submission | Sanitization and `Error -> failure -> serde_json` code not yet formally linked |
| `GarrettNR23ProductionBoundary.selected_native_attempt_and_guest_frame_have_exact_captured_bytes` | Joins exact source trace coverage, selected native send payload, successful consumed channel and public output bytes in one statement | `PayloadCorresponds`, exact sink closure, callback and JSON conversion contracts remain crucial |

All theorems quantify only over the appropriate returned-call model; hanging
or aborted processes require separately specified effect prefixes.

## Source mapping and what the code-guard actually checks

- `rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs`:
  `Session::request` performs authorization before constructing the extracted
  request, `ManifestProvider::setup_route` canonicalizes the HTTP request and
  constructs the native channel, `send_manifest_bytes` calls
  `Channel.submit`, `ManifestProvider::receive` calls `into_parts` before
  parsing, and `audit_route` binds the operation and destination to its audit
  record.
- `rust/crates/aivm-secrets-garrett/src/custody.rs`:
  the audit append helper marks the sink failed before append, writes the
  canonical record and newline, calls the sink sync callback, and clears
  failure state only on returned success.
- `rust/crates/aivm-secrets-garrett/src/tls.rs`:
  verified guest peer, `Bridge::answer`, `GuestFrame::from_answer`, and
  `Frame::send` appear in the reviewed order; the native writer delegates
  frame bytes to `write_all` and then `flush`.
- `rust/crates/aivm-secrets-garrett-core/src/provider_io.rs`:
  the source-extracted channel consumes the request on attempt and enables
  `into_parts` only after a successful returned send.

`python dev/verification/nr23_native_edges.py check` checks **15 exact source
regions** for ordered anchors. It is an opt-in source drift detector. The
accompanying mutation tests demonstrate that removing or reordering specified
anchors breaks the guard. This check is **not** a semantic proof, exhaustive
call graph, Rust compiler certificate, audit durability argument, or an
invariant against code inserted between unchanged anchors. It is not wired
to normal developer tests or a slow default hook.

## What must still be discharged before unattended AIVM trust

1. **Concrete adapter semantics.** Prove `ManifestProvider::{setup_route,
   send, receive}` and `send_manifest_bytes` implement the extracted callback
   contract with the exact original channel, wire buffer, route, state and
   error outcomes. Prefer extracting an appropriately small Rust adapter
   helper into Lean over an unreviewable handwritten correspondence axiom.
2. **Transitive credential-bearing sink closure.** Prove the actual native
   observation list is complete for the defined startup profile and ordered
   equal to modeled send events. Enumerate dispatch, TLS handshakes, direct
   socket I/O, diagnostics, destructors, panics, error handlers and alternate
   backends; exclude only paths genuinely unreachable in that profile.
3. **Audit acknowledgement.** Relate the abstract acknowledged audit event
   to the concrete `AuditState` mutex, fail-stop append, successful `sync_all`
   and actual ordering before the provider attempt. OS power-loss durability
   remains an explicit dependency contract and cannot be inferred from a
   returned method call.
4. **Credential-bearing bytes.** Establish `ManifestWire` contains the output
   of the approved canonical provider request encoder and that the native
   `write_all` callback is the precise attempt represented by
   `PayloadCorresponds`. One high-level `write_all` can make multiple actual
   syscalls and fail after transferring an unknown prefix: do not claim one
   syscall, all-or-none delivery, or successful provider reception.
5. **Guest release and native errors.** Prove `Bridge::answer` and the actual
   `Completed::into_value`/`serde_json` conversions only produce explicitly
   permitted projection/denial data, that `GuestFrame::from_answer` receives
   that value, and the exposed status/frame/eof relation is exact. Do not
   silently omit error text, reflection decisions, lengths or close behavior.
6. **Adaptive observation relation.** Instantiate the existing W5
   `step_preserves` premise with native session executions, explicit permitted
   declassification agreement, and a reviewed definition of all guest-visible
   channels. Separate this NR-4 goal from the present one-run NR-2/3 proof.

The native `ExactNativeSinkCoverage` and `PayloadCorresponds` hypotheses are
**not acceptable as assumptions for a final whole-service confidentiality
claim** if the claim is meant to cover the full broker. They are current proof
obligations requiring extraction/implementation evidence. By contrast, OS,
TLS and cryptographic contracts may ultimately be external trust assumptions,
provided their precise scope is reviewed and they do not simply assert the
conclusion.

## Build and source guard

From the repository root:

```bash
python dev/verification/nr23_native_edges.py check
python -m pytest -q tests/test_nr23_native_edges.py
cd proofs
lake exe cache get
lake build GarrettNR23ProductionBoundary
cd ..
```

Compilation verifies the **formal theorem statements under their explicit
hypotheses**. The new code has not been compiled at authoring time because
Lean/Lake is unavailable in the authoring environment. The first full
compiler diagnostics should drive one consolidated fix overlay, not a
series of isolated one-line patches. Do not introduce Lean axioms or weaken
theorems to make compilation pass.

## Maintainer falsification checks

- If a second native credential-bearing send can occur without a separate
  source `providerSend`, `ExactNativeSinkCoverage` is false: the theorem is
  not a confinement certificate for that binary.
- If a native callback rebuilds the canonical request or swaps a route,
  `PayloadCorresponds`/primitive callback correspondence may be false.
- If an audit append returns success before the agreed durable stage,
  the abstract audit acknowledgment cannot be mapped to `sync_all`.
- If a provider or socket accepts a prefix and the Rust write fails, the
  request may have had an external effect despite a denied response; our
  failure theorem correctly describes a spent channel, not rollback.
- If `serde_json` or error handling emits a secret, equality of *selected*
  bytes in the paired guest theorem says nothing about that native leak.

**This campaign is intentionally not a final assurance signoff.**
