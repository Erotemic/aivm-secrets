# Reading the native read-security proofs

**Maintainer guide — initial state, 2026-10-21.** This document explains what is proved, what is conditional, and how to inspect the result. It is **not** a whole-service verification certificate. The overnight formalization agent must update it only when the linked theorem and source evidence actually change. The [overnight campaign](../planning/aivm-secrets-overnight-formalization.md), [W0 security contract](../planning/aivm-secrets-conditional-confinement.md), [native read roadmap](../planning/aivm-secrets-native-read-assurance-roadmap.md), and [assumptions](../planning/aivm-secrets-assumptions.json) control scope.

## What you are trying to trust

A guest is malicious and may send arbitrary framed requests, select allowed arguments adaptively and retry after errors. A trusted host owns provider tokens, configured operations and result projections. The intended **read-only** contract has two halves:

1. **Effect confinement:** every *credential-bearing attempt* to contact a provider follows a permitted request, a bound current authority decision, an appropriate earlier acknowledged host audit, and exact host-selected destination/request bytes. Denied requests must not bypass the broker and cause a secret-bearing send.
2. **Information-flow confinement:** the guest learns only explicit allowed result fields and observable status/metadata; changing host-private secrets without changing permitted declassifications must not change the stated guest observation history.

The first part is a one-run, all-events property; the second compares two possible runs under a defined relation. Neither proves the cryptographic library, kernel, VM, or GitHub semantics correct. A credential necessarily reaches its **authorized HTTPS provider**; the claim is that it does **not** reach the guest or an unauthorized sink.

A successful allowed read is required as a **non-vacuity witness**. The maintainer has already run host native, synthetic and adversarial real KVM, and real GitHub read-only scenarios successfully. Those are strong integration tests, but sampled runs do not replace the quantified source-to-I/O theorem.

## Existing proof chain, in ordinary language

| Proof | How to read its implication | Important condition still external |
| --- | --- | --- |
| [`GarrettDispatchTrace.lean`](../../proofs/GarrettDispatchTrace.lean) | A returned execution of the extracted `dispatch.dispatch` has a chronological modeled trace related to its source-owned receipt transitions | It has not by itself proved every real OS/TLS effect of a `Session::request` |
| [`GarrettNativeWriterEvents.lean`](../../proofs/GarrettNativeWriterEvents.lean) | A returned extracted `Request.submit` invokes an exact high-level callback pattern: no callback on replay; write on fresh attempt; flush only after successful high-level write | One `write_all` can make multiple system calls and accept some bytes before returning error; no delivery guarantee |
| [`GarrettNativeDispatchEvents.lean`](../../proofs/GarrettNativeDispatchEvents.lean) | When the returned dispatch and returned channel are linked at the **same** `begin_send` gate, the writer callback projection agrees with a single sound W4 provider-attempt event | `beforeTrace`, `after`, checked stamp origin, channel freshness and returned callback binding must still be supplied from the actual adapter invocation |
| [`GarrettReadPaths.lean`](../../proofs/GarrettReadPaths.lean) and [`GarrettReadPrefixes.lean`](../../proofs/GarrettReadPrefixes.lean) | Models selected read paths, denials and audited-but-unsent prefixes using existing extracted controllers | Total reachable guest entry, all callbacks and actual frame emission not yet closed |
| [`GarrettNoninterference.lean`](../../proofs/GarrettNoninterference.lean) | An adaptive sequence preserves observational equality **if every paired step satisfies `DeclassificationAgreement` and preserves related private state** | The native implementation has not yet supplied that `step_preserves` proof; equal approved outputs and error/reflection status cannot simply be assumed without review |

This is why **a Lean file compiling is not sufficient evidence for the broad security claim**, even though compilation is sufficient to accept that its *stated* theorem is proved: the theorem can have hypotheses that the native system has not established. The question is whether those hypotheses are precise external contracts, source-proved facts, or an accidental restatement of the security goal.

## First source-owned read-driver/writer composition (new increment)

**The maintainer accepted the initial `GarrettNativeReadBoundary` proof after
its scoped-index binder correction and focused Lean build. The subsequent
post-send/terminal-failure extension below is a new proof increment and
requires its own focused build.**

[`GarrettNativeReadBoundary.lean`](../../proofs/GarrettNativeReadBoundary.lean)
introduces two related statements using the **actual extracted**
`provider_exchange.exchange`, bound `current_admission.Context.current`,
`dispatch.Pending` and `provider_io.Channel.submit`:

1. `rejected_before_send_keeps_receipt`: an exchange returning at `.Setup` or
   `.Admission` leaves the request-wide receipt unchanged, keeps the fixed
   context and reports no current stamp. The native primitives themselves may
   still have external setup/clock/TLS effects, so this does **not** certify
   absence of every network or filesystem effect.
2. `returned_attempted_read_has_checked_writer`: for any *returned read
   exchange* classified as attempted, its sound chronological receipt trace
   and route/operation binding follow from the **source-owned** dispatcher;
   its current stamp is issued by the bound source check; and the real native
   writer has a `write_all` callback (with optional `flush`), projecting one
   provider attempt. This includes returned send errors, response errors and
   complete responses; setup/admission failures cannot satisfy the attempted
   premise.

**Premises removed compared with a caller-assembled writer segment:** no
`beforeTrace`/`after` event lists, hand-supplied `checkedOrigin` or matching
stamp, arbitrary marked `begin_send` success, or independent `providerReached`
flag. The caller provides an actual returned `exchange` invocation, a reachable
initial receipt and `Stage.attempted = true`. Two **narrow native adapter
obligations** remain:

- `SetupReturnsFresh`: an actual successful `ManifestProvider::setup_route`
  gives a new unspent `Channel`, not a previously used channel;
- `SendsThroughChannel`: the actual returned `ManifestProvider::send` call
  delegates to the same `Channel.submit`, preserving its returned result and
  post-state.

Both are explicit premises pending linkage to the non-extracted Rust
`custody/manifest_session.rs` factory and `send_manifest_bytes`, **not**
trusted Lean axioms or assertions of whole-service mediation. The new theorem
relates an attempted read to both a sound source receipt history and the
corresponding source-owned callback path; it does not yet assert an exact
position of that callback's event in the history or prove that no other
credential-bearing I/O path exists. Actual `std::io::Write`, rustls/TCP,
completion audit, guest frames and non-returning paths remain unclosed.

**Falsifier:** if the manifest adapter can supply an already-attempted channel
at setup, bypass `Channel.submit` from `send`, or dispatch secret bytes through
another sink, the external contracts or the desired global guarantee fail.
The returned-read theorem by itself cannot rule those out.

## Next native response and failure-boundary proof batch

The extended [`GarrettNativeReadBoundary.lean`](../../proofs/GarrettNativeReadBoundary.lean)
now contains four additional statements. They are deliberately attached to
the same source-extracted `provider_exchange.exchange` execution rather than
a second handcrafted trace interpreter:

| New theorem | What it establishes | What it **does not** establish |
| --- | --- | --- |
| `constructed_setup_implies_fresh` | The extracted `Channel.new` constructor starts the captured request unspent; a returned native `setup_route` result shown equal to that constructor result discharges the original freshness premise | The unextracted native TLS factory always returns that shape; this remains a narrow implementation-to-constructor contract |
| `constructed_setup_locks_response` | A newly returned channel cannot release its response stream before sending; `Channel.into_parts` refuses the return | The native response parser always goes through `into_parts` |
| `returned_postsend_read_has_exact_flushed_wire` | A returned `.Response` or `.Complete` read has a sound source receipt trace, an issued current stamp and a same-state `Channel.submit` that read the exact captured bytes, succeeded at high-level `write_all`, and succeeded at `flush` before the channel became parser-eligible | Peer delivery, syscall segmentation, TLS correctness, post-send completion audit or selected guest frames |
| `returned_send_failure_is_spent_and_cannot_retry` | A returned `.Send` failure consumes a fresh request, locks the response handoff, and a repeat `Channel.submit` has no new writer callback even if the first attempt partially emitted bytes | Exclusion of *other* native send paths or crash/snapshot rollback restoring an earlier channel |

**Source inspection points:** `ManifestProvider::setup_route` ends in
`Channel::new(request, ProviderWriter(stream), deadline)`;
`send_manifest_bytes` calls `Channel::submit`;
`ManifestProvider::receive` calls `into_parts` before parsing. The first two
are still **native adapter contracts** in these theorems because the native
TLS/`std::io::Write` layer is not in the Aeneas extraction. The `receive`
linkage is not yet proved either. A proof of the extracted constructor does not
by itself prove that every native setup returns through that constructor.

**Falsifiers for this batch:** a native alternative setup returning a recycled
channel; a send shim bypassing the source-owned `Channel.submit`; direct native
parsing that bypasses `into_parts`; or an independent credential-bearing native
socket. All would require revisiting the implementation contracts, even if
the new extracted-core Lean proofs compile.

This increment moves the request boundary forward to *eligible response bytes*
and *failed-send replay behavior*. The next priority remains native adapter
closure, transitive I/O sink reachability and the completion/guest-frame
simulation. These are prerequisites to native adaptive noninterference.

## Walk through one intended provider attempt

```text
Malicious guest request (native TLS endpoint)
    |
    v
Session::request + host manifest + current identity/admission
    |
    v
Audit::write_record returns acknowledgment
    |
    v
RequestEffects::begin_send consumes checked state
    |
    v
ProviderWriter::write_all attempts full configured HTTP bytes
    |
    +--> possibly partial write, error, no flush, or flush failure
    |
    v
Provider result -> projection/reflection -> completion audit
    |
    v
Bridge::answer -> serialized framed guest observation / denial / EOF
```

The current extracted dispatcher and writer-event proofs cover **portions** of this graph. Specifically, `returned_dispatch_with_writer_segment` has a real conclusion about a sound modeled attempt trace, but still expects the caller to identify its prefix and suffix, checked origin and matching channel return. These are the exact points the overnight campaign should close from production-called Rust rather than re-assuming.

When reading a new theorem, ask: *Does its quantifier range over actual reachable native requests? Where is the real Rust call linked to the abstract step? Does a premise already require the send to be authorized? Which concrete error/partial-send branch was included?* A proof about a fabricated `Event` list is not equivalent to a proof that no alternate credentialed sink can be reached.

## Concrete counterexamples the assurance must rule out

| Attack/failure | Why the existing evidence alone is insufficient | What a stronger result needs |
| --- | --- | --- |
| A second credentialed native socket path bypasses `begin_send` | A theorem about the chosen dispatcher never observes this path | Reachability closure or a checked restrictive interface plus explicit trusted sink contracts |
| Audit write fails, yet provider bytes are attempted | A reported audit row is not proof of chronology | Actual returned `Audit::write_record`/receipt relation before real writer callback, including failures |
| `write_all` emits a partial request and fails | No successful response does not imply no bytes left the host | Attempt accounting with uncertainty and no unauthorized retry, not a fake one-syscall model |
| Revocation commits after late check but before network send | “Revoked means no send ever” would misstate the real race | Explicit admission linearization point and separate already-admitted send case |
| Provider returns a token string in a selected field | A schema projection can be intentional declassification but unsafe for a token | Explicit selected-field/reflection rules and the observable denial consequence |
| Host secret changes cause an observable different denial, length or EOF | Equality of parsed success JSON misses this channel | Real native observation mapping and justified declassification agreement |
| Guest mounts or host side channel expose credential files | Lean proves a controller, not hypervisor/filesystem security | External host/VM configuration contract plus targeted deployment evidence and review |

## What remains trusted even after stronger Lean proofs

- **Cryptographic implementations:** signatures, AEAD, TLS peer authentication, nonce generation and correct key handling. The formalization does not automatically establish computational cryptographic security.
- **Host integrity and VM isolation:** attacker cannot alter host policy, executable, authority keys, credential files or privileged sockets, or read host broker memory; this must be checked against actual AIVM mounts/privileges and deployment controls.
- **External I/O semantics:** `std::io::Write`, rustls, file append/sync, OS error, DNS/endpoint selection, system call/callback/drop/unwind behavior and guest frame delivery must have narrow reviewed contracts. An audit acknowledgment is not a general crash-survival guarantee.
- **Provider contracts:** an endpoint classified `read` is genuinely nonmutating under the provider semantics; a returned selected field is an allowed release, not proof it is safe to publish.
- **Threat exclusions:** timing, co-resident process and microarchitectural side channels, full availability, arbitrary provider APIs, writes and general concurrency are outside this first read-only theorem unless separately proved.

## What will count as improved confidence

For **each** proof increment, require a compact delta note in this file or the campaign handoff with:

1. **Theorem:** exact module/name, a copy of the key logical implication in plain English, and which *source-extracted* function it talks about.
2. **Premises:** old versus new premises, identifying which were discharged by Lean/Rust linkage and which remain trusted contracts; flag any that imply the conclusion.
3. **Coverage:** authorized read, early denial, audited-but-unsent, partial send, provider failure, completion audit failure, replay/revocation, guest denial and EOF as applicable.
4. **Verification:** successful focused Lean build for changed modules, relevant Rust/fault-injection tests only if source/adapter changed, and an explicit list of tests not run.
5. **Remaining falsifier:** a concrete failure or attacker behavior still not covered by the statement.

An overnight agent's self-review is not independent assurance. The maintainer should read the final theorem statements and attack correspondence **before** using this as an unattended credential-bearing AIVM integration. An NR-5/OUT-5 status change requires separate reviewer judgment, explicit external contracts and positive functionality, not just a passing build or enlarged proof file.

## NR-2/NR-3 integrated source-to-I/O attempt (next increment)

The next five Lean files are now **proposed** for the pinned toolchain; their
focused build must precede accepting their statements. They compose existing
source-extracted controllers instead of replacing them with an independent
security state machine:

- [`GarrettNR23Request.lean`](../../proofs/GarrettNR23Request.lean): the actual
  returned request yields source-derived chronological and bound audit/send
  events; successful completion requires selection, two current checks and
  an acknowledged completion audit. A returned error yields a denial trace,
  not a fabricated successful guest reply.
- [`GarrettNR23Effects.lean`](../../proofs/GarrettNR23Effects.lean): exact
  host-selected endpoint and encoded HTTP bytes, source-owned channel
  callbacks and an **explicitly unproved** native sink-coverage contract.
- [`GarrettNR23Failures.lean`](../../proofs/GarrettNR23Failures.lean): setup
  denial, audited-but-unsent, post-audit freshness denial, invalid controller
  transition, partial-write/replay failure, and response-parser failure.
- [`GarrettNR23Guest.lean`](../../proofs/GarrettNR23Guest.lean): exact bounded
  newline-terminated JSON frame for a **source-approved** completion, and
  refused-encoding / failed-send replay properties. The native conversion
  from approved `serde_json::Value` remains an explicit contract.
- [`GarrettNR23Assurance.lean`](../../proofs/GarrettNR23Assurance.lean):
  conditional top-level mediation and completed-audit/guest-frame statements.
  Neither establishes unconditional **native** sink closure or observational
  noninterference while its named native premises are not discharged.

The [technical proof and risk ledger](nr23-source-to-io-attempt.md) contains
source-path annotations, an NR-2/3 obligation matrix and a distinction between
model-level Lean theorems and executable-level claims. The important remaining
work is connecting actual native `Session::request`, `ManifestProvider`,
`Audit::write_record`, `Disclosure::project`, and `Bridge::answer` callbacks
**and all transitive sinks** to these statements. Do not treat the presence of
`NativeSinkCoverage` as a proof that the running service satisfies it. A
source trace counting a single logical provider attempt does not bound the
number of OS writes or prove a provider received the request.

Compile first, then review hypotheses and Rust source adjacency. The native
scoped read-only assurance claim is **not** promoted to complete by these new
files alone.
