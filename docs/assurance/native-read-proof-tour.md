# Reading the native read-security proofs

**Maintainer guide — initial state, 2026-10-21.** This document explains what is proved, what is conditional, and how to inspect the result. It is **not** a whole-service verification certificate. The overnight formalization agent must update it only when the linked theorem and source evidence actually change. The [overnight campaign](../planning/aivm-secrets-overnight-formalization.md), [W0 security contract](../planning/aivm-secrets-conditional-confinement.md), [native read roadmap](../planning/aivm-secrets-native-read-assurance-roadmap.md), and [assumptions](../planning/aivm-secrets-assumptions.json) control scope.


**Latest handoff:** [2026-10-23, HTTPS proxy profiles and native narrowing](handoff-2026-10-23.md) indexes the newest theorems and assumption changes.

## What you are trying to trust

A guest is malicious and may send arbitrary framed requests, select allowed arguments adaptively and retry after errors. A trusted host owns provider tokens, configured operations and result projections. The intended **read-only** contract has two halves:

1. **Effect confinement:** every *credential-bearing attempt* to contact a provider follows a permitted request, a bound current authority decision, an appropriate earlier acknowledged host audit, and exact host-selected destination/request bytes. Denied requests must not bypass the broker and cause a secret-bearing send.
2. **Information-flow confinement:** the guest learns only explicit allowed result fields and observable status/metadata; changing host-private secrets without changing permitted declassifications must not change the stated guest observation history.

The first part is a one-run, all-events property; the second compares two possible runs under a defined relation. Neither proves the cryptographic library, kernel, VM, or GitHub semantics correct. A credential necessarily reaches its **authorized HTTPS provider**; the claim is that it does **not** reach the guest or an unauthorized sink.

A successful allowed read is required as a **non-vacuity witness**. The maintainer has already run host native, synthetic and adversarial real KVM, and real GitHub read-only scenarios successfully. Those are strong integration tests, but sampled runs do not replace the quantified source-to-I/O theorem.

## Strongest production-instance statements (2026-10-22)

These theorems are about the request type and release pipeline that
`custody/manifest_session.rs` and `tls.rs` actually run, not a generic adapter.
Each removes premises that earlier statements took as given.

| Theorem | What it says, plainly | Premises removed | Still trusted |
| --- | --- | --- | --- |
| [`production_accepted_read_has_exact_attempt_accounting_and_guest_frame`](../../proofs/GarrettProductionAssurance.lean) and `production_denial_attempts_are_authorized_and_bound` | Every accounted provider attempt of a returned request was currently authorized, audit-acknowledged and bound to the context passed to `ScopedRequest::new` | `NativeContext`, the caller-chosen `capture` function | `ExactNativeSinkCoverage` (below) |
| [`denial_frame_exact`, `production_denial_has_authorized_attempts_and_fixed_guest_frame`](../../proofs/GarrettPublicError.lean) | A guest denial frame is exactly `{"error":{"code":C,"message":M},"ok":false,"version":1}` plus newline, for one of 17 fixed `(C, M)` pairs; it depends on nothing but which public error occurred | `denialJson`, its `Valid`/`Bound` and `prepared` premises | that `from_answer`'s error branch calls `denial_frame` (W3 guard) |
| [`manifest_release_noninterference`](../../proofs/GarrettNR4ManifestRelease.lean) | Two provider responses that agree on the JSON at every host-selected path and on the pagination row count release the same value or the same refusal, for any current-control callback | `toJson`, `SelectedConversion`, unlinked `raw`/`selected`; exposes the row-count channel those premises hid | parse of provider bytes into the document; same credential in both runs |
| [`adaptive_release_same_histories`](../../proofs/GarrettNR4AdaptiveRelease.lean) | A guest choosing each request from all earlier outcomes sees the same release histories in two worlds whose provider responses agree, request by request, on the declassified data | `step_preserves` / `PairedStepCertificate` for the release stage | admission/dispatch-stage outcomes are outside this step model |
| [`exchange_send_writes_route_body`](../../proofs/GarrettChannelWork.lean) | Every read exchange that reaches the send stage called the native writer with exactly the encoded body produced for its own captured route, on a fresh channel holding that body | `PayloadCorresponds` (the written channel was an arbitrary input) | native `request_body`/`connect`/`parse` primitives and writer I/O |
| [`manifest_classes`, `adaptive_exchange_noninterference`](../../proofs/GarrettNR4ExchangeAdaptive.lean) | Each status code's public class is exact (4xx rejected, other non-2xx failed, 206 partial); a guest adapting across whole exchanges (transport failure, status refusal or release) sees the same histories when the two worlds agree on transport failures, status classes and selected data | status classification as a native assumption; transport/status outcomes absent from the adaptive model | the `Answer` abstraction (transport error mapping, body parse) |
| [`adaptive_request_noninterference`, `read_confinement_for_every_document`](../../proofs/GarrettNR4RequestAdaptive.lean) | The adaptive theorem covers complete requests including admission (extracted `manifest::authorize` over host state); read confinement holds for every provider document, so for any body parser | admission absent from the adaptive model; the body parse as an assumption of confinement | admission inputs are host state shared by both worlds |
| [`adaptive_frame_noninterference`, `production_frame_noninterference`, `production_failure_frame`](../../proofs/GarrettNR4FrameAdaptive.lean) | Stated at what the guest actually reads: a guest choosing each request from earlier *frames* sees the same frame histories when two worlds agree on the public code of each transport failure (not the native error), the status class and the selected data; every failure frame is the fixed line of one of 17 codes | transport failures having to be the same native error; strategies over raw outcomes; "native errors carry no private data" (now: the code choice is a ≤17-value declassification) | `productionFrame` is now the extracted `public_error::answer_frame`; trusted: that `GuestFrame::from_answer` maps types and calls it once (`NATIVE-GLUE-01`); body parse |
| [`production_read_frame`](../../proofs/GarrettProductionReadFrame.lean) | A successful read sends exactly the JSON encoding of `{meta?,ok:true,result:<projection of this response>,version:1}` plus newline, and the credential occurs in neither those bytes nor any decoded key or string | `toCapturedJson`, `Valid`, `Bound` | two-line `Reply::Released` framing glue (W3 guard), guest writer I/O |

**Declassifications made explicit.** A successful read reveals (a) the selected
fields, by design; (b) the length of the pagination row array, through
`possibly_more` and the oversize refusal; (c) whether the selected reply would
contain the credential, through the reflection refusal. (b) was previously
hidden inside the `SelectedConversion` premise.

**Remaining NR-3 premise, stated honestly.** `ExactNativeSinkCoverage` says the
native process makes credential-bearing writes only at the source's
`providerSend` events. The core now owns channel construction, the send
(`Channel::submit`) and the response gate, so the premise has narrowed to: the
native primitives (`request_body`, `connect`, `parse`, audit/coordination
callbacks) and the rest of the native crate perform no *other* write of
credential bytes. That is a reachability property of native code, checked by
the W3/W6 source guards and their mutation tests, not by Lean.

For review, the [claim-to-evidence matrix](claim-evidence-matrix.md) lists each
property with its theorems, premises, witnesses and exclusions.

Every remaining premise, library contract and deployment assumption is
enumerated with its class and removal path in the
[assumption removal roadmap](../planning/aivm-secrets-assumption-roadmap.md).

**Not extracted, by decision.** The provider body parse into the `Json`
document stays native serde: any deterministic, effect-free parser maps
responses to documents, so noninterference over documents carries to bytes
whenever the parsed documents agree, and responses never contain the
credential.

**Verification for these increments:** fresh pinned Aeneas extraction (committed
module byte-identical), full `lake build` (1886 jobs, no warnings),
`dev/verification/system.py --full-tests` (3213 tests, no skips with `swtpm`
installed), all W0/W3/W4/W5/W6/NR source guards with updated mutation tests,
and byte-equality oracle tests for the moved Rust (17 denial frames;
30 document/page release combinations including every refusal; 2000 status
lines plus malformed ones).

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

## New NR-2/NR-3 exact-sink and writer-byte campaign (2026-10-22)

The accepted five-module NR-2/NR-3 composition is now followed by a large,
**not-yet-compiled** five-module proof increment. The critical improvement is
multiplicity-sensitive ordered accounting for actual native credential-bearing
attempts, captured-wire provenance at the `Channel.submit` callback, route
preservation through the extracted native routing wrapper, and paired exact
public-frame bytes. This is **conditional** on native adapter, sink-closure,
conversion and external OS/TLS contracts; the exact-sink premise is a
stronger requirement, not a proven fact about the live binary.

See [the source-to-I/O theorem matrix and remaining obligations](nr23-exact-native-boundary.md).
The first build command is `lake build GarrettNR23ProductionBoundary` after
`lake exe cache get`. Do not treat the source-anchor regression checker as a
proof of complete native I/O mediation.

## NR-4: recursive declassification to native guest bytes and adaptive sessions (2026-10-22)

The proposed [`GarrettNR4Assurance.lean`](../../proofs/GarrettNR4Assurance.lean)
composes five new modules. Their goal is to close a **different** gap than
NR-2/3: whether two private states with the same approved selected fields and
permitted public status can give an adaptive guest distinguishable responses.
The important improvement is a **derived equality of approved wire bytes**:
`ProjectionAgreement` + source-extracted recursive `disclosure.project` +
a single named `SelectedConversion` contract + extracted `json_wire.prepare`
produce equal complete newline frames. The caller no longer assumes that
the two encoded outputs were equal.

The [selected-renderer input refinement](../../proofs/GarrettSelectedConversionInput.lean)
now derives `OpaqueFree` of the *entire* successful selected tree from
Aeneas-extracted `disclosure.project` / `project_fields` and the existing
`Fits` postcondition. Thus nested `Opaque` leaves cannot reach the
production renderer after successful projection; the source filter itself
supplies the certificate. This does **not** yet prove the extracted renderer's output semantics.

The same proof module now establishes
`successful_project_fields_has_exact_root_keys`: successful root projection
returns an object with precisely the ordered output names from the trusted
schema, using the preexisting independent `fieldsWith` specification and the
Aeneas-extracted `project_fields` refinement. It also combines this with
`OpaqueFree` into a single `successful_project_fields_has_public_shape`
result. The native policy parser delegates output-name validation to a
production-called Aeneas-extractable `selected_conversion::public_field_name`
function. These narrow the output-name provenance boundary but do not establish
byte-level `SelectedConversion`.

The [production selected-wire conversion increment](nr4-selected-source-conversion.md)
now specializes the same extracted renderer with a concrete production
`WireBuilder` **inside the Aeneas crate**, replacing the old native
`SerdeBuilder`. UTF-8 decoding, signed decimal token construction, selected
object insertion/duplicate rejection, and final `json_wire.encode` operate
on the approved source tree. Before release, credential reflection is checked
against that tree and its actual encoded bytes, with no serde parse/re-encode
of the selected value. This narrows a real production correspondence boundary;
it does not by itself supply the Lean output theorem, native input/map-order
semantics or the still-open full `SelectedConversion`/guest-byte refinement.

The proof includes independent authorization/audit/sink sequences for both
returned source reads, a fixed public denial taxonomy, and arbitrary
feedback-dependent request strategies over offered bytes, error/outcome codes,
and modeled metadata. Error categories, reflection-denial decisions, status,
frame length, pagination and closure differences are explicitly observable.
The `PairedStepCertificate` spells out the state-preserving native refinement
required for the adaptive theorem. **Production Rust does not yet have a
formal proof that every native step supplies this certificate.**

Read the [NR-4 proof/assumption matrix](nr4-native-observation-attempt.md) before
using any new theorem as evidence for AIVM trust. The new 8-region Rust source
guard catches selected source drift but cannot establish semantic or transitive
I/O correspondence. Compilation of `GarrettNR4Assurance` on the pinned
Lean toolchain is still required for this new batch; even after compilation,
NR-4 implementation refinement and NR-5 independent review remain open.

## Next Track A increment: extractable production controllers (new proof attempt)

The production audit recorder, selected-result release and provider receive
handoff now call extractable Rust controllers rather than duplicating their
callback order in native glue. See
[`nr-native-extracted-controllers.md`](nr-native-extracted-controllers.md) for
precise Rust paths, failed branches, theorem-to-source mapping, extraction and
focused build procedure, and the assumptions that **remain**. The new Lean
entrypoint is `GarrettProductionAdapterRefinement` and requires regeneration of
`generated/AivmSecretsGarrettCore.lean` from this Rust source. Existing
NR-2/NR-3 and NR-4 formal results remain unchanged.

## Production response-gate token (Aeneas compatibility repair)

The initial extraction attempt for the native response controller failed
inside the pinned Aeneas interpreter on the Rust `response_gate::Parser` trait
signature. The revised production controller avoids this unsupported nested
trait projection by exposing an **owned, sealed `response_gate::Released` token**
in place of a generic parse callback. `ManifestProvider::receive` must obtain
the token from the extracted readiness gate before its native parser can be
called; the native parser consumes that token and cannot accept a raw Channel.

`GarrettProductionResponseGate.lean` therefore proves the source-owned
**token-eligibility and exact writer/flush provenance**, not a fictitious
symbolic native parser invocation. The concrete native parse, all other native
sinks, and OS/TLS behavior remain separate implementation obligations.

## HTTPS proxy, credential-substitution profile: where the credential goes (2026-10-23)

Reviewers: start from the [proxy claim-to-evidence matrix](proxy-claim-evidence-matrix.md).

This section is about the optional proxy profile
([plan](../planning/aivm-secrets-http-proxy-profiles.md)), not the native
read profile. Source: `rust/crates/aivm-secrets-garrett-core/src/proxy_http.rs`,
extracted by Aeneas. Proofs: [`GarrettProxyHttp`](../../proofs/GarrettProxyHttp.lean).

**The question.** The proxy takes an arbitrary guest HTTP request and adds the
real credential. Can a guest arrange for the credential to land somewhere
other than the one authentication line? Can a guest-supplied
`Authorization` or `Cookie` header be forwarded alongside it?

**What is proved, in plain words.**

| Theorem | Says |
| --- | --- |
| `dropped_eq` | The extracted filter drops a guest field exactly when its name equals one of 19 names **ignoring ASCII case**: credential fields (`authorization`, `x-api-key`, `proxy-authorization`, `cookie`), hop-by-hop and framing fields, the three method-override fields (`x-http-method-override`, `x-method-override`, `x-http-method`) and `range`/`if-range`. |
| `forwarded_contract`, `forwarded_drops` | The forwarded fields are the guest fields in their original order, minus those names. No forwarded field has a dropped name. |
| `append_fields_contract` | Each forwarded field is written as `name: value` CRLF, and nothing else. |
| `encode_upstream_contract` | For **every** guest request, host, deny list and credential, the encoder either refuses and leaves the output buffer unchanged, or it has checked that the credential is valid, the target is visible ASCII and every forwarded field is one clean header line, and it appends exactly `UpstreamPrefix ++ HeaderPrefix a ++ secret ++ CRLF ++ UpstreamSuffix`. |
| `clean_field_single_line`, `visible_single_line` | A forwarded field or accepted target contains no CR or LF, so a guest cannot add a header line. |

`UpstreamPrefix` is the request line, `Host` and the forwarded fields.
`UpstreamSuffix` is the fixed lines, an optional `Content-Length` and the
body. Both are defined without the secret. So the secret appears in the
upstream bytes as the one verified authentication line
(`http_auth.Proofs.accepted_header_exact`), placed after every guest field.

**The deny list is a host filter, not a proof.** Only totality of
`rule_matches`/`denied` is proved. To make spelling tricks fail closed, the
encoder refuses targets containing `#`, `\`, `;`, a malformed `%` escape, or
an escape of an unreserved character, `/`, `\`, NUL or `;` (so `/%61dmin/`
and `/admin%2F` are refused rather than matched). A `/x/` rule also matches
`/x`, and a rule matches the path with a trailing `/`. The provider's own
path normalization stays assumed (`PROXY-PARSE-01`).

**Read the conclusion carefully.** These theorems describe the *encoder*,
which re-checks method, target and every forwarded field itself, so header
framing and the credential filter **do not depend on the parser** being
right. They do not say that guest header values can never contain text that
*looks like* a credential: a guest can put any visible bytes there, but it
does not know the credential.

**What the guest may receive** ([`GarrettProxyResponse`](../../proofs/GarrettProxyResponse.lean)).

| Theorem | Says |
| --- | --- |
| `reflects_spec` | When the extracted check answers "not reflected", no case-sensitive form occurs anywhere in the checked bytes, nor in those bytes with line breaks removed. |
| `guest_response_contract` | For any upstream response, the proxy either refuses and appends nothing, or appends bytes in which no case-sensitive form occurs. For `HEAD`, the appended bytes are a prefix of the checked ones (`response_head_prefix`), so the same holds. |
| `reflection_forms_include_raw` | Whenever the form list is built, it contains the credential's exact bytes as a case-sensitive form. |
| `unwrapped_spec` | The extracted `unwrapped` is the checked bytes with every CR and LF removed; `reflects_spec` also rules out each case-sensitive form there, so line-wrapped (MIME-style) base64 is caught. |
| `refusal_exact` | Every refusal the proxy sends is exactly one of eleven fixed responses, which depend on nothing but the refusal code. No request, provider or credential bytes appear in a refusal. |

Together: **a released response never contains the credential's exact
bytes.** Percent, hex and base64 forms are also checked, but the proof
covers them only as listed byte strings. Any other derived value, such as a
freshly minted token, is outside it (`PROXY-REFLECT-01`, `PROXY-AUTHORITY-01`).

**Who sequences a request** ([`GarrettProxyController`](../../proofs/GarrettProxyController.lean)).
The native shell `garrett-proxy` no longer decides anything per request. It
calls the extracted `proxy_controller::serve` and supplies three callbacks:
`current` (the session clock), `admitted` (the audit line) and `exchange`
(send bytes to the pinned origin, return its answer). The theorems hold for
**any** callbacks, so they do not trust the native side to behave.

| Theorem | Says |
| --- | --- |
| `serve_paths` | Every returned `serve` took one of three paths: not current (nothing admitted or sent, `revoked`); encoder refused (nothing admitted or sent, a fixed refusal); or current, encoded, audited, then `exchange` called with **exactly the encoder's output**. |
| `serve_upstream` | A request not refused before egress went through `exchange` once, after `current` and `admitted`, and the bytes sent are `UpstreamPrefix ++ HeaderPrefix ++ secret ++ CRLF ++ UpstreamSuffix`, with a valid credential, visible target and clean guest fields. A refused request never reached `admitted` or `exchange`. |
| `serve_guest_reply` | The reply is the fixed refusal for its code, or a completed request's `guest_response` output, in which no case-sensitive credential form occurs. |
| `release_reply` | The response half: parsing failures and reflections become fixed refusals with stage `Failed`. |
| `frame_paths` | Before `serve`, the extracted `frame` decides what to do with buffered tunnel bytes: past `raw_limit` it refuses `too_large` without parsing; otherwise a request reaches `serve` only if the strict parser accepted it, and more bytes are read only if the parser asked for them. |
| `parse_request_bounds` ([`GarrettProxyParse`](../../proofs/GarrettProxyParse.lean)) | When the strict parser returns a request, it used no more bytes than were buffered (so the shell's `drain(..used)` cannot panic) and the body is at most the request limit, for `Content-Length` and chunked bodies (chunk sizes are at most 8 hex digits). Which requests it accepts is still tested, not proved. |
| `check_target_plain` (same) | Every position of a target the encoder accepts holds visible ASCII other than `#`, `\\` and `;`, and the extracted escape check found no refused escape starting there (malformed, or escaping an unreserved byte, `/`, `\\`, NUL or `;`). |
| `check_target_segments`, `segments_ok_loop_exact` (same) | In the part of an accepted target before its first `?`, every segment closed by a `/` is non-empty and not `.` or `..` (`InteriorOk`), and the last segment is not `.` or `..` (`FinalOk`; it may be empty, for a trailing `/`). So `//`, `/./` and `/../` never reach the provider. Read `SegOk`: three conditions. `tests/test_proxy_target_semantics.py` checks that every target the Python backend accepts has these properties, exhaustively over short targets. |
| `serve_paths`, `serve_upstream` ([`GarrettProxyController`](../../proofs/GarrettProxyController.lean), fail-closed audit, 2026-10-23) | The proxy used to ignore a failed admission audit and send anyway. Now `admitted` reports whether the record was durably written, and `serve` sends only after an **acknowledged** record; otherwise it refuses with `internal_error` and calls no `exchange`. The Python proxy does the same, and both have a test that forces audit writes to fail (the native one through `RLIMIT_FSIZE`). A reply is likewise released only after its `completed` record is acknowledged: the extracted `serve` calls the `completed` callback before releasing, and answers `outcome_unknown` if it fails (`exchanged_outcome`). The guest-side translated path has the same gate in native code, checked by source shape only. |
| `connect_head_returned` ([`GarrettProxyTunnel`](../../proofs/GarrettProxyTunnel.lean)) | The CONNECT head is read by the extracted `connect_head`, one byte at a time. A head it returns is complete, and no shorter prefix was complete (`NoEarlierHead`), so the reader stops exactly at the end of the head and never consumes a byte of the TLS handshake after it. The native side supplies only `next_byte` and the 30 s deadline. |
| `rule_matches_spec`, `denied_spec` ([`GarrettProxyHttp`](../../proofs/GarrettProxyHttp.lean)) | The substitution profile's deny list refuses a request **exactly** when some rule matches (`RuleMatches`): the rule's method is empty or equal, and the path equals the rule path, adds one trailing `/` to it, or (for a rule path ending in `/`) is the rule path without that `/` or extends it. Read `PathMatches`: four cases. This is matching on the bytes as written; a provider that normalizes paths differently can still route around a rule (`PROXY-AUTHORITY-01`). `tests/test_proxy_deny_semantics.py` checks that the Python backend decides the same predicate, exhaustively over short paths. |
| `step_paths`, `step_request_fits`, `tunnel_loop_open` ([`GarrettProxyTunnel`](../../proofs/GarrettProxyTunnel.lean)) | The tunnel loop itself is extracted (`proxy_controller::tunnel`). Each step does one of four things, for any native callbacks: closes an overdue partial request; audits and then writes only the fixed refusal for what `frame` refuses; appends exactly the bytes read; or serves exactly the request `frame` parsed, writes exactly that answer, and keeps exactly the bytes after it (never more than were buffered). The native shell keeps only the socket reads and writes, the deadline clock and the audit append. Read `Stepped`: it lists, per case, which callbacks ran and with what. |

Both byte statements carry a size premise: the canonical encoding (or the
checked response) fits in a `usize`. It is a memory bound, not a security
assumption. A Rust oracle test (`proxy_controller::tests`) checks that
`serve` produces the same upstream and guest bytes as the composition the
shell used before, and that callbacks run in the order the theorems state.

**Who may open a tunnel** ([`GarrettProxyConnect`](../../proofs/GarrettProxyConnect.lean)).
Before any request, the guest sends `CONNECT host:443` with the session's
proxy token. That decision is the extracted `proxy_connect::admit`.

| Theorem | Says |
| --- | --- |
| `admit_open` | A tunnel opens only if the session is current, the answer is a valid index into the configured origins, and the parsed fields authenticate. The native shell then connects the guest only to that origin. |
| `authenticated_true` | Authentication succeeds only if a field named `Proxy-Authorization` (any ASCII case) presents exactly the session token, as `Bearer TOKEN` or `Basic base64(USER:TOKEN)`. |
| `same_secret_true` | The comparison has no early exit and answers `true` only for byte-identical inputs (proved with bit-vector reasoning on the accumulated `OR` of `XOR`s). |

The base64 decoder is extracted but not proved to be base64: it does not
need to be, since whatever it decodes must still equal the token. A Rust
oracle test checks the decision against the replaced native code and the
`base64` crate over 880 heads, including malformed padding and trailing
bits.

**Byte parity with the Python reference.** `tests/secrets_vectors/proxy-http-v1.tsv`
holds 76 adversarial and positive cases (and `proxy-http-response-v1.tsv` 43 response cases). The Python test checks that the
file is exactly the Python reference's output, and the Rust test
`python_reference_vectors` checks the extracted code against every line. A
mutant that forwarded `Cookie` fails it.

**Still trusted for this profile.**
- That the provider reads the canonical HTTP/1.1 bytes conventionally and
  routes the path as written; a provider that normalizes paths (case,
  encoding) could route around a deny-list entry (`PROXY-PARSE-01`).
- Encodings of the credential other than the listed forms (`PROXY-REFLECT-01`).
- TLS and the session CA (`PROXY-TLS-01`).
- That the native callbacks do what they say: `exchange` writes its
  argument to the pinned origin and nothing else, and the shell writes only
  `serve`'s reply (or a tunnel-level fixed refusal or the CONNECT answer) to
  the guest (`PROXY-NATIVE-01`, narrowed: the sequencing is now proved).
- **The profile grants the credential's full authority at the origin**
  (`PROXY-AUTHORITY-01`). None of this is authority confinement.

## The provider request target (2026-10-23)

Every named operation's provider target, `/repos/octo/demo/pulls/7?page=2`,
used to be assembled by native string formatting in `manifest.rs`. It is now
written by the extracted `route::fill_target`
([`GarrettRoute`](../../proofs/GarrettRoute.lean)). The native manifest still
parses the policy's templates and turns each JSON argument into text
(integers in decimal); `route` writes every byte.

| Theorem | Says |
| --- | --- |
| `fill_target_exact` | A returned target is exactly `PathBytes ++ QueryBytes`: `/value` for each path part, then `?name=value` and `&name=value` for each query entry. A value is the literal, or the **first** argument with the parameter's name. Every part had a value, the path is 2–1024 bytes and the target at most 8192. |
| `fill_target_safe` | Every target byte is unreserved (`A-Z a-z 0-9 - . _ ~`) or one of `/ ? = &`. Path values hold only unreserved bytes and `/`; query names and values only unreserved bytes. So the only `?` is the query separator, and no `#`, `%`, space, CR or LF can reach the request line. |
| `segment_ok_contract`, `segments_ok_contract` | The checks behind both: a segment is non-empty, at most 128 bytes, not `.` or `..`, and unreserved. |

The statements are about what a *returned* target is, so they need no size
premise. A Rust oracle test (`manifest::route_oracle`) checks that the
extracted function gives the same target or refusal as the native code it
replaced, over more than 500 template, query and argument combinations
(including `..`, `a/b`, `x?y`, `%2e`, non-ASCII and over-long values).

Argument text is extracted too: `scalar_text_text` and
`scalar_text_integer` show a string argument is used as is, and an integer
as `-` (if negative) and its decimal digits (`decimal_value_exact` reads them
back as the number; the integer case assumes a 64-bit `usize`). An oracle
test compares it with Rust's own formatting, including `i64::MIN`.

The templates themselves are parsed by extracted code as well:
`parse_template_some` shows a parsed path template is `/` followed by its
pieces written back with `/` between them (a parameter written `{name}`),
and every piece is a valid segment or name; `parse_piece_spec` is the same
for one part (query values).

**Still trusted** (`ROUTE-NATIVE-01`): the JSON layer, reading the template
strings from the policy and mapping JSON arguments to strings or `i64`s.
Checked by the manifest parity tests against the Python reference.

**The guest-side translator (HP-6).** The constrained proxy can run inside
the guest, untrusted, with no credential (`garrett-proxy --routes ...
--bridge-client ...`). It reads candidate arguments off a request target
and accepts them only through the extracted `route_match::translate`
([`GarrettRouteMatch`](../../proofs/GarrettRouteMatch.lean)):

| Theorem | Says |
| --- | --- |
| `translate_round_trip` | Whenever `translate` returns arguments, the host encoder `fill_target`, applied to the same templates and those arguments, returns exactly the guest's target. |
| `translate_exact` | So the accepted target is `PathBytes ++ QueryBytes` of those arguments, contains only safe bytes, and every template part had a value. |

How candidates are read off the target is not proved and does not need to
be: it only decides which requests are translated. The typed arguments then
go through the guest's native `invoke` to the host bridge, which authorizes
the named operation on its **own** policy. So a guest whose route copy
differs from the host's can only ask for a different named operation, never
widen authority (`tests/test_proxy_guest_translator.py` tampers the copy).
The visualization scene `proof_constrained` walks through these steps.

## The other guest verbs: `describe` and `renounce` (2026-10-23)

The guest can send three verbs. `request` is the read/write path above. The
other two, `describe` and `renounce`, used to be answered by native code with
serde replies. Both sessions now hand them, after the same capability check,
to the extracted `control::control`
([`GarrettControl`](../../proofs/GarrettControl.lean)). The native side
supplies three callbacks: revoke the control state, durably append bytes to
the audit, deactivate the grant. Since 2026-10-23 the revocation record is
built and encoded by extracted code; the native callback only appends it,
through the same extracted `append_durable_record` that read-path records use.

| Theorem | Says |
| --- | --- |
| `control_paths` | For **any** callbacks, a returned call took one path. `renounce`: revoke, then record; only if the record succeeded, deactivate and reply `{"ok":true,"renounced":true,"version":1}`. If the record failed, the error comes back, no reply is sent, and the control state stays revoked (fail closed). `describe`: reply with the description, no callback. Anything else: `Denied`, no callback. The callback interface has no provider operation, so neither verb can cause a provider request. |
| `renounce_records_exactly`, `revoked_record_exact` | The bytes `renounce` passes to the audit are exactly the extracted encoding of `{"event":"revoked","grant":G,"policy":P,"schema":1}` (the account profile adds `"operation":"profile.read"`). Grant, policy and that operation name are the record's only inputs, so no credential or guest data can enter it. An oracle test checks these bytes equal the serde records they replaced. |
| `manifest_description_exact` | The description is `{"operations":[...],"profile":"manifest-https-v1","request_limit":"unbounded","writes":MODE}`, where the array is exactly the policy's operation names in order. Those names and the write mode are the function's only inputs, so no credential, token, identity or audit data can appear in a `describe` reply. |

The reply values go through the same extracted JSON frame encoder as read
results. The `custody::control_oracle` test checks that the framed bytes
equal the serde replies they replaced, for all write modes and several
operation lists.

**Still trusted** (`CONTROL-NATIVE-01`): that the three callbacks do what
they say (revocation takes effect for later requests; `deactivate` clears
the grant flag), that `record` is the session audit's `append_bytes` (one
native line into the extracted durable append), and the capability check that
precedes the call.

## Session audit records (2026-10-23)

The account session's audit events (`session_open`, `completed`, `failed`,
`revoked`) and the manifest session's completion record are now built by the
extracted `session_audit::event_record`; the manifest dispatch, opening and
issuance records and the account dispatch record by their own functions in
`session_audit`. They are encoded by the extracted JSON
encoder, and the native audit appends exactly those bytes through the
extracted `append_durable_record`
([`GarrettSessionAudit`](../../proofs/GarrettSessionAudit.lean)).

| Theorem | Says |
| --- | --- |
| `event_record_exact` | A record is `{"event":E,"grant":G,["operation":O,]"policy":P,["request_digest":D,]"schema":1}`, keys in byte order, and the five values the session passes are its only inputs. `OptionalField` says each optional field is absent or exactly one keyed pair. |

| `dispatch_record_exact` | The manifest dispatch record, written and acknowledged before every provider send, is `{"event":"dispatch","grant":G,"identity":I,"operation":O,"phase":PH,"policy":P,"request_digest":D,"route":{"host":H,"method":M,"path":T,"port":N},"schema":1}`; the ten values the session passes are its only inputs. |

| `opened_record_exact`, `issued_record_exact`, `account_dispatch_record_exact` | The manifest `session_open` record, the capability `issued` record and the account profile's dispatch record have the same kind of exact statement. In the account dispatch record the method is the fixed `GET`, and the authentication name (`bearer` or `x-api-key`) is decided by the scheme (`AuthenticationName`). |

| `approval_requested_record_exact`, `approved_record_exact` | The approval extension's records (a write waiting for approval, a host approval); its host `revoke` record is `event_record`. |

With these, every production audit record (account and manifest sessions and
the approval extension) is built by extracted code. Native `json!` audit
records remain only in tests.
Oracle tests check the encoded bytes against the serde records they replaced
(including nested, escaped identity claims). **Still native:** the values the
sessions pass in (the identity claims are captured from the session's claims
JSON; the port is its decimal text).

## Host output field names, and the Anodized pilot (2026-10-23)

`selected_conversion::public_field_name` checks every host-owned output field
name the manifest parser accepts. [`GarrettPublicFieldNameContract`](../../proofs/GarrettPublicFieldNameContract.lean)
proves, over the extracted function and its loop, that it **always returns and
accepts exactly** names of 1–32 bytes with a lowercase first byte and only
ASCII letters, digits and `_` (`public_field_name_spec`). The language is the
eight-line predicate `PublicFieldName` in that file; check that it says what
you want.

We also tried stating the necessary half of this as an Anodized 0.7 `ensures`
contract on the Rust function. With the pinned Charon/Aeneas the contract
turns the extracted function into a wrapper over three new uninterpreted
axioms, so nothing about it could be proved, and the contract never becomes a
Lean statement. It was not adopted; details and a reproduction script are in
[the pilot record](anodized-pilot-2026-10-23.md).

## OUT-4 first increment: the exact-write gate (2026-10-23)

Writes and reads run through the same extracted production controller,
`read_transition::run_current`. Until now, the approval decision that decides
whether a write may run was checked by native code in front of it. That check
is now the extracted `write_gate::run_approved(decision, pending)`. It is the
session's only call to the controller ([`GarrettWriteGate`](../../proofs/GarrettWriteGate.lean)).

| Theorem | Says |
| --- | --- |
| `run_approved_ran` | The controller ran only if the decision was `Allowed`, with exactly its result. |
| `run_approved_refusals` | A `Denied` or `Required` decision returns without invoking the controller, so no dispatch and no provider attempt happen. |
| `approve_mode_write_ran_consumed_its_approval` | In `approve` mode, a write that ran had a matching, unexpired approval. The approval is consumed and cannot be reused. |
| `deny_mode_write_never_runs` | In `deny` mode a write never reaches the controller. |
| `keyed_success_reserved_and_finished` | For a coordinated (keyed) write, a successful dispatch made the durable coordinator reservation *before* the exchange and finished it after; a failed finish is reported as `OUTCOME_UNKNOWN`, never retried. |
| `production_write_has_approval_and_authorized_attempts` | For the production request type, a gated request that returned had an `Allowed` decision. Every accounted provider attempt was currently authorized (write mode included), audit-acknowledged and bound to its admission context, and the attempt count equals the trace's sends, so nothing is retried behind the trace. |

Already proved for the controller itself, and so holding for writes through it: a write that was sent and then failed completion returns `outcome_unknown` and halts. It is never retried (`read_transition.Proofs.sent_write_completion_failure_is_uncertain`).

**Which approval a write spends (2026-10-23).** The host's approval store used
to be a native `BTreeMap` keyed by digest. It is now the extracted
`approval::admit` and `approval::install` over a list of slots
([`GarrettApprovalStore`](../../proofs/GarrettApprovalStore.lean)); the native
adapter only holds the lock, reads the clock and keeps the list. A byte-level
oracle test replays random sequences against the old map.

| Theorem | Says |
| --- | --- |
| `take_spec` | The slot looked up is the **first** slot whose digest is this request's digest; the rest of the store is unchanged and in order. |
| `admit_spec` | The decision is `consume` applied to exactly that slot; the new store is the rest plus whatever `consume` handed back. |
| `admit_write_spec` | In `approve` mode a write is `Allowed` exactly when the store holds a live slot for this digest. `Allowed` removes it; `Required` keeps every slot. |
| `install_spec` | Approving replaces any slot for the same digest and drops expired ones; if 16 survivors remain, it refuses and the store is unchanged. |
| `install_unique`, `admit_unique` | The store never holds two slots for one digest. |
| `spent_slot_is_gone`, `spent_approval_cannot_be_reused` | After an `Allowed` write no slot for that digest is left, so the same request is `Required` again at any later time. |

Read the predicates `ForDigest`, `Survives` and `Unique` (three lines each):
they are the whole specification. One behaviour changed on purpose: a full
store used to be pruned before refusing; now a refusal leaves it untouched. This matches the Python reference kernel (`kernel/machine.py`, `approve`), which raises `exhausted` before replacing its state.

**Still assumed:** that the session passes the gate the decision `admit`
returned for the digest it computed for *this* request (one native line), how
that digest is computed (canonical JSON and SHA-256), and the store's lock
(`APPROVAL-RUST-01`). Also assumed: the production theorem's native premises,
and the keyed-retry and coordinator contracts for coordinated writes
(`COORD-RUST-01`). This is not yet the full OUT-4 claim: provider-side write
semantics and the uncertain-outcome policy across sessions still need their
own statements.
