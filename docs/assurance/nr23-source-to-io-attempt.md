# NR-2 / NR-3: source-to-I/O security-proof attempt

**Status: substantial proposed Lean development; focused build required on the
maintainer's pinned toolchain. Not an NR-2/NR-3 closure certificate.**

This note is a map of **actual source functions, theorem statements and
remaining premises**. It is a companion to the [read-security proof tour](native-read-proof-tour.md),
[native read roadmap](../planning/aivm-secrets-native-read-assurance-roadmap.md),
and [conditional confinement contract](../planning/aivm-secrets-conditional-confinement.md).
It is intentionally not a second threat model or a substitute for verifying the
actual proof terms.

## Scope and evidence rules

The target is a native `manifest-https-v1`, `writes=deny`, sequential-session
configuration with an untrusted guest, a trusted **host** manifest and
credential, and a bounded set of nonwriting operations. A separate proof
is needed that the selected startup profile cannot reach write, delegated,
OAuth acquisition, or other excluded credential-bearing paths. Merely setting
a flag is not proof of transitive unreachability.

The first NR-2/NR-3 claim concerns **credential-bearing provider send
attempts**, not whether the provider received a complete packet. The selected
source-controller model records one *logical* attempt; a `write_all` call can
cause multiple OS calls and partial delivery before failure. A provider TLS
handshake may happen during `setup_route`, **before** the final current
admission check. That is a real network interaction but not necessarily a
credential-bearing HTTP send. The profile must explicitly classify these
setup effects and any metadata they reveal.

The second claim concerns **approved guest-visible data**. Completion gating
and bounded exact JSON framing are separate responsibilities; a receipt flag
is not a frame and a frame callback is not proof that TCP delivered bytes.

The operator's successful OUT-0 host, OUT-2 KVM, adversarial KVM, and OUT-3
real GitHub read-only acceptance runs are preserved as scoped operational
evidence. No finite test proves complete effect-sink reachability or full
confidentiality. Source guard passes likewise do not certify Lean elaboration
or I/O refinement.

## The actual code path

```text
rust/.../tls.rs
  Bridge::serve / peer verification
    -> Bridge::answer("request")
      -> custody::Session::request
         -> entry checks, captured op/args and admission context
         -> request_adapter::Pending::new / read_transition::run_current
            -> current_admission::Context::current
            -> dispatch / provider_exchange::exchange
              -> ManifestProvider::audit_route
                 -> custody::Audit::write_record
                    -> append_durable_record / flush / sync
              -> ManifestProvider::setup_route
                 -> manifest_request_bytes
                 -> TcpStream connect + rustls handshake
                 -> provider_io::Channel::new
              -> ManifestProvider::send
                 -> send_manifest_bytes
                    -> Channel::submit
                    -> ProviderWriter::write_all / flush
                       -> rustls StreamOwned / TcpStream / OS
              -> ManifestProvider::receive
                 -> Channel::into_parts
                 -> manifest_response / parser
            -> selection / reflection checks
            -> completion audit + final current check
      -> GuestFrame::from_answer
         -> json::capture(..).prepare(MAX_REPLY)
      -> GuestFrame::send
         -> GuestWriter::write_frame
            -> write_all / flush / rustls TCP
```

Source anchors: [`Session::request`](../../rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs),
[`ManifestProvider` and `send_manifest_bytes`](../../rust/crates/aivm-secrets-garrett/src/custody/manifest_session.rs),
[`Audit::write_record`](../../rust/crates/aivm-secrets-garrett/src/custody.rs),
[`Disclosure::project`](../../rust/crates/aivm-secrets-garrett/src/manifest/disclosure.rs),
and [`Bridge::answer`/`GuestFrame`](../../rust/crates/aivm-secrets-garrett/src/tls.rs).

These links identify the reviewed source path, **not** a claim that Charon
has extracted every listed native wrapper, dynamic callback, rustls
continuation or filesystem effect. Source-level `#[allow]` and pinned guard
files do not eliminate a missing correspondence proof.

## New Lean modules and concrete theorems

### 1. [`GarrettNR23Request.lean`](../../proofs/GarrettNR23Request.lean)

`all_returned_request_events_are_authorized_and_bound` starts from a returned
`read_transition.run_current` on the existing `request_adapter.Pending` and
source-derived `NativeContext`. It derives a request run, a chronological
`TraceSteps` history, reachability, `SoundTrace`, and `BoundTrace`. Every
modeled `Event.providerSend` in that derived history has an accepted gate,
`audit=true`, and the original captured binding. It does **not** take
independent trace, audit flag or native send witness premises.

`returned_success_has_selected_audited_current_value` derives selection,
pre-audit and post-audit current checks, completion audit acknowledgement,
and `value_ready` from the actual returned success of the extracted request
controller.

`trace_steps_do_not_fabricate_public_replies` proves internal source
trace deltas contain no guest reply events. This prevents an accidental
shortcut from receipt completion to unverified guest output.

`returned_error_projects_denial_not_public_success` handles returned error
outcomes without inventing a successful guest frame. A denial **event in this
abstract projection** still needs a concrete byte/transport argument.

### 2. [`GarrettNR23Effects.lean`](../../proofs/GarrettNR23Effects.lean)

`admitted_route_uses_exact_encoded_bytes_and_flushed_channel` composes a
source-issued current stamp, host-grant route, exact `provider_wire.append`
HTTP request buffer, `Channel.new`, `Channel.submit`, and `Channel.into_parts`.
The resulting buffer is the requested initial bytes followed by the exact
encoded HTTP request, and successful response eligibility entails a
successful high-level `write_all` and `flush` callback.

`source_checked_read_has_native_callback_schedule` links the source-extracted
`provider_exchange.exchange` attempted read to its issued stamp and native
writer schedule, conditional on **constructor and send adapter contracts**.

`NativeAttempt` and `AllNativeAttemptsAccounted` explicitly represent
observed credential-bearing native attempts and the **unproved coverage
contract** linking each such attempt to the source-derived send trace.
`accounted_native_attempts_have_current_bound_audit` then establishes
current authorized binding and acknowledged audit for every *covered*
attempt. Payload exactness of all native sink writes is not proved by this
event-only representation; that requires a stronger effect/event refinement.

### 3. [`GarrettNR23Failures.lean`](../../proofs/GarrettNR23Failures.lean)

- `early_refusal_retains_exact_receipt_and_no_current_stamp`:
  returned setup/current-denied exchange does not mark a provider attempt;
  no claim of zero setup network/TLS effects.
- `audited_but_unsent_cannot_complete`:
  dispatch audit alone cannot pass completion.
- `completion_audit_acknowledgement_is_not_a_reply`:
  completion audit alone does not release a selected value.
- `late_postaudit_check_still_locks_guest_value`:
  begin-post-audit recheck has not unlocked a response.
- `invalid_extra_call_withdraws_permission_not_evidence`:
  invalid controller transition fails closed while retaining the receipt.
- `returned_failed_read_send_blocks_parser_and_replay`:
  a returned failure consumes the one-attempt channel and refuses any second
  submit through that same channel; partial OS/TLS send remains possible.
- `returned_response_error_has_prior_flushed_provider_request`:
  a returned parse/response failure follows a submitted and flushed request;
  it cannot be reinterpreted as "no provider attempt".

These statements are about the **exact returned source transitions**, not
process crash, panic, cancellation, multi-threaded races, or power loss.

### 4. [`GarrettNR23Guest.lean`](../../proofs/GarrettNR23Guest.lean)

`selected_current_completed_value_has_exact_guest_frame` combines the
successful source controller's selection/current/acknowledged completion
checks with `json_wire.prepare`, `guest_frame.Frame.send`, exact bounded JSON
bytes, LF framing, and single high-level writer attempt.

`refused_encoding_constructs_no_guest_frame` denies frame creation on an
encoder refusal. `failed_guest_send_preserves_exact_bytes_and_blocks_replay`
proves no second writer callback through the already-attempted frame. The
paired exact-byte theorem is a **bridge** toward NR-4: it is not adaptive
noninterference until the complete native observation relation is proved.

`toCapturedJson` is still an externally supplied native conversion. It must
be shown to match the exact value selected by `Disclosure::project`,
`Completed::into_value`, `serde_json`, and `json::capture`, rather than a
chosen unrelated JSON value. `GuestFrame::from_answer` handles error replies
as well; `returned_denial_frame_has_exact_bounded_single_attempt` proves
the framing of a supplied fixed error JSON value, **conditional** on the
native error-to-value conversion actually supplying that value. This is
not yet a proof of native error sanitization or every native error byte.

### 5. [`GarrettNR23Assurance.lean`](../../proofs/GarrettNR23Assurance.lean)

`returned_native_attempts_have_derived_authority_audit_and_binding` is the
new top-level conditional mediation statement. It obtains *the* actual
request-wide trace from source execution, not from an arbitrary supplied
list, and combines it with the explicitly named **`NativeSinkCoverage`**
obligation to conclude all represented native credentialed send attempts
were authorized, audit-acknowledged and bound.

`accepted_native_read_has_completed_audit_and_exact_guest_frame` brings
selection and completion-audit gates into the same source-owned request as
an exact prepared guest JSON frame. It is conditional on actual guest
conversion/preparation and frame-writer calls; it does **not** infer guest
receipt or rule out other native output sinks.

**Proof-accounting rule:** Naming a native coverage relation is NOT
establishing it. The principal remaining task is proving the real callback,
sink, source-factory and guest-frame relationships actually instantiate these
abstract premises. The total theorem does **not** claim production runtime
confinement while those premises remain open.

## NR-2/NR-3 obligations: audit and falsifiers

| ID | Native obligation not discharged by the new pure Lean statements | How to discharge / attack it |
| --- | --- | --- |
| N23-01 | The authenticated TLS request truly enters `Bridge::answer → Session::request` with captured immutable identity, op, args and grant | Extract/justify the actual wrapper and constructor invocation; test malformed frames and identity substitution |
| N23-02 | `NativeContext` callback equalities/frame preservation hold for the **actual** request adapter, including every relevant error continuation | Relate concrete `Session::request` closure captures and native pending state to extracted `request_adapter.Work` fields; check error/return branches |
| N23-03 | Dispatch audit callback's success means the intended host append/ack; native `audit_route` cannot be bypassed or swallowed | Source-link `Audit::write_record` to `append_durable_record`; explicitly define process/kernel crash boundary and fail-stop policy |
| N23-04 | `setup_route` returns fresh `Channel::new` with correct bytes, destination, host-grant fields and original credential, no credential sent during TLS handshake | Extract/refine `manifest_request_bytes`, channel constructor and TLS setup; validate server cert/endpoint pins and deadline/drop paths |
| N23-05 | Actual `ManifestProvider::send` delegates exactly to `send_manifest_bytes → Channel::submit` using the same request, writer and poststate | Native specialization/monomorphization + source-linked adapter proof; forbid bypass within selected profile |
| N23-06 | **Sink closure**: every reachable native credential-bearing attempt is covered by `NativeSinkCoverage`, including transient buffers, error, shutdown and `Drop` effects | Close compiler-linked full transitive reachable sink graph; compare against `write`, `write_all`, `send`, TLS and FFI hooks; demonstrate no unmodeled sinks |
| N23-07 | High-level `write_all` and `flush` results correspond to actual OS/rustls attempt events without assuming TCP delivery; partial writes cannot be blindly retried | Define external writer semantics and trace refinement; account for multi-syscall, partial write and timeout before failure |
| N23-08 | `receive` calls `Channel::into_parts` before any parser, consumes exact channel and returns selected parser outcome | Link `ManifestProvider::receive`, `manifest_response`, size/status/encoding/reflection denials and newline/malformed-body cases |
| N23-09 | `Disclosure::project` and `ensure_safe` on the **actual** `serde_json::Value` obey the approved-field and literal-secret reflection contracts | Tie native conversions to `filter::project_fields`, `render`, `core::release` and native scanning; test secret in selected field, error text, nested values |
| N23-10 | Completion audit acknowledgment and *second* current grant/lease check are linked to the same native invocation, and no success frame is reachable on a failure | Bind actual `PendingCompletion` callbacks to completion receipts; explicitly handle close, EOF, timeout, audit failure |
| N23-11 | `Completed::into_value → GuestFrame::from_answer → GuestFrame::send` is actual approved JSON/frame path; invalid results never get a success frame | Prove native `toCapturedJson` instantiation, guest error fallback, frame limit and single-writer/error path; characterize flush/shutdown |
| N23-12 | Native feature/config closure: all excluded write, legacy, delegate, control and OAuth acquisition routes are unreachable, or all effects are included | Build profile-specific entrypoint/reachability witness, no ignored optional features, terminal/startup failure map |
| N23-13 | For NR-4, pair two actual native executions under a justified declassification relation and show all public observations match | Include denied/allowed status, byte lengths, error, timing/close metadata policy; do not assume the result as `step_preserves` |

The **first proof to close** is N23-05 against native `ManifestProvider` and
its exact `Channel.submit` callback, then N23-02, N23-03 and N23-10, then
N23-06 transitive sink closure. N23-04 and N23-07 are inseparable from
bounding the TLS/OS environment. If a required extracted API simply does not
exist, extend the tracked production-called extraction; do not introduce a
parallel hand-built happy-path model and treat it as linked.

## Review checklist for the maintainer

For each proposed theorem, check that:

1. Its hypotheses say something that has either been source-proved or is a
   narrowly stated external OS/crypto/provider contract. It must not assume
   "all native I/O is authorized" to prove that all I/O is authorized.
2. The linked Rust source actually executes the extracted function under the
   specified startup profile; type correspondence alone is not enough.
3. All returned error prefixes are covered; non-returning/panic/drop paths
   are either covered or explicitly excluded from the quantified guarantee.
4. "Audit success" is distinguished from disk durability after power loss,
   and "writer success" is distinguished from provider delivery.
5. The result includes a positive successful read and does not earn safety by
   denying everything.
6. Error framing, secret reflection, parsed response selection and bytes
   escaping to the guest are examined independently of provider sends.
7. Compilation of the focused Lean module is the routine proof gate. Do not
   add routine axiom dumps or redundant sorry/admit inventories to the build.
   The independent, comparative transitive axiom audit belongs at the end of
   the reviewed formalization campaign.

## How to build and resume

```bash
cd ~/code/aivm-secrets/proofs
lake exe cache get
lake build GarrettNR23Assurance
```

The assurance root imports the request, native effects, failure and guest
modules. For pinpointing elaboration errors, build each new module separately:

```bash
lake build GarrettNR23Request GarrettNR23Effects GarrettNR23Failures GarrettNR23Guest GarrettNR23Assurance
```

Once the Lean build passes, the next substantive increment is discharging
specific remaining native premises, not adding more abstract facts to this
ledger. Re-run focused source checks after any Rust adapter/extraction change.
