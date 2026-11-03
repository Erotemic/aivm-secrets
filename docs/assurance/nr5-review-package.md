# NR-5 review package: native read profile

**Status (2026-11-02): assembled by an agent for an independent reviewer.
Not a certification, not a release approval.** NR-5 and OUT-5 need a person
other than the author to accept or reject each row of section 8. This page
is an index: it says what to read, in what order, what to run, and where
each piece of evidence is. The detailed rows are in the
[claim-to-evidence matrix](claim-evidence-matrix.md); the plain-language
walk through the theorems is the [proof tour](native-read-proof-tour.md);
every premise is in the [assumption ledger](../planning/aivm-secrets-assumptions.json).

## 1. The claim under review

Draft of the scoped conditional statement that NR-5 would publish:

> For the native `garrett-bridge-read-only` profile (`manifest-https-v1`,
> `writes = deny`, a file credential, identity from an authority root, no
> coordinator, no legacy forwarding, one sequential mTLS guest session),
> every request a guest sends that returns has:
> (a) provider sends exactly matching the source trace's sends, each
> after a current admission, an acknowledged host audit record and the send
> gate, bound to the request's own identity, operation and route, carrying
> exactly the extracted encoder's bytes for that route;
> (b) a guest reply that is either the checked encoding of the host-selected
> fields of the provider response or one of 17 fixed denial lines;
> (c) for an adaptive guest, the same frame history in any two worlds that
> agree on the selected data, the pagination row count, the status class and
> the public code of each transport failure.
> This holds under the premises listed in section 5, which are contracts on
> named native code, libraries and the deployment, not proofs.

It does **not** claim: VM isolation, whole-service secrecy, delivery to the
provider, TLS or OS correctness, timing side channels, writes, or anything
about the proxy profiles. Three scope points a reviewer should hold it to:

- A denied or failed final outcome does not mean zero provider traffic: a
  read may send a preflight and a final request, each after its own checks,
  and a later step can still fail. (a) accounts for every such send.
- A "read" is an operation the host manifest declares as one; its absence of
  side effects is the provider API's semantics, not checked here.
- Revocation does not interrupt an admitted send. In authority-root mode a
  completed revocation has drained every earlier admission; the legacy
  registry-file mode, which lacks that fencing, is refused by the profile.

## 2. Reading order

1. The statements (not the proofs) of the three production theorems in
   section 3. Check that no premise restates its conclusion.
2. [`custody/provider_stream.rs`](../../rust/crates/aivm-secrets-garrett/src/custody/provider_stream.rs)
   (about 100 lines): the only native code that opens a provider TLS
   session or can write to one.
3. The `NATIVE-SINK-01` ledger entry, then the other premises in section 5.
4. The claim matrix rows SINK-01, TRACE-01, NI-TRACE-01 and IO-REFINE-01.
5. Run section 9's commands, or read the recorded runs in section 6.

## 3. Theorems under review

All are in the root `proofs/` Lake package, over the Aeneas extraction of
`rust/crates/aivm-secrets-garrett-core` in
`proofs/generated/AivmSecretsGarrettCore.lean`.

| Theorem | Says | Native premises it still needs |
| --- | --- | --- |
| [`production_calls_have_own_evidence`, `production_calls_have_own_route_payload`](../../proofs/GarrettProductionSendOrigin.lean) | Each send individually: its own dispatch segment has exactly one `providerSend`, of its own phase, accepted, audited and bound to the context; its channel was built by that dispatch's setup for the request's own route, holding the extracted encoder's request (over `Submitting`) | `NATIVE-SINK-01` |
| [`production_request_sends_are_the_logged_sends`](../../proofs/GarrettProductionAssurance.lean) | Every returned outcome: sound, bound source trace; the sends asked of the dispatch primitive equal the source sends in number; labelled in order they are an exact sink sequence, each accepted, audited and bound to the constructor context | `NATIVE-SINK-01` |
| `production_accepted_read_has_logged_sends_and_guest_frame` (same file) | The above for a successful read, plus: the guest frame is the exact checked encoding of the selected value | `NATIVE-SINK-01`, the reply's JSON conversion (`RUST-JSON-01`) |
| `production_denial_has_logged_sends_and_fixed_guest_frame` (same file) | The above for a denial, plus: the guest frame is one of 17 fixed lines, whichever public error is reported | `NATIVE-SINK-01` |
| [`exchange_send_writes_route_body`](../../proofs/GarrettChannelWork.lean) | Every exchange reaching the send stage called the native writer with the encoded body for its own captured route, on a fresh channel | `NATIVE-GLUE-01` (`WrapPreserves`) |
| [`production_read_frame`](../../proofs/GarrettProductionReadFrame.lean), [`denial_frame_exact`](../../proofs/GarrettPublicError.lean) | Exact success and denial frame bytes; the credential occurs in neither | `NATIVE-GLUE-01` |
| [`production_frame_noninterference`](../../proofs/GarrettNR4FrameAdaptive.lean), [`adaptive_request_noninterference`, `read_confinement_for_every_document`](../../proofs/GarrettNR4RequestAdaptive.lean) | Adaptive guest, same frame histories under the stated agreement | `MODEL-EXCHANGE-01` |
| [`production_entry_trace`](../../proofs/GarrettRequestContext.lean) | Chronology: admission, audit acknowledgement, late check, attempt, completion in order | `RUST-CLOCK-01`, `EMISSION-RUST-01` |

How the first three drop the older `ExactNativeSinkCoverage` premise:
[`GarrettNativeSendLog`](../../proofs/GarrettNativeSendLog.lean) counts the
channels the extracted dispatch passes to its primitive's `send` with a ghost
log (`dispatch_grew`, `calls_count`, `run_calls`, `calls_match_sends`,
`labelled_exact`); [`GarrettDispatchErasure`](../../proofs/GarrettDispatchErasure.lean)
shows the log changes no result (`dispatch_forward`, `logged_forward`). The
older theorems that take `ExactNativeSinkCoverage` remain in the same file
and still compile.

## 4. The trusted native boundary

The native crate is `rust/crates/aivm-secrets-garrett` (about 16k lines).
For the read profile the parts that matter are:

| File | Role | Pinned by |
| --- | --- | --- |
| `bridge_read_only_main.rs`, `profile.rs` | Refuses every configuration but the read profile | `profile::read_only` tests, NR-0 |
| `tls.rs` | Guest mTLS listener, frame read/write, `GuestFrame::from_answer` | `NATIVE-GLUE-01`, W3 |
| `custody/manifest_session.rs` | Builds the extracted `ScopedRequest`, supplies native callbacks (request fields, wrap, connect, parse, audit) | W3, W6, NR-0 hashes |
| `custody/provider_stream.rs` | The only provider TLS connect and the only provider writer; the parser gets a read-only session | W3 (with bypass tests), NR-0 hashes |
| `custody.rs` | Credential type (sealed), audit files and chain, account-status backend (unreachable in this profile) | `tests/test_native_credential_readers.py`, W3 |
| `manifest.rs`, `manifest/disclosure.rs` | Policy load, JSON parse into the document the extracted release reads | `RUST-JSON-01`, `ROUTE-NATIVE-01` |

Source guards: `dev/verification/w0_contract.py`,
`w3_effect_boundary.py`, `w6_adapter.py`, `w6_pending_boundary.py`,
`nr23_native_edges.py`, `native_read_profile.py`. They are text and hash
checks with bypass tests, not reachability proofs.

## 5. Premises to accept or reject

One line each; the ledger entry is authoritative.

| ID | Contract | Evidence |
| --- | --- | --- |
| `NATIVE-SINK-01` | Every credential-bearing provider write is one `ProviderWriter::write_all` made by the extracted `Channel::submit` | One transport module (W3), sealed credential with seven pinned readers, `dev/native_syscall_witness.py` |
| `NATIVE-GLUE-01` | The few native lines around extracted calls only map types and call once | W3 guard, byte oracles in Rust tests |
| `RUST-HTTPS-01` | rustls and the OS send the given bytes to the authenticated peer | Library contract; live OUT-3 run |
| `RUST-MTLS-01` | rustls authenticates the guest certificate chain | Library contract; identity negatives in `tests/test_rust_garrett_authority.py` |
| `RUST-AUDIT-01` | The filesystem appends, renames and fsyncs as documented | Library/OS contract; audit chain tests |
| `RUST-CLOCK-01` | Clocks and locks behave as specified | OS contract |
| `EMISSION-RUST-01` | Clocks sampled after blocking setup; adapters keep the extracted recheck before every write | Extracted `grant_window`; W3 |
| `RUST-COMPILER-01` | Rust, Charon/Aeneas and Lean correspond on the extracted fragment | Pinned toolchains; `dev/verification/garrett.py` mutants |
| `RUST-JSON-01` | serde_json parses and encodes correctly | Library contract; confinement holds for every parsed document |
| `MODEL-EXCHANGE-01` | A transport failure is modeled as one of 17 public codes | `production_failure_frame` |
| `ROUTE-NATIVE-01` | JSON layer of templates and argument text | Extracted `fill_target`, `parse_template` |
| `CONTROL-NATIVE-01` | `describe`/`renounce` callbacks revoke and record | Extracted `control` |
| `ENV-GUEST-01`, `RUST-PRINCIPAL-01`, `HOST-01`, `LAUNCH-01`, `CHAN-01`, `MEM-01` | The deployment keeps the guest out of host state | VM runs (section 6); not proved |
| `P4-CA-02` | An admitted send can complete after a later revocation | Stated race |

## 6. Recorded evidence

| Evidence | Date | Record |
| --- | --- | --- |
| Synthetic usable-system gate, `--full-tests` | 2026-11-02 (at `c1320b3` plus the docs of `b8a435e`) | passed: 167 Rust unit, 607 required workflow and 3,496 full-suite tests; evidence in the run's `.tools/system-*/report.json` (local, not committed) |
| Whole-process syscall witness | 2026-11-02 (at `a323e36`) | `dev/native_syscall_witness.py`; no credential bytes in any write-family syscall, only the provider as a destination |
| Agent-run nested KVM: baseline, adversarial, proxy, constrained, simulated agent, guest-wide secret hunt | 2026-10-24 | [local VM run](../../dev/validation/2026-10-24-local-vm-acceptance.json) |
| Maintainer-run real KVM, baseline and adversarial (OUT-2) | 2026-10-21 | [VM acceptance](../aivm-vm-native-acceptance.md) |
| Maintainer-run live GitHub read-only (OUT-3) | 2026-10-21 | [live acceptance](../aivm-github-live-readonly-acceptance.md) |
| Axiom audit (at the maintainer's request) | 2026-10-24 | [axiom-audit.md](axiom-audit.md) |

The live and VM runs predate the 2026-11-02 transport refactor (`8aa0125`)
and proof changes; the synthetic gate and the syscall witness were rerun
after them.

## 7. Mutation evidence

`mutate()` in `dev/verification/garrett.py` re-extracts the core with one source
change and rebuilds the proof modules; a mutant passes only if some proof
fails. Labels starting `owned dispatch`, `provider driver`, `provider io`,
`provider channel`, `trace origin` and `send log` target this claim. The
native guards have bypass tests in `tests/test_secrets_w3_effect_boundary.py`.
On 2026-11-02 the two `send log` mutants (a send repeated after the gate,
an attempt marked without a send) were both rejected, first by
`GarrettDispatch`, whose exact callback characterization the send-log
proofs build on. The full campaign was not rerun. `proofs/garrett-manifest.json` was
re-recorded on 2026-11-02 after an independent agent review of the changes
since its last accurate record (`e741383`): fresh extraction equal to the
committed model, every Lean module built, and 29 newer proof modules added
to its coverage. Formatting is not a gate (rustfmt was removed from `garrett.py check`).

## 8. Known limits

- A send already admitted before a later revocation can still complete
  (`P4-CA-02`).
- A partial `write_all` is an attempt, not a delivery; a failed send is never
  retried and is reported as a fixed public error.
- One sequential guest session; concurrency between sessions is outside the
  theorems.
- Connection close, EOF and partial guest frame writes are observable and are
  not modeled as guest observations (NR-0 `S-GUEST-CLOSE`).
- Timing, packet size and co-resident side channels are excluded.
- DNS is pinned by policy; TLS, the OS and the kernel are trusted.
- The account-status backend is compiled into the binary but refused by the
  read-only configuration.

## 9. Reproduce

```bash
# Proofs (warm: about 5 minutes; cold: longer)
lake -d proofs build
# Synthetic witnesses, native conformance runners and source guards
python dev/verification/system.py --full-tests
# Whole-process syscall witness (needs strace)
python dev/native_syscall_witness.py
# Mutants for this claim
PYTHONPATH=dev/verification python -c 'import garrett; garrett.mutate("^(owned dispatch|send log|provider driver) ")'
# Real VM runs need an AIVM host; see docs/aivm-vm-native-acceptance.md
```

## 10. Decision sheet

Copy this table into the review record. One rejected row blocks the claim
it supports.

| Item | Accept / reject | Reviewer notes |
| --- | --- | --- |
| Section 1 statement, as worded | | |
| SINK-01 row of the claim matrix | | |
| TRACE-01 row | | |
| NI-TRACE-01 row | | |
| IO-REFINE-01 row | | |
| Deployment and custody row | | |
| `NATIVE-SINK-01` | | |
| `NATIVE-GLUE-01` | | |
| Library contracts (`RUST-HTTPS-01`, `RUST-MTLS-01`, `RUST-AUDIT-01`, `RUST-CLOCK-01`, `RUST-JSON-01`) | | |
| `RUST-COMPILER-01` | | |
| `EMISSION-RUST-01`, `ROUTE-NATIVE-01`, `CONTROL-NATIVE-01`, `MODEL-EXCHANGE-01` | | |
| Deployment premises | | |
| Known limits acceptable for the intended deployment | | |
