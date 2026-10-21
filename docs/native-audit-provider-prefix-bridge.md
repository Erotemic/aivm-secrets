# Native audit / provider prefix bridge (Track A increment)

**Scope:** native Rust `manifest-https-v1` read-profile dispatch. **Status:**
source-reviewed production adapters with native Rust fault tests authored;
**not** a full NR-2 simulation, NR-3 reachable-I/O closure, or an independent
Lean/OS correctness proof. No protocol/credential/policy format changes.

## Production-called connection to the modeled events

The existing extracted dispatch controller in
`rust/crates/aivm-secrets-garrett-core/src/dispatch.rs` records
`begin_dispatch_audit`, calls the native `Work::audit` callback, and only then
records `acknowledge_dispatch`. In the actual manifest work,
`manifest_session.rs` routes that callback to `Audit::write_record` in
`custody.rs`. `Audit::write_record` holds its session-wide mutex and calls
`append_durable_record` on the real `std::fs::File` adapter:

1. Reject any previously poisoned audit.
2. Mark the audit poisoned **before** entering any effectful append.
3. Append the canonical record bytes, then a newline, then call `File::sync_all`.
4. Clear the poison flag and return success only if all three operations
   returned success. On any returned error, leave the session audit poisoned.

This ordering discharges the *source-owned* part of the audit acknowledgement
contract for returned successes/errors. The environment still supplies the
meaning of successful `write_all`, `sync_all`, and file/OS storage durability;
a `sync_all` return does not establish persistence against every crash/failure
model. An unwind while the mutex is held poisons the mutex as well.

After audit acknowledgement, the production controller performs provider
setup and a current-grant check. The existing `begin_send` gate records an
**attempt** before calling the native `ProviderWriter`.
`provider_io::Request::submit` consumes its single attempt before invoking
`std::io::Write::write_all`, then invokes `flush` only after successful write.
Response parsing requires a successful-flush `Channel::into_parts` receipt.
Neither an acknowledged audit nor a send attempt implies provider arrival.

| Native observable condition | Audit attempt / acknowledged | Provider attempt | Native bytes accepted | Release permission |
| --- | --- | --- | --- | --- |
| Audit already poisoned | yes / no | no | none | no |
| Audit payload, delimiter, or sync error | yes / no | no | none | no |
| Late freshness revocation after acknowledged audit | yes / yes | no | none | no |
| Native write refuses zero bytes | yes / yes | yes | none | no |
| Native write accepts prefix and fails | yes / yes | yes | prefix only | no |
| Native flush fails | yes / yes | yes | full request *may* be accepted | no |
| Write, flush and response parsing succeed | yes / yes | yes | full request | still requires selection, completed audit and late freshness check |

The modeled `GarrettRequestTrace.lean`, `GarrettOwnedRequestTrace.lean`,
`GarrettReadPrefixes.lean` and the extracted `RequestEffects` receipts already
represent these distinct causal stages. This increment provides actual
production-source event bindings and native fault witnesses for the audit /
provider primitive seam; it does **not** introduce a second handwritten
abstract request interpreter.

## Regression coverage

- `custody::tests::durable_audit_ack_only_after_payload_delimiter_and_sync`
  checks the exact accepted record-prefix and sink call ordering for payload,
  partial payload, delimiter, and sync errors. Failure cannot be retried.
- `custody::tests::panic_during_audit_append_leaves_attempt_poisoned`
  checks that an unwind cannot reset the one-attempt state.
- `custody::manifest_session::wire_tests::real_durable_dispatch_audit_precedes_each_native_write_prefix`
  reaches the production `dispatch` controller and native `ProviderWriter`
  under a real local audit file, with injected audit refusal, late revocation,
  zero/partial write, failed flush and success. It asserts that the *returned*
  receipt, actual audit JSON line, writer-accepted bytes, parsing and replay
  denial agree for each case.
- The existing `partial_native_write_and_flush_failures_are_attempts_and_never_parse_or_retry`
  and `completion_receipt_tracks_real_audit_and_late_denial` retain separate
  send and completion coverage.
- `dev/verification/w3_effect_boundary.py` now checks the reviewed production
  audit ordering and actual File adapter. `tests/test_secrets_w3_effect_boundary.py`
  includes deliberate bypass mutations. These checks are limited source guards.

## Validation and handoff

```bash
python3 dev/verification/w0_contract.py check
python3 dev/verification/w3_effect_boundary.py check
python3 dev/verification/w6_adapter.py check
python3 -m pytest -q tests/test_secrets_w3_effect_boundary.py
python3 dev/verification/quick_w6_read.py

cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib durable_audit_ack_only_after_payload_delimiter_and_sync
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib panic_during_audit_append_leaves_attempt_poisoned
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib real_durable_dispatch_audit_precedes_each_native_write_prefix
```

The authoring environment did **not** have Rust, Cargo or Lean available.
The new native test cases are therefore **not claimed to have compiled or
passed** here. Run those tests, the existing native W6 integration gate and
the focused Lean checks on the pinned maintainer toolchain. The old
`proofs/garrett-manifest.json` is deliberately **not re-recorded** by this
overlay: its native source hashes will remain stale until the maintainer
reruns `python3 dev/verification/garrett.py record` with the full associated
Rust/extraction/Lean/parity verification. Do not manually renew the assurance
hashes as a substitute for verification.

## What remains for Track A

- Derive a general native primitive-event simulation theorem for the actual
  audit/File and provider/Write callback pair instead of relying on bounded
  fault witnesses and reviewed source ordering.
- Cover exact filesystem and TLS error mapping, partial writer behavior,
  sequence lifetimes, drop/unwind effects and external syscall semantics.
- Compose both request phases, completion audit, selected guest frame,
  late revocation and connected sequential histories in one explicit
  native-to-W4 observation relation.
- Complete the NR-3 reachable-sink/dependency closure separately; this change
  does not assert complete I/O mediation.

Follow-up: [Native Writer callback-to-W4 projection](native-writer-callback-simulation.md).
