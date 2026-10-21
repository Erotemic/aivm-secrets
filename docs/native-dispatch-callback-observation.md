# Source dispatch and native writer callback chronology (Track A increment 3)

**Profile:** `manifest-https-v1` native read; both preflight and final phases.
**Status:** source-linked Lean composition and synthetic native integration
regression authored. Rust/Lean execution is pending the pinned maintainer
toolchains. **Not** NR-2/NR-3 exit or a whole-service mediation proof.

## Specific improvement

The earlier `GarrettNativeWriterEvents.lean` proved a returned call to the
extracted `Request.submit`/`Channel.submit` has a callback schedule, and that
a successful source `begin_send` gate contributes one W4 provider **attempt**
even if the high-level write or flush fails. Separately,
`GarrettDispatchTrace.lean` already proved a chronological W4 trace for every
returned extracted `dispatch.dispatch` when it is driven through
`current_admission::Bound`.

The new `GarrettNativeDispatchEvents.lean` composes those two facts at the
**same** `RequestEffects.begin_send` gate. It reconstructs an entire returned
dispatch trace as the source-gate prefix, exactly one provider-attempt event,
and the source-gate suffix. Its theorem uses actual reported dispatch state,
the checked-to-attempted native `SendState`, and the real returned
`Channel.submit` value. It does not assume an auditOK/providerReached flag,
network delivery, or a separate hand-written dispatcher.

The **explicit linkage obligations** remain:

- Identify `beforeEvents` and `afterEvents` at this specific `begin_send` call
  within the returned `dispatch.dispatch` invocation, and establish that they
  are its actual source-extracted receipt transition prefixes/suffixes.
- Identify the checked stamp with the *same* bound current-admission context
  used to construct the native provider and prove its source origin.
- Relate the channel callback return to the concrete native File, Write,
  rustls/TCP operations, including OS errors, TLS handshake, unwinding,
  shutdown and other reachable effects.

These premises are **local source/adapter obligations**, not claims about the
whole trace. The whole dispatch trace is *derived* after they are supplied.

## Native at-the-callback regression

`custody::manifest_session::wire_tests::native_read_dispatch_audit_to_writer_callback_chronology`
uses the production-owned `dispatch::dispatch` and `send_manifest_bytes` path,
`ManifestWire`, `ProviderWriter`, the full native request-byte encoder, and
`Audit::write_record` on a real temporary host audit file. The `Work`
primitive is synthetic; this test does not enter the actual `Session::request`
factory or exercise the production `CurrentChecks`/TLS implementations.

Unlike an after-the-fact file comparison, the test's `std::io::Write::write`
callback opens/parses the audit file **at the moment the provider write is
attempted**. It rejects any write before the acknowledged host audit line.
For each of preflight/final and nine outcomes it checks the exact callback
order and the extracted receipt flags:

| Fault | Audit acknowledgment | Native write calls | Native flush | Guest-style provider value |
| --- | --- | --- | --- | --- |
| Prepare fails | no | 0 | 0 | no |
| Audit refuses | no | 0 | 0 | no |
| Configure fails after audit | yes | 0 | 0 | no |
| Late check fails after audit | yes | 0 | 0 | no |
| Provider recheck fails | yes | 0 | 0 | no |
| First write returns zero | yes | 1 | 0 | no |
| Partial write then error | yes | 2 | 0 | no |
| Flush fails after write | yes | 1 | 1 | no |
| Successful write/flush | yes | 1 | 1 | yes |

For every phase except pre-audit preparation rejection, the test then reruns
that request from the same returned receipt and verifies no second audit or
write callback. Preparation rejection occurs before consuming an audit
attempt and is intentionally excluded from that replay assertion.

These 18 executions are **finite native witnesses**, not an exhaustive proof
of reachable I/O, TLS delivery, `sync_all` crash durability, or panic/drop
behavior. The test uses the actual encoder and dispatcher with synthetic
credentials and controlled writer, not a live provider connection.

## Commands

```bash
cd ~/code/aivm-secrets
python3 dev/verification/w0_contract.py check
python3 dev/verification/w3_effect_boundary.py check
python3 dev/verification/w6_adapter.py check
python3 -m pytest -q tests/test_secrets_w3_effect_boundary.py
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib \
  native_read_dispatch_audit_to_writer_callback_chronology
cd proofs
lake exe cache get
lake build GarrettNativeDispatchEvents
```

Do not print theorem/axiom inventories in everyday builds; use the final,
opt-in comparative axiom audit if specifically requested. The proof provenance
manifest must not be re-recorded until all pinned native, extraction and Lean
validation prerequisites actually pass.

## Next

Discharge the prefix/suffix adapter linkage for the **real** request factory,
connect the File append callback's exact outcome to the source audit receipt,
and then extend through completion-audit and selected guest-frame release.
The NR-3 transitive sink/OS/drop/unwind review remains independent.
