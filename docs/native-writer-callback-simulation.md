# Native Writer callback-to-W4 attempt projection (Track A increment 2)

**Scope:** `manifest-https-v1`, native read profile, *returned* calls to
`aivm_secrets_garrett_core::provider_io::Request::submit` and `Channel::submit`.
**Status:** general source-linked Lean proof **authored, pending maintainer Lean
compilation**; source-reviewed native callback binding and regression test
**authored, pending Cargo compilation**. Not an NR-2, NR-3 or NR-4 exit.

## Source path and proof

`request_adapter::Pending::dispatch` executes the extracted production
`dispatch::dispatch`; its guarded `Pending::send` calls `RequestEffects::begin_send`
first and delegates to the production provider. The native
`ManifestProvider::send` calls `send_manifest_bytes` -> extracted
`provider_io::Channel::submit` -> extracted `Request::submit` ->
`ProviderWriter<StreamOwned<...>>::write_all` / `flush` -> `std::io::Write`.
The source-owned `ProviderWriter` maps both errors to `UpstreamResponse`.

New `proofs/GarrettNativeWriterEvents.lean` imports **existing extracted Rust**
and the existing `SubmitRun` and `send_counts_exactly` proofs. Its `Observed`
relation is an observation of callback *invocations*, not another request
executor. Its `submit_observes_callbacks` classifies all returned source
executions:

| Entry/request state | Extracted outcome path | High-level callbacks | W4 delta for this call |
| --- | --- | --- | --- |
| Already spent | replay refusal | none | none (old attempt belongs to prior prefix) |
| Fresh | `write_all` returns error, including after partial acceptance | write | one provider attempt |
| Fresh | `write_all` succeeds, then `flush` returns success/error | write, flush | one provider attempt |

The last column is proved by `fresh_callback_projects_one` and
`replay_projects_nothing` under this exact observation. The
`guarded_channel_callback_projection` theorem additionally composes an
**accepted** actual `RequestEffects::begin_send` transition, a source-issued
current admission stamp, and a returned actual `Channel::submit`. Its
conclusion equates the real receipt delta to the projected writer invocation
and proves W4 soundness and single-use of the request buffer.

No `providerReached` bit, invented success acknowledgment or admission
boolean is assumed. The theorem **does** explicitly require that the
selected channel was fresh, the adapter passed the same source-issued stamp,
the prefix was reachable, and the real channel call returned; these are
inputs to be discharged by whole-native adapter linkage. The writer callback
results are part of the existing extracted semantics, not modeled TLS events.

## Native adapter and external contracts

`ProviderWriter` is a production-called `std::io::Write` adapter, not a
witness that the peer received the bytes. `write_all` can call the underlying
`write` repeatedly, retry `Interrupted`, accept only a prefix and then
return `WriteZero` or another error. The new
`native_writer_callback_retries_interrupted_but_never_retries_spent_request`
Rust test reaches `send_manifest_bytes` with exactly those cases, checks the
accepted prefix and flush calls and verifies that a replay withdraws parser
eligibility even after an earlier successful flush. The W3 source guard now
pins the exact native callback delegation, call ordering and error mapping,
including deliberate bypass mutations.

`std::io::Write`/Rustls/OS behavior, callback panics, asynchronous shutdown,
`Drop`, TLS `close_notify`, setup/handshake traffic, exact syscall counting,
arrival at the remote provider, and all alternate sinks **remain external**.
One high-level `write_all` callback is **not** one syscall. This increment
makes only a returned-call correspondence claim.

## Validate

Apply both Track A overlays in order, then run:

```bash
python3 dev/verification/w0_contract.py check
python3 dev/verification/w3_effect_boundary.py check
python3 dev/verification/w6_adapter.py check
python3 -m pytest -q tests/test_secrets_w3_effect_boundary.py

cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib native_writer_callback_retries_interrupted_but_never_retries_spent_request
cargo +nightly-2026-09-17 test --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib real_durable_dispatch_audit_precedes_each_native_write_prefix

cd proofs
lake exe cache get
lake build GarrettNativeWriterEvents
cd ..
```

Once the **full pinned** Cargo/extraction/Lean/theorem/parity gates have
passed, refresh `proofs/garrett-manifest.json` using
`python3 dev/verification/garrett.py record` (and its documented validation
prerequisites); do not hand-edit old checksums or treat the W3 fingerprint
as assurance provenance. The previous Track A patch already invalidated the
old assurance source hashes, and this one adds a theorem inventory entry.

## Next Track A work

Establish a source-linked *entire dispatch callback* relation connecting the
current-stamp factory, exact audit acknowledgment, late check and the above
writer invocation to the same request and phase. Then extend to
completion-audit/selected guest frame/close and connected request histories.
Resolve NR-3 reachable effects of all dependency callbacks and failures in
parallel. The present theorem only covers the producer of the provider-send
observation under its stated native linkage premises.

Follow-up: [Source dispatch and native writer callback chronology](native-dispatch-callback-observation.md).
