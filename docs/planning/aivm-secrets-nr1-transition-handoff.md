# NR-1A: production manifest dispatch-phase transition

## Implemented in this overlay

- Extractable pure Rust `read_transition::prepare(phase, admitted_operation_write,
  effect_write)` refuses writes in preflight and refuses a final write unless the
  original operation admitted writes. It returns an opaque `Prepared` value.
- `read_transition::acknowledge(prepared, ack)` returns an opaque `Audited`
  value only if `ack` is true.
- The production `PreparedDispatch` constructors invoke that **same** core
  function, not a parallel branch. Its audit path calls `acknowledge(..., true)`
  *after* `Audit::write_record` returns success, and the executor checks the
  effect write bit against the carried audited transition. Phase is carried
  through the core value; no second native phase enum is maintained.

These are actual Rust changes, not a simulated proof. The native bridge remains
responsible for checking the current grant immediately before provider HTTP.
No provider secret moves to the guest.

## Validate on the pinned Rust checkout

The authoring environment has no Cargo/Rust or Lean toolchain. This overlay's
Rust needs compilation and native acceptance on the maintainer's machine:

```bash
cargo +nightly-2026-09-17 test --locked --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett-core --lib read_transition
cargo +nightly-2026-09-17 test --locked --manifest-path rust/Cargo.toml \
  -p aivm-secrets-garrett --lib unapproved_read_or_preflight_cannot_become_write_dispatch
python dev/verification/quick_w6_read.py --native --build
python dev/offline_native_guest.py
```

`python dev/verification/quick_w6_read.py` runs portable source/oracle checks,
without Charon or full suite. Running the standalone operator/guest workflow
is a product acceptance witness; it remains **unconfirmed** after the last
policy fix until executed successfully on the maintainer checkout.

## Next concrete proof task

1. Re-extract the pinned production core using the existing Charon/Aeneas
   pipeline, recording exact toolchain and source provenance. Check that
   `read_transition::prepare` and `::acknowledge` are present in generated Lean.
2. Prove the phase/write and audit-acknowledgment preservation properties of
   those *extracted* functions, not of a separately copied model. Kernel/audit
   check only those dependencies.
3. Connect the extracted audited token to W4/W5 `Attempt` and native
   `Audit::write_record` effects. A successful return from the adapter is a
   named environmental assumption, not a mathematical proof of durability.
4. Continue NR-3 I/O reachability and W8 actual guest/host isolation. Do not
   claim that the private Rust type closes alternate sinks or dependency paths.

## Security boundary and known limitations

This is a **first NR-1 seam**, not complete forward simulation. `ack=true`
comes from a trusted adapter after `write_record`; the native network writer
still depends on a late grant/epoch check, TLS, socket and IO contracts.
Failures while emitting provider bytes and while returning guest frames remain
open refinement obligations. Only a real isolated VM can validate the OS guest
compartment; `dev/offline_native_guest.py` currently uses two directories
under one Unix identity.
