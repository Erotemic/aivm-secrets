# Native Garrett read failures: W4/W5/W6 finite trace refinement

Status: **portable gate checked locally; new native-process cases still require
maintainer execution.** Incremental overlay after the accepted read-history and
paired-metadata overlays. No production Rust, credential-handling logic, Lean
proofs, provider accounts or TPMs are modified or used by this change.

## Why this slice

The existing W4/W5 read-path extension considers no-preflight, checked-only
and two-phase **successful** releases. W6 observes provider bytes, dispatch
and completion audits, and the canonical guest frame. Its denial checks,
however, did not independently declare **which public error** was expected
from a host-defined failure, and it had not compared private provider
**failure** diagnostics across two full native executions.

This slice extends the finite implementation-to-model witness to failures
*after the provider receives an audited read*. The causal question is whether
private provider responses can change the guest's observed denial, alter the
approved effect sequence, produce a completion, or reach the host audit. It
also refuses unreviewed audit fields and mixed request/identity metadata.

## Scoped observed paths

| Read shape | Synthetic failure | Expected public outcome |
| --- | --- | --- |
| No preflight, final GET | 401 versus 422, with different private headers/bodies | `upstream_rejected` |
| No preflight, final GET | 500 versus 503, with different private headers/bodies | `upstream_error` |
| No preflight, final GET | two different malformed 200 JSON documents | `upstream_response` |
| Preflight-only checked fact | 401 versus 403 before any final request | `upstream_rejected` |
| Preflight plus final read | successful preflight and 500 versus 503 final responses | `upstream_error` |

All requests go to a **local synthetic HTTPS provider** through actual native
Rust bridge/provider paths when `--native` is selected. Guest frame capture
uses actual mTLS and canonical JSONL bytes. The test-owned failure category
and host-selected effect prefix are inputs to the oracle; neither is
reconstructed from the observed denial.

`FailureContract` maps four explicitly declassified failure classes to three
public codes. It does not assume that changing provider status classes is
unobservable. Each paired execution must independently agree with its declared
code; the pair then requires identical canonical guest frames and explicitly
bound read-effect phases. An observed prefix is interpreted into abstract
`audit:<phase>`, `provider-send:<phase>`, and `guest-denied:<public-code>`
events. This is a *test-level* interpretation, **not** a theorem that all
native executions refine the Lean `Event` model.

The stronger audit-schema check also verifies the exact reviewed dispatch and
completion keys, schema version, declared operation, grant/policy shape,
request digest, and identity consistency across phases. It is enabled for
native raw-frame observations; simplified historical portable fixtures retain
an opt-in to avoid fabricating claims about their missing provenance.

## Adversarial controls

Portable tests fail if a guest denial has the wrong public code, a provider
message leaks, a result/metadata field appears on denial, a second frame is
appended, a completed audit is forged, a provider send lacks a causal audit,
there is an unapproved additional send, a read is promoted to a write, a
request digest changes, an unknown audit field appears, or the bound principal
changes across phases. The source-shape gate additionally rejects reviewed
Rust mutations to the fixed public error mapping, the guest canonical
serializer, and the HTTP 4xx classification. These source checks are
**review guards**, not complete control-flow evidence.

## Fast acceptance

No Rust or Lean rebuild is necessary for this overlay: production source and
proof source are unchanged. It adds new *tests* that run existing native
binaries. On the maintainer's machine:

```bash
python dev/verification/quick_w6_read.py --failure-only
python dev/verification/quick_w6_read.py --failure-only --native
```

The second command fails on skipped native cases. It reuses the already-built
fresh native executables and runs only the new targeted mTLS/HTTPS experiments;
it does not run Cargo builds, Lean, Charon or full pytest. The normal
`quick_w6_read.py --native` now covers existing success traces **and** the new
failure traces. Use `--native --build` only if the native binary freshness check
identifies a stale/missing executable.

Portable authoring validation: **31 focused tests passed** with W0/W3/W6,
new public-error source review, and the existing W4/W5 read-path source check.
No new native-process cases were executed in this authoring environment, which
has no Rust toolchain. The maintainer's earlier passing full native/Lean gate
is a baseline, not validation of the new tests.

## Not proved or exercised here

This slice does **not** address pre-egress denials or the audit-but-no-send
window, revocation timing, TLS EOF/timeout and side-channel observations,
operator approvals, writes and retry uncertainty, OAuth refresh, coordinator
state, guest filesystem isolation, arbitrary provider responses, or complete
native call reachability. The existing W4/W5 Lean theorem statements are
unchanged; no new kernel-checked implementation-to-trace proof is claimed.

The next high-value step is formalizing the adapter's denial/success
observation abstraction against the actual extracted source and investigating
the remaining audit-without-emission and error/closure interleavings. The
reproducible finite witnesses here provide counterexamples and concrete
acceptance behavior for that proof work without claiming universality.
