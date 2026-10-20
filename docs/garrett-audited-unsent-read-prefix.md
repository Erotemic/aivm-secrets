# Garrett native read: audited-but-unsent prefix witnesses

Status: **new portable model/oracle and source-shape gates checked; native Rust
mTLS cases pending maintainer execution.** Incremental overlay following the
accepted failed-read refinement. No production Rust, credential handling,
protocol formats, or existing Lean theorems change.

## Problem

A native manifest read has two distinct moments: `PreparedDispatch::audit`
records the host-selected effect and the bridge's `exchange_manifest` later
attempts a provider TLS connection. Following TLS setup, `emit_current(fresh,
...)` checks current authority immediately before invoking the credentialed
HTTP writer. A failed connection, invalid server certificate, remote
revocation, or expiry may therefore produce **an audit record but no complete
provider request**.

The existing W6 success and provider-failure oracle requires a provider
arrival for every dispatch audit. Applying it to the interval between audit
and send would falsely classify the legitimate fail-closed trace as an
incomplete or unauthorized operation. Conversely, assuming every audit row
represents a sent request would erase the important pre-send denial boundary.

## Scoped finite trace interpretation

The reviewed profile only supports sequential read-only native
`manifest-https-v1` operations. The test supplies a host-compiled effect plan,
checks it independently against the Python normative policy compiler, and
observes real Rust guest TLS replies, provider HTTP arrivals, and private host
audit rows.

| Path | Audited prefix | Actual provider arrivals | Abstract observation |
| --- | --- | --- | --- |
| Final-only, failed TLS or late denial | `final` | none | `audit:final`, `guest-denied:<code>` |
| Preflight only, failed TLS | `preflight` | none | `audit:preflight`, `guest-denied:<code>` |
| Two-phase, final stopped before HTTP | `preflight`, `final` | `preflight` only | `audit:preflight`, `provider-send:preflight`, `audit:final`, `guest-denied:<code>` |

`PendingContract` explicitly specifies the audited prefix, the sent prefix,
and the authorized public denial code before observing the native execution.
For this initial slice, the sent prefix must equal the audited prefix with
**exactly the final audited phase removed**. This prohibits silently
accepting a missing preflight provider request, an unauthorized extra send, or
multiple pending dispatches. No completion record or guest result is permitted.

`checked_pending_witness` first uses the existing W6 strict oracle to verify
every *actually observed* provider request, with full headers, body,
policy-compiled route, causal provider-arrival audit snapshot, identity, and
canonical JSONL denial. It separately verifies the single remaining unsent
audit row against the approved last effect, digest, operation, phase,
bound client, grant and policy. It verifies that the later audit cannot appear
in an earlier provider-arrival snapshot. A paired-execution helper checks
that different private setup conditions with identical declassified failure
class and phase prefix do not change the returned guest frame.

This is a finite *application-level* interpretation, not an observation of
raw TLS record bytes or a general Lean simulation theorem. In particular,
zero recorded provider HTTP requests does **not** prove that zero TLS
application-data bytes were attempted in every possible transport failure.

## Synthetic native acceptance cases

1. **Wrong provider CA (final-only and preflight-only)**: configure a valid pinned CA that does not sign the
   synthetic provider's actual certificate. The Rust broker should record
   exactly one selected dispatch of the appropriate phase, fail the provider TLS handshake, send
   no authenticated provider HTTP, and return the fixed `unreachable` denial.
2. **Coordinator revocation at first TLS setup**: block the local HTTPS
   provider's accept path after the Rust broker has recorded `final`, commit
   terminal revocation through an independent local mTLS/SQLite coordinator,
   then unblock the handshake. The final admission check must reject the
   capability, without provider HTTP or successful completion. Another request
   through the same running broker must also fail.
3. **Coordinator revocation at second TLS setup**: allow the checked preflight
   request and fact response, then block the *final* connection. Revoke as
   above; there must be a causal audited preflight provider arrival, a distinct
   unsent audited final effect, no completed audit, and exactly one fixed
   `revoked` guest frame.

These use real Rust broker/client processes, TLS, synthetic credentials and a
local test-only authority. There is no external service or real TPM. Native
Rust coordinator authority parity is tested separately by the existing
coordination suite. The source-only gate detects selected changes to
`PreparedDispatch` auditing, admission, and output release, but cannot prove
compiler-level control-flow dominance or transitive I/O reachability.

## Fast acceptance

```bash
python dev/verification/quick_w6_read.py --pending-only
python dev/verification/quick_w6_read.py --pending-only --native
```

The second command **requires** existing fresh native bridge/client/authority
binaries and fails on skipped tests. There are no Rust production edits, so
Cargo/Lean compilation and Charon extraction are unnecessary for this
increment. To run the entire targeted read set, use
`python dev/verification/quick_w6_read.py --native`; do not run
`--full-tests --call-linkage` simply to review these new finite witnesses.

## Remaining obligations

This slice does not prove universal W3/W6 mediation, network-syscall
atomicity with authorization, truthful representation of all transport
failures, arbitrary concurrent reads, complete TLS close/error behavior,
pre-audit denials, post-provider-send revocation and release, write uncertainty,
or host/guest OS isolation. The W4/W5 Lean model and kernel-checked
obligations remain unchanged. The important next theorem remains a native
source-to-abstract-history simulation, with the exact trust assumptions and
network-visible event definition stated before claiming credential confinement.

## Native acceptance follow-up: bootstrap and issuance audit scope

Two successive native runs exposed incorrect test assumptions, not changes in
credential dispatch. The initial pending oracle passed the entire provider audit
as a request-only trace and failed on the startup `session_open` row. The first
correction excluded only that row. The next native run reported four identical
startup-prefix failures because the actual bridge also records `issued` **before
it announces the bound surrogate**.

The expected host audit prefix is now exactly:

1. `session_open`: schema 1, manifest profile, grant and policy identities;
2. `issued`: schema 1, the same grant and policy, and the public claims of the
   bound JWT returned by the native bridge.

This order is grounded in `custody.rs` (`Session::new` writes `session_open`),
`crypto.rs`/`protocol.rs` (`issue_recorded` invokes the audit observer), and
`custody.rs` (`Audit::issued` writes the identity). `AuthorityProviderCase`
returns the issued token after those calls. The audit does not contain the
credential or the JWT's protected `enc` claim.

`_session_prefix` validates both rows, requires the issued identity to agree
with the JWT's decoded **public** claims (without claiming to verify its
signature), and records that two-row prefix. Only the validated prefix is
removed from request-level audit rows and provider-arrival snapshots. Dispatch
rows must retain the same grant, policy and issued identity. Unknown startup
rows, changed issuance, missing events, extra dispatches, or changed provider
snapshots remain errors. The unsent-provider and public-denial oracles have not
been relaxed.

Portable tests use an unsigned *synthetic* JWT solely for the public-claim
correspondence check and exercise final-only and two-phase pending witnesses.
The real native tests use the signed Rust-produced token, independently
configured loopback TLS, and the existing pinned identity material.

For the native acceptance run, only the focused gate is needed:

```bash
python dev/verification/quick_w6_read.py --pending-only --native
```

The regression was addressed without production Rust/Lean changes or the
compiler-linkage extraction. Passing the portable tests is not a substitute
for rerunning these four native cases.
