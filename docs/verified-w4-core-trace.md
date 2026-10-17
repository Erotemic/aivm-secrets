# W4 — extracted-controller trace-confinement candidate

**Status (2026-10-17): Candidate Lean source is authored; only source and
structural checks ran in the overlay environment. The pinned Lean toolchain
was unavailable, so the new theorems have **not** been kernel-checked. The W4
exit gate and full SINK-01/TRACE-01 claim remain **open**.**

This file documents exactly what the added model would establish after Lean
accepts it and what must still be connected to real native service I/O.

## Reviewed source and scope

`proofs/GarrettConfinement.lean` imports the established extracted Rust
controllers and proofs: `GarrettProtocol`, `GarrettManifest`, and
`GarrettDisclosure`. `Gate.accepted` is equality to the *actual Aeneas
extraction* of `manifest::authorize`, and `CheckedFact.accepted` is equality
to the extraction of `manifest::parameter`. `SoundEvent` ties a modeled
provider send to that extracted authorization result and the modeled audit
acknowledgement; a modeled guest reply to the result of the extracted
`disclosure::project` function. The `Current`/grant and write restrictions are
obtained from `manifest.Proofs.authorize_contract`, not introduced as security
axioms. The nested credential controller's `protocol::perform` remains a
**separate** source-level component; existing `perform_contract`,
`perform_observer_failure`, and credential-use proofs are referenced, not
mistaken for native manifest service correspondence.

The Lean **trace interpreter is a specification**, *not* an extracted version
of the real W3 `custody/manifest_session.rs` or `tls.rs`. Its internal events
may carry claims and raw response data as proof witnesses; these are **not
public log records or allowed guest output bytes**. A formal claim about
concrete I/O needs to relate each native sink to a modeled event (W6).

The initial trace scope is the W1/W2 two-phase native manifest sequence:
credentialed metadata preflight, possible credentialed final request, then
selected disclosure. There is a fresh `Gate` at each send so a grant revoked
between phases cannot authorize the second. An audit acknowledgement must
precede each modeled send; completion audit must precede modeled guest success.
Preflight or final provider failure, audit failure, and a denied/revoked grant
stop their respective continuation. `request_trace_sound` is intended to
establish the invariant for each event in any modeled two-phase trace.

This is **not** an information-flow/noninterference theorem: selected fields
may themselves contain secrets; errors, length, `possibly_more`, and timing
are observable. W5 owns the stronger relational guarantee.

## Concrete obligations still open

| ID | Required to turn the candidate into a defensible service claim |
| --- | --- |
| `IO-REFINE` | Show native Rust execution emits exactly the modeled provider/audit/guest effects with corresponding source guard and durable audit outcomes. Prohibit unmodeled writes and panics across the full reachable I/O graph. W3's hash-based marker checks are not a sound refinement proof. |
| `NO-PREFLIGHT` | Model and verify native operations with no metadata preflight, including which guards still run and zero-dispatch checked-facts paths. |
| `CHECKED-FACTS` | Link `manifest::parameter` decisions and host-selected preflight/final effect compilation to actual checked provider facts, request URL/method/body, policy grants, and route selection. Merely accepting an operation identifier is not enough. |
| `METADATA` | Cover every guest-visible error, `possibly_more`, response lengths, termination, audit/diagnostics and concurrent interleavings; identify declassification vs excluded side channels explicitly. |
| `OTHER-PROFILES` | Establish separate results for `account-status-v1`, forwarded Python legacy sessions, OAuth host startup/refresh, administration and session lifecycle. Do not silently extend this native two-phase proof to them. |

The named adapter acknowledgements (`preAudit`, `finalAudit`,
`completedAuditOK`, `preflightOK`, `finalProviderOK`) are *inputs describing
external adapter outcomes*. They are not supplied by the guest and are not
proven faithful in this model. Their actual call-site association is an
important W6 obligation. The same applies to host-selected method, path,
headers and body: `manifest::authorize` proves current grant/operation/write
selection but cannot by itself prove that a concrete serialized HTTP request
matches the policy compiler's intended effect.

## How to validate

Run from the repository root after the planning, W0–W3 and W2 disclosure
repair overlays are applied:

```bash
python dev/verification/w0_contract.py check
python dev/verification/w3_effect_boundary.py check
python dev/verification/w4_trace.py check
python -m pytest -q tests/test_secrets_w4_trace.py
```

Those checks inspect source provenance, named proof obligations and accidental
scope/bypass changes. **They do not compile a proof.** The pinned Lean
acceptance gate also requires a
**project-local Aeneas backend** in `.tools/aeneas/backends/lean`; installing
Lean/Lake alone is not sufficient. Bootstrap the pinned dependencies once
(the setup requires network access, Rust, `rustup`, `elan`, `curl`, and `tar`):

```bash
python dev/verification/garrett.py bootstrap
python dev/verification/w4_trace.py prove
```

The bootstrap script uses the pinned Aeneas release and SHA-256 digest from
`dev/verification/freshness.py` and does not change the default Rust or Lean
toolchains. Subsequent runs can omit the bootstrap step. W4 `prove` now checks
for the backend before launching Lake and provides this command if it is missing.
This is a dependency setup operation, **not** a proof or a fix for potential
Lean typechecking errors in the candidate module.

`prove` builds the pre-existing proof dependencies, compiles the new Lean file
with warnings-as-errors, parses its `#print axioms` output, and accepts only
`propext`, `Classical.choice`, and `Quot.sound`. The W4 source is deliberately
not added to the recorded Garrett release manifest or default Lake roots until
this gate succeeds. That prevents a new uncompiled candidate from being
reported as part of the historical, checked Garrett theorem inventory.

After a successful kernel run, review whether the positive model traces match
W1/W2 runtime outcomes, then move the Lean module into the audited release
set and rerun the Rust extraction and mutation campaign with the pinned
compiler. W4 may be marked complete only when the exact scoped theorem,
positive runtime witness, and remaining environmental assumptions are reviewed
together. Full service assurance still requires W5 and W6.
