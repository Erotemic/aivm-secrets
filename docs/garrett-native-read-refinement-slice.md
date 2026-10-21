# Garrett: native manifest read-only security-boundary slice

Status: **implemented overlay; native build and Lean verification pending on the
maintainer's toolchain.** Based on source commit `b91748bf0344` (2026-10-19).
This is W3/W6 advancement, **not** completion of W3–W6.

## Exact scope

- **In:** native Rust `manifest-https-v1`, software mTLS identity and local
  provider certificate, static file-held synthetic credential, `writes=deny`,
  uncoordinated session, host-policy preflight/final read, checked facts,
  `request` and `renounce`, fixed errors, host audit and guest frame.
- **Out:** provider writes, approval, TPM, coordinator, OAuth rollover,
  host-only administration, Python forwarding, real provider endpoints,
  VM isolation and actual credential secrecy under hardware compromise.

## Source-linked enforcement

A policy-selected `Effect` has no right to perform credentialed I/O. The
[source-owned request adapter](garrett-owned-request.md) enforces exact
phase/write preparation before a provider factory. The
[owned dispatch controller](garrett-owned-dispatch.md) invokes
the native identity/target preparation and fixed durable audit callback before
constructing the core `Audited` permit. It owns receipt gates, provider setup,
current admission and the composite attempt gate around the native raw sender.
Owned completion selects schema-constrained fields, checks reflection and
persists completion with checks before and after audit before guest success.

An audit receipt alone does not establish a current grant. The extracted
`manifest::authorize` checks remain the admission authority, revalidated after
TLS setup and immediately before the credentialed send. Receipt/report handoffs are now extracted code. Native primitive/context
semantics, dependencies and panic/drop paths still need the complete
reachability/refinement argument.

## Independent runtime evidence

`test_w6_audit_is_present_when_each_read_reaches_real_https_provider` runs a
native Rust bridge over mTLS against a local recording HTTPS provider. It
runs an authorized two-phase read with a selected result, a forged checked
fact causing preflight-only emission, an unsupported operation, and a
post-renunciation operation denial. The provider snapshots the *actual audit
file when the HTTP request arrives*, before sending its response; the oracle
requires a matching dispatch record and correct prefix ordering already
present. It also compares provider headers/body and raw guest TLS JSONL bytes.

`test_w6_arrival_oracle_rejects_reordered_or_postdated_dispatch_audit` and
existing W3 mutants independently change postdated/reordered/missing audits,
audit permit construction, unauthorized write promotion, duplicated send
paths and guest frames. These source/unit oracles remain separate from the
native-process acceptance run.

## Relation to W4/W5

| Native fact | Modeled counterpart | Status |
| --- | --- | --- |
| Host policy compiles a checked preflight/final effect | W4 `providerSend(.preflight/.final)` and extracted `manifest::authorize` | Concrete finite trace compared to Python compiler; universal refinement open |
| Core `Audited` permit follows the native audit callback | W4 `auditAttempt` / auditOK premise | Source boundary + audit-visible-at-provider witness; crash durability and trace abstraction open |
| Owned provider current stamp after TLS setup | W4 `Gate.accepted` | Existing extracted late-authorize proof; Rust callsite/time/coordination correspondence open |
| Native project + completed audit + one `GuestFrame` | W4 `guestReply`, W5 declassification | Actual scoped raw guest TLS bytes tested; full noninterference/metadata/closure refinement open |
| Denied or revoked guest | W4 `guestDenied`, W5 denied observations | Selected synthetic examples, not all-input proof |

The owned controllers now have extracted returned-state contracts; neither
these conditional contracts, source guards nor finite trace tests establish
a universal relation from the production binary
to W4/W5. Do **not** mark IO-REFINE, NO-PREFLIGHT, CHECKED-FACTS or METADATA
as discharged in `docs/planning/aivm-secrets-w4-proof-scope.json`.

## Acceptance on a toolchain-equipped, offline development VM

```bash
python dev/verification/w0_contract.py check
python dev/verification/w3_effect_boundary.py check
python dev/verification/w6_adapter.py check
python -m pytest -q tests/test_secrets_w3_effect_boundary.py tests/test_secrets_w6_adapter.py

cargo test --locked --manifest-path rust/Cargo.toml -p aivm-secrets-garrett --lib   unapproved_read_or_preflight_cannot_become_write_dispatch

AIVM_SECRETS_REQUIRE_TPM_TESTS=1 python dev/verification/system.py   --proofs --full-tests --call-linkage
```

The last command checks all native Rust workflow cases and the existing Lean
proofs, then runs the optional compiler-specialized path investigation. It
**does not** prove transitive dependency reachability, lifetime/dominance,
filesystem power-loss guarantees or machine-code equivalence. Inspect the
compiler ledger for unresolved edges; do not turn this optional check into a
proof claim.
