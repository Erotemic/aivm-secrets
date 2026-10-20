# Native dispatch preservation and current completion

The October 20 NR-1 increment proves decisions from the **actual extracted
Rust** `read_transition` module and repairs a native manifest release gap.
It also adds an opt-in witness on an installed Linux TPM resource manager.
This is partial NR-1 implementation linkage; it does not complete NR-2–NR-5,
native I/O simulation, deployment isolation or independent security review.

## Production change

Previously, the final provider response was followed by a host-control check,
projection, reflection checking and a completion audit. The full coordinator,
surrogate, grant, time and OAuth-lease check ran before provider emission,
but did not run after a final response. A coordinator tombstone committed
while a final read was in flight could therefore be followed by a successful
guest reply. Checked-only reads already had an intervening freshness check.

`Session::request` now calls the extracted
`read_transition::complete_current` through private `PendingCompletion`:

```text
selected and reflection-checked reply (still private)
  -> full current-authority check at BeforeAudit
  -> completion audit acknowledged
  -> full current-authority check at BeforeRelease
  -> construct CompletedRelease
  -> existing guest frame adapter
```

The second check prevents a blocking completion audit from extending authority.
Both native checkpoints call the existing `fresh` closure; this retains
coordinator failure as a denial, current OAuth lease checks, exact peer and
surrogate binding, grant validity, host write policy and monotonic session
lifetime. The existing early host-control check remains in place. No cached
authorization, automatic retry, protocol change or state migration is added.
A release failure after a sent write retains `outcome_unknown`.

Checks are sampled points. Revocation after the last check does not atomically
cancel a guest TLS write or a provider effect already admitted. An acknowledged
completion row can exist without a successful guest reply if the second check
fails. Audit append/flush/sync, clock and authority correspondence, projection,
serialization and TLS remain adapter obligations. The existing successful
read-path models have not been silently extended to represent every new
failure/acknowledgment prefix.

## Checked extraction and proof scope

`proofs/GarrettReadTransition.lean` imports the generated core rather than a
hand-written replacement. Its thirteen named results cover exact preparation
and acknowledgment decisions, phase/write preservation, rejection of preflight
and unadmitted final writes, audit refusal, both completion checks, conditional
completion preservation and authorized positive witnesses. BeforeAudit and
BeforeRelease are distinct extracted callback inputs, so the interface can
represent loss of authority during the audit.

The completion preservation theorem assumes contracts for the individual
acknowledged adapter results. It proves the controller's conjunction/order;
it does not assume or prove whole-service secrecy. Arbitrary Lean `Prepared`
structures are not declared reachable Rust permits: dispatch preservation
starts at the actual `prepare` result. Provider-result classification and
the complete concrete-to-W4/W5 event relation remain unresolved.

Reproduce the focused source link, kernel check and named axiom audit:

```bash
.venv/bin/python dev/verification/read_transition.py
# Proof editing only; this omits fresh source regeneration:
.venv/bin/python dev/verification/read_transition.py --no-regenerate
# Negative Rust mutations are re-extracted, then rejected by the actual proof:
.venv/bin/python dev/verification/garrett.py mutate --mutation-filter 'read transition'
```

The default command regenerates with the repository's pinned Charon/Aeneas,
compares the generated module byte for byte, compiles the focused Lean module,
and rejects any named theorem with an axiom outside the established
`propext`, `Classical.choice`, `Quot.sound` allowance. The normal Garrett
proof audit and usable-system `--proofs` gate include this module too.

Native regressions cover coordinator revocation/outage during the last
provider response for final-only, checked-only and two-phase reads, against
both coordinator implementations. Separate no-coordinator tests delay the
last response past identity/grant expiry or the current OAuth token expiry.
Another native test commits an operator tombstone on the real coordinator mTLS
channel at the post-completion-audit check and observes a completed row followed
by guest denial. The core unit test injects failure
at each completion checkpoint and checks the actual callback prefix.

## Installed vTPM witness

The test-only `DeviceTPM` fixture is selected **only** by
`AIVM_SECRETS_TEST_TPM_DEVICE`; ordinary tests retain disposable swtpm state.
The device harness requires fresh native binaries and TPM device access:

```bash
cargo build --locked --manifest-path rust/Cargo.toml --bins --features conformance,coordinator-server
# Run as an operator with read/write access to this resource-manager device:
.venv/bin/python dev/verification/tpm_device.py --device /dev/tpmrm0
```

The witness provisions temporary signing and attestation objects at
`0x81010011` and `0x81010012`. It refuses either occupied handle, never clears
the TPM or issues a global flush, checks the public pin before cleanup, and
verifies that all pre-existing persistent public areas are unchanged afterward.
These fixture handles must be reserved from concurrent administrative changes
for the duration of the run; pin-check and eviction are separate commands.
No existing object is adopted as test key material. Missing cleanup/pins or
changed persistent objects fail the run explicitly.

The five required device cases exercise CSR possession, no private-key file,
wrong public key/attributes, no software fallback, fresh pinned-AK
creation evidence, native enrollment and actual mTLS/provider use. This tests
the installed vTPM and signer adapter; it does not establish physical TPM
provenance, EK-to-AK credential activation, host integrity, VM isolation,
snapshot/clone resistance or live-provider compatibility. Root was used only
for this opt-in test process in the development VM; no account/device ACL was
changed. New development/proof harnesses and fixtures are non-core Python.

Wrong-authorization signing tests run only on isolated swtpm. TPM dictionary-
attack counters are shared across objects; repeating those negatives on the
installed device triggered lockout during development. The counter was reset
with `tpm2_dictionarylockout --clear-lockout` (not TPM clear); existing objects
and lockout parameters were retained. The corrected harness excludes that
negative case, refuses pre-existing lockout, and checks unchanged dictionary-
attack state as well as public object pins. It never resets counters itself.

Actual validation results are recorded separately from the frozen `aeae955`
baseline in `dev/validation/2026-10-20-read-completion.json`.
