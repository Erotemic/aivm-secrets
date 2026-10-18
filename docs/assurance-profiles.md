# Configuration-dependent assurance

Open [the interactive comparison](assurance-profiles.html) to inspect the
tradeoffs. Its curves compare named conditional properties across qualitative
setup stages. They are not attack probabilities, a benchmark or a total
security score. The [versioned definitions](planning/aivm-secrets-assurance-profiles.json)
are reporting data, not guest-supplied authority or a runtime attestation API.
No operator assertion in this report upgrades a live session's assurance.

The usable baseline needs no TPM. A Python local broker keeps the provider
credential on the host and authorizes operations under its policy. The native
Rust GitHub workflow uses mTLS with an explicitly selected software key;
no TPM is required. Certificate binding prevents a stolen surrogate from being
used with another key, but cannot distinguish two copies of the same software
key and certificate. Scope and revocation still apply to both copies.

An AIVM vTPM device is infrastructure. Existing software keys remain exportable
after device creation or upgrade. A stronger enrollment needs a TPM-generated
key, its signing adapter, independently trusted provenance and verified
non-exportability. The native Rust authority/client have explicit TPM paths
and synthetic emulator tests; this is not Python TPM parity, automatic AIVM
integration, or proof of physical hardware provenance. A vTPM host can copy its
state. A guest allowed to sign can relay signatures even if it cannot export
the key. Rollback witnesses and process isolation are independent dimensions.

An arbitrary host executable given the provider credential can disclose it.
That proposed execution profile cannot inherit the broker's credential-
confinement claim merely by using a stronger client identity.

## Formal scope

`lake -d proofs build +GarrettProfiles` kernel-checks seven theorems in
[GarrettProfiles.lean](../proofs/GarrettProfiles.lean). They reuse the existing
ideal-cryptography deduction model in `GarrettSecrecy.lean`:

- Provider credentials remain non-derivable across all admitted finite protocol
  histories for every modeled client-key custody profile.
- A software identity can be copied; merely adding a device changes no key
  protection. Even that explicit copied-key witness does not reveal the
  separately held provider credential in the model.
- Independently verified custody prevents modeled key export.
- A signing oracle can authenticate without exporting its key: non-exportability
  alone cannot rule out authentication relays.
- Handing a credential to arbitrary host execution supplies a direct disclosure
  counterexample.

The trace premise still excludes unreviewed credential-bearing output. These
are conditional symbolic results, **not** extracted proofs of the TPM, guest
kernel, arbitrary response bytes or complete Rust service. Concrete I/O
refinement and declassification remain W3–W6 obligations. The `verifiedTpm`
constructor names an environmental premise, not a claim that any present VM
has established it. The curve is independent of whether the Rust native
backend has full Python contract parity; that parity worklist remains open.

## Runtime witnesses

`tests/test_assurance_profiles.py` runs the same copying attack against Python
and native Rust certificate-bound brokers. Both use real TLS and a local
recording HTTPS provider with synthetic credentials. A copied software key,
certificate and surrogate can perform the allowed PR read; a different PR is
denied without provider I/O. After enrollment revocation the copied client
cannot cause another provider call. The response does not contain the literal
provider credential. This is a concrete bounded witness, not general
noninterference against arbitrary providers or encodings.

The native authority test
`test_tpm_requirement_rejects_software_before_credential_custody` additionally
checks that a TPM-required session cannot silently acquire custody under a
software enrollment. It requires no TPM hardware. Real emulator signing tests
remain in the full suite and can run without an AIVM guest.

## Reproduction

With `.[tests]`, the pinned Rust toolchain and (for proofs) the pinned Lean /
Aeneas tools installed:

```bash
python dev/verification/system.py --proofs
python dev/verification/system.py --proofs --full-tests
python dev/verification/assurance_profiles.py render
python dev/verification/assurance_profiles.py check
```

The usable-system gate builds independent Rust binaries, runs Rust unit tests,
checks the W0/W3/W6 source inventories and executes the Python/native workflows.
It rejects skipped, failed or empty required-workflow reports. Optional full
suite skips are reported by pytest; they are not native workflow completion.
It retains command logs, JUnit and a source-fingerprinted JSON report under a
unique ignored `.tools/system-*` directory. Changing Git-visible source during
the run invalidates the result. `--proofs` compiles W4/W5 and the new profile
module; it does not rerun the separate full regeneration/mutation campaign.

The CI Garrett workflow runs the usable-system gate in addition to its existing
extraction/proof/mutation checks. Hosted CI execution is separate evidence from
a local pass. The visualization is standalone HTML with no network dependencies.
