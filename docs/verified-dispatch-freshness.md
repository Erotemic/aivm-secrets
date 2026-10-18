# Native dispatch admission after blocking setup

The native account and manifest backends now repeat authority admission after
provider TLS setup and immediately before credential-bearing HTTP. The patch
carries forward the runtime/controller work from `de4330e`, adapted to the
newer W3 typed dispatch and W6 pure HTTP encoder. The encoder still validates
all request bytes before connecting; it is not duplicated after TLS setup.

The check matters because a provider handshake can block after an earlier
admission has succeeded. Eight regressions reproduced actual acceptance on
the pre-fix `ef97326` binaries: account, manifest read, manifest write and
checked-write requests could outlive their authority during provider TLS;
`describe` and `renounce` in both backends could outlive their outer surrogate
while waiting for the OAuth vault. All eight now refuse the expired request.
The TLS cases verify that the recording provider receives no HTTP request.

This does not cancel an action already emitted before expiry or revocation.
The property is admission at the last trusted sample, not an atomic validity
check spanning every byte of a network operation.

## Implementation and proof boundary

The small extractable `emission::emit_current` controller calls `recheck` before
its emission continuation. A denied check never invokes that continuation.
Native adapters construct the pending emission after TLS setup; write failures
become `outcome_unknown` inside emission, while a preceding admission denial
retains its refusal code. Account admission reuses the extracted
`protocol::recheck`, which delegates to the existing full prepare guard.
Manifest admission repeats exact peer/outer binding and operation/grant checks.
Both control paths validate the outer surrogate again after acquiring the
vault lease. Held native authority/vault leases retain the selected state.

The regenerated Aeneas module is checked by five `GarrettEmission` contracts
and three additional `GarrettProtocol` lemmas. These cover refusal before
emission, independence from a refused continuation, preservation of admitted
results/errors, the conditional current/emission contract and positive success.
The full named Garrett axiom audit checks 213 obligations. The separate seven
configuration-profile theorems and W4/W5 trace modules also compile; their
source/proof inventories remain checked against the regenerated model.

[EMISSION-RUST-01](planning/aivm-secrets-assumptions.json) names the trusted
clocks, participating lease writers, exact route/credential selection and
native call-site correspondence premises. The source guard adds negative
mutants for bypassing the late manifest check and the extracted continuation.
This is not whole-service I/O refinement, a proof of kernel locks, or TPM
provenance. W4/W5 status records now say local kernel checking has passed while
native refinement remains open; their theorem bodies and exclusions were not
weakened.

## Executed checks and reproduction

The adapted source passed:

- The eight reproduced expiry regressions and the complete 32-case required
  Python/native workflow selection, without skips.
- The same 32 cases using release binaries built without conformance support.
- Strict Rust lint in normal and conformance modes, Rust unit tests, and the
  pinned formatting check (including formatting of the pulled W2/W6 code).
- Freshness/source regeneration and the named Garrett proof/axiom audit;
  287 selected Rust/reference contracts passed during recording.
- Four targeted re-extracted Rust mutations removing or ignoring the new
  late-admission checks; all failed their Lean obligations. This is a scoped
  four-of-94 run, **not** a completed new 94-mutation campaign.
- The source-archive regression: it failed before adding the missing W4/W5 /
  profile modules and passes with all top-level proof sources present.

Run the integrated gate on a stable checkout:

```bash
python dev/verification/system.py --proofs --full-tests
python dev/verification/garrett.py mutate --mutation-filter '^late '
```

Omitting `--mutation-filter` retains the full mutation campaign used by CI.
A filtered run prints the selected/total count and never counts as completion
of the unselected mutants. Full-system commands retain a source-fingerprinted
report, JUnit and per-command logs under `.tools/system-*`. The predecessor
`ef97326` full-system snapshot passed 2,217 tests with one explicitly pending
primitive-runner skip; that historical count is not a result for this patch.

The archive fix is necessary for reproducibility: successful creation of a
source archive alone did not mean the W4/W5 and profile proofs were shipped.
The new archive-content test verifies the actual tarball, including every
top-level Lean source and the usable-system commands, while excluding local
build/verification caches.
